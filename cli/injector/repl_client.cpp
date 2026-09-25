#include "repl_client.h"
#include "../../engine/mpack/mpack.h"

#include <iostream>
#include <thread>
#include <atomic>
#include <vector>
#include <cstring>
#include <cerrno>
#include <mutex>
#include <algorithm>
#include <strings.h>
#include <unordered_map>
#include <cctype>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <termios.h>
#include <cstddef>
#include <fcntl.h>
#include <poll.h>

namespace artpi { namespace injector {

namespace {

// -----------------------------------------------------------------------------
// Transport helpers: abstract AF_UNIX (preferred) or TCP 127.0.0.1:<port>
// -----------------------------------------------------------------------------
bool EndpointIsValid(const AgentEndpoint& ep) {
    return ep.isUnix ? !ep.unixName.empty() : (ep.port > 0);
}

// Create and connect a socket for the endpoint. timeoutMs<=0 => blocking connect.
int ConnectEndpoint(const AgentEndpoint& ep, int timeoutMs) {
    if (!EndpointIsValid(ep)) return -1;

    int fd = socket(ep.isUnix ? AF_UNIX : AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    sockaddr_storage ss{};
    socklen_t addrLen = 0;
    if (ep.isUnix) {
        auto* sun = reinterpret_cast<sockaddr_un*>(&ss);
        sun->sun_family = AF_UNIX;
        sun->sun_path[0] = '\0';   // abstract namespace
        snprintf(sun->sun_path + 1, sizeof(sun->sun_path) - 1, "%s", ep.unixName.c_str());
        addrLen = static_cast<socklen_t>(
            offsetof(sockaddr_un, sun_path) + 1 + ep.unixName.size());
    } else {
        auto* addr = reinterpret_cast<sockaddr_in*>(&ss);
        addr->sin_family = AF_INET;
        addr->sin_port = htons(static_cast<uint16_t>(ep.port));
        inet_pton(AF_INET, "127.0.0.1", &addr->sin_addr);
        addrLen = sizeof(sockaddr_in);
    }

    if (timeoutMs <= 0) {
        if (connect(fd, reinterpret_cast<sockaddr*>(&ss), addrLen) != 0) {
            close(fd);
            return -1;
        }
        return fd;
    }

    // Set non-blocking mode for true connect timeout
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    int rc = connect(fd, reinterpret_cast<sockaddr*>(&ss), addrLen);
    if (rc < 0) {
        if (errno != EINPROGRESS) {
            close(fd);
            return -1;
        }

        struct pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLOUT;
        int pollRc = poll(&pfd, 1, timeoutMs);
        if (pollRc <= 0) {
            close(fd);
            return -1;
        }

        int err = 0;
        socklen_t errLen = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errLen) < 0 || err != 0) {
            close(fd);
            return -1;
        }
    }

    // Restore original blocking flags
    if (flags >= 0) {
        fcntl(fd, F_SETFL, flags);
    }

    // Configure socket timeouts for subsequent read/write
    timeval tv{timeoutMs / 1000, (timeoutMs % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    return fd;
}

static bool RecvExact(int fd, void* buf, size_t len, int timeoutMs) {
    auto* p = static_cast<uint8_t*>(buf);
    size_t total = 0;
    while (total < len) {
        struct pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        int ret = poll(&pfd, 1, timeoutMs);
        if (ret <= 0) {
            if (ret < 0 && errno == EINTR) continue;
            return false;
        }
        ssize_t n = recv(fd, p + total, len - total, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        total += static_cast<size_t>(n);
    }
    return true;
}

bool SendAll(int fd, const void* data, size_t n) {
    const auto* p = static_cast<const uint8_t*>(data);
    while (n) {
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (w == 0) return false;
        p += w;
        n -= (size_t)w;
    }
    return true;
}

bool SendMsgpackFrame(int fd, const msgpack::Value& val) {
    msgpack::Writer writer;
    writer.writeValue(val);
    uint32_t lenBE = htonl(static_cast<uint32_t>(writer.buffer.size()));
    return SendAll(fd, &lenBE, 4) && SendAll(fd, writer.buffer.data(), writer.buffer.size());
}

// -----------------------------------------------------------------------------
// Interactive Line Editor with Ghost Text & Drop-down Menu Autocomplete
// -----------------------------------------------------------------------------

const std::vector<std::string> kCompletions = {
    "Java.",
    "Java.findClass(\"",
    "Java.findMethod(",
    "Java.listMethods(",
    "Java.findMethods(",
    "Java.methodToArt(",
    "Java.artToMethod(",
    "Java.enumerateClassLoaders()",
    "Java.dumpCode(",
    "Java.dumpSmali(",
    "Java.dumpNative(",
    "Java.decompile(",
    "Java.disassembly(",
    "Java.choose(",
    "Java.hook(",
    "Java.unhook(",
    "Java.unhookAll()",

    "Native.",
    "Native.findModule(\"",
    "Native.findSymbol(\"",
    "Native.findSymbolsMatching(\"",
    "Native.hook(",
    "Native.dumpNative(",

    "DebugSymbol.",
    "DebugSymbol.fromAddress(",
    "DebugSymbol.fromName(",
    "DebugSymbol.getFunctionByName(",

    "Trace.",
    "Trace.unified(",
    "Trace.java(",
    "Trace.native(",
    "Trace.untrace()",

    "Debug.",
    "Debug.breakJava(",
    "Debug.breakNative(",
    "Debug.step()",
    "Debug.next()",
    "Debug.continue()",
    "Debug.return()",

    "Memory.",
    "Memory.hexdump(",
    "Memory.readByteArray(",
    "Memory.writeByteArray(",
    "Memory.readCString(",
    "Memory.readU32(",
    "Memory.writeU32(",

    "dynamic.java.",
    "dynamic.native.",

    "findclass(\"",
    "findmethod(",
    "listmethods(",
    "findmethods(",
    "methodtoart(",
    "artmethodtojmethod(",
    "enumloaders()",

    "dumpcode(",
    "dumpsmali(",
    "dumpnative(",
    "decompile(",
    "disassembly(",
    "choose(",
    "jhook(",
    "nhook(",
    "unhook(",
    "unhookall()",
    "untrace()",
    "D()",
    "detach()",

    "traceunified(",
    "tracejava(",
    "tracenative(",

    "brkj(",
    "brkn(",
    "s()",
    "n()",
    "c()",
    "r()",
    "bt()",
    "inspect(",
    "po(",
    "artobject(",
    "artobjects()",
    "getreg(",
    "setreg(",
    "dumpRegs()",
    "regs.",
    "thread()",

    "hexdump(",
    "readmem(",
    "writemem(",
    "readstring(",
    "readu32(",
    "writeu32(",

    "console.log(",
    "console.warn(",
    "console.error(",
    "exit",
    "quit",
    "q",
    "help",
    "clear",
    "cls"
};

std::mutex g_termMutex;
std::string g_currentPrompt = "artpi> ";
std::string g_currentLine;
size_t g_currentPos = 0;
bool g_isRawMode = false;
termios g_origTermios{};

// Dynamic completions cached from remote Agent
std::vector<std::string> g_dynamicClasses;
std::vector<std::string> g_dynamicModules;
std::unordered_map<std::string, std::vector<std::string>> g_classMethodsCache;
std::unordered_map<std::string, std::vector<std::string>> g_moduleSymbolsCache;
int g_agentFd = -1;
int g_agentPort = -1;
std::string g_agentUnix;   // abstract AF_UNIX name when using the unix transport

static const char* kJavaMethodActions[] = {
    "dumpCode()", "dumpSmali()", "dumpNative()", "disassembly()", "decompile()", "hook(", "hookallclassmethods(", "trace(", "break()", "address", "ptr", "artMethod", "isNative"
};
static const char* kJavaClassActions[] = {
    "dumpCode()", "dumpSmali()", "disassembly()", "decompile()", "listMethods()", "findMethods(", "hookall(", "choose("
};
static const char* kNativeSymbolActions[] = {
    "dumpNative()", "break()", "hook(", "hexdump()", "address", "ptr", "readCString()", "readByteArray("
};

// Ghost text & dropdown menu state
std::string g_currentGhost;
int g_menuLines = 0;
int g_selectedMenuIndex = 0;
std::vector<std::string> g_menuItems;
size_t g_menuTokenStart = 0;

static std::vector<std::string> ExtractJsonStringArray(const std::string& json, const std::string& key = "") {
    std::vector<std::string> res;
    size_t start = 0;
    if (!key.empty()) {
        size_t keyPos = json.find("\"" + key + "\"");
        if (keyPos == std::string::npos) return res;
        start = keyPos;
    }
    size_t bracketOpen = json.find('[', start);
    if (bracketOpen == std::string::npos) return res;

    // Correctly locate matching ']' by ignoring brackets inside quotes
    size_t bracketClose = std::string::npos;
    bool inQuote = false;
    bool esc = false;
    for (size_t i = bracketOpen + 1; i < json.size(); i++) {
        char c = json[i];
        if (esc) {
            esc = false;
        } else if (c == '\\') {
            esc = true;
        } else if (c == '"') {
            inQuote = !inQuote;
        } else if (c == ']' && !inQuote) {
            bracketClose = i;
            break;
        }
    }
    if (bracketClose == std::string::npos) return res;

    size_t cur = bracketOpen + 1;
    while (cur < bracketClose) {
        size_t q1 = json.find('"', cur);
        if (q1 == std::string::npos || q1 >= bracketClose) break;
        size_t q2 = std::string::npos;
        bool qEsc = false;
        for (size_t i = q1 + 1; i < bracketClose; i++) {
            if (qEsc) {
                qEsc = false;
            } else if (json[i] == '\\') {
                qEsc = true;
            } else if (json[i] == '"') {
                q2 = i;
                break;
            }
        }
        if (q2 == std::string::npos) break;
        res.push_back(json.substr(q1 + 1, q2 - q1 - 1));
        cur = q2 + 1;
    }
    return res;
}

static std::string EvalOnAgentSync(const std::string& script) {
    if (g_agentFd < 0) return "";
    // Use a dedicated short-lived connection so completion fetches never race
    // with the background receiver thread on the main REPL socket.
    AgentEndpoint ep;
    ep.isUnix = !g_agentUnix.empty();
    ep.port = g_agentPort;
    ep.unixName = g_agentUnix;
    int cfd = ConnectEndpoint(ep, 1000);   // 1s timeout
    if (cfd < 0) return "";

    msgpack::Value req = msgpack::Value::makeMap();
    req.set("t", msgpack::Value(1));
    req.set("seq", msgpack::Value(0));
    req.set("cmd", msgpack::Value("eval"));
    msgpack::Value args = msgpack::Value::makeMap();
    args.set("script", msgpack::Value(script));
    req.set("args", args);
    if (!SendMsgpackFrame(cfd, req)) { close(cfd); return ""; }

    uint32_t lenBE = 0;
    if (!RecvExact(cfd, &lenBE, 4, 1500)) { close(cfd); return ""; }
    uint32_t frameLen = ntohl(lenBE);
    if (frameLen == 0 || frameLen > 8 * 1024 * 1024) { close(cfd); return ""; }
    std::vector<uint8_t> buf(frameLen);
    if (!RecvExact(cfd, buf.data(), frameLen, 2000)) { close(cfd); return ""; }
    close(cfd);

    msgpack::Reader reader(buf.data(), frameLen);
    msgpack::Value frame;
    if (!reader.readValue(frame)) return "";
    const msgpack::Value* data = frame.get("data");
    if (!data) return "";
    return data->getString("result");
}

static std::unordered_map<std::string, std::vector<std::string>> g_classPrefixCache;

static std::vector<std::string> FetchMatchingClasses(const std::string& prefix) {
    auto it = g_classPrefixCache.find(prefix);
    if (it != g_classPrefixCache.end()) return it->second;
    std::string script = "JSON.stringify(dynamic.__findMatchingClasses(\"" + prefix + "\", 40))";
    std::string res = EvalOnAgentSync(script);
    auto classes = ExtractJsonStringArray(res);
    g_classPrefixCache[prefix] = classes;
    for (const auto& c : classes) {
        if (std::find(g_dynamicClasses.begin(), g_dynamicClasses.end(), c) == g_dynamicClasses.end()) {
            g_dynamicClasses.push_back(c);
        }
    }
    return classes;
}

static std::vector<std::string> FetchClassMethods(const std::string& className) {
    auto it = g_classMethodsCache.find(className);
    if (it != g_classMethodsCache.end()) return it->second;
    std::string script = "JSON.stringify(dynamic.__getClassMethods(\"" + className + "\"))";
    std::string res = EvalOnAgentSync(script);
    auto methods = ExtractJsonStringArray(res);
    std::sort(methods.begin(), methods.end());
    methods.erase(std::unique(methods.begin(), methods.end()), methods.end());
    g_classMethodsCache[className] = methods;
    return methods;
}

static std::vector<std::string> FetchModuleSymbols(const std::string& modName) {
    auto it = g_moduleSymbolsCache.find(modName);
    if (it != g_moduleSymbolsCache.end()) return it->second;
    std::string script = "JSON.stringify(dynamic.__getModuleSymbols(\"" + modName + "\"))";
    std::string res = EvalOnAgentSync(script);
    auto symbols = ExtractJsonStringArray(res);
    std::sort(symbols.begin(), symbols.end());
    symbols.erase(std::unique(symbols.begin(), symbols.end()), symbols.end());
    g_moduleSymbolsCache[modName] = symbols;
    return symbols;
}

static std::vector<std::string> GetLoadedModules() {
    if (!g_dynamicModules.empty()) return g_dynamicModules;
    if (g_agentFd >= 0) {
        std::string res = EvalOnAgentSync("JSON.stringify(dynamic.__getCompletionData().modules)");
        if (!res.empty()) {
            g_dynamicModules = ExtractJsonStringArray(res);
            if (g_dynamicModules.empty()) {
                g_dynamicModules = ExtractJsonStringArray(res, "modules");
            }
        }
    }
    return g_dynamicModules;
}

static bool StartsWithIgnoreCase(const std::string& s, const std::string& prefix) {
    if (s.size() < prefix.size()) return false;
    return strncasecmp(s.c_str(), prefix.c_str(), prefix.size()) == 0;
}

static void FetchDynamicCompletions(int fd, const AgentEndpoint& ep) {
    g_agentFd = fd;
    g_agentPort = ep.isUnix ? -1 : ep.port;
    g_agentUnix = ep.isUnix ? ep.unixName : std::string();
    std::string res = EvalOnAgentSync("JSON.stringify(dynamic.__getCompletionData())");
    if (!res.empty()) {
        g_dynamicClasses = ExtractJsonStringArray(res, "classes");
        g_dynamicModules = ExtractJsonStringArray(res, "modules");
    }
}

static std::vector<std::string> GetCandidatesForToken(const std::string& token) {
    std::vector<std::string> results;
    std::string tokenLower = token;
    for (char& ch : tokenLower) ch = tolower(ch);

    // 1. Static built-ins
    for (const auto& c : kCompletions) {
        std::string cLower = c;
        for (char& ch : cLower) ch = tolower(ch);
        if (cLower.rfind(tokenLower, 0) == 0) {
            results.push_back(c);
        }
    }

    // 2. Dynamic Java completions: dynamic.java.<Class>.<method>.<action>
    if (token.rfind("dynamic.java.", 0) == 0 || std::string("dynamic.java.").rfind(token, 0) == 0) {
        if (token == "dynamic." || token == "dynamic.j" || token == "dynamic.ja" || token == "dynamic.jav" || token == "dynamic.java") {
            results.push_back("dynamic.java.");
        } else {
            std::string rest = token.size() >= 13 ? token.substr(13) : "";
            std::string matchedClass;
            for (const auto& cls : g_dynamicClasses) {
                if (rest.rfind(cls + ".", 0) == 0 || rest == cls) {
                    matchedClass = cls;
                    break;
                }
            }

            // If not found in g_dynamicClasses, dynamically resolve class from rest!
            if (matchedClass.empty() && g_agentFd >= 0) {
                size_t p = rest.size();
                while (p > 0) {
                    size_t dot = rest.rfind('.', p - 1);
                    if (dot == std::string::npos) break;
                    std::string cand = rest.substr(0, dot);
                    if (!cand.empty() && cand.find('.') != std::string::npos) {
                        auto methods = FetchClassMethods(cand);
                        if (!methods.empty()) {
                            matchedClass = cand;
                            if (std::find(g_dynamicClasses.begin(), g_dynamicClasses.end(), cand) == g_dynamicClasses.end()) {
                                g_dynamicClasses.push_back(cand);
                            }
                            break;
                        }
                    }
                    p = dot;
                }
            }

            if (!matchedClass.empty() && rest.size() > matchedClass.size() && rest[matchedClass.size()] == '.') {
                std::string afterClass = rest.substr(matchedClass.size() + 1);
                size_t nextDot = afterClass.find('.');
                std::string classPrefix = "dynamic.java." + matchedClass + ".";
                auto methods = FetchClassMethods(matchedClass);

                if (nextDot != std::string::npos) {
                    std::string methodName = afterClass.substr(0, nextDot);
                    std::string actPart = afterClass.substr(nextDot + 1);
                    std::string methodPrefix = classPrefix + methodName + ".";
                    for (const auto& act : kJavaMethodActions) {
                        if (actPart.empty() || StartsWithIgnoreCase(act, actPart)) {
                            results.push_back(methodPrefix + act);
                        }
                    }
                } else {
                    for (const auto& act : kJavaClassActions) {
                        if (afterClass.empty() || StartsWithIgnoreCase(act, afterClass)) {
                            results.push_back(classPrefix + act);
                        }
                    }
                    size_t added = 0;
                    for (const auto& mName : methods) {
                        if (afterClass.empty() || StartsWithIgnoreCase(mName, afterClass)) {
                            results.push_back(classPrefix + mName);
                            if (++added >= 40) break;
                        }
                    }
                }
            } else {
                std::vector<std::string> candidates = g_dynamicClasses;
                if (!rest.empty() && g_agentFd >= 0) {
                    auto fetched = FetchMatchingClasses(rest);
                    if (!fetched.empty()) {
                        candidates = fetched;
                    }
                }
                for (const auto& cls : candidates) {
                    std::string cand = "dynamic.java." + cls;
                    if (StartsWithIgnoreCase(cand, token)) {
                        results.push_back(cand);
                    }
                }
            }
        }
    }

    // 3. Dynamic Native completions: dynamic.native.<lib>.<symbol>.<action>
    if (token.rfind("dynamic.native.", 0) == 0 || std::string("dynamic.native.").rfind(token, 0) == 0) {
        if (token == "dynamic." || token == "dynamic.n" || token == "dynamic.na" || token == "dynamic.nat" || token == "dynamic.native") {
            results.push_back("dynamic.native.");
        } else {
            auto modules = GetLoadedModules();
            std::string rest = token.size() >= 15 ? token.substr(15) : "";
            std::string matchedMod;
            for (const auto& mod : modules) {
                std::string stem = mod;
                if (stem.size() > 3 && stem.substr(stem.size() - 3) == ".so") stem = stem.substr(0, stem.size() - 3);
                if (rest.rfind(mod + ".", 0) == 0 || rest == mod) { matchedMod = mod; break; }
                if (rest.rfind(stem + ".", 0) == 0 || rest == stem) { matchedMod = stem; break; }
            }

            if (!matchedMod.empty() && rest.size() > matchedMod.size() && rest[matchedMod.size()] == '.') {
                std::string afterMod = rest.substr(matchedMod.size() + 1);
                size_t nextDot = afterMod.find('.');
                std::string modPrefix = "dynamic.native." + matchedMod + ".";
                auto symbols = FetchModuleSymbols(matchedMod);

                if (nextDot != std::string::npos) {
                    std::string symName = afterMod.substr(0, nextDot);
                    std::string actPart = afterMod.substr(nextDot + 1);
                    std::string symPrefix = modPrefix + symName + ".";
                    for (const auto& act : kNativeSymbolActions) {
                        if (actPart.empty() || StartsWithIgnoreCase(act, actPart)) {
                            results.push_back(symPrefix + act);
                        }
                    }
                } else {
                    // For module root (dynamic.native.<mod>.), do NOT show symbol actions!
                    // Only show module helpers (findSymbol) and exported symbols
                    if (afterMod.empty() || StartsWithIgnoreCase("findSymbol(", afterMod)) {
                        results.push_back(modPrefix + "findSymbol(");
                    }
                    size_t added = 0;
                    for (const auto& sym : symbols) {
                        if (afterMod.empty() || StartsWithIgnoreCase(sym, afterMod)) {
                            results.push_back(modPrefix + sym);
                            if (++added >= 40) break;
                        }
                    }
                }
            } else {
                for (const auto& mod : modules) {
                    std::string stem = mod;
                    if (stem.size() > 3 && stem.substr(stem.size() - 3) == ".so") stem = stem.substr(0, stem.size() - 3);
                    std::string cand = "dynamic.native." + stem;
                    if (rest.empty() || StartsWithIgnoreCase(cand, token)) {
                        if (std::find(results.begin(), results.end(), cand) == results.end()) {
                            results.push_back(cand);
                        }
                    }
                }
            }
        }
    }

    return results;
}

static std::unordered_map<std::string, std::vector<std::string>> g_exprMembersCache;

static std::string QuoteJsString(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '\\') out += "\\\\";
        else if (c == '"') out += "\\\"";
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else out += c;
    }
    out += "\"";
    return out;
}

static std::vector<std::string> FetchExprMembers(const std::string& expr) {
    auto it = g_exprMembersCache.find(expr);
    if (it != g_exprMembersCache.end()) return it->second;

    std::string script = "JSON.stringify(__getCompletions(" + QuoteJsString(expr) + "))";
    std::string res = EvalOnAgentSync(script);
    auto members = ExtractJsonStringArray(res);
    std::sort(members.begin(), members.end());
    members.erase(std::unique(members.begin(), members.end()), members.end());
    if (!members.empty()) {
        g_exprMembersCache[expr] = members;
    }
    return members;
}

struct CompletionContext {
    size_t tokenStart = 0;
    std::string prefix;
    std::string expr;
    bool isMemberAccess = false;
};

static CompletionContext FindCompletionContext(const std::string& line, size_t pos) {
    CompletionContext ctx;
    if (pos == 0) return ctx;

    // Scan backwards from pos for member prefix
    size_t memberStart = pos;
    while (memberStart > 0) {
        char c = line[memberStart - 1];
        if (isalnum(c) || c == '_' || c == '$') {
            memberStart--;
        } else {
            break;
        }
    }
    std::string memberPrefix = line.substr(memberStart, pos - memberStart);

    // If character immediately before memberStart is a dot '.'
    if (memberStart > 0 && line[memberStart - 1] == '.') {
        // First check if this is part of dynamic.java or dynamic.native
        size_t wordStart = pos;
        while (wordStart > 0) {
            char c = line[wordStart - 1];
            if (isalnum(c) || c == '_' || c == '$' || c == '.') {
                wordStart--;
            } else {
                break;
            }
        }
        std::string fullWord = line.substr(wordStart, pos - wordStart);
        if (fullWord.rfind("dynamic.", 0) == 0) {
            ctx.tokenStart = wordStart;
            ctx.prefix = fullWord;
            ctx.isMemberAccess = false;
            return ctx;
        }

        // Scan expression before the dot
        size_t dotPos = memberStart - 1;
        size_t p = dotPos;
        int paren = 0;
        int bracket = 0;
        while (p > 0) {
            char c = line[p - 1];
            if (c == ')') { paren++; p--; }
            else if (c == '(') {
                if (paren == 0) break;
                paren--; p--;
            }
            else if (c == ']') { bracket++; p--; }
            else if (c == '[') {
                if (bracket == 0) break;
                bracket--; p--;
            }
            else if (paren > 0 || bracket > 0) {
                p--;
            }
            else if (isalnum(c) || c == '_' || c == '$' || c == '.' || c == '"' || c == '\'') {
                p--;
            }
            else {
                break;
            }
        }

        std::string expr = line.substr(p, dotPos - p);
        if (!expr.empty()) {
            ctx.tokenStart = memberStart;
            ctx.prefix = memberPrefix;
            ctx.expr = expr;
            ctx.isMemberAccess = true;
            return ctx;
        }
    }

    // Default: normal word completion
    size_t wordStart = pos;
    while (wordStart > 0) {
        char c = line[wordStart - 1];
        if (isalnum(c) || c == '_' || c == '$' || c == '.') {
            wordStart--;
        } else {
            break;
        }
    }
    ctx.tokenStart = wordStart;
    ctx.prefix = line.substr(wordStart, pos - wordStart);
    ctx.isMemberAccess = false;
    return ctx;
}

static std::vector<std::string> GetCandidatesForContext(const CompletionContext& ctx, bool allowNetwork = true) {
    if (ctx.isMemberAccess) {
        std::vector<std::string> candidates;
        if (!ctx.expr.empty()) {
            auto it = g_exprMembersCache.find(ctx.expr);
            std::vector<std::string> members;
            if (it != g_exprMembersCache.end()) {
                members = it->second;
            } else if (allowNetwork && g_agentFd >= 0) {
                members = FetchExprMembers(ctx.expr);
            }
            for (const auto& m : members) {
                if (ctx.prefix.empty() || StartsWithIgnoreCase(m, ctx.prefix)) {
                    candidates.push_back(m);
                }
            }
        }
        return candidates;
    }
    return GetCandidatesForToken(ctx.prefix);
}

struct RawTermGuard {
    bool active_ = false;

    RawTermGuard() {
        if (isatty(STDIN_FILENO)) {
            if (tcgetattr(STDIN_FILENO, &g_origTermios) == 0) {
                termios raw = g_origTermios;
                cfmakeraw(&raw);
                raw.c_oflag |= OPOST; // Maintain proper \n -> \r\n conversion
                if (tcsetattr(STDIN_FILENO, TCSANOW, &raw) == 0) {
                    active_ = true;
                    g_isRawMode = true;
                }
            }
        }
    }

    ~RawTermGuard() {
        if (active_) {
            tcsetattr(STDIN_FILENO, TCSANOW, &g_origTermios);
            g_isRawMode = false;
        }
    }
};

void EraseMenuLinesLocked() {
    if (g_menuLines > 0) {
        for (int i = 0; i < g_menuLines; i++) {
            std::cout << "\r\n\033[2K";
        }
        std::cout << "\033[" << g_menuLines << "A"; // Move back up to input line
        std::cout << "\r\033[K" << g_currentPrompt << g_currentLine;
        if (g_currentLine.size() > g_currentPos) {
            std::cout << "\033[" << (g_currentLine.size() - g_currentPos) << "D";
        }
        std::cout << std::flush;
        g_menuLines = 0;
    }
}

void ClearMenuLocked() {
    EraseMenuLinesLocked();
    g_menuItems.clear();
    g_selectedMenuIndex = 0;
}

void ComputeGhostTextLocked() {
    g_currentGhost.clear();
    if (g_currentLine.empty() || g_currentPos != g_currentLine.size()) return;

    CompletionContext ctx = FindCompletionContext(g_currentLine, g_currentPos);
    if (ctx.prefix.empty() && !ctx.isMemberAccess) return;

    std::vector<std::string> matches = GetCandidatesForContext(ctx, /*allowNetwork=*/true);
    if (!matches.empty()) {
        std::string cand = matches[0];
        if (cand.size() > ctx.prefix.size()) {
            g_currentGhost = cand.substr(ctx.prefix.size());
        }
    }
}

void RefreshLineLocked() {
    ComputeGhostTextLocked();

    std::cout << "\r\033[K" << g_currentPrompt << g_currentLine;

    // Render faint gray ghost text (\033[90m) if available at end of line
    if (!g_currentGhost.empty() && g_currentPos == g_currentLine.size()) {
        std::cout << "\033[90m" << g_currentGhost << "\033[0m";
        std::cout << "\033[" << g_currentGhost.size() << "D";
    } else if (g_currentLine.size() > g_currentPos) {
        std::cout << "\033[" << (g_currentLine.size() - g_currentPos) << "D";
    }
    std::cout << std::flush;
}

void RenderDropdownMenuLocked(const std::vector<std::string>& candidates, size_t selectedIdx) {
    if (candidates.empty()) {
        ClearMenuLocked();
        return;
    }

    if (&g_menuItems != &candidates) {
        g_menuItems = candidates;
    }

    // Compact list, at most 8 rows, scrolled so the selected item is visible.
    const size_t kMax = 8;
    size_t n = g_menuItems.size();
    if (selectedIdx >= n) selectedIdx = n - 1;
    size_t count = std::min(n, kMax);
    size_t start = 0;
    if (selectedIdx >= count) start = std::min(selectedIdx - count + 1, n - count);
    size_t end = start + count;

    int newLines = static_cast<int>(end - start);
    int prevLines = g_menuLines;

    // Draw dropdown items downwards from the current input line
    for (size_t i = start; i < end; i++) {
        std::cout << "\r\n\033[2K";
        if (i == selectedIdx) {
            std::cout << "  \033[7;36m " << g_menuItems[i] << " \033[0m";  // highlighted
        } else {
            std::cout << "  \033[90m" << g_menuItems[i] << "\033[0m";       // dim
        }
    }
    if (start > 0) std::cout << " \033[2;90m(+" << start << " above)\033[0m";
    if (end < n) std::cout << " \033[2;90m(+" << (n - end) << " more)\033[0m";

    // If previous menu had more lines, clear the remaining stale lines
    int totalLinesDown = newLines;
    if (prevLines > newLines) {
        for (int i = 0; i < (prevLines - newLines); i++) {
            std::cout << "\r\n\033[2K";
            totalLinesDown++;
        }
    }

    // Move cursor straight back UP to the input line
    std::cout << "\033[" << totalLinesDown << "A";

    // Reposition cursor horizontally on input line
    std::cout << "\r" << g_currentPrompt << g_currentLine;
    if (g_currentLine.size() > g_currentPos) {
        std::cout << "\033[" << (g_currentLine.size() - g_currentPos) << "D";
    }
    std::cout << std::flush;

    g_menuLines = newLines;
    g_selectedMenuIndex = static_cast<int>(selectedIdx);
}

// Apply the currently-selected dropdown item to the input line.
void ApplyMenuSelectionLocked() {
    if (g_menuItems.empty()) return;
    if (g_selectedMenuIndex < 0) g_selectedMenuIndex = 0;
    if (g_selectedMenuIndex >= static_cast<int>(g_menuItems.size()))
        g_selectedMenuIndex = static_cast<int>(g_menuItems.size()) - 1;

    std::string choice = g_menuItems[g_selectedMenuIndex];
    std::string suffix = g_currentLine.substr(g_currentPos);
    g_currentLine = g_currentLine.substr(0, g_menuTokenStart) + choice + suffix;
    g_currentPos = g_menuTokenStart + choice.size();

    RefreshLineLocked();
    RenderDropdownMenuLocked(g_menuItems, static_cast<size_t>(g_selectedMenuIndex));
}

std::string FindLongestCommonPrefix(const std::vector<std::string>& list) {
    if (list.empty()) return "";
    std::string prefix = list[0];
    for (size_t i = 1; i < list.size(); i++) {
        size_t j = 0;
        while (j < prefix.size() && j < list[i].size() &&
               tolower(prefix[j]) == tolower(list[i][j])) {
            j++;
        }
        prefix = prefix.substr(0, j);
    }
    return prefix;
}

void HandleTabCompletion() {
    // 1. If dropdown menu is currently active, cycle to next item
    if (g_menuLines > 0 && !g_menuItems.empty()) {
        g_selectedMenuIndex = (g_selectedMenuIndex + 1) % static_cast<int>(g_menuItems.size());
        ApplyMenuSelectionLocked();
        return;
    }

    // 2. Identify current completion context ending at g_currentPos
    CompletionContext ctx = FindCompletionContext(g_currentLine, g_currentPos);
    g_menuTokenStart = ctx.tokenStart;

    if (ctx.prefix.empty() && !ctx.isMemberAccess) {
        std::vector<std::string> basics = {
            "dynamic.java.", "dynamic.native.", "Java.", "Native.", "Trace.", "Debug.", "Memory.", "findclass(\"", "artobject(", "exit"
        };
        RenderDropdownMenuLocked(basics, 0);
        return;
    }

    std::vector<std::string> matches = GetCandidatesForContext(ctx, /*allowNetwork=*/true);
    if (matches.empty()) {
        return;
    }

    if (matches.size() == 1) {
        std::string suffix = g_currentLine.substr(g_currentPos);
        g_currentLine = g_currentLine.substr(0, ctx.tokenStart) + matches[0] + suffix;
        g_currentPos = ctx.tokenStart + matches[0].size();
        RefreshLineLocked();
    } else {
        std::string lcp = FindLongestCommonPrefix(matches);
        if (lcp.size() > ctx.prefix.size()) {
            std::string suffix = g_currentLine.substr(g_currentPos);
            g_currentLine = g_currentLine.substr(0, ctx.tokenStart) + lcp + suffix;
            g_currentPos = ctx.tokenStart + lcp.size();
            RefreshLineLocked();
        }
        RenderDropdownMenuLocked(matches, 0);
    }
}

bool ReadInteractiveLine(std::string& outLine, std::vector<std::string>& history) {
    if (!g_isRawMode) {
        std::cout << g_currentPrompt << std::flush;
        return static_cast<bool>(std::getline(std::cin, outLine));
    }

    {
        std::lock_guard<std::mutex> lk(g_termMutex);
        ClearMenuLocked();
        g_currentLine.clear();
        g_currentPos = 0;
        RefreshLineLocked();
    }

    int historyIndex = static_cast<int>(history.size());
    std::string savedCurrent;

    for (;;) {
        char c = 0;
        ssize_t n = read(STDIN_FILENO, &c, 1);
        if (n <= 0) return false;

        std::lock_guard<std::mutex> lk(g_termMutex);

        if (c == '\r' || c == '\n') {
            if (g_menuLines > 0 && !g_menuItems.empty()) {
                // If dropdown menu is active, pressing Enter confirms the selected completion!
                ApplyMenuSelectionLocked();
                ClearMenuLocked();
                RefreshLineLocked();
                continue;
            }
            ClearMenuLocked();
            std::cout << "\r\n" << std::flush;
            outLine = g_currentLine;
            if (!outLine.empty()) {
                if (history.empty() || history.back() != outLine) {
                    history.push_back(outLine);
                }
            }
            g_currentLine.clear();
            g_currentPos = 0;
            return true;
        }

        if (c == '\t') {
            HandleTabCompletion();
            continue;
        }

        if (c == 3) { // Ctrl+C
            ClearMenuLocked();
            std::cout << "^C\r\n" << std::flush;
            g_currentLine.clear();
            g_currentPos = 0;
            RefreshLineLocked();
            continue;
        }

        if (c == 4) { // Ctrl+D
            ClearMenuLocked();
            if (g_currentLine.empty()) {
                std::cout << "\r\n" << std::flush;
                outLine = "exit";
                return true;
            }
            continue;
        }

        if (c == 127 || c == 8) { // Backspace
            ClearMenuLocked();
            if (g_currentPos > 0) {
                g_currentLine.erase(g_currentPos - 1, 1);
                g_currentPos--;
                RefreshLineLocked();
            }
            continue;
        }

        if (c == 27) { // ANSI Escape Sequence or solitary ESC
            struct pollfd pfd{};
            pfd.fd = STDIN_FILENO;
            pfd.events = POLLIN;
            if (poll(&pfd, 1, 30) <= 0) {
                // Solitary ESC key: dismiss dropdown menu
                ClearMenuLocked();
                RefreshLineLocked();
                continue;
            }

            char seq[3] = {0};
            if (read(STDIN_FILENO, &seq[0], 1) <= 0) continue;
            if (read(STDIN_FILENO, &seq[1], 1) <= 0) continue;

            if (seq[0] == '[') {
                if (seq[1] == 'A') { // Up Arrow
                    if (g_menuLines > 0 && !g_menuItems.empty()) {
                        // Navigate the dropdown menu instead of history.
                        int n = static_cast<int>(g_menuItems.size());
                        g_selectedMenuIndex = (g_selectedMenuIndex - 1 + n) % n;
                        ApplyMenuSelectionLocked();
                    } else if (!history.empty() && historyIndex > 0) {
                        ClearMenuLocked();
                        if (historyIndex == static_cast<int>(history.size())) {
                            savedCurrent = g_currentLine;
                        }
                        historyIndex--;
                        g_currentLine = history[historyIndex];
                        g_currentPos = g_currentLine.size();
                        RefreshLineLocked();
                    }
                } else if (seq[1] == 'B') { // Down Arrow
                    if (g_menuLines > 0 && !g_menuItems.empty()) {
                        // Navigate the dropdown menu instead of history.
                        int n = static_cast<int>(g_menuItems.size());
                        g_selectedMenuIndex = (g_selectedMenuIndex + 1) % n;
                        ApplyMenuSelectionLocked();
                    } else if (historyIndex < static_cast<int>(history.size())) {
                        ClearMenuLocked();
                        historyIndex++;
                        if (historyIndex == static_cast<int>(history.size())) {
                            g_currentLine = savedCurrent;
                        } else {
                            g_currentLine = history[historyIndex];
                        }
                        g_currentPos = g_currentLine.size();
                        RefreshLineLocked();
                    }
                } else if (seq[1] == 'C') { // Right Arrow
                    if (g_menuLines > 0 && !g_menuItems.empty()) {
                        // Accept current completion on Right Arrow
                        ApplyMenuSelectionLocked();
                        ClearMenuLocked();
                        RefreshLineLocked();
                        continue;
                    }
                    ClearMenuLocked();
                    // If at the end of the line and ghost text is visible, accept the ghost text!
                    if (g_currentPos == g_currentLine.size() && !g_currentGhost.empty()) {
                        g_currentLine += g_currentGhost;
                        g_currentPos = g_currentLine.size();
                        RefreshLineLocked();
                    } else if (g_currentPos < g_currentLine.size()) {
                        g_currentPos++;
                        RefreshLineLocked();
                    }
                } else if (seq[1] == 'D') { // Left Arrow
                    ClearMenuLocked();
                    if (g_currentPos > 0) {
                        g_currentPos--;
                        RefreshLineLocked();
                    }
                } else if (seq[1] == 'H') { // Home
                    ClearMenuLocked();
                    g_currentPos = 0;
                    RefreshLineLocked();
                } else if (seq[1] == 'F') { // End
                    ClearMenuLocked();
                    g_currentPos = g_currentLine.size();
                    RefreshLineLocked();
                } else if (seq[1] == '3') { // Delete
                    char t = 0;
                    if (read(STDIN_FILENO, &t, 1) > 0 && t == '~') {
                        ClearMenuLocked();
                        if (g_currentPos < g_currentLine.size()) {
                            g_currentLine.erase(g_currentPos, 1);
                            RefreshLineLocked();
                        }
                    }
                }
            }
            continue;
        }

        // Normal printable characters
        if (static_cast<unsigned char>(c) >= 32) {
            ClearMenuLocked();
            g_currentLine.insert(g_currentPos, 1, c);
            g_currentPos++;
            RefreshLineLocked();
        }
    }
}

static void RunInteractiveSession(const AgentEndpoint& ep) {
    g_agentPort = ep.isUnix ? -1 : ep.port;
    g_agentUnix = ep.isUnix ? ep.unixName : std::string();

    int fd = -1;
    for (int retry = 0; retry < 50; retry++) {
        fd = ConnectEndpoint(ep, 0);   // blocking connect
        if (fd >= 0) break;
        usleep(100 * 1000);
    }

    if (fd < 0) {
        std::cerr << "[!] Failed to connect to agent at " << DescribeEndpoint(ep) << std::endl;
        return;
    }

    if (!ep.isUnix) {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }

    // Fetch dynamic completion data (classes and modules) from agent before launching background receiver
    FetchDynamicCompletions(fd, ep);

    std::cout << "\n========================================================\n"
              << "  ArtPI Interactive QuickJS REPL (Connected to " << DescribeEndpoint(ep) << ")\n"
              << "  Type JS commands (e.g. dynamic.java.<Class>.dumpCode())\n"
              << "  [Ghost Text] autosuggest, [\u2192/Tab] accept, [Tab] menu dropdown.\n"
              << "========================================================\n" << std::endl;

    std::atomic<bool> running{true};
    std::atomic<int64_t> currentSeq{1};
    std::atomic<int64_t> lastCompletedSeq{0};

    // Background thread: continuously receives frames from agent (RESP / EVT / Console)
    std::thread receiverThread([&]() {
        std::vector<uint8_t> rbuf;
        rbuf.reserve(64 * 1024);
        uint8_t buf[4096];

        while (running.load()) {
            ssize_t n = recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) {
                if (running.exchange(false)) {
                    std::lock_guard<std::mutex> lk(g_termMutex);
                    ClearMenuLocked();
                    std::cout << "\r\033[K[!] Connection closed by remote agent\r\n" << std::flush;
                    if (g_isRawMode) {
                        tcsetattr(STDIN_FILENO, TCSANOW, &g_origTermios);
                    }
                    _exit(0);
                }
                break;
            }
            rbuf.insert(rbuf.end(), buf, buf + n);

            while (rbuf.size() >= 4) {
                uint32_t lenBE = 0;
                std::memcpy(&lenBE, rbuf.data(), 4);
                uint32_t frameLen = ntohl(lenBE);
                if (rbuf.size() < 4 + frameLen) break;

                msgpack::Reader reader(rbuf.data() + 4, frameLen);
                msgpack::Value frame;
                if (reader.readValue(frame)) {
                    int64_t t = frame.getInt("t", 0);
                    if (t == 2) {
                        // RESP: command evaluation result
                        int64_t respSeq = frame.getInt("seq", 0);
                        lastCompletedSeq.store(respSeq);
                        bool ok = frame.getBool("ok", false);
                        const msgpack::Value* data = frame.get("data");
                        
                        std::lock_guard<std::mutex> lk(g_termMutex);
                        ClearMenuLocked();
                        if (ok && data) {
                            std::string res = data->getString("result");
                            if (!res.empty() && res != "undefined" && res != "[undefined]") {
                                std::cout << "\r\033[K" << res << "\r\n";
                            }
                        } else {
                            std::string err = frame.getString("err", "error");
                            std::cout << "\r\033[K[!] " << err << "\r\n";
                        }
                        RefreshLineLocked();
                    } else if (t == 3) {
                        // EVT: async event / console log stream
                        std::string ch = frame.getString("ch");
                        const msgpack::Value* data = frame.get("data");
                        std::string text = (data && data->type == msgpack::Type::STR) ? data->str : "";

                        std::lock_guard<std::mutex> lk(g_termMutex);
                        ClearMenuLocked();
                        std::cout << "\r\033[K[" << ch << "] " << text << "\r\n";
                        RefreshLineLocked();
                    }
                }
                rbuf.erase(rbuf.begin(), rbuf.begin() + 4 + frameLen);
            }
        }
    });

    // Enter raw terminal mode for ghost text, tab completion & history
    RawTermGuard termGuard;
    std::vector<std::string> history;
    std::string line;

    while (running.load() && ReadInteractiveLine(line, history)) {
        if (line == "exit" || line == "quit" || line == "q") {
            break;
        }
        if (line == "clear" || line == "cls") {
            std::lock_guard<std::mutex> lk(g_termMutex);
            ClearMenuLocked();
            std::cout << "\033[2J\033[H" << std::flush;   // clear screen, home cursor
            RefreshLineLocked();
            continue;
        }
        if (line.empty()) {
            if (!history.empty()) {
                line = history.back();
                std::lock_guard<std::mutex> lk(g_termMutex);
                std::cout << "\r\033[K" << g_currentPrompt << line << "\r\n" << std::flush;
            } else {
                continue;
            }
        }

        msgpack::Value req = msgpack::Value::makeMap();
        req.set("t", msgpack::Value(1)); // 1 = CMD
        int64_t seq = currentSeq.fetch_add(1);
        req.set("seq", msgpack::Value(seq));
        req.set("cmd", msgpack::Value("eval"));

        msgpack::Value args = msgpack::Value::makeMap();
        args.set("script", msgpack::Value(line));
        req.set("args", args);

        if (!SendMsgpackFrame(fd, req)) {
            std::lock_guard<std::mutex> lk(g_termMutex);
            std::cerr << "\r\033[K[!] Failed to send command\r\n" << std::flush;
            break;
        }

        // Wait briefly for response
        for (int w = 0; w < 50; w++) {
            if (lastCompletedSeq.load() >= seq) break;
            usleep(20 * 1000);
        }
    }

    running.store(false);
    shutdown(fd, SHUT_RDWR);
    close(fd);
    if (receiverThread.joinable()) {
        receiverThread.join();
    }
    std::cout << "\n[*] REPL session closed.\n" << std::endl;
}

} // namespace

namespace {
bool PingFd(int fd, int& outPid, std::string& outPkg) {
    msgpack::Value req = msgpack::Value::makeMap();
    req.set("t", msgpack::Value(1));
    req.set("seq", msgpack::Value(1));
    req.set("cmd", msgpack::Value("ping"));
    if (!SendMsgpackFrame(fd, req)) return false;

    uint32_t lenBE = 0;
    if (recv(fd, &lenBE, 4, MSG_WAITALL) != 4) return false;
    uint32_t frameLen = ntohl(lenBE);
    if (frameLen == 0 || frameLen > 65536) return false;

    std::vector<uint8_t> buf(frameLen);
    if (recv(fd, buf.data(), frameLen, MSG_WAITALL) != static_cast<ssize_t>(frameLen)) return false;

    msgpack::Reader reader(buf.data(), frameLen);
    msgpack::Value resp;
    if (!reader.readValue(resp)) return false;
    const msgpack::Value* data = resp.get("data");
    if (!data) return false;
    outPid = static_cast<int>(data->getInt("pid", 0));
    outPkg = data->getString("pkg", "");
    return true;
}
} // namespace

bool ProbeAgentAlive(const AgentEndpoint& ep, int& outPid, std::string& outPkg) {
    int fd = ConnectEndpoint(ep, 80);   // 80ms timeout
    if (fd < 0) return false;
    bool ok = PingFd(fd, outPid, outPkg);
    close(fd);
    return ok;
}

bool ProbeAgentAlive(int port, int& outPid, std::string& outPkg) {
    AgentEndpoint ep;
    ep.isUnix = false;
    ep.port = port;
    return ProbeAgentAlive(ep, outPid, outPkg);
}

int ScanAndFindAgentPort(int startPort, int endPort, int targetPid, const std::string& targetPkg,
                        int& outPid, std::string& outPkg) {
    for (int p = startPort; p <= endPort; p++) {
        int pid = 0;
        std::string pkg;
        if (ProbeAgentAlive(p, pid, pkg)) {
            if (targetPid > 0 && pid == targetPid) {
                outPid = pid;
                outPkg = pkg;
                return p;
            }
            if (!targetPkg.empty() && pkg == targetPkg) {
                outPid = pid;
                outPkg = pkg;
                return p;
            }
            if (targetPid <= 0 && targetPkg.empty()) {
                outPid = pid;
                outPkg = pkg;
                return p;
            }
        }
    }
    return -1;
}

std::string DescribeEndpoint(const AgentEndpoint& ep) {
    if (ep.isUnix) return "@" + ep.unixName;
    return "127.0.0.1:" + std::to_string(ep.port);
}

bool DiscoverAgent(int targetPid, const std::string& targetPkg,
                   int startPort, int endPort,
                   AgentEndpoint& outEp, int& outPid, std::string& outPkg) {
    // 1) Prefer the abstract AF_UNIX socket (name is derived from the PID and
    //    works even when the app has no INTERNET permission / AF_INET is denied).
    if (targetPid > 0) {
        AgentEndpoint uep;
        uep.isUnix = true;
        uep.unixName = "artpi_agent_" + std::to_string(targetPid);
        int pid = 0;
        std::string pkg;
        if (ProbeAgentAlive(uep, pid, pkg) &&
            (targetPkg.empty() || pkg == targetPkg)) {
            outEp = uep;
            outPid = pid;
            outPkg = pkg;
            return true;
        }
    }

    // 2) Fall back to a TCP port scan.
    int pid = 0;
    std::string pkg;
    int p = ScanAndFindAgentPort(startPort, endPort, targetPid, targetPkg, pid, pkg);
    if (p > 0) {
        AgentEndpoint tep;
        tep.isUnix = false;
        tep.port = p;
        outEp = tep;
        outPid = pid;
        outPkg = pkg;
        return true;
    }
    return false;
}

void RunInteractiveRepl(const AgentEndpoint& ep) {
    RunInteractiveSession(ep);
}

void RunInteractiveRepl(int port) {
    AgentEndpoint ep;
    ep.isUnix = false;
    ep.port = port;
    RunInteractiveSession(ep);
}

bool EvalScript(const AgentEndpoint& ep, const std::string& script, std::string& outResult, std::string& outErr) {
    int fd = ConnectEndpoint(ep, 1000);
    if (fd < 0) {
        outErr = "Failed to connect to agent at " + DescribeEndpoint(ep);
        return false;
    }
    if (!ep.isUnix) {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }

    msgpack::Value req = msgpack::Value::makeMap();
    req.set("t", msgpack::Value(1)); // 1 = CMD
    req.set("seq", msgpack::Value(1));
    req.set("cmd", msgpack::Value("eval"));
    msgpack::Value args = msgpack::Value::makeMap();
    args.set("script", msgpack::Value(script));
    req.set("args", args);

    if (!SendMsgpackFrame(fd, req)) {
        close(fd);
        outErr = "Failed to send eval frame";
        return false;
    }

    std::vector<uint8_t> rbuf;
    rbuf.reserve(64 * 1024);
    uint8_t buf[4096];
    bool gotResp = false;
    bool success = false;

    // Timeout loop up to 10 seconds
    for (int retry = 0; retry < 500; retry++) {
        struct pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        int pr = poll(&pfd, 1, 20);
        if (pr > 0) {
            ssize_t n = recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            rbuf.insert(rbuf.end(), buf, buf + n);

            while (rbuf.size() >= 4) {
                uint32_t lenBE = 0;
                std::memcpy(&lenBE, rbuf.data(), 4);
                uint32_t frameLen = ntohl(lenBE);
                if (rbuf.size() < 4 + frameLen) break;

                msgpack::Reader reader(rbuf.data() + 4, frameLen);
                msgpack::Value frame;
                if (reader.readValue(frame)) {
                    int64_t t = frame.getInt("t", 0);
                    if (t == 2) { // RESP
                        int64_t respSeq = frame.getInt("seq", 0);
                        if (respSeq == 1) {
                            success = frame.getBool("ok", false);
                            if (success) {
                                const msgpack::Value* data = frame.get("data");
                                outResult = data ? data->getString("result") : "";
                            } else {
                                outErr = frame.getString("err", "evaluation error");
                            }
                            gotResp = true;
                            break;
                        }
                    } else if (t == 3) {
                        // EVT: asynchronous output / console stream
                        std::string ch = frame.getString("ch");
                        const msgpack::Value* data = frame.get("data");
                        std::string text = (data && data->type == msgpack::Type::STR) ? data->str : "";
                        std::cout << "[" << ch << "] " << text << "\n";
                    }
                }
                rbuf.erase(rbuf.begin(), rbuf.begin() + 4 + frameLen);
            }
            if (gotResp) break;
        }
    }
    close(fd);
    if (!gotResp && outErr.empty()) {
        outErr = "Timed out waiting for agent evaluation response";
    }
    return gotResp && success;
}

}} // namespace artpi::injector
