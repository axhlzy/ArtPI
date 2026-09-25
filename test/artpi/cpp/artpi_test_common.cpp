//
// artpi_test_common.cpp - shared helpers for the ArtPI native-API test suite
//
#include "artpi_test_common.h"

namespace artpi_test {

namespace {
std::mutex g_mu;
std::map<int, PI::HookHandle> g_handles;
int g_nextHandle = 1;
} // namespace

std::string JStr(JNIEnv* env, jstring s) {
    if (!s) return "";
    const char* c = env->GetStringUTFChars(s, nullptr);
    std::string r = c ? c : "";
    if (c) env->ReleaseStringUTFChars(s, c);
    return r;
}

std::string ToSlash(std::string s) {
    for (char& c : s) if (c == '.') c = '/';
    return s;
}

int Store(PI::HookHandle h) {
    if (!h.isValid()) return -1;
    std::lock_guard<std::mutex> lk(g_mu);
    int id = g_nextHandle++;
    g_handles.emplace(id, std::move(h));
    return id;
}

bool Unhook(int id) {
    std::lock_guard<std::mutex> lk(g_mu);
    auto it = g_handles.find(id);
    if (it == g_handles.end()) return false;
    bool ok = it->second.unhook();
    g_handles.erase(it);
    LOGI("unhook id=%d -> %d", id, (int) ok);
    return ok;
}

int UnhookAll() {
    std::lock_guard<std::mutex> lk(g_mu);
    int n = 0;
    for (auto& kv : g_handles) {
        if (kv.second.unhook()) n++;
    }
    g_handles.clear();
    return n;
}

int CountHandles() {
    std::lock_guard<std::mutex> lk(g_mu);
    return (int) g_handles.size();
}

PI::Method Resolve(JNIEnv* env, jstring cls, jstring name, jstring sig) {
    std::string c = ToSlash(JStr(env, cls));
    std::string n = JStr(env, name);
    std::string s = JStr(env, sig);
    return PI::resolve(env, c, n, s);
}

} // namespace artpi_test
