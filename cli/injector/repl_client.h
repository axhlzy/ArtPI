//
// repl_client.h - Embedded interactive REPL client for artpi-cli
// Connects to local agent (AF_UNIX abstract socket preferred, TCP fallback),
// sends JS eval commands, streams console/logs.
//
#pragma once

#include <string>

namespace artpi { namespace injector {

// Transport locator for a running agent.
//   - Agent server prefers an abstract AF_UNIX socket "@artpi_agent_<pid>"
//     (always available, even for apps without android.permission.INTERNET),
//     and falls back to TCP 127.0.0.1:<port> otherwise.
struct AgentEndpoint {
    bool isUnix = false;
    int port = -1;            // valid when !isUnix
    std::string unixName;     // abstract socket name (no leading NUL) when isUnix
};

// Probes whether an agent is currently listening on port (TCP).
// If alive, populates outPid and outPkg from ping response.
bool ProbeAgentAlive(int port, int& outPid, std::string& outPkg);

// Probes an arbitrary endpoint (AF_UNIX or TCP).
bool ProbeAgentAlive(const AgentEndpoint& ep, int& outPid, std::string& outPkg);

// Scans port range [startPort..endPort]. If an agent matching targetPid or targetPkg is found,
// returns the bound port, otherwise returns -1.
int ScanAndFindAgentPort(int startPort, int endPort, int targetPid, const std::string& targetPkg,
                        int& outPid, std::string& outPkg);

// Discovers a live agent for targetPid/targetPkg, preferring AF_UNIX (needs a known PID)
// over a TCP port scan. Returns true and fills outEp/outPid/outPkg on success.
bool DiscoverAgent(int targetPid, const std::string& targetPkg,
                   int startPort, int endPort,
                   AgentEndpoint& outEp, int& outPid, std::string& outPkg);

// Human-readable description, e.g. "@artpi_agent_1234" or "127.0.0.1:20700".
std::string DescribeEndpoint(const AgentEndpoint& ep);

// Starts interactive REPL session connected to the given endpoint.
// Blocks until user types 'exit' or session terminates.
void RunInteractiveRepl(const AgentEndpoint& ep);

// Back-compat: connect over TCP to 127.0.0.1:port.
void RunInteractiveRepl(int port);

// Runs a single evaluation command against the endpoint and returns result or error.
bool EvalScript(const AgentEndpoint& ep, const std::string& script, std::string& outResult, std::string& outErr);

}} // namespace artpi::injector
