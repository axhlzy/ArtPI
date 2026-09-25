//
// agent_net.h - Agent TCP server for CLI communication (MessagePack frame based)
// Framing: [4-byte big-endian length][MessagePack binary payload]
//
#pragma once

#include <string>
#include <vector>
#include <functional>
#include <cstdint>
#include "../engine/mpack/mpack.h"

namespace artpi { namespace agent {

using MessageHandler = std::function<msgpack::Value(const msgpack::Value& req)>;

// Start the agent server on localhost (tries port base 27183..27190)
bool StartServer(MessageHandler handler);

// Broadcast an event to connected client (e.g. log, trace, debug)
void BroadcastEvent(const std::string& channel, const msgpack::Value& data);

// Send console/log text line
void BroadcastLog(const char* channel, const std::string& text);

// Active client connection count
int GetActiveClientCount();

// Bound listening port, -1 if not listening
int GetServerPort();

// Abstract AF_UNIX socket name when AF_INET is unavailable (nullptr if TCP).
const char* GetUnixSocketName();

// Current client session fd handling request on this thread (-1 if none)
int GetCurrentClientFd();
void SetCurrentClientFd(int fd);

// Stop the server
void StopServer();

}} // namespace artpi::agent
