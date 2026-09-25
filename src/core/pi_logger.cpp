//
// pi_logger.cpp - pluggable logging dispatch implementation
//

#include "pi_logger.h"
#include <android/log.h>
#include <cstdarg>
#include <cstdio>
#include <mutex>

namespace PI {

namespace {
    std::mutex g_mutex;
    LogSink g_sink;                 // 可选自定义接收器
    bool g_logcatEnabled = true;    // logcat 镜像开关
    LogLevel g_minLevel = LogLevel::DEBUG;

    int androidPriority(LogLevel level) {
        switch (level) {
            case LogLevel::DEBUG: return ANDROID_LOG_DEBUG;
            case LogLevel::INFO:  return ANDROID_LOG_INFO;
            case LogLevel::WARN:  return ANDROID_LOG_WARN;
            case LogLevel::ERROR: return ANDROID_LOG_ERROR;
            case LogLevel::TRACE: return ANDROID_LOG_VERBOSE;
            default:              return ANDROID_LOG_INFO;
        }
    }
} // namespace

void Logger::setLogSink(LogSink sink) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_sink = std::move(sink);
}

void Logger::resetToDefault() {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_sink = nullptr;
    g_logcatEnabled = true;
    g_minLevel = LogLevel::DEBUG;
}

void Logger::setLogcatEnabled(bool enabled) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_logcatEnabled = enabled;
}

bool Logger::logcatEnabled() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_logcatEnabled;
}

void Logger::setMinLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_minLevel = level;
}

LogLevel Logger::minLevel() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_minLevel;
}

void Logger::log(LogLevel level, const char* tag, const char* fmt, ...) {
    if (static_cast<int>(level) < static_cast<int>(minLevel())) return;

    char msgBuf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(msgBuf, sizeof(msgBuf), fmt, args);
    va_end(args);
    dispatch(level, tag, msgBuf);
}

void Logger::dispatch(LogLevel level, const char* tag, const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_sink) {
        g_sink(level, tag ? tag : "ArtPI", msg.c_str());
    }
    if (g_logcatEnabled) {
        __android_log_print(androidPriority(level), tag ? tag : "ArtPI", "%s",
                            msg.c_str());
    }
}

} // namespace PI
