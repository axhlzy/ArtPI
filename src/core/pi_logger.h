//
// pi_logger.h - pluggable logging dispatch (§10 LogSink & Socket Stream)
//
// All framework output (PI_LOGx, PI_VMTrace, smali dumps) flows through
// PI::Logger. Default destination is Android logcat; a host (or the future
// CLI daemon) can install a LogSink to redirect everything - e.g. pump
// trace data into a Unix socket - and mute logcat entirely for stealth.
//
// Thread safety: all setters / log() are internally synchronized.
//

#ifndef PI_LOGGER_H
#define PI_LOGGER_H

#include <jni.h>
#include <string>
#include <functional>

#if defined(__GNUC__) || defined(__clang__)
#define PI_LOGGER_EXPORT __attribute__((visibility("default")))
#else
#define PI_LOGGER_EXPORT
#endif

namespace PI {

// 宿主工程常见 `#define DEBUG` 等宏会污染枚举名 — 临时屏蔽后恢复
#pragma push_macro("DEBUG")
#pragma push_macro("INFO")
#pragma push_macro("WARN")
#pragma push_macro("ERROR")
#pragma push_macro("TRACE")
#undef DEBUG
#undef INFO
#undef WARN
#undef ERROR
#undef TRACE

enum class LogLevel : int {
    DEBUG = 0,
    INFO  = 1,
    WARN  = 2,
    ERROR = 3,
    TRACE = 4,   // 专门的执行流 Trace 数据通道 (PI_VMTrace 等)
};

#pragma pop_macro("TRACE")
#pragma pop_macro("ERROR")
#pragma pop_macro("WARN")
#pragma pop_macro("INFO")
#pragma pop_macro("DEBUG")

// 抽象日志接收器：级别、标签、格式化后的文本
using LogSink = std::function<void(LogLevel level, const char* tag, const char* message)>;

class PI_LOGGER_EXPORT Logger {
public:
    /// 注册自定义日志接收器 (每条日志都会回调; 不再写 logcat 除非 logcat 镜像开启)
    static void setLogSink(LogSink sink);

    /// 重置回默认行为 (无 sink + logcat 镜像开启)
    static void resetToDefault();

    /// 控制是否向系统 logcat 镜像输出 (CLI 隐蔽注入时可设 false 彻底静音)
    static void setLogcatEnabled(bool enabled);
    static bool logcatEnabled();

    /// 最低输出级别过滤 (默认 DEBUG 全量)
    static void setMinLevel(LogLevel level);
    static LogLevel minLevel();

    /// 核心输出函数 (printf 风格)
    static void log(LogLevel level, const char* tag, const char* fmt, ...)
#if defined(__GNUC__)
        __attribute__((format(printf, 3, 4)))
#endif
        ;

    /// 内部分发 (已格式化): sink 回调 + 可选 logcat 镜像
    static void dispatch(LogLevel level, const char* tag, const std::string& msg);
};

} // namespace PI

#endif // PI_LOGGER_H
