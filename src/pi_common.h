//
// pi_common.h - Common definitions for PI framework
//

#ifndef PI_COMMON_H
#define PI_COMMON_H

#include <jni.h>
#include <android/log.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <sstream>

#include "core/pi_logger.h"

#define PI_TAG "PI_Framework"
// §10: 全部框架日志走 PI::Logger (可插拔 LogSink / logcat 镜像开关)
#define PI_LOGI(...) ::PI::Logger::log(::PI::LogLevel::INFO,  PI_TAG, __VA_ARGS__)
#define PI_LOGW(...) ::PI::Logger::log(::PI::LogLevel::WARN,  PI_TAG, __VA_ARGS__)
#define PI_LOGE(...) ::PI::Logger::log(::PI::LogLevel::ERROR, PI_TAG, __VA_ARGS__)
#define PI_LOGD(...) ::PI::Logger::log(::PI::LogLevel::DEBUG, PI_TAG, __VA_ARGS__)

namespace pine::art {
    class ArtMethod;
}

namespace PI {
    using ArtMethod = pine::art::ArtMethod;
}

#endif // PI_COMMON_H
