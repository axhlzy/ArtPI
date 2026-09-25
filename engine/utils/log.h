//
// Created by canyie on 2020/2/9.
//

#ifndef PINE_LOG_H
#define PINE_LOG_H

#include <android/log.h>
#include <cstdlib>

#ifndef LOG_TAG
#define LOG_TAG "Pine"
#endif

#ifndef LOGV
#define LOGV(...) __android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__)
#endif
#ifndef LOGD
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#endif
#ifndef LOGI
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#endif
#ifndef LOGW
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#endif
#ifndef LOGE
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif
#ifndef LOGF
#define LOGF(...) __android_log_print(ANDROID_LOG_FATAL, LOG_TAG, __VA_ARGS__)
#endif

#define FATAL(...) \
do {\
LOGF(__VA_ARGS__);\
LOGF("Aborting...");\
abort(); \
} while(false)

#define CHECK(cond, ...) \
do { \
    if (UNLIKELY(!(cond))) {\
        LOGF("%s#%d: Check failed: %s", __FILE__, __LINE__, #cond);\
        FATAL(__VA_ARGS__); \
    }\
} while(false)

#define CHECK_EQ(a, b, ...) CHECK((a) == (b), __VA_ARGS__)


#endif //PINE_LOG_H
