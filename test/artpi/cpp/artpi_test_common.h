//
// artpi_test_common.h - shared helpers for the ArtPI native-API test suite
//
#pragma once

#include <jni.h>
#include <android/log.h>

#include <map>
#include <mutex>
#include <string>

#include "ArtPI.h"

#define TEST_LOG_TAG "ArtPI_Test"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TEST_LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TEST_LOG_TAG, __VA_ARGS__)

namespace artpi_test {

// Java UTF-8 string -> std::string ("" on null).
std::string JStr(JNIEnv* env, jstring s);

// "com.artpi.test.Target" -> "com/artpi/test/Target"
std::string ToSlash(std::string s);

// Register a live hook handle and return a >0 id (or -1 on invalid handle).
int Store(PI::HookHandle h);

// Unhook / bulk-unhook / count via the shared handle registry.
bool Unhook(int id);
int UnhookAll();
int CountHandles();

// PI::resolve from JNI strings (class name dots are normalized).
PI::Method Resolve(JNIEnv* env, jstring cls, jstring name, jstring sig);

} // namespace artpi_test
