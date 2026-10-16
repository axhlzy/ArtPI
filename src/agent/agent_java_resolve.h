//
// agent_java_resolve.h - Class & Method resolution, classloader enumeration & metadata
//
#pragma once

#include <jni.h>
#include <string>
#include <vector>

extern "C" {
#include "../../engine/qjs/quickjs/quickjs.h"
}

namespace artpi { namespace agent {

// Pattern matcher with support for wildcard (*, ?), pipe union (a|b), and substring matching
bool MatchPatternSubstr(const std::string& str, const std::string& pattern);

// Format ART method modifiers (public static final ...)
std::string FormatModifiers(uint32_t f);

// Fast in-memory DEX candidate class pre-scanner
std::vector<std::string> FastScanCandidateClasses(JNIEnv* env,
                                                  const std::string& classPattern,
                                                  const std::string& methodPattern,
                                                  bool singleKeywordMode);

// Register Java resolve APIs (findClass, findMethod, listMethods, findMethods, etc.)
void RegisterJavaResolveApis(JSContext* ctx, JSValue global, JSValue java);

}} // namespace artpi::agent
