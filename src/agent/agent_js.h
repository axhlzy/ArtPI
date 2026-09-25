//
// agent_js.h - QuickJS Runtime container & ArtPI Native Bridge
//
#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <jni.h>

namespace artpi { namespace agent {

// Initialize QuickJS runtime, context, and bind Java/Native/Trace/Debug/Memory APIs
bool InitJs(JNIEnv* env);

// Evaluate JS script string, returns result string (or error description)
std::string EvalJs(const std::string& script, const char* filename = "eval.js");

// Cleanup and destroy JS runtime
void DestroyJs();

}} // namespace artpi::agent
