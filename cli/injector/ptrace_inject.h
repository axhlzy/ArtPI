//
// ptrace_inject.h - ptrace-based remote dlopen injector for arm64 Android (runs as root).
//
#pragma once
#include <string>
#include <sys/types.h>

// True when a module with the given basename is currently mapped in pid.
bool IsLibraryMapped(pid_t pid, const char *basename);

// Wait until the process can host a remote dlopen: linker64+libc mapped AND a
// valid caller module exists.
bool WaitForEarlyWindow(pid_t pid, const char *apkDirPrefix, int timeoutMs);

// Inject soPath into pid.
// Caller module lookup order (generic App support):
//   1. App's own APK file mapping with ELF magic base
//   2. Any loaded native library belonging to the app (/data/app/...)
//   3. Fallback to any app-namespace .so mapped with ELF magic
bool InjectLibrary(pid_t pid, const char *soPath, const char *apkDirPrefix, std::string &err);
