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

// Inject soPath into pid via ptrace (PTRACE_SEIZE + PTRACE_INTERRUPT preferred).
// If pauseMainThread is true, the target's main thread is redirected into
// artpi_gate_trampoline (paused) before detaching, waiting for Process.resume().
bool InjectLibrary(pid_t pid, const char *soPath, const char *apkDirPrefix,
                   std::string &err, bool pauseMainThread = false);

// Inject soPath into pid WITHOUT ptrace using /proc/<pid>/mem 2-stage trampoline.
// Ideal when target process has anti-debugging (TracerPid != 0) or --no-ptrace is specified.
bool InjectLibraryNoPtrace(pid_t pid, const char *soPath, const char *apkDirPrefix, std::string &err);

