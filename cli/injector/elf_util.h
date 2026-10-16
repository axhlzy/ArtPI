//
// elf_util.h - ELF and /proc/<pid>/maps utilities for ArtPI arm64 Android injector
//
#pragma once
#include <cstdint>
#include <initializer_list>
#include <string>
#include <sys/types.h>
#include <vector>

struct Module {
    uint64_t base = 0; // lowest mapping start for this file
    uint64_t end = 0;  // highest mapping end
    std::string path;  // on-disk path as it appears in maps
};

// A single raw /proc/<pid>/maps line (no merging). Needed for apk-backed mappings
struct Mapping {
    uint64_t start = 0;
    uint64_t end = 0;
    std::string path;
};

// Parse /proc/<pid>/maps, merging all mappings of the same file into one Module.
bool GetModules(pid_t pid, std::vector<Module> &out);

// Parse /proc/<pid>/maps into raw per-line mappings (file-backed lines only).
bool GetMappings(pid_t pid, std::vector<Mapping> &out);

// Find a module by file basename ("libart.so", "linker64", ...). nullptr when absent.
const Module *FindModuleByBasename(const std::vector<Module> &mods, const char *basename);

// Resolve a symbol's file offset (st_value for ET_DYN) by parsing the ELF at elfPath.
uint64_t ElfSymbolOffset(const char *elfPath, std::initializer_list<const char *> names);

// Find process PID by Android package name (inspects /proc/<pid>/cmdline)
pid_t FindPidByPackageName(const std::string& pkgName);

// Resolve the foreground (top-resumed Activity) app's PID, package name, and activity component.
bool FindTopActivityApp(pid_t& outPid, std::string& outPkg, std::string& outActivity);

// Return TracerPid from /proc/<pid>/status (0 if not traced, >0 if traced by another process).
pid_t GetTracerPid(pid_t pid);

// True once /proc/<pid>/attr/current has left the "zygote" SELinux domain.
bool IsAppSpecialized(pid_t pid);

// Force-stop pkgName, launch its main Activity, catch the new process at birth
// (via LOG_ID_EVENTS am_proc_start + /proc fast poll), and wait until specialized.
bool SpawnAndWatchPackage(const std::string& pkgName, pid_t& outPid, std::string& err);

// Wait for a newly started process whose cmdline or comm matches `procPattern`
// (case-insensitive substring or wildcard, e.g. "dex2oat" or "com.example.app").
bool WaitForNewProcessByName(const std::string& procPattern, pid_t& outPid,
                             std::string& outName, std::string& err);




