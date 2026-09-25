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

