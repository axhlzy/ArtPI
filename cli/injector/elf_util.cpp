#include "elf_util.h"

#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <elf.h>

// The kernel appends " (deleted)" to /proc/<pid>/maps for a mapping whose
// backing file was unlinked or replaced (e.g. our payload overwritten with
// O_TRUNC while the previous agent was still mapped). Strip it, otherwise
// basename matching (IsLibraryMapped) misses the live mapping and the injector
// re-deploys over a file that is still mapped.
static void StripDeletedSuffix(char *path) {
    static const char kSuffix[] = " (deleted)";
    const size_t slen = sizeof(kSuffix) - 1;
    size_t plen = strlen(path);
    if (plen >= slen && strcmp(path + plen - slen, kSuffix) == 0) {
        path[plen - slen] = '\0';
    }
}

bool GetModules(pid_t pid, std::vector<Module> &out) {
    out.clear();
    char mapsPath[64];
    snprintf(mapsPath, sizeof(mapsPath), "/proc/%d/maps", (int) pid);
    FILE *f = fopen(mapsPath, "r");
    if (!f) return false;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        unsigned long long start = 0, end = 0;
        if (sscanf(line, "%llx-%llx", &start, &end) != 2) continue;
        char *p = strchr(line, '/');
        if (!p) continue; // anonymous / [vdso] style entries
        p[strcspn(p, "\r\n")] = 0;
        StripDeletedSuffix(p);
        bool merged = false;
        for (auto &m : out) {
            if (m.path == p) {
                if (start < m.base) m.base = start;
                if (end > m.end) m.end = end;
                merged = true;
                break;
            }
        }
        if (!merged) out.push_back(Module{start, end, p});
    }
    fclose(f);
    return true;
}

const Module *FindModuleByBasename(const std::vector<Module> &mods, const char *basename) {
    for (const auto &m : mods) {
        const char *bn = strrchr(m.path.c_str(), '/');
        bn = bn ? bn + 1 : m.path.c_str();
        if (strcmp(bn, basename) == 0) return &m;
    }
    return nullptr;
}

bool GetMappings(pid_t pid, std::vector<Mapping> &out) {
    out.clear();
    char mapsPath[64];
    snprintf(mapsPath, sizeof(mapsPath), "/proc/%d/maps", (int) pid);
    FILE *f = fopen(mapsPath, "r");
    if (!f) return false;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        unsigned long long start = 0, end = 0;
        if (sscanf(line, "%llx-%llx", &start, &end) != 2) continue;
        char *p = strchr(line, '/');
        if (!p) continue;
        p[strcspn(p, "\r\n")] = 0;
        StripDeletedSuffix(p);
        out.push_back(Mapping{start, end, p});
    }
    fclose(f);
    return true;
}

uint64_t ElfSymbolOffset(const char *elfPath, std::initializer_list<const char *> names) {
    int fd = open(elfPath, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    struct stat st{};
    if (fstat(fd, &st) != 0 || st.st_size < (off_t) sizeof(Elf64_Ehdr)) { close(fd); return 0; }
    std::vector<uint8_t> buf((size_t) st.st_size);
    ssize_t got = pread(fd, buf.data(), buf.size(), 0);
    close(fd);
    if (got != (ssize_t) buf.size()) return 0;

    const auto *ehdr = (const Elf64_Ehdr *) buf.data();
    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0 || ehdr->e_ident[EI_CLASS] != ELFCLASS64)
        return 0;
    if (ehdr->e_shoff == 0 || ehdr->e_shentsize != sizeof(Elf64_Shdr)) return 0;
    if (ehdr->e_shoff + (uint64_t) ehdr->e_shnum * ehdr->e_shentsize > buf.size()) return 0;

    const auto *shdrs = (const Elf64_Shdr *) (buf.data() + ehdr->e_shoff);
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (shdrs[i].sh_type != SHT_DYNSYM) continue;
        if (shdrs[i].sh_link >= (uint32_t) ehdr->e_shnum) continue;
        const Elf64_Shdr &strtab = shdrs[shdrs[i].sh_link];
        if (shdrs[i].sh_offset + shdrs[i].sh_size > buf.size()) continue;
        if (strtab.sh_offset + strtab.sh_size > buf.size()) continue;
        const auto *syms = (const Elf64_Sym *) (buf.data() + shdrs[i].sh_offset);
        size_t nsyms = shdrs[i].sh_size / sizeof(Elf64_Sym);
        const char *strs = (const char *) (buf.data() + strtab.sh_offset);
        for (const char *want : names) {
            for (size_t s = 0; s < nsyms; s++) {
                if (syms[s].st_value == 0 || syms[s].st_name == 0) continue;
                if (syms[s].st_name >= strtab.sh_size) continue;
                if (strcmp(strs + syms[s].st_name, want) == 0) return syms[s].st_value;
            }
        }
        break;
    }
    return 0;
}

#include <dirent.h>

pid_t FindPidByPackageName(const std::string& pkgName) {
    DIR* dir = opendir("/proc");
    if (!dir) return -1;

    struct dirent* ent = nullptr;
    while ((ent = readdir(dir)) != nullptr) {
        if (ent->d_type != DT_DIR) continue;
        char* endp = nullptr;
        long pid = strtol(ent->d_name, &endp, 10);
        if (*endp != '\0' || pid <= 0) continue;

        char path[64];
        snprintf(path, sizeof(path), "/proc/%ld/cmdline", pid);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;

        char cmd[256] = {0};
        ssize_t n = read(fd, cmd, sizeof(cmd) - 1);
        close(fd);
        if (n <= 0) continue;

        if (pkgName == cmd) {
            closedir(dir);
            return static_cast<pid_t>(pid);
        }
    }
    closedir(dir);
    return -1;
}

