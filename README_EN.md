# ArtPI (ART Process Instrumentation)

[English](README_EN.md) | [中文](README.md)

> A high-performance native dynamic instrumentation and reverse engineering toolkit for the Android ART runtime.  
> Featuring Java method hooking, Smali disassembly, **on-the-fly zero-OOM Java source decompilation via embedded JADX CLI**, heap instance enumeration (`choose`), Dalvik bytecode emulation sandbox (step-in, mock return values, exception interception), seamless cross-layer Java↔Native unified tracing, and an interactive **in-process QuickJS REPL** with chainable dynamic proxies, packaged into a self-contained multi-payload binary with ptrace remote injection.

Target Platform: **Android 7.0 ~ 15 (arm64-v8a)**, root privileges required for process injection.

### Test Benchmark Platform

| Specification | Details / Description |
|---|---|
| **Device Model** | Google Pixel 6 (`oriole`) |
| **Operating System** | Android 13 (Tiramisu, API Level 33) |
| **Build ID** | `TP1A.220624.021` |
| **Linux Kernel** | `5.10.107-android13-4-00005-ge05ae1680b1c-ab8715050` |
| **Root Environment** | APatch (Kernel Patch, SuperUser v11039) / Magisk |

---

## 1. Core Capabilities

| Feature | Description |
|---|---|
| **Java Method Hooking** | `PI::resolve(...).hook(cb)` with full `frame[0]` argument read/write, `setResult` return value tampering, and `invokeOriginal` calls; supports class-wide `hookall` |
| **High-Speed Java Decompilation** | Ultra-fast single-DEX memory extraction paired with an embedded JADX CLI execution sandbox for sub-second, **zero-OOM decompilation of individual classes and methods** (`.disassembly()` / `.decompile()`) |
| **Smali Disassembly** | Direct in-memory parsing of runtime `CodeItem` structures (StandardDex and CompactDex) to output formatted Smali opcodes and register states |
| **Heap Instance Enumeration (`choose`)** | Similar to Frida's `Java.choose`: dual-mode scanning supporting high-speed JVMTI iteration with fallback to pure native ART heap space physical memory sweeping |
| **Bytecode Sandbox & Emulation** | Embedded nmmvm interpreter for bytecode replay, supporting single-stepping, `StepIn` recursive interpretation, return value mocking, and exception interception |
| **Unified Cross-Layer Tracing** | Full-stack tracing: Dalvik bytecode execution seamlessly delegates to Frida-Gum and QBDI when hitting JNI boundaries, rendering a continuous cross-layer call tree |
| **Dynamic Reflective Proxies** | `artobject(addr)` wraps live heap instances into global references with chainable member calls, property access, and interactive REPL Tab completions |
| **Self-Contained Multi-Payload Packing** | A single `artpi-cli` binary encapsulates the injector ELF, XZ-compressed `libartpi_agent.so`, and deflated `jadxcli.jar` (~10MB total), auto-extracting upon launch |
| **Built-in QuickJS REPL** | Direct terminal interaction inside the target process with dynamic proxy trees (`dynamic.java.*`, `dynamic.native.*`), eliminating script compilation overhead |

---

## 2. Architecture Overview

```text
┌────────────────────────────────────────────────────────────────────────┐
│ Host Interactive Layer (Host / adb shell terminal)                     │
│ Interactive REPL, single-line evaluation (-e), script execution (-f)   │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Multi-Payload Chained Package (Self-contained)
┌───────────────────────────────────▼────────────────────────────────────┐
│ artpi-cli (arm64 root standalone executable, ~10 MB)                   │
│   [Injector ELF][libartpi_agent.so.xz][PPAYLOAD][jadxcli.jar][PJADXJAR]│
│   • Auto-extracts jadxcli.jar to /data/local/tmp (0666)                │
│   • Auto-decompresses agent SO to app cache -> ptrace remote injection │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Injected into target App process
┌───────────────────────────────────▼────────────────────────────────────┐
│ libartpi_agent.so  (Linked with libartpi_static.a + QuickJS + Server)  │
│   PI::init -> QuickJS runtime -> TCP Agent Server (20700..20800)       │
│   • dynamic.java / dynamic.native chainable proxies                    │
│   • Single-DEX in-memory dump + dalvikvm isolated JADX execution       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│ libartpi_static.a  (Core Foundation Library)                           │
│  ├─ engine/pine       Pine Hook base (Trampolines / ArtMethod hijack)  │
│  ├─ engine/art        ART internal layouts & dynamic offset probe      │
│  ├─ engine/trampoline arm64 / thumb2 / x86 assembly trampolines        │
│  ├─ engine/nmmvm      Embedded Dalvik bytecode interpreter             │
│  ├─ engine/native     Frida-Gum Inline Hook + QBDI DBI engine          │
│  ├─ engine/tracer     Unified Java<->Native cross-layer bridge         │
│  ├─ engine/utils      Memory protection, ELF parser, WellKnownClasses  │
│  ├─ src/core          PI::init / resolve / Method / HookHandle / Heap  │
│  ├─ src/dex           StandardDex / CompactDex parsing & Smali engine  │
│  └─ src/sandbox       CodeItem extraction / Executor / Tracer callbacks│
└────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Directory Layout

```text
impl_glm/
├── include/ArtPI.h              # Unified public API facade (PI::resolve / CallFrame / Native)
├── src/
│   ├── core/                    # Framework entry point, Method wrapper, HookHandle, Logger, Heap scan
│   ├── dex/                     # DEX parsing and runtime Smali disassembly
│   ├── sandbox/                 # Emulation sandbox: CodeProvider / Executor / Tracer callbacks
│   └── agent/                   # Injected Agent: QuickJS runtime + TCP/MessagePack Server + dynamic proxy
├── engine/
│   ├── art/ pine/ trampoline/   # ART data structures, Pine hook foundation, assembly trampolines
│   ├── nmmvm/                   # Embedded Dalvik bytecode interpreter
│   ├── native/                  # Frida-Gum hooker and QBDI DBI engine
│   ├── tracer/unified/          # Unified Java<->Native tracing bridge
│   ├── qjs/quickjs/             # QuickJS engine source
│   ├── mpack/mpack.h            # Lightweight MessagePack encoder/decoder
│   └── utils/                   # Memory protection, ELF parsing, symbols, helpers
├── cli/
│   ├── injector/                # artpi-cli: ptrace injector + multi-payload packager + REPL client
│   ├── jadxcli.jar              # Embedded decompilation engine (auto-deployed at runtime)
│   ├── pack_compress.py         # Payload XZ/LZMA compression utility
│   └── artpi_repl.py            # Python host REPL client
├── external/                    # xdl (linker namespace bypass) / xz-embedded / frida-gum / qbdi
├── assets/                      # Static resources
│   └── screenshots/             # Terminal session and feature showcase screenshots
└── prebuild/                    # Build outputs (libartpi.so / libartpi_static.a / libartpi_agent.so / artpi-cli)
```

---

## 4. Quick Start

The repository includes a standalone Gradle Wrapper that is fully cross-platform (Windows, Linux, macOS) with zero external script dependencies.

### 4.1 Build Commands

```bash
# Build products (Core static/shared, Agent SO, and packed CLI)
./gradlew build                  # = buildNative (builds all product binaries)
./gradlew buildNative            # Builds core, agent, and CLI with payloads
./gradlew libartpi               # Builds core static and shared libraries
./gradlew :agent:build           # Builds Agent SO
./gradlew :cli:build             # Builds CLI and packs XZ-compressed agent + JADX jar

# Clean outputs
./gradlew cleanNative            # Cleans build/ and prebuild/ directories
```

> **Requirements**: Android SDK with NDK r25+ (`ANDROID_HOME`, `ANDROID_SDK_ROOT`, or `NDK_HOME`). Tools such as `cmake`, `ninja`, and `adb` are indexed automatically by Gradle.

Build artifacts are located in `prebuild/`:

| Artifact | Path | Contents |
|---|---|---|
| Standalone CLI | `prebuild/bin/arm64-v8a/artpi-cli` | Injector executable + embedded `libartpi_agent.so.xz` + `jadxcli.jar` (~10MB) |
| Agent Dynamic Library | `prebuild/lib/arm64-v8a/libartpi_agent.so` | Runtime agent engine injected into target processes |
| Core Static Library | `prebuild/lib/arm64-v8a/libartpi_static.a` | Foundation static library for custom tool development |
| Core Shared Library | `prebuild/lib/arm64-v8a/libartpi.so` | C++ public shared library |
| C++ Header | `prebuild/include/ArtPI.h` | Unified API facade |

---

### 4.2 Deployment & Execution

```bash
# 1. Deploy the standalone CLI to device /data/local/tmp (grants executable permissions)
./gradlew deploy

# 2. Inject into target app and enter interactive REPL
adb shell su -c "/data/local/tmp/artpi-cli -k com.example.app"

# 3. Or execute a JavaScript script file and exit
adb push my_script.js /data/local/tmp/my_script.js
adb shell su -c "/data/local/tmp/artpi-cli -k com.example.app -f /data/local/tmp/my_script.js"

# 4. Or evaluate a single expression from command line
adb shell su -c "/data/local/tmp/artpi-cli -k com.example.app -e 'findclass(\"*Activity\");'"
```

> **Connection Reuse**: `artpi-cli` automatically probes ports `20700..20800` to reconnect to an already injected Agent. If the target has not yet been injected, it extracts payloads and completes remote ptrace injection. If the app lacks `INTERNET` permissions, it automatically falls back to an abstract UNIX Domain Socket (`@artpi_agent_<pid>`).

---

## 5. Live Showcase

Upon injecting into the target process, enter the built-in QuickJS REPL for interactive dynamic analysis:

### 5.1 Class Search & Wildcard Pattern Matching (`findclass`)
Search for loaded classes using wildcards and regular expressions with immediate handle feedback:
![Class Search](assets/screenshots/findclasses.png)

### 5.2 Declared Methods & Signatures (`listMethods`)
List all declared methods of a class, complete with access modifiers, parameter signatures, and underlying `ArtMethod*` pointers:
![List Methods](assets/screenshots/listMethods.png)
![List Methods Detail](assets/screenshots/listmethods_2.png)

### 5.3 Batch Method Hooking (`hookall`)
Hook every non-abstract method of a target class in one command with automatic caller, arguments, and return value logging:
![Batch Hook](assets/screenshots/hookall.png)

### 5.4 Cross-Layer Unified Call Tree Tracing (`Trace.unified` / `trace`)
Seamlessly trace calls across Dalvik bytecode and native C/C++ machine code with automatic JNI delegation:
- **Trace Initialization and Boundary Delegation**:
![Cross Trace Start](assets/screenshots/cross_trace_start.png)
- **Complete Cross-Layer Execution Tree**:
![Cross Trace End](assets/screenshots/cross_trace_end.png)
- **Fine-Grained Method Tracing**:
![Execution Trace](assets/screenshots/trace.png)

### 5.5 Breakpoints & Interactive Stepping (`break`)
Set breakpoints on Java methods to pause execution, inspect registers (`regs`), and step line-by-line (`s`/`n`/`c`):
![Method Breakpoint](assets/screenshots/break.png)

### 5.6 Cross-Layer Step-In to Native Code
Step directly from Java bytecode through the JNI bridge into native disassembly, observing ARM64 CPU registers in real time:
![Cross Breakpoint](assets/screenshots/break_cross_java2native.png)

### 5.7 Persistent Live Object Reflection (`artobject`)
Promote live heap instances to persistent global references with chainable member calls and property inspection:
![Object Reflection](assets/screenshots/artobject.png)

---

## 6. JavaScript Runtime API Manual

### 6.1 Dynamic Proxy Tree (`dynamic.*`) — Recommended Interface

`dynamic` provides property-tree syntax with automatic routing across packages, classes, inner classes, and methods.

#### 1. Java Classes & Methods (`dynamic.java.*`)

```javascript
// 1. Obtain a class proxy box (ClassBox)
let Act = dynamic.java.com.blink.drama.player.ui.activity.download.BlinkDownloadManageActivity;

// Class-level operations
Act.dumpCode();           // Dump disassembly for all declared methods
Act.dumpSmali();          // Dump Smali mnemonics for all declared methods
Act.listMethods();        // List declared methods and ArtMethod* pointers
Act.findMethods("on*");   // Search methods matching pattern
Act.hookall(cb?);         // Hook all non-abstract/non-native methods of the class

// Class decompilation: decompile full class to readable Java source
console.log(Act.disassembly());  // or Act.decompile()

// Heap search: find all active live instances on the GC heap
Act.choose({
    onMatch: function(instance) {
        console.log("Found instance: " + instance);
    },
    onComplete: function(total) {
        console.log("Total found: " + total);
    }
});

// 2. Access method proxy box (MethodBox)
let oc = Act.onCreate;

// Method-level decompilation: extract exact method source with annotations and body
console.log(oc.disassembly());    // or oc.decompile()

// Method-level Smali / native disassembly
console.log(oc.dumpSmali());      // Dump Smali bytecode
console.log(oc.dumpCode());       // Auto-detect Java or Native and dump code

// Install method hook
oc.hook(function(ctx) {
    console.log("onCreate called! this=" + ctx.thiz);
    // ctx.setResult(...);
});

// Breakpoint & debugging
oc.break();                       // Pause thread at method entry and enter interactive step mode
oc.trace({ mode: "CALL_TREE" });  // Render call tree
```

#### 2. Native Modules & Symbols (`dynamic.native.*`)

```javascript
// Obtain native module (.so suffix auto-completed)
let lib = dynamic.native.libart;

// Access symbol and inspect
let fn = lib.art_quick_to_interpreter_bridge;
fn.dumpNative(30);                // Disassemble first 30 ARM64 instructions
fn.hexdump(64);                   // Hexdump 64 bytes of memory
fn.hook(function(ctx) {           // Frida-Gum Inline Hook
    console.log("x0 =", ctx.args[0]);
});
```

---

### 6.2 `Java.*` — Core Java & ART Domain

| API | Signature | Return Value | Description |
|---|---|---|---|
| `Java.findClass` | `(pattern[, limit])` | `BigInt` / `string` / `null` | Returns `jclass` pointer for exact names; returns match list (`0xxxx -> name`) for wildcards (`*`, `?`) |
| `Java.findMethod` | `(clsOrName, name[, sig])` | `BigInt` / `null` | Finds `ArtMethod*` pointer; traverses inheritance hierarchy upwards |
| `Java.listMethods` | `(clsOrName)` | `string` | Lists declared methods, modifiers, signatures, and ArtMethod pointers |
| `Java.findMethods` | `(classOrPattern[, mPattern])`| `string` | Searches methods matching pattern within a class or across classes |
| `Java.decompile` | `(clsOrMethod[, mName])` | `string` | **Single-class or single-method JADX decompilation**; alias `Java.disassembly` |
| `Java.dumpSmali` | `(artMethod[, maxInsn])` | `string` | Directly parses runtime `CodeItem` into standard Smali opcodes |
| `Java.dumpCode` | `(artOrAddr[, maxInsn])` | `string` | Unified disassembly (auto-dispatches Smali or ARM64 assembly) |
| `Java.choose` | `(className[, callbacks])` | `array` / `number` | **Heap instance enumeration**; callback mode for streaming, without callbacks returns array |
| `Java.hook` | `(artMethod[, callback])` | `string` | Installs Java hook; logs arguments/returns formatted when callback is omitted |
| `Java.unhook` | `(id)` | `string` | Uninstalls hook by ID |
| `Java.unhookAll` | `()` | `string` | Uninstalls all active Java hooks |
| `Java.methodInfo` | `(artMethod)` | `object` | Extracts modifiers, class name, signature, and native entry point |

> **Global Aliases**: `findclass`, `findmethod`, `listmethods`, `dumpsmali`, `dumpcode`, `decompile`, `disassembly`, `choose`, `jhook`, `unhook`, `unhookall` are exposed in the global scope.

---

### 6.3 `Native.*` & `DebugSymbol.*` — Native Binary & Symbols

| API | Signature | Description |
|---|---|---|
| `Native.findModule` | `(nameOrPattern)` | Enumerates memory modules, returning `{name, path, base, size}` |
| `Native.findSymbol` | `(module, symbol)` | Resolves absolute symbol address via xDL |
| `Native.findSymbolsMatching` | `(module, pattern)` | Fast pattern matching against module ELF `.dynsym` |
| `Native.dumpNative` | `(addr[, maxInsn])` | ARM64 disassembly with symbol resolution and inline annotations |
| `Native.hook` | `(addrOrSym, cb)` | Frida-Gum Inline Hook (alias `nhook`) |
| `DebugSymbol.findSymbolByName` | `(pattern[, lib])` | Cross-module symbol search with C++ name demangling |
| `DebugSymbol.fromAddress` | `(address)` | Resolves memory address back to module name and symbol |

---

### 6.4 `Memory.*` — Safe Memory Access

| API | Signature | Description |
|---|---|---|
| `Memory.hexdump` | `(addr[, len])` | 16-byte hex + ASCII memory dump with `process_vm_readv` protection |
| `Memory.readByteArray` | `(addr, len)` | Reads raw memory into an `ArrayBuffer` |
| `Memory.writeByteArray` | `(addr, data)` | Writes bytes to memory (automatically calls `mprotect` RWX) |
| `Memory.readCString` | `(addr)` | Reads null-terminated C string |
| `Memory.readU32` / `writeU32` | `(addr[, val])` | Reads or writes 32-bit unsigned integer |

---

### 6.5 `Trace.*` & `Debug.*` — Collaborative Stepping & Tracing

| API | Description |
|---|---|
| `Trace.unified(target, opt)` | **Unified cross-layer Java↔Native tracing** across runtime boundaries |
| `Trace.java(artMethod, opt)` | Java method execution tracing (`CALL_TREE` or `INSN_STEP` instruction snapshots) |
| `brkj(method[, cond])` | Sets breakpoint on Java method, pausing thread to start stepping |
| `brkn(addr[, cond])` | Sets breakpoint at native memory address |
| `s` / `n` / `r` / `c` | Step-In / Step-Over / Step-Return / Continue execution |
| `bt` | Prints accurate Java stack trace with class, method, DEX PC, and **source line numbers** |
| `regs` / `dumpRegs()` | Prints active registers (`v0..vN` for Java, `x0..x30, fp, lr, sp` for Native) |
| `getreg(n)` / `setreg(n, val)` | Inspects or modifies register contents |
| `D()` / `detach()` | **Clean Detach**: unhooks all Java/Native hooks, resumes threads, and clears breakpoints |

---

## 7. Dependencies & Acknowledgments

- [Pine](https://github.com/canyie/pine) — ART method hooking foundation (trampolines & ArtMethod hijacking)
- [JADX](https://github.com/skylot/jadx) — High-performance DEX-to-Java decompilation engine
- [nmmvm](https://github.com/zb0933/nmmvm) — Embedded Dalvik bytecode interpreter
- [Frida-Gum](https://github.com/frida/frida-gum) — Native inline hook engine
- [QBDI](https://github.com/quarkslab/QBDI) — Native Dynamic Binary Instrumentation (DBI) engine
- [QuickJS](https://bellard.org/quickjs/) — Lightweight embeddable JavaScript engine
- [xDL](https://github.com/hexhacking/xDL) — Android 7.0+ linker namespace bypass
- [xz-embedded](https://github.com/torvalds/linux/tree/master/lib/xz) — Embedded LZMA2/XZ decompression
