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
| **Dual-Track JNI Tracing** | Zero-patch hardware breakpoint tracing (`jnihw`) paired with fast global Vtable hijacking (`jnitrace`); concise single-line logging of arguments, return values, elapsed ms, and caller offset, with automatic `RegisterNatives` dynamic symbol decoding |
| **Dynamic Reflective Proxies** | `artobject(addr)` wraps live heap instances into global references with chainable member calls, property access, and interactive REPL Tab completions |
| **UI Automation (`UI.*`)** | `UI.dump` prints the view hierarchy, `UI.find` returns the ancestor chain and nearest click target, and `UI.click` / `swipe` / `setText` drive the UI directly without ADB |
| **Self-Contained Multi-Payload Packing** | A single `artpi-cli` binary encapsulates the injector ELF, XZ-compressed `libartpi_agent.so`, and deflated `jadxcli.jar` (~10MB total), auto-extracting upon launch |
| **Unity IL2CPP Analysis** | `dynamic.unity` powered by UnityResolve: assembly/class/field/method traversal and invocation, wildcard `findclass` / `findmethods`, MethodInfo breakpoints and hooks, GameObject / Button listener inspection, direct `libil2cpp.so` export access, and Levenshtein fuzzy error tolerance |
| **Memory Scanning & Patching** | Embedded KittyMemory core: IDA-style hex pattern scanning (`Memory.scan`), atomic reversible memory patching (`Memory.patch` / `.restore()`), `/proc/self/maps` inspection (`Memory.maps`), and JNI `RegisterNatives` dynamic symbol scanning (`Memory.findNative`) |
| **NativeBox Variadic Invocation**| `NativeBox` returned by `dynamic.native.<mod>.<sym>` and `dynamic.unity.il2cpp.<sym>` supports variadic native calls via `.invoke(...args)` or direct callable proxy `fn(...args)` with automatic AAPCS64 packaging |
| **Built-in QuickJS REPL** | Direct terminal interaction inside the target process with registrable proxy domains (`dynamic.java.*`, `dynamic.native.*`, `dynamic.unity.*`; `objc` mounted by runtime), enhanced with Levenshtein-based chained syntax and fuzzy auto-completion |

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

# 5. Spawn and monitor dynamic library loading (zero-patch hardware breakpoint on dlopen)
adb shell su -c "/data/local/tmp/artpi-cli -S com.example.app --lib-log"

# 6. Spawn and pause main thread automatically when target SO library is loaded
adb shell su -c "/data/local/tmp/artpi-cli -S com.example.app --stop-lib libnative.so"
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

#### 3. Build a MethodBox from a raw `ArtMethod*` (`jmethodBox`)

If you already hold a raw `ArtMethod*` (e.g. from a `jhook` callback, `UI.find`'s `clickListener.artMethod`, or `findmethod`), wrap it into a MethodBox identical to `dynamic.java`:

```javascript
let art = findmethod("com.example.App", "onCreate");

let m = jmethodBox(art);          // aliases: jmethodbox / methodBox / methodbox / Java.methodBox
m.className; m.methodName; m.artMethod; m.address; m.isNative; m.signature;

m.hook(function(ctx) { ... });    // install hook
m.dumpSmali(); m.dumpNative();    // disassemble
m.disassembly();                  // decompile
m.trace({ mode: "CALL_TREE" });   // trace
m.break();                        // breakpoint
```

Typical use — hook an arbitrary `ArtMethod*`, for example a button's click callback:

```javascript
let item = UI.find("Advanced")[0];
jmethodBox(item.clickTarget.clickListener.artMethod).hook(function(ctx) {
    console.log("clicked!");
});
```

#### 4. Domain registry & conditional mounting (`dynamic.unity` / `dynamic.objc`)

`dynamic` is a registry of domains; each domain is mounted only when its runtime exists:

| Domain | Mount condition | Status |
|---|---|---|
| `dynamic.java` | Android / ART process | Full |
| `dynamic.native` | Always | Full |
| `dynamic.unity` | Android process with `libil2cpp.so` / `libunity.so` loaded, or an injector-provided `unityLibDir` hint | Full (UnityResolve / IL2CPP) |
| `dynamic.objc` | Apple platform | Empty stub (reserved) |

```javascript
dynamic.domains();                    // mounted domains, e.g. ["java", "native", "unity"]
dynamic.has("unity");                 // whether a domain is mounted
dynamic.register("mydomain", rootObj);// register a custom domain
```

#### 5. Unity Domain (`dynamic.unity.*`) — UnityResolve / IL2CPP

`dynamic.unity` is backed by the vendored `UnityResolve.hpp`. Initialization is lazy: metadata is read only after `libil2cpp.so` is loaded and the Unity runtime has finished starting. Early calls return a retryable error instead of faulting inside the Unity loader.

| API | Signature | Description |
|---|---|---|
| `unity.available()` / `isAvailable()` | `()` | Whether the runtime and metadata are ready |
| `unity.assemblies()` | `()` | Assembly name list |
| `unity.assembly` | `(name)` | Assembly wrapper |
| `unity.class` | `(asm, name[, ns])` | Class wrapper |
| `unity.findclass` | `(pattern[, options])` | Scans all classes; supports `*` / `?` wildcards |
| `unity.findmethods` | `(pattern[, options])` | Scans all methods; supports `*` / `?` wildcards |
| `unity.m` | `(classOrName[, sort[, detailed]])` | Il2CppHookScripts-compatible `m()` / `showMethods` |
| `unity.mi` | `(methodInfoPtr)` | Prints Assembly → Image → Class → Method hierarchy |
| `unity.b` | `(methodInfoPtr[, maxCalls])` | Detailed single-method breakpoint (args, return value, time) |
| `unity.lfs` | `(instancePtr)` | Lists instance fields, offsets, types, and values |
| `unity.showGameObject` | `(gameObjectPtr)` | Prints GameObject name, layer, transform, and hierarchy |
| `unity.button` / `unity.buttons()` | `(buttonPtr)` / `()` | Inspect buttons and their onClick listeners |
| `unity.B_Button` | `()` | Hooks `Button.OnPointerClick` / `UIButton.OnClick` and prints the hook MethodInfo, GameObject, `m_RuntimeCalls` / `m_PersistentCalls`, and each UnityAction's MethodInfo, RVA, signature, and target |
| `unity.HookSetActive` | `()` | Hooks `GameObject.SetActive` with per-object/state deduplication |
| `unity.HookOnPointerClick` | `()` | Hooks `Button.OnPointerClick` and prints GameObject info |
| `unity.hooks.BF` / `BFA` | `(filter[, options])` | Batch inline hooks by method name |
| `unity.hooks.list()` / `unhookAll()` | `()` | List / detach Unity hooks |
| `unity.il2cpp.<symbol>` | property | Access any `libil2cpp.so` export as a `NativeBox` (address/hook/dump helpers) |
| `unity.dump` | `([path])` | Dump `dump.cs` |

`findclass` / `findmethods` options: `{ assembly, namespace, class, exact, limit, includeAbstract }`. `unity.m` accepts `sort` = `access` / `address` / `name` / `args`.

```javascript
dynamic.unity.findclass("*Stage12*");
dynamic.unity.findmethods("Run", { class: "Stage12*", limit: 30 });

let cls = dynamic.unity.assembly("Assembly-CSharp.dll")
                     .class("Stage12CueResetSourceChecks");
cls.methods();   // 0x... ---> 0x... (0x7c6644@libil2cpp.so) | public static String Run()
cls.m();         // TS m() / showMethods style
cls.m("address", true); // sort by address with detailed parameters

// MethodInfo pointer is methodInfo; native function address is address
let run = cls.method("Run");
dynamic.unity.b(run.methodInfo);       // detailed breakpoint
dynamic.unity.mi(run.methodInfo);      // hierarchy

dynamic.unity.B_Button();              // print listener MethodInfo on click
dynamic.unity.buttons();

// Chained discovery with parameter/field inspection; REPL Tab completes quoted strings with Levenshtein fuzzy matching
let method = dynamic.unity.assembly("Assembly-CSharp.dll").class("BallClickLayer").method(".ctor");
console.log(method.toString()); // namespace, assembly, class, method, rva, return, parameters

// Direct libil2cpp.so exports; NativeBox supports variadic native invocation (.invoke(...args) or direct call)
let strFn = dynamic.unity.il2cpp.il2cpp_string_new;
let myStr = strFn.invoke("Hello from ArtPI!"); // or directly strFn("Hello from ArtPI!")
console.log("il2cpp string ptr:", myStr);

D();  // detaches Java / native / Unity hooks together
```

> `m`, `findclass`, and `findmethods` are mounted under `dynamic.unity` (not global) to avoid collisions with the Java-side APIs.

---

### 6.2 `Java.*` — Core Java & ART Domain

| API | Signature | Return Value | Description |
|---|---|---|---|
| `Java.findClass` | `(pattern[, limit])` | `BigInt` / `string` / `null` | Returns `jclass` pointer for exact names; returns match list (`0xxxx -> name`) for wildcards (`*`, `?`); suggests similar classes via Levenshtein on typo |
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
| `Java.methodBox` | `(artMethod)` | `MethodBox` | Wraps a raw `ArtMethod*` into a `dynamic.java`-style MethodBox; global aliases `jmethodBox` / `jmethodbox` / `methodBox` / `methodbox` |

> **Global Aliases**: `findclass`, `findmethod`, `listmethods`, `dumpsmali`, `dumpcode`, `decompile`, `disassembly`, `choose`, `jhook`, `unhook`, `unhookall`, `jmethodbox` are exposed in the global scope.

---

### 6.3 `Native.*` & `DebugSymbol.*` — Native Binary, Variadic Calls & Symbols

| API | Signature | Description |
|---|---|---|
| `Native.findModule` | `(nameOrPattern)` | Enumerates memory modules, returning `{name, path, base, size}` |
| `Native.findSymbol` | `(module, symbol)` | Resolves absolute symbol address via xDL |
| `Native.findSymbolsMatching` | `(module, pattern)` | Fast pattern matching against module ELF `.dynsym` |
| `Native.dumpNative` | `(addr[, maxInsn])` | ARM64 disassembly with symbol resolution and inline annotations |
| `Native.hook` | `(addrOrSym, cb)` | Frida-Gum Inline Hook (alias `nhook`) |
| `Native.invoke` / `callnative` | `(target, ...args)` | **Universal variadic native invocation** (AAPCS64 automatic parameter packaging and stack alignment for strings, numbers, BigInts, ArrayBuffers) |
| `DebugSymbol.findSymbolByName` | `(pattern[, lib])` | Cross-module symbol search with C++ name demangling |
| `DebugSymbol.fromAddress` | `(address)` | Resolves memory address back to module name and symbol |

> **`NativeBox` Variadic Invocation**: Functions returned by `dynamic.native.<mod>.<sym>` or `dynamic.unity.il2cpp.<sym>` are callable objects (`NativeBox`). You can invoke them directly as functions `fn(...args)` or via `.invoke(...args)` / `.call(...args)`.

---

### 6.4 `Memory.*` — Pattern Scanning, Reversible Patching & Safe Access (KittyMemory)

| API | Signature | Description |
|---|---|---|
| `Memory.scan` / `scanmem` | `(target[, size], pattern[, max])` | **IDA-style hex pattern scanning** with `??` wildcards (e.g. `"48 89 ?? ?? 55"`); `target` can be module name (`"libil2cpp.so"`) or start address |
| `Memory.patch` / `patchmem` | `(addrOrModule[, rva], hexString)` | **Atomic reversible memory patch**; supports module + RVA or absolute address, handles page protections, flushes cache, and returns patch object (`.origBytes`, `.patchBytes`, `.currBytes`, `.modify()`, `.restore()`) |
| `Memory.restoreAll` / `restoreall`| `()` | Restores all memory patches applied via `Memory.patch` |
| `Memory.maps` / `maps` | `([filter])` | Formats and filters `/proc/self/maps` memory regions |
| `Memory.findNative` / `findnative`| `(funcName[, libName])` | Fast scanner locating functions registered via JNI `RegisterNatives` (`JNINativeMethod`) |
| `Memory.protect` | `(addr, len, prot)` | Wraps `mprotect` with safe page alignment (0: NONE, 1: R, 2: W, 4: X, etc.) |
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

> **Trace scope**: for stability, the interpreter only steps into classes owned by the **app's own package** (app-scope allowlist; package from `ActivityThread.currentPackageName()`, falling back to `/proc/self/cmdline` for app_process). System/framework classes are black-boxed. `suspend` methods (signature contains `Continuation`) and Kotlin runtimes (`kotlin` / `kotlinx` / `org.jetbrains`) are skipped automatically, avoiding the coroutine exception-flow corruption that R8-obfuscated code can trigger.

---

### 6.6 `UI.*` — View Hierarchy Inspection & Automation

| API | Description |
|---|---|
| `UI.dump([filter])` | Prints the active window view hierarchy (aliases `dumpViews()` / `dumpviews()`) |
| `UI.find(pattern)` / `UI.views(pattern)` | Finds views by text / id / class / clickable (aliases `findViews()` / `findviews()`) |
| `UI.click(view \| 'text' \| x, y)` | Clicks a view, text label, or screen coordinates |
| `UI.longClick(...)` | Long-presses a view / text / coordinates |
| `UI.swipe(x1, y1, x2, y2, [ms])` | Smooth swipe gesture |
| `UI.setText(view \| 'id', text)` | Sets text on an EditText / TextView |
| `UI.currentActivity()` / `UI.topActivity()` | Returns the foreground Activity (JRef) |
| `UI.pressBack()` | Triggers Activity back |
| `UI.help()` | Lists all UI APIs |

Each item returned by `UI.find` / `UI.views` carries the **ancestor chain** and the **nearest click target**, so you can follow the hierarchy to find a button's click handler:

```javascript
let r = UI.find("Advanced");

r[0].clickTarget;                            // nearest ancestor that actually has a clickListener
r[0].clickTarget.clickListener.className;    // listener class, e.g. w5
r[0].clickTarget.clickListener.artMethod;    // listener method ArtMethod*
r[0].parents;                                // full ancestor chain (root -> immediate parent)
r[0].clickTarget.click();                    // click that node directly
```

Sample output:

```text
[View ThemeTextView id/item_title "Advanced" [199,549,347,586]]
  clickTarget: ThemeRelativeLayout [68,541,1012,702] [Click: w5 @0x7780288be8]  <-- click fires here
  parents:
    ├─ DecorView [0,0,1080,2400]
    ├─ LinearLayout [0,0,1080,2400]
    ...
    └─ LinearLayout [199,541,933,594]
```

> `[CLICKABLE]` means `View.isClickable()==true`; `[Click: <class> @0x...]` means the node actually has an `mOnClickListener`. When the matched node has no listener, `clickTarget` walks up to the nearest ancestor that does.

---

### 6.7 Hardware Breakpoints & Watchpoints (`HW`) — Zero-Patching Pseudo-Hook & dlopen Monitoring

Leveraging ARM64 physical hardware debug registers and Frida-Gum's `GumExceptor` engine, ArtPI provides a modern, unified hardware breakpoint API. **Zero code patching** is required (the `.text` section remains strictly read-only, leaving no memory patch signatures or `BRK` opcodes). An automatic **hardware single-step (Step-Over) state machine** handles step-over and re-arming upon each hit, completely eliminating infinite break loops.

#### 1. Core APIs (`HW`)

| API | Signature | Description |
|---|---|---|
| `HW.attach` | `(target, options \| cb)` | Arm a **hardware execution breakpoint** (pseudo-hook / instruction interception) |
| `HW.watch` | `(addr, options \| cb)` | Arm a **hardware watchpoint** (data read/write monitoring) |
| `HW.watchDlopen` | `(options)` | Hardware breakpoint based `dlopen` monitor, logs SO loads and optionally pauses main thread upon target SO hit |
| `HW.list()` | `()` | List all active hardware breakpoint/watchpoint sessions |
| `HW.detach(id)` | `(id)` | Detach and free debug registers for a specific session ID |
| `HW.detachAll()` | `()` | Detach all hardware sessions and release all physical register slots |
| Global Aliases | `hwhook()` / `hwwatch()` / `hwunhook()` / `hwunhookall()` | Global convenience shortcuts |
| Legacy Aliases | `HWBreakpoint.attach` / `HWWatchpoint.attach` | Backward compatibility with legacy API |

**Target (`target`) Resolution**:
- Symbol string: `"libnative.so!exported_func"` or `("libnative.so", "exported_func")`
- Hex string: `"0x70123456"`
- Integer / Pointer: `BigInt` / `Number`

**Options (`options`)**:
- `onEnter` / `onHit`: Callback function `function(ctx) { ... }` (passing a function directly as the 2nd argument is shorthand for `{ onEnter: cb }`)
- `slot`: Specific debug register slot (`0` ~ `3`, default `-1` for automatic allocation)
- `threadId`: Target thread TID (`0` for all existing threads in target process)
- `once`: Single-shot trigger (`true` disarms after first hit; default `false` for continuous interception)
- (`HW.watch` only) `size`: Watch byte size (`1`, `2`, `4`, `8`, default `4`)
- (`HW.watch` only) `conditions`: Access condition (`'r'` read, `'w'` write, `'rw'` read/write, default `'w'`)
- (`HW.watchDlopen` only) `stopLib`: Pause main thread automatically via futex when library matching name is loaded (type `resume` in REPL to continue)
- (`HW.watchDlopen` only) `libLog`: Log all SO load events (default `true`)
- (`HW.watchDlopen` only) `onLoading(path, caller)`: Callback fired when SO begins loading
- (`HW.watchDlopen` only) `onLoaded(path, handle)`: Callback fired when SO finishes loading (captures return handle at LR)

#### 2. Callback Context (`ctx`)

When a hardware breakpoint triggers, `ctx` delivers complete ARM64 execution context:

| Property / Method | Type | Description |
|---|---|---|
| `ctx.pc` | `BigInt` | Program counter (fault address) |
| `ctx.sp` | `BigInt` | Stack pointer SP |
| `ctx.lr` | `BigInt` | Link register LR (caller return address) |
| `ctx.fp` | `BigInt` | Frame pointer FP |
| `ctx.threadId` | `number` | Thread ID where the breakpoint hit |
| `ctx.slot` | `number` | Physical debug register slot index |
| `ctx.args` | `Array<BigInt>` | Fast argument array (`args[0]` ~ `args[7]`, corresponding to `x0` ~ `x7`) |
| `ctx.x0` ~ `ctx.x28` | `BigInt` | General-purpose ARM64 register values |
| `ctx.setArg(index, val)` | `function` | Modify the i-th argument register (`x0` ~ `x7`) |
| `ctx.setRet(val)` | `function` | Modify return value register (`x0`) |
| `ctx.readCString(addr)` | `function` | Read null-terminated C string from memory |
| `ctx.readU32(addr)` / `readU64(addr)` | `function` | Read 32-bit / 64-bit unsigned integer from memory |
| `ctx.memory.address` | `BigInt` | (Watchpoint only) Memory address accessed |
| `ctx.memory.operation` | `string` | (Watchpoint only) Operation type (`"read"` or `"write"`) |

#### 3. Example

```javascript
// 1. Code execution interception (pseudo-hook / instruction breakpoint)
var bp = HW.attach("liboattest.so!Java_com_axhlzy_oattest_MainActivity_stringFromJNI", {
    onEnter: function(ctx) {
        console.log("[+] [HW HIT] stringFromJNI entered!");
        console.log("[+] PC: 0x" + ctx.pc.toString(16) + ", LR: 0x" + ctx.lr.toString(16));
        console.log("[+] JNIEnv (x0): 0x" + ctx.args[0].toString(16));
        console.log("[+] jobject (x1): 0x" + ctx.args[1].toString(16));
    }
});

// 2. Memory data access monitoring (hardware watchpoint)
var wp = HW.watch("0x7012345000", {
    size: 4,
    conditions: "rw",
    onHit: function(ctx) {
        console.log("[+] [Watchpoint HIT] Addr: 0x" + ctx.memory.address.toString(16) +
                    ", op: " + ctx.memory.operation + ", PC: 0x" + ctx.pc.toString(16));
    }
});

// 3. Dynamic library loading monitor & interceptor (dlopen)
HW.watchDlopen({
    stopLib: "liboattest.so", // Pause main thread when liboattest.so is loaded
    onLoading: function(name, caller) {
        console.log("[dlopen] Loading SO: " + name + " (caller=0x" + caller.toString(16) + ")");
    },
    onLoaded: function(name, handle) {
        console.log("[dlopen] Loaded SO: " + name + " handle=0x" + handle.toString(16));
    },
    constructors: true // Relay-trace each DT_INIT/DT_INIT_ARRAY constructor with execution timing
});

// List all active hardware sessions
console.log(JSON.stringify(HW.list()));

// Detach specific or all sessions
bp.detach();
HW.detachAll();
```

#### CLI Early Spawn Monitoring & Constructor Tracing (`-S` with `-L` / `-LC` / `--stop-lib`)
When spawning an app with `-S`:
- `-L, --lib-log`: Trace all dynamic library loading events via hardware breakpoint on `dlopen`/`android_dlopen_ext`.
- `-LC, --lib-constructors`: In addition to dlopen logging, hooks Linker's `soinfo::call_constructors`, parses `DT_INIT` and `DT_INIT_ARRAY` from memory, and daisy-chains one-shot hardware breakpoints to trace each constructor with millisecond execution timing and xDL symbol resolution using strictly 1 hardware breakpoint slot.
  - `-LC`: Trace all constructors across all loaded libraries with millisecond timing.
  - `-LC <libName>:<index>`: e.g. `-LC liboattest.so:0` isolates and traces constructor index 0 using QBDI emulation, while relaying others via hardware breakpoints.
  - `-LC <libName>:<symbolName>`: e.g. `-LC liboattest.so:custom_dt_init` triggers QBDI emulation by symbol name.
  - `-LC <libName>@<offsetOrAddr>`: e.g. `-LC liboattest.so@0x475bc` triggers QBDI emulation by relative file offset or virtual memory address.
  - `--log / --full-log`: Full trace logging without truncation limits.
  - `--max-log <N>`: Custom log budget (default 100, 0 for unlimited).
- `--stop-lib <name>`: Pause the main thread upon loading the specified library.

---

### 6.8 `Linker.*` / `linker.*` — Linker & ELF Soinfo Introspection & Control

Provides deep introspection into the Bionic Linker's runtime internal data structures and loaded ELF metadata. Fully case-insensitive (`Linker` or `linker`).

#### 1. Core APIs

| API | Signature | Description |
|---|---|---|
| `Linker.find` / `linker.find` | `(nameOrAddr)` | Find the `soinfo` object corresponding to a library name or memory address |
| `Linker.main` / `linker.somain` | `()` | Obtain the `soinfo` object of the main executable |
| `Linker.list` / `linker.modules` | `()` | Enumerate `soinfo` objects of all loaded libraries in the process |
| `Linker.getConstructors` | `(nameOrAddr)` | Extract all initialization functions (`DT_INIT`, `DT_INIT_ARRAY`) with resolved xDL symbol names and relative offsets |
| `Linker.getDestructors` | `(nameOrAddr)` | Extract all termination functions (`DT_FINI`, `DT_FINI_ARRAY`) with resolved xDL symbol names |
| `Linker.symbols` / `linker.symtab` | `(nameOrAddr[, count])` | Parse ELF `.symtab` and `.strtab`, returning an array of symbols (name, address, size, bind, type) |
| `Linker.linkMap` | `()` | Traverse and return the `link_map` chain (`{addr, name, phnum}`) |
| `Linker.load` | `(libName)` | Call Linker kernel `__loader_dlopen` directly, **bypassing Android 7.0+ Linker Namespace restrictions** |
| `Linker.dump` | `(nameOrAddr)` | Return formatted text summary of the library metadata |

#### 2. `soinfo` Object Properties

Calling `linker.find("liboattest.so")` or `linker.main()` returns an object with:
- `name` / `soname`: Library filename (e.g. `"liboattest.so"`)
- `base`: Load base address (`"0x7b6705f000"`)
- `size`: Mapped memory size in bytes
- `loadBias`: Load bias (`base - p_vaddr`)
- `phdr` / `phnum`: Program headers array pointer and count
- `dynamic`: `PT_DYNAMIC` segment pointer
- `strtab` / `strtabSize`: String table pointer and size
- `symtab` / `symentSize` / `symtabCount`: Symbol table pointer, entry size, and total symbol count
- `needed` / `dependencies`: Array of DT_NEEDED library names
- `constructors`: Array of constructors `{ type, tag, desc, symbol, address, func, offset }`
- `destructors`: Array of destructors `{ type, tag, desc, symbol, address, func, offset }`
- `preinit`: Array of preinitializers (if present)
- `dumpText`: Structured string representation with decimal numbering and space alignment
- `toString()`: Invoked automatically by REPL to render structured output

#### 3. Example

```javascript
// 1. Inspect loaded library
console.log(linker.find("liboattest.so"));

// 2. Query destructors
let dtors = linker.getDestructors("liboattest.so");
console.log("Destructors: " + dtors.destructors.length);

// 3. Inspect symbols
let syms = linker.symbols("liboattest.so", 10);
syms.forEach(s => console.log(`[${s.index}] ${s.name} @ ${s.address}`));
```

---

### 6.9 `QBDI.*` / `qbdi.*` — Dynamic Binary Instrumentation (DBI) Emulation & Tracing

Integrates Quarkslab's Native Dynamic Binary Instrumentation (QBDI) engine into QuickJS. Fully case-insensitive (`QBDI`, `Qbdi`, or `qbdi`).

#### 1. Core APIs

| API | Signature | Description |
|---|---|---|
| `qbdi.version()` | `()` | Returns QBDI engine version information |
| `qbdi.trace` | `(options \| fnOrAddr[, options])` | Launch instruction-level QBDI execution trace on a native function or address |
| `qbdi.disassemble` | `(addr, count)` | Disassemble `count` instructions starting at `addr` |
| `qbdi.run` | `(fnOrAddr, ...args)` | Emulate calling a native function in an isolated QBDI context |

#### 2. `qbdi.trace` Options

- `target`: Function address or symbol name
- `range`: Instrumented memory range (default: module code range)
- `maxInstructions`: Execution instruction budget (default: 500,000)
- `maxLog`: Log line count limit (default: 100, 0 for unlimited)
- `dumpRegs`: Enable real-time GPR register diff logging (e.g. ` ; x0=0x4, sp=0x...`)
- `onInstruction`: Per-instruction callback `function(inst)`
- `onBasicBlock`: Per-basic-block callback `function(bb)`

---

### 6.10 `JNI.*` / `jnitrace` / `jnihw` — Dual-Track JNI Tracing (Global Vtable Hijack & Hardware Breakpoint)

To dissect high-frequency native JNI interactions (dynamic registrations, reflection, field lookups, array copies, string allocations), ArtPI provides an innovative **Dual-Track JNI Tracing Engine**.

#### 1. Architecture & Trade-Off Comparison

| Dimension | Global Vtable Hijack (`jnitrace`) | Hardware Breakpoint Trace (`jnihw`) |
|---|---|---|
| **Mechanism** | On-demand takeover of the 233-slot `JNINativeInterface` vtable in `JNIEnv` | ARM64 hardware debug registers set directly on target JNI function entry |
| **Memory Modification** | Rewrites only data-section function pointers; **zero code patching** | **0 memory modification** (read-only execution breakpoint, untouched vtable) |
| **Anti-Hook Evasion** | Cleanly restored on stop; pure in-process trampolines | **Immune to memory integrity/checksum and code-segment CRC scans** |
| **Coverage** | Intercepts all 233 JNI APIs globally with rich filter rules | Pinpoint precision on targeted JNI functions of interest |
| **Return Value Capture**| Stack frame preserves return value registers and measures duration | Arms a transient `once = true` return address (`LR`) breakpoint upon entry |

#### 2. Core APIs

| API | Signature | Description |
|---|---|---|
| `jnitrace` / `JNI.trace` | `([filter])` | Activate global JNI vtable tracing with optional filter options |
| `jnistop` / `JNI.stop` | `()` | Stop JNI vtable tracing and cleanly restore original `JNINativeInterface` table |
| `jnihw` / `JNI.hwtrace` | `(funcName[, callback])` | Arm hardware execution and return breakpoints on target JNI API (auto-binds C++ `V` variant slot) |
| `jnihwstop` / `JNI.hwstop` / `jnihwdetachAll` | `()` | Detach all active JNI hardware breakpoints |
| `JNI.status()` | `()` | Query JNI tracing status and active hardware breakpoints |
| `lists()` / `L()` / `list()` | `()` | List all active instrumentations, including hardware debug registers and JNI status |

#### 3. Filtering Capabilities

`jnitrace` offers flexible filtering options:
```javascript
// Simple shorthand:
jnitrace();                    // Trace all JNI calls
jnitrace("liboattest.so");     // Filter by caller shared library
jnitrace("FindClass,Call*");   // Filter by function name pattern
jnitrace("!GetVersion");       // Exclude specific function

// Structured object config:
jnitrace({
    from: "libnative.so",            // Caller module
    only: ["NewStringUTF", "Call*"], // Whitelist functions
    exclude: ["GetVersion"],          // Blacklist functions
    class: "com.example.app",        // Class filter
    grep: "token"                    // Text search filter
});
```

#### 4. Single-Line Output & RegisterNatives / ART Object Deep Resolution

Traced calls emit **compact single-line logs** upon return, highlighting parameters, return values, elapsed milliseconds, and caller offset.

ArtPI features a built-in **ART runtime object and symbol resolution engine**:
- **`jobject` Resolution**: Automatically extracts and prints runtime class name and memory address, e.g. `<MainActivity@0x7fd716b538>`. Objects are **automatically registered as global observed objects**, ready for instant interactive method invocation and property probing via `artobject(0x7fd716b538)` in the REPL!
- **`jclass` Resolution**: Directly formatted as fully-qualified class names, e.g. `<class com.axhlzy.oattest.MainActivity>`.
- **`jmethodID` / `jfieldID` Resolution**: Translates opaque IDs into human-readable class names and signatures, e.g. `mid=MainActivity.instanceMultiply(II)I` or `fid=MainActivity.mCount:I`.
- **`jstring` / Array Resolution**: Formats string literals as `"..."` and arrays with element type and count, e.g. `<int[4]@0x...>`.
- **Dual-Slot Arming**: Because NDK C++ headers inline `env->Call*Method` into `functions->Call*MethodV`, `jnihw("CallIntMethod")` seamlessly arms both the base slot and the `V` variant slot, ensuring C and C++ callers are trapped reliably without missing events.

```text
[JNI] FindClass("com/axhlzy/oattest/MainActivity") = <class com.axhlzy.oattest.MainActivity> (0.010 ms)  [liboattest.so+0x2389c]
[JNI] GetMethodID(class=<class com.axhlzy.oattest.MainActivity>, "instanceMultiply", "(II)I") = mid:MainActivity.instanceMultiply(II)I (0.019 ms)  [liboattest.so+0x23970]
[JNI] CallIntMethodV(obj=<MainActivity@0x7fd716b538>, mid=MainActivity.instanceMultiply(II)I) = 56 (0.019 ms)  [liboattest.so+0x23a3c]
[JNI] GetStringUTFChars(jstring="sum=40") = "sum=40" (0.003 ms)  [liboattest.so+0x23be8]
[JNI] GetIntField(obj=<MainActivity@0x7fd716b538>, fid=MainActivity.mCount:I) = 42 (0.007 ms)  [liboattest.so+0x23ca4]
[JNI] ExceptionCheck() = false (0.002 ms)  [liboattest.so+0x23de0]
```

Dynamic registration via `RegisterNatives` recursively decodes method names, signatures, and target native pointers:
```text
[JNI] RegisterNatives(class=<class com.axhlzy.oattest.MainActivity>, n=1)
      #0 dynamicNativeMethod(I)I -> liboattest.so+0x238a8 (0x7b6684d8a8) = 0 (0.111 ms)  [liboattest.so+0x2392c]
```

Hardware breakpoint tracing `jnihw` shares the exact same ART object resolution and return value interception:
```text
[HW-JNI] CallIntMethodV(obj=<MainActivity@0x7fd716b538>, mid=MainActivity.instanceMultiply(II)I) = 56 (5.002 ms)  [libartpi_agent.so+0xc38238]
[HW-JNI] FindClass("com/axhlzy/oattest/MainActivity") = <class com.axhlzy.oattest.MainActivity> (5.455 ms)  [liboattest.so+0x2389c]
[HW-JNI] NewStringUTF("Hello from C++!") = "Hello from C++!" (4.911 ms)  [liboattest.so+0x23524]
```

#### 5. Stack Unwinding & Custom Callbacks (`{ stack: true }` & `ctx.stack`)

To reveal **which native routine or shared library initiated the JNI call**, full native/ART backtracing can be activated effortlessly:

- **Declarative Configuration (auto-appends formatted backtrace under the single-line log)**:
  ```javascript
  jnihw("CallStaticObjectMethod", { stack: true });
  ```
  Example output:
  ```text
  [HW-JNI] CallStaticObjectMethodV(class=0x1e06, mid=android.view.MotionEvent.obtain()) = 0x7ec2efb04d (78.704 ms)  [libandroid_runtime.so+0x12eaec]
      #00 0x7ec2eff878 [vdso]!__kernel_rt_sigreturn+0x0
      #01 0x7c00a023d8 libart.so!art::CheckJNI::CallStaticObjectMethodV+0x0
      #02 0x7ea0aca040 libandroid_runtime.so!android_view_MotionEvent_obtainAsCopy+0x30
      #03 0x7ea0ac1ee0 libandroid_runtime.so!NativeInputEventReceiver::consumeEvents+0x230
      #04 0x7e9dca417c libutils.so!android::Looper::pollOnce+0x32c
      #05 0x7ea0af8420 libandroid_runtime.so!android_os_MessageQueue_nativePollOnce+0x30
  ```

- **Programmatic Custom Callback (inspect or log `ctx.stack` freely)**:
  ```javascript
  jnihw("CallIntMethod", (ctx) => {
      console.log(`[+] ${ctx.func} returned ${ctx.retStr} from ${ctx.caller}`);
      console.log("[+] Caller Stack:\n" + ctx.stack);
  });
  ```

- **Phased Callbacks (`onEnter` / `onLeave`)**:
  ```javascript
  jnihw("CallStaticObjectMethod", {
      onEnter(ctx) {
          console.log("[Enter] " + ctx.func + " caller=" + ctx.caller);
          console.log(ctx.stack); // Pristine stack captured directly upon entry
      },
      onLeave(ctx) {
          console.log("[Leave] retval=" + ctx.retStr + " cost=" + ctx.duration_ms + "ms");
      }
  });
  ```

- **Also Supported in Global Vtable Tracing**:
  ```javascript
  jnitrace({ only: "CallStaticObjectMethod", stack: true });
  ```

---

## 7. Dependencies & Acknowledgments

- [Pine](https://github.com/canyie/pine) — ART method hooking foundation (trampolines & ArtMethod hijacking)
- [JADX](https://github.com/skylot/jadx) — High-performance DEX-to-Java decompilation engine
- [nmmvm](https://github.com/zb0933/nmmvm) — Embedded Dalvik bytecode interpreter
- [Frida-Gum](https://github.com/frida/frida-gum) — Native inline hook engine
- [QBDI](https://github.com/quarkslab/QBDI) — Native Dynamic Binary Instrumentation (DBI) engine
- [QuickJS](https://bellard.org/quickjs/) — Lightweight embeddable JavaScript engine
- [xDL](https://github.com/hexhacking/xDL) — Android 7.0+ linker namespace bypass
- [UnityResolve.hpp](https://github.com/issuimo/UnityResolve.hpp) — Unity IL2CPP metadata resolution and invocation (MIT, vendored under `external/unityresolve`)
- [xz-embedded](https://github.com/torvalds/linux/tree/master/lib/xz) — Embedded LZMA2/XZ decompression
