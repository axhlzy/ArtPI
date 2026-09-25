# ArtPI Test Suite

真机（Android / arm64）功能测试，采用与参考项目 `jniprobe/test` 相同的模式：
**NDK 编译 JNI 测试库 → `javac` + `d8` 生成 dex → `app_process` 加载 dex 与 so 运行**。
无需安装 APK、无需 Activity。

测试分为两套，外加一个 playground：

| 套件 | 目录 | 测什么 | 状态 |
|---|---|---|---|
| **Suite 1 — ArtPI.h 原生 API** | [`artpi/`](artpi) | `ArtPI.h` 暴露的全部 C++ API（resolve/hook/沙箱/xDL/…） | ✅ 73 断言 |
| **Suite 2 — QuickJS 绑定** | [`js/`](js) | 注入代理内的 QuickJS 运行时与 JS API（`Java.*`/`Memory.*`/`jhook`/`JRef`/…） | ✅ 132 断言 |
| **Playground — trace/hook 试验场** | [`harness/`](harness) | 进程内加载 agent + ticker 循环调用 `Target.*`，供 REPL 交互验证 hook/trace | 手动交互 |

---

## 1. 目录结构

```
test/
├── CMakeLists.txt                  # ninja 目标：artpi_test / artpi_js_test / artpi_harness
├── artpi/                          # :test 子工程（Suite 1）
│   ├── build.gradle                  # 套件配置（apply ../../gradle/test-suite.gradle）
│   ├── cpp/
│   │   ├── artpi_test_common.h/.cpp  # 公共：句柄注册表、JStr/ToSlash/Resolve
│   │   ├── artpi_test_core.cpp       # 功能测试：hook / 解释器 / 沙箱 / trace
│   │   └── artpi_test_api.cpp        # API 覆盖：resolve 重载 / getter / ArgProxy / 回调 / xDL
│   └── src/com/artpi/test/
│       ├── Main.java                 # 功能测试入口（断言 + 汇总 + 退出码）
│       ├── ApiCoverage.java          # API 覆盖入口（由 Main 调用，计数合并）
│       ├── NativeTest.java           # native 声明（与 cpp 一一对应）
│       ├── Target.java / Helper.java # 被测目标类
├── js/                             # :test-js 子工程（Suite 2）
│   ├── build.gradle                  # apply ../../gradle/test-suite.gradle
│   ├── cpp/js_test.cpp               # JNI 驱动：dlopen agent + eval + 已知内存缓冲
│   └── src/com/artpi/js/{JsMain,NativeJs,JsTarget}.java
└── harness/                        # :test-harness 子工程（Playground）
    ├── build.gradle                  # apply ../../gradle/test-suite.gradle
    ├── cpp/harness.cpp               # dlopen agent + JNI 入口 + native 目标
    └── src/com/artpi/harness/{Harness,Target,Native}.java
```

## 2. 构建与运行

三个套件均为 Gradle 子工程（跨平台，无 pwsh/sh 脚本）。注意 **`./gradlew build` 不含测试**。

```bash
# Suite 1 — ArtPI.h 原生 API            -> prebuild/test/artpi/
./gradlew :test:buildTest
./gradlew :test:pushTest               # 推送
./gradlew :test:runTest -Psu           # 设备上运行（root；-Pserial= 指定设备）

# Suite 2 — QuickJS 绑定                -> prebuild/test/js/
./gradlew :test-js:buildTest
./gradlew :test-js:runTest -Psu

# Playground — trace/hook 试验场        -> prebuild/test/harness/
./gradlew :test-harness:buildTest
./gradlew :test-harness:runTest -Psu   # 常驻；另开终端连 REPL（见 harness/README.md）
```

Suite 1 手动运行（等价）：

```bash
adb shell -t "su -c 'cd /data/local/tmp/artpi_test && \
  CLASSPATH=/data/local/tmp/artpi_test/classes.dex \
  ARTPI_TEST_LIB=/data/local/tmp/artpi_test/libartpi_test.so \
  app_process /system/bin com.artpi.test.Main'"
```

环境变量：`ARTPI_TEST_LIB`、`ARTPI_WAIT=1`、`ARTPI_STRICT=1`。
退出码：全通过 `0`，否则 `1`。末行 `Result: <passed> passed, <failed> failed, <skipped> skipped`。

> 仅支持 adb。本机 ssh 会话下 `app_process` 无法启动（静默退出、无输出），故脚本不提供 ssh 运行方式。

---

## 3. 覆盖范围

### Suite 1a — 功能（`Main.java`）

`init/isInitialized`、`resolve`（静态/实例/缺失）、`methodInfo`、`dumpSmali`、
hook 改写返回值 / 调原方法 / 篡改 arg0、`long`/`boolean`/`double`/`String`/实例方法、
`unhook`/`unhookAll`/句柄计数、nmmvm 解释执行、沙箱 Mock（`runMethodInternal` + `onInvoke`）、
内联 hook 路径拦截、`Method::trace`。

### Suite 1b — API 覆盖（`ApiCoverage.java`）

| 组 | 覆盖 |
|---|---|
| resolve 重载 | `(env,jclass)` `(env,className)` `(jclass)` `(className)` `(env,reflected)` `(ArtMethod*)` 全部 6 个 |
| Method getter | `isValid/operator bool/getName/getSignature/getDeclaringClassName/isStatic/isNative/isCompiled/getMethodId/getDeclaringClass/getAccessFlags/toString/dumpSmali/dumpCode/dumpNative` |
| HookHandle | `isValid/operator bool/isHooked/getBackup/getArtMethod/unhook` |
| ArgProxy | `frame[i]` 读 (`int`/`std::string`)、写 (`=int`/`=std::string`)、`as<int>`、`as_string`、`isThis/getIndex/isObject` |
| ArgsAccessor | `frame.args[i]` 读 / `as_string` |
| CallFrame | `getArgRaw/setArgRaw/getArg<T>/getArg(jobject)/getArgString/resetResult/hasResult/variant 元数据` |
| frame 级执行 | `invokeInterpreted`（当前实参 / 自定义实参）、`invokeTrace(METHOD_ONLY/INSTRUCTION_DIFF)`、`invokeInterpretedWith(cbs, Options)` |
| 解释器 | `runMethod`、`runMethodInternal`、`shortyFromSignature`、`RunResult`、`Options(max_instructions)`、`FilterOptions` |
| 沙箱决策 | `InvokeVerdict::Mock / JniDirect / StepIn` |
| 回调 | `onInsn`、`onInvoke`、`onInvokePost`、`onException`；`InvokeEvent::formatMethod/formatArgs/formatResult/getArgRaw/getArgString`；`ExceptionEvent::catchPc` |
| 工具 | `isSystemDescriptor`、`formatInvokeArgs`、`formatReturnValue`、`isInterpretingOnCurrentThread`、`setTraceEnabled/isTraceEnabled` |
| xDL | `xdl_open/xdl_sym/xdl_dsym/xdl_addr/xdl_addr_clean/xdl_close` |
| 引擎 | `PI::Native::initNativeEngine/isNativeEngineInitialized`、`Pine::PineInit`、`PI::dumpSmali/dumpCode/dumpNative/resolveNativeMethod` |

### Suite 2 — QuickJS 绑定（`js/JsMain.java`，44 断言）

JS 基础语义、`Java/Native/Memory/Trace/Debug` 命名空间与小写别名、全局别名清单、
`findclass/findmethod/methodtoart/dumpsmali/listMethods`、`Memory.*`（hexdump/readmem/writeU32/writemem/readstring）、
`jhook` 端到端（安装→调用→回调触发→`unhookall` 还原）、`Debug.*` 与 `Trace.*` 绑定面。
详见 [`js/README.md`](js/README.md)。

### 尚未覆盖（Suite 1 后续）

- `TracePreset::FULL_STACK_NATIVE`（需真实 native SO 目标）、`TraceGuard`（需 dex 内部句柄）。
- `DexResolver` 类（当前仅经 `dumpSmali`/解释器间接使用）。
- `xdl_info`、`PI::dumpNative(const void* pc, …)` 重载、`ArgProxy` 的 `jclass/void*/float/jlong/bool` 转换。
- `FilterOptions` 白/黑名单的**行为**（当前仅验证不改变结果）。

### 尚未覆盖（Suite 2 后续）

- `Trace.*`/`Debug.*` 的交互式语义（断点命中、协同单步、regs 读写）——当前仅验证绑定存在。
- `Native.nhook` 的真实 native 目标 hook（无 native SO 目标）、`agent_dynamic` 代理树细节。

---

## 4. 本套件发现并已修复的框架问题

1. **内联 hook 装了却拦截不到** — `CannotSafeInlineHook()` 对未编译方法（entry 指向共享
   `art_quick_to_interpreter_bridge`）误判为可内联；修复为 `!IsCompiled()` 强制走 replacement。
   （`engine/trampoline/trampoline_installer.h`）
2. **`Method::trace()` SIGSEGV** — `getJavaStackTrace()` 的 `FindClass`/`Throwable` 触发 ART
   托管栈回溯，而裸 hook 跳板无合法栈帧；改为原生 backtrace。
   （`engine/pine/pine_native.cpp`）
3. **float/double 参数与返回值全错** — `PineNativeContext` 公共头与内部/汇编定义不一致
   （缺 `sp`，`d[32]` vs `d[8]`）导致 `ctx->d[i]` 错位；补齐 FP 读写与 `F/D` 返回分支。
   （`include/ArtPI.h`、`engine/pine/pine_native.cpp/.h`）

详见各修复处代码注释与套件内对应断言（`inlineHook.intercept`、`hook.double.active`、`trace.*`）。

---

## 5. 相关文档

| 文档 | 内容 |
|---|---|
| [`../doc/JS_BINDINGS.md`](../doc/JS_BINDINGS.md) | JS 运行时绑定参考：绑定方式、逐域 API 表、hook 回调 `o`/`JRef`、`dynamic.*` 代理、示例与限制 |
| [`../doc/CLI_DESIGN.md`](../doc/CLI_DESIGN.md) | CLI 注入器、通信协议与 JS 运行时总体设计 |
