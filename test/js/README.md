# Suite 2 — ArtPI QuickJS bindings

在真机上验证注入代理 `libartpi_agent.so` 内的 **QuickJS 运行时与 JS API 绑定**。

驱动方式（无需注入第三方 App）：测试库 `libartpi_js_test.so` 在 `app_process` 中
`dlopen` 载入 `libartpi_agent.so`（其构造函数会拉起 `PI::init` + QuickJS + TCP server），
再通过导出入口 `artpi_agent_js_eval()` 执行 JS 片段并断言结果。

---

## 1. 目录结构

```
test/js/
├── cpp/js_test.cpp                  # JNI 驱动：dlopen agent + eval + 已知内存缓冲
├── src/com/artpi/js/
│   ├── JsMain.java                  # 断言入口（132 项）
│   ├── NativeJs.java                # native 声明
│   ├── JsTarget.java                # JS 侧被测目标类（含 Box 字段对象）
│   └── JsNativeTarget.java          # JNI 边界目标（traceunified 用，nadd 静态注册）
├── build.gradle                     # :test-js（apply ../../gradle/test-suite.gradle）
└── README.md
```

## 2. 构建与运行

```bash
./gradlew :test-js:buildTest    # ninja(agent+js_test) + javac + d8 -> prebuild/test/js/
./gradlew :test-js:pushTest     # 推送
./gradlew :test-js:runTest -Psu # app_process 运行
```

推送三个产物到 `/data/local/tmp/artpi_js_test/`：`libartpi_agent.so`、`libartpi_js_test.so`、`classes.dex`。
（`/data/local/tmp` 对 shell 只读，任务经 `/sdcard` 暂存 + `su` 搬入。）

> 仅支持 adb 运行（本机 ssh 会话无法运行 app_process）。

结果行：`Result: <passed> passed, <failed> failed`；退出码 0/1。

---

## 3. 覆盖范围（54 项）

| 组 | 覆盖 |
|---|---|
| JS 基础 | 算术、字符串、BigInt、布尔/null/undefined、闭包、数组、`console.log`、异常捕获 |
| 命名空间 | `Java/Native/Memory/Trace/Debug` 及小写别名 `debug/memory/trace` |
| 全局别名 | `findclass findmethod methodtoart dumpsmali jhook unhook unhookall nhook traceunified tracejava tracenative brkj brkn s n c r bt inspect po getreg setreg dumpRegs thread hexdump readmem writemem readstring readu32 writeU32` |
| Debug 命名空间 | `Debug.breakJava/breakNative/continue/step/next/return/bt/inspect/getreg/setreg/dumpRegs/thread`；`regs` Proxy 对象 |
| Java 绑定 | `findclass`（命中/未命中）、`findmethod`、`methodtoart` 往返一致、`dumpsmali` 含 opcode、`listMethods`、`enumloaders` 冒烟 |
| Memory 绑定 | `hexdump` 字节、`readu32` 小端、`readmem` ArrayBuffer、`writeU32` 往返、`writemem`+`readstring` |
| JS Hook（端到端） | 观察型：`jhook(m, cb)` 安装 → Java 调用 → 回调计数 → 原方法仍执行 → `unhookall()` 还原 |
| JS Hook（改参/改返回） | `o.setResult(v)` 覆盖返回值且跳过原方法；`o.args[i]=` 改参后执行原方法；String 入参读取 + String 返回值覆写 |
| Native/Trace/Debug 面 | `nhook`/`Native.findModule`/`Native.findSymbol`、`traceunified/tracejava/tracenative`、`brkj/brkn/s/n/c/r`、`Debug.*` |

### JS hook 回调对象（`o`）

```js
const t = findclass("com.example.Foo");
const m = findmethod(t, "bar", "(Lcom/example/Box;)I");
jhook(m, o => {
    o.method;                        // 方法名
    o.class;                         // 声明类描述符
    o.thiz;                          // 实例方法的 this（JRef；静态为 null）
    o.args[0].value;                 // 对象实参：读 int 字段
    o.args[0].value = 42;            // 写字段（原地修改，原方法可见）
    o.args[0].label;                 // String 字段 -> JS string
    String(o.args[0]);               // -> object.toString()
    o.args[1] = 99;                  // 基本类型改参（原方法以新实参执行）
    // o.setResult(v);               // 覆写返回值：调用后跳过原方法
    // 未调用 setResult 时，框架以（可能已改的）实参执行原方法
});
```

参数/返回值按签名自动编组：`I/S/B/C→number`、`J→BigInt`、`Z→boolean`、`F/D→number`、
`String→string`；非 String 对象曝露为 **JRef**（字段读写 + `toString`，句柄仅在本次回调内有效）。

hook 回调的每个动作都会打日志（`[debug] [hook] … entered / arg[i] MODIFIED / return MODIFIED to … / original return …`），
经 `artpi_agent_take_log()` 回读（测试用 `NativeJs.takeLog()` 断言）。

### 命名约定（易混，已按实现校正）

- **命名空间 vs 全局别名** 双轨：如 `Debug.breakJava` ⇄ 全局 `brkj`；`Debug.step` ⇄ 全局 `s`。
  `breakJava/breakNative/step/next/continue/return` **仅**挂 `Debug.*`（无同名全局）；`stop` 未实现。
- 无全局 `findmodule/findsymbol`，模块/符号走 `Native.findModule` / `Native.findSymbol`。

---

## 4. 已修复的绑定层问题

1. **`jhook` 原先只读**：回调只能观察 `{method,args(字符串)}`，框架无条件执行原方法，JS 无法改参/改返回值。
   现已支持面向对象的回调对象 `o`：`o.args[i]` 读写（按签名编组）、`o.setResult(v)` 覆写返回值并跳过原方法。
   （`src/agent/agent_java.cpp` `JsJavaHook` + `JsValueFromFrameArg/JsValueToFrameArg/JsValueToFrameResult`）
2. **回调 JSValue 泄漏**：原实现把 `JS_DupValue` 后的 callback 捕获进 Pine 的 `std::function`，
   unhook 时不释放。现用 `std::shared_ptr<JSValue>` 守卫，hook 移除（`std::function` 析构）即释放。
3. **JRef 字段访问崩溃（SIGSEGV）**：JRef 起初在 hook 回调里调用 `env->FindClass`，在无托管栈帧的跳板
   上下文触发 ART `StackVisitor::WalkStack` 崩溃。改为 **init 期预缓存** `java.lang.Class` / `reflect.Field` /
   各包装类（`InitJRefClassCache`），hook 路径完全禁用 `FindClass`。
4. **hook 日志缺失**：补上 entry / 改参 / 改返回值 / 原返回 日志，并落环形缓冲供测试与 REPL 回读
   （`src/agent/agent_net.cpp` `artpi_agent_take_log`）。

## 5. 尚未覆盖（后续）

- `Trace.*` / `Debug.*` 的**交互式语义**（断点命中、协同单步、regs 读写）——当前仅验证绑定存在。
- `Native.nhook` 的真实 IL2CPP/Native 目标 hook（无 native SO 目标）。
- JRef 的方法调用（`obj.method(...)`）、数组元素访问、句柄跨回调存活。
- `agent_dynamic` 的 `dynamic.*` 代理树细节（`__native_getClassMethods` 等）。
