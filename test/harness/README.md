# ArtPI Playground（trace / hook 试验场）

一个基于 `app_process` 的常驻 playground：进程内 `dlopen` `libartpi_agent.so`，
并起一个 **ticker 线程无限循环调用 `Target.step(i)`**，让 hook / tracer 装上去后
能源源不断收到调用事件，**无需驱动真实 App 的 UI**。

> 用途：把「trace/hook 机制」的调试与真实 App 解耦。要测真实 App 的某个方法，
> 仍建议注入到那个 App（见根 `README.md`），但机制本身的验证/迭代用这个 playground 最省事。

## 目录

```
test/harness/
├── cpp/harness.cpp                 # dlopen agent + JNI 入口 + native 目标
├── src/com/artpi/harness/
│   ├── Harness.java                # main：加载 agent + ticker + 本地 REPL
│   ├── Target.java                 # Java 目标（step/add/greet/callNative）
│   └── Native.java                 # native 目标（nativeAdd）
├── build.gradle                    # :test-harness（apply ../../gradle/test-suite.gradle）
└── README.md
```

## 构建与运行

```bash
./gradlew :test-harness:buildTest    # 编译 agent + harness so + dex -> prebuild/test/harness/
./gradlew :test-harness:pushTest     # 推送
./gradlew :test-harness:runTest -Psu # app_process 前台运行（阻塞；建议放 tmux）
```

前台运行会打印 agent endpoint（TCP `127.0.0.1:<port>`，root 有 INTERNET；否则 AF_UNIX），
并进入本地 REPL（读 stdin）。`Ctrl+C` 结束。

环境变量：

| 变量 | 默认 | 说明 |
|---|---|---|
| `ARTPI_HARNESS_INTERVAL_MS` | `500` | ticker 调用周期 |
| `ARTPI_HARNESS_MAX_TICKS` | `0`（无限） | >0 时跑完 N 次自动退出（冒烟用） |
| `ARTPI_HARNESS_LIB` | `/data/local/tmp/artpi_harness/libartpi_harness.so` | harness so 绝对路径 |

## 连接控制（REPL）

三种方式任选：

```bash
# 1) 主机 REPL（TCP）
adb forward tcp:20702 tcp:20702
python cli/artpi_repl.py --port 20702

# 2) 用注入器发现并复用已存在的 agent（不会再注入；进程名是 app_process）
PID=$(adb shell su -c 'pidof app_process')      # 或用 ps 过滤 Harness
adb shell su -c "/data/local/tmp/artpi-cli -P $PID"

# 3) 直接在 :test-harness:runTest 的前台会话里输入 JS（本地 REPL）
```

## 示例：装 hook / trace 观察 ticker

> **trace 逐指令 + debug 断点单步的完整实操与实测输出见
> [`../../doc/TRACE_DEBUG.md`](../../doc/TRACE_DEBUG.md)。**

```js
// hook Target.step，看每次调用的实参
var t = findclass('com.artpi.harness.Target');
jhook(findmethod(t, 'step', '(I)I'), o => {
    console.log('step arg0 = ' + o.args[0]);
    // o.args[0] = 42;  o.setResult(0);   // 改参 / 改返回值
});

// 贯通追踪 JNI 边界（Java -> native via QBDI）
traceunified(findmethod(t, 'callNative', '(II)I'),
    { onInsn: e => console.log(e.layer + ' ' + e.text) });

// 原生 hook
nhook(findSymbol('libartpi_harness.so', 'artpi_harness_native_add'), {
    onEnter: c => c.setArg(0, 100n),
    onLeave: c => c.setRet(0n)
});

unhookall();              // 清 Java hook
nunhookall();             // 清 native hook
```

预期：`Target.step` 的 hook 每 `ARTPI_HARNESS_INTERVAL_MS` 触发一次，
日志形如：

```
[EVT debug]   [hook] com.artpi.harness.Target.step entered
[EVT console] HOOK step arg0=16
[EVT debug]   [hook] com.artpi.harness.Target.step -> original return: 52
```

## 可选目标方法

| 目标 | 签名 | 用于 |
|---|---|---|
| `Target.step(int)` | `(I)I` | 调用链（`innerA`/`innerB`）→ 调用树 / StepIn |
| `Target.add(int,int)` | `(II)I` | 改参 / 改返回值 |
| `Target.greet(String)` | `(Ljava/lang/String;)Ljava/lang/String;` | 对象实参/返回值 |
| `Target.callNative(int,int)` | `(II)I` | JNI 边界 → `traceunified` |
| `Native.nativeAdd(int,int)` | native `artpi_harness_native_add` | `nhook` / `tracenative` |
