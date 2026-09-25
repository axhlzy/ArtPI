#!/usr/bin/env python3
"""
artpi_repl.py - Python Interactive REPL client for ArtPI Agent with rich Tab Autocomplete.
Connects to ArtPI Agent's TCP MessagePack protocol via adb port forwarding.

Protocol framing:
  [4-byte big-endian length][MessagePack binary payload]

Usage:
  # 1. Forward agent port to local host:
  #    adb forward tcp:20700 tcp:20700
  # 2. Start REPL:
  #    python artpi_repl.py --port 20700
  # Or automatically forward via ADB:
  #    python artpi_repl.py -s <serial> -p 20700 -r 20700
"""

import sys
import socket
import struct
import threading
import argparse
import subprocess
import json
import time

try:
    import msgpack
except ImportError:
    print("[!] msgpack not installed. Please install it via: pip install msgpack")
    sys.exit(1)

# Tab completion keywords & API patterns
COMPLETIONS = [
    "Java.",
    "Java.findClass(\"",
    "Java.findMethod(",
    "Java.listMethods(",
    "Java.findMethods(",
    "Java.methodToArt(",
    "Java.artToMethod(",
    "Java.enumerateClassLoaders()",
    "Java.dumpCode(",
    "Java.dumpSmali(",
    "Java.dumpNative(",
    "Java.decompile(",
    "Java.disassembly(",
    "Java.choose(",
    "Java.hook(",
    "Java.unhook(",
    "Java.unhookAll()",

    "Native.",
    "Native.findModule(\"",
    "Native.findSymbol(\"",
    "Native.enumerateExports(\"",
    "Native.hook(",
    "Native.dumpNative(",

    "Trace.",
    "Trace.unified(",
    "Trace.java(",
    "Trace.native(",

    "Debug.",
    "Debug.breakJava(",
    "Debug.breakNative(",
    "Debug.step()",
    "Debug.next()",
    "Debug.continue()",
    "Debug.return()",

    "Memory.",
    "Memory.hexdump(",
    "Memory.readByteArray(",
    "Memory.writeByteArray(",
    "Memory.readCString(",
    "Memory.readU32(",
    "Memory.writeU32(",

    "dynamic.java.",
    "dynamic.native.",

    "findclass(\"",
    "findmethod(",
    "listmethods(",
    "findmethods(",
    "dumpcode(",
    "dumpsmali(",
    "dumpnative(",
    "decompile(",
    "disassembly(",
    "choose(",
    "jhook(",
    "nhook(",
    "unhook(",
    "unhookall()",
    "untrace()",
    "D()",
    "detach()",

    "hexdump(",
    "readmem(",
    "writemem(",
    "readstring(",
    "readu32(",
    "writeu32(",

    "console.log(",
    "console.warn(",
    "console.error(",
    "exit",
    "quit",
    "q",
    "help",
    "clear",
    "cls",
]


JAVA_METHOD_ACTIONS = ["dumpCode()", "dumpSmali()", "dumpNative()", "disassembly()", "decompile()", "hook(", "hookallclassmethods(", "trace(", "break()", "address", "ptr", "artMethod", "isNative"]
JAVA_CLASS_ACTIONS = ["dumpCode()", "dumpSmali()", "disassembly()", "decompile()", "listMethods()", "findMethods(", "hookall(", "choose("]
NATIVE_SYMBOL_ACTIONS = ["dumpCode()", "dumpNative()", "hook(", "break()", "hexdump()", "address", "ptr", "readCString()", "readByteArray("]


class ArtPiCompleter:
    def __init__(self, client):
        self.client = client
        self.matches = []

    def complete(self, text, state):
        if state == 0:
            self.matches = self._build_matches(text)
        if state < len(self.matches):
            return self.matches[state]
        return None

    def _build_matches(self, text):
        text_lower = text.lower()
        matches = [c for c in COMPLETIONS if c.lower().startswith(text_lower)]
        if not self.client:
            return matches

        if text.startswith("dynamic.java.") or "dynamic.java.".startswith(text):
            matches.extend(self._java_matches(text))
        if text.startswith("dynamic.native.") or "dynamic.native.".startswith(text):
            matches.extend(self._native_matches(text))

        seen = set()
        uniq = []
        for m in matches:
            if m not in seen:
                seen.add(m)
                uniq.append(m)
        return uniq[:60]

    def _java_matches(self, text):
        out = []
        prefix = "dynamic.java."
        if not text.startswith(prefix):
            if prefix.startswith(text):
                out.append(prefix)
            return out
        rest = text[len(prefix):]
        classes = self.client.get_classes()
        matched = None
        for cls in classes:
            if rest == cls or rest.startswith(cls + "."):
                matched = cls
                break
        if matched and rest.startswith(matched + "."):
            after = rest[len(matched) + 1:]
            class_prefix = prefix + matched + "."
            if "." in after:
                method, act = after.split(".", 1)
                method_prefix = class_prefix + method + "."
                for a in JAVA_METHOD_ACTIONS:
                    if a.lower().startswith(act.lower()):
                        out.append(method_prefix + a)
            else:
                for a in JAVA_CLASS_ACTIONS:
                    if a.lower().startswith(after.lower()):
                        out.append(class_prefix + a)
                for m in self.client.get_class_methods(matched):
                    if m.lower().startswith(after.lower()):
                        out.append(class_prefix + m)
        else:
            for cls in classes:
                cand = prefix + cls
                if cand.lower().startswith(text.lower()):
                    out.append(cand)
        return out

    def _native_matches(self, text):
        out = []
        prefix = "dynamic.native."
        if not text.startswith(prefix):
            if prefix.startswith(text):
                out.append(prefix)
            return out
        rest = text[len(prefix):]
        modules = self.client.get_modules()
        matched = None
        for mod in modules:
            stem = mod[:-3] if mod.endswith(".so") else mod
            if rest == mod or rest.startswith(mod + ".") or rest == stem or rest.startswith(stem + "."):
                matched = mod if rest.startswith(mod) else stem
                break
        if matched and rest.startswith(matched + "."):
            after = rest[len(matched) + 1:]
            mod_prefix = prefix + matched + "."
            if "." in after:
                sym, act = after.split(".", 1)
                sym_prefix = mod_prefix + sym + "."
                for a in NATIVE_SYMBOL_ACTIONS:
                    if a.lower().startswith(act.lower()):
                        out.append(sym_prefix + a)
            else:
                for a in NATIVE_SYMBOL_ACTIONS:
                    if a.lower().startswith(after.lower()):
                        out.append(mod_prefix + a)
                for s in self.client.get_module_symbols(matched):
                    if s.lower().startswith(after.lower()):
                        out.append(mod_prefix + s)
                        if len(out) >= 40:
                            break
        else:
            for mod in modules:
                stem = mod[:-3] if mod.endswith(".so") else mod
                for name in (mod, stem):
                    cand = prefix + name
                    if cand.lower().startswith(text.lower()) and cand not in out:
                        out.append(cand)
        return out


def setup_readline(client):
    try:
        import readline
        completer = ArtPiCompleter(client)
        readline.set_completer(completer.complete)
        readline.set_completer_delims(" \t\n`!@#%^&*()=+[{]}\\|;:'\",<>/?")
        readline.parse_and_bind("tab: complete")
        return True
    except Exception:
        try:
            import pyreadline3 as readline
            completer = ArtPiCompleter(client)
            readline.set_completer(completer.complete)
            readline.set_completer_delims(" \t\n`!@#%^&*()=+[{]}\\|;:'\",<>/?")
            readline.parse_and_bind("tab: complete")
            return True
        except Exception:
            return False


class ArtPiClient:
    def __init__(self, host: str = "127.0.0.1", port: int = 20700):
        self.host = host
        self.port = port
        self.sock = None
        self.lock = threading.Lock()
        self.running = False
        self.recv_thread = None
        self._pending = None
        self._pending_event = threading.Event()
        self._silent = False
        self._classes = []
        self._modules = []
        self._class_methods = {}
        self._module_symbols = {}

    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            self.running = True
            self.recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
            self.recv_thread.start()
            return True
        except Exception as e:
            print(f"[!] Failed to connect to ArtPI Agent at {self.host}:{self.port}: {e}")
            return False

    def close(self):
        self.running = False
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def _recv_all(self, n: int):
        buf = bytearray()
        while len(buf) < n and self.running:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return None
            buf.extend(chunk)
        return bytes(buf)

    def _recv_loop(self):
        while self.running:
            try:
                header = self._recv_all(4)
                if not header or len(header) < 4:
                    break
                (length,) = struct.unpack("!I", header)
                if length == 0 or length > (32 * 1024 * 1024):
                    break
                payload = self._recv_all(length)
                if not payload or len(payload) < length:
                    break
                data = msgpack.unpackb(payload, raw=False)
                self._handle_message(data)
            except Exception as e:
                if self.running:
                    print(f"\n[!] Disconnected from server: {e}")
                break
        self.running = False

    def _handle_message(self, data):
        if self._silent and isinstance(data, dict) and data.get("t") != 3:
            self._pending = data
            self._pending_event.set()
            return
        if isinstance(data, dict):
            t = data.get("t")
            if t == 3:  # Broadcast Event / Log
                ch = data.get("ch", "event")
                ev_data = data.get("data")
                if ch in ("log", "console"):
                    sys.stdout.write(f"\r{ev_data}\nartpi> ")
                else:
                    sys.stdout.write(f"\r[{ch}] {ev_data}\nartpi> ")
                sys.stdout.flush()
                return

            # REPL response
            ok = data.get("ok", False)
            if ok:
                res = data.get("data", {})
                if isinstance(res, dict) and "result" in res:
                    val = res["result"]
                    sys.stdout.write(f"{val}\n")
                elif isinstance(res, dict) and "pkg" in res:
                    sys.stdout.write(f"[+] Connected to: {res['pkg']} (PID: {res.get('pid')})\n")
                else:
                    sys.stdout.write(f"{res}\n")
            else:
                err = data.get("err", "unknown error")
                sys.stdout.write(f"\033[31m[Error] {err}\033[0m\n")
            sys.stdout.write("artpi> ")
            sys.stdout.flush()
        else:
            sys.stdout.write(f"{data}\nartpi> ")
            sys.stdout.flush()

    def send_cmd(self, cmd: str, args: dict = None):
        if not self.sock or not self.running:
            print("[!] Not connected.")
            return
        req = {"cmd": cmd}
        if args is not None:
            req["args"] = args
        payload = msgpack.packb(req, use_bin_type=True)
        length = struct.pack("!I", len(payload))
        with self.lock:
            try:
                self.sock.sendall(length + payload)
            except Exception as e:
                print(f"[!] Send failed: {e}")
                self.running = False

    def eval_js(self, script: str):
        self.send_cmd("eval", {"script": script})

    def eval_js_sync(self, script: str, timeout: float = 2.0):
        self._pending_event.clear()
        self._pending = None
        self._silent = True
        try:
            self.send_cmd("eval", {"script": script})
            if not self._pending_event.wait(timeout):
                return None
            data = self._pending or {}
            if data.get("ok"):
                res = data.get("data", {})
                if isinstance(res, dict):
                    return res.get("result")
                return res
            return None
        finally:
            self._silent = False

    def refresh_completion_index(self):
        raw = self.eval_js_sync("JSON.stringify(dynamic.__getCompletionData())")
        if not raw:
            return
        try:
            obj = json.loads(raw) if isinstance(raw, str) else raw
            self._classes = obj.get("classes", []) if isinstance(obj, dict) else []
            self._modules = obj.get("modules", []) if isinstance(obj, dict) else []
        except Exception:
            pass

    def get_classes(self):
        if not self._classes:
            self.refresh_completion_index()
        return self._classes

    def get_modules(self):
        if not self._modules:
            self.refresh_completion_index()
        return self._modules

    def get_class_methods(self, class_name: str):
        if class_name in self._class_methods:
            return self._class_methods[class_name]
        raw = self.eval_js_sync(f'JSON.stringify(dynamic.__getClassMethods("{class_name}"))')
        methods = []
        if raw:
            try:
                methods = json.loads(raw) if isinstance(raw, str) else list(raw)
            except Exception:
                methods = []
        self._class_methods[class_name] = methods
        return methods

    def get_module_symbols(self, mod_name: str):
        if mod_name in self._module_symbols:
            return self._module_symbols[mod_name]
        raw = self.eval_js_sync(f'JSON.stringify(dynamic.__getModuleSymbols("{mod_name}"))')
        symbols = []
        if raw:
            try:
                symbols = json.loads(raw) if isinstance(raw, str) else list(raw)
            except Exception:
                symbols = []
        self._module_symbols[mod_name] = symbols
        return symbols


def setup_adb_forward(serial: str, device_port: int, local_port: int) -> bool:
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    cmd += ["forward", f"tcp:{local_port}", f"tcp:{device_port}"]
    print(f"[*] Setting up ADB port forward: {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"[!] adb forward failed: {res.stderr.strip()}")
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description="ArtPI Remote Python REPL Client")
    parser.add_argument("-H", "--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    parser.add_argument("-p", "--port", type=int, default=20700, help="Local or forwarded TCP port (default: 20700)")
    parser.add_argument("-s", "--serial", default="", help="ADB device serial for auto port-forwarding")
    parser.add_argument("-r", "--remote-port", type=int, default=0, help="Device port to forward from (if specified)")
    args = parser.parse_args()

    if args.remote_port > 0:
        if not setup_adb_forward(args.serial, args.remote_port, args.port):
            sys.exit(1)

    print("=" * 62)
    print("  ArtPI Python Remote REPL Client")
    print(f"  Target: {args.host}:{args.port}")
    print("  Type 'help' or JavaScript snippets (e.g. Java.findClass(...))")
    print("  Type 'exit' or Ctrl+D to quit.")
    print("=" * 62)

    client = ArtPiClient(args.host, args.port)
    if not client.connect():
        sys.exit(1)

    has_readline = setup_readline(client)
    if has_readline:
        print("  [Tab Autocomplete Enabled: classes / methods / libs / symbols]")
    client.refresh_completion_index()

    # Initial hello / query target info
    client.send_cmd("info")

    last_cmd = ""
    try:
        while client.running:
            try:
                line = input("artpi> ")
            except EOFError:
                break
            except KeyboardInterrupt:
                print()
                continue

            line = line.strip()
            if not line:
                if last_cmd:
                    line = last_cmd
                    print(f"artpi> {line}")
                else:
                    continue
            if line in ("exit", "quit", "q"):
                break
            if line in ("clear", "cls"):
                print("\033[2J\033[H", end="")
                continue
            if line in ("help", "?"):
                print("Available built-ins:")
                print("  Java.findClass(name)         - Find class by name")
                print("  Java.listMethods(clazz)      - List methods of class")
                print("  Java.dumpCode(method)        - Disassemble Java/Native code")
                print("  Java.hook(method, callbacks) - Hook Java method")
                print("  Native.findSymbol(mod, sym)  - Find native symbol")
                print("  Native.dumpNative(addr)      - Disassemble ARM64 native code")
                print("  Memory.hexdump(addr, len)    - Hexdump memory")
                continue

            last_cmd = line
            client.eval_js(line)
    finally:
        client.close()
        print("\n[*] Exiting ArtPI REPL. Bye!")


if __name__ == "__main__":
    main()
