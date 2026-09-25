package com.artpi.harness;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import android.util.Log;

/**
 * ArtPI trace/hook playground.
 *
 * Loads libartpi_agent.so in-process and runs a background ticker that calls
 * {@link Target#step(int)} forever, so hooks / tracers installed from the agent
 * REPL get a continuous stream of calls without driving a real app UI.
 *
 * Env:
 *   ARTPI_HARNESS_INTERVAL_MS  ticker period (default 500)
 *   ARTPI_HARNESS_MAX_TICKS    stop after N ticks (default 0 = run forever)
 *
 * Connect from the host:
 *   adb forward tcp:20700 tcp:20700            # TCP (this process has inet)
 *   python cli/artpi_repl.py --port 20700
 * or attach the on-device injector REPL (it discovers & reuses the live agent):
 *   adb shell su -c '/data/local/tmp/artpi-cli -P <pid>'
 */
public class Harness {

    static {
        // Absolute path (isolated classloader namespace can't resolve short names).
        String lib = System.getenv("ARTPI_HARNESS_LIB");
        if (lib == null || lib.isEmpty()) {
            lib = "/data/local/tmp/artpi_harness/libartpi_harness.so";
        }
        System.load(lib);
    }

    private static native boolean load();
    private static native String eval(String js);
    private static native int listenPort();
    private static native String unixName();

    private static final String TAG = "ArtPI_Harness";

    /** Mirror output to both stdout (local REPL console) and logcat (detached). */
    private static void log(String s) {
        System.out.println(s);
        Log.i(TAG, s);
    }

    public static void main(String[] args) throws Exception {
        boolean ok = load();
        int pid = android.os.Process.myPid();

        long interval = 500;
        String iv = System.getenv("ARTPI_HARNESS_INTERVAL_MS");
        if (iv != null) {
            try { interval = Long.parseLong(iv.trim()); } catch (Exception ignored) {}
        }
        long maxTicks = 0;
        String mt = System.getenv("ARTPI_HARNESS_MAX_TICKS");
        if (mt != null) {
            try { maxTicks = Long.parseLong(mt.trim()); } catch (Exception ignored) {}
        }
        final long fInterval = interval;
        final long fMax = maxTicks;

        // Ticker: steady stream of Target.step(i) calls.
        Thread ticker = new Thread(() -> {
            long i = 0;
            while (fMax == 0 || i < fMax) {
                try {
                    int r = Target.step((int) i);
                    int a = Target.add((int) i, 1);
                    String g = Target.greet("h" + i);
                    int n = Target.callNative((int) i, 2);
                    if (i % 10 == 0) {
                        log("[harness] tick #" + i + " step=" + r + " add=" + a
                                + " greet=" + g + " native=" + n);
                    }
                    i++;
                    Thread.sleep(fInterval);
                } catch (Throwable t) {
                    t.printStackTrace();
                }
            }
            log("[harness] reached max ticks (" + fMax + "); ticker stopped.");
        }, "harness-ticker");
        ticker.setDaemon(true);
        ticker.start();

        // Wait until the agent net server has actually bound (it runs on a
        // separate thread ~hundreds of ms after dlopen).
        String un = null;
        int port = -1;
        for (int t = 0; t < 50; t++) {   // up to ~5s
            un = unixName();
            port = listenPort();
            if ((un != null && !un.isEmpty()) || port > 0) break;
            Thread.sleep(100);
        }

        log("========================================================");
        log(" ArtPI harness  |  agent loaded=" + ok + "  pid=" + pid);
        if (un != null && !un.isEmpty()) {
            log(" agent endpoint: @" + un);
            log("   adb forward tcp:20700 localabstract:" + un);
        } else {
            log(" agent endpoint: 127.0.0.1:" + port);
            log("   adb forward tcp:" + port + " tcp:" + port);
            log("   python cli/artpi_repl.py --port " + port);
        }
        log(" targets: Target.step/add/greet/callNative, Native.nativeAdd");
        log(" type JS below for a local REPL (or 'exit'), or attach remotely.");
        log("========================================================");

        // Optional on-device REPL (stdin). EOF does NOT exit the process so a
        // remote REPL can still attach afterwards.
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String line;
        while ((line = br.readLine()) != null) {
            line = line.trim();
            if (line.isEmpty()) continue;
            if (line.equals("exit") || line.equals("quit")) break;
            System.out.println(eval(line));
        }

        if (fMax > 0) {
            // Smoke-test mode: exit immediately so the caller regains the terminal
            // (halt() skips static destructors; the agent's joinable server thread
            // would otherwise std::terminate at exit).
            log("[harness] done (max ticks).");
            Runtime.getRuntime().halt(0);
        }

        log("[harness] stdin closed; ticker keeps running. attach a REPL or kill the pid.");

        // Stay alive so the agent server remains reachable.
        while (true) {
            Thread.sleep(60000);
        }
    }
}
