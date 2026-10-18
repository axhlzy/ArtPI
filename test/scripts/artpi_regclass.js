// ArtPI on-device smoke test: Java.registerClass (runtime DEX generation).
// Run with:  artpi-cli -S <pkg> -f /data/local/tmp/artpi_regclass.js
(function () {
    var out = [];
    function chk(name, actual, expected) {
        var ok = String(actual) === String(expected);
        out.push((ok ? 'PASS ' : 'FAIL ') + name + ' = ' + actual +
                 (ok ? '' : '  (want ' + expected + ')'));
        return ok;
    }

    function run(tag) {
        try {
            var G = Java.registerClass({
                name: 'com.artpi.probe.Gen' + tag,
                methods: {
                    ping: { returnType: 'java.lang.String', argumentTypes: [],
                            static: true,
                            implementation: function () { return 'pong'; } },
                    add: { returnType: 'int', argumentTypes: ['int', 'int'],
                           static: true,
                           implementation: function (a, b) { return a + b; } }
                }
            });
            chk(tag + '.define', G.$className, 'com.artpi.probe.Gen' + tag);
            chk(tag + '.ping', G.ping(), 'pong');
            chk(tag + '.add', G.add(20, 22), 42);
            chk(tag + '.new', typeof G.$new(), 'object');
            chk(tag + '.artmethod', typeof G.$method('add', '(II)I'), 'bigint');
            chk(tag + '.dispose', G.$dispose(), true);
        } catch (e) {
            out.push('EXC ' + tag + ': ' + e);
        }
    }

    function runnable(tag) {
        try {
            globalThis.__ran = 0;
            var T = Java.registerClass({
                name: 'com.artpi.probe.Runner' + tag,
                implements: ['java.lang.Runnable'],
                methods: { run: function () { globalThis.__ran = 7; } }
            });
            var t = T.$new();
            t.run();                       // instance method through the JRef proxy
            chk(tag + '.runnable', globalThis.__ran, 7);
            T.$dispose();
        } catch (e) {
            out.push('EXC ' + tag + '-runnable: ' + e);
        }
    }

    run('Mem');
    runnable('Mem');

    // Force the DexClassLoader fallback (API < 26 path) and repeat.
    // The flag only affects DEX loading, so it is safe to flip at runtime.
    __native_dexdisk(1);
    run('Disk');
    runnable('Disk');
    __native_dexdisk(0);

    out.push('DONE');
    return out.join('\n');
})();
