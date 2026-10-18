// Verifies BOTH DEX loading strategies inside a real app:
//   mode 0 -> dalvik.system.InMemoryDexClassLoader
//   mode 1 -> forced disk fallback (dalvik.system.DexClassLoader)
//   mode 2 -> emulates API < 26 (InMemoryDexClassLoader "missing" -> fallback)
//
// Run:  artpi-cli -S <pkg> -f /data/local/tmp/artpi_loader_modes.js
(function () {
    var out = [];
    function chk(n, a, e) {
        var ok = String(a) === String(e);
        out.push((ok ? 'PASS ' : 'FAIL ') + n + ' = ' + a + (ok ? '' : '  (want ' + e + ')'));
    }

    function exercise(mode, tag) {
        __native_dexdisk(mode);
        try {
            var G = Java.registerClass({
                name: 'com.artpi.probe.Loader' + tag,
                methods: {
                    ping: { returnType: 'java.lang.String', argumentTypes: [],
                            static: true,
                            implementation: function () { return tag; } },
                    add: { returnType: 'int', argumentTypes: ['int', 'int'],
                           static: true,
                           implementation: function (a, b) { return a + b; } }
                }
            });
            chk('mode' + mode + '.define', G.$className, 'com.artpi.probe.Loader' + tag);
            // In-memory dex can be spliced into the app loader; the disk
            // fallback cannot (ART: one DexFile -> one class loader).
            chk('mode' + mode + '.injected', G.$injected, mode === 0);
            chk('mode' + mode + '.ping', G.ping(), tag);
            chk('mode' + mode + '.add', G.add(20, 22), 42);
            var inst = G.$new();
            chk('mode' + mode + '.instance', typeof inst, 'object');
            chk('mode' + mode + '.artmethod', typeof G.$method('add', '(II)I'), 'bigint');
            G.$dispose();
        } catch (e) {
            out.push('EXC mode' + mode + ': ' + e);
        }
    }

    exercise(0, 'Mem');    // InMemoryDexClassLoader
    exercise(1, 'Disk');   // forced DexClassLoader
    exercise(2, 'NoMem');  // API<26 emulation -> automatic fallback
    __native_dexdisk(0);

    out.push('DONE');
    return out.join('\n');
})();
