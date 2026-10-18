// Verifies Java.loadDex + that loaded DEXes are spliced into the app
// PathClassLoader (so Class.forName(name, init, appLoader) resolves them).
//
// Requires /data/user/0/<pkg>/cache/artpi_probe.dex (a standalone dex).
// Run:  artpi-cli -S <pkg> -f /data/local/tmp/artpi_loaddex.js
(function () {
    var out = [];
    function chk(n, a, e) {
        var ok = String(a) === String(e);
        out.push((ok ? 'PASS ' : 'FAIL ') + n + ' = ' + a + (ok ? '' : '  (want ' + e + ')'));
    }

    // ---- 1. Java.registerClass now default-injects into the app loader ----
    try {
        var G = Java.registerClass({
            name: 'com.artpi.probe.GenInj',
            methods: {
                ping: { returnType: 'java.lang.String', argumentTypes: [], static: true,
                        implementation: function () { return 'pong'; } }
            }
        });
        chk('reg.injected', G.$injected, true);
        chk('reg.call', G.ping(), 'pong');
        var cls = __native_jcall('java.lang.Class', 'forName',
                                 'com.artpi.probe.GenInj', true, G.$loader);
        chk('reg.apploader.name', cls.getName(), 'com.artpi.probe.GenInj');
        out.push('reg.classes = ' + Java.registeredClasses().join(','));
    } catch (e) {
        out.push('EXC reg: ' + e);
    }

    // ---- 2. Java.loadDex on a standalone .dex ----
    try {
        var app = __native_jcall('android.app.ActivityThread', 'currentApplication');
        var dir = app.getCacheDir().getAbsolutePath();
        var path = dir + '/artpi_probe.dex';
        out.push('loaddex.path = ' + path);

        var D = Java.loadDex(path, { name: 'probe' });
        chk('loaddex.injected', D.$injected, true);
        chk('loaddex.loadClass', D.loadClass('com.artpi.js.JsTarget').getName(),
            'com.artpi.js.JsTarget');
        chk('loaddex.call', __native_jcall('com.artpi.js.JsTarget', 'add', 20, 22), 42);

        var viaAppLoader = __native_jcall('java.lang.Class', 'forName',
                                          'com.artpi.js.JsTarget', true, D.$loader);
        chk('loaddex.apploader', viaAppLoader.getName(), 'com.artpi.js.JsTarget');

        out.push('loadedDexes = ' + Java.loadedDexes().map(function (x) {
            return x.name + ':' + x.injected;
        }).join(','));
    } catch (e) {
        out.push('EXC loaddex: ' + e);
    }

    // ---- 3. opt-out: isolated loader stays invisible to the app loader ----
    try {
        var app2 = __native_jcall('android.app.ActivityThread', 'currentApplication');
        var dir2 = app2.getCacheDir().getAbsolutePath();
        var I = Java.loadDex(dir2 + '/artpi_probe.dex', { name: 'isolated', inject: false });
        chk('isolated.injected', I.$injected, false);
        chk('isolated.loadClass', I.loadClass('com.artpi.js.JsCallback').getName(),
            'com.artpi.js.JsCallback');
    } catch (e) {
        out.push('EXC isolated: ' + e);
    }

    out.push('DONE');
    return out.join('\n');
})();
