// Registers classes and LEAVES THEM ALIVE (no $dispose) so that a later
// REPL attach can inspect them:
//
//   findclass('GenKeep')            // simple-name lookup into the registry
//   findclass('com.artpi.probe.*')  // wildcard listing includes them
//   Java.registeredClasses()
//   dynamic.java.com.artpi.probe.GenKeep.listMethods()
//
// Run:  artpi-cli -S <pkg> -f /data/local/tmp/artpi_regclass_keep.js
var G = Java.registerClass({
    name: 'com.artpi.probe.GenKeep',
    methods: {
        ping: { returnType: 'java.lang.String', argumentTypes: [], static: true,
                implementation: function () { return 'pong'; } },
        add:  { returnType: 'int', argumentTypes: ['int', 'int'], static: true,
                implementation: function (a, b) { return a + b; } }
    }
});

var R = Java.registerClass({
    name: 'com.artpi.probe.RunnerKeep',
    implements: ['java.lang.Runnable'],
    methods: { run: function () { globalThis.__ran = 1; } }
});

'registered: ' + G.$className + ', ' + R.$className;
