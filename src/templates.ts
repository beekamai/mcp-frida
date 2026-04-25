/*
 * Pre-baked Frida script templates for common reverse-engineering tasks.
 * Returned by list-templates / get-template so the agent can paste them
 * straight into create-script. Each template is self-contained and has
 * a top comment describing parameters that the user typically wants
 * to tweak before running.
 */

export const TEMPLATES: Record<string, { description: string; source: string }> = {
  "trace-all-exports": {
    description:
      "Trace every export of a target module, log args and return values. " +
      "Replace MODULE with the module name (e.g. 'plugin.dll').",
    source: `
const MODULE = 'plugin.dll';
const matches = new ApiResolver('module').enumerateMatches('exports:' + MODULE + '!*');
send({ resolved: matches.length });
matches.forEach(m => {
  try {
    Interceptor.attach(m.address, {
      onEnter(args) {
        this.name = m.name;
        send({ ev: 'enter', fn: m.name, args: [args[0], args[1], args[2], args[3]].map(a => a ? a.toString() : null) });
      },
      onLeave(retval) {
        send({ ev: 'leave', fn: this.name, ret: retval ? retval.toString() : null });
      }
    });
  } catch (e) { send({ err: String(e), name: m.name }); }
});
`.trim(),
  },

  "dotnet-list-modules": {
    description:
      "Wait for the .NET runtime to be loaded, then enumerate loaded assemblies via clr.dll. " +
      "Useful as a sanity check that the bot's CLR is up before deeper hooks.",
    source: `
const runtime = Module.findBaseAddress('coreclr.dll') || Module.findBaseAddress('clr.dll');
send({ runtime: runtime ? runtime.toString() : null });
if (!runtime) {
  send({ err: 'No CoreCLR/CLR runtime found yet — script must run after runtime load' });
} else {
  // Hooks LoadLibraryExW so we see future modules too
  const llxw = Module.findExportByName('kernel32.dll', 'LoadLibraryExW');
  if (llxw) {
    Interceptor.attach(llxw, {
      onEnter(args) { this.path = args[0].readUtf16String(); },
      onLeave(retval) { send({ ev: 'LoadLibraryExW', path: this.path, handle: retval ? retval.toString() : null }); }
    });
  }
  Process.enumerateModules().filter(m => /\\.dll$/i.test(m.name)).forEach(m => send({ mod: m.name, base: m.base.toString(), path: m.path }));
}
`.trim(),
  },

  "dump-decrypted-dotnet-assembly": {
    description:
      "DNGuard / similar packers decrypt managed assemblies into freshly-allocated RX " +
      "regions before the JIT consumes them. This template enumerates RX ranges and " +
      "scans for PE/MZ headers, dumps each candidate to disk. Run after the bot has " +
      "logged in (so all license-time DLLs are decrypted).",
    source: `
const OUT_DIR = 'C:\\\\Users\\\\Jaros\\\\Desktop\\\\dumps';
const fs = new File(OUT_DIR + '\\\\index.txt', 'w');
let n = 0;
Process.enumerateRanges({ protection: 'r-x', coalesce: false }).forEach(r => {
  try {
    const head = r.base.readByteArray(2);
    if (!head) return;
    const u8 = new Uint8Array(head);
    if (u8[0] !== 0x4d || u8[1] !== 0x5a) return;
    // Naive PE: read e_lfanew, validate 'PE\\0\\0'
    const peOff = r.base.add(0x3c).readU32();
    const sig = r.base.add(peOff).readU32();
    if (sig !== 0x00004550) return;
    const buf = r.base.readByteArray(r.size);
    const path = OUT_DIR + '\\\\dump_' + r.base.toString() + '_' + r.size.toString(16) + '.bin';
    const f = new File(path, 'wb');
    f.write(buf);
    f.close();
    fs.write(path + '\\n');
    n++;
    send({ dumped: path, base: r.base.toString(), size: r.size });
  } catch (e) { /* skip */ }
});
fs.close();
send({ done: true, count: n });
`.trim(),
  },

  "hook-binaryformatter-deserialize": {
    description:
      "Many .NET Framework apps wrap encrypted blobs in an AES-then-BinaryFormatter " +
      "pipeline. Hooking System.Runtime.Serialization.Formatters.Binary.BinaryFormatter::Deserialize " +
      "via .NET internal call lets you observe every decrypted object. Requires CLR " +
      "runtime to be live. Replace ASSEMBLY paths if .NET 8+.",
    source: `
// Approximation: we hook the JIT entry by symbolic search after the runtime is up.
// For pure .NET hooks consider running 'dotnet-il-stub-trace' from frida-clr instead.
const runtime = Module.findBaseAddress('coreclr.dll');
if (!runtime) {
  send({ err: 'coreclr.dll not loaded' });
} else {
  const sym = DebugSymbol.findFunctionsMatching('*BinaryFormatter*Deserialize*');
  send({ candidates: sym.map(a => ({ addr: a.toString(), sym: DebugSymbol.fromAddress(a).toString() })) });
  sym.forEach(addr => {
    try {
      Interceptor.attach(addr, {
        onEnter(args) { send({ ev: 'BinaryFormatter::Deserialize', this: args[0].toString() }); },
        onLeave(retval) { send({ ev: 'BinaryFormatter::Deserialize:ret', ret: retval.toString() }); }
      });
    } catch (e) { send({ err: String(e) }); }
  });
}
`.trim(),
  },

  "il2cpp-bridge-bootstrap": {
    description:
      "Bootstrap the il2cpp-bridge for Unity targets. Once loaded, Il2Cpp.perform(() => ...) " +
      "exposes Il2Cpp.domain, classes, methods. Useful for native Unity games (not for " +
      ".NET Framework apps — use the BinaryFormatter template instead there).",
    source: `
// Requires user to load https://github.com/vfsfitvnm/frida-il2cpp-bridge bundled JS
// before running. Bridge: const Il2Cpp = require('frida-il2cpp-bridge');
const url = 'frida-il2cpp-bridge';
send({ note: "Use create-script with a bundled il2cpp-bridge build. Calling Il2Cpp.perform() inside the script body once 'GameAssembly.dll' is loaded." });
const wait = Module.findExportByName('GameAssembly.dll', 'il2cpp_init') || null;
send({ il2cpp_init: wait ? wait.toString() : 'not found' });
`.trim(),
  },

  "block-syscall-by-name": {
    description:
      "Replace a Win32 export with a stub that returns 0/false (or your chosen value). " +
      "Useful for killing anti-debug / anti-VM checks (IsDebuggerPresent, GetTickCount-loops). " +
      "Replace MODULE/FN/RET as needed.",
    source: `
const MODULE = 'kernel32.dll';
const FN = 'IsDebuggerPresent';
const RET = 0; // override return value
const addr = Module.findExportByName(MODULE, FN);
if (!addr) {
  send({ err: 'export not found: ' + MODULE + '!' + FN });
} else {
  Interceptor.replace(addr, new NativeCallback(function () {
    return RET;
  }, 'int', []));
  send({ replaced: MODULE + '!' + FN, ret: RET });
}
`.trim(),
  },

  "hook-button-onclick-windowsforms": {
    description:
      "WinForms button click handler hijack. The bot uses WinForms — every Button has " +
      "an onClick event whose underlying delegate eventually calls Button.OnClick. " +
      "Hook that to inspect/replace per-button behaviour. For your own cheat tool you " +
      "can also use it to fire actions on game UI.",
    source: `
// Symbol-based hook works only when CLR symbols are loaded; otherwise locate by signature.
const matches = DebugSymbol.findFunctionsMatching('*Windows.Forms.Button*OnClick*');
send({ matches: matches.map(a => DebugSymbol.fromAddress(a).toString()) });
matches.forEach(addr => {
  Interceptor.attach(addr, {
    onEnter(args) { send({ ev: 'Button.OnClick', this: args[0].toString() }); }
  });
});
`.trim(),
  },

  "hook-wininet-get": {
    description:
      "Trace HTTP requests through WinInet (HttpOpenRequestW / InternetReadFile). " +
      "Quick way to see CDN polling, license endpoints, telemetry — without TLS-MITM.",
    source: `
['HttpOpenRequestW', 'InternetReadFile', 'HttpSendRequestW', 'InternetConnectW'].forEach(name => {
  const addr = Module.findExportByName('wininet.dll', name);
  if (!addr) return send({ err: 'not found ' + name });
  Interceptor.attach(addr, {
    onEnter(args) {
      const a = [args[0], args[1], args[2], args[3]].map(p => {
        try { return p ? p.readUtf16String() : null; } catch { return p ? p.toString() : null; }
      });
      send({ ev: name, args: a });
    }
  });
});
`.trim(),
  },

  "find-pattern-and-patch": {
    description:
      "Scan all readable memory for a byte pattern and patch matches with a fixed payload. " +
      "Classic 'AOB+inject' style — for cheat development on native games or to disable " +
      "license checks once you know the comparison signature.",
    source: `
const PATTERN = '74 ?? 48 8b ?? ?? ?? ?? ?? 48 85 c0';
const PATCH_HEX = 'EB';  // jz -> jmp short
const ranges = Process.enumerateRanges({ protection: 'r-x', coalesce: true });
let total = 0;
for (const r of ranges) {
  try {
    Memory.scanSync(r.base, r.size, PATTERN).forEach(m => {
      total++;
      Memory.protect(m.address, 1, 'rwx');
      m.address.writeByteArray([parseInt(PATCH_HEX, 16)]);
      send({ patched: m.address.toString() });
    });
  } catch (e) { /* skip */ }
}
send({ done: true, total });
`.trim(),
  },
};

export const listTemplates = () =>
  Object.entries(TEMPLATES).map(([id, t]) => ({ id, description: t.description }));

export const getTemplate = (id: string) => {
  const t = TEMPLATES[id];
  if (!t) throw new Error(`Unknown template: ${id}. Use list-templates to see options.`);
  return { id, description: t.description, source: t.source };
};
