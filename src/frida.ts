/*
 * Frida session manager — wraps frida-node into a stateful API for the MCP layer.
 * Sessions, scripts and trace handles live in process memory and are addressed by
 * stable string ids so the MCP client can drive long-running instrumentation
 * across multiple tool calls.
 */
import frida, { Device, Session, Script, TargetProcess, ScriptRuntime } from "frida";
import { writeFile } from "node:fs/promises";

type ScriptEntry = {
  id: string;
  sessionId: string;
  source: string;
  script: Script;
  messages: { type: string; payload: unknown; data?: string }[];
  createdAt: number;
};

type SessionEntry = {
  id: string;
  pid: number;
  target: string;
  device: Device;
  session: Session;
  spawned: boolean;
  resumed: boolean;
  createdAt: number;
};

type TraceEntry = {
  id: string;
  sessionId: string;
  scriptId: string;
  patterns: string[];
  startedAt: number;
};

const sessions = new Map<string, SessionEntry>();
const scripts = new Map<string, ScriptEntry>();
const traces = new Map<string, TraceEntry>();

let counter = 0;
const nextId = (prefix: string) => `${prefix}_${Date.now().toString(36)}_${(counter++).toString(36)}`;

const requireSession = (sessionId: string): SessionEntry => {
  const entry = sessions.get(sessionId);
  if (!entry) throw new Error(`Unknown sessionId: ${sessionId}`);
  return entry;
};

const requireScript = (scriptId: string): ScriptEntry => {
  const entry = scripts.get(scriptId);
  if (!entry) throw new Error(`Unknown scriptId: ${scriptId}`);
  return entry;
};

const resolveDevice = async (deviceId?: string): Promise<Device> => {
  if (!deviceId || deviceId === "local") return frida.getLocalDevice();
  if (deviceId === "usb") return frida.getUsbDevice();
  if (deviceId === "remote") return frida.getRemoteDevice();
  const mgr = await frida.getDeviceManager();
  const all = await mgr.enumerateDevices();
  const match = all.find((d) => d.id === deviceId || d.name === deviceId);
  if (!match) throw new Error(`Device not found: ${deviceId}`);
  return match;
};

export const listDevices = async () => {
  const mgr = await frida.getDeviceManager();
  const devs = await mgr.enumerateDevices();
  return devs.map((d) => ({ id: d.id, name: d.name, type: d.type }));
};

export const listProcesses = async (deviceId?: string) => {
  const dev = await resolveDevice(deviceId);
  const procs = await dev.enumerateProcesses();
  return procs.map((p) => ({ pid: p.pid, name: p.name }));
};

export const listApplications = async (deviceId?: string) => {
  const dev = await resolveDevice(deviceId);
  try {
    const apps = await dev.enumerateApplications();
    return apps.map((a) => ({ pid: a.pid, name: a.name, identifier: a.identifier }));
  } catch (e) {
    return { error: `enumerate-applications not supported on this device: ${(e as Error).message}` };
  }
};

export const spawn = async (program: string, args?: string[], deviceId?: string) => {
  const dev = await resolveDevice(deviceId);
  const pid = await dev.spawn(program, { argv: args ? [program, ...args] : [program] });
  const session = await dev.attach(pid);
  const id = nextId("sess");
  sessions.set(id, {
    id,
    pid,
    target: program,
    device: dev,
    session,
    spawned: true,
    resumed: false,
    createdAt: Date.now(),
  });
  return { sessionId: id, pid, suspended: true, hint: "Call resume(sessionId) after loading scripts to continue execution." };
};

export const attach = async (target: string | number, deviceId?: string) => {
  const dev = await resolveDevice(deviceId);
  const procTarget: TargetProcess = target;
  const session = await dev.attach(procTarget);
  const id = nextId("sess");
  const pid = typeof target === "number" ? target : (await dev.getProcess(target)).pid;
  sessions.set(id, {
    id,
    pid,
    target: typeof target === "string" ? target : `pid:${target}`,
    device: dev,
    session,
    spawned: false,
    resumed: true,
    createdAt: Date.now(),
  });
  return { sessionId: id, pid };
};

export const resume = async (sessionId: string) => {
  const entry = requireSession(sessionId);
  if (entry.resumed) return { sessionId, alreadyResumed: true };
  await entry.device.resume(entry.pid);
  entry.resumed = true;
  return { sessionId, resumed: true };
};

export const detach = async (sessionId: string) => {
  const entry = requireSession(sessionId);
  for (const [sid, s] of scripts) {
    if (s.sessionId === sessionId) {
      try { await s.script.unload(); } catch { /* ignore */ }
      scripts.delete(sid);
    }
  }
  for (const [tid, t] of traces) if (t.sessionId === sessionId) traces.delete(tid);
  await entry.session.detach();
  sessions.delete(sessionId);
  return { sessionId, detached: true };
};

export const kill = async (sessionId: string) => {
  const entry = requireSession(sessionId);
  await entry.device.kill(entry.pid);
  sessions.delete(sessionId);
  return { sessionId, killed: true, pid: entry.pid };
};

export const listSessions = () =>
  Array.from(sessions.values()).map((s) => ({
    sessionId: s.id,
    pid: s.pid,
    target: s.target,
    spawned: s.spawned,
    resumed: s.resumed,
    createdAt: s.createdAt,
  }));

export const createScript = async (sessionId: string, source: string, runtime?: "qjs" | "v8") => {
  const entry = requireSession(sessionId);
  const opts = runtime
    ? { runtime: runtime === "v8" ? ScriptRuntime.V8 : ScriptRuntime.QJS }
    : undefined;
  const script = await entry.session.createScript(source, opts);
  const id = nextId("scr");
  const scriptEntry: ScriptEntry = {
    id,
    sessionId,
    source,
    script,
    messages: [],
    createdAt: Date.now(),
  };
  script.message.connect((message: any, data: Buffer | null) => {
    scriptEntry.messages.push({
      type: message.type,
      payload: message.type === "error" ? { description: message.description, stack: message.stack } : message.payload,
      data: data ? data.toString("base64") : undefined,
    });
    if (scriptEntry.messages.length > 5000) scriptEntry.messages.splice(0, scriptEntry.messages.length - 5000);
  });
  await script.load();
  scripts.set(id, scriptEntry);
  return { scriptId: id, sessionId };
};

export const destroyScript = async (scriptId: string) => {
  const entry = requireScript(scriptId);
  try { await entry.script.unload(); } catch { /* ignore */ }
  scripts.delete(scriptId);
  return { scriptId, destroyed: true };
};

export const listScripts = () =>
  Array.from(scripts.values()).map((s) => ({
    scriptId: s.id,
    sessionId: s.sessionId,
    sourceBytes: s.source.length,
    pendingMessages: s.messages.length,
    createdAt: s.createdAt,
  }));

export const evalInSession = async (
  sessionId: string,
  source: string,
  timeoutMs = 5000
): Promise<{ result?: unknown; messages: ScriptEntry["messages"]; error?: string }> => {
  const wrapped = `
    (async () => {
      try {
        const __r = await (async () => { ${source} })();
        send({ __mcp_eval__: true, ok: true, value: __r });
      } catch (e) {
        send({ __mcp_eval__: true, ok: false, error: String(e), stack: e && e.stack });
      }
    })();
  `;
  const { scriptId } = await createScript(sessionId, wrapped);
  const entry = requireScript(scriptId);
  const start = Date.now();
  let resultMsg: any = null;
  while (Date.now() - start < timeoutMs) {
    const idx = entry.messages.findIndex((m) => (m.payload as any)?.__mcp_eval__);
    if (idx >= 0) {
      resultMsg = entry.messages.splice(idx, 1)[0];
      break;
    }
    await new Promise((r) => setTimeout(r, 25));
  }
  const otherMessages = entry.messages.slice();
  await destroyScript(scriptId);
  if (!resultMsg) return { messages: otherMessages, error: `eval timed out after ${timeoutMs}ms` };
  const payload = resultMsg.payload as any;
  if (payload.ok) return { result: payload.value, messages: otherMessages };
  return { messages: otherMessages, error: payload.error };
};

export const postMessage = async (scriptId: string, payload: unknown) => {
  const entry = requireScript(scriptId);
  entry.script.post(payload as any);
  return { scriptId, posted: true };
};

export const recvMessages = async (scriptId: string, drain = true, max = 200) => {
  const entry = requireScript(scriptId);
  const slice = entry.messages.slice(0, max);
  if (drain) entry.messages.splice(0, slice.length);
  return { scriptId, count: slice.length, remaining: entry.messages.length, messages: slice };
};

export const callRpc = async (scriptId: string, fn: string, args: unknown[] = []) => {
  const entry = requireScript(scriptId);
  const exports_: any = entry.script.exports as any;
  if (!exports_ || typeof exports_[fn] !== "function") {
    throw new Error(`Script does not expose rpc.exports.${fn}. Check the script defines rpc.exports = { ${fn}: ... }.`);
  }
  const result = await exports_[fn](...args);
  return { scriptId, fn, result };
};

const evalOk = async (sessionId: string, expr: string, timeoutMs = 8000) => {
  const r = await evalInSession(sessionId, `return ${expr};`, timeoutMs);
  if (r.error) throw new Error(r.error);
  return r.result;
};

export const listModules = (sessionId: string) =>
  evalOk(
    sessionId,
    `Process.enumerateModules().map(m => ({ name: m.name, base: m.base.toString(), size: m.size, path: m.path }))`
  );

export const listExports = (sessionId: string, moduleName: string) =>
  evalOk(
    sessionId,
    `Module.enumerateExports(${JSON.stringify(moduleName)}).map(e => ({ type: e.type, name: e.name, address: e.address.toString() }))`,
    20000
  );

export const listImports = (sessionId: string, moduleName: string) =>
  evalOk(
    sessionId,
    `Module.enumerateImports(${JSON.stringify(moduleName)}).map(i => ({ type: i.type, name: i.name, module: i.module, address: i.address ? i.address.toString() : null }))`
  );

export const findSymbol = (sessionId: string, name: string, moduleName?: string) =>
  evalOk(
    sessionId,
    moduleName
      ? `(() => { const a = Module.findExportByName(${JSON.stringify(moduleName)}, ${JSON.stringify(name)}); return a ? a.toString() : null; })()`
      : `(() => { const a = DebugSymbol.fromName(${JSON.stringify(name)}); return a && !a.address.isNull() ? { name: a.name, module: a.moduleName, address: a.address.toString() } : null; })()`
  );

export const readMemory = (sessionId: string, address: string, size: number, format: "hex" | "base64" = "hex") =>
  evalOk(
    sessionId,
    `(() => {
      const ptr_ = ptr(${JSON.stringify(address)});
      const buf = ptr_.readByteArray(${size});
      if (!buf) return null;
      const arr = new Uint8Array(buf);
      ${
        format === "hex"
          ? `let s=''; for (let i=0;i<arr.length;i++){const h=arr[i].toString(16); s+= h.length===1?'0'+h:h;} return s;`
          : `let s=''; for (let i=0;i<arr.length;i++) s+= String.fromCharCode(arr[i]); return { base64: globalThis.btoa ? btoa(s) : Memory.allocUtf8String(s).readCString() };`
      }
    })()`,
    20000
  );

export const writeMemory = async (sessionId: string, address: string, hex: string) => {
  const cleaned = hex.replace(/[^0-9a-fA-F]/g, "");
  if (cleaned.length % 2) throw new Error("hex string must be even length");
  return evalOk(
    sessionId,
    `(() => {
      const bytes = [${Array.from({ length: cleaned.length / 2 }, (_, i) => parseInt(cleaned.slice(i * 2, i * 2 + 2), 16)).join(",")}];
      ptr(${JSON.stringify(address)}).writeByteArray(bytes);
      return { written: bytes.length };
    })()`
  );
};

export const scanMemory = (sessionId: string, address: string, size: number, pattern: string, max = 100) =>
  evalOk(
    sessionId,
    `(() => {
      const hits = [];
      Memory.scanSync(ptr(${JSON.stringify(address)}), ${size}, ${JSON.stringify(pattern)}).forEach(h => {
        if (hits.length < ${max}) hits.push({ address: h.address.toString(), size: h.size });
      });
      return hits;
    })()`,
    60000
  );

export const enumerateRanges = (sessionId: string, protection = "r--") =>
  evalOk(
    sessionId,
    `Process.enumerateRanges(${JSON.stringify(protection)}).map(r => ({ base: r.base.toString(), size: r.size, protection: r.protection, file: r.file ? { path: r.file.path, offset: r.file.offset } : null }))`,
    20000
  );

export const dumpRange = async (sessionId: string, address: string, size: number, outPath: string) => {
  const r = await readMemory(sessionId, address, size, "base64");
  const b64 = (r as any)?.base64 ?? r;
  if (!b64 || typeof b64 !== "string") throw new Error("read-memory returned no data");
  await writeFile(outPath, Buffer.from(b64, "base64"));
  return { outPath, bytes: size, address };
};

export const dumpModule = async (sessionId: string, moduleName: string, outPath: string) => {
  const info: any = await evalOk(
    sessionId,
    `(() => { const m = Process.findModuleByName(${JSON.stringify(moduleName)}); return m ? { base: m.base.toString(), size: m.size, name: m.name, path: m.path } : null; })()`
  );
  if (!info) throw new Error(`Module not found: ${moduleName}`);
  const r = await readMemory(sessionId, info.base, info.size, "base64");
  const b64 = (r as any)?.base64 ?? r;
  await writeFile(outPath, Buffer.from(b64 as string, "base64"));
  return { outPath, bytes: info.size, base: info.base, originalPath: info.path };
};

export const startTrace = async (
  sessionId: string,
  patterns: string[],
  options: { logArgs?: boolean; logRet?: boolean; logBacktrace?: boolean } = {}
) => {
  const id = nextId("tr");
  const matchExpr = patterns.map((p) => `(${JSON.stringify(p)})`).join(",");
  const source = `
    const __patterns = [${matchExpr}];
    const __resolved = [];
    function __log(o) { send({ __trace__: true, ev: o }); }
    __patterns.forEach(p => {
      try {
        if (p.indexOf('!') !== -1) {
          const [mod, fn] = p.split('!');
          const matches = new ApiResolver('module').enumerateMatches('exports:' + mod + '!' + fn);
          matches.forEach(m => __resolved.push({ name: m.name, address: m.address }));
        } else {
          const matches = new ApiResolver('module').enumerateMatches('exports:*!' + p);
          matches.forEach(m => __resolved.push({ name: m.name, address: m.address }));
        }
      } catch (e) { __log({ err: 'resolve failed for ' + p + ': ' + e }); }
    });
    __log({ resolved: __resolved.length, names: __resolved.slice(0, 50).map(r => r.name) });
    __resolved.forEach(r => {
      try {
        Interceptor.attach(r.address, {
          onEnter(args) {
            this.__name = r.name;
            const ev = { fn: r.name, ts: Date.now() };
            ${options.logArgs ? "ev.args = [args[0], args[1], args[2], args[3]].map(a => a ? a.toString() : null);" : ""}
            ${options.logBacktrace ? "ev.bt = Thread.backtrace(this.context, Backtracer.ACCURATE).map(p => DebugSymbol.fromAddress(p).toString());" : ""}
            __log(ev);
          },
          ${
            options.logRet
              ? "onLeave(retval) { __log({ fn: this.__name, ts: Date.now(), ret: retval ? retval.toString() : null }); }"
              : ""
          }
        });
      } catch (e) { __log({ err: 'attach failed for ' + r.name + ': ' + e }); }
    });
  `;
  const { scriptId } = await createScript(sessionId, source);
  traces.set(id, { id, sessionId, scriptId, patterns, startedAt: Date.now() });
  return { traceId: id, scriptId, patterns };
};

export const stopTrace = async (traceId: string) => {
  const entry = traces.get(traceId);
  if (!entry) throw new Error(`Unknown traceId: ${traceId}`);
  await destroyScript(entry.scriptId);
  traces.delete(traceId);
  return { traceId, stopped: true };
};

export const fetchTrace = async (traceId: string, drain = true, max = 500) => {
  const entry = traces.get(traceId);
  if (!entry) throw new Error(`Unknown traceId: ${traceId}`);
  const r = await recvMessages(entry.scriptId, drain, max);
  const events = r.messages
    .filter((m) => (m.payload as any)?.__trace__)
    .map((m) => (m.payload as any).ev);
  return { traceId, events, count: events.length, remaining: r.remaining };
};

export const listTraces = () =>
  Array.from(traces.values()).map((t) => ({
    traceId: t.id,
    sessionId: t.sessionId,
    scriptId: t.scriptId,
    patterns: t.patterns,
    startedAt: t.startedAt,
  }));

export const cleanupAll = async () => {
  for (const id of Array.from(scripts.keys())) {
    try { await destroyScript(id); } catch { /* ignore */ }
  }
  for (const id of Array.from(sessions.keys())) {
    try { await detach(id); } catch { /* ignore */ }
  }
};
