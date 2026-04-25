#!/usr/bin/env node
/*
 * mcp-frida — MCP server exposing Frida dynamic-instrumentation primitives
 * for native and managed Windows / Linux / macOS / Android / iOS processes.
 * Spawn or attach to a process, inject JS, hook native functions, scan and
 * patch memory, dump unpacked modules, trace exports — driven entirely by
 * tool calls from an LLM.
 */
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import * as F from "./frida.js";
import { getTemplate, listTemplates } from "./templates.js";

const server = new Server(
  { name: "mcp-frida", version: "0.1.0" },
  { capabilities: { tools: {} } }
);

const ok = (data: unknown) => ({
  content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
});
const err = (e: unknown) => ({
  isError: true,
  content: [{ type: "text" as const, text: `Error: ${(e as Error).message ?? String(e)}` }],
});

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "list-devices",
      description: "Enumerate available Frida devices (local, USB, remote, network).",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "list-processes",
      description: "List running processes on the chosen device. Default device: local.",
      inputSchema: {
        type: "object",
        properties: { device: { type: "string", description: "Device id or alias (local/usb/remote)." } },
      },
    },
    {
      name: "list-applications",
      description: "List installed/running applications. Mostly meaningful on mobile (Android/iOS) devices.",
      inputSchema: {
        type: "object",
        properties: { device: { type: "string" } },
      },
    },
    {
      name: "spawn",
      description:
        "Spawn a binary in a suspended state and attach Frida. Returns sessionId and pid. " +
        "Call resume(sessionId) after loading any scripts you want active before main runs.",
      inputSchema: {
        type: "object",
        required: ["program"],
        properties: {
          program: { type: "string", description: "Absolute path to the executable, or app id on mobile." },
          args: { type: "array", items: { type: "string" }, description: "Argv after program." },
          device: { type: "string" },
        },
      },
    },
    {
      name: "attach",
      description: "Attach Frida to a running process by name or pid. Returns sessionId.",
      inputSchema: {
        type: "object",
        required: ["target"],
        properties: {
          target: { type: ["string", "number"], description: "Process name or pid." },
          device: { type: "string" },
        },
      },
    },
    {
      name: "resume",
      description: "Resume a session that was spawned suspended.",
      inputSchema: { type: "object", required: ["sessionId"], properties: { sessionId: { type: "string" } } },
    },
    {
      name: "detach",
      description: "Detach from a session, unloading all of its scripts.",
      inputSchema: { type: "object", required: ["sessionId"], properties: { sessionId: { type: "string" } } },
    },
    {
      name: "kill",
      description: "Kill the target process and remove the session.",
      inputSchema: { type: "object", required: ["sessionId"], properties: { sessionId: { type: "string" } } },
    },
    {
      name: "list-sessions",
      description: "List active Frida sessions tracked by this server.",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "create-script",
      description:
        "Create and load a long-lived Frida script in the target process. Returns scriptId. " +
        "The script can use send()/recv()/rpc.exports — use post-message and recv-messages to talk to it.",
      inputSchema: {
        type: "object",
        required: ["sessionId", "source"],
        properties: {
          sessionId: { type: "string" },
          source: { type: "string", description: "Frida JS source (Gum runtime). Use globals like Module, Interceptor, Memory, Process, ApiResolver, send()." },
          runtime: { type: "string", enum: ["qjs", "v8"], description: "JS runtime in the agent (default qjs)." },
        },
      },
    },
    {
      name: "destroy-script",
      description: "Unload a script previously created with create-script.",
      inputSchema: { type: "object", required: ["scriptId"], properties: { scriptId: { type: "string" } } },
    },
    {
      name: "list-scripts",
      description: "List currently loaded scripts.",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "eval",
      description:
        "One-shot expression evaluator. Wraps your code in an async IIFE, returns the value. " +
        "For long-lived hooks use create-script instead. Body is a JS function body — use 'return' to yield a value.",
      inputSchema: {
        type: "object",
        required: ["sessionId", "source"],
        properties: {
          sessionId: { type: "string" },
          source: { type: "string", description: "Function-body JS, e.g. 'return Process.getCurrentThreadId();'" },
          timeoutMs: { type: "number", default: 5000 },
        },
      },
    },
    {
      name: "post-message",
      description: "Post a message to a script (script side reads with recv()).",
      inputSchema: {
        type: "object",
        required: ["scriptId", "payload"],
        properties: { scriptId: { type: "string" }, payload: {} },
      },
    },
    {
      name: "recv-messages",
      description:
        "Drain (or peek at) messages the script has sent via send(). Each message includes type/payload and optional base64 binary data.",
      inputSchema: {
        type: "object",
        required: ["scriptId"],
        properties: {
          scriptId: { type: "string" },
          drain: { type: "boolean", default: true, description: "If true, removes returned messages from the queue." },
          max: { type: "number", default: 200 },
        },
      },
    },
    {
      name: "call-rpc",
      description: "Invoke an exported RPC function defined by the script via rpc.exports.<fn>.",
      inputSchema: {
        type: "object",
        required: ["scriptId", "fn"],
        properties: {
          scriptId: { type: "string" },
          fn: { type: "string" },
          args: { type: "array", items: {}, description: "Positional args, JSON-serialisable." },
        },
      },
    },
    {
      name: "list-modules",
      description: "Enumerate loaded modules (DLLs/shared libs) in the target.",
      inputSchema: { type: "object", required: ["sessionId"], properties: { sessionId: { type: "string" } } },
    },
    {
      name: "list-exports",
      description: "Enumerate exported symbols of a module. Heavy on huge runtimes.",
      inputSchema: {
        type: "object",
        required: ["sessionId", "module"],
        properties: { sessionId: { type: "string" }, module: { type: "string" } },
      },
    },
    {
      name: "list-imports",
      description: "Enumerate imported symbols of a module.",
      inputSchema: {
        type: "object",
        required: ["sessionId", "module"],
        properties: { sessionId: { type: "string" }, module: { type: "string" } },
      },
    },
    {
      name: "find-symbol",
      description: "Resolve a symbol name to an address. Pass a module to scope the lookup, or omit to use DebugSymbol.fromName.",
      inputSchema: {
        type: "object",
        required: ["sessionId", "name"],
        properties: { sessionId: { type: "string" }, name: { type: "string" }, module: { type: "string" } },
      },
    },
    {
      name: "read-memory",
      description: "Read N bytes at an address. Format: hex (default) or base64.",
      inputSchema: {
        type: "object",
        required: ["sessionId", "address", "size"],
        properties: {
          sessionId: { type: "string" },
          address: { type: "string", description: "Pointer as 0x... or decimal string." },
          size: { type: "number" },
          format: { type: "string", enum: ["hex", "base64"], default: "hex" },
        },
      },
    },
    {
      name: "write-memory",
      description: "Write a hex byte string to an address. Memory must already be writable (Memory.protect first if not).",
      inputSchema: {
        type: "object",
        required: ["sessionId", "address", "hex"],
        properties: { sessionId: { type: "string" }, address: { type: "string" }, hex: { type: "string" } },
      },
    },
    {
      name: "scan-memory",
      description: "Pattern scan a range. Pattern uses Frida's syntax e.g. '4d 5a ?? ?? 50 45'.",
      inputSchema: {
        type: "object",
        required: ["sessionId", "address", "size", "pattern"],
        properties: {
          sessionId: { type: "string" },
          address: { type: "string" },
          size: { type: "number" },
          pattern: { type: "string" },
          max: { type: "number", default: 100 },
        },
      },
    },
    {
      name: "enumerate-ranges",
      description: "List memory ranges with chosen protection (e.g. 'r-x', 'rw-', 'r--').",
      inputSchema: {
        type: "object",
        required: ["sessionId"],
        properties: { sessionId: { type: "string" }, protection: { type: "string", default: "r--" } },
      },
    },
    {
      name: "dump-range",
      description: "Dump a memory range to a file on disk. Useful for carving unpacked code/data.",
      inputSchema: {
        type: "object",
        required: ["sessionId", "address", "size", "outPath"],
        properties: {
          sessionId: { type: "string" },
          address: { type: "string" },
          size: { type: "number" },
          outPath: { type: "string", description: "Absolute path (parent dir must exist)." },
        },
      },
    },
    {
      name: "dump-module",
      description:
        "Dump the in-memory image of a loaded module to disk. Killer for unpacking DNGuard / VMP / Themida-protected binaries that decrypt themselves at runtime.",
      inputSchema: {
        type: "object",
        required: ["sessionId", "module", "outPath"],
        properties: { sessionId: { type: "string" }, module: { type: "string" }, outPath: { type: "string" } },
      },
    },
    {
      name: "trace-start",
      description:
        "Auto-hook every export that matches one of the supplied glob patterns. Each pattern is 'module!fn' or just 'fn' (matched against all modules). Captures args/ret/backtrace optionally. Use trace-fetch to drain events.",
      inputSchema: {
        type: "object",
        required: ["sessionId", "patterns"],
        properties: {
          sessionId: { type: "string" },
          patterns: { type: "array", items: { type: "string" } },
          logArgs: { type: "boolean", default: true },
          logRet: { type: "boolean", default: true },
          logBacktrace: { type: "boolean", default: false },
        },
      },
    },
    {
      name: "trace-stop",
      description: "Stop and remove a running trace.",
      inputSchema: { type: "object", required: ["traceId"], properties: { traceId: { type: "string" } } },
    },
    {
      name: "trace-fetch",
      description: "Drain (or peek at) buffered trace events.",
      inputSchema: {
        type: "object",
        required: ["traceId"],
        properties: {
          traceId: { type: "string" },
          drain: { type: "boolean", default: true },
          max: { type: "number", default: 500 },
        },
      },
    },
    {
      name: "list-traces",
      description: "List active traces.",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "list-templates",
      description:
        "List built-in Frida script templates (trace-all-exports, dump-decrypted-dotnet-assembly, " +
        "hook-binaryformatter-deserialize, il2cpp-bridge-bootstrap, block-syscall-by-name, " +
        "hook-button-onclick-windowsforms, hook-wininet-get, find-pattern-and-patch, dotnet-list-modules).",
      inputSchema: { type: "object", properties: {} },
    },
    {
      name: "get-template",
      description: "Fetch a script template's full source. Edit the marked constants, then pass to create-script.",
      inputSchema: {
        type: "object",
        required: ["id"],
        properties: { id: { type: "string", description: "Template id from list-templates." } },
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const a = (req.params.arguments ?? {}) as Record<string, any>;
  try {
    switch (req.params.name) {
      case "list-devices": return ok(await F.listDevices());
      case "list-processes": return ok(await F.listProcesses(a.device));
      case "list-applications": return ok(await F.listApplications(a.device));
      case "spawn": return ok(await F.spawn(a.program, a.args, a.device));
      case "attach": return ok(await F.attach(a.target, a.device));
      case "resume": return ok(await F.resume(a.sessionId));
      case "detach": return ok(await F.detach(a.sessionId));
      case "kill": return ok(await F.kill(a.sessionId));
      case "list-sessions": return ok(F.listSessions());
      case "create-script": return ok(await F.createScript(a.sessionId, a.source, a.runtime));
      case "destroy-script": return ok(await F.destroyScript(a.scriptId));
      case "list-scripts": return ok(F.listScripts());
      case "eval": return ok(await F.evalInSession(a.sessionId, a.source, a.timeoutMs ?? 5000));
      case "post-message": return ok(await F.postMessage(a.scriptId, a.payload));
      case "recv-messages": return ok(await F.recvMessages(a.scriptId, a.drain ?? true, a.max ?? 200));
      case "call-rpc": return ok(await F.callRpc(a.scriptId, a.fn, a.args ?? []));
      case "list-modules": return ok(await F.listModules(a.sessionId));
      case "list-exports": return ok(await F.listExports(a.sessionId, a.module));
      case "list-imports": return ok(await F.listImports(a.sessionId, a.module));
      case "find-symbol": return ok(await F.findSymbol(a.sessionId, a.name, a.module));
      case "read-memory": return ok(await F.readMemory(a.sessionId, a.address, a.size, a.format ?? "hex"));
      case "write-memory": return ok(await F.writeMemory(a.sessionId, a.address, a.hex));
      case "scan-memory": return ok(await F.scanMemory(a.sessionId, a.address, a.size, a.pattern, a.max ?? 100));
      case "enumerate-ranges": return ok(await F.enumerateRanges(a.sessionId, a.protection ?? "r--"));
      case "dump-range": return ok(await F.dumpRange(a.sessionId, a.address, a.size, a.outPath));
      case "dump-module": return ok(await F.dumpModule(a.sessionId, a.module, a.outPath));
      case "trace-start":
        return ok(
          await F.startTrace(a.sessionId, a.patterns, {
            logArgs: a.logArgs ?? true,
            logRet: a.logRet ?? true,
            logBacktrace: a.logBacktrace ?? false,
          })
        );
      case "trace-stop": return ok(await F.stopTrace(a.traceId));
      case "trace-fetch": return ok(await F.fetchTrace(a.traceId, a.drain ?? true, a.max ?? 500));
      case "list-traces": return ok(F.listTraces());
      case "list-templates": return ok(listTemplates());
      case "get-template": return ok(getTemplate(a.id));
      default: return err(new Error(`Unknown tool: ${req.params.name}`));
    }
  } catch (e) {
    return err(e);
  }
});

const cleanup = async () => {
  try { await F.cleanupAll(); } catch { /* ignore */ }
  process.exit(0);
};
process.on("SIGINT", cleanup);
process.on("SIGTERM", cleanup);

const transport = new StdioServerTransport();
await server.connect(transport);
