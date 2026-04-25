# mcp-frida

[Русская версия ниже / Russian version below](#mcp-frida-ru)

A Model Context Protocol (MCP) server that puts [Frida](https://frida.re/) — the
dynamic-instrumentation toolkit — behind a stdio interface so an LLM can
**spawn or attach to a running process, inject JavaScript, hook functions,
scan and patch memory, dump unpacked modules, and trace exports** with plain
tool calls. Works on whatever Frida supports: Windows, Linux, macOS, Android,
iOS.

## Why this exists

Frida is wonderful but its workflow is REPL-shaped: you write a JS snippet,
push it into the agent, watch `send()` messages stream back. Driving that
from an LLM means re-uploading the script every turn, manually shuttling
session ids, and losing context whenever the chat compacts. This server
removes the friction:

* Sessions, scripts and traces live in process memory and are addressed by
  stable string ids — `sessionId`, `scriptId`, `traceId` — so an agent can
  start something, do other work, and come back to it many tool calls later.
* `eval` wraps a one-shot expression evaluator (auto-load, auto-collect, auto-unload).
* `create-script` keeps a script alive for streaming hooks; `recv-messages`
  drains its `send()` queue without losing data.
* `trace-start` is `frida-trace` in one tool — give it `module!fn` glob
  patterns, it auto-resolves matches and attaches an Interceptor with
  optional args / return / backtrace capture.
* `dump-module` writes the **in-memory** image of a loaded module straight
  to disk — the killer feature against DNGuard / VMProtect / Themida and
  any other packer that decrypts itself at runtime.

Underneath it's `frida-node` 16.5+; nothing exotic.

## Tools

| Category   | Tools |
| ---------- | ----- |
| Devices    | `list-devices`, `list-processes`, `list-applications` |
| Lifecycle  | `spawn`, `attach`, `resume`, `detach`, `kill`, `list-sessions` |
| Scripting  | `create-script`, `destroy-script`, `list-scripts`, `eval`, `post-message`, `recv-messages`, `call-rpc` |
| Symbols    | `list-modules`, `list-exports`, `list-imports`, `find-symbol` |
| Memory     | `read-memory`, `write-memory`, `scan-memory`, `enumerate-ranges`, `dump-range`, `dump-module` |
| Tracing    | `trace-start`, `trace-stop`, `trace-fetch`, `list-traces` |
| Templates  | `list-templates`, `get-template` |

## Usage examples

These show the call shape — drop them into whatever MCP client you use; the
exact JSON wrapper depends on the client.

### 1. Quick survey of an unknown process

```js
attach({ target: "target.exe" })
// → { sessionId: "sess_xxx", pid: 12345 }

list-modules({ sessionId: "sess_xxx" })
// → [{ name: "plugin.dll", base: "0x7ff8...", size: 3670016, path: "..." }, ...]

eval({ sessionId: "sess_xxx", source: "return { id: Process.id, arch: Process.arch, threads: Process.enumerateThreads().length };" })
// → { result: { id: 12345, arch: "x64", threads: 18 } }
```

### 2. Resolve a symbol and read a struct

```js
find-symbol({ sessionId: "sess_xxx", name: "CreateFileW", module: "kernel32.dll" })
// → "0x7ffb032670f0"

read-memory({ sessionId: "sess_xxx", address: "0x7ffb032670f0", size: 16, format: "hex" })
// → "488bc44c89488856..." (first 16 bytes of CreateFileW prologue)
```

### 3. Trace every export of a DLL with args + return

```js
trace-start({
  sessionId: "sess_xxx",
  patterns: ["plugin.dll!*"],
  logArgs: true, logRet: true
})
// → { traceId: "tr_xxx", scriptId: "scr_xxx", patterns: [...] }

// ... let the target run ...

trace-fetch({ traceId: "tr_xxx", drain: true, max: 200 })
// → { events: [
//     { fn: "plugin.dll!process_data", ts: ..., args: ["0x...", "0x...", null, null] },
//     { fn: "plugin.dll!process_data", ts: ..., ret: "0x0" },
//     ...
//   ] }

trace-stop({ traceId: "tr_xxx" })
```

### 4. Hook a function and modify its return value

```js
create-script({
  sessionId: "sess_xxx",
  source: `
    const addr = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
    Interceptor.replace(addr, new NativeCallback(() => 0, 'int', []));
    send({ patched: 'IsDebuggerPresent → 0' });
  `
})
// → { scriptId: "scr_xxx" }

recv-messages({ scriptId: "scr_xxx" })
// → { messages: [{ type: "send", payload: { patched: "IsDebuggerPresent → 0" } }] }
```

### 5. Pattern-scan and patch (AOB+inject for cheat dev)

```js
// JZ short → JMP short, classic license-check bypass
scan-memory({
  sessionId: "sess_xxx",
  address: "0x140000000", size: 0x800000,
  pattern: "74 ?? 48 8b ?? ?? ?? ?? ?? 48 85 c0"
})
// → [{ address: "0x140012a3f", size: 12 }, ...]

write-memory({ sessionId: "sess_xxx", address: "0x140012a3f", hex: "EB" })
// → { written: 1 }
```

### 6. Dump a packed module out of memory

```js
spawn({ program: "C:\\Path\\Protected.exe" })
// → { sessionId: "sess_xxx", pid: 6543, suspended: true }

resume({ sessionId: "sess_xxx" })
// ... wait for the runtime to decrypt itself ...

dump-module({
  sessionId: "sess_xxx",
  module: "core.dll",
  outPath: "D:\\dumps\\core_runtime.bin"
})
// → { outPath: "...", bytes: 12500992, base: "0x180000000", originalPath: "..." }
```

The dumped file is the **decrypted** in-memory image, ready for ILSpy /
`mcp-dotnet` decompilation or Ghidra import — no relying on the disk
ciphertext.

### 7. Two-way RPC with a long-lived script

```js
create-script({
  sessionId: "sess_xxx",
  source: `
    const recvKey = (buf) => {
      const bytes = ptr(buf).readByteArray(32);
      return Array.from(new Uint8Array(bytes));
    };
    rpc.exports = {
      readBytes(addrStr, n) { return Array.from(new Uint8Array(ptr(addrStr).readByteArray(n))); },
      enumExports(mod) { return Module.enumerateExports(mod).slice(0, 50).map(e => e.name); }
    };
    send({ ready: true });
  `
})
// → { scriptId: "scr_xxx" }

call-rpc({ scriptId: "scr_xxx", fn: "enumExports", args: ["plugin.dll"] })
// → { result: ["init", "process_data", "shutdown", ...] }

call-rpc({ scriptId: "scr_xxx", fn: "readBytes", args: ["0x7ff8a1c00000", 16] })
// → { result: [77, 90, 144, 0, 3, 0, 0, 0, ...] }
```

### 8. Spawn suspended, set hooks before main runs

```js
spawn({ program: "C:\\target.exe" })
// → { sessionId, pid, suspended: true }

create-script({ sessionId, source: "/* attach Interceptor.attach(...) here */" })
resume({ sessionId })
```

This is the only way to catch behaviour that happens during DllMain or
TLS callbacks — you have to hook **before** the main thread starts.

### 9. Trace HTTP without a TLS MITM

```js
get-template({ id: "hook-wininet-get" })
// → { source: "['HttpOpenRequestW', ...].forEach(name => { ... });" }

create-script({ sessionId, source: /* paste source */ })
recv-messages({ scriptId })
// → { messages: [{ payload: { ev: "HttpOpenRequestW", args: ["GET", "/api/login", null] } }, ...] }
```

### 10. Replace a UI button's click handler

```js
get-template({ id: "hook-button-onclick-windowsforms" })
// → JS that hooks System.Windows.Forms.Button::OnClick via DebugSymbol search

create-script({ sessionId, source: /* edited source */ })
// Now every WinForms button click is logged or rerouted
```

## Built-in templates

`list-templates` returns these, `get-template` fetches the source. Each one
is self-contained and has a header comment with the constants you're meant
to edit.

| Template                              | When to reach for it |
| ------------------------------------- | -------------------- |
| `trace-all-exports`                   | Quick survey of any module — args/ret on every export |
| `dotnet-list-modules`                 | Wait for CLR up, log future LoadLibrary calls |
| `dump-decrypted-dotnet-assembly`      | Walks RX ranges, dumps every PE-shaped region — kills DNGuard / packer assembly encryption |
| `hook-binaryformatter-deserialize`    | Observe MemCipher-style decrypt paths in .NET Framework apps |
| `il2cpp-bridge-bootstrap`             | Stub for Unity reverse-engineering (load `frida-il2cpp-bridge`) |
| `block-syscall-by-name`               | Kill anti-debug / anti-VM exports (IsDebuggerPresent, GetTickCount loops) |
| `hook-button-onclick-windowsforms`    | Hijack WinForms `Button.OnClick` for inspection or full rerouting |
| `hook-wininet-get`                    | Watch HTTP traffic without TLS MITM (HttpOpenRequestW, InternetReadFile, …) |
| `find-pattern-and-patch`              | Classic AOB+inject — pattern scan + byte patch, scripted |

## Install

```bash
git clone https://github.com/beekamai/mcp-frida.git
cd mcp-frida
npm install
npm run build
```

Wire it into any MCP-capable client over stdio:

```bash
your-mcp-client mcp add frida --scope user -- node /absolute/path/to/mcp-frida/dist/index.js
```

For remote / mobile / sandboxed targets you also need
[`frida-server`](https://github.com/frida/frida/releases) running on the
target device. Reference the device by id in any tool that takes one (e.g.
`spawn({ program: ..., device: "usb" })`).

## Notes

* **Local mode is sandbox-aware.** Frida injects a Gum agent into the
  target process and creates a thread there. If the target is hardened
  (CIG, ACG, signed-code-only), local-mode injection can fail. Spawn-mode
  works around most of that since the agent is loaded before any
  third-party protection.
* **Scripts run in the target's address space**, with the privileges of the
  target process. They can read/write any memory the target can. Treat
  user-supplied script source the same as any other code execution.
* **`dump-module` reads the live image**. If the binary unpacks itself
  lazily, dump it *after* exercising the relevant code paths.
* **Tracing wide globs is expensive.** `kernel32!*` will hook ~1000
  functions and slow the target. Prefer narrow patterns.
* All file paths are absolute. The server runs in its own working directory
  and refuses to guess where your `outPath` should land.

## License

MIT.

---

<a id="mcp-frida-ru"></a>

# mcp-frida (RU)

MCP-сервер, который кладёт [Frida](https://frida.re/) — инструмент динамической
инструментации — за stdio-интерфейс, чтобы LLM могла **поднимать/прицепляться
к процессу, инжектить JavaScript, хукать функции, сканировать и патчить
память, дампить распакованные модули и трассировать экспорты** обычными
tool-call'ами. Работает везде, где Frida: Windows, Linux, macOS, Android, iOS.

## Зачем это нужно

Frida прекрасна, но её воркфлоу REPL-образный: пишешь JS-сниппет, пушишь
в агент, ловишь `send()`-ы. Гонять это через LLM значит каждый раз
перезаливать скрипт, вручную таскать session id и терять состояние при
любой компактификации чата. Сервер убирает трение:

* Сессии, скрипты и трейсы живут в памяти процесса и адресуются стабильными
  id — `sessionId`, `scriptId`, `traceId` — поэтому агент может что-то
  запустить, отвлечься на десятки tool-call'ов, и вернуться.
* `eval` — однострочный evaluator с авто-загрузкой/-сбором/-выгрузкой.
* `create-script` держит скрипт живым для стриминговых хуков;
  `recv-messages` дрейнит очередь `send()` без потерь.
* `trace-start` — это `frida-trace` в одном туле: даёшь glob-паттерны
  `module!fn`, оно резолвит совпадения и цепляет Interceptor с опциональным
  args/ret/backtrace.
* `dump-module` пишет **runtime-образ** загруженного модуля прямо на диск —
  главная фича против DNGuard / VMProtect / Themida и любого packer'а,
  который расшифровывает себя в рантайме.

Под капотом — `frida-node` 16.5+, ничего экзотического.

## Тулы

| Категория   | Тулы |
| ----------- | ---- |
| Устройства  | `list-devices`, `list-processes`, `list-applications` |
| Жизн. цикл  | `spawn`, `attach`, `resume`, `detach`, `kill`, `list-sessions` |
| Скриптинг   | `create-script`, `destroy-script`, `list-scripts`, `eval`, `post-message`, `recv-messages`, `call-rpc` |
| Символы     | `list-modules`, `list-exports`, `list-imports`, `find-symbol` |
| Память      | `read-memory`, `write-memory`, `scan-memory`, `enumerate-ranges`, `dump-range`, `dump-module` |
| Трейсинг    | `trace-start`, `trace-stop`, `trace-fetch`, `list-traces` |
| Шаблоны     | `list-templates`, `get-template` |

## Примеры

Форма вызовов — оборачивай в свой MCP-клиент по его конвенциям.

### 1. Быстрый осмотр процесса

```js
attach({ target: "target.exe" })
// → { sessionId: "sess_xxx", pid: 12345 }

list-modules({ sessionId: "sess_xxx" })
// → [{ name: "plugin.dll", base: "0x7ff8...", size: 3670016, path: "..." }, ...]

eval({ sessionId: "sess_xxx", source: "return { id: Process.id, arch: Process.arch, threads: Process.enumerateThreads().length };" })
// → { result: { id: 12345, arch: "x64", threads: 18 } }
```

### 2. Резолв символа и чтение байт

```js
find-symbol({ sessionId: "sess_xxx", name: "CreateFileW", module: "kernel32.dll" })
// → "0x7ffb032670f0"

read-memory({ sessionId: "sess_xxx", address: "0x7ffb032670f0", size: 16, format: "hex" })
// → "488bc44c89488856..." (первые 16 байт пролога)
```

### 3. Трейс всех экспортов DLL с args + ret

```js
trace-start({
  sessionId: "sess_xxx",
  patterns: ["plugin.dll!*"],
  logArgs: true, logRet: true
})
// → { traceId: "tr_xxx", scriptId: "scr_xxx" }

// ... даём процессу поработать ...

trace-fetch({ traceId: "tr_xxx", drain: true, max: 200 })
// → { events: [
//     { fn: "plugin.dll!process_data", ts: ..., args: ["0x...", "0x...", null, null] },
//     { fn: "plugin.dll!process_data", ts: ..., ret: "0x0" },
//   ] }

trace-stop({ traceId: "tr_xxx" })
```

### 4. Хук функции с подменой возврата

```js
create-script({
  sessionId: "sess_xxx",
  source: `
    const addr = Module.findExportByName('kernel32.dll', 'IsDebuggerPresent');
    Interceptor.replace(addr, new NativeCallback(() => 0, 'int', []));
    send({ patched: 'IsDebuggerPresent → 0' });
  `
})

recv-messages({ scriptId: "scr_xxx" })
// → { messages: [{ payload: { patched: "IsDebuggerPresent → 0" } }] }
```

### 5. Pattern-scan и патч (AOB+inject для читов)

```js
// JZ short → JMP short — классический обход license-проверки
scan-memory({
  sessionId: "sess_xxx",
  address: "0x140000000", size: 0x800000,
  pattern: "74 ?? 48 8b ?? ?? ?? ?? ?? 48 85 c0"
})
// → [{ address: "0x140012a3f", size: 12 }, ...]

write-memory({ sessionId: "sess_xxx", address: "0x140012a3f", hex: "EB" })
// → { written: 1 }
```

### 6. Дамп распакованного модуля из памяти

```js
spawn({ program: "C:\\Path\\Protected.exe" })
// → { sessionId, pid, suspended: true }

resume({ sessionId })
// ... ждём пока рантайм себя расшифрует ...

dump-module({
  sessionId: "sess_xxx",
  module: "core.dll",
  outPath: "D:\\dumps\\core_runtime.bin"
})
// → { outPath: "...", bytes: 12500992, base: "0x180000000", originalPath: "..." }
```

На диске получится **расшифрованный** runtime-образ — готов для ILSpy /
`mcp-dotnet` или импорта в Ghidra.

### 7. Двухсторонний RPC с долгоживущим скриптом

```js
create-script({
  sessionId: "sess_xxx",
  source: `
    rpc.exports = {
      readBytes(addrStr, n) { return Array.from(new Uint8Array(ptr(addrStr).readByteArray(n))); },
      enumExports(mod) { return Module.enumerateExports(mod).slice(0, 50).map(e => e.name); }
    };
    send({ ready: true });
  `
})

call-rpc({ scriptId: "scr_xxx", fn: "enumExports", args: ["plugin.dll"] })
// → { result: ["init", "process_data", "shutdown", ...] }

call-rpc({ scriptId: "scr_xxx", fn: "readBytes", args: ["0x7ff8a1c00000", 16] })
// → { result: [77, 90, 144, 0, 3, 0, 0, 0, ...] }
```

### 8. Spawn suspended — поставить хуки до старта main

```js
spawn({ program: "C:\\target.exe" })
// → { sessionId, pid, suspended: true }

create-script({ sessionId, source: "/* Interceptor.attach(...) тут */" })
resume({ sessionId })
```

Единственный способ поймать поведение во время DllMain / TLS-callbacks —
хук должен быть установлен **до** запуска главного потока.

### 9. Трейс HTTP без TLS MITM

```js
get-template({ id: "hook-wininet-get" })
create-script({ sessionId, source: /* вставить source */ })
recv-messages({ scriptId })
// → { messages: [{ payload: { ev: "HttpOpenRequestW", args: ["GET", "/api/login", null] } }] }
```

### 10. Подмена обработчика UI-кнопки

```js
get-template({ id: "hook-button-onclick-windowsforms" })
// → JS, который хукает System.Windows.Forms.Button::OnClick

create-script({ sessionId, source: /* отредактированный source */ })
// Каждый клик WinForms-кнопки логируется или подменяется
```

## Встроенные шаблоны

`list-templates` выдаёт список, `get-template` — исходник. Каждый шаблон
самодостаточный, с шапкой-комментом и константами под редактирование.

| Шаблон                              | Когда брать |
| ----------------------------------- | ----------- |
| `trace-all-exports`                 | Быстрый осмотр любого модуля — args/ret на каждый экспорт |
| `dotnet-list-modules`               | Дождаться CLR + логировать все будущие LoadLibrary |
| `dump-decrypted-dotnet-assembly`    | Обходит RX-регионы, дампит каждую PE-область — рушит шифрование сборок DNGuard / packer'ов |
| `hook-binaryformatter-deserialize`  | Наблюдение за MemCipher-style decrypt в .NET Framework |
| `il2cpp-bridge-bootstrap`           | Стартер для Unity-реверса (загружаешь `frida-il2cpp-bridge`) |
| `block-syscall-by-name`             | Убить anti-debug / anti-VM экспорты (IsDebuggerPresent, GetTickCount-loops) |
| `hook-button-onclick-windowsforms`  | Перехват WinForms `Button.OnClick` — лог или полная подмена |
| `hook-wininet-get`                  | HTTP-трафик без TLS MITM (HttpOpenRequestW, InternetReadFile, …) |
| `find-pattern-and-patch`            | Классический AOB+inject — pattern scan + патч байт, скриптом |

## Установка

```bash
git clone https://github.com/beekamai/mcp-frida.git
cd mcp-frida
npm install
npm run build
```

Подключение к MCP-клиенту через stdio:

```bash
your-mcp-client mcp add frida --scope user -- node /абсолютный/путь/к/mcp-frida/dist/index.js
```

Для remote / mobile / sandbox-таргетов нужен ещё
[`frida-server`](https://github.com/frida/frida/releases) на устройстве.
В каждом туле, где есть параметр `device`, можно указать его id:
`spawn({ program: ..., device: "usb" })`.

## Заметки

* **Local-mode зависит от sandbox'а.** Frida инжектит Gum-agent в процесс
  и создаёт там поток. Если таргет hardened (CIG / ACG / только подписанный
  код), local-mode инжект может упасть. Spawn-mode почти всегда обходит
  это, потому что агент грузится до сторонней защиты.
* **Скрипты крутятся в адресном пространстве таргета** с его правами —
  читают/пишут любую доступную память. Относиться к user-supplied
  скриптам как к любому code-execution.
* **`dump-module` читает живой образ.** Если бинарь распаковывается
  лениво — дампи *после* того, как нужный код уже исполнился.
* **Широкие globs дорогие.** `kernel32!*` цепляет ~1000 функций и роняет
  скорость таргета. Лучше уже паттерны.
* Все пути абсолютные. Сервер крутится в своём `cwd` и не угадывает где
  должен лежать `outPath`.

## Лицензия

MIT.
