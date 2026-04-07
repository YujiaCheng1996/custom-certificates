const MODULE_ID = "custom-certificates";
const PARSE_TIMEOUT_MS = 20000;
const ASCII_CHUNK_SIZE = 0x8000;
const CURVE_BITS = { "P-256": 256, "K-256": 256, "P-384": 384, "P-521": 521, Ed25519: 256, Ed448: 456 };
const i18n = globalThis.customCertificateI18n || {};
const t = (key, vars = {}, language) => (typeof i18n.t === "function" ? i18n.t(key, vars, language) : key);
const localizeRuntimeText = (value, vars = {}, language) =>
  typeof i18n.localizeRuntimeText === "function" ? i18n.localizeRuntimeText(value, vars, language) : String(value ?? "");
const displayValue = (value, fallbackKey = "common.unknown", language) =>
  typeof i18n.displayValue === "function"
    ? i18n.displayValue(value, fallbackKey, language)
    : String(value ?? "").trim() || t(fallbackKey, {}, language);
const isPlaceholderValue = (value) => (typeof i18n.isPlaceholderValue === "function" ? i18n.isPlaceholderValue(value) : !String(value ?? "").trim());

const state = {
  moduleRoot: "",
  apiScriptPath: "",
  certs: { custom: [], added: [] },
  cryptoReady: Boolean(globalThis.crypto?.subtle),
  parserMode: "worker",
  connected: false,
  refreshing: false,
  importing: false,
  parsingAll: false,
  hydrationToken: 0,
  expandedKey: null,
  pendingHydrations: new Map(),
  pendingMoves: new Set(),
  pendingDeletes: new Set(),
};

const elements = {
  statusBadge: document.querySelector("#statusBadge"),
  statusDot: document.querySelector("#statusDot"),
  statusText: document.querySelector("#statusText"),
  fabStack: document.querySelector("#fabStack"),
  fabLanguageButton: document.querySelector("#fabLanguageButton"),
  fabRefreshButton: document.querySelector("#fabRefreshButton"),
  importButton: document.querySelector("#importButton"),
  importFiles: document.querySelector("#importFiles"),
  importUrl: document.querySelector("#importUrl"),
  importTarget: document.querySelector("#importTarget"),
  importResult: document.querySelector("#importResult"),
  customList: document.querySelector("#customList"),
  addedList: document.querySelector("#addedList"),
  customCount: document.querySelector("#customCount"),
  addedCount: document.querySelector("#addedCount"),
};

let parserWorker = null;
let parserRequestId = 0;
let renderScheduled = false;
let lastScrollY = 0;
const parserPending = new Map();
let activeChoiceDialog = null;

function errorMessage(error) {
  return localizeRuntimeText(error instanceof Error ? error.message : String(error));
}

function formatPublicKeyValue(algorithm, publicKeySizeBits) {
  const value = displayValue(algorithm);
  return publicKeySizeBits ? `${value} (${publicKeySizeBits} ${t("common.bitsUnit")})` : value;
}

function buildParseFailureDetail(message) {
  return t("cert.parseFailedDetail", { message: localizeRuntimeText(message) || t("common.unknown") });
}

function getCurrentLanguage() {
  return typeof i18n.getLanguage === "function" ? i18n.getLanguage() : "zh-CN";
}

function getNextLanguage(currentLanguage = getCurrentLanguage()) {
  return currentLanguage === "zh-CN" ? "en-US" : "zh-CN";
}

function updateLanguageFab() {
  if (!elements.fabLanguageButton) return;
  const currentLanguage = getCurrentLanguage();
  const nextLanguage = getNextLanguage(currentLanguage);
  const nextLabel = nextLanguage === "en-US" ? "EN" : "中";
  const titleKey = nextLanguage === "en-US" ? "fab.language.switchToEnglish" : "fab.language.switchToChinese";
  elements.fabLanguageButton.textContent = nextLabel;
  elements.fabLanguageButton.title = t(titleKey);
  elements.fabLanguageButton.setAttribute("aria-label", t(titleKey));
}

function syncLanguageUi() {
  if (typeof i18n.applyTranslations === "function") {
    i18n.applyTranslations(document);
  }
  updateLanguageFab();
  updateStatusIndicator();
  renderAllLists();
}

function ensureUint8Array(data) {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  return new Uint8Array(data);
}

function bytesToBinary(bytes) {
  const input = ensureUint8Array(bytes);
  if (!input.length) return "";
  const parts = [];
  for (let index = 0; index < input.length; index += ASCII_CHUNK_SIZE) {
    parts.push(String.fromCharCode(...input.subarray(index, index + ASCII_CHUNK_SIZE)));
  }
  return parts.join("");
}

function bytesToBase64(bytes) {
  return btoa(bytesToBinary(bytes));
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function detectSourceFormat(bytes) {
  return bytesToBinary(ensureUint8Array(bytes).slice(0, 64)).includes("BEGIN CERTIFICATE") ? "PEM" : "DER";
}

function bytesToHex(bytes, separator = ":") {
  return [...ensureUint8Array(bytes)].map((value) => value.toString(16).padStart(2, "0").toUpperCase()).join(separator);
}

function formatDate(value) {
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) return t("common.unknown");
  const year = value.getUTCFullYear();
  const month = String(value.getUTCMonth() + 1).padStart(2, "0");
  const day = String(value.getUTCDate()).padStart(2, "0");
  const hours = String(value.getUTCHours()).padStart(2, "0");
  const minutes = String(value.getUTCMinutes()).padStart(2, "0");
  const seconds = String(value.getUTCSeconds()).padStart(2, "0");
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds} UTC`;
}

function formatAlgorithm(algorithm) {
  if (!algorithm || typeof algorithm !== "object") return t("common.unknown");
  const parts = [];
  if (algorithm.name) parts.push(String(algorithm.name));
  if (algorithm.hash?.name) parts.push(String(algorithm.hash.name));
  if (algorithm.namedCurve) parts.push(String(algorithm.namedCurve));
  return parts.length ? parts.join(" / ") : t("common.unknown");
}

function getPublicKeySizeBits(algorithm) {
  if (!algorithm || typeof algorithm !== "object") return 0;
  if (typeof algorithm.modulusLength === "number") return algorithm.modulusLength;
  if (algorithm.namedCurve && CURVE_BITS[algorithm.namedCurve]) return CURVE_BITS[algorithm.namedCurve];
  if (algorithm.name && CURVE_BITS[algorithm.name]) return CURVE_BITS[algorithm.name];
  return 0;
}

async function sha256Fingerprint(bytes) {
  if (!globalThis.crypto?.subtle) return t("common.unknown");
  const input = ensureUint8Array(bytes);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength));
  return bytesToHex(new Uint8Array(digest));
}

async function sha1Fingerprint(bytes) {
  if (!globalThis.crypto?.subtle) return t("common.unknown");
  const input = ensureUint8Array(bytes);
  const digest = await globalThis.crypto.subtle.digest("SHA-1", input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength));
  return bytesToHex(new Uint8Array(digest));
}

function md5Digest(bytes) {
  const input = ensureUint8Array(bytes);
  const originalLengthBits = input.length * 8;
  const paddedLength = (((input.length + 8) >> 6) + 1) * 64;
  const buffer = new Uint8Array(paddedLength);
  buffer.set(input);
  buffer[input.length] = 0x80;
  const lengthView = new DataView(buffer.buffer);
  lengthView.setUint32(paddedLength - 8, originalLengthBits >>> 0, true);
  lengthView.setUint32(paddedLength - 4, Math.floor(originalLengthBits / 0x100000000), true);

  let a0 = 0x67452301;
  let b0 = 0xefcdab89;
  let c0 = 0x98badcfe;
  let d0 = 0x10325476;
  const shifts = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23,
    4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  ];
  const constants = new Array(64).fill(0).map((_, index) => Math.floor(Math.abs(Math.sin(index + 1)) * 0x100000000) >>> 0);

  for (let offset = 0; offset < paddedLength; offset += 64) {
    const chunk = new Uint32Array(16);
    for (let index = 0; index < 16; index += 1) chunk[index] = lengthView.getUint32(offset + index * 4, true);
    let a = a0;
    let b = b0;
    let c = c0;
    let d = d0;
    for (let index = 0; index < 64; index += 1) {
      let f = 0;
      let g = 0;
      if (index < 16) {
        f = (b & c) | (~b & d);
        g = index;
      } else if (index < 32) {
        f = (d & b) | (~d & c);
        g = (5 * index + 1) % 16;
      } else if (index < 48) {
        f = b ^ c ^ d;
        g = (3 * index + 5) % 16;
      } else {
        f = c ^ (b | ~d);
        g = (7 * index) % 16;
      }
      const value = (a + f + constants[index] + chunk[g]) >>> 0;
      const rotated = (value << shifts[index]) | (value >>> (32 - shifts[index]));
      [a, d, c, b] = [d, c, b, (b + rotated) >>> 0];
    }
    a0 = (a0 + a) >>> 0;
    b0 = (b0 + b) >>> 0;
    c0 = (c0 + c) >>> 0;
    d0 = (d0 + d) >>> 0;
  }

  const output = new Uint8Array(16);
  const outputView = new DataView(output.buffer);
  outputView.setUint32(0, a0, true);
  outputView.setUint32(4, b0, true);
  outputView.setUint32(8, c0, true);
  outputView.setUint32(12, d0, true);
  return output;
}

function computeSubjectHashOld(subjectBytes) {
  const digest = md5Digest(subjectBytes);
  const value = ((digest[3] << 24) | (digest[2] << 16) | (digest[1] << 8) | digest[0]) >>> 0;
  return value.toString(16).padStart(8, "0");
}

function ensureX509Api() {
  const api = globalThis.x509;
  if (!api?.X509Certificate) throw new Error(t("error.x509BrowserBuildMissing"));
  return api;
}

function splitEscaped(value, delimiter) {
  const parts = [];
  let current = "";
  let escaped = false;
  for (const char of String(value || "")) {
    if (escaped) {
      current += char;
      escaped = false;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      continue;
    }
    if (char === delimiter) {
      parts.push(current.trim());
      current = "";
      continue;
    }
    current += char;
  }
  if (escaped) current += "\\";
  if (current || !parts.length) parts.push(current.trim());
  return parts.filter(Boolean);
}

function unescapeDnValue(value) {
  return String(value || "")
    .replace(/\\([,=+<>#;"\\])/g, "$1")
    .replace(/\\ /g, " ")
    .trim();
}

function parseDistinguishedName(value) {
  const raw = String(value || "").trim();
  const fields = {};
  const ordered = [];
  for (const segment of splitEscaped(raw, ",")) {
    for (const part of splitEscaped(segment, "+")) {
      const pivot = part.indexOf("=");
      if (pivot <= 0) continue;
      const key = part.slice(0, pivot).trim().toUpperCase();
      const fieldValue = unescapeDnValue(part.slice(pivot + 1));
      if (!fieldValue) continue;
      if (!fields[key]) fields[key] = [];
      fields[key].push(fieldValue);
      ordered.push(`${key}=${fieldValue}`);
    }
  }
  const cn = fields.CN?.[0] || fields.OU?.[0] || fields.O?.[0] || raw || t("common.unknown");
  return { raw: raw || t("common.unknown"), fields, ordered, cn };
}

function dnField(dn, key) {
  return dn.fields[key]?.join(" / ") || t("common.notProvided");
}

function normalizeParsedCertificate(parsed) {
  const subjectDn = parseDistinguishedName(parsed.subject);
  const issuerDn = parseDistinguishedName(parsed.issuer);
  return { ...parsed, subjectDn, issuerDn, subjectCn: subjectDn.cn, issuerCn: issuerDn.cn };
}

function extractEmbeddedCertificateText(bytes) {
  const sourceText = bytesToBinary(ensureUint8Array(bytes)).replace(/\r\n/g, "\n");
  const match = sourceText.match(/-----END CERTIFICATE-----\n([\s\S]*)$/);
  if (!match) return { detailText: "", fingerprintLine: "" };

  const appendix = match[1].trim();
  if (!appendix) return { detailText: "", fingerprintLine: "" };

  const lines = appendix.split("\n");
  let fingerprintLine = "";
  while (lines.length && !lines[lines.length - 1].trim()) {
    lines.pop();
  }
  if (lines.length && /^(?:sha1|SHA1) Fingerprint=/.test(lines[lines.length - 1].trim())) {
    fingerprintLine = lines.pop().trim();
  }

  while (lines.length && !lines[lines.length - 1].trim()) {
    lines.pop();
  }
  const detailText = lines.join("\n").trim();
  if (!detailText && !fingerprintLine) return { detailText: "", fingerprintLine: "" };
  if (detailText && !/^Certificate:/m.test(detailText) && !fingerprintLine) {
    return { detailText: "", fingerprintLine: "" };
  }

  return { detailText, fingerprintLine };
}

function buildFallbackDetailText(summary) {
  return [
    "Certificate Summary",
    `Subject: ${summary.subject}`,
    `Issuer: ${summary.issuer}`,
    `Serial Number: ${summary.serialNumber}`,
    `Not Before: ${summary.notBefore}`,
    `Not After: ${summary.notAfter}`,
    `Signature Algorithm: ${summary.signatureAlgorithmName}`,
    `Public Key: ${summary.publicKeyAlgorithm}${summary.publicKeySizeBits ? ` (${summary.publicKeySizeBits} bits)` : ""}`,
    `Extensions: ${summary.extensionCount}`,
    `SHA256 Fingerprint: ${summary.sha256}`,
    `subject_hash_old: ${summary.subjectHashOld}`,
  ].join("\n");
}

function buildOpenSslDetailText(summary, certificate) {
  const formatter = globalThis.customCertificateText;
  if (!formatter?.buildOpenSslCertificateText) return buildFallbackDetailText(summary);
  try {
    return formatter.buildOpenSslCertificateText(certificate);
  } catch (_) {
    return buildFallbackDetailText(summary);
  }
}

async function parseCertificateWithX509(inputBytes) {
  const api = ensureX509Api();
  const rawBytes = ensureUint8Array(inputBytes);
  if (!rawBytes.length) throw new Error(t("error.certificateEmpty"));

  const certificate = new api.X509Certificate(rawBytes);
  const derBytes = ensureUint8Array(certificate.rawData).slice();
  const pem = certificate.toString("pem");
  const pemBytes = new TextEncoder().encode(pem);
  const embeddedText = extractEmbeddedCertificateText(rawBytes);
  const sha1 = await sha1Fingerprint(derBytes);
  const summary = {
    serialNumber: String(certificate.serialNumber || "").toUpperCase() || t("common.unknown"),
    issuer: certificate.issuer || t("common.unknown"),
    subject: certificate.subject || t("common.unknown"),
    notBefore: formatDate(certificate.notBefore),
    notAfter: formatDate(certificate.notAfter),
    notBeforeTime: certificate.notBefore instanceof Date ? certificate.notBefore.getTime() : null,
    notAfterTime: certificate.notAfter instanceof Date ? certificate.notAfter.getTime() : null,
    sha1,
    sha256: await sha256Fingerprint(derBytes),
    subjectHashOld: computeSubjectHashOld(certificate.subjectName.toArrayBuffer()),
    sourceFormat: detectSourceFormat(rawBytes),
    signatureAlgorithmName: formatAlgorithm(certificate.signatureAlgorithm),
    publicKeyAlgorithm: formatAlgorithm(certificate.publicKey?.algorithm),
    publicKeySizeBits: getPublicKeySizeBits(certificate.publicKey?.algorithm),
    extensionCount: Array.isArray(certificate.extensions) ? certificate.extensions.length : 0,
    pemBytes,
    derBytes,
    pem,
    fingerprintLine: embeddedText.fingerprintLine || (sha1 ? `sha1 Fingerprint=${sha1}` : ""),
  };

  let detailText = "";
  if (embeddedText.detailText) {
    detailText = embeddedText.detailText;
  } else {
    detailText = buildOpenSslDetailText(summary, certificate);
  }

  return { ...summary, detailText };
}

function pushUnique(list, value) {
  if (value && !list.includes(value)) list.push(value);
}

function normalizeRoot(value) {
  return value ? String(value).replace(/\\/g, "/").replace(/\/+$/, "") : "";
}

function deriveRootFromUrl(value) {
  if (!value) return "";
  try {
    const url = new URL(value, window.location.href);
    const path = decodeURIComponent(url.pathname || "");
    const webrootIndex = path.lastIndexOf("/webroot/");
    if (webrootIndex >= 0) return normalizeRoot(path.slice(0, webrootIndex));
    const moduleIndex = path.lastIndexOf(`/${MODULE_ID}/`);
    if (moduleIndex >= 0) return normalizeRoot(path.slice(0, moduleIndex + MODULE_ID.length + 1));
  } catch (_) {
    return "";
  }
  return "";
}

function getModuleRootCandidates() {
  const candidates = [];
  const search = new URLSearchParams(window.location.search);
  [
    window.ksu?.moduleRoot,
    window.ksu?.module_root,
    window.ksu?.moduleDir,
    window.ksu?.module_dir,
    window.ksu?.modulePath,
    window.ksu?.module_path,
    search.get("moduleRoot"),
    search.get("module_root"),
    search.get("moduleDir"),
    search.get("module_dir"),
    search.get("modulePath"),
    search.get("module_path"),
    deriveRootFromUrl(import.meta.url),
    deriveRootFromUrl(window.location.href),
    `/data/adb/modules/${MODULE_ID}`,
  ]
    .map(normalizeRoot)
    .forEach((value) => pushUnique(candidates, value));

  const moduleId = search.get("module") || search.get("id") || search.get("moduleId");
  if (moduleId && !moduleId.includes("/") && !moduleId.includes("\\")) {
    pushUnique(candidates, `/data/adb/modules/${moduleId}`);
  }
  return candidates;
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, `'\"'\"'`)}'`;
}

function showMessage(node, text, isError = false) {
  node.hidden = false;
  node.textContent = text;
  node.classList.toggle("error", isError);
}

function clearMessage(node) {
  node.hidden = true;
  node.textContent = "";
  node.classList.remove("error");
}

function toast(message) {
  if (window.ksu && typeof window.ksu.toast === "function") {
    window.ksu.toast(message);
  } else {
    window.alert(message);
  }
}

function createChoiceDialog() {
  const backdrop = document.createElement("div");
  backdrop.className = "choice-dialog-backdrop";
  backdrop.hidden = true;

  const dialog = document.createElement("div");
  dialog.className = "choice-dialog";
  dialog.setAttribute("role", "dialog");
  dialog.setAttribute("aria-modal", "true");

  const title = document.createElement("h3");
  title.className = "choice-dialog-title";
  const message = document.createElement("p");
  message.className = "choice-dialog-message";
  const actions = document.createElement("div");
  actions.className = "choice-dialog-actions";

  dialog.append(title, message, actions);
  backdrop.appendChild(dialog);
  document.body.appendChild(backdrop);
  return { backdrop, dialog, title, message, actions };
}

function showChoiceDialog({ title, message, actions, cancelId = "cancel" }) {
  if (activeChoiceDialog) {
    activeChoiceDialog.resolve(cancelId);
  }

  const dialog = createChoiceDialog();
  const restoreFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
  dialog.title.textContent = title;
  dialog.message.textContent = message;
  dialog.actions.innerHTML = "";

  return new Promise((resolve) => {
    const finish = (result) => {
      if (activeChoiceDialog?.dialog !== dialog) return;
      activeChoiceDialog = null;
      dialog.backdrop.hidden = true;
      dialog.backdrop.remove();
      window.removeEventListener("keydown", handleKeydown);
      restoreFocus?.focus?.();
      resolve(result);
    };

    const handleKeydown = (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        finish(cancelId);
      }
    };

    dialog.backdrop.addEventListener("click", (event) => {
      if (event.target === dialog.backdrop) {
        finish(cancelId);
      }
    });

    for (const action of actions) {
      const button = document.createElement("button");
      button.type = "button";
      button.className =
        action.variant === "danger" ? "button button-danger" : action.variant === "primary" ? "button button-primary" : "button button-secondary";
      button.textContent = action.label;
      button.addEventListener("click", () => finish(action.id));
      dialog.actions.appendChild(button);
      if (action.focus) {
        window.requestAnimationFrame(() => button.focus());
      }
    }

    activeChoiceDialog = { dialog, resolve: finish };
    dialog.backdrop.hidden = false;
    window.addEventListener("keydown", handleKeydown);
  });
}

function targetBucketLabel(bucket) {
  return bucket === "custom" ? "cacerts-custom" : "cacerts-added";
}

function nextBucket(item) {
  return item.bucket === "custom" ? "added" : "custom";
}

function isMoveDisabled(item) {
  return item.bucket === "added" && item.protected;
}

function itemKey(item) {
  return `${item.bucket}:${item.name}`;
}

function itemSubjectHashOld(item) {
  return String(item?.name || "").replace(/\.\d+$/, "");
}

function normalizeExistingNames(source) {
  if (source instanceof Set) return new Set(source);
  if (Array.isArray(source)) return new Set(source.map((entry) => (typeof entry === "string" ? entry : entry.name)).filter(Boolean));
  return new Set();
}

function getImportNameIndex(name) {
  const match = String(name || "").match(/\.(\d+)$/);
  return match ? Number(match[1]) : Number.POSITIVE_INFINITY;
}

function listImportConflicts(source, subjectHashOld) {
  return [...normalizeExistingNames(source)]
    .filter((name) => itemSubjectHashOld({ name }) === subjectHashOld)
    .sort((left, right) => getImportNameIndex(left) - getImportNameIndex(right) || left.localeCompare(right));
}

function createScrollRestorer() {
  const x = window.scrollX;
  const y = window.scrollY;
  return () => {
    window.requestAnimationFrame(() => {
      window.scrollTo(x, y);
    });
  };
}

function scheduleRender() {
  if (renderScheduled) return;
  renderScheduled = true;
  window.requestAnimationFrame(() => {
    renderScheduled = false;
    renderAllLists();
  });
}

function updateControls() {
  const disableRefresh = !state.connected || state.refreshing || state.importing || state.parsingAll;
  const disableImport = !state.connected || state.refreshing || state.importing;
  elements.fabRefreshButton.disabled = disableRefresh;
  elements.importButton.disabled = disableImport;
}

function terminateParserWorker(reason = t("error.parserReset")) {
  if (parserWorker) {
    parserWorker.terminate();
    parserWorker = null;
  }

  const error = reason instanceof Error ? reason : new Error(String(reason));
  for (const { reject, timer } of parserPending.values()) {
    clearTimeout(timer);
    reject(error);
  }
  parserPending.clear();
}

function ensureParserWorker() {
  if (!("Worker" in window)) throw new Error(t("error.noWebWorker"));
  if (parserWorker) return parserWorker;

  const worker = new Worker(new URL("./cert-worker.js", import.meta.url));
  worker.addEventListener("message", (event) => {
    const message = event.data || {};
    const entry = parserPending.get(message.id);
    if (!entry) return;
    clearTimeout(entry.timer);
    parserPending.delete(message.id);
    if (message.ok) {
      entry.resolve(normalizeParsedCertificate(message.result));
      return;
    }
    entry.reject(new Error(message.error || t("error.certificateParseFailed")));
  });
  worker.addEventListener("error", (event) => {
    terminateParserWorker(new Error(event.message || t("error.parserWorkerExit")));
  });

  parserWorker = worker;
  return worker;
}

function normalizeTransferBytes(bytes) {
  const input = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (input.byteOffset === 0 && input.byteLength === input.buffer.byteLength) return input;
  return input.slice();
}

async function parseCertificateSafe(bytes) {
  if (state.parserMode === "main-thread") {
    return normalizeParsedCertificate(await parseCertificateWithX509(bytes));
  }

  let worker;
  try {
    worker = ensureParserWorker();
  } catch (error) {
    state.parserMode = "main-thread";
    return normalizeParsedCertificate(await parseCertificateWithX509(bytes));
  }

  const payload = normalizeTransferBytes(bytes);
  return new Promise((resolve, reject) => {
    const id = `parse-${Date.now()}-${parserRequestId++}`;
    const timer = window.setTimeout(() => {
      terminateParserWorker(new Error(t("error.parseTimeout", { timeoutMs: PARSE_TIMEOUT_MS })));
    }, PARSE_TIMEOUT_MS);
    parserPending.set(id, { resolve, reject, timer });
    worker.postMessage({ id, type: "parse", bytes: payload }, [payload.buffer]);
  });
}

async function exec(command) {
  if (!window.ksu || typeof window.ksu.exec !== "function") {
    throw new Error(t("error.bridgeUnavailable"));
  }

  return new Promise((resolve, reject) => {
    const callbackName = `__customCerts_${Date.now()}_${Math.random().toString(16).slice(2)}`;
    window[callbackName] = (...args) => {
      delete window[callbackName];
      let errno = 0;
      let stdout = "";
      let stderr = "";
      if (args.length >= 3) [errno, stdout, stderr] = args;
      else if (args.length === 2) [stdout, stderr] = args;
      else if (args.length === 1) [stdout] = args;
      resolve({ errno: Number(errno || 0), stdout: String(stdout || ""), stderr: String(stderr || "") });
    };

    try {
      window.ksu.exec(command, callbackName);
    } catch (error) {
      delete window[callbackName];
      reject(error);
    }
  });
}

async function resolveApiScriptPath() {
  if (state.apiScriptPath) return state.apiScriptPath;
  const candidates = getModuleRootCandidates().map((root) => ({ root, api: `${root}/webui-api.sh` }));
  for (const candidate of candidates) {
    const probe = await exec(`[ -f ${shellQuote(candidate.api)} ]`);
    if (probe.errno === 0) {
      state.moduleRoot = candidate.root;
      state.apiScriptPath = candidate.api;
      return candidate.api;
    }
  }
  throw new Error(t("error.apiScriptNotFound", { paths: candidates.map((item) => item.api).join(" , ") }));
}

async function runApi(args) {
  const scriptPath = await resolveApiScriptPath();
  const command = `sh ${shellQuote(scriptPath)} ${args.map(shellQuote).join(" ")}`;
  const result = await exec(command);
  if (result.errno !== 0) {
    throw new Error((result.stdout || result.stderr || t("error.commandFailed", { code: result.errno })).replace(/^ERR\t/, ""));
  }
  return result.stdout.trimEnd();
}

function parseList(stdout) {
  const lines = stdout.split(/\r?\n/).filter(Boolean);
  if (!lines.length) return [];

  const header = lines.shift().split("\t");
  if (header[0] !== "OK") throw new Error(stdout || t("error.unexpectedApiResponse"));

  return lines
    .map((line) => line.split("\t"))
    .filter((parts) => parts[0] === "ITEM")
    .map((parts) => ({
      bucket: parts[1],
      name: parts[2],
      protected: parts[3] === "1",
      loaded: false,
      parseError: "",
      parseErrorRaw: "",
      subjectCn: parts[2],
      issuerCn: t("cert.pendingShort"),
      detailText: "",
    }));
}

async function fetchCertificateBytes(item) {
  const stdout = await runApi(["read", item.bucket, item.name]);
  const [status, payload] = stdout.split("\t");
  if (status !== "OK") throw new Error(stdout || t("error.readCertificateFailed"));
  return base64ToBytes(payload || "");
}

async function downloadCertificateBytes(url) {
  const stdout = await runApi(["download", url]);
  const [status, payload] = stdout.split("\t");
  if (status !== "OK") throw new Error(stdout || t("error.downloadCertificateFailed"));
  return base64ToBytes(payload || "");
}

function buildFailedItem(item, error) {
  const message = error instanceof Error ? error.message : String(error);
  const raw = item.name;
  return {
    ...item,
    subject: raw,
    issuer: "",
    subjectDn: parseDistinguishedName(raw),
    issuerDn: parseDistinguishedName(""),
    subjectCn: raw,
    issuerCn: "",
    serialNumber: "",
    notBefore: "",
    notAfter: "",
    sha256: "",
    subjectHashOld: item.name.replace(/\.\d+$/, ""),
    signatureAlgorithmName: "",
    publicKeyAlgorithm: "",
    publicKeySizeBits: 0,
    extensionCount: 0,
    sourceFormat: "",
    detailText: "",
    parseError: localizeRuntimeText(message),
    parseErrorRaw: message,
    pemBytes: new Uint8Array(),
    derBytes: new Uint8Array(),
    loaded: true,
  };
}

async function hydrateItem(item) {
  if (item.loaded) return item;
  try {
    const rawBytes = await fetchCertificateBytes(item);
    return { ...item, ...(await parseCertificateSafe(rawBytes)), parseError: "", parseErrorRaw: "", loaded: true };
  } catch (error) {
    return buildFailedItem(item, error);
  }
}

function replaceItem(nextItem) {
  const bucketItems = state.certs[nextItem.bucket];
  const index = bucketItems.findIndex((entry) => entry.name === nextItem.name);
  if (index < 0) return null;
  bucketItems[index] = nextItem;
  return nextItem;
}

async function hydrateItemTracked(item, token = state.hydrationToken) {
  const key = itemKey(item);
  if (state.pendingHydrations.has(key)) return state.pendingHydrations.get(key);

  const task = (async () => {
    const hydrated = await hydrateItem(item);
    if (token !== state.hydrationToken) return hydrated;
    replaceItem(hydrated);
    scheduleRender();
    return hydrated;
  })();

  state.pendingHydrations.set(key, task);
  task.finally(() => {
    state.pendingHydrations.delete(key);
  });
  return task;
}

function updateStatusIndicator() {
  elements.statusBadge.classList.toggle("connected", state.connected);
  elements.statusBadge.classList.toggle("disconnected", !state.connected);
  elements.statusText.textContent = state.connected ? t("status.connected") : t("status.disconnected");
}

function isExpanded(item) {
  return state.expandedKey === itemKey(item);
}

function buildDnPillGrid(dn) {
  const grid = document.createElement("div");
  grid.className = "detail-pill-grid";
  const keys = ["CN", "O", "OU", "C", "ST", "L"];
  for (const key of keys) {
    const value = dn.fields[key]?.join(" / ");
    if (!value) continue;
    grid.appendChild(createMetaPill(`${key}: ${value}`));
  }
  return grid;
}

async function copyTextValue(value) {
  if (!value) return false;
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
      return true;
    }
  } catch (_) {
    // Fallback below.
  }

  const input = document.createElement("textarea");
  input.value = value;
  input.setAttribute("readonly", "");
  input.style.position = "fixed";
  input.style.opacity = "0";
  document.body.appendChild(input);
  input.select();
  const ok = document.execCommand("copy");
  document.body.removeChild(input);
  return ok;
}

function getCopyPayload(text) {
  const match = String(text).match(/^[^:]+:\s*(.*)$/);
  return match ? match[1].trim() : "";
}

function attachCopyHandlers(node, text) {
  const payload = getCopyPayload(text);
  if (!payload) return;

  let timer = 0;
  let copied = false;

  const clear = () => {
    if (timer) {
      window.clearTimeout(timer);
      timer = 0;
    }
    node.classList.remove("is-pressed");
  };

  node.classList.add("copyable");
  node.addEventListener("pointerdown", () => {
    copied = false;
    node.classList.add("is-pressed");
    timer = window.setTimeout(async () => {
      copied = await copyTextValue(payload);
      node.classList.remove("is-pressed");
      if (copied) {
        toast(t("toast.copied", { value: payload }));
      }
      timer = 0;
    }, 450);
  });
  node.addEventListener("pointerup", clear);
  node.addEventListener("pointerleave", clear);
  node.addEventListener("pointercancel", clear);
  node.addEventListener("contextmenu", (event) => {
    event.preventDefault();
  });
  node.addEventListener("click", (event) => {
    if (copied) {
      event.preventDefault();
      copied = false;
    }
  });
}

function createMetaPill(text, variant = "") {
  const pill = document.createElement("button");
  pill.type = "button";
  pill.className = variant ? `meta-pill ${variant}` : "meta-pill";
  pill.textContent = text;
  attachCopyHandlers(pill, text);
  return pill;
}

function buildAccordionBody(item) {
  const body = document.createElement("div");
  body.className = "accordion-body";
  const parseError = item.parseErrorRaw || item.parseError;

  if (!item.loaded && !state.pendingHydrations.has(itemKey(item))) {
    const pending = document.createElement("p");
    pending.className = "detail-hint";
    pending.textContent = t("detail.pendingQueue");
    body.appendChild(pending);
    return body;
  }

  if (!item.loaded) {
    const pending = document.createElement("p");
    pending.className = "detail-hint";
    pending.textContent = t("detail.pendingReadParse");
    body.appendChild(pending);
    return body;
  }

  const groups = document.createElement("div");
  groups.className = "detail-groups";

  const subjectGroup = document.createElement("section");
  subjectGroup.className = "detail-group";
  const subjectHeading = document.createElement("h4");
  subjectHeading.textContent = t("detail.subject");
  const subjectGrid = buildDnPillGrid(item.subjectDn);
  if (subjectGrid.childElementCount) {
    subjectGroup.append(subjectHeading, subjectGrid);
    groups.appendChild(subjectGroup);
  }

  const issuerGroup = document.createElement("section");
  issuerGroup.className = "detail-group";
  const issuerHeading = document.createElement("h4");
  issuerHeading.textContent = t("detail.issuer");
  const issuerGrid = buildDnPillGrid(item.issuerDn);
  if (issuerGrid.childElementCount) {
    issuerGroup.append(issuerHeading, issuerGrid);
    groups.appendChild(issuerGroup);
  }

  if (groups.childElementCount) {
    body.appendChild(groups);
  }

  const meta = document.createElement("div");
  meta.className = "detail-meta";
  meta.append(
    createMetaPill(t("detail.directory", { value: targetBucketLabel(item.bucket) })),
    createMetaPill(t("detail.serialNumber", { value: displayValue(item.serialNumber) })),
    createMetaPill(t("detail.validFrom", { value: displayValue(item.notBefore) })),
    createMetaPill(t("detail.validUntil", { value: displayValue(item.notAfter) })),
    createMetaPill(t("detail.signatureAlgorithm", { value: displayValue(item.signatureAlgorithmName) })),
    createMetaPill(t("detail.publicKey", { value: formatPublicKeyValue(item.publicKeyAlgorithm, item.publicKeySizeBits) })),
    createMetaPill(t("detail.extensions", { value: item.extensionCount ?? t("common.unknown") })),
    createMetaPill(t("detail.format", { value: displayValue(item.sourceFormat) })),
    createMetaPill(t("detail.sha256", { value: displayValue(item.sha256) })),
    createMetaPill(t("detail.subjectHashOld", { value: displayValue(item.subjectHashOld) })),
  );
  if (item.protected) meta.appendChild(createMetaPill(t("detail.protectedAdguard"), "warn"));
  if (parseError) meta.appendChild(createMetaPill(localizeRuntimeText(parseError), "warn"));
  body.appendChild(meta);

  const detail = document.createElement("pre");
  detail.className = "detail-output";
  detail.textContent = parseError ? buildParseFailureDetail(parseError) : item.detailText || t("detail.noDetails");
  body.appendChild(detail);
  return body;
}

function renderList(bucket) {
  const listNode = bucket === "custom" ? elements.customList : elements.addedList;
  const countNode = bucket === "custom" ? elements.customCount : elements.addedCount;
  const items = state.certs[bucket];

  countNode.textContent = String(items.length);
  listNode.innerHTML = "";
  if (!items.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = t("list.empty");
    listNode.appendChild(empty);
    return;
  }

  for (const item of items) {
    const key = itemKey(item);
    const expanded = isExpanded(item);
    const card = document.createElement("article");
    card.className = expanded ? "cert-card active" : "cert-card";

    const titleWrap = document.createElement("div");
    titleWrap.className = "card-title";
    const title = document.createElement("h3");
    title.textContent = item.loaded && !isPlaceholderValue(item.subjectCn) ? item.subjectCn : item.name;
    const fileName = document.createElement("code");
    fileName.textContent = item.name;
    titleWrap.append(title, fileName);
    card.appendChild(titleWrap);

    const meta = document.createElement("div");
    meta.className = "cert-meta";
    meta.appendChild(createMetaPill(item.loaded ? t("list.expires", { value: displayValue(item.notAfter) }) : t("cert.parsingShort")));
    if (item.protected) meta.appendChild(createMetaPill(t("cert.protected"), "warn"));
    if (item.parseErrorRaw || item.parseError) meta.appendChild(createMetaPill(t("cert.parseFailedShort"), "warn"));
    card.appendChild(meta);

    const actions = document.createElement("div");
    actions.className = "card-actions";
    const itemBusy = state.pendingMoves.has(key) || state.pendingDeletes.has(key);

    const deleteButton = document.createElement("button");
    deleteButton.className = "icon-button icon-button-danger";
    deleteButton.type = "button";
    deleteButton.setAttribute("aria-label", t("list.deleteAria", { name: item.name }));
    deleteButton.title = t("list.deleteAria", { name: item.name });
    deleteButton.innerHTML = `
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M3 6h18" />
        <path d="M8 6V4h8v2" />
        <path d="M19 6l-1 14H6L5 6" />
        <path d="M10 10v6" />
        <path d="M14 10v6" />
      </svg>
    `;
    deleteButton.disabled = itemBusy || !state.connected || state.refreshing || state.importing;
    deleteButton.addEventListener("click", async () => {
      await deleteCertificate(item);
    });
    actions.appendChild(deleteButton);

    const moveButton = document.createElement("button");
    moveButton.className = "button button-primary";
    moveButton.type = "button";
    moveButton.textContent = t("list.move");
    if (isMoveDisabled(item)) {
      moveButton.textContent = t("list.stayInAdded");
      moveButton.disabled = true;
    } else {
      moveButton.disabled = itemBusy || !state.connected || state.refreshing || state.importing;
      moveButton.addEventListener("click", async () => {
        await moveCertificate(item);
      });
    }
    actions.appendChild(moveButton);

    const detailButton = document.createElement("button");
    detailButton.className = "button button-secondary";
    detailButton.type = "button";
    detailButton.textContent = expanded ? t("list.collapseDetails") : t("list.expandDetails");
    detailButton.disabled = itemBusy || state.refreshing;
    detailButton.addEventListener("click", async () => {
      if (expanded) {
        state.expandedKey = null;
        renderAllLists();
        return;
      }
      state.expandedKey = key;
      renderAllLists();
      if (!item.loaded) await hydrateItemTracked(item);
    });
    actions.appendChild(detailButton);
    card.appendChild(actions);

    if (expanded) card.appendChild(buildAccordionBody(item));
    listNode.appendChild(card);
  }
}

function renderAllLists() {
  renderList("custom");
  renderList("added");
}

function reconcileExpandedKey() {
  if (!state.expandedKey) return;
  const exists = [...state.certs.custom, ...state.certs.added].some((item) => itemKey(item) === state.expandedKey);
  if (!exists) state.expandedKey = null;
}

async function hydrateAllCertificates(token) {
  const items = [...state.certs.custom, ...state.certs.added];
  if (!items.length) {
    state.parsingAll = false;
    updateControls();
    return;
  }

  state.parsingAll = true;
  updateControls();
  let cursor = 0;
  const concurrency = Math.min(4, items.length);
  const workers = Array.from({ length: concurrency }, async () => {
    while (token === state.hydrationToken) {
      const index = cursor;
      cursor += 1;
      const item = items[index];
      if (!item) return;
      await hydrateItemTracked(item, token);
    }
  });

  await Promise.allSettled(workers);
  if (token !== state.hydrationToken) return;
  state.parsingAll = false;
  updateControls();
  renderAllLists();
}

async function refreshList({ preserveScroll = false } = {}) {
  const restoreScroll = preserveScroll ? createScrollRestorer() : null;
  const token = ++state.hydrationToken;
  state.refreshing = true;
  clearMessage(elements.importResult);
  updateControls();

  try {
    const items = parseList(await runApi(["list"]));
    state.certs.custom = items.filter((item) => item.bucket === "custom");
    state.certs.added = items.filter((item) => item.bucket === "added");
    reconcileExpandedKey();
    renderAllLists();
  } catch (error) {
    toast(t("toast.refreshFailed", { message: errorMessage(error) }));
    return;
  } finally {
    state.refreshing = false;
    updateControls();
    restoreScroll?.();
  }

  await hydrateAllCertificates(token);
  restoreScroll?.();
}

async function moveCertificate(item) {
  if (isMoveDisabled(item)) {
    toast(t("toast.moveProtected"));
    return;
  }

  const key = itemKey(item);
  if (state.pendingMoves.has(key)) return;
  state.pendingMoves.add(key);
  renderAllLists();

  try {
    const target = nextBucket(item);
    await runApi(["move", item.bucket, target, item.name]);
    toast(t("toast.moved", { bucket: targetBucketLabel(target) }));
    state.expandedKey = itemKey({ bucket: target, name: item.name });
    await refreshList({ preserveScroll: true });
  } catch (error) {
    toast(t("toast.moveFailed", { message: errorMessage(error) }));
  } finally {
    state.pendingMoves.delete(key);
    renderAllLists();
  }
}

async function deleteCertificate(item) {
  const key = itemKey(item);
  if (state.pendingDeletes.has(key)) return;
  if (!(await confirmDeleteCertificate(item))) return;

  state.pendingDeletes.add(key);
  renderAllLists();

  try {
    await runApi(["delete", item.bucket, item.name]);
    if (state.expandedKey === key) state.expandedKey = null;
    toast(t("toast.deleted", { name: item.name }));
    await refreshList({ preserveScroll: true });
  } catch (error) {
    toast(t("toast.deleteFailed", { message: errorMessage(error) }));
  } finally {
    state.pendingDeletes.delete(key);
    renderAllLists();
  }
}

function readFileBytes(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(new Uint8Array(reader.result));
    reader.onerror = () => reject(new Error(t("error.readFileFailed", { name: file.name })));
    reader.readAsArrayBuffer(file);
  });
}

function getNextImportName(bucketOrNames, subjectHashOld) {
  const existing =
    bucketOrNames === "custom" || bucketOrNames === "added"
      ? normalizeExistingNames(state.certs[bucketOrNames])
      : normalizeExistingNames(bucketOrNames);
  const indices = [...existing]
    .filter((name) => itemSubjectHashOld({ name }) === subjectHashOld)
    .map((name) => getImportNameIndex(name))
    .filter(Number.isFinite);
  const nextIndex = indices.length ? Math.max(...indices) + 1 : 0;
  return `${subjectHashOld}.${nextIndex}`;
}

function shouldConfirmExpiry(certificate) {
  if (typeof certificate.notAfterTime !== "number" || Number.isNaN(certificate.notAfterTime)) {
    return false;
  }
  const warningThreshold = Date.now() + 30 * 24 * 60 * 60 * 1000;
  return certificate.notAfterTime <= warningThreshold;
}

function buildImportPayload(certificate) {
  const pemBlock = certificate.pem.endsWith("\n") ? certificate.pem : `${certificate.pem}\n`;
  const detailBlock = certificate.detailText ? certificate.detailText.trim() : "";
  const sha1Line = certificate.fingerprintLine || (certificate.sha1 ? `sha1 Fingerprint=${certificate.sha1}` : "");
  const suffix = [detailBlock, sha1Line].filter(Boolean).join("\n");
  return suffix ? `${pemBlock}${suffix}\n` : pemBlock;
}

async function confirmExpiringCertificate(certificate, sourceLabel) {
  if (!shouldConfirmExpiry(certificate)) {
    return true;
  }

  const action = await showChoiceDialog({
    title: t("dialog.expiring.title"),
    message: [
      t("dialog.expiring.line1", { source: sourceLabel, date: displayValue(certificate.notAfter) }),
      t("dialog.expiring.line2"),
      t("dialog.expiring.line3"),
    ].join("\n"),
    actions: [
      { id: "cancel", label: t("common.cancel"), variant: "secondary" },
      { id: "continue", label: t("common.continueImport"), variant: "primary", focus: true },
    ],
  });
  return action === "continue";
}

async function resolveImportCollision(bucket, sourceLabel, certificate, existingNames) {
  const conflicts = listImportConflicts(existingNames, certificate.subjectHashOld);
  if (!conflicts.length) {
    const finalName = getNextImportName(existingNames, certificate.subjectHashOld);
    return { cancelled: false, overwrite: false, finalName, resultText: t("import.resultCreated", { source: sourceLabel, name: finalName }) };
  }

  const replaceName = conflicts.includes(`${certificate.subjectHashOld}.0`) ? `${certificate.subjectHashOld}.0` : conflicts[0];
  const renameName = getNextImportName(existingNames, certificate.subjectHashOld);
  const action = await showChoiceDialog({
    title: t("dialog.duplicate.title"),
    message: [
      t("dialog.duplicate.line1", { bucket: targetBucketLabel(bucket) }),
      t("dialog.duplicate.line2", { conflicts: conflicts.join(", ") }),
      t("dialog.duplicate.line3", { replaceName }),
      t("dialog.duplicate.line4", { renameName }),
    ].join("\n"),
    actions: [
      { id: "cancel", label: t("common.cancel"), variant: "secondary", focus: true },
      { id: "replace", label: t("common.replace"), variant: "danger" },
      { id: "rename", label: t("common.rename"), variant: "primary" },
    ],
  });

  if (action === "replace") {
    return {
      cancelled: false,
      overwrite: true,
      finalName: replaceName,
      resultText: t("import.resultReplaced", { source: sourceLabel, name: replaceName }),
    };
  }

  if (action === "rename") {
    return {
      cancelled: false,
      overwrite: false,
      finalName: renameName,
      resultText: t("import.resultRenamed", { source: sourceLabel, name: renameName }),
    };
  }

  return { cancelled: true };
}

async function confirmDeleteCertificate(item) {
  const action = await showChoiceDialog({
    title: t("dialog.delete.title"),
    message: [
      t("dialog.delete.line1", { bucket: targetBucketLabel(item.bucket), name: item.name }),
      t("dialog.delete.line2"),
      t("dialog.delete.line3"),
    ].join("\n"),
    actions: [
      { id: "cancel", label: t("common.cancel"), variant: "secondary", focus: true },
      { id: "delete", label: t("common.delete"), variant: "danger" },
    ],
  });
  return action === "delete";
}

async function importFiles() {
  const files = [...elements.importFiles.files];
  const importUrl = elements.importUrl.value.trim();
  const target = elements.importTarget.value;
  if (!files.length && !importUrl) {
    showMessage(elements.importResult, t("import.missingSource"), true);
    return;
  }

  state.importing = true;
  updateControls();
  clearMessage(elements.importResult);
  const results = [];
  const skipped = [];
  const existingNames = {
    custom: normalizeExistingNames(state.certs.custom),
    added: normalizeExistingNames(state.certs.added),
  };

  try {
    const sources = files.length
      ? await Promise.all(files.map(async (file) => ({ label: file.name, bytes: await readFileBytes(file) })))
      : [{ label: importUrl, bytes: await downloadCertificateBytes(importUrl) }];

    for (const source of sources) {
      const certificate = await parseCertificateSafe(source.bytes);
      if (!(await confirmExpiringCertificate(certificate, source.label))) {
        skipped.push(t("import.resultCancelled", { source: source.label }));
        continue;
      }

      const collision = await resolveImportCollision(target, source.label, certificate, existingNames[target]);
      if (collision.cancelled) {
        skipped.push(t("import.resultCancelled", { source: source.label }));
        continue;
      }

      const finalName = collision.finalName;
      const payload = bytesToBase64(new TextEncoder().encode(buildImportPayload(certificate)));
      await runApi(["save", target, finalName, payload, collision.overwrite ? "overwrite" : "create"]);
      existingNames[target].add(finalName);
      results.push(collision.resultText);
    }

    if (!results.length && skipped.length) {
      showMessage(elements.importResult, t("import.summaryNone", { entries: skipped.join("\n") }), true);
      return;
    }

    const lines = [t("import.summarySuccess", { entries: results.join("\n") })];
    if (skipped.length) {
      lines.push(t("import.summarySkipped", { entries: skipped.join("\n") }));
    }
    showMessage(elements.importResult, lines.join("\n\n"));
    elements.importFiles.value = "";
    elements.importUrl.value = "";
    toast(t("toast.importComplete"));
    await refreshList({ preserveScroll: true });
  } catch (error) {
    showMessage(elements.importResult, t("toast.importFailed", { message: errorMessage(error) }), true);
    toast(t("toast.importFailed", { message: errorMessage(error) }));
  } finally {
    state.importing = false;
    updateControls();
  }
}

function bindEvents() {
  elements.fabRefreshButton.addEventListener("click", async () => {
    await refreshList({ preserveScroll: true });
  });
  elements.fabLanguageButton?.addEventListener("click", () => {
    if (typeof i18n.setLanguage === "function") {
      i18n.setLanguage(getNextLanguage());
    }
    syncLanguageUi();
  });
  elements.importButton.addEventListener("click", importFiles);
  lastScrollY = window.scrollY || 0;
  window.addEventListener(
    "scroll",
    () => {
      const currentY = window.scrollY || 0;
      const delta = currentY - lastScrollY;
      if (Math.abs(delta) < 4) {
        return;
      }

      if (currentY <= 8 || delta < 0) {
        elements.fabStack?.classList.remove("is-hidden");
      } else {
        elements.fabStack?.classList.add("is-hidden");
      }

      lastScrollY = currentY;
    },
    { passive: true },
  );
}

async function init() {
  bindEvents();
  if (window.ksu && typeof window.ksu.fullScreen === "function") {
    window.ksu.fullScreen(true);
  }

  state.connected = Boolean(window.ksu && typeof window.ksu.exec === "function");
  syncLanguageUi();
  updateControls();
  if (!state.connected) {
    return;
  }

  try {
    ensureParserWorker();
  } catch (error) {
    state.parserMode = "main-thread";
  }

  await refreshList();
}

init().catch((error) => {
  toast(t("toast.initFailed", { message: errorMessage(error) }));
});
