(function initCustomCertificateI18n(global) {
  const STORAGE_KEY = "custom-certificates.language";
  const DEFAULT_LANGUAGE = "zh-CN";
  const SUPPORTED_LANGUAGES = ["zh-CN", "en-US"];

  // Centralized translation table for the WebUI.
  const MESSAGES = {
    "zh-CN": {
      "page.title": "Custom Certificates",
      "hero.title": "证书仓库",
      "hero.lede": "查看、解析、移动与导入用户证书。目录改动会立即写入文件系统，但系统信任链需要重启后才会完全生效。",
      "status.connecting": "准备连接",
      "status.connected": "已连接",
      "status.disconnected": "未连接",
      "import.sectionLabel": "导入证书",
      "import.heading": "选择文件或链接并转换保存",
      "import.copy": "支持 PEM 或 DER。文件和 URL 二选一即可；若两者都填写，仍会优先使用所选文件。",
      "import.targetLabel": "保存到",
      "import.fileLabel": "证书文件",
      "import.urlLabel": "证书 URL",
      "import.urlPlaceholder": "https://example.com/cacert.pem",
      "import.urlHint": "文件和 URL 二选一即可。若两者都提供，将优先使用文件。",
      "import.submit": "转换并导入",
      "import.missingSource": "请先选择证书文件，或填写一个证书 URL。",
      "import.summaryNone": "未导入任何证书:\n{entries}",
      "import.summarySuccess": "导入完成:\n{entries}",
      "import.summarySkipped": "已跳过:\n{entries}",
      "import.resultCreated": "{source} -> {name}",
      "import.resultCancelled": "{source} -> 已取消",
      "import.resultReplaced": "{source} -> {name}（替换）",
      "import.resultRenamed": "{source} -> {name}（重命名）",
      "fab.language.switchToEnglish": "切换到 English",
      "fab.language.switchToChinese": "切换到 中文",
      "fab.refresh": "刷新列表",
      "common.unknown": "未知",
      "common.notProvided": "未填写",
      "common.bitsUnit": "bits",
      "common.cancel": "取消",
      "common.delete": "删除",
      "common.replace": "替换",
      "common.rename": "重命名",
      "common.continueImport": "继续导入",
      "detail.pendingQueue": "正在排队解析证书，请稍候…",
      "detail.pendingReadParse": "正在读取并解析证书，请稍候…",
      "detail.subject": "主题",
      "detail.issuer": "签发者",
      "detail.directory": "目录: {value}",
      "detail.serialNumber": "序列号: {value}",
      "detail.validFrom": "生效: {value}",
      "detail.validUntil": "到期: {value}",
      "detail.signatureAlgorithm": "签名算法: {value}",
      "detail.publicKey": "公钥: {value}",
      "detail.extensions": "扩展: {value}",
      "detail.format": "格式: {value}",
      "detail.sha256": "SHA256: {value}",
      "detail.subjectHashOld": "subject_hash_old: {value}",
      "detail.protectedAdguard": "AdGuard 证书固定在 cacerts-added",
      "detail.noDetails": "没有可显示的证书详情。",
      "cert.pendingShort": "待解析",
      "cert.parsingShort": "解析中",
      "cert.protected": "受保护",
      "cert.parseFailedShort": "解析失败",
      "cert.parseFailedDetail": "证书解析失败\n{message}",
      "list.empty": "当前目录中没有证书。",
      "list.expires": "到期: {value}",
      "list.deleteAria": "删除 {name}",
      "list.move": "移动",
      "list.stayInAdded": "固定",
      "list.expandDetails": "查看详情",
      "list.collapseDetails": "收起详情",
      "dialog.expiring.title": "证书即将过期",
      "dialog.expiring.line1": "证书 {source} 的到期时间为 {date}。",
      "dialog.expiring.line2": "距离当前时间已不足 30 天，或已经过期。",
      "dialog.expiring.line3": "仍要继续导入吗？",
      "dialog.duplicate.title": "发现重复导入",
      "dialog.duplicate.line1": "目录 {bucket} 已存在相同 subject_hash_old 的证书。",
      "dialog.duplicate.line2": "已存在: {conflicts}",
      "dialog.duplicate.line3": "替换: 覆盖 {replaceName}",
      "dialog.duplicate.line4": "重命名: 保存为 {renameName}",
      "dialog.delete.title": "删除证书",
      "dialog.delete.line1": "将从 {bucket} 删除 {name}。",
      "dialog.delete.line2": "此操作会直接删除文件。",
      "dialog.delete.line3": "确定删除吗？",
      "toast.copied": "已复制: {value}",
      "toast.refreshFailed": "刷新失败: {message}",
      "toast.moveProtected": "AdGuard Personal Intermediate 必须保留在 cacerts-added。",
      "toast.moved": "已移动到 {bucket}",
      "toast.moveFailed": "移动失败: {message}",
      "toast.deleted": "已删除 {name}",
      "toast.deleteFailed": "删除失败: {message}",
      "toast.importComplete": "证书导入完成",
      "toast.importFailed": "导入失败: {message}",
      "toast.initFailed": "初始化失败: {message}",
      "error.x509BrowserBuildMissing": "@peculiar/x509 浏览器构建未加载",
      "error.certificateEmpty": "证书内容为空",
      "error.parserReset": "解析器已重置",
      "error.noWebWorker": "当前 WebView 不支持 Web Worker",
      "error.certificateParseFailed": "证书解析失败",
      "error.parserWorkerExit": "证书解析 Worker 异常退出",
      "error.parseTimeout": "证书解析超时（>{timeoutMs}ms）",
      "error.bridgeUnavailable": "KernelSU WebUI bridge 不可用",
      "error.unexpectedApiResponse": "API 返回格式异常",
      "error.readCertificateFailed": "读取证书失败",
      "error.downloadCertificateFailed": "下载证书失败",
      "error.unableToParse": "未能解析",
      "error.readFileFailed": "读取 {name} 失败",
      "error.apiScriptNotFound": "无法定位 webui-api.sh，已尝试: {paths}",
      "error.commandFailed": "命令执行失败，退出码 {code}",
    },
    "en-US": {
      "page.title": "Custom Certificates",
      "hero.title": "Certificate Store",
      "hero.lede":
        "Browse, inspect, move, and import user certificates. Directory changes are written immediately, but the system trust chain needs a reboot to fully take effect.",
      "status.connecting": "Connecting",
      "status.connected": "Connected",
      "status.disconnected": "Disconnected",
      "import.sectionLabel": "Import Certificate",
      "import.heading": "Choose a file or URL and save the converted result",
      "import.copy": "PEM and DER are supported. Provide either files or a URL; if both are set, the selected files take precedence.",
      "import.targetLabel": "Save to",
      "import.fileLabel": "Certificate File",
      "import.urlLabel": "Certificate URL",
      "import.urlPlaceholder": "https://example.com/cacert.pem",
      "import.urlHint": "Provide either files or a URL. If both are set, the selected files take precedence.",
      "import.submit": "Convert and Import",
      "import.missingSource": "Choose certificate files first, or enter a certificate URL.",
      "import.summaryNone": "No certificates were imported:\n{entries}",
      "import.summarySuccess": "Import complete:\n{entries}",
      "import.summarySkipped": "Skipped:\n{entries}",
      "import.resultCreated": "{source} -> {name}",
      "import.resultCancelled": "{source} -> cancelled",
      "import.resultReplaced": "{source} -> {name} (replaced)",
      "import.resultRenamed": "{source} -> {name} (renamed)",
      "fab.language.switchToEnglish": "Switch to English",
      "fab.language.switchToChinese": "Switch to Chinese",
      "fab.refresh": "Refresh list",
      "common.unknown": "Unknown",
      "common.notProvided": "Not provided",
      "common.bitsUnit": "bits",
      "common.cancel": "Cancel",
      "common.delete": "Delete",
      "common.replace": "Replace",
      "common.rename": "Rename",
      "common.continueImport": "Continue Import",
      "detail.pendingQueue": "Certificate parsing is queued. Please wait…",
      "detail.pendingReadParse": "Reading and parsing the certificate. Please wait…",
      "detail.subject": "Subject",
      "detail.issuer": "Issuer",
      "detail.directory": "Directory: {value}",
      "detail.serialNumber": "Serial Number: {value}",
      "detail.validFrom": "Not Before: {value}",
      "detail.validUntil": "Not After: {value}",
      "detail.signatureAlgorithm": "Signature Algorithm: {value}",
      "detail.publicKey": "Public Key: {value}",
      "detail.extensions": "Extensions: {value}",
      "detail.format": "Format: {value}",
      "detail.sha256": "SHA256: {value}",
      "detail.subjectHashOld": "subject_hash_old: {value}",
      "detail.protectedAdguard": "The AdGuard certificate is pinned to cacerts-added",
      "detail.noDetails": "No certificate details are available.",
      "cert.pendingShort": "Pending parse",
      "cert.parsingShort": "Parsing",
      "cert.protected": "Protected",
      "cert.parseFailedShort": "Parse failed",
      "cert.parseFailedDetail": "Certificate parse failed\n{message}",
      "list.empty": "There are no certificates in this directory.",
      "list.expires": "Expires: {value}",
      "list.deleteAria": "Delete {name}",
      "list.move": "Move",
      "list.stayInAdded": "Fixed",
      "list.expandDetails": "Details",
      "list.collapseDetails": "Hide",
      "dialog.expiring.title": "Certificate Is Expiring Soon",
      "dialog.expiring.line1": "Certificate {source} expires at {date}.",
      "dialog.expiring.line2": "It will expire within 30 days, or has already expired.",
      "dialog.expiring.line3": "Do you still want to import it?",
      "dialog.duplicate.title": "Duplicate Import Detected",
      "dialog.duplicate.line1": "A certificate with the same subject_hash_old already exists in {bucket}.",
      "dialog.duplicate.line2": "Existing: {conflicts}",
      "dialog.duplicate.line3": "Replace: overwrite {replaceName}",
      "dialog.duplicate.line4": "Rename: save as {renameName}",
      "dialog.delete.title": "Delete Certificate",
      "dialog.delete.line1": "Delete {name} from {bucket}.",
      "dialog.delete.line2": "This action removes the file immediately.",
      "dialog.delete.line3": "Delete it now?",
      "toast.copied": "Copied: {value}",
      "toast.refreshFailed": "Refresh failed: {message}",
      "toast.moveProtected": "AdGuard Personal Intermediate must remain in cacerts-added.",
      "toast.moved": "Moved to {bucket}",
      "toast.moveFailed": "Move failed: {message}",
      "toast.deleted": "Deleted {name}",
      "toast.deleteFailed": "Delete failed: {message}",
      "toast.importComplete": "Certificate import complete",
      "toast.importFailed": "Import failed: {message}",
      "toast.initFailed": "Initialization failed: {message}",
      "error.x509BrowserBuildMissing": "@peculiar/x509 browser build is not loaded",
      "error.certificateEmpty": "Certificate content is empty",
      "error.parserReset": "Parser was reset",
      "error.noWebWorker": "This WebView does not support Web Workers",
      "error.certificateParseFailed": "Certificate parse failed",
      "error.parserWorkerExit": "Certificate parser worker exited unexpectedly",
      "error.parseTimeout": "Certificate parse timed out (>{timeoutMs}ms)",
      "error.bridgeUnavailable": "KernelSU WebUI bridge is unavailable",
      "error.unexpectedApiResponse": "Unexpected API response",
      "error.readCertificateFailed": "Failed to read certificate",
      "error.downloadCertificateFailed": "Failed to download certificate",
      "error.unableToParse": "Unable to parse",
      "error.readFileFailed": "Failed to read {name}",
      "error.apiScriptNotFound": "Unable to locate webui-api.sh. Tried: {paths}",
      "error.commandFailed": "Command failed with code {code}",
    },
  };

  const RUNTIME_PATTERNS = [
    { values: ["未知", "Unknown"], key: "common.unknown" },
    { values: ["未填写", "Not provided"], key: "common.notProvided" },
    { values: ["待解析", "Pending parse"], key: "cert.pendingShort" },
    { values: ["解析中", "Parsing"], key: "cert.parsingShort" },
    { values: ["未能解析", "Unable to parse"], key: "error.unableToParse" },
    { values: ["@peculiar/x509 浏览器构建未加载", "@peculiar/x509 browser build is not loaded"], key: "error.x509BrowserBuildMissing" },
    { values: ["证书内容为空", "Certificate content is empty"], key: "error.certificateEmpty" },
    { values: ["解析器已重置", "Parser was reset"], key: "error.parserReset" },
    { values: ["当前 WebView 不支持 Web Worker", "This WebView does not support Web Workers"], key: "error.noWebWorker" },
    { values: ["证书解析失败", "Certificate parse failed"], key: "error.certificateParseFailed" },
    { values: ["证书解析 Worker 异常退出", "Certificate parser worker exited unexpectedly"], key: "error.parserWorkerExit" },
    { values: ["KernelSU WebUI bridge 不可用", "KernelSU WebUI bridge is unavailable"], key: "error.bridgeUnavailable" },
    { values: ["API 返回格式异常", "Unexpected API response"], key: "error.unexpectedApiResponse" },
    { values: ["读取证书失败", "Failed to read certificate"], key: "error.readCertificateFailed" },
    { values: ["下载证书失败", "Failed to download certificate"], key: "error.downloadCertificateFailed" },
    {
      test(value) {
        return /^证书解析超时（>(\d+)ms）$/.test(value) || /^Certificate parse timed out \(>(\d+)ms\)$/.test(value);
      },
      translate(value, language) {
        const match = value.match(/^证书解析超时（>(\d+)ms）$/) || value.match(/^Certificate parse timed out \(>(\d+)ms\)$/);
        return t("error.parseTimeout", { timeoutMs: match ? match[1] : "0" }, language);
      },
    },
  ];

  function normalizeLanguage(value) {
    const text = String(value || "").trim();
    if (/^zh\b/i.test(text)) return "zh-CN";
    if (/^en\b/i.test(text)) return "en-US";
    return SUPPORTED_LANGUAGES.includes(text) ? text : DEFAULT_LANGUAGE;
  }

  function resolveInitialLanguage() {
    try {
      const stored = global.localStorage?.getItem(STORAGE_KEY);
      if (stored) return normalizeLanguage(stored);
    } catch (_) {
      // Ignore storage access failures.
    }
    return normalizeLanguage(global.navigator?.language || DEFAULT_LANGUAGE);
  }

  function interpolate(template, vars) {
    return String(template).replace(/\{(\w+)\}/g, (_, key) => (key in vars ? String(vars[key]) : ""));
  }

  function messageFor(key, language) {
    const locale = normalizeLanguage(language);
    return MESSAGES[locale]?.[key] ?? MESSAGES[DEFAULT_LANGUAGE]?.[key] ?? key;
  }

  let currentLanguage = resolveInitialLanguage();

  function t(key, vars = {}, language = currentLanguage) {
    return interpolate(messageFor(key, language), vars);
  }

  function localizeRuntimeText(value, vars = {}, language = currentLanguage) {
    const text = String(value ?? "").trim();
    if (!text) return "";

    for (const entry of RUNTIME_PATTERNS) {
      if (entry.values && entry.values.includes(text)) {
        return t(entry.key, vars, language);
      }
      if (typeof entry.test === "function" && entry.test(text)) {
        return entry.translate ? entry.translate(text, language) : t(entry.key, vars, language);
      }
    }

    return text;
  }

  function isPlaceholderValue(value) {
    const text = String(value ?? "").trim();
    if (!text) return true;
    return ["未知", "Unknown", "未填写", "Not provided", "待解析", "Pending parse", "解析中", "Parsing", "未能解析", "Unable to parse"].includes(
      text,
    );
  }

  function displayValue(value, fallbackKey = "common.unknown", language = currentLanguage) {
    const text = localizeRuntimeText(value, {}, language);
    return text || t(fallbackKey, {}, language);
  }

  function queryAll(root, selector) {
    if (!root) return [];
    const nodes = [];
    if (root !== global.document && typeof root.matches === "function" && root.matches(selector)) {
      nodes.push(root);
    }
    if (typeof root.querySelectorAll === "function") {
      nodes.push(...root.querySelectorAll(selector));
    }
    return nodes;
  }

  function applyTranslations(root = global.document) {
    if (!global.document || !root) return currentLanguage;

    global.document.documentElement.lang = currentLanguage;
    global.document.title = t("page.title");

    for (const node of queryAll(root, "[data-i18n]")) {
      node.textContent = t(node.getAttribute("data-i18n"));
    }
    for (const node of queryAll(root, "[data-i18n-placeholder]")) {
      node.setAttribute("placeholder", t(node.getAttribute("data-i18n-placeholder")));
    }
    for (const node of queryAll(root, "[data-i18n-title]")) {
      node.setAttribute("title", t(node.getAttribute("data-i18n-title")));
    }
    for (const node of queryAll(root, "[data-i18n-aria-label]")) {
      node.setAttribute("aria-label", t(node.getAttribute("data-i18n-aria-label")));
    }
    return currentLanguage;
  }

  function setLanguage(nextLanguage, { persist = true } = {}) {
    currentLanguage = normalizeLanguage(nextLanguage);
    if (persist) {
      try {
        global.localStorage?.setItem(STORAGE_KEY, currentLanguage);
      } catch (_) {
        // Ignore storage access failures.
      }
    }
    applyTranslations(global.document);
    return currentLanguage;
  }

  global.customCertificateI18n = {
    DEFAULT_LANGUAGE,
    STORAGE_KEY,
    SUPPORTED_LANGUAGES,
    MESSAGES,
    normalizeLanguage,
    getLanguage: () => currentLanguage,
    setLanguage,
    t,
    applyTranslations,
    localizeRuntimeText,
    displayValue,
    isPlaceholderValue,
  };

  if (global.document) {
    if (global.document.readyState === "loading") {
      global.document.addEventListener(
        "DOMContentLoaded",
        () => {
          applyTranslations(global.document);
        },
        { once: true },
      );
    } else {
      applyTranslations(global.document);
    }
  }
})(globalThis);
