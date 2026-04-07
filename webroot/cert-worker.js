importScripts("./reflection.min.js");
importScripts("./x509.min.js", "./cert-text.js");

const ASCII_CHUNK_SIZE = 0x8000;
const CURVE_BITS = {
  "P-256": 256,
  "K-256": 256,
  "P-384": 384,
  "P-521": 521,
  Ed25519: 256,
  Ed448: 456,
};

function ensureUint8Array(data) {
  if (data instanceof Uint8Array) {
    return data;
  }
  if (data instanceof ArrayBuffer) {
    return new Uint8Array(data);
  }
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  return new Uint8Array(data);
}

function bytesToBinary(bytes) {
  const input = ensureUint8Array(bytes);
  if (!input.length) {
    return "";
  }

  const parts = [];
  for (let index = 0; index < input.length; index += ASCII_CHUNK_SIZE) {
    parts.push(String.fromCharCode(...input.subarray(index, index + ASCII_CHUNK_SIZE)));
  }
  return parts.join("");
}

function detectSourceFormat(bytes) {
  return bytesToBinary(ensureUint8Array(bytes).slice(0, 64)).includes("BEGIN CERTIFICATE") ? "PEM" : "DER";
}

function bytesToHex(bytes, separator = ":") {
  return [...ensureUint8Array(bytes)].map((value) => value.toString(16).padStart(2, "0").toUpperCase()).join(separator);
}

function formatDate(value) {
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    return "未知";
  }

  const year = value.getUTCFullYear();
  const month = String(value.getUTCMonth() + 1).padStart(2, "0");
  const day = String(value.getUTCDate()).padStart(2, "0");
  const hours = String(value.getUTCHours()).padStart(2, "0");
  const minutes = String(value.getUTCMinutes()).padStart(2, "0");
  const seconds = String(value.getUTCSeconds()).padStart(2, "0");
  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds} UTC`;
}

function formatAlgorithm(algorithm) {
  if (!algorithm || typeof algorithm !== "object") {
    return "未知";
  }

  const parts = [];
  if (algorithm.name) {
    parts.push(String(algorithm.name));
  }
  if (algorithm.hash?.name) {
    parts.push(String(algorithm.hash.name));
  }
  if (algorithm.namedCurve) {
    parts.push(String(algorithm.namedCurve));
  }

  return parts.length ? parts.join(" / ") : "未知";
}

function getPublicKeySizeBits(algorithm) {
  if (!algorithm || typeof algorithm !== "object") {
    return 0;
  }

  if (typeof algorithm.modulusLength === "number") {
    return algorithm.modulusLength;
  }
  if (algorithm.namedCurve && CURVE_BITS[algorithm.namedCurve]) {
    return CURVE_BITS[algorithm.namedCurve];
  }
  if (algorithm.name && CURVE_BITS[algorithm.name]) {
    return CURVE_BITS[algorithm.name];
  }
  return 0;
}

async function sha256Fingerprint(bytes) {
  if (!globalThis.crypto?.subtle) {
    return "未知";
  }

  const input = ensureUint8Array(bytes);
  const digest = await globalThis.crypto.subtle.digest("SHA-256", input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength));
  return bytesToHex(new Uint8Array(digest));
}

async function sha1Fingerprint(bytes) {
  if (!globalThis.crypto?.subtle) {
    return "未知";
  }

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
    for (let index = 0; index < 16; index += 1) {
      chunk[index] = lengthView.getUint32(offset + index * 4, true);
    }

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

function extractEmbeddedCertificateText(bytes) {
  const sourceText = bytesToBinary(ensureUint8Array(bytes)).replace(/\r\n/g, "\n");
  const match = sourceText.match(/-----END CERTIFICATE-----\n([\s\S]*)$/);
  if (!match) {
    return { detailText: "", fingerprintLine: "" };
  }

  const appendix = match[1].trim();
  if (!appendix) {
    return { detailText: "", fingerprintLine: "" };
  }

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
  if (!detailText && !fingerprintLine) {
    return { detailText: "", fingerprintLine: "" };
  }
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
  const formatter = self.customCertificateText;
  if (!formatter?.buildOpenSslCertificateText) {
    return buildFallbackDetailText(summary);
  }

  try {
    return formatter.buildOpenSslCertificateText(certificate);
  } catch (_) {
    return buildFallbackDetailText(summary);
  }
}

async function parseCertificate(bytes) {
  if (!self.x509?.X509Certificate) {
    throw new Error("@peculiar/x509 浏览器构建未加载");
  }

  const rawBytes = ensureUint8Array(bytes);
  if (!rawBytes.length) {
    throw new Error("证书内容为空");
  }

  const certificate = new self.x509.X509Certificate(rawBytes);
  const derBytes = ensureUint8Array(certificate.rawData).slice();
  const pem = certificate.toString("pem");
  const pemBytes = new TextEncoder().encode(pem);
  const embeddedText = extractEmbeddedCertificateText(rawBytes);
  const sha1 = await sha1Fingerprint(derBytes);
  const summary = {
    serialNumber: String(certificate.serialNumber || "").toUpperCase() || "未知",
    issuer: certificate.issuer || "未知",
    subject: certificate.subject || "未知",
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

  return {
    ...summary,
    detailText,
  };
}

self.addEventListener("message", async (event) => {
  const message = event.data || {};
  if (message.type !== "parse") {
    return;
  }

  try {
    const result = await parseCertificate(message.bytes);
    const transfer = [];

    if (result.pemBytes?.buffer) {
      transfer.push(result.pemBytes.buffer);
    }
    if (result.derBytes?.buffer && result.derBytes.buffer !== result.pemBytes?.buffer) {
      transfer.push(result.derBytes.buffer);
    }

    self.postMessage({ id: message.id, ok: true, result }, transfer);
  } catch (error) {
    self.postMessage({
      id: message.id,
      ok: false,
      error: error instanceof Error ? error.message : String(error),
    });
  }
});
