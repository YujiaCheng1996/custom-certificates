(function initCustomCertificateText(global) {
  if (global.customCertificateText?.buildOpenSslCertificateText) {
    return;
  }

  const MONTH_NAMES = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const CURVE_BITS = { "P-256": 256, "K-256": 256, "P-384": 384, "P-521": 521, Ed25519: 256, Ed448: 456 };
  const CURVE_DETAILS = {
    "1.2.840.10045.3.1.7": { asn1: "prime256v1", nist: "P-256", bits: 256 },
    "1.3.132.0.10": { asn1: "secp256k1", bits: 256 },
    "1.3.132.0.34": { asn1: "secp384r1", nist: "P-384", bits: 384 },
    "1.3.132.0.35": { asn1: "secp521r1", nist: "P-521", bits: 521 },
  };
  const OID_NAMES = {
    "1.2.840.10045.2.1": "id-ecPublicKey",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.10": "rsassaPss",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.3.101.112": "ED25519",
    "1.3.101.113": "ED448",
  };
  const EXTENSION_NAMES = {
    "1.3.6.1.5.5.7.1.1": "Authority Information Access",
    "2.5.29.14": "Subject Key Identifier",
    "2.5.29.15": "Key Usage",
    "2.5.29.17": "Subject Alternative Name",
    "2.5.29.18": "Issuer Alternative Name",
    "2.5.29.19": "Basic Constraints",
    "2.5.29.31": "CRL Distribution Points",
    "2.5.29.32": "Certificate Policies",
    "2.5.29.35": "Authority Key Identifier",
    "2.5.29.37": "Extended Key Usage",
  };
  const ACCESS_METHOD_NAMES = {
    "1.3.6.1.5.5.7.48.1": "OCSP",
    "1.3.6.1.5.5.7.48.2": "CA Issuers",
    "1.3.6.1.5.5.7.48.5": "CA Repository",
  };
  const EXTENDED_KEY_USAGE_NAMES = {
    "1.3.6.1.4.1.311.10.3.3": "Microsoft Server Gated Crypto",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.5.5.7.3.1": "TLS Web Server Authentication",
    "1.3.6.1.5.5.7.3.2": "TLS Web Client Authentication",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.5.5.7.3.4": "E-mail Protection",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    "2.5.29.37.0": "Any Extended Key Usage",
  };
  const KEY_USAGE_NAMES = [
    [0, "Digital Signature"],
    [1, "Non Repudiation"],
    [2, "Key Encipherment"],
    [3, "Data Encipherment"],
    [4, "Key Agreement"],
    [5, "Certificate Sign"],
    [6, "CRL Sign"],
    [7, "Encipher Only"],
    [8, "Decipher Only"],
  ];
  const textDecoder = typeof TextDecoder === "function" ? new TextDecoder("utf-8") : null;

  function ensureUint8Array(data) {
    if (data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    return new Uint8Array(data || []);
  }

  function toArrayBuffer(bytes) {
    const input = ensureUint8Array(bytes);
    return input.buffer.slice(input.byteOffset, input.byteOffset + input.byteLength);
  }

  function decodeText(bytes) {
    const input = ensureUint8Array(bytes);
    if (!input.length) return "";
    if (textDecoder) return textDecoder.decode(input);
    return Array.from(input, (value) => String.fromCharCode(value)).join("");
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
    return String(value || "").replace(/\\([,=+<>#;"\\])/g, "$1").replace(/\\ /g, " ").trim();
  }

  function formatDistinguishedName(value) {
    const raw = String(value || "").trim();
    if (!raw) return "未知";
    const ordered = [];
    for (const segment of splitEscaped(raw, ",")) {
      for (const part of splitEscaped(segment, "+")) {
        const pivot = part.indexOf("=");
        if (pivot <= 0) continue;
        const key = part.slice(0, pivot).trim().toUpperCase();
        const fieldValue = unescapeDnValue(part.slice(pivot + 1));
        if (!fieldValue) continue;
        ordered.push(`${key} = ${fieldValue}`);
      }
    }
    return ordered.length ? ordered.join(", ") : raw;
  }

  function isDateLike(value) {
    return value && typeof value.getTime === "function" && typeof value.getUTCFullYear === "function";
  }

  function formatOpenSslDate(value) {
    if (!isDateLike(value) || Number.isNaN(value.getTime())) return "未知";
    return `${MONTH_NAMES[value.getUTCMonth()]} ${String(value.getUTCDate()).padStart(2, " ")} ${String(value.getUTCHours()).padStart(2, "0")}:${String(
      value.getUTCMinutes(),
    ).padStart(2, "0")}:${String(value.getUTCSeconds()).padStart(2, "0")} ${value.getUTCFullYear()} GMT`;
  }

  function readDerLength(bytes, offset) {
    const first = bytes[offset];
    if (typeof first !== "number") throw new Error("Unexpected end of DER length");
    if ((first & 0x80) === 0) return { length: first, offset: offset + 1 };
    const count = first & 0x7f;
    if (!count) throw new Error("Indefinite DER lengths are unsupported");
    let length = 0;
    for (let index = 0; index < count; index += 1) {
      const value = bytes[offset + 1 + index];
      if (typeof value !== "number") throw new Error("Unexpected end of DER length");
      length = (length << 8) | value;
    }
    return { length, offset: offset + 1 + count };
  }

  function readDer(input, offset = 0) {
    const bytes = ensureUint8Array(input);
    if (offset >= bytes.length) throw new Error("Unexpected end of DER input");
    const tag = bytes[offset];
    const lengthData = readDerLength(bytes, offset + 1);
    const end = lengthData.offset + lengthData.length;
    if (end > bytes.length) throw new Error("Invalid DER length");
    return {
      tag,
      end,
      bytes: bytes.subarray(offset, end),
      valueBytes: bytes.subarray(lengthData.offset, end),
    };
  }

  function readChildren(element) {
    const children = [];
    const bytes = ensureUint8Array(element.valueBytes || element);
    let offset = 0;
    while (offset < bytes.length) {
      const child = readDer(bytes, offset);
      children.push(child);
      offset = child.end;
    }
    return children;
  }

  function readWholeDer(input, expectedTag) {
    const bytes = ensureUint8Array(input);
    const element = readDer(bytes, 0);
    if (element.end !== bytes.length) throw new Error("Trailing DER data is not supported");
    if (typeof expectedTag === "number" && element.tag !== expectedTag) {
      throw new Error(`Unexpected DER tag: 0x${element.tag.toString(16)}`);
    }
    return element;
  }

  function decodeOid(input) {
    const bytes = ensureUint8Array(input);
    if (!bytes.length) return "";
    const firstByte = bytes[0];
    const first = firstByte < 40 ? 0 : firstByte < 80 ? 1 : 2;
    const values = [first, firstByte - (first === 2 ? 80 : first * 40)];
    let current = 0n;
    for (let index = 1; index < bytes.length; index += 1) {
      current = (current << 7n) | BigInt(bytes[index] & 0x7f);
      if ((bytes[index] & 0x80) === 0) {
        values.push(current.toString());
        current = 0n;
      }
    }
    return values.join(".");
  }

  function trimIntegerPadding(input) {
    const bytes = ensureUint8Array(input);
    let index = 0;
    while (index < bytes.length - 1 && bytes[index] === 0) index += 1;
    return bytes.subarray(index);
  }

  function integerBytesToBigInt(input) {
    let value = 0n;
    for (const byte of ensureUint8Array(input)) {
      value = (value << 8n) | BigInt(byte);
    }
    return value;
  }

  function formatIntegerValue(input) {
    const value = integerBytesToBigInt(trimIntegerPadding(input));
    return value > 9n ? `${value.toString()} (0x${value.toString(16)})` : value.toString();
  }

  function computeBitLength(input) {
    const bytes = trimIntegerPadding(input);
    if (!bytes.length) return 0;
    let bitLength = (bytes.length - 1) * 8;
    let firstByte = bytes[0];
    while (firstByte > 0) {
      bitLength += 1;
      firstByte >>= 1;
    }
    return bitLength;
  }

  function formatHex(input, separator = ":", uppercase = false) {
    return Array.from(ensureUint8Array(input), (value) => {
      const hex = value.toString(16).padStart(2, "0");
      return uppercase ? hex.toUpperCase() : hex;
    }).join(separator);
  }

  function formatHexLines(input, bytesPerLine, separator = ":", uppercase = false, trailingSeparator = false) {
    const bytes = ensureUint8Array(input);
    if (!bytes.length) return [];
    const lines = [];
    for (let offset = 0; offset < bytes.length; offset += bytesPerLine) {
      let line = formatHex(bytes.subarray(offset, offset + bytesPerLine), separator, uppercase);
      if (trailingSeparator && offset + bytesPerLine < bytes.length && line) {
        line += separator;
      }
      lines.push(line);
    }
    return lines;
  }

  function formatIpAddress(input) {
    const bytes = ensureUint8Array(input);
    if (bytes.length === 4) return Array.from(bytes).join(".");
    if (bytes.length === 16) {
      const parts = [];
      for (let offset = 0; offset < bytes.length; offset += 2) {
        parts.push(((bytes[offset] << 8) | bytes[offset + 1]).toString(16));
      }
      return parts.join(":");
    }
    return formatHex(bytes, ":", true);
  }

  function formatDirectoryName(input) {
    if (global.x509?.Name) {
      try {
        const name = new global.x509.Name(toArrayBuffer(input));
        return `DirName:${formatDistinguishedName(name.toString())}`;
      } catch (_) {
        // Fall through to hex fallback.
      }
    }
    return `DirName:${formatHex(input, ":", true)}`;
  }

  function parseAlgorithmIdentifier(element) {
    const children = readChildren(element);
    const oid = children[0]?.tag === 0x06 ? decodeOid(children[0].valueBytes) : "";
    return {
      oid,
      name: OID_NAMES[oid] || oid || "未知",
      parameters: children[1] || null,
    };
  }

  function mapWebCryptoAlgorithmToOpenSsl(algorithm) {
    if (!algorithm || typeof algorithm !== "object") return "未知";
    const name = String(algorithm.name || "");
    const hash = String(algorithm.hash?.name || "").replace(/-/g, "");
    if (name === "ECDSA") return hash ? `ecdsa-with-${hash}` : "ecdsa";
    if (name === "RSASSA-PKCS1-v1_5") return hash ? `sha${hash.replace(/^SHA/i, "")}WithRSAEncryption` : "rsaEncryption";
    if (name === "RSA-PSS") return "rsassaPss";
    if (name === "Ed25519" || name === "Ed448") return name.toUpperCase();
    if (name === "ECDH") return "id-ecPublicKey";
    return name || "未知";
  }

  function parseBitStringContent(input) {
    const bytes = ensureUint8Array(input);
    return bytes.length ? bytes.subarray(1) : new Uint8Array();
  }

  function parseCertificateStructure(rawData) {
    const certificate = readWholeDer(rawData, 0x30);
    const certificateChildren = readChildren(certificate);
    if (certificateChildren.length < 3) throw new Error("Invalid certificate structure");

    const tbsCertificate = certificateChildren[0];
    const tbsChildren = readChildren(tbsCertificate);
    let index = 0;
    let version = 1;

    if (tbsChildren[index]?.tag === 0xa0) {
      const versionChildren = readChildren(tbsChildren[index]);
      version = Number(integerBytesToBigInt(versionChildren[0]?.valueBytes || [])) + 1;
      index += 1;
    }

    const serialNumber = trimIntegerPadding(tbsChildren[index]?.valueBytes || []);
    index += 1;
    const signatureAlgorithm = parseAlgorithmIdentifier(tbsChildren[index]);
    index += 4;
    const subjectPublicKeyInfo = tbsChildren[index];

    return {
      version,
      serialNumber,
      signatureAlgorithm,
      outerSignatureAlgorithm: parseAlgorithmIdentifier(certificateChildren[1]),
      signatureValue: parseBitStringContent(certificateChildren[2]?.valueBytes || []),
      subjectPublicKeyInfo,
    };
  }

  function getNamedCurveInfo(curveOid, algorithm) {
    const byOid = CURVE_DETAILS[curveOid];
    if (byOid) return byOid;
    if (algorithm?.namedCurve) {
      return {
        asn1: algorithm.namedCurve,
        nist: algorithm.namedCurve.startsWith("P-") ? algorithm.namedCurve : "",
        bits: CURVE_BITS[algorithm.namedCurve] || 0,
      };
    }
    return { asn1: curveOid || "未知", bits: 0 };
  }

  function parsePublicKeyInfo(element, publicKeyAlgorithm) {
    const children = readChildren(element);
    const algorithm = parseAlgorithmIdentifier(children[0]);
    const publicKeyBytes = parseBitStringContent(children[1]?.valueBytes || []);
    const info = {
      algorithm,
      publicKeyBytes,
      kind: "generic",
      keySizeBits: 0,
    };

    if (algorithm.oid === "1.2.840.10045.2.1") {
      const curveOid = algorithm.parameters?.tag === 0x06 ? decodeOid(algorithm.parameters.valueBytes) : "";
      const curve = getNamedCurveInfo(curveOid, publicKeyAlgorithm);
      info.kind = "ec";
      info.curve = curve;
      info.keySizeBits = curve.bits || CURVE_BITS[publicKeyAlgorithm?.namedCurve] || 0;
      return info;
    }

    if (algorithm.oid === "1.2.840.113549.1.1.1") {
      try {
        const rsaPublicKey = readWholeDer(publicKeyBytes, 0x30);
        const rsaChildren = readChildren(rsaPublicKey);
        info.kind = "rsa";
        info.modulus = trimIntegerPadding(rsaChildren[0]?.valueBytes || []);
        info.exponent = trimIntegerPadding(rsaChildren[1]?.valueBytes || []);
        info.keySizeBits = publicKeyAlgorithm?.modulusLength || computeBitLength(info.modulus);
        return info;
      } catch (_) {
        // Fall through to generic rendering.
      }
    }

    if (algorithm.oid === "1.3.101.112" || algorithm.oid === "1.3.101.113") {
      info.kind = "eddsa";
      info.keySizeBits = CURVE_BITS[algorithm.name] || CURVE_BITS[publicKeyAlgorithm?.name] || publicKeyBytes.length * 8;
      return info;
    }

    info.keySizeBits =
      publicKeyAlgorithm?.modulusLength ||
      CURVE_BITS[publicKeyAlgorithm?.namedCurve] ||
      CURVE_BITS[publicKeyAlgorithm?.name] ||
      publicKeyBytes.length * 8;
    return info;
  }

  function getExtensionValueBytes(extension) {
    if (extension?.value) return ensureUint8Array(extension.value);
    if (!extension?.rawData) return new Uint8Array();
    try {
      const root = readWholeDer(extension.rawData, 0x30);
      const children = readChildren(root);
      return children[2]?.tag === 0x04 ? ensureUint8Array(children[2].valueBytes) : new Uint8Array();
    } catch (_) {
      return new Uint8Array();
    }
  }

  function formatGeneralNameElement(element) {
    switch (element.tag) {
      case 0x81:
        return `email:${decodeText(element.valueBytes)}`;
      case 0x82:
        return `DNS:${decodeText(element.valueBytes)}`;
      case 0x86:
        return `URI:${decodeText(element.valueBytes)}`;
      case 0x87:
        return `IP Address:${formatIpAddress(element.valueBytes)}`;
      case 0x88:
        return `RID:${decodeOid(element.valueBytes)}`;
      case 0xa4:
        return formatDirectoryName(element.valueBytes);
      default:
        return formatHex(element.valueBytes, ":", true);
    }
  }

  function parseGeneralNames(input, assumeContents = false) {
    try {
      const bytes = ensureUint8Array(input);
      const names = assumeContents ? readChildren({ valueBytes: bytes }) : readChildren(readWholeDer(bytes, 0x30));
      return names.map((element) => formatGeneralNameElement(element)).filter(Boolean);
    } catch (_) {
      return [];
    }
  }

  function formatSubjectKeyIdentifier(extension) {
    const value = readWholeDer(getExtensionValueBytes(extension), 0x04);
    return formatHexLines(value.valueBytes, 20, ":", true);
  }

  function formatAuthorityKeyIdentifier(extension) {
    const sequence = readWholeDer(getExtensionValueBytes(extension), 0x30);
    const lines = [];
    const children = readChildren(sequence);
    let onlyKeyId = true;
    for (const child of children) {
      if (child.tag === 0x80) {
        const rendered = formatHexLines(child.valueBytes, 20, ":", true);
        if (!rendered.length) continue;
        if (children.length === 1) lines.push(...rendered);
        else lines.push(`keyid:${rendered[0]}`, ...rendered.slice(1));
        continue;
      }
      onlyKeyId = false;
      if (child.tag === 0xa1) {
        const names = parseGeneralNames(child.valueBytes, true);
        for (const name of names) lines.push(name);
        continue;
      }
      if (child.tag === 0x82) {
        lines.push(`serial:${formatHex(trimIntegerPadding(child.valueBytes), ":", true)}`);
      }
    }
    return onlyKeyId ? lines : lines.map((line, index) => (index === 0 && line.startsWith("keyid:") ? line : line));
  }

  function formatBasicConstraints(extension) {
    const sequence = readWholeDer(getExtensionValueBytes(extension), 0x30);
    const children = readChildren(sequence);
    let offset = 0;
    let isCa = false;
    let pathLength = null;
    if (children[offset]?.tag === 0x01) {
      isCa = children[offset].valueBytes[0] !== 0;
      offset += 1;
    }
    if (children[offset]?.tag === 0x02) {
      pathLength = Number(integerBytesToBigInt(children[offset].valueBytes));
    }
    return [`CA:${isCa ? "TRUE" : "FALSE"}${pathLength === null ? "" : `, pathlen:${pathLength}`}`];
  }

  function formatKeyUsage(extension) {
    const bitString = readWholeDer(getExtensionValueBytes(extension), 0x03);
    const data = parseBitStringContent(bitString.valueBytes);
    const names = KEY_USAGE_NAMES.filter(([bit]) => {
      const byteIndex = Math.floor(bit / 8);
      const bitMask = 0x80 >> (bit % 8);
      return byteIndex < data.length && (data[byteIndex] & bitMask) !== 0;
    }).map(([, label]) => label);
    return [names.join(", ")];
  }

  function formatExtendedKeyUsage(extension) {
    const sequence = readWholeDer(getExtensionValueBytes(extension), 0x30);
    const values = readChildren(sequence)
      .filter((child) => child.tag === 0x06)
      .map((child) => {
        const oid = decodeOid(child.valueBytes);
        return EXTENDED_KEY_USAGE_NAMES[oid] || oid;
      });
    return [values.join(", ")];
  }

  function formatSubjectAlternativeName(extension) {
    return [parseGeneralNames(getExtensionValueBytes(extension)).join(", ")];
  }

  function formatAuthorityInfoAccess(extension) {
    const sequence = readWholeDer(getExtensionValueBytes(extension), 0x30);
    const lines = [];
    for (const child of readChildren(sequence)) {
      const parts = readChildren(child);
      const methodOid = parts[0]?.tag === 0x06 ? decodeOid(parts[0].valueBytes) : "";
      const locationText = parts[1] ? formatGeneralNameElement(parts[1]) : "";
      lines.push(`${ACCESS_METHOD_NAMES[methodOid] || methodOid} - ${locationText}`);
    }
    return lines;
  }

  function formatCertificatePolicies(extension) {
    const sequence = readWholeDer(getExtensionValueBytes(extension), 0x30);
    const lines = [];
    for (const child of readChildren(sequence)) {
      const parts = readChildren(child);
      if (parts[0]?.tag === 0x06) lines.push(`Policy: ${decodeOid(parts[0].valueBytes)}`);
    }
    return lines;
  }

  function formatDistributionPointName(wrapper) {
    const lines = [];
    const inner = readChildren(wrapper)[0];
    if (!inner) return lines;
    if (inner.tag === 0xa0) {
      lines.push("Full Name:");
      for (const name of parseGeneralNames(inner.valueBytes, true)) {
        lines.push(`  ${name}`);
      }
      return lines;
    }
    lines.push(`Distribution Point:${formatHex(inner.valueBytes, ":", true)}`);
    return lines;
  }

  function formatCrlDistributionPoints(extension) {
    const sequence = readWholeDer(getExtensionValueBytes(extension), 0x30);
    const lines = [];
    for (const child of readChildren(sequence)) {
      for (const field of readChildren(child)) {
        if (field.tag === 0xa0) {
          lines.push(...formatDistributionPointName(field));
        } else if (field.tag === 0xa1) {
          lines.push("CRL Issuer:");
          for (const name of parseGeneralNames(field.valueBytes, true)) {
            lines.push(`  ${name}`);
          }
        }
      }
    }
    return lines;
  }

  function formatUnknownExtension(extension) {
    return formatHexLines(getExtensionValueBytes(extension), 18, ":", true);
  }

  function formatExtensionLines(extension) {
    try {
      switch (extension.type) {
        case "1.3.6.1.5.5.7.1.1":
          return formatAuthorityInfoAccess(extension);
        case "2.5.29.14":
          return formatSubjectKeyIdentifier(extension);
        case "2.5.29.15":
          return formatKeyUsage(extension);
        case "2.5.29.17":
        case "2.5.29.18":
          return formatSubjectAlternativeName(extension);
        case "2.5.29.19":
          return formatBasicConstraints(extension);
        case "2.5.29.31":
          return formatCrlDistributionPoints(extension);
        case "2.5.29.32":
          return formatCertificatePolicies(extension);
        case "2.5.29.35":
          return formatAuthorityKeyIdentifier(extension);
        case "2.5.29.37":
          return formatExtendedKeyUsage(extension);
        default:
          return formatUnknownExtension(extension);
      }
    } catch (_) {
      return formatUnknownExtension(extension);
    }
  }

  function buildExtensionSectionLines(extensions) {
    if (!Array.isArray(extensions) || !extensions.length) return [];
    const lines = ["        X509v3 extensions:"];
    for (const extension of extensions) {
      const label = EXTENSION_NAMES[extension.type] ? `X509v3 ${EXTENSION_NAMES[extension.type]}` : extension.type || "Unknown Extension";
      lines.push(`            ${label}:${extension.critical ? " critical" : " "}`);
      const valueLines = formatExtensionLines(extension);
      for (const line of valueLines) {
        lines.push(`                ${line}`);
      }
    }
    return lines;
  }

  function buildPublicKeySectionLines(publicKeyInfo) {
    const lines = [`            Public Key Algorithm: ${publicKeyInfo.algorithm.name}`];

    if (publicKeyInfo.kind === "rsa") {
      lines.push(`                Public-Key: (${publicKeyInfo.keySizeBits} bit)`);
      lines.push("                Modulus:");
      for (const line of formatHexLines(publicKeyInfo.modulus, 15, ":", false, true)) {
        lines.push(`                    ${line}`);
      }
      lines.push(`                Exponent: ${formatIntegerValue(publicKeyInfo.exponent)}`);
      return lines;
    }

    lines.push(`                Public-Key: (${publicKeyInfo.keySizeBits} bit)`);
    lines.push("                pub:");
    for (const line of formatHexLines(publicKeyInfo.publicKeyBytes, 15, ":", false, true)) {
      lines.push(`                    ${line}`);
    }

    if (publicKeyInfo.kind === "ec") {
      lines.push(`                ASN1 OID: ${publicKeyInfo.curve.asn1}`);
      if (publicKeyInfo.curve.nist) lines.push(`                NIST CURVE: ${publicKeyInfo.curve.nist}`);
    }

    return lines;
  }

  function buildOpenSslCertificateText(certificate) {
    const structure = parseCertificateStructure(certificate.rawData);
    const publicKeyInfo = parsePublicKeyInfo(structure.subjectPublicKeyInfo, certificate.publicKey?.algorithm);
    const tbsSignatureAlgorithm = structure.signatureAlgorithm.name || mapWebCryptoAlgorithmToOpenSsl(certificate.signatureAlgorithm);
    const outerSignatureAlgorithm = structure.outerSignatureAlgorithm.name || tbsSignatureAlgorithm;
    const lines = [
      "Certificate:",
      "    Data:",
      `        Version: ${structure.version} (0x${Math.max(structure.version - 1, 0).toString(16)})`,
      "        Serial Number:",
    ];

    for (const line of formatHexLines(structure.serialNumber, 20, ":", false)) {
      lines.push(`            ${line}`);
    }

    lines.push(`        Signature Algorithm: ${tbsSignatureAlgorithm}`);
    lines.push(`        Issuer: ${formatDistinguishedName(certificate.issuer)}`);
    lines.push("        Validity");
    lines.push(`            Not Before: ${formatOpenSslDate(certificate.notBefore)}`);
    lines.push(`            Not After : ${formatOpenSslDate(certificate.notAfter)}`);
    lines.push(`        Subject: ${formatDistinguishedName(certificate.subject)}`);
    lines.push("        Subject Public Key Info:");
    lines.push(...buildPublicKeySectionLines(publicKeyInfo));
    lines.push(...buildExtensionSectionLines(certificate.extensions));
    lines.push(`    Signature Algorithm: ${outerSignatureAlgorithm}`);
    lines.push("    Signature Value:");
    for (const line of formatHexLines(structure.signatureValue, 18, ":", false, true)) {
      lines.push(`        ${line}`);
    }
    return lines.join("\n");
  }

  global.customCertificateText = {
    buildOpenSslCertificateText,
  };
})(typeof globalThis !== "undefined" ? globalThis : self);
