(() => {
  var __defProp = Object.defineProperty;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __esm = (fn, res, err) => function __init() {
    if (err) throw err[0];
    try {
      return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
    } catch (e) {
      throw err = [e], e;
    }
  };
  var __export = (target, all) => {
    for (var name in all)
      __defProp(target, name, { get: all[name], enumerable: true });
  };

  // src/app/ui.js
  function deviceSummary(device) {
    const remoteTag = device.isRemote ? " \xB7 remote" : " \xB7 local";
    if (device.type === "zrdcp-native") {
      return `zrdcp-native \xB7 pubkey ${device.publicKeyHex.slice(0, 12)}\u2026${remoteTag}`;
    }
    return `fido2 \xB7 ${device.participationMode}${device.fido.simulated ? " (simulated)" : ""}${remoteTag}`;
  }
  function formatTimestamp(iso) {
    try {
      return new Date(iso).toLocaleString();
    } catch {
      return iso;
    }
  }
  var el;
  var init_ui = __esm({
    "src/app/ui.js"() {
      el = (tag, props = {}, children = []) => {
        const node = document.createElement(tag);
        Object.assign(node, props);
        for (const child of children) node.append(child);
        return node;
      };
    }
  });

  // src/vault/storage.js
  function createLocalStorageAdapter() {
    if (typeof globalThis.localStorage === "undefined") {
      throw new Error("createLocalStorageAdapter: localStorage is not available in this environment");
    }
    return {
      async getItem(key) {
        return globalThis.localStorage.getItem(key);
      },
      async setItem(key, value) {
        globalThis.localStorage.setItem(key, value);
      },
      async removeItem(key) {
        globalThis.localStorage.removeItem(key);
      }
    };
  }
  var init_storage = __esm({
    "src/vault/storage.js"() {
    }
  });

  // src/vault/vault.js
  function randomBytes(len) {
    return globalThis.crypto.getRandomValues(new Uint8Array(len));
  }
  function toB64(bytes) {
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin);
  }
  function fromB64(str) {
    const bin = atob(str);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  async function deriveKey(passphrase, salt, iterations) {
    const keyMaterial = await SUBTLE.importKey("raw", enc.encode(passphrase), "PBKDF2", false, [
      "deriveKey"
    ]);
    return SUBTLE.deriveKey(
      { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }
  async function seal(passphrase, plaintextObj, iterations = DEFAULT_PBKDF2_ITERATIONS) {
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const key = await deriveKey(passphrase, salt, iterations);
    const plaintext = enc.encode(JSON.stringify(plaintextObj));
    const ciphertextBuf = await SUBTLE.encrypt({ name: "AES-GCM", iv }, key, plaintext);
    return {
      v: 1,
      kdf: "PBKDF2-SHA256",
      iterations,
      salt: toB64(salt),
      iv: toB64(iv),
      ciphertext: toB64(new Uint8Array(ciphertextBuf))
    };
  }
  async function open(passphrase, sealedVault) {
    const salt = fromB64(sealedVault.salt);
    const iv = fromB64(sealedVault.iv);
    const key = await deriveKey(passphrase, salt, sealedVault.iterations);
    try {
      const plaintextBuf = await SUBTLE.decrypt(
        { name: "AES-GCM", iv },
        key,
        fromB64(sealedVault.ciphertext)
      );
      return JSON.parse(dec.decode(plaintextBuf));
    } catch {
      throw new WrongPassphraseOrCorruptVaultError();
    }
  }
  async function deriveKeyFromRawMaterial(keyBytes, salt) {
    const keyMaterial = await SUBTLE.importKey("raw", keyBytes, "HKDF", false, ["deriveKey"]);
    return SUBTLE.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt, info: RAW_KEY_INFO },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }
  function hexToBytesLocal(hex) {
    const clean2 = hex.length % 2 ? "0" + hex : hex;
    const bytes = new Uint8Array(clean2.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean2.slice(i * 2, i * 2 + 2), 16);
    return bytes;
  }
  async function sealWithKey(keyHex, plaintextObj) {
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const key = await deriveKeyFromRawMaterial(hexToBytesLocal(keyHex), salt);
    const plaintext = enc.encode(JSON.stringify(plaintextObj));
    const ciphertextBuf = await SUBTLE.encrypt({ name: "AES-GCM", iv }, key, plaintext);
    return {
      v: 1,
      kdf: "HKDF-SHA256-rawkey",
      salt: toB64(salt),
      iv: toB64(iv),
      ciphertext: toB64(new Uint8Array(ciphertextBuf))
    };
  }
  async function openWithKey(keyHex, sealedVault) {
    const salt = fromB64(sealedVault.salt);
    const iv = fromB64(sealedVault.iv);
    const key = await deriveKeyFromRawMaterial(hexToBytesLocal(keyHex), salt);
    try {
      const plaintextBuf = await SUBTLE.decrypt({ name: "AES-GCM", iv }, key, fromB64(sealedVault.ciphertext));
      return JSON.parse(dec.decode(plaintextBuf));
    } catch {
      throw new WrongPassphraseOrCorruptVaultError();
    }
  }
  var SUBTLE, DEFAULT_PBKDF2_ITERATIONS, enc, dec, WrongPassphraseOrCorruptVaultError, RAW_KEY_INFO;
  var init_vault = __esm({
    "src/vault/vault.js"() {
      SUBTLE = globalThis.crypto.subtle;
      DEFAULT_PBKDF2_ITERATIONS = 21e4;
      enc = new TextEncoder();
      dec = new TextDecoder();
      WrongPassphraseOrCorruptVaultError = class extends Error {
        constructor() {
          super("Wrong passphrase, or the vault data is corrupted/tampered.");
          this.name = "WrongPassphraseOrCorruptVaultError";
        }
      };
      RAW_KEY_INFO = enc.encode("ZRDCP/1.0 IdenTT vault-unlock-key AES-GCM");
    }
  });

  // src/registry/schema.js
  function assert(condition, message) {
    if (!condition) throw new RegistryValidationError(message);
  }
  function nowIso() {
    return (/* @__PURE__ */ new Date()).toISOString();
  }
  function makeId(prefix = "dev") {
    idCounter += 1;
    const rand = globalThis.crypto.getRandomValues(new Uint8Array(8));
    const randHex = Array.from(rand, (b) => b.toString(16).padStart(2, "0")).join("");
    return `${prefix}_${Date.now().toString(36)}_${idCounter}_${randHex}`;
  }
  function validateContactChannel(channel) {
    assert(channel && typeof channel === "object", "contact channel must be an object");
    assert(
      Object.values(CONTACT_KINDS).includes(channel.kind),
      `contact channel kind must be one of: ${Object.values(CONTACT_KINDS).join(", ")}`
    );
    assert(typeof channel.address === "string" && channel.address.length > 0, "contact channel address is required");
  }
  function createZrdcpNativeDevice({ name, contactChannels, publicKeyHex, isRemote = false }) {
    assert(typeof name === "string" && name.trim().length > 0, "device name is required");
    assert(Array.isArray(contactChannels) && contactChannels.length > 0, "at least one contact channel is required");
    contactChannels.forEach(validateContactChannel);
    assert(typeof publicKeyHex === "string" && /^[0-9a-fA-F]+$/.test(publicKeyHex), "publicKeyHex must be a hex string");
    return {
      id: makeId("zrdcp"),
      type: DEVICE_TYPES.ZRDCP_NATIVE,
      name: name.trim(),
      contactChannels,
      publicKeyHex,
      isRemote: Boolean(isRemote),
      createdAt: nowIso(),
      updatedAt: nowIso()
    };
  }
  function createFidoDevice({ name, contactChannels, credential, isRemote = false }) {
    assert(typeof name === "string" && name.trim().length > 0, "device name is required");
    assert(Array.isArray(contactChannels) && contactChannels.length > 0, "at least one contact channel is required");
    contactChannels.forEach(validateContactChannel);
    assert(credential && typeof credential.credentialId === "string", "credential.credentialId is required");
    assert(credential.publicKeyJwk && typeof credential.publicKeyJwk === "object", "credential.publicKeyJwk is required");
    assert(typeof credential.prfSupported === "boolean", "credential.prfSupported must be boolean");
    const participationMode = credential.prfSupported ? PARTICIPATION_MODES.FULL_SHARE : PARTICIPATION_MODES.APPROVAL_ONLY;
    if (participationMode === PARTICIPATION_MODES.FULL_SHARE) {
      assert(
        typeof credential.derivedPublicKeyHex === "string" && credential.derivedPublicKeyHex.length > 0,
        "a PRF-capable credential must include derivedPublicKeyHex (see src/fido/simulate.js)"
      );
    }
    return {
      id: makeId("fido"),
      type: DEVICE_TYPES.FIDO2,
      name: name.trim(),
      contactChannels,
      fido: {
        credentialId: credential.credentialId,
        publicKeyJwk: credential.publicKeyJwk,
        prfSupported: credential.prfSupported,
        // ECDH-capable public key derived from this device's PRF output (see
        // src/fido/simulate.js's module comment for the full mechanism) — null for approval-only
        // devices, which never hold share math and so never need one.
        derivedPublicKeyHex: credential.derivedPublicKeyHex ?? null,
        transports: credential.transports ?? [],
        simulated: credential.simulated ?? false
      },
      participationMode,
      isRemote: Boolean(isRemote),
      createdAt: nowIso(),
      updatedAt: nowIso()
    };
  }
  var DEVICE_TYPES, PARTICIPATION_MODES, CONTACT_KINDS, RegistryValidationError, idCounter;
  var init_schema = __esm({
    "src/registry/schema.js"() {
      DEVICE_TYPES = Object.freeze({
        ZRDCP_NATIVE: "zrdcp-native",
        FIDO2: "fido2"
      });
      PARTICIPATION_MODES = Object.freeze({
        FULL_SHARE: "full-share",
        APPROVAL_ONLY: "approval-only"
      });
      CONTACT_KINDS = Object.freeze({
        EMAIL: "email",
        SMS: "sms",
        VOICE: "voice",
        WEBAPI: "webapi",
        RESPONDER_LINK: "responder-link"
      });
      RegistryValidationError = class extends Error {
        constructor(message) {
          super(message);
          this.name = "RegistryValidationError";
        }
      };
      idCounter = 0;
    }
  });

  // src/registry/registry.js
  function createRegistry({ targetN = 6, kAuthentication = 2, kRecovery = 3, minRemoteForRecovery = 1 } = {}) {
    const threshold = { targetN, kAuthentication, kRecovery, minRemoteForRecovery };
    validateThreshold(threshold);
    return {
      version: CURRENT_VERSION,
      threshold,
      devices: [],
      updatedAt: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
  function validateThreshold({ targetN, kAuthentication, kRecovery, minRemoteForRecovery }) {
    if (!Number.isInteger(targetN) || targetN < MIN_TARGET_N || targetN > MAX_TARGET_N) {
      throw new RegistryValidationError(
        `targetN must be an integer greater than 3 and less than 10 (i.e. ${MIN_TARGET_N}-${MAX_TARGET_N}); got ${targetN}`
      );
    }
    if (!Number.isInteger(kAuthentication) || kAuthentication < 2) {
      throw new RegistryValidationError("kAuthentication must be an integer >= 2");
    }
    if (!Number.isInteger(kRecovery) || kRecovery < 3) {
      throw new RegistryValidationError("kRecovery must be an integer >= 3");
    }
    if (kAuthentication > targetN) {
      throw new RegistryValidationError(`kAuthentication (${kAuthentication}) cannot exceed targetN (${targetN})`);
    }
    if (kRecovery > targetN) {
      throw new RegistryValidationError(`kRecovery (${kRecovery}) cannot exceed targetN (${targetN})`);
    }
    if (!Number.isInteger(minRemoteForRecovery) || minRemoteForRecovery < 1) {
      throw new RegistryValidationError("minRemoteForRecovery must be an integer >= 1");
    }
    if (minRemoteForRecovery > kRecovery) {
      throw new RegistryValidationError(
        `minRemoteForRecovery (${minRemoteForRecovery}) cannot exceed kRecovery (${kRecovery})`
      );
    }
  }
  function touch(registry) {
    return { ...registry, updatedAt: (/* @__PURE__ */ new Date()).toISOString() };
  }
  function addDevice(registry, device) {
    if (registry.devices.length >= MAX_DEVICES) {
      throw new RegistryValidationError(
        `this mesh already has the maximum of ${MAX_DEVICES} trusted devices \u2014 remove one before adding another`
      );
    }
    const nameCollision = registry.devices.some(
      (d) => d.name.toLowerCase() === device.name.toLowerCase()
    );
    if (nameCollision) {
      throw new RegistryValidationError(`a device named "${device.name}" already exists`);
    }
    return touch({ ...registry, devices: [...registry.devices, device] });
  }
  function removeDevice(registry, deviceId) {
    const exists = registry.devices.some((d) => d.id === deviceId);
    if (!exists) {
      throw new RegistryValidationError(`no device with id ${deviceId}`);
    }
    return touch({ ...registry, devices: registry.devices.filter((d) => d.id !== deviceId) });
  }
  function setThreshold(registry, patch) {
    const next = { ...registry.threshold, ...patch };
    validateThreshold(next);
    return touch({ ...registry, threshold: next });
  }
  function shareHoldingDeviceCount(registry) {
    return shareHoldingDevices(registry).length;
  }
  function shareHoldingDevices(registry) {
    return registry.devices.filter(
      (d) => d.type === "zrdcp-native" || d.participationMode === "full-share"
    );
  }
  function remoteShareHoldingDevices(registry) {
    return shareHoldingDevices(registry).filter((d) => d.isRemote);
  }
  function ecdhPublicKeyForDevice(device) {
    if (device.type === "zrdcp-native") return device.publicKeyHex;
    if (device.type === "fido2" && device.participationMode === "full-share") {
      return device.fido.derivedPublicKeyHex;
    }
    throw new RegistryValidationError(
      `device ${device.id} (${device.name}) is not share-holding \u2014 it has no ECDH-capable public key`
    );
  }
  function registryWarnings(registry) {
    const warnings = [];
    const { targetN, kAuthentication, kRecovery, minRemoteForRecovery } = registry.threshold;
    const enrolled = registry.devices.length;
    const holders = shareHoldingDevices(registry);
    const remoteHolders = remoteShareHoldingDevices(registry);
    if (enrolled < targetN) {
      warnings.push(`${enrolled} of ${targetN} target trusted devices enrolled.`);
    }
    if (enrolled > 0 && enrolled < MIN_TARGET_N) {
      warnings.push(`A valid mesh needs at least ${MIN_TARGET_N} trusted devices \u2014 currently ${enrolled}.`);
    }
    if (enrolled > 0 && enrolled < kAuthentication) {
      warnings.push(
        `Only ${enrolled} device(s) enrolled, but authentication requires ${kAuthentication} approvals \u2014 authentication would be impossible.`
      );
    }
    if (enrolled > 0 && holders.length < kRecovery) {
      warnings.push(
        `Only ${holders.length} enrolled device(s) can hold a real share, but recovery requires ${kRecovery} \u2014 recovery would be impossible even with full approval. Add more zrdcp-native or PRF-capable FIDO2 devices, or lower kRecovery.`
      );
    }
    if (enrolled > 0 && holders.length >= kRecovery && remoteHolders.length < minRemoteForRecovery) {
      warnings.push(
        `Recovery requires at least ${minRemoteForRecovery} remote share-holding device(s), but only ${remoteHolders.length} enrolled/flagged as remote \u2014 recovery would be impossible even with enough approvals.`
      );
    }
    return warnings;
  }
  var CURRENT_VERSION, MAX_DEVICES, MIN_TARGET_N, MAX_TARGET_N;
  var init_registry = __esm({
    "src/registry/registry.js"() {
      init_schema();
      CURRENT_VERSION = 2;
      MAX_DEVICES = 9;
      MIN_TARGET_N = 4;
      MAX_TARGET_N = 9;
    }
  });

  // node_modules/@noble/hashes/_u64.js
  function fromBig(n, le = false) {
    if (le)
      return { h: Number(n & U32_MASK64), l: Number(n >> _32n & U32_MASK64) };
    return { h: Number(n >> _32n & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
  }
  function split(lst, le = false) {
    const len = lst.length;
    let Ah = new Uint32Array(len);
    let Al = new Uint32Array(len);
    for (let i = 0; i < len; i++) {
      const { h, l } = fromBig(lst[i], le);
      [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
  }
  function setU64FromNum(view, byteOffset, n, isLE2) {
    const h = fromNumH(n);
    const l = fromNumL(n);
    view.setUint32(byteOffset, isLE2 ? l : h, isLE2);
    view.setUint32(byteOffset + 4, isLE2 ? h : l, isLE2);
  }
  var U32_MASK64, _32n, fromNumH, fromNumL;
  var init_u64 = __esm({
    "node_modules/@noble/hashes/_u64.js"() {
      U32_MASK64 = /* @__PURE__ */ (() => BigInt(2 ** 32 - 1))();
      _32n = /* @__PURE__ */ BigInt(32);
      fromNumH = (n) => n / 2 ** 32 | 0;
      fromNumL = (n) => n >>> 0;
    }
  });

  // node_modules/@noble/hashes/utils.js
  function isBytes(a) {
    return a instanceof Uint8Array || ArrayBuffer.isView(a) && a.constructor.name === "Uint8Array" && "BYTES_PER_ELEMENT" in a && a.BYTES_PER_ELEMENT === 1;
  }
  function anumber(n, title = "") {
    if (typeof n !== "number")
      throw new TypeError(atitle(title) + "expected number, got " + typeof n);
    if (!Number.isSafeInteger(n) || n < 0)
      throw new RangeError(atitle(title) + "expected integer >= 0, got " + n);
    return n;
  }
  function abool(value, title = "") {
    if (typeof value !== "boolean")
      throw new TypeError(atitle(title) + "expected boolean, got type=" + typeof value);
    return value;
  }
  function abytes(value, length, title = "") {
    if (isBytes(value) && (length === void 0 || value.length === length))
      return value;
    if (length !== void 0)
      anumber(length, "length");
    const bytes = isBytes(value);
    const ofLen = length !== void 0 ? ` of length ${length}` : "";
    const got = bytes ? `length=${value.length}` : `type=${typeof value}`;
    const message = atitle(title) + "expected Uint8Array" + ofLen + ", got " + got;
    if (!bytes)
      throw new TypeError(message);
    throw new RangeError(message);
  }
  function ahash(h) {
    if (typeof h !== "function" || typeof h.create !== "function")
      throw new TypeError("expected hash wrapped by utils.createHasher");
    anumber(h.outputLen);
    anumber(h.blockLen);
    if (h.outputLen < 1 || h.blockLen < 1)
      throw new Error("hash blockLen / outputLen must be >= 1");
  }
  function aexists(instance, checkFinished = true) {
    if (instance.destroyed)
      throw new Error("hash was destroyed");
    if (checkFinished && instance.finished)
      throw new Error("digest() was already called");
  }
  function aoutput(out, instance) {
    abytes(out, void 0, "output");
    const min = instance.outputLen;
    if (!(out.length >= min)) {
      throw new RangeError('"output" expected length >= ' + min);
    }
  }
  function u32(arr) {
    return new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
  }
  function clean(...arrays) {
    for (let i = 0; i < arrays.length; i++) {
      arrays[i].fill(0);
    }
  }
  function createView(arr) {
    return new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
  }
  function rotr(word, shift) {
    return word << 32 - shift | word >>> shift;
  }
  function byteSwap(word) {
    return word << 24 & 4278190080 | word << 8 & 16711680 | word >>> 8 & 65280 | word >>> 24 & 255;
  }
  function byteSwap32(arr) {
    for (let i = 0; i < arr.length; i++) {
      arr[i] = byteSwap(arr[i]);
    }
    return arr;
  }
  function bytesToHex(bytes) {
    abytes(bytes);
    if (hasHexBuiltin)
      return bytes.toHex();
    let hex = "";
    for (let i = 0; i < bytes.length; i++) {
      hex += hexes[bytes[i]];
    }
    return hex;
  }
  function asciiToBase16(ch) {
    return ch >= 48 && ch <= 57 ? ch - 48 : ch >= 65 && ch <= 70 ? ch - (65 - 10) : ch >= 97 && ch <= 102 ? ch - (97 - 10) : void 0;
  }
  function hexToBytes(hex) {
    if (typeof hex !== "string")
      throw new TypeError("hex string expected, got " + typeof hex);
    if (hasHexBuiltin) {
      try {
        return Uint8Array.fromHex(hex);
      } catch (error) {
        if (error instanceof SyntaxError)
          throw new RangeError(error.message);
        throw error;
      }
    }
    const hl = hex.length;
    const al = hl / 2;
    if (hl % 2)
      throw new RangeError("hex string expected, got unpadded hex of length " + hl);
    const array = new Uint8Array(al);
    for (let ai = 0, hi = 0; ai < al; ai++, hi += 2) {
      const n1 = asciiToBase16(hex.charCodeAt(hi));
      const n2 = asciiToBase16(hex.charCodeAt(hi + 1));
      if (n1 === void 0 || n2 === void 0) {
        const char = hex[hi] + hex[hi + 1];
        throw new RangeError('hex string expected, got non-hex character "' + char + '" at index ' + hi);
      }
      array[ai] = n1 * 16 + n2;
    }
    return array;
  }
  function concatBytes(...arrays) {
    let sum = 0;
    for (let i = 0; i < arrays.length; i++) {
      const a = arrays[i];
      abytes(a);
      sum += a.length;
    }
    const res = new Uint8Array(sum);
    for (let i = 0, pad = 0; i < arrays.length; i++) {
      const a = arrays[i];
      res.set(a, pad);
      pad += a.length;
    }
    return res;
  }
  function checkOpts(defaults, opts, title = "opts") {
    aobject(defaults, "defaults");
    if (opts !== void 0)
      aobject(opts, title);
    const merged = Object.assign(defaults, opts);
    return merged;
  }
  function createHasher(hashCons, info = {}) {
    if (typeof hashCons !== "function")
      throw new TypeError('"hashCons" expected function, got type=' + typeof hashCons);
    info = checkOpts({}, info, "info");
    const hashC = (msg, opts) => hashCons(opts).update(msg).digest();
    const tmp = hashCons(void 0);
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.canXOF = tmp.canXOF;
    hashC.create = (opts) => hashCons(opts);
    Object.assign(hashC, info);
    return Object.freeze(hashC);
  }
  function randomBytes2(bytesLength = 32) {
    anumber(bytesLength, "bytesLength");
    const cr = typeof globalThis === "object" ? globalThis.crypto : null;
    if (typeof cr?.getRandomValues !== "function")
      throw new Error("crypto.getRandomValues must be defined");
    if (bytesLength > 65536)
      throw new RangeError(`"bytesLength" expected <= 65536, got ${bytesLength}`);
    return cr.getRandomValues(new Uint8Array(bytesLength));
  }
  var atitle, aobject, isLE, swap32IfBE, hasHexBuiltin, hexes, oidNist;
  var init_utils = __esm({
    "node_modules/@noble/hashes/utils.js"() {
      atitle = (title) => title ? `"${title}" ` : "";
      aobject = (value, label) => {
        if (value === null || typeof value !== "object" || Array.isArray(value))
          throw new TypeError((label === "object" ? "" : `"${label}" `) + "expected object, got type=" + typeof value);
      };
      isLE = /* @__PURE__ */ (() => new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68)();
      swap32IfBE = isLE ? (u) => u : byteSwap32;
      hasHexBuiltin = /* @__PURE__ */ (() => (
        // @ts-ignore
        typeof Uint8Array.from([]).toHex === "function" && typeof Uint8Array.fromHex === "function"
      ))();
      hexes = /* @__PURE__ */ Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, "0"));
      oidNist = (suffix) => ({
        // Current NIST hashAlgs suffixes used here fit in one DER subidentifier octet.
        // Larger suffix values would need base-128 OID encoding and a different length byte.
        oid: Uint8Array.from([6, 9, 96, 134, 72, 1, 101, 3, 4, 2, suffix])
      });
    }
  });

  // node_modules/@noble/hashes/_md.js
  function Chi(a, b, c) {
    return a & b ^ ~a & c;
  }
  function Maj(a, b, c) {
    return a & b ^ a & c ^ b & c;
  }
  var HashMD, SHA256_IV;
  var init_md = __esm({
    "node_modules/@noble/hashes/_md.js"() {
      init_u64();
      init_utils();
      HashMD = class {
        blockLen;
        outputLen;
        canXOF = false;
        padOffset;
        isLE;
        // For partial updates less than block size
        buffer;
        view;
        finished = false;
        length = 0;
        pos = 0;
        destroyed = false;
        constructor(blockLen, outputLen, padOffset, isLE2) {
          this.blockLen = blockLen;
          this.outputLen = outputLen;
          this.padOffset = padOffset;
          this.isLE = isLE2;
          this.buffer = new Uint8Array(blockLen);
          this.view = createView(this.buffer);
        }
        update(data) {
          aexists(this);
          abytes(data);
          const { view, buffer, blockLen } = this;
          const len = data.length;
          let processed = false;
          for (let pos = 0; pos < len; ) {
            const take = Math.min(blockLen - this.pos, len - pos);
            if (take === blockLen) {
              const dataView = createView(data);
              for (; blockLen <= len - pos; pos += blockLen)
                this.process(dataView, pos);
              processed = true;
              continue;
            }
            buffer.set(pos === 0 && take === len ? data : data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
              this.process(view, 0);
              this.pos = 0;
              processed = true;
            }
          }
          this.length += data.length;
          if (processed)
            this.roundClean();
          return this;
        }
        digestInto(out) {
          aexists(this);
          aoutput(out, this);
          this.finished = true;
          const { buffer, view, blockLen, isLE: isLE2 } = this;
          let { pos } = this;
          buffer[pos++] = 128;
          buffer.fill(0, pos);
          if (this.padOffset > blockLen - pos) {
            this.process(view, 0);
            buffer.fill(0);
          }
          setU64FromNum(view, blockLen - 8, this.length * 8, isLE2);
          this.process(view, 0);
          this.roundClean();
          const oview = out === buffer ? view : createView(out);
          const len = this.outputLen;
          const outLen = len / 4;
          const state = this.get();
          if (len % 4 || outLen > state.length)
            throw new Error("invalid outputLen");
          for (let i = 0; i < outLen; i++)
            oview.setUint32(4 * i, state[i], isLE2);
        }
        digest() {
          const { buffer, outputLen } = this;
          this.digestInto(buffer);
          const res = buffer.slice(0, outputLen);
          this.destroy();
          return res;
        }
        _cloneIntoMeta(to) {
          const { buffer, length, finished, destroyed, pos } = this;
          to.destroyed = destroyed;
          to.finished = finished;
          to.length = length;
          to.pos = pos;
          if (pos)
            to.buffer.set(buffer);
          return to;
        }
        clone() {
          return this._cloneInto();
        }
      };
      SHA256_IV = /* @__PURE__ */ Uint32Array.from([
        1779033703,
        3144134277,
        1013904242,
        2773480762,
        1359893119,
        2600822924,
        528734635,
        1541459225
      ]);
    }
  });

  // node_modules/@noble/hashes/sha2.js
  var SHA256_K, SHA256_W, SHA2_32B, _SHA256, sha256;
  var init_sha2 = __esm({
    "node_modules/@noble/hashes/sha2.js"() {
      init_md();
      init_utils();
      SHA256_K = /* @__PURE__ */ Uint32Array.from([
        1116352408,
        1899447441,
        3049323471,
        3921009573,
        961987163,
        1508970993,
        2453635748,
        2870763221,
        3624381080,
        310598401,
        607225278,
        1426881987,
        1925078388,
        2162078206,
        2614888103,
        3248222580,
        3835390401,
        4022224774,
        264347078,
        604807628,
        770255983,
        1249150122,
        1555081692,
        1996064986,
        2554220882,
        2821834349,
        2952996808,
        3210313671,
        3336571891,
        3584528711,
        113926993,
        338241895,
        666307205,
        773529912,
        1294757372,
        1396182291,
        1695183700,
        1986661051,
        2177026350,
        2456956037,
        2730485921,
        2820302411,
        3259730800,
        3345764771,
        3516065817,
        3600352804,
        4094571909,
        275423344,
        430227734,
        506948616,
        659060556,
        883997877,
        958139571,
        1322822218,
        1537002063,
        1747873779,
        1955562222,
        2024104815,
        2227730452,
        2361852424,
        2428436474,
        2756734187,
        3204031479,
        3329325298
      ]);
      SHA256_W = /* @__PURE__ */ new Uint32Array(64);
      SHA2_32B = class extends HashMD {
        // We cannot use array here since array allows indexing by variable
        // which means optimizer/compiler cannot use registers.
        // Numeric initializers matter: starting the fields as `undefined` changes
        // V8's field representation and makes sha256 3x slower (measured).
        A = 0;
        B = 0;
        C = 0;
        D = 0;
        E = 0;
        F = 0;
        G = 0;
        H = 0;
        constructor(outputLen, IV) {
          super(64, outputLen, 8, false);
          this.A = IV[0] | 0;
          this.B = IV[1] | 0;
          this.C = IV[2] | 0;
          this.D = IV[3] | 0;
          this.E = IV[4] | 0;
          this.F = IV[5] | 0;
          this.G = IV[6] | 0;
          this.H = IV[7] | 0;
        }
        get() {
          const { A, B: B2, C, D, E, F, G: G2, H: H3 } = this;
          return [A, B2, C, D, E, F, G2, H3];
        }
        // prettier-ignore
        set(A, B2, C, D, E, F, G2, H3) {
          this.A = A | 0;
          this.B = B2 | 0;
          this.C = C | 0;
          this.D = D | 0;
          this.E = E | 0;
          this.F = F | 0;
          this.G = G2 | 0;
          this.H = H3 | 0;
        }
        _cloneInto(to) {
          (to ||= new this.constructor()).set(...this.get());
          return this._cloneIntoMeta(to);
        }
        process(view, offset) {
          for (let i = 0; i < 16; i++, offset += 4)
            SHA256_W[i] = view.getUint32(offset, false);
          for (let i = 16; i < 64; i++) {
            const W15 = SHA256_W[i - 15];
            const W2 = SHA256_W[i - 2];
            const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ W15 >>> 3;
            const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ W2 >>> 10;
            SHA256_W[i] = s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16] | 0;
          }
          let { A, B: B2, C, D, E, F, G: G2, H: H3 } = this;
          for (let i = 0; i < 64; i++) {
            const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
            const T1 = H3 + sigma1 + Chi(E, F, G2) + SHA256_K[i] + SHA256_W[i] | 0;
            const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
            const T2 = sigma0 + Maj(A, B2, C) | 0;
            H3 = G2;
            G2 = F;
            F = E;
            E = D + T1 | 0;
            D = C;
            C = B2;
            B2 = A;
            A = T1 + T2 | 0;
          }
          A = A + this.A | 0;
          B2 = B2 + this.B | 0;
          C = C + this.C | 0;
          D = D + this.D | 0;
          E = E + this.E | 0;
          F = F + this.F | 0;
          G2 = G2 + this.G | 0;
          H3 = H3 + this.H | 0;
          this.set(A, B2, C, D, E, F, G2, H3);
        }
        roundClean() {
          clean(SHA256_W);
        }
        destroy() {
          this.destroyed = true;
          this.set(0, 0, 0, 0, 0, 0, 0, 0);
          clean(this.buffer);
        }
      };
      _SHA256 = class extends SHA2_32B {
        constructor() {
          super(32, SHA256_IV);
        }
      };
      sha256 = /* @__PURE__ */ createHasher(
        () => new _SHA256(),
        /* @__PURE__ */ oidNist(1)
      );
    }
  });

  // node_modules/@noble/curves/utils.js
  function aarray(item, title, inner = () => {
  }) {
    if (!Array.isArray(item))
      throw new TypeError(`"${title}" expected array, got type=${typeof item}`);
    for (let i = 0; i < item.length; i++)
      inner(item[i], `${title}[${i}]`);
    return item;
  }
  function astring(value, title = "") {
    if (typeof value !== "string") {
      const prefix = title && `"${title}" `;
      throw new TypeError(prefix + "expected string, got type=" + typeof value);
    }
    return value;
  }
  function aobject2(value, title = "object") {
    if (value === null || typeof value !== "object" || Array.isArray(value))
      throw new TypeError(title === "object" ? "expected valid options object" : `"${title}" expected object, got type=${typeof value}`);
    return value;
  }
  function afunction(value, title) {
    if (typeof value !== "function")
      throw new TypeError(`"${title}" is invalid: expected function, got ${typeof value}`);
    return value;
  }
  function abool2(value, title = "") {
    if (typeof value !== "boolean")
      throw new TypeError(atitle2(title) + "expected boolean, got type=" + typeof value);
    return value;
  }
  function abignumber(n) {
    if (typeof n === "bigint") {
      if (!isPosBig(n))
        throw new RangeError("positive bigint expected, got " + n);
    } else
      anumber2(n);
    return n;
  }
  function asafenumber(value, title = "") {
    if (typeof value !== "number") {
      const prefix = title && `"${title}" `;
      throw new TypeError(prefix + "expected number, got type=" + typeof value);
    }
    if (!Number.isSafeInteger(value)) {
      const prefix = title && `"${title}" `;
      throw new RangeError(prefix + "expected safe integer, got " + value);
    }
  }
  function numberToHexUnpadded(num) {
    const hex = abignumber(num).toString(16);
    return hex.length & 1 ? "0" + hex : hex;
  }
  function hexToNumber(hex) {
    if (typeof hex !== "string")
      throw new TypeError("hex string expected, got " + typeof hex);
    return hex === "" ? _0n : BigInt("0x" + hex);
  }
  function bytesToNumberBE(bytes) {
    return hexToNumber(bytesToHex(bytes));
  }
  function bytesToNumberLE(bytes) {
    return hexToNumber(bytesToHex(copyBytes(abytes(bytes)).reverse()));
  }
  function numberToBytesBE(n, len) {
    anumber(len);
    if (len === 0)
      throw new Error("zero output length is invalid");
    n = abignumber(n);
    const expectedLen = len * 2;
    const hex = n.toString(16);
    if (hex.length > expectedLen)
      throw new RangeError("number is too large");
    return hexToBytes(hex.padStart(expectedLen, "0"));
  }
  function numberToBytesLE(n, len) {
    return numberToBytesBE(n, len).reverse();
  }
  function copyBytes(bytes) {
    return Uint8Array.from(abytes2(bytes));
  }
  function asciiToBytes(ascii) {
    if (typeof ascii !== "string")
      throw new TypeError("ascii string expected, got " + typeof ascii);
    return Uint8Array.from(ascii, (c, i) => {
      const charCode = c.charCodeAt(0);
      if (c.length !== 1 || charCode > 127) {
        throw new RangeError(`string contains non-ASCII character "${ascii[i]}" with code ${charCode} at position ${i}`);
      }
      return charCode;
    });
  }
  function isPosBig(n) {
    return typeof n === "bigint" && _0n <= n;
  }
  function inRange(n, min, max) {
    return isPosBig(n) && isPosBig(min) && isPosBig(max) && min <= n && n < max;
  }
  function aInRange(title, n, min, max) {
    if (!inRange(n, min, max))
      throw new RangeError("expected valid " + title + ": " + min + " <= n < " + max + ", got " + n);
  }
  function bitLen(n) {
    if (n < _0n)
      throw new Error("expected non-negative bigint, got " + n);
    return n === _0n ? 0 : n.toString(2).length;
  }
  function createHmacDrbg(hashLen, qByteLen, hmacFn) {
    anumber(hashLen, "hashLen");
    anumber(qByteLen, "qByteLen");
    if (typeof hmacFn !== "function")
      throw new TypeError("hmacFn must be a function");
    const u8n = (len) => new Uint8Array(len);
    const NULL = Uint8Array.of();
    const byte0 = Uint8Array.of(0);
    const byte1 = Uint8Array.of(1);
    const _maxDrbgIters = 1e3;
    let v = u8n(hashLen);
    let k = u8n(hashLen);
    let i = 0;
    const reset = () => {
      v.fill(1);
      k.fill(0);
      i = 0;
    };
    const h = (...msgs) => hmacFn(k, concatBytes2(v, ...msgs));
    const reseed = (seed = NULL) => {
      k = h(byte0, seed);
      v = h();
      if (seed.length === 0)
        return;
      k = h(byte1, seed);
      v = h();
    };
    const gen = () => {
      if (i++ >= _maxDrbgIters)
        throw new Error("drbg: tried max amount of iterations");
      let len = 0;
      const out = [];
      while (len < qByteLen) {
        v = h();
        const sl = v.slice();
        out.push(sl);
        len += v.length;
      }
      return concatBytes2(...out);
    };
    const genUntil = (seed, pred) => {
      reset();
      reseed(seed);
      let res = void 0;
      while ((res = pred(gen())) === void 0)
        reseed();
      reset();
      return res;
    };
    return genUntil;
  }
  function validateObject(object, fields = {}, optFields = {}, title = "object") {
    aobject2(object, title);
    aobject2(fields, "fields");
    aobject2(optFields, "optFields");
    function checkField(fieldName, expectedType, isOpt) {
      const label = title === "object" ? `param "${String(fieldName)}"` : `"${title}.${String(fieldName)}"`;
      const val = object[fieldName];
      if (!Object.hasOwn(object, fieldName) && (isOpt ? val !== void 0 : expectedType !== "function")) {
        throw new TypeError(`${label} is invalid: expected own property`);
      }
      if (isOpt && val === void 0)
        return;
      const current = typeof val;
      if (current !== expectedType || val === null)
        throw new TypeError(`${label} is invalid: expected ${expectedType}, got ${current}`);
    }
    const iter = (f, isOpt) => Object.entries(f).forEach(([k, v]) => checkField(k, v, isOpt));
    iter(fields, false);
    iter(optFields, true);
  }
  var abytes2, anumber2, bytesToHex2, concatBytes2, hexToBytes2, isBytes2, randomBytes3, _0n, _1n, atitle2, bitMask;
  var init_utils2 = __esm({
    "node_modules/@noble/curves/utils.js"() {
      init_utils();
      abytes2 = (value, length, title) => abytes(value, length, title);
      anumber2 = anumber;
      bytesToHex2 = bytesToHex;
      concatBytes2 = (...arrays) => concatBytes(...arrays);
      hexToBytes2 = (hex) => hexToBytes(hex);
      isBytes2 = isBytes;
      randomBytes3 = (bytesLength) => randomBytes2(bytesLength);
      _0n = /* @__PURE__ */ BigInt(0);
      _1n = /* @__PURE__ */ BigInt(1);
      atitle2 = (title) => title ? `"${title}" ` : "";
      bitMask = (n) => {
        asafenumber(n, "n");
        return (_1n << BigInt(n)) - _1n;
      };
    }
  });

  // node_modules/@noble/curves/abstract/modular.js
  function mod(a, b) {
    if (b <= _0n2)
      throw new Error("mod: expected positive modulus, got " + b);
    const result = a % b;
    return result >= _0n2 ? result : b + result;
  }
  function pow(num, power, modulo) {
    if (modulo <= _1n2)
      throw new Error("pow: expected modulus > 1, got " + modulo);
    if (typeof power !== "bigint")
      throw new TypeError("invalid exponent: expected bigint, got " + typeof power);
    if (power < _0n2)
      throw new Error("invalid exponent, negatives unsupported");
    if (power === _0n2)
      return _1n2;
    if (power === _1n2)
      return num;
    let d = num % modulo;
    if (d < _0n2)
      d += modulo;
    if (power < POW_WINDOWED_MIN) {
      let p2 = _1n2;
      while (power > _0n2) {
        if (power & _1n2)
          p2 = p2 * d % modulo;
        d = d * d % modulo;
        power >>= _1n2;
      }
      return p2;
    }
    const digits = [];
    while (power > _0n2) {
      digits.push(Number(power & _15n));
      power >>= _4n;
    }
    const table = new Array(16);
    table[0] = _1n2;
    table[1] = d;
    for (let i = 2; i < 16; i++)
      table[i] = table[i - 1] * d % modulo;
    let p = table[digits[digits.length - 1]];
    for (let w = digits.length - 2; w >= 0; w--) {
      p = p * p % modulo;
      p = p * p % modulo;
      p = p * p % modulo;
      p = p * p % modulo;
      const digit = digits[w];
      if (digit !== 0)
        p = p * table[digit] % modulo;
    }
    return p;
  }
  function pow2(x, power, modulo) {
    if (modulo <= _1n2)
      throw new Error("pow2: expected modulus > 1, got " + modulo);
    if (power < _0n2)
      throw new Error("pow2: expected non-negative exponent, got " + power);
    let res = x;
    while (power-- > _0n2) {
      res *= res;
      res %= modulo;
    }
    return res;
  }
  function invert(number, modulo) {
    if (number === _0n2)
      throw new Error("invert: expected non-zero number");
    if (modulo <= _1n2)
      throw new Error("invert: expected modulus > 1, got " + modulo);
    let a = mod(number, modulo);
    let b = modulo;
    let x = _0n2, u = _1n2;
    while (a !== _0n2) {
      const q = b / a;
      const r = b - a * q;
      const m = x - u * q;
      b = a, a = r, x = u, u = m;
    }
    const gcd = b;
    if (gcd !== _1n2)
      throw new Error("invert: does not exist");
    return mod(x, modulo);
  }
  function invertCt(a, prime) {
    if (prime <= _1n2)
      throw new Error("invertCt: expected prime modulus > 1, got " + prime);
    const an = mod(a, prime);
    if (an === _0n2)
      throw new Error("invertCt: expected non-zero number");
    const inverse = pow(an, prime - _2n, prime);
    if (mod(an * inverse, prime) !== _1n2)
      throw new Error("invertCt: does not exist");
    return inverse;
  }
  function assertIsSquare(Fp, root2, n) {
    const F = Fp;
    if (!F.eql(F.sqr(root2), n))
      throw new Error("Cannot find square root");
  }
  function aoddModulus(order, fnName) {
    if ((order & _1n2) === _0n2)
      throw new Error(fnName + ": expected odd modulus, got " + order);
  }
  function sqrt3mod4(Fp, n) {
    const F = Fp;
    const p1div4 = (F.ORDER + _1n2) / _4n;
    const root2 = F.pow(n, p1div4);
    assertIsSquare(F, root2, n);
    return root2;
  }
  function sqrt5mod8(Fp, n) {
    const F = Fp;
    const p5div8 = (F.ORDER - _5n) / _8n;
    const n2 = F.mul(n, _2n);
    const v = F.pow(n2, p5div8);
    const nv = F.mul(n, v);
    const i = F.mul(F.mul(nv, _2n), v);
    const root2 = F.mul(nv, F.sub(i, F.ONE));
    assertIsSquare(F, root2, n);
    return root2;
  }
  function sqrt9mod16(P) {
    const Fp_ = Field(P);
    const tn = tonelliShanks(P);
    const c1 = tn(Fp_, Fp_.neg(Fp_.ONE));
    const c2 = tn(Fp_, c1);
    const c3 = tn(Fp_, Fp_.neg(c1));
    const c4 = (P + _7n) / _16n;
    return ((Fp, n) => {
      const F = Fp;
      let tv1 = F.pow(n, c4);
      let tv2 = F.mul(tv1, c1);
      const tv3 = F.mul(tv1, c2);
      const tv4 = F.mul(tv1, c3);
      const e1 = F.eql(F.sqr(tv2), n);
      const e2 = F.eql(F.sqr(tv3), n);
      tv1 = F.cmov(tv1, tv2, e1);
      tv2 = F.cmov(tv4, tv3, e2);
      const e3 = F.eql(F.sqr(tv2), n);
      const root2 = F.cmov(tv1, tv2, e3);
      assertIsSquare(F, root2, n);
      return root2;
    });
  }
  function tonelliShanks(P) {
    if (P < _3n)
      throw new Error("sqrt is not defined for small field");
    aoddModulus(P, "tonelliShanks");
    let Q = P - _1n2;
    let S = 0;
    while (Q % _2n === _0n2) {
      Q /= _2n;
      S++;
    }
    let Z = _2n;
    const _Fp = Field(P);
    while (FpLegendre(_Fp, Z) === 1) {
      if (Z++ > 1e3)
        throw new Error("Cannot find square root: probably non-prime P");
    }
    if (S === 1)
      return sqrt3mod4;
    let cc = _Fp.pow(Z, Q);
    const Q1div2 = (Q + _1n2) / _2n;
    return function tonelliSlow(Fp, n) {
      const F = Fp;
      if (F.is0(n))
        return n;
      if (FpLegendre(F, n) !== 1)
        throw new Error("Cannot find square root");
      let M = S;
      let c = F.mul(F.ONE, cc);
      let t = F.pow(n, Q);
      let R = F.pow(n, Q1div2);
      while (!F.eql(t, F.ONE)) {
        if (F.is0(t))
          throw new Error("Cannot find square root: probably non-prime P");
        let i = 1;
        let t_tmp = F.sqr(t);
        while (!F.eql(t_tmp, F.ONE)) {
          i++;
          t_tmp = F.sqr(t_tmp);
          if (i === M)
            throw new Error("Cannot find square root");
        }
        const exponent = _1n2 << BigInt(M - i - 1);
        const b = F.pow(c, exponent);
        M = i;
        c = F.sqr(b);
        t = F.mul(t, c);
        R = F.mul(R, b);
      }
      return R;
    };
  }
  function FpSqrt(P) {
    aoddModulus(P, "Fp.sqrt");
    if (P % _4n === _3n)
      return sqrt3mod4;
    if (P % _8n === _5n)
      return sqrt5mod8;
    if (P % _16n === _9n)
      return sqrt9mod16(P);
    return tonelliShanks(P);
  }
  function validateField(field) {
    aobject2(field, "field");
    if (typeof field.ORDER !== "bigint")
      throw new TypeError('param "ORDER" is invalid: expected bigint, got ' + typeof field.ORDER);
    asafenumber(field.BYTES, "BYTES");
    asafenumber(field.BITS, "BITS");
    for (const name of FIELD_FIELDS)
      afunction(field[name], "field." + name);
    if (field.BYTES < 1 || field.BITS < 1)
      throw new Error("invalid field: expected BYTES/BITS > 0");
    if (field.ORDER <= _1n2)
      throw new Error("invalid field: expected ORDER > 1, got " + field.ORDER);
    return field;
  }
  function FpInvertBatch(Fp, nums, passZero = false) {
    validateField(Fp);
    aarray(nums, "nums");
    abool2(passZero, "passZero");
    const F = Fp;
    const inverted = new Array(nums.length).fill(passZero ? F.ZERO : void 0);
    const multipliedAcc = nums.reduce((acc, num, i) => {
      if (F.is0(num))
        return acc;
      inverted[i] = acc;
      return F.mul(acc, num);
    }, F.ONE);
    const invertedAcc = F.inv(multipliedAcc);
    nums.reduceRight((acc, num, i) => {
      if (F.is0(num))
        return acc;
      inverted[i] = F.mul(acc, inverted[i]);
      return F.mul(acc, num);
    }, invertedAcc);
    return inverted;
  }
  function FpLegendre(Fp, n) {
    validateField(Fp);
    const F = Fp;
    aoddModulus(F.ORDER, "FpLegendre");
    const p1mod2 = (F.ORDER - _1n2) / _2n;
    const powered = F.pow(n, p1mod2);
    const yes = F.eql(powered, F.ONE);
    const zero = F.eql(powered, F.ZERO);
    const no = F.eql(powered, F.neg(F.ONE));
    if (!yes && !zero && !no)
      throw new Error("invalid Legendre symbol result");
    return yes ? 1 : zero ? 0 : -1;
  }
  function FpIsSquare(Fp, n) {
    const l = FpLegendre(Fp, n);
    return l !== -1;
  }
  function nLength(n, nBitLength) {
    if (nBitLength !== void 0)
      anumber2(nBitLength);
    if (n <= _0n2)
      throw new Error("invalid n length: expected positive n, got " + n);
    if (nBitLength !== void 0 && nBitLength < 1)
      throw new Error("invalid n length: expected positive bit length, got " + nBitLength);
    const bits = bitLen(n);
    if (nBitLength !== void 0 && nBitLength < bits)
      throw new Error(`invalid n length: expected nBitLength (${nBitLength}) >= bitLen(n) (${bits})`);
    const _nBitLength = nBitLength !== void 0 ? nBitLength : bits;
    const nByteLength = Math.ceil(_nBitLength / 8);
    return { nBitLength: _nBitLength, nByteLength };
  }
  function Field(ORDER2, opts = {}) {
    Object.freeze(_Field.prototype);
    return new _Field(ORDER2, opts);
  }
  function getFieldBytesLength(fieldOrder) {
    if (typeof fieldOrder !== "bigint")
      throw new Error("field order must be bigint");
    if (fieldOrder <= _1n2)
      throw new Error("field order must be greater than 1");
    const bitLength = bitLen(fieldOrder - _1n2);
    return Math.ceil(bitLength / 8);
  }
  function getMinHashLength(fieldOrder) {
    const length = getFieldBytesLength(fieldOrder);
    return length + Math.ceil(length / 2);
  }
  function mapHashToField(key, fieldOrder, isLE2 = false) {
    abytes2(key);
    const len = key.length;
    const fieldLen = getFieldBytesLength(fieldOrder);
    const minLen = Math.max(getMinHashLength(fieldOrder), 16);
    if (len < minLen || len > 1024)
      throw new Error("expected " + minLen + "-1024 bytes of input, got " + len);
    const num = isLE2 ? bytesToNumberLE(key) : bytesToNumberBE(key);
    const reduced = mod(num, fieldOrder - _1n2) + _1n2;
    return isLE2 ? numberToBytesLE(reduced, fieldLen) : numberToBytesBE(reduced, fieldLen);
  }
  var _0n2, _1n2, _2n, _3n, _4n, _5n, _7n, _8n, _9n, _15n, _16n, POW_WINDOWED_MIN, FIELD_FIELDS, FIELD_SQRT, _Field;
  var init_modular = __esm({
    "node_modules/@noble/curves/abstract/modular.js"() {
      init_utils2();
      _0n2 = /* @__PURE__ */ BigInt(0);
      _1n2 = /* @__PURE__ */ BigInt(1);
      _2n = /* @__PURE__ */ BigInt(2);
      _3n = /* @__PURE__ */ BigInt(3);
      _4n = /* @__PURE__ */ BigInt(4);
      _5n = /* @__PURE__ */ BigInt(5);
      _7n = /* @__PURE__ */ BigInt(7);
      _8n = /* @__PURE__ */ BigInt(8);
      _9n = /* @__PURE__ */ BigInt(9);
      _15n = /* @__PURE__ */ BigInt(15);
      _16n = /* @__PURE__ */ BigInt(16);
      POW_WINDOWED_MIN = /* @__PURE__ */ BigInt("0x10000000000000000");
      FIELD_FIELDS = [
        "create",
        "isValid",
        "is0",
        "neg",
        "inv",
        "sqrt",
        "sqr",
        "eql",
        "add",
        "sub",
        "mul",
        "pow",
        "div",
        "addN",
        "subN",
        "mulN",
        "sqrN"
      ];
      FIELD_SQRT = /* @__PURE__ */ new WeakMap();
      _Field = class {
        ORDER;
        BITS;
        BYTES;
        isLE;
        ZERO = _0n2;
        ONE = _1n2;
        _lengths;
        _mod;
        constructor(ORDER2, opts = {}) {
          if (ORDER2 <= _1n2)
            throw new Error("invalid field: expected ORDER > 1, got " + ORDER2);
          let _nbitLength = void 0;
          this.isLE = false;
          if (opts != null && typeof opts === "object") {
            if (typeof opts.BITS === "number")
              _nbitLength = opts.BITS;
            if (typeof opts.sqrt === "function")
              Object.defineProperty(this, "sqrt", { value: opts.sqrt, enumerable: true });
            if (typeof opts.isLE === "boolean")
              this.isLE = opts.isLE;
            if (opts.allowedLengths)
              this._lengths = Object.freeze(opts.allowedLengths.slice());
            if (typeof opts.modFromBytes === "boolean")
              this._mod = opts.modFromBytes;
          }
          const { nBitLength, nByteLength } = nLength(ORDER2, _nbitLength);
          if (nByteLength > 2048)
            throw new Error("invalid field: expected ORDER of <= 2048 bytes");
          this.ORDER = ORDER2;
          this.BITS = nBitLength;
          this.BYTES = nByteLength;
          Object.freeze(this);
        }
        create(num) {
          return mod(num, this.ORDER);
        }
        isValid(num) {
          if (typeof num !== "bigint")
            throw new TypeError("invalid field element: expected bigint, got " + typeof num);
          return _0n2 <= num && num < this.ORDER;
        }
        is0(num) {
          return num === _0n2;
        }
        // is valid and invertible
        isValidNot0(num) {
          return !this.is0(num) && this.isValid(num);
        }
        isOdd(num) {
          return (num & _1n2) === _1n2;
        }
        neg(num) {
          return mod(-num, this.ORDER);
        }
        eql(lhs, rhs) {
          return lhs === rhs;
        }
        sqr(num) {
          return mod(num * num, this.ORDER);
        }
        add(lhs, rhs) {
          return mod(lhs + rhs, this.ORDER);
        }
        sub(lhs, rhs) {
          return mod(lhs - rhs, this.ORDER);
        }
        mul(lhs, rhs) {
          return mod(lhs * rhs, this.ORDER);
        }
        pow(num, power) {
          return pow(num, power, this.ORDER);
        }
        div(lhs, rhs) {
          return mod(lhs * invert(rhs, this.ORDER), this.ORDER);
        }
        // Same as above, but doesn't normalize
        sqrN(num) {
          return num * num;
        }
        addN(lhs, rhs) {
          return lhs + rhs;
        }
        subN(lhs, rhs) {
          return lhs - rhs;
        }
        mulN(lhs, rhs) {
          return lhs * rhs;
        }
        inv(num) {
          return invert(num, this.ORDER);
        }
        sqrt(num) {
          let sqrt = FIELD_SQRT.get(this);
          if (!sqrt)
            FIELD_SQRT.set(this, sqrt = FpSqrt(this.ORDER));
          return sqrt(this, num);
        }
        toBytes(num) {
          return this.isLE ? numberToBytesLE(num, this.BYTES) : numberToBytesBE(num, this.BYTES);
        }
        fromBytes(bytes, skipValidation = false) {
          abytes2(bytes);
          const { _lengths: allowedLengths, BYTES, isLE: isLE2, ORDER: ORDER2, _mod: modFromBytes } = this;
          if (allowedLengths) {
            if (bytes.length < 1 || !allowedLengths.includes(bytes.length) || bytes.length > BYTES) {
              throw new Error("Field.fromBytes: expected " + allowedLengths + " bytes, got " + bytes.length);
            }
            const padded = new Uint8Array(BYTES);
            padded.set(bytes, isLE2 ? 0 : padded.length - bytes.length);
            bytes = padded;
          }
          if (bytes.length !== BYTES)
            throw new Error("Field.fromBytes: expected " + BYTES + " bytes, got " + bytes.length);
          let scalar = isLE2 ? bytesToNumberLE(bytes) : bytesToNumberBE(bytes);
          if (modFromBytes)
            scalar = mod(scalar, ORDER2);
          if (!skipValidation) {
            if (!this.isValid(scalar))
              throw new Error("invalid field element: outside of range 0..ORDER");
          }
          return scalar;
        }
        // TODO: we don't need it here, move out to separate fn
        invertBatch(lst) {
          return FpInvertBatch(this, lst, true);
        }
        // We can't move this out because Fp6, Fp12 implement it
        // and it's unclear what to return in there.
        cmov(a, b, condition) {
          abool2(condition, "condition");
          return condition ? b : a;
        }
      };
    }
  });

  // node_modules/@noble/curves/abstract/curve.js
  function validatePointCons(Point) {
    const pc = Point;
    if (typeof pc !== "function")
      throw new TypeError('"Point" expected constructor, got type=' + typeof Point);
    afunction(pc.fromAffine, "Point.fromAffine");
    afunction(pc.fromBytes, "Point.fromBytes");
    afunction(pc.fromHex, "Point.fromHex");
    aobject2(pc.BASE, "Point.BASE");
    aobject2(pc.ZERO, "Point.ZERO");
    validateField(pc.Fp);
    validateField(pc.Fn);
  }
  function normalizeZ(c, points) {
    validatePointCons(c);
    validateMSMPoints(points, c);
    const invertedZs = FpInvertBatch(c.Fp, points.map((p) => p.Z));
    return points.map((p, i) => c.fromAffine(p.toAffine(invertedZs[i])));
  }
  function validateW(W, bits, min = 1) {
    if (!Number.isSafeInteger(W) || W < min || W > bits)
      throw new Error("invalid window size, expected [" + min + ".." + bits + "], got W=" + W);
  }
  function validateTableBytes(numPoints, fpBytes) {
    const bytes = numPoints * (4 * fpBytes + 128);
    if (bytes > TABLE_BYTES_MAX)
      throw new Error("invalid window size: table would need ~" + Math.ceil(bytes / 2 ** 20) + " MiB, max " + TABLE_BYTES_MAX / 2 ** 20 + " MiB");
  }
  function probeRandomBytes(randomBytes5, length) {
    if (randomBytes5 === void 0)
      return void 0;
    afunction(randomBytes5, "randomBytes");
    try {
      const probe = randomBytes5(length);
      if (!isBytes2(probe) || probe.length !== length)
        return void 0;
    } catch {
      return void 0;
    }
    return randomBytes5;
  }
  function validateMSMPoints(points, c) {
    aarray(points, "points");
    points.forEach((p, i) => {
      if (!(p instanceof c))
        throw new Error("invalid point at index " + i);
    });
  }
  function validateMSMScalars(scalars, field, maxScalar) {
    if (!Array.isArray(scalars))
      throw new Error("array of scalars expected");
    scalars.forEach((s, i) => {
      const ok = maxScalar === void 0 ? field.isValid(s) : isPosBig(s) && s < maxScalar;
      if (!ok)
        throw new Error("invalid scalar at index " + i);
    });
  }
  function getWindowSize(P) {
    return pointWindowSizes.get(P) || 1;
  }
  function oddMultiples(p, size) {
    const dbl = p.double();
    const t = [p];
    for (let j = 1; j < size; j++)
      t.push(t[j - 1].add(dbl));
    return t;
  }
  function wnafDigits(n, W) {
    const size = 2 ** W;
    const half = size / 2;
    const mask = BigInt(size - 1);
    const d = [];
    while (n > _0n3) {
      let w = 0;
      if (n & _1n3) {
        w = Number(n & mask);
        if (w >= half)
          w -= size;
        n -= BigInt(w);
      }
      d.push(w);
      n >>= _1n3;
    }
    return d;
  }
  function signedWindowDigits(n, W, windows) {
    const size = 2 ** W;
    const half = size / 2;
    const mask = BigInt(size - 1);
    const shiftBy = BigInt(W);
    const d = [];
    for (let w = 0; w < windows; w++) {
      let v = Number(n & mask);
      n >>= shiftBy;
      if (v > half) {
        v -= size;
        n += _1n3;
      }
      d.push(v);
    }
    if (n !== _0n3)
      throw new Error("invalid wnaf");
    return d;
  }
  function wnafWalk(zero, tables, digits) {
    let max = 0;
    for (const d of digits)
      max = Math.max(max, d.length);
    let acc = zero;
    for (let bit = max - 1; bit >= 0; bit--) {
      if (bit !== max - 1)
        acc = acc.double();
      for (let i = 0; i < digits.length; i++) {
        const w = digits[i][bit];
        if (w) {
          const item = tables[i][Math.abs(w) - 1 >> 1];
          acc = acc.add(w < 0 ? item.negate() : item);
        }
      }
    }
    return acc;
  }
  function mulAddUnsafe(c, points, scalars, allowOversized = false) {
    validatePointCons(c);
    validateMSMPoints(points, c);
    abool2(allowOversized, "allowOversized");
    validateMSMScalars(scalars, c.Fn, allowOversized ? c.Fn.ORDER ** _4n2 : void 0);
    if (points.length !== scalars.length)
      throw new Error("arrays of points and scalars must have equal length");
    const tables = points.map((p) => oddMultiples(p, 4));
    const digits = scalars.map((n) => wnafDigits(n, 4));
    return wnafWalk(c.ZERO, tables, digits);
  }
  function createField(order, field, isLE2) {
    if (field) {
      if (field.ORDER !== order)
        throw new Error("Field.ORDER must match order: Fp == p, Fn == n");
      validateField(field);
      return field;
    } else {
      return Field(order, { isLE: isLE2 });
    }
  }
  function createCurveFields(type, CURVE, curveOpts = {}, FpFnLE) {
    if (type !== "weierstrass" && type !== "edwards")
      throw new Error('expected curve type "weierstrass" or "edwards"');
    if (FpFnLE === void 0)
      FpFnLE = type === "edwards";
    if (!CURVE || typeof CURVE !== "object")
      throw new Error(`expected valid ${type} CURVE object`);
    validateObject(curveOpts);
    for (const p of ["p", "n", "h"]) {
      const val = CURVE[p];
      if (!(isPosBig(val) && val !== _0n3))
        throw new Error(`CURVE.${p} must be positive bigint`);
    }
    const Fp = createField(CURVE.p, curveOpts.Fp, FpFnLE);
    const Fn = createField(CURVE.n, curveOpts.Fn, FpFnLE);
    const _b = type === "weierstrass" ? "b" : "d";
    const params = ["Gx", "Gy", "a", _b];
    for (const p of params) {
      if (!Fp.isValid(CURVE[p]))
        throw new Error(`CURVE.${p} must be valid field element of CURVE.Fp`);
    }
    CURVE = Object.freeze(Object.assign({}, CURVE));
    return { CURVE, Fp, Fn };
  }
  function createKeygen(randomSecretKey, getPublicKey) {
    return function keygen(seed) {
      const secretKey = randomSecretKey(seed);
      return { secretKey, publicKey: getPublicKey(secretKey) };
    };
  }
  var _0n3, _1n3, _4n2, BLIND_BYTES, BLIND_BITS, FW_WINDOW, TABLE_BYTES_MAX, pointWindowSizes, ScalarMultiplier;
  var init_curve = __esm({
    "node_modules/@noble/curves/abstract/curve.js"() {
      init_utils2();
      init_modular();
      _0n3 = /* @__PURE__ */ BigInt(0);
      _1n3 = /* @__PURE__ */ BigInt(1);
      _4n2 = /* @__PURE__ */ BigInt(4);
      BLIND_BYTES = 16;
      BLIND_BITS = 128;
      FW_WINDOW = 5;
      TABLE_BYTES_MAX = /* @__PURE__ */ (() => 2 ** 31)();
      pointWindowSizes = /* @__PURE__ */ new WeakMap();
      ScalarMultiplier = class {
        Point;
        BASE;
        ZERO;
        randomBytes;
        wnafPrecomputes = /* @__PURE__ */ new WeakMap();
        baseCanBeBlinded;
        bits;
        // Parametrized with a given Point class (not individual point)
        constructor(Point, randomBytes5) {
          validatePointCons(Point);
          this.randomBytes = probeRandomBytes(randomBytes5, BLIND_BYTES);
          this.Point = Point;
          this.BASE = Point.BASE;
          this.ZERO = Point.ZERO;
          this.bits = Point.Fn.BITS;
        }
        /**
         * Creates a signed fixed-window wNAF precomputation table: for every window w, the
         * multiples `[1..2^(W−1)]⋅2^(w⋅W)⋅P`, flattened. All doublings are baked into the table,
         * so cached multiplication is additions-only. `windows = ceil(bits/W) + 1`: the extra
         * window absorbs the final carry of signed-digit recoding.
         * For a 256-bit curve and W=6, the table is 44⋅32 = 1408 points.
         * @param point - Point instance
         * @param W - window size
         * @param bits - scalar bitlength the table must cover
         */
        buildWnafTable(point, W, bits) {
          const windows = Math.ceil(bits / W) + 1;
          const half = 2 ** (W - 1);
          const comp = [];
          let base = point;
          for (let w = 0; w < windows; w++) {
            let acc = base;
            for (let i = 0; i < half; i++) {
              comp.push(acc);
              acc = acc.add(base);
            }
            base = comp[comp.length - 1].double();
          }
          return { W, bits, windows, comp };
        }
        /**
         * Implements ec multiplication using precomputed signed fixed-window wNAF tables.
         * Constant-time: fixed window count with one table addition per window — zero digits feed
         * the fake accumulator — and no doublings; the lookup scans the whole window slice.
         * Scalar bounds are validated by the public entry points ({@link ScalarMultiplier.mulCT},
         * {@link ScalarMultiplier.mulCTBlinded}, {@link ScalarMultiplier.mulUnsafe});
         * signedWindowDigits throws if `n` exceeds the table.
         * @returns real and fake (for const-time) points
         */
        wnafCachedCT(precomputes, n) {
          const { W, windows, comp } = precomputes;
          const half = 2 ** (W - 1);
          const digits = signedWindowDigits(n, W, windows);
          let p = this.ZERO;
          let f = this.BASE;
          for (let w = 0; w < windows; w++) {
            const digit = digits[w];
            const start = w * half;
            const idx = Math.abs(digit) - 1;
            let sel = comp[start];
            for (let i = 1; i < half; i++)
              sel = i === idx ? comp[start + i] : sel;
            const neg = sel.negate();
            if (digit === 0)
              f = f.add(comp[start]);
            else
              p = p.add(digit < 0 ? neg : sel);
          }
          return { p, f };
        }
        // Cache key is point identity plus (W, bits); at most two entries exist per point (public-width
        // `Fn.BITS` and blinded `Fn.BITS + BLIND_BITS`). Callers must not reuse the same point with
        // incompatible `transform(...)` layouts and expect a separate cache entry.
        getWnafPrecomputes(W, point, bits, transform) {
          let entries = this.wnafPrecomputes.get(point);
          let comp = entries?.find((entry) => entry.W === W && entry.bits === bits);
          if (!comp) {
            comp = this.buildWnafTable(point, W, bits);
            if (typeof transform === "function")
              comp = { ...comp, comp: transform(comp.comp) };
            if (!entries) {
              entries = [];
              this.wnafPrecomputes.set(point, entries);
            }
            entries.push(comp);
          }
          return comp;
        }
        assertPoint(point) {
          if (!(point instanceof this.Point))
            throw new TypeError('"point" expected Point instance, got type=' + typeof point);
        }
        // Shared prologue of the constant-time entry points. Rejects scalar 0: in key/signature-style
        // callers a zero scalar means broken upstream plumbing, and concrete Points already reject it.
        // Uses inRange instead of Fn.isValidNot0: validateField() only certifies the arithmetic subset.
        validateMulInput(point, scalar) {
          this.assertPoint(point);
          if (!inRange(scalar, _1n3, this.Point.Fn.ORDER))
            throw new Error("invalid scalar");
        }
        // Constant-time dispatch shared by mulCT / mulCTBlinded. Un-precomputed points (W===1, e.g.
        // ECDH peer keys) skip building a throwaway cached table in favor of a small fixed-window
        // multiply. `n` must be < 2^bits.
        runCT(point, n, bits, transform) {
          const W = getWindowSize(point);
          if (W === 1)
            return this.fixedWindowCT(point, n, bits);
          return this.wnafCachedCT(this.getWnafPrecomputes(W, point, bits, transform), n);
        }
        mulCT(point, scalar, transform) {
          this.validateMulInput(point, scalar);
          return this.runCT(point, scalar, this.bits, transform);
        }
        mulCTBlinded(point, scalar, transform) {
          this.validateMulInput(point, scalar);
          if (this.randomBytes === void 0)
            throw new Error("randomBytes is required for scalar blinding");
          const bits = this.Point.Fn.BITS + BLIND_BITS;
          const blind = this.randomBytes(BLIND_BYTES);
          if (!isBytes2(blind) || blind.length !== BLIND_BYTES)
            throw new Error("randomBytes returned invalid byte array");
          blind[0] = blind[0] & 63 | 128;
          const n = scalar + bytesToNumberBE(blind) * this.Point.Fn.ORDER;
          return this.runCT(point, n, bits, transform);
        }
        /**
         * Constant-time multiplication `n*point` for an un-precomputed point, via a small fixed window.
         * A cached wNAF table only pays off when reused; a flat 2^FW_WINDOW table (`size-1` adds) is
         * far cheaper to build for a single use. The point-operation sequence is independent of `n`:
         * build the table, then per window exactly FW_WINDOW doublings, a data-oblivious scan over
         * every table entry, and one addition (adds the identity when the window digit is 0 — never
         * skipped).
         *
         * `n` must be `< 2^bits`. Assumes complete addition (adding the identity costs the same as any
         * add), which holds for the Weierstrass/Edwards point types used here. The table is left in
         * projective form (no normalizeZ): normalizing this small a table costs more than the
         * mixed-add savings it would buy for a single multiply.
         * @returns real point `p`; `f` duplicates it only to match {@link wnafCachedCT}'s return shape
         * (this path needs no fake accumulator — its op-count is already scalar-independent).
         */
        fixedWindowCT(point, n, bits) {
          const W = FW_WINDOW;
          const size = 1 << W;
          const mask = bitMask(W);
          const table = new Array(size);
          table[0] = this.ZERO;
          for (let i = 1; i < size; i++)
            table[i] = table[i - 1].add(point);
          const windows = Math.ceil(bits / W);
          let acc = this.ZERO;
          for (let window = windows - 1; window >= 0; window--) {
            if (window !== windows - 1)
              for (let d = 0; d < W; d++)
                acc = acc.double();
            const digit = Number(n >> BigInt(window * W) & mask);
            let sel = table[0];
            for (let i = 1; i < size; i++)
              sel = i === digit ? table[i] : sel;
            acc = acc.add(sel);
          }
          return { p: acc, f: acc };
        }
        shouldBlind(point, cofactor) {
          if (this.randomBytes === void 0)
            return false;
          if (cofactor === _1n3)
            return true;
          if (point !== this.BASE)
            return false;
          if (this.baseCanBeBlinded === void 0)
            this.baseCanBeBlinded = this.mulUnsafe(this.BASE, this.Point.Fn.ORDER).is0();
          return this.baseCanBeBlinded;
        }
        mulSecret(point, scalar, cofactor, transform) {
          return this.shouldBlind(point, cofactor) ? this.mulCTBlinded(point, scalar, transform) : this.mulCT(point, scalar, transform);
        }
        mulUnsafe(point, scalar, transform) {
          this.assertPoint(point);
          if (!isPosBig(scalar))
            throw new Error("invalid scalar");
          const W = getWindowSize(point);
          if (W === 1 || scalar >= this.Point.Fn.ORDER)
            return mulAddUnsafe(this.Point, [point], [scalar], true);
          const precomputes = this.getWnafPrecomputes(W, point, this.bits, transform);
          return this.wnafCachedCT(precomputes, scalar).p;
        }
        // Remembers the window size used for precomputed wNAF multiplication of the given point
        // and drops any previously built tables. Usually only the base point is precomputed.
        // W=1 resets the point to the un-precomputed (table-less) paths.
        // W is additionally capped so tables stay under ~2 GiB ({@link TABLE_BYTES_MAX}).
        setWindowSize(point, W) {
          this.assertPoint(point);
          validateW(W, this.bits);
          const windows = Math.ceil((this.bits + BLIND_BITS) / W) + 1;
          validateTableBytes(windows * 2 ** (W - 1), this.Point.Fp.BYTES);
          pointWindowSizes.set(point, W);
          this.wnafPrecomputes.delete(point);
        }
        // True when a window size is set: tables themselves are built lazily on first multiply.
        hasWindowSize(point) {
          return getWindowSize(point) !== 1;
        }
      };
    }
  });

  // node_modules/@noble/curves/abstract/hash-to-curve.js
  function i2osp(value, length) {
    asafenumber(value);
    asafenumber(length);
    if (length < 0 || length > 4)
      throw new Error("invalid I2OSP length: " + length);
    if (value < 0 || value > 2 ** (8 * length) - 1)
      throw new Error("invalid I2OSP input: " + value);
    const res = Array.from({ length }).fill(0);
    for (let i = length - 1; i >= 0; i--) {
      res[i] = value & 255;
      value >>>= 8;
    }
    return new Uint8Array(res);
  }
  function strxor(a, b) {
    const arr = new Uint8Array(a.length);
    for (let i = 0; i < a.length; i++) {
      arr[i] = a[i] ^ b[i];
    }
    return arr;
  }
  function normDST(DST) {
    if (!isBytes2(DST) && typeof DST !== "string")
      throw new Error("DST must be Uint8Array or ascii string");
    const dst = typeof DST === "string" ? asciiToBytes(DST) : DST;
    if (dst.length === 0)
      throw new Error("DST must be non-empty");
    return dst;
  }
  function expand_message_xmd(msg, DST, lenInBytes, H3) {
    abytes2(msg);
    asafenumber(lenInBytes);
    if (typeof H3 !== "function")
      throw new Error("expand_message_xmd: expected hash function");
    asafenumber(H3.outputLen, "hash.outputLen");
    asafenumber(H3.blockLen, "hash.blockLen");
    DST = normDST(DST);
    if (DST.length > 255)
      DST = H3(concatBytes2(asciiToBytes("H2C-OVERSIZE-DST-"), DST));
    const { outputLen: b_in_bytes, blockLen: r_in_bytes } = H3;
    const ell = Math.ceil(lenInBytes / b_in_bytes);
    if (lenInBytes > 65535 || ell > 255)
      throw new Error("expand_message_xmd: invalid lenInBytes");
    const DST_prime = concatBytes2(DST, i2osp(DST.length, 1));
    const Z_pad = new Uint8Array(r_in_bytes);
    const l_i_b_str = i2osp(lenInBytes, 2);
    const b = new Array(ell);
    const b_0 = H3(concatBytes2(Z_pad, msg, l_i_b_str, i2osp(0, 1), DST_prime));
    b[0] = H3(concatBytes2(b_0, i2osp(1, 1), DST_prime));
    for (let i = 1; i < ell; i++) {
      const args = [strxor(b_0, b[i - 1]), i2osp(i + 1, 1), DST_prime];
      b[i] = H3(concatBytes2(...args));
    }
    const pseudo_random_bytes = concatBytes2(...b);
    return pseudo_random_bytes.slice(0, lenInBytes);
  }
  function expand_message_xof(msg, DST, lenInBytes, k, H3) {
    abytes2(msg);
    asafenumber(lenInBytes);
    asafenumber(k, "k");
    if (k < 0)
      throw new Error("expand_message_xof: invalid k");
    if (typeof H3 !== "function")
      throw new Error("expand_message_xof: expected XOF function");
    if (typeof H3.create !== "function")
      throw new Error("expand_message_xof: expected XOF create");
    DST = normDST(DST);
    if (lenInBytes < 0 || lenInBytes > 65535)
      throw new Error("expand_message_xof: invalid lenInBytes");
    if (DST.length > 255) {
      const dkLen = Math.ceil(2 * k / 8);
      DST = H3.create({ dkLen }).update(asciiToBytes("H2C-OVERSIZE-DST-")).update(DST).digest();
    }
    if (DST.length > 255)
      throw new Error("expand_message_xof: invalid DST");
    return H3.create({ dkLen: lenInBytes }).update(msg).update(i2osp(lenInBytes, 2)).update(DST).update(i2osp(DST.length, 1)).digest();
  }
  function hash_to_field(msg, count, options) {
    validateObject(options, {
      p: "bigint",
      m: "number",
      k: "number",
      hash: "function"
    });
    const { p, k, m, hash, expand, DST } = options;
    asafenumber(hash.outputLen, "valid hash");
    abytes2(msg);
    asafenumber(count);
    asafenumber(m, "m");
    asafenumber(k, "k");
    if (p <= BigInt(1))
      throw new Error("hash_to_field: expected valid field characteristic");
    if (count < 1)
      throw new Error("hash_to_field: expected count >= 1");
    if (m < 1)
      throw new Error("hash_to_field: expected m >= 1");
    if (k < 0)
      throw new Error("hash_to_field: invalid k");
    const log2p = p.toString(2).length;
    const L = Math.ceil((log2p + k) / 8);
    const len_in_bytes = count * m * L;
    let prb;
    if (expand === "xmd") {
      prb = expand_message_xmd(msg, DST, len_in_bytes, hash);
    } else if (expand === "xof") {
      prb = expand_message_xof(msg, DST, len_in_bytes, k, hash);
    } else if (expand === "_internal_pass") {
      prb = msg;
    } else {
      throw new Error('expand must be "xmd" or "xof"');
    }
    const u = new Array(count);
    for (let i = 0; i < count; i++) {
      const e = new Array(m);
      for (let j = 0; j < m; j++) {
        const elm_offset = L * (j + i * m);
        const tv = prb.subarray(elm_offset, elm_offset + L);
        e[j] = mod(os2ip(tv), p);
      }
      u[i] = e;
    }
    return u;
  }
  function isogenyMap(field, map) {
    validateField(field);
    aarray(map, "map");
    const coeff = map.map((i, row) => {
      aarray(i, "map[" + row + "]");
      if (i.length < 1)
        throw new Error("isogenyMap: expected non-empty coefficients");
      return Array.from(i).reverse();
    });
    return (x, y) => {
      const [xn, xd, yn, yd] = coeff.map((val) => val.reduce((acc, i) => field.add(field.mul(acc, x), i)));
      const isZero = field.is0(xd) || field.is0(yd);
      const [xd_inv, yd_inv] = FpInvertBatch(field, [xd, yd], true);
      x = field.mul(xn, xd_inv);
      y = field.mul(y, field.mul(yn, yd_inv));
      return isZero ? { x: field.ZERO, y: field.ZERO } : { x, y };
    };
  }
  function createHasher2(Point, mapToCurve, defaults) {
    if (typeof mapToCurve !== "function")
      throw new Error("mapToCurve() must be defined");
    validateObject(defaults);
    const snapshot = (src) => Object.freeze({
      ...src,
      DST: isBytes2(src.DST) ? copyBytes(src.DST) : src.DST,
      ...src.encodeDST === void 0 ? {} : { encodeDST: isBytes2(src.encodeDST) ? copyBytes(src.encodeDST) : src.encodeDST }
    });
    const safeDefaults = snapshot(defaults);
    const dstOverride = (options) => options && options.DST !== void 0 ? { DST: options.DST } : void 0;
    function map(num) {
      return Point.fromAffine(mapToCurve(num));
    }
    function clear(initial) {
      const P = initial.clearCofactor();
      if (P.equals(Point.ZERO))
        return Point.ZERO;
      P.assertValidity();
      return P;
    }
    return Object.freeze({
      get defaults() {
        return snapshot(safeDefaults);
      },
      Point,
      hashToCurve(msg, options) {
        const opts = Object.assign({}, safeDefaults, dstOverride(options));
        const u = hash_to_field(msg, 2, opts);
        const u0 = map(u[0]);
        const u1 = map(u[1]);
        return clear(u0.add(u1));
      },
      encodeToCurve(msg, options) {
        const optsDst = safeDefaults.encodeDST === void 0 ? {} : { DST: safeDefaults.encodeDST };
        const opts = Object.assign({}, safeDefaults, optsDst, dstOverride(options));
        const u = hash_to_field(msg, 1, opts);
        const u0 = map(u[0]);
        return clear(u0);
      },
      /** See {@link H2CHasher} */
      mapToCurve(scalars) {
        if (safeDefaults.m === 1) {
          if (typeof scalars !== "bigint")
            throw new Error("expected bigint (m=1)");
          return clear(map([scalars]));
        }
        if (!Array.isArray(scalars))
          throw new Error("expected array of bigints");
        if (scalars.length !== safeDefaults.m)
          throw new Error(`expected array of ${safeDefaults.m} bigints`);
        for (const i of scalars)
          if (typeof i !== "bigint")
            throw new Error("expected array of bigints");
        return clear(map(scalars));
      },
      // hash_to_scalar can produce 0: https://www.rfc-editor.org/errata/eid8393
      // RFC 9380, draft-irtf-cfrg-bbs-signatures-08. Default scalar DST is the shared generic
      // `HashToScalar-` prefix above unless the caller overrides it per invocation.
      hashToScalar(msg, options) {
        const N = Point.Fn.ORDER;
        const opts = Object.assign({}, safeDefaults, { DST: _DST_scalar }, dstOverride(options), {
          p: N,
          m: 1
        });
        return hash_to_field(msg, 1, opts)[0][0];
      }
    });
  }
  function SWUFpSqrtRatio(Fp, Z) {
    const F = validateField(Fp);
    const q = F.ORDER;
    let l = _0n4;
    for (let o = q - _1n4; o % _2n2 === _0n4; o /= _2n2)
      l += _1n4;
    const c1 = l;
    const _2n_pow_c1_1 = _2n2 << c1 - _1n4 - _1n4;
    const _2n_pow_c1 = _2n_pow_c1_1 * _2n2;
    const c2 = (q - _1n4) / _2n_pow_c1;
    const c3 = (c2 - _1n4) / _2n2;
    const c4 = _2n_pow_c1 - _1n4;
    const c5 = _2n_pow_c1_1;
    const c6 = F.pow(Z, c2);
    const c7 = F.pow(Z, (c2 + _1n4) / _2n2);
    let sqrtRatio = (u, v) => {
      let tv1 = c6;
      let tv2 = F.pow(v, c4);
      let tv3 = F.sqr(tv2);
      tv3 = F.mul(tv3, v);
      let tv5 = F.mul(u, tv3);
      tv5 = F.pow(tv5, c3);
      tv5 = F.mul(tv5, tv2);
      tv2 = F.mul(tv5, v);
      tv3 = F.mul(tv5, u);
      let tv4 = F.mul(tv3, tv2);
      tv5 = F.pow(tv4, c5);
      let isQR = F.eql(tv5, F.ONE);
      tv2 = F.mul(tv3, c7);
      tv5 = F.mul(tv4, tv1);
      tv3 = F.cmov(tv2, tv3, isQR);
      tv4 = F.cmov(tv5, tv4, isQR);
      for (let i = c1; i > _1n4; i--) {
        let tv52 = i - _2n2;
        tv52 = _2n2 << tv52 - _1n4;
        let tvv5 = F.pow(tv4, tv52);
        const e1 = F.eql(tvv5, F.ONE);
        tv2 = F.mul(tv3, tv1);
        tv1 = F.mul(tv1, tv1);
        tvv5 = F.mul(tv4, tv1);
        tv3 = F.cmov(tv2, tv3, e1);
        tv4 = F.cmov(tvv5, tv4, e1);
      }
      return { isValid: !F.is0(v) && (isQR || F.is0(u)), value: tv3 };
    };
    if (F.ORDER % _4n3 === _3n2) {
      const c12 = (F.ORDER - _3n2) / _4n3;
      const c22 = F.sqrt(F.neg(Z));
      sqrtRatio = (u, v) => {
        let tv1 = F.sqr(v);
        const tv2 = F.mul(u, v);
        tv1 = F.mul(tv1, tv2);
        let y1 = F.pow(tv1, c12);
        y1 = F.mul(y1, tv2);
        const y2 = F.mul(y1, c22);
        const tv3 = F.mul(F.sqr(y1), v);
        const isQR = F.eql(tv3, u);
        let y = F.cmov(y2, y1, isQR);
        return { isValid: !F.is0(v) && isQR, value: y };
      };
    }
    return sqrtRatio;
  }
  function mapToCurveSimpleSWU(Fp, opts) {
    const F = validateField(Fp);
    validateObject(opts, {}, {}, "opts");
    const { A, B: B2, Z } = opts;
    if (!F.isValidNot0(A) || !F.isValidNot0(B2) || !F.isValid(Z))
      throw new Error("mapToCurveSimpleSWU: invalid opts");
    if (F.eql(Z, F.neg(F.ONE)) || FpIsSquare(F, Z))
      throw new Error("mapToCurveSimpleSWU: invalid opts");
    const x = F.mul(B2, F.inv(F.mul(Z, A)));
    const gx = F.add(F.add(F.mul(F.sqr(x), x), F.mul(A, x)), B2);
    if (!FpIsSquare(F, gx))
      throw new Error("mapToCurveSimpleSWU: invalid opts");
    const sqrtRatio = SWUFpSqrtRatio(F, Z);
    if (!F.isOdd)
      throw new Error("Field does not have .isOdd()");
    return (u) => {
      let tv1, tv2, tv3, tv4, tv5, tv6, x2, y;
      tv1 = F.sqr(u);
      tv1 = F.mul(tv1, Z);
      tv2 = F.sqr(tv1);
      tv2 = F.add(tv2, tv1);
      tv3 = F.add(tv2, F.ONE);
      tv3 = F.mul(tv3, B2);
      tv4 = F.cmov(Z, F.neg(tv2), !F.eql(tv2, F.ZERO));
      tv4 = F.mul(tv4, A);
      tv2 = F.sqr(tv3);
      tv6 = F.sqr(tv4);
      tv5 = F.mul(tv6, A);
      tv2 = F.add(tv2, tv5);
      tv2 = F.mul(tv2, tv3);
      tv6 = F.mul(tv6, tv4);
      tv5 = F.mul(tv6, B2);
      tv2 = F.add(tv2, tv5);
      x2 = F.mul(tv1, tv3);
      const { isValid, value } = sqrtRatio(tv2, tv6);
      y = F.mul(tv1, u);
      y = F.mul(y, value);
      x2 = F.cmov(x2, tv3, isValid);
      y = F.cmov(y, value, isValid);
      const e1 = F.isOdd(u) === F.isOdd(y);
      y = F.cmov(F.neg(y), y, e1);
      const tv4_inv = FpInvertBatch(F, [tv4], true)[0];
      x2 = F.mul(x2, tv4_inv);
      return { x: x2, y };
    };
  }
  var _0n4, _1n4, _2n2, _3n2, _4n3, os2ip, _DST_scalar;
  var init_hash_to_curve = __esm({
    "node_modules/@noble/curves/abstract/hash-to-curve.js"() {
      init_utils2();
      init_modular();
      _0n4 = /* @__PURE__ */ BigInt(0);
      _1n4 = /* @__PURE__ */ BigInt(1);
      _2n2 = /* @__PURE__ */ BigInt(2);
      _3n2 = /* @__PURE__ */ BigInt(3);
      _4n3 = /* @__PURE__ */ BigInt(4);
      os2ip = bytesToNumberBE;
      _DST_scalar = "HashToScalar-";
    }
  });

  // node_modules/@noble/hashes/hmac.js
  var _HMAC, hmac;
  var init_hmac = __esm({
    "node_modules/@noble/hashes/hmac.js"() {
      init_utils();
      _HMAC = class {
        oHash;
        iHash;
        blockLen;
        outputLen;
        canXOF = false;
        finished = false;
        destroyed = false;
        constructor(hash, key) {
          ahash(hash);
          abytes(key, void 0, "key");
          this.iHash = hash.create();
          if (typeof this.iHash.update !== "function")
            throw new Error("expected Hash instance");
          this.blockLen = this.iHash.blockLen;
          this.outputLen = this.iHash.outputLen;
          const blockLen = this.blockLen;
          const pad = new Uint8Array(blockLen);
          pad.set(key.length > blockLen ? hash.create().update(key).digest() : key);
          for (let i = 0; i < pad.length; i++)
            pad[i] ^= 54;
          this.iHash.update(pad);
          this.oHash = hash.create();
          for (let i = 0; i < pad.length; i++)
            pad[i] ^= 54 ^ 92;
          this.oHash.update(pad);
          clean(pad);
        }
        update(buf) {
          aexists(this);
          this.iHash.update(buf);
          return this;
        }
        digestInto(out) {
          aexists(this);
          aoutput(out, this);
          this.finished = true;
          const buf = out.subarray(0, this.outputLen);
          this.iHash.digestInto(buf);
          this.oHash.update(buf);
          this.oHash.digestInto(buf);
          this.destroy();
        }
        digest() {
          const out = new Uint8Array(this.oHash.outputLen);
          this.digestInto(out);
          return out;
        }
        _cloneInto(to) {
          to ||= Object.create(Object.getPrototypeOf(this), {});
          const { oHash, iHash, finished, destroyed, blockLen, outputLen, canXOF } = this;
          to = to;
          to.finished = finished;
          to.destroyed = destroyed;
          to.blockLen = blockLen;
          to.outputLen = outputLen;
          to.canXOF = canXOF;
          to.oHash = oHash._cloneInto(to.oHash);
          to.iHash = iHash._cloneInto(to.iHash);
          return to;
        }
        clone() {
          return this._cloneInto();
        }
        destroy() {
          this.destroyed = true;
          this.oHash.destroy();
          this.iHash.destroy();
        }
      };
      hmac = /* @__PURE__ */ (() => {
        const hmac_ = ((hash, key, message) => new _HMAC(hash, key).update(message).digest());
        hmac_.create = (hash, key) => new _HMAC(hash, key);
        return hmac_;
      })();
    }
  });

  // node_modules/@noble/curves/abstract/der.js
  var _0n5, DERErr, _DER, DER;
  var init_der = __esm({
    "node_modules/@noble/curves/abstract/der.js"() {
      init_utils2();
      _0n5 = /* @__PURE__ */ BigInt(0);
      DERErr = class extends Error {
        constructor(m = "") {
          super(m);
        }
      };
      _DER = {
        // asn.1 DER encoding utils
        Err: DERErr,
        // Basic building block is TLV (Tag-Length-Value)
        _tlv: {
          encode: (tag, data) => {
            const { Err: E } = _DER;
            asafenumber(tag, "tag");
            if (tag < 0 || tag > 255)
              throw new E("tlv.encode: wrong tag");
            astring(data, "data");
            if (data.length & 1)
              throw new E("tlv.encode: unpadded data");
            const dataLen = data.length / 2;
            const len = numberToHexUnpadded(dataLen);
            if (len.length / 2 & 128)
              throw new E("tlv.encode: long form length too big");
            const lenLen = dataLen > 127 ? numberToHexUnpadded(len.length / 2 | 128) : "";
            const t = numberToHexUnpadded(tag);
            return t + lenLen + len + data;
          },
          // v - value, l - left bytes (unparsed)
          decode(tag, data) {
            const { Err: E } = _DER;
            data = abytes2(data, void 0, "DER data");
            let pos = 0;
            if (tag < 0 || tag > 255)
              throw new E("tlv.decode: wrong tag");
            if (data.length < 2 || data[pos++] !== tag)
              throw new E("tlv.decode: wrong tlv");
            const first = data[pos++];
            const isLong = !!(first & 128);
            let length = 0;
            if (!isLong)
              length = first;
            else {
              const lenLen = first & 127;
              if (!lenLen)
                throw new E("tlv.decode(long): indefinite length not supported");
              if (lenLen > 4)
                throw new E("tlv.decode(long): byte length is too big");
              const lengthBytes = data.subarray(pos, pos + lenLen);
              if (lengthBytes.length !== lenLen)
                throw new E("tlv.decode: length bytes not complete");
              if (lengthBytes[0] === 0)
                throw new E("tlv.decode(long): zero leftmost byte");
              for (const b of lengthBytes)
                length = length << 8 | b;
              pos += lenLen;
              if (length < 128)
                throw new E("tlv.decode(long): not minimal encoding");
            }
            const v = data.subarray(pos, pos + length);
            if (v.length !== length)
              throw new E("tlv.decode: wrong value length");
            return { v, l: data.subarray(pos + length) };
          }
        },
        // https://crypto.stackexchange.com/a/57734 Leftmost bit of first byte is 'negative' flag,
        // since we always use positive integers here. It must always be empty:
        // - add zero byte if exists
        // - if next byte doesn't have a flag, leading zero is not allowed (minimal encoding)
        _int: {
          encode(num) {
            const { Err: E } = _DER;
            abignumber(num);
            if (num < _0n5)
              throw new E("integer: negative integers are not allowed");
            let hex = numberToHexUnpadded(num);
            if (Number.parseInt(hex[0], 16) & 8)
              hex = "00" + hex;
            if (hex.length & 1)
              throw new E("unexpected DER parsing assertion: unpadded hex");
            return hex;
          },
          decode(data) {
            const { Err: E } = _DER;
            if (data.length < 1)
              throw new E("invalid signature integer: empty");
            if (data[0] & 128)
              throw new E("invalid signature integer: negative");
            if (data.length > 1 && data[0] === 0 && !(data[1] & 128))
              throw new E("invalid signature integer: unnecessary leading zero");
            return bytesToNumberBE(data);
          }
        },
        toSig(bytes) {
          const { Err: E, _int: int, _tlv: tlv } = _DER;
          const data = abytes2(bytes, void 0, "signature");
          const { v: seqBytes, l: seqLeftBytes } = tlv.decode(48, data);
          if (seqLeftBytes.length)
            throw new E("invalid signature: left bytes after parsing");
          const { v: rBytes, l: rLeftBytes } = tlv.decode(2, seqBytes);
          const { v: sBytes, l: sLeftBytes } = tlv.decode(2, rLeftBytes);
          if (sLeftBytes.length)
            throw new E("invalid signature: left bytes after parsing");
          return { r: int.decode(rBytes), s: int.decode(sBytes) };
        },
        hexFromSig(sig) {
          const { _tlv: tlv, _int: int } = _DER;
          validateObject(sig, { r: "bigint", s: "bigint" }, {}, "sig");
          const rs = tlv.encode(2, int.encode(sig.r));
          const ss = tlv.encode(2, int.encode(sig.s));
          const seq = rs + ss;
          return tlv.encode(48, seq);
        }
      };
      DER = /* @__PURE__ */ (() => {
        Object.freeze(_DER._tlv);
        Object.freeze(_DER._int);
        return Object.freeze(_DER);
      })();
    }
  });

  // node_modules/@noble/curves/abstract/weierstrass.js
  function _splitEndoScalar(k, basis, n) {
    aInRange("scalar", k, _0n6, n);
    const [[a1, b1], [a2, b2]] = basis;
    const c1 = divNearest(b2 * k, n);
    const c2 = divNearest(-b1 * k, n);
    let k1 = k - c1 * a1 - c2 * a2;
    let k2 = -c1 * b1 - c2 * b2;
    const k1neg = k1 < _0n6;
    const k2neg = k2 < _0n6;
    if (k1neg)
      k1 = -k1;
    if (k2neg)
      k2 = -k2;
    const MAX_NUM = bitMask(Math.ceil(bitLen(n) / 2)) + _1n5;
    if (k1 < _0n6 || k1 >= MAX_NUM || k2 < _0n6 || k2 >= MAX_NUM) {
      throw new Error("splitScalar (endomorphism): failed for k");
    }
    return { k1neg, k1, k2neg, k2 };
  }
  function validateSigFormat(format) {
    if (!["compact", "recovered", "der"].includes(format))
      throw new Error('Signature format must be "compact", "recovered", or "der"');
    return format;
  }
  function validateSigOpts(opts, def) {
    validateObject(opts);
    const optsn = {};
    for (let optName of Object.keys(def)) {
      optsn[optName] = opts[optName] === void 0 ? def[optName] : opts[optName];
    }
    abool2(optsn.lowS, "lowS");
    abool2(optsn.prehash, "prehash");
    if (optsn.format !== void 0)
      validateSigFormat(optsn.format);
    return optsn;
  }
  function weierstrass(params, extraOpts = {}) {
    const validated = createCurveFields("weierstrass", params, extraOpts);
    const Fp = validated.Fp;
    const Fn = validated.Fn;
    let CURVE = validated.CURVE;
    const { h: cofactor, n: CURVE_ORDER } = CURVE;
    validateObject(extraOpts, {}, {
      allowInfinityPoint: "boolean",
      clearCofactor: "function",
      isTorsionFree: "function",
      fromBytes: "function",
      toBytes: "function",
      endo: "object",
      randomBytes: "function"
    });
    const { endo, allowInfinityPoint } = extraOpts;
    const randomBytes5 = extraOpts.randomBytes === void 0 ? randomBytes3 : extraOpts.randomBytes;
    if (endo) {
      if (!Fp.is0(CURVE.a) || typeof endo.beta !== "bigint" || !Array.isArray(endo.basises)) {
        throw new Error('invalid endo: expected "beta": bigint and "basises": array');
      }
    }
    const lengths = getWLengths(Fp, Fn);
    function assertCompressionIsSupported() {
      if (!Fp.isOdd)
        throw new Error("compression is not supported: Field does not have .isOdd()");
    }
    function pointToBytes(_c, point, isCompressed) {
      if (allowInfinityPoint && point.is0())
        return Uint8Array.of(0);
      const { x, y } = point.toAffine();
      const bx = Fp.toBytes(x);
      abool2(isCompressed, "isCompressed");
      if (isCompressed) {
        assertCompressionIsSupported();
        const hasEvenY = !Fp.isOdd(y);
        return concatBytes2(pprefix(hasEvenY), bx);
      } else {
        return concatBytes2(Uint8Array.of(4), bx, Fp.toBytes(y));
      }
    }
    function pointFromBytes(bytes) {
      abytes2(bytes, void 0, "Point");
      const { publicKey: comp, publicKeyUncompressed: uncomp } = lengths;
      const length = bytes.length;
      const head = bytes[0];
      const tail = bytes.subarray(1);
      if (allowInfinityPoint && length === 1 && head === 0)
        return { x: Fp.ZERO, y: Fp.ZERO };
      if (length === comp && (head === 2 || head === 3)) {
        const x = Fp.fromBytes(tail);
        if (!Fp.isValid(x))
          throw new Error("bad point: is not on curve, wrong x");
        const y2 = weierstrassEquation(x);
        let y;
        try {
          y = Fp.sqrt(y2);
        } catch (sqrtError) {
          const err = sqrtError instanceof Error ? ": " + sqrtError.message : "";
          throw new Error("bad point: is not on curve, sqrt error" + err);
        }
        assertCompressionIsSupported();
        const evenY = Fp.isOdd(y);
        const evenH = (head & 1) === 1;
        if (evenH !== evenY)
          y = Fp.neg(y);
        return { x, y };
      } else if (length === uncomp && head === 4) {
        const L = Fp.BYTES;
        const x = Fp.fromBytes(tail.subarray(0, L));
        const y = Fp.fromBytes(tail.subarray(L, L * 2));
        if (!isValidXY(x, y))
          throw new Error("bad point: is not on curve");
        return { x, y };
      } else {
        throw new Error(`bad point: got length ${length}, expected compressed=${comp} or uncompressed=${uncomp}`);
      }
    }
    const encodePoint = extraOpts.toBytes === void 0 ? pointToBytes : extraOpts.toBytes;
    const decodePoint = extraOpts.fromBytes === void 0 ? pointFromBytes : extraOpts.fromBytes;
    const b3 = Fp.mul(CURVE.b, _3n3);
    const mulA = Fp.is0(CURVE.a) ? (_) => Fp.ZERO : (x) => Fp.mul(CURVE.a, x);
    function weierstrassEquation(x) {
      const x2 = Fp.sqr(x);
      const x3 = Fp.mul(x2, x);
      return Fp.add(Fp.add(x3, Fp.mul(x, CURVE.a)), CURVE.b);
    }
    function isValidXY(x, y) {
      const left = Fp.sqr(y);
      const right = weierstrassEquation(x);
      return Fp.eql(left, right);
    }
    if (!isValidXY(CURVE.Gx, CURVE.Gy))
      throw new Error("bad curve params: generator point");
    const _4a3 = Fp.mul(Fp.pow(CURVE.a, _3n3), _4n4);
    const _27b2 = Fp.mul(Fp.sqr(CURVE.b), BigInt(27));
    if (Fp.is0(Fp.add(_4a3, _27b2)))
      throw new Error("bad curve params: a or b");
    function acoord(title, n, banZero = false) {
      if (!Fp.isValid(n) || banZero && Fp.is0(n))
        throw new Error(`bad point coordinate ${title}`);
      return n;
    }
    function aprjpoint(other) {
      if (!(other instanceof Point))
        throw new Error("Weierstrass Point expected");
    }
    function splitEndoScalarN(k) {
      if (!endo || !endo.basises)
        throw new Error("no endo");
      return _splitEndoScalar(k, endo.basises, Fn.ORDER);
    }
    function pushWnafPair(points, scalars, p, k) {
      if (!Fn.isValid(k))
        throw new RangeError("invalid scalar: out of range");
      if (endo) {
        const { k1neg, k1, k2neg, k2 } = splitEndoScalarN(k);
        const psi = new Point(Fp.mul(p.X, endo.beta), p.Y, p.Z);
        points.push(k1neg ? p.negate() : p, k2neg ? psi.negate() : psi);
        scalars.push(k1, k2);
      } else {
        points.push(p);
        scalars.push(k);
      }
    }
    const validityCache = /* @__PURE__ */ new WeakSet();
    class Point {
      static BASE = new Point(CURVE.Gx, CURVE.Gy, Fp.ONE);
      static ZERO = new Point(Fp.ZERO, Fp.ONE, Fp.ZERO);
      static Fp = Fp;
      static Fn = Fn;
      X;
      Y;
      Z;
      /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
      constructor(X, Y, Z) {
        this.X = acoord("x", X);
        this.Y = acoord("y", Y, true);
        this.Z = acoord("z", Z);
        Object.freeze(this);
      }
      static CURVE() {
        return CURVE;
      }
      /** Does NOT validate if the point is valid. Use `.assertValidity()`. */
      static fromAffine(p) {
        const { x, y } = p || {};
        if (!p || !Fp.isValid(x) || !Fp.isValid(y))
          throw new Error("invalid affine point");
        if (p instanceof Point)
          throw new Error("projective point not allowed");
        if (Fp.is0(x) && Fp.is0(y))
          return Point.ZERO;
        return new Point(x, y, Fp.ONE);
      }
      static fromBytes(bytes) {
        const P = Point.fromAffine(decodePoint(abytes2(bytes, void 0, "point")));
        P.assertValidity();
        return P;
      }
      static fromHex(hex) {
        return Point.fromBytes(hexToBytes2(hex));
      }
      get x() {
        return this.toAffine().x;
      }
      get y() {
        return this.toAffine().y;
      }
      /**
       * @param isLazy - true will defer table computation until the first multiplication
       */
      precompute(windowSize = 6, isLazy = true) {
        wnaf.setWindowSize(this, windowSize);
        if (!isLazy)
          this.multiply(_3n3);
        return this;
      }
      // TODO: return `this`
      /** A point on curve is valid if it conforms to equation. */
      assertValidity() {
        const p = this;
        if (p.is0()) {
          if (extraOpts.allowInfinityPoint && Fp.is0(p.X) && Fp.eql(p.Y, Fp.ONE) && Fp.is0(p.Z))
            return;
          throw new Error("bad point: ZERO");
        }
        if (validityCache.has(p))
          return;
        const { x, y } = p.toAffine();
        if (!Fp.isValid(x) || !Fp.isValid(y))
          throw new Error("bad point: x or y not field elements");
        if (!isValidXY(x, y))
          throw new Error("bad point: equation left != right");
        if (!p.isTorsionFree())
          throw new Error("bad point: not in prime-order subgroup");
        validityCache.add(p);
      }
      hasEvenY() {
        const { y } = this.toAffine();
        if (!Fp.isOdd)
          throw new Error("Field doesn't support isOdd");
        return !Fp.isOdd(y);
      }
      /** Compare one point to another. */
      equals(other) {
        aprjpoint(other);
        const { X: X1, Y: Y1, Z: Z1 } = this;
        const { X: X2, Y: Y2, Z: Z2 } = other;
        const U1 = Fp.eql(Fp.mul(X1, Z2), Fp.mul(X2, Z1));
        const U2 = Fp.eql(Fp.mul(Y1, Z2), Fp.mul(Y2, Z1));
        return U1 && U2;
      }
      /** Flips point to one corresponding to (x, -y) in Affine coordinates. */
      negate() {
        return new Point(this.X, Fp.neg(this.Y), this.Z);
      }
      // Renes-Costello-Batina exception-free doubling formula.
      // There is 30% faster Jacobian formula, but it is not complete.
      // https://eprint.iacr.org/2015/1060, algorithm 3
      // Cost: 8M + 3S + 3*a + 2*b3 + 15add.
      double() {
        const { X: X1, Y: Y1, Z: Z1 } = this;
        let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO;
        let t0 = Fp.mul(X1, X1);
        let t1 = Fp.mul(Y1, Y1);
        let t2 = Fp.mul(Z1, Z1);
        let t3 = Fp.mul(X1, Y1);
        t3 = Fp.add(t3, t3);
        Z3 = Fp.mul(X1, Z1);
        Z3 = Fp.add(Z3, Z3);
        X3 = mulA(Z3);
        Y3 = Fp.mul(b3, t2);
        Y3 = Fp.add(X3, Y3);
        X3 = Fp.sub(t1, Y3);
        Y3 = Fp.add(t1, Y3);
        Y3 = Fp.mul(X3, Y3);
        X3 = Fp.mul(t3, X3);
        Z3 = Fp.mul(b3, Z3);
        t2 = mulA(t2);
        t3 = Fp.sub(t0, t2);
        t3 = mulA(t3);
        t3 = Fp.add(t3, Z3);
        Z3 = Fp.add(t0, t0);
        t0 = Fp.add(Z3, t0);
        t0 = Fp.add(t0, t2);
        t0 = Fp.mul(t0, t3);
        Y3 = Fp.add(Y3, t0);
        t2 = Fp.mul(Y1, Z1);
        t2 = Fp.add(t2, t2);
        t0 = Fp.mul(t2, t3);
        X3 = Fp.sub(X3, t0);
        Z3 = Fp.mul(t2, t1);
        Z3 = Fp.add(Z3, Z3);
        Z3 = Fp.add(Z3, Z3);
        return new Point(X3, Y3, Z3);
      }
      // Renes-Costello-Batina exception-free addition formula.
      // There is 30% faster Jacobian formula, but it is not complete.
      // https://eprint.iacr.org/2015/1060, algorithm 1
      // Cost: 12M + 0S + 3*a + 3*b3 + 23add.
      add(other) {
        aprjpoint(other);
        const { X: X1, Y: Y1, Z: Z1 } = this;
        const { X: X2, Y: Y2, Z: Z2 } = other;
        let X3 = Fp.ZERO, Y3 = Fp.ZERO, Z3 = Fp.ZERO;
        let t0 = Fp.mul(X1, X2);
        let t1 = Fp.mul(Y1, Y2);
        let t2 = Fp.mul(Z1, Z2);
        let t3 = Fp.add(X1, Y1);
        let t4 = Fp.add(X2, Y2);
        t3 = Fp.mul(t3, t4);
        t4 = Fp.add(t0, t1);
        t3 = Fp.sub(t3, t4);
        t4 = Fp.add(X1, Z1);
        let t5 = Fp.add(X2, Z2);
        t4 = Fp.mul(t4, t5);
        t5 = Fp.add(t0, t2);
        t4 = Fp.sub(t4, t5);
        t5 = Fp.add(Y1, Z1);
        X3 = Fp.add(Y2, Z2);
        t5 = Fp.mul(t5, X3);
        X3 = Fp.add(t1, t2);
        t5 = Fp.sub(t5, X3);
        Z3 = mulA(t4);
        X3 = Fp.mul(b3, t2);
        Z3 = Fp.add(X3, Z3);
        X3 = Fp.sub(t1, Z3);
        Z3 = Fp.add(t1, Z3);
        Y3 = Fp.mul(X3, Z3);
        t1 = Fp.add(t0, t0);
        t1 = Fp.add(t1, t0);
        t2 = mulA(t2);
        t4 = Fp.mul(b3, t4);
        t1 = Fp.add(t1, t2);
        t2 = Fp.sub(t0, t2);
        t2 = mulA(t2);
        t4 = Fp.add(t4, t2);
        t0 = Fp.mul(t1, t4);
        Y3 = Fp.add(Y3, t0);
        t0 = Fp.mul(t5, t4);
        X3 = Fp.mul(t3, X3);
        X3 = Fp.sub(X3, t0);
        t0 = Fp.mul(t3, t1);
        Z3 = Fp.mul(t5, Z3);
        Z3 = Fp.add(Z3, t0);
        return new Point(X3, Y3, Z3);
      }
      subtract(other) {
        aprjpoint(other);
        return this.add(other.negate());
      }
      is0() {
        return this.equals(Point.ZERO);
      }
      /**
       * Constant time multiplication.
       * Uses precomputed tables (signed fixed-window wNAF) when available.
       * Uses scalar blinding and avoids endomorphism splitting in the secret-scalar path.
       * @param scalar - by which the point would be multiplied
       * @returns New point
       */
      multiply(scalar) {
        if (!Fn.isValidNot0(scalar))
          throw new RangeError("invalid scalar: out of range");
        const { p, f } = wnaf.mulSecret(this, scalar, cofactor, normalize);
        return normalize([p, f])[0];
      }
      /**
       * Non-constant-time multiplication. Uses width-4 wNAF with GLV endomorphism splitting
       * when available (two half-width scalars sharing one halved doubling chain).
       * It's faster, but should only be used when you don't care about
       * an exposed secret key e.g. sig verification, which works over *public* keys.
       */
      multiplyUnsafe(scalar) {
        const p = this;
        const sc = scalar;
        if (!Fn.isValid(sc))
          throw new RangeError("invalid scalar: out of range");
        if (sc === _0n6 || p.is0())
          return Point.ZERO;
        if (sc === _1n5)
          return p;
        if (wnaf.hasWindowSize(this))
          return wnaf.mulUnsafe(p, sc, normalize);
        const points = [];
        const scalars = [];
        pushWnafPair(points, scalars, p, sc);
        return mulAddUnsafe(Point, points, scalars);
      }
      /**
       * Non-constant-time double-scalar multiplication `a⋅this + b⋅other` (Strauss–Shamir).
       * Both walks share one doubling chain via {@link mulAddUnsafe}, and GLV endomorphism
       * (when available) halves the chain again by splitting each scalar into two half-width
       * parts. Used by ECDSA verification and public-key recovery for `R = u1⋅G + u2⋅P`.
       * Only for public scalars.
       */
      mulAddUnsafe(a, other, b) {
        aprjpoint(other);
        const points = [];
        const scalars = [];
        pushWnafPair(points, scalars, this, a);
        pushWnafPair(points, scalars, other, b);
        return mulAddUnsafe(Point, points, scalars);
      }
      /**
       * Converts Projective point to affine (x, y) coordinates.
       * (X, Y, Z) ∋ (x=X/Z, y=Y/Z).
       * @param invertedZ - Z^-1 (inverted zero) - optional, precomputation is useful for invertBatch
       */
      toAffine(invertedZ) {
        const p = this;
        let iz = invertedZ;
        if (iz != null && !Fp.isValid(iz))
          throw new RangeError('"invertedZ" expected valid field element');
        const { X, Y, Z } = p;
        if (Fp.eql(Z, Fp.ONE))
          return { x: X, y: Y };
        const is0 = p.is0();
        if (iz == null)
          iz = is0 ? Fp.ONE : Fp.inv(Z);
        const x = Fp.mul(X, iz);
        const y = Fp.mul(Y, iz);
        const zz = Fp.mul(Z, iz);
        if (is0)
          return { x: Fp.ZERO, y: Fp.ZERO };
        if (!Fp.eql(zz, Fp.ONE))
          throw new Error("invZ was invalid");
        return { x, y };
      }
      /**
       * Checks whether Point is free of torsion elements (is in prime subgroup).
       * Always torsion-free for cofactor=1 curves.
       */
      isTorsionFree() {
        const { isTorsionFree } = extraOpts;
        if (cofactor === _1n5)
          return true;
        if (isTorsionFree)
          return isTorsionFree(Point, this);
        return wnaf.mulUnsafe(this, CURVE_ORDER).is0();
      }
      clearCofactor() {
        const { clearCofactor } = extraOpts;
        if (cofactor === _1n5)
          return this;
        if (clearCofactor)
          return clearCofactor(Point, this);
        return this.multiplyUnsafe(cofactor);
      }
      isSmallOrder() {
        if (cofactor === _1n5)
          return this.is0();
        return this.clearCofactor().is0();
      }
      toBytes(isCompressed = true) {
        abool2(isCompressed, "isCompressed");
        this.assertValidity();
        return encodePoint(Point, this, isCompressed);
      }
      toHex(isCompressed = true) {
        return bytesToHex2(this.toBytes(isCompressed));
      }
      toString() {
        return `<Point ${this.is0() ? "ZERO" : this.toHex()}>`;
      }
    }
    const normalize = (points) => normalizeZ(Point, points);
    const wnaf = new ScalarMultiplier(Point, randomBytes5);
    if (wnaf.bits >= 6)
      Point.BASE.precompute(6);
    Object.freeze(Point.prototype);
    Object.freeze(Point);
    return Point;
  }
  function pprefix(hasEvenY) {
    return Uint8Array.of(hasEvenY ? 2 : 3);
  }
  function getWLengths(Fp, Fn) {
    return {
      secretKey: Fn.BYTES,
      publicKey: 1 + Fp.BYTES,
      publicKeyUncompressed: 1 + 2 * Fp.BYTES,
      publicKeyHasPrefix: true,
      // Raw compact `(r || s)` signature width; DER and recovered signatures use
      // different lengths outside this helper.
      signature: 2 * Fn.BYTES
    };
  }
  function ecdh(Point, ecdhOpts = {}) {
    validatePointCons(Point);
    const { Fn } = Point;
    const randomBytes_ = ecdhOpts.randomBytes === void 0 ? randomBytes3 : ecdhOpts.randomBytes;
    const lengths = Object.assign(getWLengths(Point.Fp, Fn), {
      seed: Math.max(getMinHashLength(Fn.ORDER), 16)
    });
    function isValidSecretKey(secretKey) {
      try {
        const num = Fn.fromBytes(secretKey);
        return Fn.isValidNot0(num);
      } catch (error) {
        return false;
      }
    }
    function isValidPublicKey(publicKey, isCompressed) {
      const { publicKey: comp, publicKeyUncompressed } = lengths;
      try {
        const l = publicKey.length;
        if (isCompressed === true && l !== comp)
          return false;
        if (isCompressed === false && l !== publicKeyUncompressed)
          return false;
        return !!Point.fromBytes(publicKey);
      } catch (error) {
        return false;
      }
    }
    function randomSecretKey(seed) {
      seed = seed === void 0 ? randomBytes_(lengths.seed) : seed;
      return mapHashToField(abytes2(seed, lengths.seed, "seed"), Fn.ORDER);
    }
    function getPublicKey(secretKey, isCompressed = true) {
      return Point.BASE.multiply(Fn.fromBytes(secretKey)).toBytes(isCompressed);
    }
    function isProbPub(item) {
      const { secretKey, publicKey, publicKeyUncompressed } = lengths;
      const allowedLengths = Fn._lengths;
      if (!isBytes2(item))
        return void 0;
      const l = abytes2(item, void 0, "key").length;
      const isPub = l === publicKey || l === publicKeyUncompressed;
      const isSec = l === secretKey || !!allowedLengths?.includes(l);
      if (isPub && isSec)
        return void 0;
      return isPub;
    }
    function getSharedSecret(secretKeyA, publicKeyB, isCompressed = true) {
      if (isProbPub(secretKeyA) === true)
        throw new Error("first arg must be private key");
      if (isProbPub(publicKeyB) === false)
        throw new Error("second arg must be public key");
      const s = Fn.fromBytes(secretKeyA);
      const b = Point.fromBytes(publicKeyB);
      return b.multiply(s).toBytes(isCompressed);
    }
    const utils = {
      isValidSecretKey,
      isValidPublicKey,
      randomSecretKey
    };
    const keygen = createKeygen(randomSecretKey, getPublicKey);
    Object.freeze(utils);
    Object.freeze(lengths);
    return Object.freeze({ getPublicKey, getSharedSecret, keygen, Point, utils, lengths });
  }
  function ecdsa(Point, hash, ecdsaOpts = {}) {
    validatePointCons(Point);
    const hash_ = hash;
    ahash(hash_);
    validateObject(ecdsaOpts, {}, {
      hmac: "function",
      lowS: "boolean",
      randomBytes: "function",
      bits2int: "function",
      bits2int_modN: "function"
    });
    const opts = Object.assign({}, ecdsaOpts);
    const randomBytes5 = opts.randomBytes === void 0 ? randomBytes3 : opts.randomBytes;
    const hmac2 = opts.hmac === void 0 ? (key, msg) => hmac(hash_, key, msg) : opts.hmac;
    const { Fp, Fn } = Point;
    const { ORDER: CURVE_ORDER, BITS: fnBits } = Fn;
    const blindLength = getMinHashLength(CURVE_ORDER);
    const csprng = probeRandomBytes(randomBytes5, blindLength);
    const { keygen, getPublicKey, getSharedSecret, utils, lengths } = ecdh(Point, opts);
    const defaultSigOpts = {
      prehash: true,
      lowS: typeof opts.lowS === "boolean" ? opts.lowS : true,
      format: "compact",
      extraEntropy: false
    };
    const hasLargeRecoveryLifts = CURVE_ORDER * _2n3 + _1n5 < Fp.ORDER;
    function isBiggerThanHalfOrder(number) {
      const HALF = CURVE_ORDER >> _1n5;
      return number > HALF;
    }
    function validateRS(title, num) {
      if (!Fn.isValidNot0(num))
        throw new Error(`invalid signature ${title}: out of range 1..Point.Fn.ORDER`);
      return num;
    }
    function assertFieldSignIsSupported() {
      if (!Fp.isOdd)
        throw new Error("Field doesn't support isOdd");
    }
    function getRecoveryBit(x, y, r) {
      assertFieldSignIsSupported();
      return (x === r ? 0 : 2) | Number(Fp.isOdd(y));
    }
    function assertRecoverableCurve() {
      if (hasLargeRecoveryLifts)
        throw new Error('"recovered" sig type is not supported for cofactor >2 curves');
    }
    function validateSigLength(bytes, format) {
      validateSigFormat(format);
      const size = lengths.signature;
      const sizer = format === "compact" ? size : format === "recovered" ? size + 1 : void 0;
      return abytes2(bytes, sizer);
    }
    class Signature {
      r;
      s;
      recovery;
      constructor(r, s, recovery) {
        this.r = validateRS("r", r);
        this.s = validateRS("s", s);
        if (recovery != null) {
          assertRecoverableCurve();
          if (![0, 1, 2, 3].includes(recovery))
            throw new Error("invalid recovery id");
          this.recovery = recovery;
        }
        Object.freeze(this);
      }
      static fromBytes(bytes, format = defaultSigOpts.format) {
        validateSigLength(bytes, format);
        let recid;
        if (format === "der") {
          const { r: r2, s: s2 } = DER.toSig(abytes2(bytes));
          return new Signature(r2, s2);
        }
        if (format === "recovered") {
          recid = bytes[0];
          format = "compact";
          bytes = bytes.subarray(1);
        }
        const L = lengths.signature / 2;
        const r = bytes.subarray(0, L);
        const s = bytes.subarray(L, L * 2);
        return new Signature(Fn.fromBytes(r), Fn.fromBytes(s), recid);
      }
      static fromHex(hex, format) {
        return this.fromBytes(hexToBytes2(hex), format);
      }
      assertRecovery() {
        const { recovery } = this;
        if (recovery == null)
          throw new Error("invalid recovery id: must be present");
        return recovery;
      }
      addRecoveryBit(recovery) {
        return new Signature(this.r, this.s, recovery);
      }
      // Unlike the top-level helper below, this method expects a digest that has
      // already been hashed to the curve's message representative.
      recoverPublicKey(messageHash) {
        const { r, s } = this;
        const recovery = this.assertRecovery();
        const radj = recovery === 2 || recovery === 3 ? r + CURVE_ORDER : r;
        if (!Fp.isValid(radj))
          throw new Error("invalid recovery id: sig.r+curve.n != R.x");
        const x = Fp.toBytes(radj);
        const R = Point.fromBytes(concatBytes2(pprefix((recovery & 1) === 0), x));
        const ir = Fn.inv(radj);
        const h = bits2int_modN(abytes2(messageHash, void 0, "msgHash"));
        const u1 = Fn.create(-h * ir);
        const u2 = Fn.create(s * ir);
        const Q = Point.BASE.mulAddUnsafe(u1, R, u2);
        if (Q.is0())
          throw new Error("invalid recovery: point at infinify");
        Q.assertValidity();
        return Q;
      }
      // Signatures should be low-s, to prevent malleability.
      hasHighS() {
        return isBiggerThanHalfOrder(this.s);
      }
      toBytes(format = defaultSigOpts.format) {
        validateSigFormat(format);
        if (format === "der")
          return hexToBytes2(DER.hexFromSig(this));
        const { r, s } = this;
        const rb = Fn.toBytes(r);
        const sb = Fn.toBytes(s);
        if (format === "recovered") {
          assertRecoverableCurve();
          return concatBytes2(Uint8Array.of(this.assertRecovery()), rb, sb);
        }
        return concatBytes2(rb, sb);
      }
      toHex(format) {
        return bytesToHex2(this.toBytes(format));
      }
    }
    Object.freeze(Signature.prototype);
    Object.freeze(Signature);
    const bits2int = opts.bits2int === void 0 ? function bits2int_def(bytes) {
      if (bytes.length > 8192)
        throw new Error("input is too large");
      const num = bytesToNumberBE(bytes);
      const delta = bytes.length * 8 - fnBits;
      return delta > 0 ? num >> BigInt(delta) : num;
    } : opts.bits2int;
    const bits2int_modN = opts.bits2int_modN === void 0 ? function bits2int_modN_def(bytes) {
      return Fn.create(bits2int(bytes));
    } : opts.bits2int_modN;
    const ORDER_MASK = bitMask(fnBits);
    function int2octets(num) {
      aInRange("num < 2^" + fnBits, num, _0n6, ORDER_MASK);
      return Fn.toBytes(num);
    }
    function validateMsgAndHash(message, prehash) {
      abytes2(message, void 0, "message");
      return prehash ? abytes2(hash_(message), void 0, "prehashed message") : message;
    }
    function prepSig(message, secretKey, opts2) {
      const { lowS, prehash, extraEntropy } = validateSigOpts(opts2, defaultSigOpts);
      message = validateMsgAndHash(message, prehash);
      const h1int = bits2int_modN(message);
      const d = Fn.fromBytes(secretKey);
      if (!Fn.isValidNot0(d))
        throw new Error("invalid private key");
      const seedArgs = [int2octets(d), int2octets(h1int)];
      if (extraEntropy != null && extraEntropy !== false) {
        const e = extraEntropy === true ? randomBytes5(lengths.secretKey) : extraEntropy;
        seedArgs.push(abytes2(e, void 0, "extraEntropy"));
      }
      const seed = concatBytes2(...seedArgs);
      const m = h1int;
      function k2sig(kBytes) {
        const k = bits2int(kBytes);
        if (!Fn.isValidNot0(k))
          return;
        const q = Point.BASE.multiply(k).toAffine();
        const r = Fn.create(q.x);
        if (r === _0n6)
          return;
        let s;
        if (csprng !== void 0) {
          const b = bytesToNumberBE(mapHashToField(csprng(blindLength), CURVE_ORDER));
          const ibk = Fn.inv(Fn.mul(b, k));
          const bm = Fn.mul(b, m);
          const bd = Fn.mul(b, d);
          s = Fn.create(ibk * Fn.create(bm + bd * r));
        } else {
          const ik = invertCt(k, CURVE_ORDER);
          s = Fn.create(ik * Fn.create(m + r * d));
        }
        if (s === _0n6)
          return;
        let recovery = getRecoveryBit(q.x, q.y, r);
        let normS = s;
        if (lowS && isBiggerThanHalfOrder(s)) {
          normS = Fn.neg(s);
          recovery ^= 1;
        }
        return new Signature(r, normS, hasLargeRecoveryLifts ? void 0 : recovery);
      }
      return { seed, k2sig };
    }
    function sign(message, secretKey, opts2 = {}) {
      const { seed, k2sig } = prepSig(message, secretKey, opts2);
      const drbg = createHmacDrbg(hash_.outputLen, Fn.BYTES, hmac2);
      const sig = drbg(seed, k2sig);
      return sig.toBytes(opts2.format);
    }
    function verify(signature, message, publicKey, opts2 = {}) {
      const { lowS, prehash, format } = validateSigOpts(opts2, defaultSigOpts);
      publicKey = abytes2(publicKey, void 0, "publicKey");
      message = validateMsgAndHash(message, prehash);
      if (!isBytes2(signature)) {
        const end = signature instanceof Signature ? ", use sig.toBytes()" : "";
        throw new Error("verify expects Uint8Array signature" + end);
      }
      validateSigLength(signature, format);
      try {
        const sig = Signature.fromBytes(signature, format);
        const P = Point.fromBytes(publicKey);
        if (lowS && sig.hasHighS())
          return false;
        const { r, s } = sig;
        const h = bits2int_modN(message);
        const is = Fn.inv(s);
        const u1 = Fn.create(h * is);
        const u2 = Fn.create(r * is);
        const R = Point.BASE.mulAddUnsafe(u1, P, u2);
        if (R.is0())
          return false;
        const q = R.toAffine();
        const v = Fn.create(q.x);
        if (v !== r)
          return false;
        if (format === "recovered" && sig.recovery !== getRecoveryBit(q.x, q.y, r))
          return false;
        return true;
      } catch (e) {
        return false;
      }
    }
    function recoverPublicKey(signature, message, opts2 = {}) {
      const { prehash } = validateSigOpts(opts2, defaultSigOpts);
      message = validateMsgAndHash(message, prehash);
      return Signature.fromBytes(signature, "recovered").recoverPublicKey(message).toBytes();
    }
    return Object.freeze({
      keygen,
      getPublicKey,
      getSharedSecret,
      utils,
      lengths,
      Point,
      sign,
      verify,
      recoverPublicKey,
      Signature,
      hash: hash_
    });
  }
  var divNearest, _0n6, _1n5, _2n3, _3n3, _4n4;
  var init_weierstrass = __esm({
    "node_modules/@noble/curves/abstract/weierstrass.js"() {
      init_hmac();
      init_utils();
      init_utils2();
      init_curve();
      init_der();
      init_modular();
      divNearest = (num, den) => (num + (num >= 0 ? den : -den) / _2n3) / den;
      _0n6 = /* @__PURE__ */ BigInt(0);
      _1n5 = /* @__PURE__ */ BigInt(1);
      _2n3 = /* @__PURE__ */ BigInt(2);
      _3n3 = /* @__PURE__ */ BigInt(3);
      _4n4 = /* @__PURE__ */ BigInt(4);
    }
  });

  // node_modules/@noble/curves/secp256k1.js
  function sqrtMod(y) {
    const P = secp256k1_CURVE.p;
    const _3n4 = BigInt(3), _6n = BigInt(6), _11n = BigInt(11), _22n = BigInt(22);
    const _23n = BigInt(23), _44n = BigInt(44), _88n = BigInt(88);
    const b2 = y * y * y % P;
    const b3 = b2 * b2 * y % P;
    const b6 = pow2(b3, _3n4, P) * b3 % P;
    const b9 = pow2(b6, _3n4, P) * b3 % P;
    const b11 = pow2(b9, _2n4, P) * b2 % P;
    const b22 = pow2(b11, _11n, P) * b11 % P;
    const b44 = pow2(b22, _22n, P) * b22 % P;
    const b88 = pow2(b44, _44n, P) * b44 % P;
    const b176 = pow2(b88, _88n, P) * b88 % P;
    const b220 = pow2(b176, _44n, P) * b44 % P;
    const b223 = pow2(b220, _3n4, P) * b3 % P;
    const t1 = pow2(b223, _23n, P) * b22 % P;
    const t2 = pow2(t1, _6n, P) * b2 % P;
    const root2 = pow2(t2, _2n4, P);
    if (!Fpk1.eql(Fpk1.sqr(root2), y))
      throw new Error("Cannot find square root");
    return root2;
  }
  var secp256k1_CURVE, secp256k1_ENDO, _2n4, Fpk1, Pointk1, secp256k1, isoMap, mapSWU, getMapSWU, secp256k1_hasher;
  var init_secp256k1 = __esm({
    "node_modules/@noble/curves/secp256k1.js"() {
      init_sha2();
      init_hash_to_curve();
      init_modular();
      init_weierstrass();
      secp256k1_CURVE = {
        p: BigInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
        n: BigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
        h: BigInt(1),
        a: BigInt(0),
        b: BigInt(7),
        Gx: BigInt("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        Gy: BigInt("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
      };
      secp256k1_ENDO = {
        beta: BigInt("0x7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee"),
        basises: [
          [BigInt("0x3086d221a7d46bcde86c90e49284eb15"), -BigInt("0xe4437ed6010e88286f547fa90abfe4c3")],
          [BigInt("0x114ca50f7a8e2f3f657c1108d9d44cfd8"), BigInt("0x3086d221a7d46bcde86c90e49284eb15")]
        ]
      };
      _2n4 = /* @__PURE__ */ BigInt(2);
      Fpk1 = /* @__PURE__ */ Field(secp256k1_CURVE.p, { sqrt: sqrtMod });
      Pointk1 = /* @__PURE__ */ weierstrass(secp256k1_CURVE, {
        Fp: Fpk1,
        endo: secp256k1_ENDO
      });
      secp256k1 = /* @__PURE__ */ ecdsa(Pointk1, sha256);
      isoMap = /* @__PURE__ */ (() => isogenyMap(Fpk1, [
        // xNum
        [
          "0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7",
          "0x7d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581",
          "0x534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262",
          "0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c"
        ],
        // xDen
        [
          "0xd35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b",
          "0xedadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14",
          "0x0000000000000000000000000000000000000000000000000000000000000001"
          // LAST 1
        ],
        // yNum
        [
          "0x4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c",
          "0xc75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3",
          "0x29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931",
          "0x2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84"
        ],
        // yDen
        [
          "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b",
          "0x7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573",
          "0x6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f",
          "0x0000000000000000000000000000000000000000000000000000000000000001"
          // LAST 1
        ]
      ].map((i) => i.map((j) => BigInt(j)))))();
      getMapSWU = () => mapSWU || (mapSWU = mapToCurveSimpleSWU(Fpk1, {
        // Building the SWU sqrt-ratio helper eagerly adds noticeable `secp256k1.js` import cost, so
        // defer it to first use; after that the cached mapper is reused directly.
        A: BigInt("0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533"),
        B: BigInt("1771"),
        Z: Fpk1.create(BigInt("-11"))
      }));
      secp256k1_hasher = /* @__PURE__ */ (() => createHasher2(Pointk1, (scalars) => {
        const { x, y } = getMapSWU()(Fpk1.create(scalars[0]));
        return isoMap(x, y);
      }, {
        DST: "secp256k1_XMD:SHA-256_SSWU_RO_",
        encodeDST: "secp256k1_XMD:SHA-256_SSWU_NU_",
        p: Fpk1.ORDER,
        m: 1,
        k: 128,
        expand: "xmd",
        hash: sha256
      }))();
    }
  });

  // src/crypto/curve.js
  function mod2(x) {
    const r = x % ORDER;
    return r < 0n ? r + ORDER : r;
  }
  function randomScalar() {
    const bytes = secp256k1.utils.randomSecretKey();
    return bytesToScalar(bytes);
  }
  function bytesToScalar(bytes) {
    let x = 0n;
    for (const b of bytes) x = x << 8n | BigInt(b);
    return mod2(x);
  }
  function pointToHex(point) {
    return point.toHex(true);
  }
  function scalarToHex(scalar) {
    let hex = mod2(scalar).toString(16);
    while (hex.length < 64) hex = "0" + hex;
    return hex;
  }
  function hexToBytes3(hex) {
    const clean2 = hex.length % 2 ? "0" + hex : hex;
    const bytes = new Uint8Array(clean2.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean2.slice(i * 2, i * 2 + 2), 16);
    return bytes;
  }
  function bytesToHex3(bytes) {
    let out = "";
    for (const b of bytes) out += HEX_CHARS[b >> 4] + HEX_CHARS[b & 15];
    return out;
  }
  function generateIdentityKeypair() {
    const privateScalar = randomScalar();
    const publicPoint = G.multiply(privateScalar);
    return {
      privateKeyHex: scalarToHex(privateScalar),
      publicKeyHex: pointToHex(publicPoint)
    };
  }
  function modPow(base, exp) {
    let result = 1n;
    let b = mod2(base);
    let e = exp;
    while (e > 0n) {
      if (e & 1n) result = mod2(result * b);
      b = mod2(b * b);
      e >>= 1n;
    }
    return result;
  }
  function modInverse(x) {
    const xr = mod2(x);
    if (xr === 0n) throw new RangeError("modInverse: 0 has no inverse");
    return modPow(xr, ORDER - 2n);
  }
  var ORDER, G, H, HEX_CHARS;
  var init_curve2 = __esm({
    "src/crypto/curve.js"() {
      init_secp256k1();
      ORDER = secp256k1.Point.Fn.ORDER;
      G = secp256k1.Point.BASE;
      H = secp256k1_hasher.hashToCurve(
        new TextEncoder().encode("ZRDCP/1.0 Pedersen generator h \u2014 nothing-up-my-sleeve")
      );
      HEX_CHARS = "0123456789abcdef";
    }
  });

  // src/vault/store.js
  function storageKeyFor(vaultName) {
    return `identt.vault.${encodeURIComponent(vaultName)}.sealed.v1`;
  }
  function createVaultStore(storageAdapter, vaultName) {
    const STORAGE_KEY = storageKeyFor(vaultName);
    return {
      /** True if this named vault has been created before (does not require any secret to check). */
      async exists() {
        return await storageAdapter.getItem(STORAGE_KEY) !== null;
      },
      /**
       * Creates a brand-new empty registry, seals it under `passphrase`, and persists it. Overwrites
       * any existing vault of this name. Also generates this device's own persistent ZRDCP identity
       * keypair (`registry.localIdentity`) — distinct from the trusted-device list, which holds
       * OTHER devices' public keys. This is the key every outgoing share gets wrapped with (see
       * src/crypto/shareWrap.js).
       */
      async createNew(passphrase, initialThreshold) {
        const registry = { ...createRegistry(initialThreshold), localIdentity: generateIdentityKeypair() };
        await this.save(passphrase, registry);
        return registry;
      },
      /**
       * Opens the persisted vault with `passphrase`, returning the plain registry object.
       * Transparently migrates older vaults so they keep working without user action:
       *   - vaults created before `localIdentity` existed (Phase 1) get one generated;
       *   - vaults created before the authentication/recovery threshold split existed (Phase 2's
       *     single `threshold.k`) get mapped onto the new shape: `kAuthentication` defaults to 2,
       *     `kRecovery` becomes `max(old k, 3)`, `minRemoteForRecovery` defaults to 1, and
       *     `targetN` gets clamped into the now-required 4-9 range.
       */
      async load(passphrase) {
        const raw = await storageAdapter.getItem(STORAGE_KEY);
        if (raw === null) throw new Error("No vault exists yet \u2014 call createNew() first.");
        const sealedVault = JSON.parse(raw);
        const registry = await open(passphrase, sealedVault);
        return this._migrate(registry, (r) => this.save(passphrase, r));
      },
      /** Same as `load()`, but for a `recovery`-unlock-policy vault: opens with a raw HKDF key
       * (see `src/vault/vault.js`'s `sealWithKey`/`openWithKey`) instead of a passphrase — the key
       * a successful mesh reconstruction produces (`src/vault/unlockRecovery.js`). */
      async loadWithKey(keyHex) {
        const raw = await storageAdapter.getItem(STORAGE_KEY);
        if (raw === null) throw new Error("No vault exists yet \u2014 call createNew() first.");
        const sealedVault = JSON.parse(raw);
        const registry = await openWithKey(keyHex, sealedVault);
        return this._migrate(registry, (r) => this.saveWithKey(keyHex, r));
      },
      async _migrate(registry, resave) {
        let needsSave = false;
        if (!registry.localIdentity) {
          registry.localIdentity = generateIdentityKeypair();
          needsSave = true;
        }
        if (!registry.threshold || !("kAuthentication" in registry.threshold)) {
          const old = registry.threshold || {};
          registry.threshold = {
            targetN: Math.min(Math.max(old.targetN ?? 6, 4), 9),
            kAuthentication: 2,
            kRecovery: Math.max(old.k ?? 3, 3),
            minRemoteForRecovery: 1
          };
          registry.version = 2;
          needsSave = true;
        }
        if (needsSave) await resave(registry);
        return registry;
      },
      /** Re-seals `registry` under `passphrase` and persists it, replacing whatever was there. */
      async save(passphrase, registry) {
        const sealedVault = await seal(passphrase, registry);
        await storageAdapter.setItem(STORAGE_KEY, JSON.stringify(sealedVault));
      },
      /** Re-seals `registry` under a raw HKDF key (`recovery`-unlock-policy vaults) and persists it. */
      async saveWithKey(keyHex, registry) {
        const sealedVault = await sealWithKey(keyHex, registry);
        await storageAdapter.setItem(STORAGE_KEY, JSON.stringify(sealedVault));
      },
      async destroy() {
        await storageAdapter.removeItem(STORAGE_KEY);
      }
    };
  }
  var LEGACY_SINGLE_VAULT_STORAGE_KEY;
  var init_store = __esm({
    "src/vault/store.js"() {
      init_vault();
      init_registry();
      init_curve2();
      LEGACY_SINGLE_VAULT_STORAGE_KEY = "identt.vault.v1";
    }
  });

  // src/app/state.js
  function setSession(next) {
    session = next;
  }
  function setPendingNotice(message) {
    pendingNotice = message;
  }
  function consumePendingNotice() {
    const notice = pendingNotice;
    pendingNotice = null;
    return notice;
  }
  async function persist() {
    const store = createVaultStore(storage, session.vaultName);
    if (session.unlockSecret.kind === "passphrase") {
      await store.save(session.unlockSecret.value, session.registry);
    } else {
      await store.saveWithKey(session.unlockSecret.value, session.registry);
    }
  }
  var storage, session, pendingNotice;
  var init_state = __esm({
    "src/app/state.js"() {
      init_storage();
      init_store();
      storage = createLocalStorageAdapter();
      session = { vaultName: null, registry: null, unlockSecret: null };
      pendingNotice = null;
    }
  });

  // src/vault/directory.js
  async function readJson(storageAdapter, key, fallback) {
    const raw = await storageAdapter.getItem(key);
    return raw === null ? fallback : JSON.parse(raw);
  }
  async function listVaultNames(storageAdapter) {
    return readJson(storageAdapter, VAULTS_INDEX_KEY, []);
  }
  async function registerVaultName(storageAdapter, name) {
    const list = await listVaultNames(storageAdapter);
    if (list.some((v) => v.name === name)) {
      throw new Error(`a vault named "${name}" already exists`);
    }
    list.push({ name, createdAt: (/* @__PURE__ */ new Date()).toISOString() });
    await storageAdapter.setItem(VAULTS_INDEX_KEY, JSON.stringify(list));
  }
  async function unregisterVaultName(storageAdapter, name) {
    const list = await listVaultNames(storageAdapter);
    await storageAdapter.setItem(VAULTS_INDEX_KEY, JSON.stringify(list.filter((v) => v.name !== name)));
  }
  async function identityMap(storageAdapter) {
    return readJson(storageAdapter, IDENTITY_INDEX_KEY, {});
  }
  async function registerIdentity(storageAdapter, publicKeyHex, vaultName) {
    const map = await identityMap(storageAdapter);
    map[publicKeyHex] = vaultName;
    await storageAdapter.setItem(IDENTITY_INDEX_KEY, JSON.stringify(map));
  }
  async function unregisterIdentitiesForVault(storageAdapter, vaultName) {
    const map = await identityMap(storageAdapter);
    for (const [pubKey, name] of Object.entries(map)) {
      if (name === vaultName) delete map[pubKey];
    }
    await storageAdapter.setItem(IDENTITY_INDEX_KEY, JSON.stringify(map));
  }
  async function findVaultNameForPublicKey(storageAdapter, publicKeyHex) {
    const map = await identityMap(storageAdapter);
    return map[publicKeyHex] ?? null;
  }
  var VAULTS_INDEX_KEY, IDENTITY_INDEX_KEY;
  var init_directory = __esm({
    "src/vault/directory.js"() {
      VAULTS_INDEX_KEY = "identt.vaults.index.v1";
      IDENTITY_INDEX_KEY = "identt.identities.index.v1";
    }
  });

  // src/vault/meta.js
  function metaKeyFor(vaultName) {
    return `identt.vault.${encodeURIComponent(vaultName)}.meta.v1`;
  }
  async function getVaultMeta(storageAdapter, vaultName) {
    const raw = await storageAdapter.getItem(metaKeyFor(vaultName));
    return raw === null ? { ...DEFAULT_META } : JSON.parse(raw);
  }
  async function setVaultMeta(storageAdapter, vaultName, meta) {
    await storageAdapter.setItem(metaKeyFor(vaultName), JSON.stringify(meta));
  }
  async function deleteVaultMeta(storageAdapter, vaultName) {
    await storageAdapter.removeItem(metaKeyFor(vaultName));
  }
  var UNLOCK_POLICIES, DEFAULT_META;
  var init_meta = __esm({
    "src/vault/meta.js"() {
      UNLOCK_POLICIES = Object.freeze({
        PASSPHRASE: "passphrase",
        AUTHENTICATION: "authentication",
        RECOVERY: "recovery"
      });
      DEFAULT_META = { unlockPolicy: UNLOCK_POLICIES.PASSPHRASE, recoverySplit: null };
    }
  });

  // src/vault/crossVault.js
  function inboxKeyFor(publicKeyHex) {
    return `identt.inbox.${encodeURIComponent(publicKeyHex)}.v1`;
  }
  function reconstructionKeyFor(vaultName) {
    return `identt.vault.${encodeURIComponent(vaultName)}.reconstruction.v1`;
  }
  function authApprovalsKeyFor(vaultName) {
    return `identt.vault.${encodeURIComponent(vaultName)}.authApprovals.v1`;
  }
  async function readJson2(storageAdapter, key, fallback) {
    const raw = await storageAdapter.getItem(key);
    return raw === null ? fallback : JSON.parse(raw);
  }
  async function pushInbox(storageAdapter, recipientPublicKeyHex, entry) {
    const key = inboxKeyFor(recipientPublicKeyHex);
    const list = await readJson2(storageAdapter, key, []);
    list.push(entry);
    await storageAdapter.setItem(key, JSON.stringify(list));
  }
  async function listInbox(storageAdapter, recipientPublicKeyHex) {
    return readJson2(storageAdapter, inboxKeyFor(recipientPublicKeyHex), []);
  }
  async function removeInboxEntry(storageAdapter, recipientPublicKeyHex, entryId) {
    const key = inboxKeyFor(recipientPublicKeyHex);
    const list = await readJson2(storageAdapter, key, []);
    await storageAdapter.setItem(key, JSON.stringify(list.filter((e) => e.id !== entryId)));
  }
  async function listReconstructionShares(storageAdapter, vaultName) {
    return readJson2(storageAdapter, reconstructionKeyFor(vaultName), []);
  }
  async function pushReconstructionShare(storageAdapter, vaultName, { deviceId, x, y }) {
    const key = reconstructionKeyFor(vaultName);
    const list = await readJson2(storageAdapter, key, []);
    const next = list.filter((s) => s.deviceId !== deviceId);
    next.push({ deviceId, x, y: y.toString() });
    await storageAdapter.setItem(key, JSON.stringify(next));
  }
  async function clearReconstructionShares(storageAdapter, vaultName) {
    await storageAdapter.removeItem(reconstructionKeyFor(vaultName));
  }
  async function listAuthApprovals(storageAdapter, vaultName) {
    return readJson2(storageAdapter, authApprovalsKeyFor(vaultName), []);
  }
  async function pushAuthApproval(storageAdapter, vaultName, { deviceId }) {
    const key = authApprovalsKeyFor(vaultName);
    const list = await readJson2(storageAdapter, key, []);
    if (list.some((a) => a.deviceId === deviceId)) return;
    list.push({ deviceId, approvedAt: (/* @__PURE__ */ new Date()).toISOString() });
    await storageAdapter.setItem(key, JSON.stringify(list));
  }
  async function clearAuthApprovals(storageAdapter, vaultName) {
    await storageAdapter.removeItem(authApprovalsKeyFor(vaultName));
  }
  var init_crossVault = __esm({
    "src/vault/crossVault.js"() {
    }
  });

  // src/crypto/shamir.js
  function split2(secret, { n, k }) {
    if (!Number.isInteger(n) || !Number.isInteger(k) || k < 1 || n < k) {
      throw new RangeError(`split: invalid (n=${n}, k=${k}) \u2014 require 1 <= k <= n`);
    }
    const coefficients = [mod2(secret)];
    for (let i = 1; i < k; i++) coefficients.push(randomScalar());
    const evaluate = (x) => {
      let y = 0n;
      for (let i = coefficients.length - 1; i >= 0; i--) {
        y = mod2(y * BigInt(x) + coefficients[i]);
      }
      return y;
    };
    const shares = [];
    for (let x = 1; x <= n; x++) shares.push({ x, y: evaluate(x) });
    return shares;
  }
  function lagrangeInterpolate(points, atX) {
    const xs = new Set(points.map((s) => s.x));
    if (xs.size !== points.length) {
      throw new RangeError("lagrangeInterpolate: duplicate x-values \u2014 cannot interpolate");
    }
    if (points.length === 0) {
      throw new RangeError("lagrangeInterpolate: need at least one point");
    }
    const target = BigInt(atX);
    let result = 0n;
    for (const j of points) {
      let num = 1n;
      let den = 1n;
      for (const m of points) {
        if (m.x === j.x) continue;
        num = mod2(num * (target - BigInt(m.x)));
        den = mod2(den * BigInt(j.x - m.x));
      }
      const lj = mod2(num * modInverse(den));
      result = mod2(result + mod2(j.y * lj));
    }
    return result;
  }
  function reconstruct(shares) {
    return lagrangeInterpolate(shares, 0n);
  }
  var init_shamir = __esm({
    "src/crypto/shamir.js"() {
      init_curve2();
    }
  });

  // src/crypto/shareWrap.js
  async function deriveAesKey(sharedSecretBytes) {
    const keyMaterial = await SUBTLE2.importKey("raw", sharedSecretBytes, "HKDF", false, ["deriveKey"]);
    return SUBTLE2.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: HKDF_INFO },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }
  function serializeShare(share) {
    return enc2.encode(JSON.stringify({ x: share.x, y: share.y.toString() }));
  }
  function deserializeShare(bytes) {
    const obj = JSON.parse(dec2.decode(bytes));
    return { x: obj.x, y: BigInt(obj.y) };
  }
  async function wrapShare({ share, senderIdentity, recipientPublicKeyHex }) {
    const sharedSecret = secp256k1.getSharedSecret(
      hexToBytes3(senderIdentity.privateKeyHex),
      hexToBytes3(recipientPublicKeyHex)
    );
    const key = await deriveAesKey(sharedSecret);
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const ciphertextBuf = await SUBTLE2.encrypt({ name: "AES-GCM", iv }, key, serializeShare(share));
    return {
      method: "ecdh-secp256k1-hkdf-aes256gcm",
      senderPublicKeyHex: senderIdentity.publicKeyHex,
      ivHex: bytesToHex3(iv),
      ciphertextHex: bytesToHex3(new Uint8Array(ciphertextBuf))
    };
  }
  async function unwrapShare({ wrapped, recipientPrivateKeyHex }) {
    const sharedSecret = secp256k1.getSharedSecret(
      hexToBytes3(recipientPrivateKeyHex),
      hexToBytes3(wrapped.senderPublicKeyHex)
    );
    const key = await deriveAesKey(sharedSecret);
    try {
      const plaintextBuf = await SUBTLE2.decrypt(
        { name: "AES-GCM", iv: hexToBytes3(wrapped.ivHex) },
        key,
        hexToBytes3(wrapped.ciphertextHex)
      );
      return deserializeShare(new Uint8Array(plaintextBuf));
    } catch {
      throw new ShareUnwrapError();
    }
  }
  var SUBTLE2, enc2, dec2, HKDF_INFO, ShareUnwrapError;
  var init_shareWrap = __esm({
    "src/crypto/shareWrap.js"() {
      init_curve2();
      SUBTLE2 = globalThis.crypto.subtle;
      enc2 = new TextEncoder();
      dec2 = new TextDecoder();
      HKDF_INFO = enc2.encode("ZRDCP/1.0 share-wrap AES-GCM key");
      ShareUnwrapError = class extends Error {
        constructor() {
          super("Could not unwrap share: wrong key, or the payload was tampered with in transit.");
          this.name = "ShareUnwrapError";
        }
      };
    }
  });

  // src/vault/unlockRecovery.js
  async function enableRecoveryUnlock({ registry }) {
    if (!registry.localIdentity) {
      throw new VaultUnlockRecoveryError("this vault has no local device identity yet \u2014 cannot wrap shares");
    }
    const { kRecovery, minRemoteForRecovery } = registry.threshold;
    const holders = shareHoldingDevices(registry);
    if (holders.length < kRecovery) {
      throw new VaultUnlockRecoveryError(
        `only ${holders.length} share-holding device(s) enrolled, but recovery-unlock requires ${kRecovery} \u2014 enroll more zrdcp-native or PRF-capable fido2 devices, or lower kRecovery first.`
      );
    }
    const remoteHolders = remoteShareHoldingDevices(registry);
    if (remoteHolders.length < minRemoteForRecovery) {
      throw new VaultUnlockRecoveryError(
        `recovery-unlock requires at least ${minRemoteForRecovery} remote share-holding device(s), but only ${remoteHolders.length} are enrolled/flagged remote.`
      );
    }
    const secretScalar = randomScalar();
    const shares = split2(secretScalar, { n: holders.length, k: kRecovery });
    const wrappedShares = [];
    for (let i = 0; i < holders.length; i++) {
      const device = holders[i];
      const wrapped = await wrapShare({
        share: shares[i],
        senderIdentity: registry.localIdentity,
        recipientPublicKeyHex: ecdhPublicKeyForDevice(device)
      });
      wrappedShares.push({
        deviceId: device.id,
        deviceName: device.name,
        devicePublicKeyHex: ecdhPublicKeyForDevice(device),
        isRemote: Boolean(device.isRemote),
        wrapped
      });
    }
    return {
      keyHex: scalarToHex(secretScalar),
      recoverySplit: {
        kRecovery,
        minRemoteForRecovery,
        holderCount: holders.length,
        shares: wrappedShares
      }
    };
  }
  function attemptReconstruction({ recoverySplit, collectedShares }) {
    const { kRecovery, minRemoteForRecovery, shares: splitShares } = recoverySplit;
    const remoteDeviceIds = new Set(splitShares.filter((s) => s.isRemote).map((s) => s.deviceId));
    const validDeviceIds = new Set(splitShares.map((s) => s.deviceId));
    const usable = collectedShares.filter((s) => validDeviceIds.has(s.deviceId));
    const collectedCount = usable.length;
    const remoteCollectedCount = usable.filter((s) => remoteDeviceIds.has(s.deviceId)).length;
    if (collectedCount < kRecovery || remoteCollectedCount < minRemoteForRecovery) {
      const parts = [`${collectedCount}/${kRecovery} real responses collected`];
      parts.push(`${remoteCollectedCount}/${minRemoteForRecovery} required remote responses collected`);
      return { ok: false, reason: parts.join(" \xB7 "), collectedCount, remoteCollectedCount };
    }
    const points = usable.slice(0, kRecovery).map((s) => ({ x: s.x, y: BigInt(s.y) }));
    const reconstructed = reconstruct(points);
    return { ok: true, keyHex: scalarToHex(reconstructed) };
  }
  var VaultUnlockRecoveryError;
  var init_unlockRecovery = __esm({
    "src/vault/unlockRecovery.js"() {
      init_curve2();
      init_shamir();
      init_shareWrap();
      init_registry();
      VaultUnlockRecoveryError = class extends Error {
        constructor(message) {
          super(message);
          this.name = "VaultUnlockRecoveryError";
        }
      };
    }
  });

  // src/recovery/respond.js
  async function approveInboxEntry({ entry, responderLocalIdentity }) {
    if (entry.kind === "vault-unlock-authentication") {
      return { kind: "vault-unlock-authentication" };
    }
    if (entry.kind === "vault-unlock-recovery") {
      if (!entry.wrappedShare) {
        throw new ResponderError(`inbox entry ${entry.id} is a recovery request but carries no wrapped share`);
      }
      const { x, y } = await unwrapShare({
        wrapped: entry.wrappedShare,
        recipientPrivateKeyHex: responderLocalIdentity.privateKeyHex
      });
      return { kind: "vault-unlock-recovery", x, y: y.toString() };
    }
    throw new ResponderError(`unknown inbox entry kind: ${entry.kind}`);
  }
  var ResponderError;
  var init_respond = __esm({
    "src/recovery/respond.js"() {
      init_shareWrap();
      ResponderError = class extends Error {
        constructor(message) {
          super(message);
          this.name = "ResponderError";
        }
      };
    }
  });

  // node_modules/@noble/hashes/sha3.js
  function keccakP(s, rounds = 24) {
    if (!(s instanceof Uint32Array))
      throw new TypeError('"s" expected Uint32Array(50), got type=' + typeof s);
    if (s.length !== 50)
      throw new RangeError('"s" expected Uint32Array(50), got length=' + s.length);
    anumber(rounds, "rounds");
    if (rounds < 1 || rounds > 24)
      throw new Error('"rounds" expected integer 1..24');
    for (let round = 24 - rounds; round < 24; round++) {
      for (let x = 0; x < 10; x++)
        B[x] = s[x] ^ s[x + 10] ^ s[x + 20] ^ s[x + 30] ^ s[x + 40];
      for (let x = 0; x < 10; x += 2) {
        const idx1 = (x + 8) % 10;
        const idx0 = (x + 2) % 10;
        const B0 = B[idx0];
        const B1 = B[idx0 + 1];
        const Th = rotlH(B0, B1, 1) ^ B[idx1];
        const Tl = rotlL(B0, B1, 1) ^ B[idx1 + 1];
        for (let y = 0; y < 50; y += 10) {
          s[x + y] ^= Th;
          s[x + y + 1] ^= Tl;
        }
      }
      let curH = s[2];
      let curL = s[3];
      for (let t = 0; t < 24; t++) {
        const shift = SHA3_ROTL[t];
        const Th = rotlH(curH, curL, shift);
        const Tl = rotlL(curH, curL, shift);
        const PI = SHA3_PI[t];
        curH = s[PI];
        curL = s[PI + 1];
        s[PI] = Th;
        s[PI + 1] = Tl;
      }
      for (let y = 0; y < 50; y += 10) {
        const b0 = s[y], b1 = s[y + 1], b2 = s[y + 2], b3 = s[y + 3];
        s[y] ^= ~s[y + 2] & s[y + 4];
        s[y + 1] ^= ~s[y + 3] & s[y + 5];
        s[y + 2] ^= ~s[y + 4] & s[y + 6];
        s[y + 3] ^= ~s[y + 5] & s[y + 7];
        s[y + 4] ^= ~s[y + 6] & s[y + 8];
        s[y + 5] ^= ~s[y + 7] & s[y + 9];
        s[y + 6] ^= ~s[y + 8] & b0;
        s[y + 7] ^= ~s[y + 9] & b1;
        s[y + 8] ^= ~b0 & b2;
        s[y + 9] ^= ~b1 & b3;
      }
      s[0] ^= SHA3_IOTA_H[round];
      s[1] ^= SHA3_IOTA_L[round];
    }
    clean(B);
  }
  var _0n7, _1n6, _2n5, _7n2, _256n, _0x71n, SHA3_PI, SHA3_ROTL, _SHA3_IOTA, IOTAS, SHA3_IOTA_H, SHA3_IOTA_L, rotlSH, rotlSL, rotlBH, rotlBL, rotlH, rotlL, B, Keccak, genKeccak, sha3_256;
  var init_sha3 = __esm({
    "node_modules/@noble/hashes/sha3.js"() {
      init_u64();
      init_utils();
      _0n7 = BigInt(0);
      _1n6 = BigInt(1);
      _2n5 = BigInt(2);
      _7n2 = BigInt(7);
      _256n = BigInt(256);
      _0x71n = BigInt(113);
      SHA3_PI = [];
      SHA3_ROTL = [];
      _SHA3_IOTA = [];
      for (let round = 0, R = _1n6, x = 1, y = 0; round < 24; round++) {
        [x, y] = [y, (2 * x + 3 * y) % 5];
        SHA3_PI.push(2 * (5 * y + x));
        SHA3_ROTL.push((round + 1) * (round + 2) / 2 % 64);
        let t = _0n7;
        for (let j = 0; j < 7; j++) {
          R = (R << _1n6 ^ (R >> _7n2) * _0x71n) % _256n;
          if (R & _2n5)
            t ^= _1n6 << (_1n6 << BigInt(j)) - _1n6;
        }
        _SHA3_IOTA.push(t);
      }
      IOTAS = split(_SHA3_IOTA, true);
      SHA3_IOTA_H = IOTAS[0];
      SHA3_IOTA_L = IOTAS[1];
      rotlSH = (h, l, s) => h << s | l >>> 32 - s;
      rotlSL = (h, l, s) => l << s | h >>> 32 - s;
      rotlBH = (h, l, s) => l << s - 32 | h >>> 64 - s;
      rotlBL = (h, l, s) => h << s - 32 | l >>> 64 - s;
      rotlH = (h, l, s) => s > 32 ? rotlBH(h, l, s) : rotlSH(h, l, s);
      rotlL = (h, l, s) => s > 32 ? rotlBL(h, l, s) : rotlSL(h, l, s);
      B = new Uint32Array(5 * 2);
      Keccak = class _Keccak {
        state;
        pos = 0;
        posOut = 0;
        finished = false;
        state32;
        destroyed = false;
        blockLen;
        suffix;
        outputLen;
        canXOF;
        enableXOF = false;
        rounds;
        // NOTE: we accept arguments in bytes instead of bits here.
        constructor(blockLen, suffix, outputLen, enableXOF = false, rounds = 24) {
          anumber(blockLen, "blockLen");
          anumber(suffix, "suffix");
          anumber(rounds, "rounds");
          abool(enableXOF, "enableXOF");
          this.blockLen = blockLen;
          this.suffix = suffix;
          this.outputLen = outputLen;
          this.enableXOF = enableXOF;
          this.canXOF = enableXOF;
          this.rounds = rounds;
          anumber(outputLen, "outputLen");
          if (!(0 < blockLen && blockLen < 200))
            throw new Error('"blockLen" must be 1..199');
          this.state = new Uint8Array(200);
          this.state32 = u32(this.state);
        }
        clone() {
          return this._cloneInto();
        }
        keccak() {
          swap32IfBE(this.state32);
          keccakP(this.state32, this.rounds);
          swap32IfBE(this.state32);
          this.posOut = 0;
          this.pos = 0;
        }
        update(data) {
          aexists(this);
          abytes(data);
          const { blockLen, state, state32 } = this;
          const len = data.length;
          const canUseU32 = blockLen % 4 === 0 && data.byteOffset % 4 === 0;
          const blockLen32 = blockLen / 4;
          const data32 = canUseU32 && len >= blockLen ? u32(data) : void 0;
          for (let pos = 0; pos < len; ) {
            if (data32 !== void 0 && this.pos === 0 && pos % 4 === 0 && len - pos >= blockLen) {
              for (let i = 0, o = pos / 4; i < blockLen32; i++)
                state32[i] ^= data32[o + i];
              pos += blockLen;
              this.pos = blockLen;
              this.keccak();
              continue;
            }
            const take = Math.min(blockLen - this.pos, len - pos);
            for (let i = 0; i < take; i++)
              state[this.pos++] ^= data[pos++];
            if (this.pos === blockLen)
              this.keccak();
          }
          return this;
        }
        finish() {
          if (this.finished)
            return;
          this.finished = true;
          const { state, suffix, pos, blockLen } = this;
          state[pos] ^= suffix;
          if ((suffix & 128) !== 0 && pos === blockLen - 1)
            this.keccak();
          state[blockLen - 1] ^= 128;
          this.keccak();
        }
        writeInto(out) {
          aexists(this, false);
          abytes(out);
          this.finish();
          const bufferOut = this.state;
          const { blockLen } = this;
          for (let pos = 0, len = out.length; pos < len; ) {
            if (this.posOut >= blockLen)
              this.keccak();
            const take = Math.min(blockLen - this.posOut, len - pos);
            out.set(bufferOut.subarray(this.posOut, this.posOut + take), pos);
            this.posOut += take;
            pos += take;
          }
          return out;
        }
        xofInto(out) {
          if (!this.enableXOF)
            throw new Error("XOF is not enabled");
          return this.writeInto(out);
        }
        xof(bytes) {
          anumber(bytes);
          return this.xofInto(new Uint8Array(bytes));
        }
        digestInto(out) {
          aoutput(out, this);
          if (this.finished)
            throw new Error("digest() was already called");
          this.writeInto(out.length === this.outputLen ? out : out.subarray(0, this.outputLen));
          this.destroy();
        }
        digest() {
          const out = new Uint8Array(this.outputLen);
          this.digestInto(out);
          return out;
        }
        destroy() {
          this.destroyed = true;
          clean(this.state);
        }
        _cloneInto(to) {
          const { blockLen, suffix, outputLen, rounds, enableXOF } = this;
          to ||= new _Keccak(blockLen, suffix, outputLen, enableXOF, rounds);
          to.blockLen = blockLen;
          to.state32.set(this.state32);
          to.pos = this.pos;
          to.posOut = this.posOut;
          to.finished = this.finished;
          to.rounds = rounds;
          to.suffix = suffix;
          to.outputLen = outputLen;
          to.enableXOF = enableXOF;
          to.canXOF = this.canXOF;
          to.destroyed = this.destroyed;
          return to;
        }
      };
      genKeccak = (suffix, blockLen, outputLen, info = {}) => createHasher(() => new Keccak(blockLen, suffix, outputLen), info);
      sha3_256 = /* @__PURE__ */ genKeccak(
        6,
        136,
        32,
        /* @__PURE__ */ oidNist(8)
      );
    }
  });

  // src/crypto/hash.js
  function toBytes(input) {
    if (input instanceof Uint8Array) return input;
    if (typeof input === "string") return enc3.encode(input);
    throw new TypeError("toBytes: expected string or Uint8Array");
  }
  function H2(input) {
    const digest = sha3_256(toBytes(input));
    return bytesToScalar(digest);
  }
  function concatForChallenge({ commitmentHex, tHex, contextId, certHash }) {
    const parts = [commitmentHex, tHex, contextId];
    if (certHash !== void 0) parts.push(certHash);
    return parts.map((p) => `${p.length}:${p}`).join("|");
  }
  var enc3;
  var init_hash = __esm({
    "src/crypto/hash.js"() {
      init_sha3();
      init_curve2();
      enc3 = new TextEncoder();
    }
  });

  // src/crypto/pedersen.js
  function commit(runtimeEntropy, r = randomScalar()) {
    const m = H2(runtimeEntropy);
    const K = G.multiply(m).add(H.multiply(r));
    return { K, m, r };
  }
  function prove({ m, r, K, contextId, certHash }) {
    const w1 = randomScalar();
    const w2 = randomScalar();
    const t = G.multiply(w1).add(H.multiply(w2));
    const c = H2(
      concatForChallenge({
        commitmentHex: pointToHex(K),
        tHex: pointToHex(t),
        contextId,
        certHash
      })
    );
    const s1 = mod2(w1 + mod2(c * m));
    const s2 = mod2(w2 + mod2(c * r));
    return { t, s1, s2, c };
  }
  var init_pedersen = __esm({
    "src/crypto/pedersen.js"() {
      init_curve2();
      init_hash();
    }
  });

  // src/protocol/messages.js
  function hex0x(str) {
    return str.startsWith("0x") ? str : "0x" + str;
  }
  function buildRecoveryInit({ sessionId, K, proof, contextId, purpose = "recovery", certHash, timestampMs }) {
    return {
      protocol_version: PROTOCOL_VERSION,
      message_type: purpose === "authentication" ? "AUTH_CHALLENGE" : "RECOVERY_INIT",
      purpose,
      session_id: sessionId,
      context_id: contextId,
      pedersen_commitment: hex0x(pointToHex(K)),
      nizk_t: hex0x(pointToHex(proof.t)),
      nizk_proof_s1: hex0x(proof.s1.toString(16)),
      nizk_proof_s2: hex0x(proof.s2.toString(16)),
      context_binding: {
        tls_cert_hash: certHash ? hex0x(certHash) : null,
        timestamp: timestampMs ?? Date.now()
      }
    };
  }
  function buildShareDelivery({ sessionId, nodeIndex, wrapped }) {
    return {
      protocol_version: PROTOCOL_VERSION,
      message_type: "SHARE_DELIVERY",
      session_id: sessionId,
      node_index: nodeIndex,
      wrap_method: wrapped.method,
      ephemeral_dh_pubkey: hex0x(wrapped.senderPublicKeyHex),
      iv: hex0x(wrapped.ivHex),
      encrypted_share: hex0x(wrapped.ciphertextHex)
    };
  }
  function generateSessionId() {
    const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
    return "0x" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }
  var PROTOCOL_VERSION;
  var init_messages = __esm({
    "src/protocol/messages.js"() {
      init_curve2();
      PROTOCOL_VERSION = "ZRDCP/1.0";
    }
  });

  // src/dispatch/simulate.js
  function buildResponderLink({ sessionId, deviceId }, base = "identt://responder") {
    const params = new URLSearchParams({ session: sessionId, device: deviceId });
    return `${base}?${params.toString()}`;
  }
  function simulateDispatchToDevice({ device, sessionId, purpose, recoveryInitMessage, shareDeliveryMessage }) {
    const channel = device.contactChannels[0];
    const responderLink = buildResponderLink({ sessionId, deviceId: device.id });
    const hasShare = shareDeliveryMessage !== null && shareDeliveryMessage !== void 0;
    let payloadPreview;
    if (purpose === "authentication") {
      payloadPreview = `AUTH_CHALLENGE (session ${sessionId.slice(0, 10)}\u2026) \u2014 please approve or deny this authentication request. No share exchange is involved.`;
    } else if (hasShare) {
      payloadPreview = `RECOVERY_INIT (session ${sessionId.slice(0, 10)}\u2026) + your encrypted share (node_index ${shareDeliveryMessage.node_index}). Open the responder link to review and approve.`;
    } else {
      payloadPreview = `RECOVERY_INIT (session ${sessionId.slice(0, 10)}\u2026) \u2014 you're an approval-only participant on this mesh. Open the responder link to authenticate and approve; no share is sent to you.`;
    }
    return {
      deviceId: device.id,
      deviceName: device.name,
      deviceType: device.type,
      isRemote: device.isRemote ?? false,
      participationMode: device.type === "fido2" ? device.participationMode : "full-share",
      channelKind: channel?.kind ?? "unknown",
      address: channel?.address ?? "(no contact channel configured)",
      hasShare,
      payloadPreview,
      // The actual wire messages this dispatch would carry — both are already public/ciphertext by
      // design (the whole point of NIZK + AES-GCM wrapping), so echoing them back here is exactly
      // what a real email/SMS/WebAPI payload would attach.
      recoveryInitMessage,
      shareDeliveryMessage: hasShare ? shareDeliveryMessage : null,
      responderLink,
      simulated: true,
      dispatchedAt: (/* @__PURE__ */ new Date()).toISOString()
    };
  }
  var init_simulate = __esm({
    "src/dispatch/simulate.js"() {
    }
  });

  // src/recovery/initiate.js
  async function initiateRecovery({ registry, runtimeEntropy, purpose = "recovery", contextId, certHash }) {
    if (purpose !== "authentication" && purpose !== "recovery") {
      throw new RecoveryInitiationError(`purpose must be 'authentication' or 'recovery', got '${purpose}'`);
    }
    if (!registry.localIdentity) {
      throw new RecoveryInitiationError(
        "this vault has no local device identity yet \u2014 reload the vault (VaultStore.load migrates older vaults automatically) before initiating a challenge"
      );
    }
    if (!runtimeEntropy || typeof runtimeEntropy !== "string") {
      throw new RecoveryInitiationError("runtime code is required");
    }
    const { kAuthentication, kRecovery, minRemoteForRecovery } = registry.threshold;
    const requiredK = purpose === "authentication" ? kAuthentication : kRecovery;
    const holders = shareHoldingDevices(registry);
    if (purpose === "authentication") {
      if (registry.devices.length < requiredK) {
        throw new RecoveryInitiationError(
          `only ${registry.devices.length} device(s) enrolled, but authentication requires ${requiredK} approvals \u2014 enroll more trusted devices, or lower kAuthentication.`
        );
      }
    } else {
      if (holders.length < requiredK) {
        throw new RecoveryInitiationError(
          `only ${holders.length} share-holding device(s) enrolled, but recovery requires ${requiredK} \u2014 recovery cannot proceed. Enroll more zrdcp-native or PRF-capable fido2 devices, or lower kRecovery.`
        );
      }
      const remoteHolders = remoteShareHoldingDevices(registry);
      if (remoteHolders.length < minRemoteForRecovery) {
        throw new RecoveryInitiationError(
          `recovery requires at least ${minRemoteForRecovery} remote share-holding device(s), but only ${remoteHolders.length} enrolled/flagged remote \u2014 recovery cannot proceed. Flag an existing share-holding device as remote, enroll another, or lower minRemoteForRecovery.`
        );
      }
    }
    const sessionId = generateSessionId();
    const effectiveContextId = contextId ?? sessionId;
    const { K, m, r } = commit(runtimeEntropy);
    const proof = prove({ m, r, K, contextId: effectiveContextId, certHash });
    const recoveryInit = buildRecoveryInit({
      sessionId,
      K,
      proof,
      contextId: effectiveContextId,
      purpose,
      certHash
    });
    const dispatches = [];
    if (purpose === "authentication") {
      for (const device of registry.devices) {
        dispatches.push(
          simulateDispatchToDevice({
            device,
            sessionId,
            purpose,
            recoveryInitMessage: recoveryInit,
            shareDeliveryMessage: null
          })
        );
      }
    } else {
      const shares = split2(m, { n: holders.length, k: requiredK });
      for (let i = 0; i < holders.length; i++) {
        const device = holders[i];
        const share = shares[i];
        const wrapped = await wrapShare({
          share,
          senderIdentity: registry.localIdentity,
          recipientPublicKeyHex: ecdhPublicKeyForDevice(device)
        });
        const shareDelivery = buildShareDelivery({ sessionId, nodeIndex: share.x, wrapped });
        dispatches.push(
          simulateDispatchToDevice({
            device,
            sessionId,
            purpose,
            recoveryInitMessage: recoveryInit,
            shareDeliveryMessage: shareDelivery
          })
        );
      }
      const holderIds = new Set(holders.map((d) => d.id));
      for (const device of registry.devices) {
        if (holderIds.has(device.id)) continue;
        dispatches.push(
          simulateDispatchToDevice({
            device,
            sessionId,
            purpose,
            recoveryInitMessage: recoveryInit,
            shareDeliveryMessage: null
          })
        );
      }
    }
    return {
      sessionId,
      contextId: effectiveContextId,
      purpose,
      requiredK,
      minRemoteForRecovery: purpose === "recovery" ? minRemoteForRecovery : null,
      recoveryInit,
      dispatches
    };
  }
  var RecoveryInitiationError;
  var init_initiate = __esm({
    "src/recovery/initiate.js"() {
      init_pedersen();
      init_shamir();
      init_shareWrap();
      init_messages();
      init_simulate();
      init_registry();
      RecoveryInitiationError = class extends Error {
        constructor(message) {
          super(message);
          this.name = "RecoveryInitiationError";
        }
      };
    }
  });

  // src/recovery/evaluateOutcome.js
  function evaluateChallengeOutcome({ session: session2, responses }) {
    const successDispatches = session2.dispatches.filter((d) => responses[d.deviceId] === "success");
    if (session2.purpose === "authentication") {
      const successCount = successDispatches.length;
      const granted2 = successCount >= session2.requiredK;
      return {
        granted: granted2,
        purpose: "authentication",
        requiredK: session2.requiredK,
        successCount,
        reason: granted2 ? `${successCount}/${session2.requiredK} required approvals received.` : `Only ${successCount}/${session2.requiredK} required approvals received.`
      };
    }
    const successShareHolders = successDispatches.filter((d) => d.hasShare);
    const successRemoteShareHolders = successShareHolders.filter((d) => d.isRemote);
    const metCount = successShareHolders.length >= session2.requiredK;
    const metRemote = successRemoteShareHolders.length >= session2.minRemoteForRecovery;
    const granted = metCount && metRemote;
    let reason;
    if (granted) {
      reason = `${successShareHolders.length}/${session2.requiredK} share-holders responded, including ${successRemoteShareHolders.length}/${session2.minRemoteForRecovery} required remote device(s).`;
    } else if (!metCount) {
      reason = `Only ${successShareHolders.length}/${session2.requiredK} required share-holders responded successfully.`;
    } else {
      reason = `${successShareHolders.length}/${session2.requiredK} share-holders responded, but only ${successRemoteShareHolders.length}/${session2.minRemoteForRecovery} required remote device(s) among them.`;
    }
    return {
      granted,
      purpose: "recovery",
      requiredK: session2.requiredK,
      minRemoteForRecovery: session2.minRemoteForRecovery,
      successCount: successShareHolders.length,
      remoteSuccessCount: successRemoteShareHolders.length,
      metCount,
      metRemote,
      reason
    };
  }
  var init_evaluateOutcome = __esm({
    "src/recovery/evaluateOutcome.js"() {
    }
  });

  // src/recovery/decoy.js
  function buildDecoySession({ registry, purpose = "recovery" }) {
    const sessionId = generateSessionId();
    const { kAuthentication, kRecovery, minRemoteForRecovery } = registry.threshold;
    const requiredK = purpose === "authentication" ? kAuthentication : kRecovery;
    const dispatches = registry.devices.map((device) => {
      const primaryContact = device.contactChannels[0] ?? { kind: "email", address: "(none)" };
      return {
        deviceId: device.id,
        deviceName: device.name,
        deviceType: device.type,
        channelKind: primaryContact.kind,
        address: primaryContact.address,
        hasShare: device.type === "zrdcp-native" || device.participationMode === "full-share",
        isRemote: !!device.isRemote,
        payloadPreview: "(withheld)",
        responderLink: "",
        simulated: true
      };
    });
    return {
      sessionId,
      contextId: sessionId,
      purpose,
      requiredK,
      minRemoteForRecovery: purpose === "recovery" ? minRemoteForRecovery : null,
      recoveryInit: { pedersen_commitment: sessionId },
      dispatches,
      decoy: true
    };
  }
  function decoyOutcome(session2) {
    const remoteRequired = session2.minRemoteForRecovery ?? 0;
    return {
      granted: true,
      purpose: session2.purpose,
      requiredK: session2.requiredK,
      minRemoteForRecovery: session2.minRemoteForRecovery,
      successCount: session2.requiredK,
      remoteSuccessCount: remoteRequired,
      reason: session2.purpose === "authentication" ? `${session2.requiredK}/${session2.requiredK} required approvals received.` : `${session2.requiredK}/${session2.requiredK} share-holders responded, including ${remoteRequired}/${remoteRequired} required remote device(s).`
    };
  }
  var init_decoy = __esm({
    "src/recovery/decoy.js"() {
      init_messages();
    }
  });

  // src/vault/duress.js
  function randomBytes4(len) {
    return globalThis.crypto.getRandomValues(new Uint8Array(len));
  }
  function toB642(bytes) {
    return btoa(String.fromCharCode(...bytes));
  }
  function fromB642(b64) {
    return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  }
  async function pbkdf2Hash(passcode, saltBytes, iterations) {
    const keyMaterial = await SUBTLE3.importKey("raw", new TextEncoder().encode(passcode), "PBKDF2", false, [
      "deriveBits"
    ]);
    const bits = await SUBTLE3.deriveBits({ name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" }, keyMaterial, 256);
    return toB642(new Uint8Array(bits));
  }
  async function setDuressPasscode(registry, passcode) {
    if (!passcode || passcode.length < 4) {
      throw new DuressError("duress passcode must be at least 4 characters");
    }
    const salt = randomBytes4(16);
    const hash = await pbkdf2Hash(passcode, salt, ITERATIONS);
    return { ...registry, duressPasscode: { salt: toB642(salt), hash, iterations: ITERATIONS } };
  }
  function clearDuressPasscode(registry) {
    const { duressPasscode, ...rest } = registry;
    return rest;
  }
  function hasDuressPasscode(registry) {
    return !!registry.duressPasscode;
  }
  async function isDuressPasscode(registry, candidate) {
    if (!registry.duressPasscode || !candidate) return false;
    const salt = fromB642(registry.duressPasscode.salt);
    const hash = await pbkdf2Hash(candidate, salt, registry.duressPasscode.iterations);
    return hash === registry.duressPasscode.hash;
  }
  function setDefaultAuthCode(registry, code) {
    return { ...registry, defaultAuthCode: code ? code : null };
  }
  function getDefaultAuthCode(registry) {
    return registry.defaultAuthCode ?? null;
  }
  var SUBTLE3, ITERATIONS, DuressError;
  var init_duress = __esm({
    "src/vault/duress.js"() {
      SUBTLE3 = globalThis.crypto.subtle;
      ITERATIONS = 21e4;
      DuressError = class extends Error {
        constructor(message) {
          super(message);
          this.name = "DuressError";
        }
      };
    }
  });

  // src/vault/history.js
  function appendHistory(registry, { kind, detail = {} }) {
    const entry = { id: makeId("hist"), kind, detail, at: (/* @__PURE__ */ new Date()).toISOString() };
    const history = [...registry.history ?? [], entry].slice(-MAX_HISTORY_ENTRIES);
    return { ...registry, history };
  }
  function listHistory(registry) {
    return [...registry.history ?? []].reverse();
  }
  var HISTORY_KINDS, MAX_HISTORY_ENTRIES;
  var init_history = __esm({
    "src/vault/history.js"() {
      init_schema();
      HISTORY_KINDS = Object.freeze({
        CHALLENGE_INITIATED: "challenge-initiated",
        CHALLENGE_OUTCOME: "challenge-outcome",
        DURESS_TRIGGERED: "duress-triggered",
        DEVICE_ADDED: "device-added",
        DEVICE_REMOVED: "device-removed",
        UNLOCK_POLICY_CHANGED: "unlock-policy-changed",
        THRESHOLD_UPDATED: "threshold-updated",
        RESPONDER_APPROVED: "responder-approved",
        RESPONDER_DENIED: "responder-denied",
        REAL_DISPATCH_SENT: "real-dispatch-sent"
      });
      MAX_HISTORY_ENTRIES = 500;
    }
  });

  // src/dispatch/realDispatch.js
  async function sendReal({ channelKind, address, subject, message, baseUrl = DEFAULT_BASE_URL }) {
    if (channelKind !== "email" && channelKind !== "sms") {
      throw new RealDispatchError(`real dispatch only supports 'email' and 'sms' channels, got '${channelKind}'`);
    }
    const path = channelKind === "email" ? "/send-email" : "/send-sms";
    const body = channelKind === "email" ? { to: address, subject: subject || "IdenTT request", text: message } : { to: address, body: message };
    let response;
    try {
      response = await fetch(`${baseUrl}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });
    } catch (e) {
      throw new RealDispatchError(
        `could not reach the local IdenTT backend at ${baseUrl} \u2014 is it running? (cd server && npm install && npm start, after filling in server/.env). Original error: ${e.message}`
      );
    }
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new RealDispatchError(payload.error || `backend responded with HTTP ${response.status}`);
    }
    return payload;
  }
  async function checkBackendHealth(baseUrl = DEFAULT_BASE_URL) {
    try {
      const response = await fetch(`${baseUrl}/health`, { method: "GET" });
      if (!response.ok) return { reachable: false, email: false, sms: false };
      const body = await response.json();
      return { reachable: true, email: !!body.email, sms: !!body.sms };
    } catch {
      return { reachable: false, email: false, sms: false };
    }
  }
  var DEFAULT_BASE_URL, RealDispatchError;
  var init_realDispatch = __esm({
    "src/dispatch/realDispatch.js"() {
      DEFAULT_BASE_URL = "http://localhost:4737";
      RealDispatchError = class extends Error {
        constructor(message) {
          super(message);
          this.name = "RealDispatchError";
        }
      };
    }
  });

  // src/app/screens/requests.js
  function getOutgoingChallenges() {
    return outgoingChallengesByVault.get(session.vaultName) ?? [];
  }
  function pushOutgoingChallenge(challengeSession) {
    const list = outgoingChallengesByVault.get(session.vaultName) ?? [];
    list.unshift(challengeSession);
    outgoingChallengesByVault.set(session.vaultName, list);
  }
  function runtimeChallengeDigest(code) {
    return H2(code).toString(16);
  }
  async function renderRequestsTab(container, root2) {
    container.innerHTML = "";
    const subTabNav = el(
      "nav",
      { className: "subtab-nav" },
      SUB_TABS.map(
        (tab) => el("button", {
          className: `subtab-button${tab.id === activeSubTabId ? " active" : ""}`,
          textContent: tab.label,
          onclick: () => {
            activeSubTabId = tab.id;
            renderRequestsTab(container, root2);
          }
        })
      )
    );
    const subTabContent = el("div", { className: "subtab-content" });
    container.append(subTabNav, subTabContent);
    if (activeSubTabId === "responses") {
      subTabContent.append(renderResponsesSubTab(container));
      await refreshAllResponderInboxes(container);
    } else {
      subTabContent.append(await renderCreateChallengeSection(container, root2));
    }
    container.append(renderHistorySection());
  }
  function renderResponsesSubTab(tabContainer) {
    const responderContainer = el("div", { className: "recovery-results", id: "responder-inbox" });
    const incomingSection = el("section", { className: "card" }, [
      el("h2", { textContent: "Awaiting your response" }),
      el("p", {
        className: "hint",
        textContent: "Authentication/recovery requests from other devices in your trusted mesh. Real live responses come from other local IdenTT (ZRDCP-native) vaults in this browser that have enrolled this vault as a trusted device \u2014 approving a recovery request really decrypts your share with your own private key here, nothing is simulated. FIDO2 devices are approval-only credentials you hold yourself; they don't independently send requests here."
      }),
      responderContainer
    ]);
    const outgoingSection = renderOutgoingChallengesSection(tabContainer);
    return el("div", {}, [incomingSection, outgoingSection]);
  }
  async function refreshAllResponderInboxes(container) {
    const responderContainer = container.querySelector("#responder-inbox");
    if (!responderContainer) return;
    const registry = session.registry;
    responderContainer.innerHTML = "";
    const entries = await listInbox(storage, registry.localIdentity.publicKeyHex);
    if (!entries.length) {
      responderContainer.append(el("p", { className: "hint", textContent: "No pending requests right now." }));
      return;
    }
    responderContainer.append(
      el(
        "ul",
        { className: "dispatch-list" },
        entries.map((entry) => {
          const rowError = el("p", { className: "error" });
          const kindLabel = entry.kind === "vault-unlock-recovery" ? "wants your real share to help unlock its vault" : "wants a live authentication approval to unlock its vault";
          const approveBtn = el("button", {
            textContent: "Approve",
            onclick: async () => {
              rowError.textContent = "";
              try {
                const result = await approveInboxEntry({ entry, responderLocalIdentity: registry.localIdentity });
                if (result.kind === "vault-unlock-recovery") {
                  await pushReconstructionShare(storage, entry.fromVaultName, { deviceId: entry.deviceId, x: result.x, y: result.y });
                } else {
                  await pushAuthApproval(storage, entry.fromVaultName, { deviceId: entry.deviceId });
                }
                await removeInboxEntry(storage, registry.localIdentity.publicKeyHex, entry.id);
                session.registry = appendHistory(registry, {
                  kind: HISTORY_KINDS.RESPONDER_APPROVED,
                  detail: { fromVaultName: entry.fromVaultName, requestKind: entry.kind }
                });
                await persist();
                refreshHistorySection(container);
                await refreshAllResponderInboxes(container);
              } catch (e) {
                rowError.textContent = e.message;
              }
            }
          });
          const denyBtn = el("button", {
            className: "danger",
            textContent: "Deny",
            onclick: async () => {
              await removeInboxEntry(storage, registry.localIdentity.publicKeyHex, entry.id);
              session.registry = appendHistory(registry, {
                kind: HISTORY_KINDS.RESPONDER_DENIED,
                detail: { fromVaultName: entry.fromVaultName, requestKind: entry.kind }
              });
              await persist();
              refreshHistorySection(container);
              await refreshAllResponderInboxes(container);
            }
          });
          return el("li", { className: "dispatch-row" }, [
            el("span", { className: "device-name", textContent: `"${entry.fromVaultName}" ${kindLabel}` }),
            el("span", { className: "hint", textContent: `Request ${entry.id}` }),
            approveBtn,
            denyBtn,
            rowError
          ]);
        })
      )
    );
  }
  function renderOutgoingChallengesSection(tabContainer) {
    const challenges = getOutgoingChallenges();
    const section2 = el("section", { className: "card" }, [
      el("h2", { textContent: `Challenges you've initiated (${challenges.length})` }),
      el("p", {
        className: "hint",
        textContent: "Recovery/authentication challenges you started from this vault this browser session \u2014 track dispatch and evaluate responses here, including the runtime-challenge authentication step below."
      })
    ]);
    if (!challenges.length) {
      section2.append(el("p", { className: "hint", textContent: "None yet \u2014 start one from the Create Challenge sub-tab." }));
      return section2;
    }
    for (const challengeSession of challenges) {
      const wrapper = el("div", { className: "recovery-results" });
      renderChallengeResults(wrapper, challengeSession, tabContainer);
      section2.append(wrapper, el("hr"));
    }
    return section2;
  }
  async function renderCreateChallengeSection(tabContainer, root2) {
    const registry = session.registry;
    const backendStatus = el("p", { className: "hint", textContent: "Checking local backend for real email/SMS\u2026" });
    checkBackendHealth().then((health) => {
      backendStatus.textContent = health.reachable ? `Local backend reachable \u2014 real send available for: ${[health.email && "email", health.sms && "SMS"].filter(Boolean).join(", ") || "none configured yet"}.` : 'Local backend not reachable \u2014 "Send for real" will be unavailable until you run it (see server/README.md). Simulated dispatch below still works either way.';
    });
    const purposeSelect = el("select", {}, [
      el("option", { value: "recovery", textContent: `Recovery (needs ${registry.threshold.kRecovery} shares, ${registry.threshold.minRemoteForRecovery} remote)` }),
      el("option", { value: "authentication", textContent: `Authentication (needs ${registry.threshold.kAuthentication} approvals)` })
    ]);
    const recoveryCodeInput = el("input", { type: "password", placeholder: "Runtime code (C_r)", value: getDefaultAuthCode(registry) ?? "" });
    const recoveryError = el("p", { className: "error" });
    const recoveryStatus = el("p", { className: "status" });
    const initiateBtn = el("button", {
      className: "danger-action",
      textContent: "Initiate challenge",
      onclick: async () => {
        recoveryError.textContent = "";
        if (!recoveryCodeInput.value) {
          recoveryError.textContent = "Enter a runtime code first.";
          return;
        }
        recoveryStatus.textContent = "Computing commitment, proof, and (for recovery) shares\u2026";
        try {
          const enteredCode = recoveryCodeInput.value;
          const isDuress = await isDuressPasscode(session.registry, enteredCode);
          recoveryCodeInput.value = "";
          recoveryStatus.textContent = "";
          if (isDuress) {
            const decoySession = buildDecoySession({ registry: session.registry, purpose: purposeSelect.value });
            session.registry = appendHistory(session.registry, {
              kind: HISTORY_KINDS.DURESS_TRIGGERED,
              detail: { purpose: purposeSelect.value, sessionId: decoySession.sessionId }
            });
            await persist();
            pushOutgoingChallenge(decoySession);
            activeSubTabId = "responses";
            await renderRequestsTab(tabContainer, root2);
            return;
          }
          const challengeSession = await initiateRecovery({
            registry: session.registry,
            runtimeEntropy: enteredCode,
            purpose: purposeSelect.value
          });
          challengeSession.runtimeChallengeHash = runtimeChallengeDigest(enteredCode);
          session.registry = appendHistory(session.registry, {
            kind: HISTORY_KINDS.CHALLENGE_INITIATED,
            detail: { purpose: challengeSession.purpose, sessionId: challengeSession.sessionId }
          });
          await persist();
          pushOutgoingChallenge(challengeSession);
          activeSubTabId = "responses";
          await renderRequestsTab(tabContainer, root2);
        } catch (e) {
          recoveryStatus.textContent = "";
          recoveryError.textContent = e instanceof RecoveryInitiationError ? e.message : `Unexpected error: ${e.message}`;
        }
      }
    });
    return el("section", { className: "card" }, [
      el("h2", { textContent: "Create a challenge" }),
      el("p", {
        className: "hint",
        textContent: "For proving yourself to some OTHER application that issued a challenge \u2014 not for unlocking this vault (see the Vaults tab for that). Authentication is a lightweight quorum check; Recovery computes the Pedersen commitment + NIZK proof and splits it across your share-holding devices, requiring at least one remote device among the responders."
      }),
      el("p", {
        className: "hint",
        textContent: "Every device this gets dispatched to must independently enter the exact same runtime code you use below before its response counts \u2014 an authentication step confirming they're a trusted party in real time, on top of (not instead of) the cryptographic proof. Submitting takes you to the Responses sub-tab to track it."
      }),
      backendStatus,
      el("label", { textContent: "Purpose" }),
      purposeSelect,
      recoveryCodeInput,
      initiateBtn,
      recoveryStatus,
      recoveryError
    ]);
  }
  function renderChallengeResults(resultsContainer, recoverySession, tabContainer) {
    resultsContainer.innerHTML = "";
    const challengeInputs = /* @__PURE__ */ new Map();
    const outcomeResult = el("div", { className: "outcome-result" });
    if (recoverySession._lastOutcome) {
      renderOutcome(outcomeResult, recoverySession._lastOutcome);
    }
    const dispatchRows = recoverySession.dispatches.map((d) => {
      const challengeInput = el("input", {
        type: "text",
        className: "outcome-select",
        placeholder: "Enter the exact runtime challenge",
        "data-device-id": d.deviceId
      });
      challengeInputs.set(d.deviceId, challengeInput);
      const rowChildren = [
        el("span", { className: "device-name", textContent: `${d.deviceName} (${d.deviceType})` }),
        el("span", { className: "device-meta", textContent: `${d.channelKind} \u2192 ${d.address}` }),
        el("span", {
          className: "device-meta",
          textContent: d.hasShare ? "share sent" : "notification only (no share)"
        }),
        el("span", { className: "device-meta", textContent: d.isRemote ? "remote" : "local" })
      ];
      if (!recoverySession.decoy) {
        rowChildren.push(
          el("span", { className: "hint", textContent: d.payloadPreview }),
          el("span", { className: "hint", textContent: `Responder link: ${d.responderLink}` })
        );
      }
      if (!recoverySession.decoy && (d.channelKind === "email" || d.channelKind === "sms")) {
        const realStatus = el("span", { className: "hint" });
        const realBtn = el("button", {
          className: "secondary",
          textContent: `Send for real (${d.channelKind})`,
          onclick: async () => {
            realStatus.textContent = "Sending\u2026";
            try {
              const message = `${d.payloadPreview} Responder link: ${d.responderLink}`;
              await sendReal({ channelKind: d.channelKind, address: d.address, subject: "IdenTT request", message });
              realStatus.textContent = "\u2713 sent for real.";
              session.registry = appendHistory(session.registry, {
                kind: HISTORY_KINDS.REAL_DISPATCH_SENT,
                detail: { deviceName: d.deviceName, channelKind: d.channelKind, sessionId: recoverySession.sessionId }
              });
              await persist();
              refreshHistorySection(tabContainer);
            } catch (e) {
              realStatus.textContent = e instanceof RealDispatchError ? e.message : `Unexpected error: ${e.message}`;
            }
          }
        });
        rowChildren.push(realBtn, realStatus);
      }
      rowChildren.push(
        el("label", {
          className: "outcome-label",
          textContent: "Receiving device's response \u2014 must enter the exact runtime challenge to authenticate:"
        }),
        challengeInput
      );
      return el("li", { className: "dispatch-row" }, rowChildren);
    });
    const evaluateBtn = el("button", {
      className: "secondary",
      textContent: "Evaluate outcome",
      onclick: async () => {
        let outcome;
        if (recoverySession.decoy) {
          outcome = decoyOutcome(recoverySession);
        } else {
          const responses = {};
          for (const [deviceId, input] of challengeInputs) {
            const typed = input.value.trim();
            if (!typed) continue;
            responses[deviceId] = runtimeChallengeDigest(typed) === recoverySession.runtimeChallengeHash ? "success" : "fail";
          }
          outcome = evaluateChallengeOutcome({ session: recoverySession, responses });
          session.registry = appendHistory(session.registry, {
            kind: HISTORY_KINDS.CHALLENGE_OUTCOME,
            detail: { sessionId: recoverySession.sessionId, granted: outcome.granted, purpose: outcome.purpose }
          });
          await persist();
          refreshHistorySection(tabContainer);
        }
        recoverySession._lastOutcome = outcome;
        renderOutcome(outcomeResult, outcome);
      }
    });
    resultsContainer.append(
      el("p", { className: "status", textContent: `Session ${recoverySession.sessionId} initiated (${recoverySession.purpose}).` }),
      el("p", {
        className: "hint",
        textContent: `Commitment: ${recoverySession.recoveryInit.pedersen_commitment.slice(0, 24)}\u2026`
      }),
      el("ul", { className: "dispatch-list" }, dispatchRows),
      evaluateBtn,
      outcomeResult
    );
  }
  function renderOutcome(container, outcome) {
    container.innerHTML = "";
    const verdict = el("p", {
      className: outcome.granted ? "status" : "error",
      textContent: outcome.granted ? `\u2713 ${outcome.purpose === "authentication" ? "Authentication" : "Recovery"} would succeed.` : `\u2717 ${outcome.purpose === "authentication" ? "Authentication" : "Recovery"} would fail.`
    });
    const detailParts = [`${outcome.successCount}/${outcome.requiredK} required responses succeeded`];
    if (outcome.purpose === "recovery") {
      detailParts.push(
        `${outcome.remoteSuccessCount}/${outcome.minRemoteForRecovery} required remote share-holder responses succeeded`
      );
    }
    const detail = el("p", { className: "hint", textContent: detailParts.join(" \xB7 ") });
    const reason = el("p", { className: "hint", textContent: outcome.reason ?? "" });
    container.append(verdict, detail, reason);
  }
  function historyRows(entries) {
    return entries.map((entry) => {
      const labelFn = HISTORY_LABELS[entry.kind];
      const label = labelFn ? labelFn(entry.detail) : entry.kind;
      return el("li", { className: "dispatch-row" }, [
        el("span", { className: "device-name", textContent: label }),
        el("span", { className: "hint", textContent: formatTimestamp(entry.at) })
      ]);
    });
  }
  function renderHistorySection() {
    const entries = listHistory(session.registry);
    const rows = historyRows(entries);
    return el("section", { className: "card" }, [
      el("h2", { id: "history-heading", textContent: `History (${entries.length})` }),
      el("p", { className: "hint", textContent: "A record of challenges, responses, and security changes for this vault, newest first." }),
      el("ul", { className: "dispatch-list", id: "history-list" }, rows.length ? rows : [el("li", { textContent: "Nothing yet." })])
    ]);
  }
  function refreshHistorySection(tabContainer) {
    if (!tabContainer) return;
    const heading = tabContainer.querySelector("#history-heading");
    const list = tabContainer.querySelector("#history-list");
    if (!heading || !list) return;
    const entries = listHistory(session.registry);
    heading.textContent = `History (${entries.length})`;
    list.innerHTML = "";
    const rows = historyRows(entries);
    for (const row of rows.length ? rows : [el("li", { textContent: "Nothing yet." })]) {
      list.append(row);
    }
  }
  var SUB_TABS, activeSubTabId, outgoingChallengesByVault, HISTORY_LABELS;
  var init_requests = __esm({
    "src/app/screens/requests.js"() {
      init_ui();
      init_state();
      init_crossVault();
      init_respond();
      init_initiate();
      init_evaluateOutcome();
      init_decoy();
      init_duress();
      init_history();
      init_realDispatch();
      init_hash();
      SUB_TABS = [
        { id: "create", label: "Create Challenge" },
        { id: "responses", label: "Responses" }
      ];
      activeSubTabId = "create";
      outgoingChallengesByVault = /* @__PURE__ */ new Map();
      HISTORY_LABELS = {
        [HISTORY_KINDS.CHALLENGE_INITIATED]: (d) => `Challenge initiated (${d.purpose}) \u2014 session ${d.sessionId}`,
        [HISTORY_KINDS.CHALLENGE_OUTCOME]: (d) => `Challenge outcome (${d.purpose}) \u2014 ${d.granted ? "granted" : "denied"} \u2014 session ${d.sessionId}`,
        [HISTORY_KINDS.DURESS_TRIGGERED]: (d) => `\u26A0 Duress passcode used (${d.purpose}) \u2014 session ${d.sessionId}`,
        [HISTORY_KINDS.DEVICE_ADDED]: (d) => `Device added: ${d.deviceName}`,
        [HISTORY_KINDS.DEVICE_REMOVED]: (d) => `Device removed: ${d.deviceName}`,
        [HISTORY_KINDS.UNLOCK_POLICY_CHANGED]: (d) => `Unlock policy changed to "${d.policy}"`,
        [HISTORY_KINDS.THRESHOLD_UPDATED]: () => `Mesh & threshold settings updated`,
        [HISTORY_KINDS.RESPONDER_APPROVED]: (d) => `Approved a ${d.requestKind} request from "${d.fromVaultName}"`,
        [HISTORY_KINDS.RESPONDER_DENIED]: (d) => `Denied a ${d.requestKind} request from "${d.fromVaultName}"`,
        [HISTORY_KINDS.REAL_DISPATCH_SENT]: (d) => `Real ${d.channelKind} sent to ${d.deviceName} \u2014 session ${d.sessionId}`
      };
    }
  });

  // src/app/screens/vaults.js
  async function renderVaultsTab(container, root2) {
    container.innerHTML = "";
    const registry = session.registry;
    const vaultName = session.vaultName;
    const vaultMeta = await getVaultMeta(storage, vaultName);
    container.append(
      renderSecuritySection(root2, vaultName, vaultMeta),
      renderThresholdSection(root2, registry),
      renderWarnings(registry),
      renderPasscodesSection(root2, registry)
    );
  }
  function renderSecuritySection(root2, vaultName, vaultMeta) {
    const registry = session.registry;
    const policySelect = el(
      "select",
      {},
      [
        { value: UNLOCK_POLICIES.PASSPHRASE, textContent: "Passphrase only" },
        {
          value: UNLOCK_POLICIES.AUTHENTICATION,
          textContent: `Passphrase + live authentication (needs ${registry.threshold.kAuthentication} approvals)`
        },
        {
          value: UNLOCK_POLICIES.RECOVERY,
          textContent: `Recovery only, no passphrase (needs ${registry.threshold.kRecovery} shares, ${registry.threshold.minRemoteForRecovery} remote)`
        }
      ].map((opt) => el("option", opt))
    );
    policySelect.value = vaultMeta.unlockPolicy;
    const newPassInput = el("input", { type: "password", placeholder: "New passphrase (only needed when leaving Recovery-only)" });
    const securityError = el("p", { className: "error" });
    const securityStatus = el("p", { className: "status", textContent: consumePendingNotice() ?? "" });
    const savePolicyBtn = el("button", {
      textContent: "Update unlock policy",
      onclick: async () => {
        securityError.textContent = "";
        securityStatus.textContent = "";
        const targetPolicy = policySelect.value;
        const store = createVaultStore(storage, vaultName);
        try {
          if (targetPolicy === UNLOCK_POLICIES.RECOVERY) {
            const { keyHex, recoverySplit } = await enableRecoveryUnlock({ registry: session.registry });
            session.registry = appendHistory(session.registry, {
              kind: HISTORY_KINDS.UNLOCK_POLICY_CHANGED,
              detail: { policy: UNLOCK_POLICIES.RECOVERY }
            });
            await store.saveWithKey(keyHex, session.registry);
            await setVaultMeta(storage, vaultName, { unlockPolicy: UNLOCK_POLICIES.RECOVERY, recoverySplit });
            await clearReconstructionShares(storage, vaultName);
            session.unlockSecret = { kind: "key", value: keyHex };
            setPendingNotice(
              "Recovery-based unlock enabled. Your passphrase no longer opens this vault \u2014 only your trusted-device mesh can, from now on."
            );
          } else {
            if (session.unlockSecret.kind === "key") {
              if (!newPassInput.value) {
                securityError.textContent = "Set a new passphrase to leave Recovery-only unlock.";
                return;
              }
              session.registry = appendHistory(session.registry, {
                kind: HISTORY_KINDS.UNLOCK_POLICY_CHANGED,
                detail: { policy: targetPolicy }
              });
              await store.save(newPassInput.value, session.registry);
              session.unlockSecret = { kind: "passphrase", value: newPassInput.value };
            } else {
              session.registry = appendHistory(session.registry, {
                kind: HISTORY_KINDS.UNLOCK_POLICY_CHANGED,
                detail: { policy: targetPolicy }
              });
              await persist();
            }
            await setVaultMeta(storage, vaultName, { unlockPolicy: targetPolicy, recoverySplit: vaultMeta.recoverySplit });
            setPendingNotice(`Unlock policy set to "${targetPolicy}".`);
          }
          renderShell(root2, { tabId: "vaults" });
        } catch (e) {
          securityError.textContent = e.message;
        }
      }
    });
    const children = [
      el("h2", { textContent: "Vault security" }),
      el("p", {
        className: "hint",
        textContent: 'How this vault unlocks next time. "Recovery only" protects it with your trusted-device mesh instead of a passphrase \u2014 see the Help tab for the full mechanism.'
      }),
      policySelect,
      newPassInput,
      savePolicyBtn
    ];
    if (vaultMeta.unlockPolicy === UNLOCK_POLICIES.RECOVERY) {
      children.push(
        el("button", {
          className: "secondary",
          textContent: "Regenerate recovery split (after mesh changes)",
          onclick: async () => {
            securityError.textContent = "";
            try {
              const { keyHex, recoverySplit } = await enableRecoveryUnlock({ registry: session.registry });
              const store = createVaultStore(storage, vaultName);
              await store.saveWithKey(keyHex, session.registry);
              await setVaultMeta(storage, vaultName, { unlockPolicy: UNLOCK_POLICIES.RECOVERY, recoverySplit });
              await clearReconstructionShares(storage, vaultName);
              session.unlockSecret = { kind: "key", value: keyHex };
              renderShell(root2, { tabId: "vaults" });
            } catch (e) {
              securityError.textContent = e.message;
            }
          }
        })
      );
    }
    children.push(securityStatus, securityError);
    return el("section", { className: "card" }, children);
  }
  function renderThresholdSection(root2, registry) {
    const targetNInput = el("input", { type: "number", min: 4, max: 9, value: registry.threshold.targetN });
    const kAuthInput = el("input", { type: "number", min: 2, value: registry.threshold.kAuthentication });
    const kRecoveryInput = el("input", { type: "number", min: 3, value: registry.threshold.kRecovery });
    const minRemoteInput = el("input", { type: "number", min: 1, value: registry.threshold.minRemoteForRecovery });
    const thresholdError = el("p", { className: "error" });
    const saveThresholdBtn = el("button", {
      textContent: "Update threshold",
      onclick: async () => {
        thresholdError.textContent = "";
        try {
          session.registry = setThreshold(session.registry, {
            targetN: Number(targetNInput.value),
            kAuthentication: Number(kAuthInput.value),
            kRecovery: Number(kRecoveryInput.value),
            minRemoteForRecovery: Number(minRemoteInput.value)
          });
          session.registry = appendHistory(session.registry, { kind: HISTORY_KINDS.THRESHOLD_UPDATED });
          await persist();
          renderShell(root2, { tabId: "vaults" });
        } catch (e) {
          thresholdError.textContent = e.message;
        }
      }
    });
    return el("section", { className: "card" }, [
      el("h2", { textContent: "Mesh & threshold" }),
      el("label", { textContent: "Max / target trusted devices for this mesh (n) \u2014 must be 4-9" }),
      targetNInput,
      el("label", { textContent: "Devices required to authenticate (any type, no share math)" }),
      kAuthInput,
      el("label", { textContent: "Devices required to recover (must hold real shares)" }),
      kRecoveryInput,
      el("label", { textContent: "Of those, minimum flagged remote (not co-located with you)" }),
      minRemoteInput,
      saveThresholdBtn,
      thresholdError
    ]);
  }
  function renderWarnings(registry) {
    const warnings = registryWarnings(registry);
    return warnings.length ? el(
      "div",
      { className: "warnings" },
      warnings.map((w) => el("p", { textContent: `\u26A0 ${w}` }))
    ) : el("div");
  }
  function renderPasscodesSection(root2, registry) {
    const defaultCodeInput = el("input", { type: "text", placeholder: "Default authentication code (optional)", value: getDefaultAuthCode(registry) ?? "" });
    const defaultCodeError = el("p", { className: "error" });
    const defaultCodeStatus = el("p", { className: "status" });
    const saveDefaultBtn = el("button", {
      className: "secondary",
      textContent: "Save default authentication code",
      onclick: async () => {
        defaultCodeError.textContent = "";
        session.registry = setDefaultAuthCode(session.registry, defaultCodeInput.value.trim());
        await persist();
        defaultCodeStatus.textContent = defaultCodeInput.value.trim() ? "Saved." : "Cleared.";
      }
    });
    const duressInput = el("input", { type: "password", placeholder: "New duress passcode" });
    const duressConfirm = el("input", { type: "password", placeholder: "Confirm duress passcode" });
    const duressError = el("p", { className: "error" });
    const duressStatus = el("p", { className: "status", textContent: hasDuressPasscode(registry) ? "A duress passcode is currently set." : "No duress passcode is set." });
    const saveDuressBtn = el("button", {
      className: "secondary",
      textContent: "Set duress passcode",
      onclick: async () => {
        duressError.textContent = "";
        if (duressInput.value !== duressConfirm.value) {
          duressError.textContent = "Passcodes do not match.";
          return;
        }
        try {
          session.registry = await setDuressPasscode(session.registry, duressInput.value);
          await persist();
          duressInput.value = "";
          duressConfirm.value = "";
          duressStatus.textContent = "Duress passcode set.";
        } catch (e) {
          duressError.textContent = e instanceof DuressError ? e.message : `Unexpected error: ${e.message}`;
        }
      }
    });
    const clearDuressBtn = el("button", {
      className: "danger",
      textContent: "Clear duress passcode",
      onclick: async () => {
        session.registry = clearDuressPasscode(session.registry);
        await persist();
        duressStatus.textContent = "Duress passcode cleared.";
      }
    });
    return el("section", { className: "card" }, [
      el("h2", { textContent: "Duress & authentication passcodes" }),
      el("p", {
        className: "hint",
        textContent: "Default authentication code: optional convenience that prefills the Requests tab's runtime-code field. Fully overridable per attempt \u2014 leaving it blank changes nothing about how a challenge is computed."
      }),
      defaultCodeInput,
      saveDefaultBtn,
      defaultCodeStatus,
      defaultCodeError,
      el("hr"),
      el("p", {
        className: "hint",
        textContent: "Duress passcode: enter this instead of your real runtime code on the Requests tab under coercion, and IdenTT produces an indistinguishable fake success instead \u2014 nothing real is sent or reconstructed. The only record is a silent history entry, visible only here after you've genuinely signed in."
      }),
      duressStatus,
      duressInput,
      duressConfirm,
      saveDuressBtn,
      clearDuressBtn,
      duressError
    ]);
  }
  var init_vaults = __esm({
    "src/app/screens/vaults.js"() {
      init_ui();
      init_state();
      init_meta();
      init_unlockRecovery();
      init_crossVault();
      init_store();
      init_registry();
      init_duress();
      init_history();
      init_shell();
    }
  });

  // src/fido/simulate.js
  function deriveKeypairFromPrfOutput(prfOutputBytes) {
    const privateScalar = mod2(H2(prfOutputBytes));
    const publicPoint = G.multiply(privateScalar);
    return {
      privateKeyHex: scalarToHex(privateScalar),
      publicKeyHex: pointToHex(publicPoint)
    };
  }
  async function simulateGetPrfOutput(credential, salt) {
    if (!credential._debugPrfSeed) {
      throw new Error(
        "simulateGetPrfOutput: this credential has no PRF seed \u2014 either it was registered without prfSupported, or (realistically) this in-memory simulation does not outlive the session it was created in."
      );
    }
    const hmacKey = await globalThis.crypto.subtle.importKey(
      "raw",
      credential._debugPrfSeed,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sig = await globalThis.crypto.subtle.sign("HMAC", hmacKey, new TextEncoder().encode(salt));
    return new Uint8Array(sig);
  }
  function base64url(bytes) {
    let bin = "";
    for (const b of bytes) bin += String.fromCharCode(b);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  async function simulateRegister({ name, prfHint } = {}) {
    const keypair = await globalThis.crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const publicKeyJwk = await globalThis.crypto.subtle.exportKey("jwk", keypair.publicKey);
    const credentialId = base64url(globalThis.crypto.getRandomValues(new Uint8Array(32)));
    const prfSupported = typeof prfHint === "boolean" ? prfHint : Math.random() < 0.7;
    let derivedPublicKeyHex = null;
    let debugPrfSeed = null;
    if (prfSupported) {
      debugPrfSeed = globalThis.crypto.getRandomValues(new Uint8Array(32));
      const prfOutput = await simulateGetPrfOutput({ _debugPrfSeed: debugPrfSeed }, PRF_SALT);
      derivedPublicKeyHex = deriveKeypairFromPrfOutput(prfOutput).publicKeyHex;
    }
    return {
      credentialId,
      publicKeyJwk,
      prfSupported,
      derivedPublicKeyHex,
      transports: ["internal", "hybrid"],
      attestationFormat: "simulated-none",
      simulated: true,
      _debugLabel: name,
      _debugPrivateKeyHandle: keypair.privateKey,
      // in-memory only, for simulateAssert(); never persisted
      _debugPrfSeed: debugPrfSeed
      // in-memory only, for simulateGetPrfOutput() later this session; never persisted
    };
  }
  var PRF_SALT;
  var init_simulate2 = __esm({
    "src/fido/simulate.js"() {
      init_hash();
      init_curve2();
      PRF_SALT = "ZRDCP/1.0 IdenTT share-wrap-keypair v1";
    }
  });

  // src/app/screens/devices.js
  async function renderDevicesTab(container, root2) {
    container.innerHTML = "";
    container.append(
      renderIdentitySection(),
      renderDeviceList(root2),
      renderAddNativeSection(root2),
      renderAddFidoSection(root2)
    );
  }
  function renderIdentitySection() {
    const registry = session.registry;
    const identityCopyStatus = el("p", { className: "status" });
    return el("section", { className: "card" }, [
      el("h2", { textContent: "Your device identity" }),
      el("p", {
        className: "hint",
        textContent: "This device's own ZRDCP public key \u2014 share it with people/devices enrolling YOU as one of their trusted devices. Generated once when this vault was created; every outgoing share is wrapped using its private half, which never leaves this vault."
      }),
      el("input", { type: "text", readOnly: true, value: registry.localIdentity.publicKeyHex }),
      el("button", {
        className: "secondary",
        textContent: "Copy public key",
        onclick: async () => {
          try {
            await navigator.clipboard.writeText(registry.localIdentity.publicKeyHex);
            identityCopyStatus.textContent = "Copied.";
          } catch {
            identityCopyStatus.textContent = "Could not copy \u2014 select and copy manually.";
          }
        }
      }),
      identityCopyStatus
    ]);
  }
  function renderDeviceList(root2) {
    const registry = session.registry;
    const deviceRows = registry.devices.map(
      (device) => el("li", { className: "device-row" }, [
        el("span", { className: "device-name", textContent: device.name }),
        el("span", { className: "device-meta", textContent: deviceSummary(device) }),
        el("span", {
          className: "device-contacts",
          textContent: device.contactChannels.map((c) => `${c.kind}:${c.address}`).join(", ")
        }),
        el("button", {
          className: "danger",
          textContent: "Remove",
          onclick: async () => {
            session.registry = removeDevice(session.registry, device.id);
            session.registry = appendHistory(session.registry, {
              kind: HISTORY_KINDS.DEVICE_REMOVED,
              detail: { deviceName: device.name }
            });
            await persist();
            const { renderShell: renderShell2 } = await Promise.resolve().then(() => (init_shell(), shell_exports));
            renderShell2(root2, { tabId: "devices" });
          }
        })
      ])
    );
    return el("section", { className: "card" }, [
      el("h2", {
        textContent: `Trusted devices (${registry.devices.length} enrolled, ${shareHoldingDeviceCount(registry)} share-holding)`
      }),
      el("ul", { className: "device-list" }, deviceRows.length ? deviceRows : [el("li", { textContent: "None yet." })])
    ]);
  }
  function renderAddNativeSection(root2) {
    const nativeName = el("input", { type: "text", placeholder: `Device name (e.g. "Spouse's phone")` });
    const nativeContactKind = el(
      "select",
      {},
      Object.values(CONTACT_KINDS).map((k) => el("option", { value: k, textContent: k }))
    );
    const nativeContactAddr = el("input", { type: "text", placeholder: "Contact address (email/phone/URL)" });
    const nativePubkey = el("input", { type: "text", placeholder: "Public key (hex) \u2014 paste another local vault's identity key to test Responder Mode for real" });
    const nativeIsRemote = el("input", { type: "checkbox" });
    const nativeRemoteLabel = el("label", { className: "checkbox-label" }, [
      nativeIsRemote,
      document.createTextNode(" This device is remote (not physically co-located with me)")
    ]);
    const generateDemoKeyBtn = el("button", {
      className: "secondary",
      textContent: "Generate demo keypair",
      title: "For testing only \u2014 a real device should generate and keep its own private key locally.",
      onclick: () => {
        const priv = randomScalar();
        const pub = G.multiply(priv);
        nativePubkey.value = pointToHex(pub);
      }
    });
    const nativeError = el("p", { className: "error" });
    const addNativeBtn = el("button", {
      textContent: "Add zrdcp-native device",
      onclick: async () => {
        nativeError.textContent = "";
        try {
          const device = createZrdcpNativeDevice({
            name: nativeName.value,
            contactChannels: [{ kind: nativeContactKind.value, address: nativeContactAddr.value }],
            publicKeyHex: nativePubkey.value,
            isRemote: nativeIsRemote.checked
          });
          session.registry = addDevice(session.registry, device);
          session.registry = appendHistory(session.registry, {
            kind: HISTORY_KINDS.DEVICE_ADDED,
            detail: { deviceName: device.name }
          });
          await persist();
          const { renderShell: renderShell2 } = await Promise.resolve().then(() => (init_shell(), shell_exports));
          renderShell2(root2, { tabId: "devices" });
        } catch (e) {
          nativeError.textContent = e.message;
        }
      }
    });
    return el("section", { className: "card" }, [
      el("h2", { textContent: "Add a ZRDCP-native device" }),
      nativeName,
      nativeContactKind,
      nativeContactAddr,
      nativePubkey,
      generateDemoKeyBtn,
      nativeRemoteLabel,
      addNativeBtn,
      nativeError
    ]);
  }
  function renderAddFidoSection(root2) {
    const fidoName = el("input", { type: "text", placeholder: 'Device name (e.g. "YubiKey 5C")' });
    const fidoContactKind = el(
      "select",
      {},
      Object.values(CONTACT_KINDS).map((k) => el("option", { value: k, textContent: k }))
    );
    const fidoContactAddr = el("input", { type: "text", placeholder: "Contact address (email/phone/URL)" });
    const fidoIsRemote = el("input", { type: "checkbox" });
    const fidoRemoteLabel = el("label", { className: "checkbox-label" }, [
      fidoIsRemote,
      document.createTextNode(" This device is remote (not physically co-located with me)")
    ]);
    const fidoStatus = el("p", { className: "status" });
    const fidoError = el("p", { className: "error" });
    const registerFidoBtn = el("button", {
      textContent: "Register FIDO2 device (simulated)",
      title: "Real WebAuthn ceremonies need a local server + real hardware \u2014 deferred to a later phase.",
      onclick: async () => {
        fidoError.textContent = "";
        if (!fidoName.value.trim()) {
          fidoError.textContent = "Device name is required.";
          return;
        }
        fidoStatus.textContent = "Registering (simulated ceremony)\u2026";
        try {
          const credential = await simulateRegister({ name: fidoName.value });
          const device = createFidoDevice({
            name: fidoName.value,
            contactChannels: [{ kind: fidoContactKind.value, address: fidoContactAddr.value }],
            credential,
            isRemote: fidoIsRemote.checked
          });
          session.registry = addDevice(session.registry, device);
          session.registry = appendHistory(session.registry, {
            kind: HISTORY_KINDS.DEVICE_ADDED,
            detail: { deviceName: device.name }
          });
          await persist();
          const { renderShell: renderShell2 } = await Promise.resolve().then(() => (init_shell(), shell_exports));
          renderShell2(root2, { tabId: "devices" });
        } catch (e) {
          fidoStatus.textContent = "";
          fidoError.textContent = e.message;
        }
      }
    });
    return el("section", { className: "card" }, [
      el("h2", { textContent: "Add a FIDO2/WebAuthn device" }),
      el("p", {
        className: "hint",
        textContent: "Simulated for now \u2014 participation mode (full-share vs. approval-only) is decided by whether the simulated ceremony reports PRF/hmac-secret support, exactly as a real one would. FIDO2 devices can never be a local Responder Mode vault (they are not IdenTT vaults) \u2014 only zrdcp-native devices can."
      }),
      fidoName,
      fidoContactKind,
      fidoContactAddr,
      fidoRemoteLabel,
      registerFidoBtn,
      fidoStatus,
      fidoError
    ]);
  }
  var init_devices = __esm({
    "src/app/screens/devices.js"() {
      init_ui();
      init_state();
      init_registry();
      init_schema();
      init_simulate2();
      init_curve2();
      init_history();
    }
  });

  // src/app/screens/help.js
  function section(title, paragraphs) {
    return el("section", { className: "card" }, [
      el("h2", { textContent: title }),
      ...paragraphs.map((p) => el("p", { className: "hint", textContent: p }))
    ]);
  }
  async function renderHelpTab(container) {
    container.innerHTML = "";
    container.append(
      section("What IdenTT is", [
        "IdenTT is a local, offline-first implementation of the Zero-Knowledge Runtime-Generated Dynamic Challenge Protocol (ZRDCP): a way to authenticate or recover access to an account using a threshold of trusted devices instead of (or in addition to) a single password, without ever exposing your real secret to any one device or server.",
        "Everything runs in your browser and, optionally, a small local backend you run yourself for real email/SMS. Nothing is sent to any third party unless you explicitly configure that backend."
      ]),
      section("1. Signing on", [
        'The Sign On screen is the only screen you see before unlocking a vault. Pick a vault from the dropdown to see its sign-in options, or choose "+ Create a new vault" to start fresh.',
        `Authentication mode: enter the vault's passphrase. If the vault also requires a live authentication check-in (its own "devices required to authenticate" quorum, set on the Vaults tab), you'll be asked to collect that many real approvals from other local vaults next, before it opens.`,
        "Recovery mode: for a vault with no passphrase at all. Its unlock key is protected by a real Shamir secret split across its trusted-device mesh \u2014 generated once when you switch a vault to this mode (Vaults tab) and reconstructed for real once enough of those devices respond with their genuine shares.",
        "Deleting a vault (from its sign-in panel) removes it and its local scratch data permanently \u2014 this cannot be undone."
      ]),
      section("2. Requests tab", [
        "Two sub-tabs live here: Create Challenge, and Responses. History (below both) is a running log of challenges, responses, and security-relevant changes for this vault, newest first \u2014 stored inside the vault itself, so it's only ever visible once you've genuinely signed in.",
        "Create Challenge: for proving yourself to some OTHER application that issued a challenge \u2014 not for unlocking the vault you're currently in (see Vault security below for that). Choose Authentication (a lightweight quorum check) or Recovery (computes a Pedersen commitment + zero-knowledge proof and splits it across your share-holding devices, requiring at least one remote responder). Submitting takes you straight to Responses to track it.",
        `Runtime-challenge response authentication: every device a challenge is dispatched to must independently enter the EXACT runtime code you used before its response counts \u2014 a manual, real-time authentication step (you'd tell trusted responders the code directly, e.g. by phone) that sits on top of, not instead of, the Pedersen/NIZK cryptographic proof. Typing the wrong code, or nothing, means that device's response doesn't count toward the threshold even though it "responded."`,
        `Responses \u2014 "Awaiting your response": requests from OTHER local vaults in this same browser that have enrolled this vault as one of their trusted devices. Approving a recovery request really decrypts your genuine Shamir share using this vault's own private key \u2014 nothing here is simulated.`,
        `Responses \u2014 "Challenges you've initiated": every challenge you've started this browser session, each with its dispatch rows, the runtime-challenge entry field described above, and an "Evaluate outcome" button. If you've run the local backend (see "Real email/SMS" below), email and SMS rows also get a "Send for real" button that actually delivers the request.`
      ]),
      section("3. Vaults tab", [
        "Vault security: choose how this vault unlocks \u2014 passphrase only, passphrase plus a live authentication check-in, or recovery-only (no passphrase, mesh-protected). Switching to recovery-only generates a fresh Shamir split across your currently enrolled share-holding devices; regenerate it any time your mesh changes.",
        "Mesh & threshold: set the target/max number of trusted devices for this vault's mesh (4-9), how many devices must approve an authentication check, how many must contribute real shares to a recovery, and how many of those must be flagged remote.",
        "Default authentication code: an optional convenience that prefills the Requests tab's runtime-code field. It changes nothing about how a challenge is computed and can always be overridden per attempt.",
        `Duress passcode: a separate secret you can enter INSTEAD of your real runtime code on the Requests tab if you're ever forced to authenticate under coercion. Doing so produces a fake "success" that looks identical to a real one \u2014 nothing real is sent, decrypted, or reconstructed \u2014 while silently recording the event in this vault's own history, visible only to you, only after you've genuinely signed in later. Set it here in advance; it's useless if configured only after the fact.`
      ]),
      section("4. Trusted Devices tab", [
        "Your device identity: this vault's own ZRDCP public key, generated once when the vault was created. Share it with anyone who wants to enroll YOU as one of their trusted devices. The matching private key never leaves this vault.",
        "Trusted devices: the current mesh, and a Remove button for each. Add a ZRDCP-native device (another IdenTT vault or client \u2014 paste its public key, or generate a demo keypair for local testing) or a FIDO2/WebAuthn device (currently simulated pending real hardware ceremonies).",
        'A device flagged "remote" counts toward the "minimum remote" recovery requirement on the Vaults tab \u2014 the rule that stops someone from recovering your account just by possessing every device that happens to be sitting next to you.'
      ]),
      section("Real email & SMS", [
        "By default every challenge uses SIMULATED dispatch \u2014 no message actually leaves your machine, and you manually mark each device's response for testing. To send for real, run the small local backend included in the server/ folder: cd server, npm install, cp .env.example .env, fill in your own SMTP (email) and/or Twilio (SMS) credentials, then npm start.",
        "That backend is the only place real credentials ever live \u2014 the browser app never sees them, it only calls the backend's /send-email and /send-sms endpoints over localhost. You can configure just email, just SMS, both, or neither; whichever is left unconfigured simply reports that it's not set up yet when you try to use it.",
        "The backend has no authentication of its own and is meant to run only on your own machine \u2014 see server/README.md before considering exposing it any other way."
      ]),
      section("Security model, briefly", [
        "No single device \u2014 including this one \u2014 ever holds enough information alone to impersonate you. Recovery requires a real threshold of independently-held Shamir shares, each individually encrypted toward its holder's own key; authentication requires a real threshold of live approvals. A vault's registry (devices, thresholds, history) only ever exists in plaintext behind whatever unlock policy currently protects that vault."
      ])
    );
  }
  var init_help = __esm({
    "src/app/screens/help.js"() {
      init_ui();
    }
  });

  // src/app/screens/shell.js
  var shell_exports = {};
  __export(shell_exports, {
    renderShell: () => renderShell
  });
  async function renderShell(root2, { tabId } = {}) {
    if (tabId) activeTabId = tabId;
    root2.innerHTML = "";
    const vaultName = session.vaultName;
    const header = el("div", { className: "header" }, [
      el("h1", { textContent: `IdenTT \u2014 "${vaultName}"` }),
      el("div", { className: "header-actions" }, [
        el("button", { className: "link-button", textContent: "Lock", onclick: () => {
          activeTabId = "requests";
          renderSignOn(root2, { preselect: vaultName });
        } }),
        el("button", { className: "link-button", textContent: "All vaults", onclick: () => {
          activeTabId = "requests";
          renderSignOn(root2);
        } })
      ])
    ]);
    const tabNav = el(
      "nav",
      { className: "tab-nav" },
      TABS.map(
        (tab) => el("button", {
          className: `tab-button${tab.id === activeTabId ? " active" : ""}`,
          textContent: tab.label,
          onclick: () => renderShell(root2, { tabId: tab.id })
        })
      )
    );
    const contentContainer = el("div", { className: "tab-content" });
    root2.append(header, tabNav, contentContainer);
    const activeTab = TABS.find((t) => t.id === activeTabId) ?? TABS[0];
    await activeTab.render(contentContainer, root2);
  }
  var TABS, activeTabId;
  var init_shell = __esm({
    "src/app/screens/shell.js"() {
      init_ui();
      init_state();
      init_signOn();
      init_requests();
      init_vaults();
      init_devices();
      init_help();
      TABS = [
        { id: "requests", label: "Requests", render: renderRequestsTab },
        { id: "vaults", label: "Vault settings", render: renderVaultsTab },
        { id: "devices", label: "Trusted devices", render: renderDevicesTab },
        { id: "help", label: "Help", render: renderHelpTab }
      ];
      activeTabId = "requests";
    }
  });

  // src/app/screens/signOn.js
  async function migrateLegacyVaultIfPresent() {
    const legacyRaw = await storage.getItem(LEGACY_SINGLE_VAULT_STORAGE_KEY);
    if (legacyRaw === null) return;
    if ((await listVaultNames(storage)).length > 0) return;
    const legacyName = "My first vault";
    await storage.setItem(storageKeyFor(legacyName), legacyRaw);
    await storage.removeItem(LEGACY_SINGLE_VAULT_STORAGE_KEY);
    await registerVaultName(storage, legacyName);
  }
  async function renderSignOn(root2, { preselect } = {}) {
    root2.innerHTML = "";
    const vaults = await listVaultNames(storage);
    const heading = el("h1", { textContent: "IdenTT" });
    const subheading = el("p", {
      className: "subtitle",
      textContent: "Sign in to a vault, or create a new one."
    });
    const instructionsSection = el("section", { className: "card" }, [
      el("h2", { textContent: "How signing in works" }),
      el("p", {
        className: "hint",
        textContent: "Authentication mode: enter the vault's passphrase. If that vault also requires a live authentication check-in (its own kAuthentication quorum), you'll be asked for that next, before it opens."
      }),
      el("p", {
        className: "hint",
        textContent: "Recovery mode: for a vault with no passphrase at all \u2014 its unlock key is protected by a real Shamir split across its trusted-device mesh, reconstructed once enough of those devices respond."
      }),
      el("p", {
        className: "hint",
        textContent: 'Pick a vault below to see the sign-in options that apply to it, or choose "Create a new vault."'
      })
    ]);
    const options = [el("option", { value: "", textContent: `-- Select a vault (${vaults.length} available) --` })];
    for (const { name } of vaults) options.push(el("option", { value: name, textContent: name }));
    options.push(el("option", { value: CREATE_NEW_VALUE, textContent: "+ Create a new vault" }));
    const vaultSelect = el("select", {}, options);
    if (preselect) vaultSelect.value = preselect;
    const detailContainer = el("div", { className: "signon-detail" });
    async function renderDetail() {
      detailContainer.innerHTML = "";
      const value = vaultSelect.value;
      if (!value) return;
      if (value === CREATE_NEW_VALUE) {
        detailContainer.append(renderCreateForm(root2));
        return;
      }
      detailContainer.append(await renderVaultSignIn(root2, value));
    }
    vaultSelect.addEventListener("change", renderDetail);
    const pickerSection = el("section", { className: "card" }, [
      el("h2", { textContent: "Vault" }),
      el("label", { textContent: "Choose a vault to sign in to, or create a new one" }),
      vaultSelect,
      detailContainer
    ]);
    root2.append(el("div", { className: "header" }, [heading]), subheading, instructionsSection, pickerSection);
    await renderDetail();
  }
  function renderCreateForm(root2) {
    const nameInput = el("input", { type: "text", placeholder: 'Vault name (e.g. "Personal", "Work")' });
    const passInput = el("input", { type: "password", placeholder: "Passphrase" });
    const confirmInput = el("input", { type: "password", placeholder: "Confirm passphrase" });
    const createError = el("p", { className: "error" });
    const createBtn = el("button", {
      textContent: "Create vault",
      onclick: async () => {
        createError.textContent = "";
        const name = nameInput.value.trim();
        if (!name) {
          createError.textContent = "Vault name is required.";
          return;
        }
        if (!passInput.value) {
          createError.textContent = "Passphrase is required.";
          return;
        }
        if (passInput.value !== confirmInput.value) {
          createError.textContent = "Passphrases do not match.";
          return;
        }
        try {
          const store = createVaultStore(storage, name);
          if (await store.exists()) {
            createError.textContent = `A vault named "${name}" already exists.`;
            return;
          }
          const registry = await store.createNew(passInput.value);
          await registerVaultName(storage, name);
          await registerIdentity(storage, registry.localIdentity.publicKeyHex, name);
          setSession({ vaultName: name, registry, unlockSecret: { kind: "passphrase", value: passInput.value } });
          renderShell(root2, { tabId: "requests" });
        } catch (e) {
          createError.textContent = e.message;
        }
      }
    });
    return el("div", { className: "signon-subsection" }, [
      el("h3", { textContent: "Create a new vault" }),
      nameInput,
      passInput,
      confirmInput,
      createBtn,
      createError
    ]);
  }
  async function renderVaultSignIn(root2, vaultName) {
    const vaultMeta = await getVaultMeta(storage, vaultName);
    const store = createVaultStore(storage, vaultName);
    const container = el("div", { className: "signon-subsection" });
    const error = el("p", { className: "error" });
    const deleteArea = el("span", {});
    const deleteBtn = el("button", {
      className: "danger",
      textContent: "Delete this vault",
      onclick: () => {
        deleteArea.innerHTML = "";
        deleteArea.append(
          el("span", { className: "hint", textContent: `Delete "${vaultName}"? This cannot be undone. ` }),
          el("button", {
            className: "danger",
            textContent: "Really delete",
            onclick: async () => {
              await createVaultStore(storage, vaultName).destroy();
              await deleteVaultMeta(storage, vaultName);
              await unregisterVaultName(storage, vaultName);
              await unregisterIdentitiesForVault(storage, vaultName);
              await clearReconstructionShares(storage, vaultName);
              await clearAuthApprovals(storage, vaultName);
              renderSignOn(root2);
            }
          }),
          el("button", { className: "secondary", textContent: "Cancel", onclick: () => {
            deleteArea.innerHTML = "";
            deleteArea.append(deleteBtn);
          } })
        );
      }
    });
    deleteArea.append(deleteBtn);
    if (vaultMeta.unlockPolicy === UNLOCK_POLICIES.RECOVERY) {
      container.append(await renderRecoveryUnlock(root2, vaultName, vaultMeta, store, error));
      container.append(deleteArea);
      return container;
    }
    const policyHint = vaultMeta.unlockPolicy === UNLOCK_POLICIES.AUTHENTICATION ? "Enter your passphrase. This vault also requires a live authentication check-in from your mesh afterward." : "Enter your passphrase to unlock this vault.";
    const passInput = el("input", { type: "password", placeholder: "Passphrase", autofocus: true });
    const unlockBtn = el("button", {
      textContent: "Unlock",
      onclick: async () => {
        error.textContent = "";
        try {
          const registry = await store.load(passInput.value);
          await registerIdentity(storage, registry.localIdentity.publicKeyHex, vaultName);
          setSession({ vaultName, registry, unlockSecret: { kind: "passphrase", value: passInput.value } });
          if (vaultMeta.unlockPolicy === UNLOCK_POLICIES.AUTHENTICATION) {
            renderAuthStepUp(root2, vaultName, registry);
          } else {
            renderShell(root2, { tabId: "requests" });
          }
        } catch {
          error.textContent = "Wrong passphrase.";
        }
      }
    });
    container.append(
      el("h3", { textContent: `Sign in to "${vaultName}"` }),
      el("p", { className: "hint", textContent: policyHint }),
      passInput,
      unlockBtn,
      error,
      deleteArea
    );
    return container;
  }
  async function renderRecoveryUnlock(root2, vaultName, vaultMeta, store, error) {
    const split3 = vaultMeta.recoverySplit;
    const wrapper = el("div", {});
    const statusArea = el("div", { className: "recovery-results" });
    const initiateStatus = el("p", { className: "hint" });
    const openBtn = el("button", { className: "danger-action", textContent: "Attempt to open", disabled: true });
    if (!split3) {
      wrapper.append(
        el("h3", { textContent: `Sign in to "${vaultName}"` }),
        el("p", {
          className: "error",
          textContent: "This vault is set to recovery-only unlock, but no recovery split was ever generated \u2014 this should not happen. It cannot be opened this way; delete it and start over, or contact support."
        })
      );
      return wrapper;
    }
    async function refreshStatus() {
      statusArea.innerHTML = "";
      const collected = await listReconstructionShares(storage, vaultName);
      const validIds = new Set(split3.shares.map((s) => s.deviceId));
      const usable = collected.filter((s) => validIds.has(s.deviceId));
      const remoteIds = new Set(split3.shares.filter((s) => s.isRemote).map((s) => s.deviceId));
      const remoteCollected = usable.filter((s) => remoteIds.has(s.deviceId)).length;
      const ready = usable.length >= split3.kRecovery && remoteCollected >= split3.minRemoteForRecovery;
      openBtn.disabled = !ready;
      statusArea.append(
        el("p", {
          className: "hint",
          textContent: `${usable.length}/${split3.kRecovery} real responses collected \xB7 ${remoteCollected}/${split3.minRemoteForRecovery} required remote responses collected`
        }),
        el(
          "ul",
          { className: "dispatch-list" },
          split3.shares.map(
            (s) => el("li", { className: "dispatch-row" }, [
              el("span", { className: "device-name", textContent: `${s.deviceName}${s.isRemote ? " \xB7 remote" : " \xB7 local"}` }),
              el("span", {
                className: "device-meta",
                textContent: usable.some((u) => u.deviceId === s.deviceId) ? "\u2713 real response received" : "pending"
              })
            ])
          )
        )
      );
    }
    const initiateBtn = el("button", {
      className: "secondary",
      textContent: "Initiate recovery (notify local responders)",
      onclick: async () => {
        let dispatchedToAnyLocal = false;
        for (const s of split3.shares) {
          const localName = await findVaultNameForPublicKey(storage, s.devicePublicKeyHex);
          if (!localName) continue;
          const existing = await listInbox(storage, s.devicePublicKeyHex);
          const already = existing.some((e) => e.kind === "vault-unlock-recovery" && e.fromVaultName === vaultName && e.deviceId === s.deviceId);
          if (!already) {
            await pushInbox(storage, s.devicePublicKeyHex, {
              id: makeId("req"),
              kind: "vault-unlock-recovery",
              fromVaultName: vaultName,
              deviceId: s.deviceId,
              wrappedShare: s.wrapped,
              createdAt: (/* @__PURE__ */ new Date()).toISOString()
            });
          }
          dispatchedToAnyLocal = true;
        }
        initiateStatus.textContent = dispatchedToAnyLocal ? "Notified local responder vault(s) \u2014 open them (choose a different vault above) and check the Requests tab's Responder Mode to approve, then come back and check for responses." : "None of this recovery split's devices are other local vaults in this browser \u2014 recovery can't be completed here. In a real deployment, each would respond via its own IdenTT app.";
        await refreshStatus();
      }
    });
    const refreshBtn = el("button", { className: "secondary", textContent: "Check for responses", onclick: refreshStatus });
    openBtn.addEventListener("click", async () => {
      error.textContent = "";
      const collected = await listReconstructionShares(storage, vaultName);
      const result = attemptReconstruction({ recoverySplit: split3, collectedShares: collected });
      if (!result.ok) {
        error.textContent = `Not enough real responses yet \u2014 ${result.reason}.`;
        return;
      }
      try {
        const registry = await store.loadWithKey(result.keyHex);
        await registerIdentity(storage, registry.localIdentity.publicKeyHex, vaultName);
        await clearReconstructionShares(storage, vaultName);
        setSession({ vaultName, registry, unlockSecret: { kind: "key", value: result.keyHex } });
        renderShell(root2, { tabId: "requests" });
      } catch (e) {
        error.textContent = `The reconstructed key did not open the vault (${e.message}) \u2014 the split may be out of date; regenerate it from the Vaults tab next time you're in.`;
      }
    });
    const holderSummary = `Needs ${split3.kRecovery} real share-holder responses (of ${split3.holderCount} enrolled), including ${split3.minRemoteForRecovery} remote.`;
    wrapper.append(
      el("h3", { textContent: `Sign in to "${vaultName}" \u2014 Recovery mode` }),
      el("p", {
        className: "hint",
        textContent: "This vault unlocks via Recovery \u2014 there is no passphrase to enter. Ask your trusted-device mesh to respond (Responder Mode, on the Requests tab of any of them), then attempt to open once enough real responses are in."
      }),
      el("p", { className: "hint", textContent: holderSummary }),
      initiateBtn,
      initiateStatus,
      refreshBtn,
      statusArea,
      openBtn,
      error
    );
    await refreshStatus();
    return wrapper;
  }
  async function renderAuthStepUp(root2, vaultName, registry) {
    root2.innerHTML = "";
    const heading = el("h1", { textContent: "IdenTT" });
    const subheading = el("p", { className: "subtitle", textContent: `Vault: "${vaultName}" \u2014 step-up authentication required` });
    const { kAuthentication } = registry.threshold;
    const statusArea = el("div", { className: "recovery-results" });
    const dispatchStatus = el("p", { className: "hint" });
    const continueBtn = el("button", { className: "danger-action", textContent: "Continue", disabled: true });
    async function refreshStatus() {
      const approvals = await listAuthApprovals(storage, vaultName);
      statusArea.innerHTML = "";
      statusArea.append(el("p", { className: "hint", textContent: `${approvals.length}/${kAuthentication} real approvals collected.` }));
      continueBtn.disabled = approvals.length < kAuthentication;
    }
    const dispatchBtn = el("button", {
      className: "secondary",
      textContent: "Notify local responders",
      onclick: async () => {
        let any = false;
        for (const device of registry.devices) {
          if (device.type !== "zrdcp-native") continue;
          const localName = await findVaultNameForPublicKey(storage, device.publicKeyHex);
          if (!localName) continue;
          const existing = await listInbox(storage, device.publicKeyHex);
          const already = existing.some((e) => e.kind === "vault-unlock-authentication" && e.fromVaultName === vaultName && e.deviceId === device.id);
          if (!already) {
            await pushInbox(storage, device.publicKeyHex, {
              id: makeId("req"),
              kind: "vault-unlock-authentication",
              fromVaultName: vaultName,
              deviceId: device.id,
              wrappedShare: null,
              createdAt: (/* @__PURE__ */ new Date()).toISOString()
            });
          }
          any = true;
        }
        dispatchStatus.textContent = any ? "Notified local responder vault(s) \u2014 open them and check the Requests tab's Responder Mode to approve." : "None of your enrolled zrdcp-native devices are other local vaults in this browser \u2014 nothing to notify here.";
        await refreshStatus();
      }
    });
    const refreshBtn = el("button", { className: "secondary", textContent: "Check for responses", onclick: refreshStatus });
    continueBtn.addEventListener("click", async () => {
      await clearAuthApprovals(storage, vaultName);
      renderShell(root2, { tabId: "requests" });
    });
    root2.append(
      el("div", { className: "header" }, [heading]),
      subheading,
      el("div", { className: "gate" }, [
        el("p", { className: "hint", textContent: "Your passphrase was correct. This vault also requires a live authentication check-in before it opens." }),
        dispatchBtn,
        dispatchStatus,
        refreshBtn,
        statusArea,
        continueBtn
      ])
    );
    await refreshStatus();
  }
  var CREATE_NEW_VALUE;
  var init_signOn = __esm({
    "src/app/screens/signOn.js"() {
      init_ui();
      init_state();
      init_store();
      init_directory();
      init_meta();
      init_crossVault();
      init_unlockRecovery();
      init_schema();
      init_shell();
      CREATE_NEW_VALUE = "__create__";
    }
  });

  // src/app/main.js
  init_signOn();
  var root = document.getElementById("app");
  migrateLegacyVaultIfPresent().then(() => renderSignOn(root));
})();
/*! Bundled license information:

@noble/curves/utils.js:
@noble/curves/abstract/modular.js:
@noble/curves/abstract/curve.js:
@noble/curves/abstract/der.js:
@noble/curves/abstract/weierstrass.js:
@noble/curves/secp256k1.js:
  (*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) *)
*/
