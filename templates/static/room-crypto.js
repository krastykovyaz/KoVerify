/*
 * End-to-end encryption for the room. Runs in the browser; also loads under
 * Node (module.exports) so it can be tested against the real WebCrypto.
 *
 * Each person makes an ECDH P-256 key pair and publishes only the public half.
 * The shared secret is the same on both sides, so either person can read what
 * either of them sent, and the server holds nothing it can decrypt.
 *
 *   key  = HKDF-SHA256(ECDH(mine, theirs), salt = room code, info = label)
 *   data = AES-256-GCM, fresh random IV, AAD = "<room code>|<sender slot>"
 *
 * The AAD binds a message to its room and direction, so the server cannot move
 * a ciphertext into another room or make it look like it came from the other
 * person.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(globalThis.crypto)
  else root.RoomCrypto = factory(root.crypto)
})(typeof self !== 'undefined' ? self : this, function (crypto) {
  'use strict'

  const enc = new TextEncoder()
  const dec = new TextDecoder()
  const CURVE = { name: 'ECDH', namedCurve: 'P-256' }
  const LABEL = 'verifier-room-v1'
  const FIELDS = ['login', 'password', 'code', 'key', 'note']

  function toB64(bytes) {
    let s = ''
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
    return btoa(s)
  }
  function fromB64(text) {
    const s = atob(text)
    const out = new Uint8Array(s.length)
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i)
    return out
  }

  async function generateIdentity() {
    const pair = await crypto.subtle.generateKey(CURVE, true, ['deriveBits'])
    const publicB64 = toB64(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey)))
    return {
      privateJwk: await crypto.subtle.exportKey('jwk', pair.privateKey),
      publicB64,
      commit: await commitment(publicB64),
    }
  }

  // Keys are committed before they are revealed. A side publishes this hash
  // first and may show the key only after both hashes exist; the other side pins
  // the hash it saw first and checks the revealed key against it. That is what
  // makes the safety code mean something: without it a server choosing both
  // fake keys could match the ten digits by birthday search in seconds.
  async function commitment(publicB64) {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(publicB64)))
    return Array.from(digest, b => b.toString(16).padStart(2, '0')).join('')
  }

  async function keyMatchesCommitment(publicB64, commitHex) {
    return typeof commitHex === 'string' && (await commitment(publicB64)) === commitHex
  }

  async function deriveRoomKey(privateJwk, peerPublicB64, code) {
    const priv = await crypto.subtle.importKey('jwk', privateJwk, CURVE, false, ['deriveBits'])
    const pub = await crypto.subtle.importKey('raw', fromB64(peerPublicB64), CURVE, false, [])
    const secret = await crypto.subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 256)
    const material = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveKey'])
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: enc.encode(code), info: enc.encode(LABEL) },
      material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt'],
    )
  }

  function aad(code, fromSlot) {
    return enc.encode(`${code}|${fromSlot}`)
  }

  // Only the known, non-empty fields are sent, and never anything else.
  function cleanFields(input) {
    const out = {}
    for (const name of FIELDS) {
      const value = typeof input[name] === 'string' ? input[name].trim() : ''
      if (value) out[name] = value
    }
    return out
  }

  async function encryptItem(key, code, fromSlot, input) {
    const fields = cleanFields(input)
    if (Object.keys(fields).length === 0) throw new Error('empty')
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const plaintext = enc.encode(JSON.stringify({ v: 1, fields }))
    const sealed = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: aad(code, fromSlot) }, key, plaintext,
    )
    return { iv: toB64(iv), ciphertext: toB64(new Uint8Array(sealed)) }
  }

  async function decryptItem(key, code, fromSlot, item) {
    const opened = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(item.iv), additionalData: aad(code, fromSlot) },
      key, fromB64(item.ciphertext),
    )
    const parsed = JSON.parse(dec.decode(opened))
    if (!parsed || parsed.v !== 1 || typeof parsed.fields !== 'object') throw new Error('format')
    return cleanFields(parsed.fields)
  }

  // A recorded video proof. Sealed under the same room key as messages but with
  // its own AAD label, so a message ciphertext can never be passed off as a
  // proof or the other way round. The plaintext is framed as
  //   [2-byte header length][JSON header {v, mime}][video bytes]
  // so the receiving browser knows how to play it without the server ever
  // learning what it is.
  async function encryptBytes(key, code, fromSlot, mime, bytes) {
    const header = enc.encode(JSON.stringify({ v: 1, mime }))
    const plain = new Uint8Array(2 + header.length + bytes.length)
    plain[0] = header.length >> 8; plain[1] = header.length & 255
    plain.set(header, 2); plain.set(bytes, 2 + header.length)
    const iv = crypto.getRandomValues(new Uint8Array(12))
    const sealed = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: enc.encode(`${code}|${fromSlot}|proof`) }, key, plain)
    return { iv: toB64(iv), ciphertext: new Uint8Array(sealed) }
  }

  async function decryptBytes(key, code, fromSlot, ivB64, ciphertext) {
    const opened = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(ivB64), additionalData: enc.encode(`${code}|${fromSlot}|proof`) },
      key, ciphertext))
    const length = (opened[0] << 8) | opened[1]
    const header = JSON.parse(dec.decode(opened.subarray(2, 2 + length)))
    if (!header || header.v !== 1 || typeof header.mime !== 'string') throw new Error('format')
    return { mime: header.mime, bytes: opened.subarray(2 + length) }
  }

  // Ten digits both people read aloud. If the server swapped either public key,
  // the two screens disagree.
  async function safetyCode(publicA, publicB, code) {
    const [first, second] = [publicA, publicB].sort()
    const digest = new Uint8Array(await crypto.subtle.digest(
      'SHA-256', enc.encode(`${LABEL}|${code}|${first}|${second}`),
    ))
    let n = 0n
    for (let i = 0; i < 5; i++) n = (n << 8n) | BigInt(digest[i])
    const digits = (n % 10000000000n).toString().padStart(10, '0')
    return `${digits.slice(0, 5)} ${digits.slice(5)}`
  }

  return { FIELDS, generateIdentity, commitment, keyMatchesCommitment, deriveRoomKey, encryptItem, decryptItem, encryptBytes, decryptBytes, safetyCode, toB64, fromB64 }
})
