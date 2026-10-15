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
  const VIDEO_LABEL = 'verifier-room-video-v1'
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
    return {
      privateJwk: await crypto.subtle.exportKey('jwk', pair.privateKey),
      publicB64: toB64(new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey))),
    }
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

  // The name of the video meeting, derived from the same ECDH secret as the
  // message key but under its own label. Both browsers compute the same 128-bit
  // value; the server only ever sees public keys, so it cannot, and nobody else
  // can guess it.
  async function videoRoomName(privateJwk, peerPublicB64, code) {
    const priv = await crypto.subtle.importKey('jwk', privateJwk, CURVE, false, ['deriveBits'])
    const pub = await crypto.subtle.importKey('raw', fromB64(peerPublicB64), CURVE, false, [])
    const secret = await crypto.subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 256)
    const material = await crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits'])
    const bits = new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: enc.encode(code), info: enc.encode(VIDEO_LABEL) }, material, 128,
    ))
    return 'verifier-' + Array.from(bits, b => b.toString(16).padStart(2, '0')).join('')
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

  return { FIELDS, generateIdentity, deriveRoomKey, encryptItem, decryptItem, safetyCode, videoRoomName, toB64, fromB64 }
})
