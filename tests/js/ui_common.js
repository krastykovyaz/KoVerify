// Shared harness for the page tests: real HTML, real scripts, a real DOM (jsdom),
// real WebCrypto, against a live copy of the server. Browser features jsdom lacks
// (system notifications, sound, vibration, tab visibility) are stubbed and counted.
const crypto = require('node:crypto')
const { JSDOM } = require(process.env.JSDOM_DIR || 'jsdom')

const BASE = process.env.BASE
const USERS = JSON.parse(process.env.USERS)
const results = []
const ok = (name, value, extra) => results.push([name, Boolean(value), extra || ''])
const sleep = ms => new Promise(r => setTimeout(r, ms))

async function until(fn, label, ms = 8000) {
  const t0 = Date.now()
  while (Date.now() - t0 < ms) {
    try { const v = await fn(); if (v) return v } catch (e) {}
    await sleep(80)
  }
  throw new Error('timed out waiting for: ' + label)
}

function base32(text) {
  const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const c of text.replace(/=+$/, '')) bits += a.indexOf(c).toString(2).padStart(5, '0')
  const out = []
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2))
  return Buffer.from(out)
}
function totp(secret) {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)))
  const mac = crypto.createHmac('sha1', base32(secret)).update(counter).digest()
  const o = mac[19] & 0xf
  const n = ((mac[o] & 0x7f) << 24) | (mac[o + 1] << 16) | (mac[o + 2] << 8) | mac[o + 3]
  return String(n % 1000000).padStart(6, '0')
}

async function api(method, path, body) {
  const res = await fetch(BASE + path, {
    method, headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  return res.json()
}

// Verify every user over the API and return their seats, as the browser would
// have stored them after logging in.
async function seatsFor(code) {
  const seats = []
  for (const u of USERS) {
    const r = await api('POST', `/api/session/${code}/verify/totp`, { user_id: u.id, code: totp(u.secret) })
    seats.push({ slot: r.slot, token: r.token, savedAt: Date.now() })
  }
  return seats
}

async function openBrowser(path, seat, rawSeat) {
  const errors = []
  const t = { notes: [], beeps: 0, vibes: 0, hidden: false, clip: null }
  const dom = await JSDOM.fromURL(BASE + path, {
    runScripts: 'dangerously', resources: 'usable', pretendToBeVisual: true,
    beforeParse(window) {
      window.fetch = (u, o) => fetch(new URL(u, BASE), o)
      Object.defineProperty(window, 'crypto', { value: crypto.webcrypto, configurable: true })
      window.TextEncoder = TextEncoder; window.TextDecoder = TextDecoder
      window.navigator.clipboard = { writeText: (x) => { t.clip = x; window.__clip = x; return Promise.resolve() } }
      window.navigator.vibrate = () => { t.vibes++; return true }
      window.AudioContext = function () {
        t.beeps++
        return { createOscillator: () => ({ frequency: {}, connect() {}, start() {}, stop() {} }),
                 createGain: () => ({ gain: {}, connect() {} }), destination: {}, currentTime: 0, close() {} }
      }
      window.Notification = function (title, opts) { t.notes.push({ title, body: opts && opts.body }); this.close = () => {} }
      window.Notification.permission = 'default'
      window.Notification.requestPermission = async () => { window.Notification.permission = 'granted'; return 'granted' }
      Object.defineProperty(window.document, 'hidden', { get: () => t.hidden, configurable: true })
      window.addEventListener('error', e => errors.push(String(e.message)))
      const key = 'room:' + path.split('/').pop()
      if (rawSeat) window.localStorage.setItem(key, rawSeat)
      else if (seat) window.localStorage.setItem(key, JSON.stringify(seat))
    },
  })
  dom.errors = errors; dom.t = t
  dom.setHidden = (h) => { t.hidden = h; dom.window.document.dispatchEvent(new dom.window.Event('visibilitychange')) }
  return dom
}

const $ = (dom, id) => dom.window.document.getElementById(id)
const visible = (dom, id) => $(dom, id) && $(dom, id).style.display !== 'none'

function finish() {
  for (const [n, v, e] of results) console.log((v ? 'PASS ' : 'FAIL ') + n + (v ? '' : '  -> ' + e))
  process.exit(results.every(r => r[1]) ? 0 : 1)
}
function crash(e) {
  for (const [n, v, x] of results) console.log((v ? 'PASS ' : 'FAIL ') + n + (v ? '' : '  -> ' + x))
  console.log('ERROR', e.message)
  process.exit(2)
}

module.exports = { BASE, USERS, ok, sleep, until, totp, api, seatsFor, openBrowser, $, visible, finish, crash, JSDOM }
