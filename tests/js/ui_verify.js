// The verify page must keep the seat token it is handed, or the room never opens.
const C = require('./ui_common')
const { ok, sleep, api, $ } = C
const { VirtualConsole } = require(process.env.JSDOM_DIR || 'jsdom')
const crypto = require('node:crypto')

;(async () => {
  const { code } = await api('POST', '/api/session/create')
  const user = C.USERS[0]
  const vc = new VirtualConsole()                       // jsdom cannot navigate; ignore that message
  const dom = await C.JSDOM.fromURL(`${C.BASE}/session/${code}`, {
    runScripts: 'dangerously', resources: 'usable', virtualConsole: vc,
    beforeParse(w) {
      w.fetch = (u, o) => fetch(new URL(u, C.BASE), o)
      Object.defineProperty(w, 'crypto', { value: crypto.webcrypto })
    },
  })
  $(dom, 'totp-userid').value = user.id
  const field = $(dom, 'totp-code'); field.value = C.totp(user.secret)
  field.dispatchEvent(new dom.window.Event('input', { bubbles: true }))
  const t0 = Date.now(); let saved = null
  while (Date.now() - t0 < 6000 && !saved) { saved = dom.window.localStorage.getItem('room:' + code); await sleep(80) }
  const seat = saved && JSON.parse(saved)
  ok('the seat is saved after a TOTP login', seat && seat.token && seat.slot, saved)
  ok('the token is a full-length random value', seat && seat.token.length >= 40)
  ok('it records when it was saved, so stale ones can be dropped', seat && typeof seat.savedAt === 'number')
  ok('the page confirms the login', $(dom, 'alert').textContent.includes('Верифицированы'))
  C.finish()
})().catch(C.crash)
