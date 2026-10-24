// A server that swaps the other person's key must be caught by the page itself.
const C = require('./ui_common')
const { ok, until, api, openBrowser, $, visible, seatsFor } = C
const RC = require('../../templates/static/room-crypto.js')

;(async () => {
  const { code } = await api('POST', '/api/session/create')
  const seats = await seatsFor(code)
  const A = await openBrowser(`/result/${code}`, seats[0])
  const B = await openBrowser(`/result/${code}`, seats[1])
  // Let both commit honestly, then make the server lie to A about B's key.
  await until(async () => {
    const s = await (await fetch(`${C.BASE}/api/session/${code}/room`, { headers: { 'X-Room-Token': seats[0].token } })).json()
    return s.you.commit && s.peer.commit
  }, 'both committed')
  const impostor = await RC.generateIdentity()
  const real = A.window.fetch
  A.window.fetch = async (u, o) => {
    const res = await real(u, o)
    if (!String(u).endsWith('/room') || (o && o.method !== 'GET')) return res
    const body = await res.json()
    if (body.peer && body.peer.public_key) body.peer.public_key = impostor.publicB64   // commitment left as is
    return new Response(JSON.stringify(body), { status: res.status, headers: { 'Content-Type': 'application/json' } })
  }
  await until(() => $(A, 'room-note').textContent.includes('вмешался'), 'tamper notice', 25000)
  ok('A refuses the swapped key and says someone interfered', $(A, 'room-note').textContent.includes('не совпадает с его обязательством'), $(A, 'room-note').textContent)
  ok('the sharing form never opens for A', !visible(A, 'room-live'))
  ok('A stops polling, so nothing further is sent or derived', (() => { const n = A.window.document.getElementById('room-safety').textContent; return n === '' })())
  await until(() => visible(B, 'room-live'), 'B, who was told the truth, proceeds')
  ok('B, who received the honest keys, is unaffected', visible(B, 'room-live'))
  ok('no script errors', A.errors.length === 0 && B.errors.length === 0, A.errors.concat(B.errors).join('; '))
  C.finish()
})().catch(C.crash)
