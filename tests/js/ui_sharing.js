const C = require('./ui_common')
const { ok, sleep, until, api, openBrowser, $, visible, seatsFor } = C
;(async () => {
  const { code } = await api('POST', '/api/session/create')
  const seats = await seatsFor(code)

  // A stranger who only knows the code gets no panel content.
  const stranger = await openBrowser(`/result/${code}`, null)
  await until(() => $(stranger, 'room-note').textContent.includes('на том устройстве'), 'stranger note')
  ok('a visitor without a seat token sees only a pointer, no form', !visible(stranger, 'room-live'))

  const A = await openBrowser(`/result/${code}`, seats[0])
  const B = await openBrowser(`/result/${code}`, seats[1])
  await until(() => visible(A, 'room-live') && visible(B, 'room-live'), 'both panels live')
  ok('both browsers reach a ready room by themselves', true)
  ok('neither page threw a script error', A.errors.length === 0 && B.errors.length === 0, A.errors.concat(B.errors).join('; '))

  const sa = $(A, 'room-safety').textContent, sb = $(B, 'room-safety').textContent
  ok('both pages display the same safety code', sa === sb && /^\d{5} \d{5}$/.test(sa), `${sa} / ${sb}`)

  const SECRET = { login: 'maria.k', password: 'Tr0ub4dor&3-xyz', code: '771204', key: 'sk_live_FAKE0123456789', note: '<img src=x onerror="window.__xss=1">' }
  for (const [k, v] of Object.entries(SECRET)) $(A, 'f-' + k).value = v
  $(A, 'room-form').dispatchEvent(new A.window.Event('submit', { cancelable: true, bubbles: true }))

  await until(() => B.window.document.querySelectorAll('#room-items .item').length === 1, 'B receives the item', 9000)
  const item = B.window.document.querySelector('#room-items .item')
  const text = item.textContent
  ok('B sees login, code, key and note from A', text.includes('maria.k') && text.includes('771204') && text.includes('sk_live_FAKE0123456789'))
  ok('the password is masked until revealed', !text.includes('Tr0ub4dor') && text.includes('••••••••'))
  const eye = [...item.querySelectorAll('button')].find(b => b.textContent === 'показать')
  eye.click()
  ok('revealing shows the password', item.textContent.includes('Tr0ub4dor&3-xyz'))
  const copy = [...item.querySelectorAll('.item-row')].find(r => r.textContent.includes('Пароль')).querySelector('button:last-child')
  copy.click()
  ok('copy puts the real password on the clipboard', B.window.__clip === 'Tr0ub4dor&3-xyz')
  ok('markup in a note is shown as text, never run', B.window.__xss === undefined && !item.querySelector('img'))
  ok('A\'s own form was cleared after sending', ['login','password','code','key','note'].every(k => $(A, 'f-' + k).value === ''))
  await until(() => A.window.document.querySelectorAll('#room-items .item').length === 1, 'A sees its own copy')
  ok('A sees what it sent, labelled as sent by A', A.window.document.querySelector('#room-items .item-head').textContent.includes('Вы отправили'))

  // B replies; A reads it.
  $(B, 'f-note').value = 'got it'
  $(B, 'room-form').dispatchEvent(new B.window.Event('submit', { cancelable: true, bubbles: true }))
  await until(() => A.window.document.querySelectorAll('#room-items .item').length === 2, 'A sees the reply')
  ok('the reply arrives with the sender\'s name', [...A.window.document.querySelectorAll('#room-items .item-head')].some(h => h.textContent.startsWith('От ')))

  // An empty form is refused locally.
  $(B, 'room-form').dispatchEvent(new B.window.Event('submit', { cancelable: true, bubbles: true }))
  await until(() => $(B, 'room-error').textContent.includes('хотя бы одно поле'), 'empty form message')
  ok('submitting nothing says to fill a field', true)

  // Deleting removes it on the other side too.
  const del = [...B.window.document.querySelectorAll('#room-items .item')][1].querySelector('.item-head button')
  del.click()
  await until(() => A.window.document.querySelectorAll('#room-items .item').length === 1, 'deletion reaches A', 9000)
  ok('deleting an item removes it from both screens', true)

  // The room closes: the page must wipe the local key and say so.
  const sqlite = require('node:child_process')
  require('node:fs').writeFileSync(process.env.EXPIRE_FLAG, code)
  await until(() => require('node:fs').existsSync(process.env.EXPIRE_DONE), 'server-side expiry')
  await until(() => $(A, 'room-note').textContent.includes('Комната закрыта'), 'closed notice', 9000)
  ok('an expired room shows the closed notice and hides the form', !visible(A, 'room-live'))
  ok('the seat and private key are wiped from local storage', A.window.localStorage.getItem('room:' + code) === null)
  ok('the received items are removed from the page', A.window.document.querySelectorAll('#room-items .item').length === 0)

  C.finish()
})().catch(C.crash)
