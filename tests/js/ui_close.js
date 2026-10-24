const C = require('./ui_common')
const { ok, sleep, until, api, openBrowser, $, visible, seatsFor } = C
const text = (dom, id) => $(dom, id).textContent
const items = (dom) => dom.window.document.querySelectorAll('#room-items .item').length

;(async () => {
  const { code } = await api('POST', '/api/session/create')
  const seats = await seatsFor(code)
  const A = await openBrowser(`/result/${code}`, seats[0])
  const B = await openBrowser(`/result/${code}`, seats[1])
  await until(() => visible(A, 'room-live') && visible(B, 'room-live'), 'both panels live')
  ok('the live room shows a countdown to closing', /закроется через \d+ мин/.test(text(A, 'room-countdown')), text(A, 'room-countdown'))
  ok('the status card names both people before closing', text(A, 'name-a') !== '—' && text(A, 'name-b') !== '—')

  // A message, so there is something to delete.
  $(A, 'f-password').value = 'hunter2-hunter2'
  $(A, 'room-form').dispatchEvent(new A.window.Event('submit', { cancelable: true, bubbles: true }))
  await until(() => items(B) === 1, 'B has the item')

  // Changing your mind leaves everything as it was.
  A.window.confirm = () => false
  $(A, 'room-close').click(); await sleep(400)
  ok('declining the confirmation closes nothing', visible(A, 'room-live') && items(A) === 1 && !!A.window.localStorage.getItem('room:' + code))

  A.window.confirm = () => true
  $(A, 'room-close').click()
  await until(() => !visible(A, 'room-live') && text(A, 'room-note').includes('Вы закрыли комнату'), 'A closed', 9000)
  ok('the person who closed is told everything was deleted', text(A, 'room-note').includes('удалено с сервера и из этого браузера'))
  ok('their form, items and countdown are gone', items(A) === 0 && text(A, 'room-countdown') === '' && A.window.document.getElementById('f-password').value === '')
  ok('their seat and private key are wiped from the browser', A.window.localStorage.getItem('room:' + code) === null)
  ok('their status card no longer shows who was in the room', text(A, 'name-a') === '—' && text(A, 'name-b') === '—' && text(A, 'status-bar').includes('закрыта'))

  await until(() => !visible(B, 'room-live') && text(B, 'room-note').includes('закрыта'), 'B sees it closed', 9000)
  ok('the other person sees the room closed on their next poll', true)
  ok('and has nothing left on screen', items(B) === 0 && text(B, 'room-countdown') === '')
  ok('their seat and private key are wiped too', B.window.localStorage.getItem('room:' + code) === null)
  await until(() => text(B, 'name-a') === '—', 'B status card wiped', 6000)
  ok('their status card is wiped as well', text(B, 'name-b') === '—' && text(B, 'status-bar').includes('закрыта'))
  ok('the page offers to start over', B.window.document.getElementById('btn-new').style.display === 'block')
  ok('no script errors', A.errors.length === 0 && B.errors.length === 0, A.errors.concat(B.errors).join('; '))

  const status = await api('GET', `/api/session/${code}/status`)
  ok('the public status now says only "closed"', JSON.stringify(status) === JSON.stringify({ status: 'closed' }), JSON.stringify(status))

  C.finish()
})().catch(C.crash)
