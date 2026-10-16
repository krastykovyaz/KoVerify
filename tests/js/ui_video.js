const C = require('./ui_common')
const { ok, sleep, until, api, openBrowser, $, visible, seatsFor } = C
const text = (dom, id) => $(dom, id).textContent
const buttons = (dom) => [...dom.window.document.querySelectorAll('#video-buttons button')].map(b => b.textContent)
const click = (dom, label) => [...dom.window.document.querySelectorAll('#video-buttons button')].find(b => b.textContent === label).click()
const cls = (dom) => $(dom, 'video').className

;(async () => {
  const { code } = await api('POST', '/api/session/create')
  const seats = await seatsFor(code)
  const A = await openBrowser(`/result/${code}`, seats[0])
  const B = await openBrowser(`/result/${code}`, seats[1])
  await until(() => visible(A, 'room-live') && visible(B, 'room-live'), 'both panels live')
  ok('idle: both offer to request a video verification', buttons(A).join() === 'Запросить видеопроверку' && buttons(B).join() === 'Запросить видеопроверку')
  ok('idle: the call link is hidden', !visible(A, 'video-link') && !visible(B, 'video-link'))

  click(A, 'Запросить видеопроверку')
  await until(() => buttons(A).join() === 'Отменить запрос' && buttons(B).join() === 'Принять,Отклонить', 'request reaches B', 9000)
  ok('asker sees a waiting message with a cancel button', text(A, 'video-text').includes('Запрос отправлен'))
  ok('the other person gets an incoming banner naming the asker', cls(B) === 'video incoming' && text(B, 'video-text').includes('просит пройти видеопроверку'))
  const titles = new Set()
  for (let i = 0; i < 30; i++) { titles.add(B.window.document.title); await sleep(100) }
  ok('an incoming request flashes the page title', titles.has('📹 Запрос видеопроверки') && titles.size >= 2, [...titles].join(' | '))
  const quiet = new Set()
  for (let i = 0; i < 5; i++) { quiet.add(A.window.document.title); await sleep(100) }
  ok('the asker\'s own title is not flashed', !quiet.has('📹 Запрос видеопроверки'))

  click(B, 'Принять')
  await until(() => visible(A, 'video-link') && visible(B, 'video-link'), 'call link on both', 9000)
  const urlA = $(A, 'video-link').href, urlB = $(B, 'video-link').href
  ok('both get the same call link', urlA === urlB)
  ok('the link is https on the configured provider with an unguessable room', /^https:\/\/meet\.jit\.si\/verifier-[0-9a-f]{32}$/.test(urlA), urlA)
  ok('the link opens in a new tab without leaking the page', $(A, 'video-link').target === '_blank' && /noopener/.test($(A, 'video-link').rel))
  const safety = text(A, 'room-safety')
  ok('the safety code is repeated in the call instructions', text(A, 'video-text').includes(safety) && text(B, 'video-text').includes(safety))
  ok('only the asker gets the confirm and deny buttons', buttons(A).join() === 'Это он(а): подтверждаю,Не подтверждаю' && buttons(B).length === 0)
  ok('the verified person is told to wait for the decision', text(B, 'video-text').includes('проверяет вашу личность') && B.window.document.querySelector('#video-buttons').textContent.includes('Ждём решения'))

  click(A, 'Это он(а): подтверждаю')
  await until(() => cls(A) === 'video good' && cls(B) === 'video good', 'confirmed on both', 9000)
  ok('a confirmation shows on both screens, naming the asker', text(B, 'video-text').includes('подтвердил(а) личность') && text(A, 'video-text').startsWith('✅ Вы'))
  const after = new Set()
  for (let i = 0; i < 25; i++) { after.add(B.window.document.title); await sleep(100) }
  ok('the title stops flashing once the request is answered', !after.has('📹 Запрос видеопроверки'), [...after].join(' | '))
  ok('the call link disappears once decided', !visible(A, 'video-link') && !visible(B, 'video-link'))

  // Decline path, with the roles reversed.
  click(B, 'Запросить снова')
  await until(() => buttons(A).join() === 'Принять,Отклонить', 'B asks A', 9000)
  ok('either side can ask, and the roles swap', buttons(B).join() === 'Отменить запрос')
  click(A, 'Отклонить')
  await until(() => cls(A) === 'video bad' && cls(B) === 'video bad', 'declined on both', 9000)
  ok('a decline is explained to both sides', text(B, 'video-text').includes('отклонил(а) запрос') && text(A, 'video-text').includes('Вы отклонили'))

  // A denial carries a warning.
  click(A, 'Запросить снова')
  await until(() => buttons(B).join() === 'Принять,Отклонить', 'A asks again', 9000)
  click(B, 'Принять')
  await until(() => visible(A, 'video-link'), 'call again', 9000)
  click(A, 'Не подтверждаю')
  await until(() => cls(B) === 'video bad' && text(B, 'video-text').includes('не подтвердил'), 'denied', 9000)
  ok('a denial warns both people not to share secrets', text(B, 'video-text').includes('Не передавайте секреты'))
  ok('no script errors on either page', A.errors.length === 0 && B.errors.length === 0, A.errors.concat(B.errors).join('; '))

  C.finish()
})().catch(C.crash)
