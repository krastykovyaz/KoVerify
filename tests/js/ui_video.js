// Video verification: one person asks, the other records a proof in the page,
// it travels encrypted, the asker watches it and decides.
const C = require('./ui_common')
const { ok, until, api, openBrowser, $, visible, seatsFor } = C

const text = (dom, id) => $(dom, id).textContent
const labels = (dom) => [...dom.window.document.querySelectorAll('#video-buttons button')].map(b => b.textContent)
const click = (dom, label) => [...dom.window.document.querySelectorAll('#video-buttons button')].find(b => b.textContent === label).click()
const cls = (dom) => $(dom, 'video').className
const readBlob = (dom, blob) => new Promise((resolve, reject) => {
  const reader = new dom.window.FileReader()
  reader.onload = () => resolve(Buffer.from(reader.result)); reader.onerror = reject
  reader.readAsArrayBuffer(blob)
})

;(async () => {
  const { code } = await api('POST', '/api/session/create')
  const seats = await seatsFor(code)
  const A = await openBrowser(`/result/${code}`, seats[0])      // Maria asks
  const B = await openBrowser(`/result/${code}`, seats[1])      // Ivan is asked
  await until(() => visible(A, 'room-live') && visible(B, 'room-live'), 'both panels live')
  const safety = text(A, 'room-safety')
  ok('idle: both can request a video verification', labels(A).join() === 'Запросить видеопроверку' && labels(B).join() === 'Запросить видеопроверку')

  click(A, 'Запросить видеопроверку')
  await until(() => labels(A).join() === 'Отменить запрос' && labels(B).join() === 'Включить камеру,Отклонить', 'request reaches B', 12000)
  ok('the asker is told it was sent and is waiting', text(A, 'video-text').includes('Запрос отправлен'))
  ok('the other person gets an incoming banner', cls(B) === 'video incoming' && text(B, 'video-text').includes('просит доказать'))
  const steps = [...B.window.document.querySelectorAll('#video-stage .steps li')].map(li => li.textContent)
  ok('they are given three clear steps', steps.length === 3 && steps[0].includes('камеру') && steps[1].includes('имя и код сверки') && steps[2].includes('Отправить'), steps.join('|'))
  ok('the code they must say is shown large, and is the real one', B.window.document.querySelector('#video-stage .big-code').textContent === safety && /^\d{5} \d{5}$/.test(safety))

  // Recording.
  click(B, 'Включить камеру')
  await until(() => labels(B).includes('● Начать запись'), 'camera on')
  ok('the camera was opened only after they chose to', B.t.camera.opens === 1)
  ok('they are told what to say, including the code', text(B, 'video-stage').includes(safety) && text(B, 'video-stage').includes('20 секунд'))
  click(B, '● Начать запись')
  await until(() => labels(B).includes('■ Остановить'), 'recording')
  ok('a visible recording indicator with a countdown', /Идёт запись… \d+ с/.test(text(B, 'video-stage')))
  click(B, '■ Остановить')
  await until(() => labels(B).some(l => l.startsWith('Отправить')), 'review')
  ok('the camera is released as soon as recording stops', B.t.camera.stops === 1)
  ok('they review their own recording before sending, with a retake option', labels(B).includes('Записать заново') && B.window.document.querySelector('#video-stage video'))

  // Retake once, then send.
  click(B, 'Записать заново')
  await until(() => labels(B).includes('● Начать запись'), 'camera again')
  click(B, '● Начать запись'); await until(() => labels(B).includes('■ Остановить'), 'recording 2')
  click(B, '■ Остановить'); await until(() => labels(B).some(l => l.startsWith('Отправить')), 'review 2')
  const sent = B.t.recordings.at(-1)
  click(B, 'Отправить Maria')
  await until(() => labels(A).includes('▶ Посмотреть видео'), 'A has the recording', 15000)
  ok('the asker is told a recording arrived', text(A, 'video-text').includes('записал(а) видео') && text(A, 'video-text').includes(safety))
  ok('the person who recorded is told to wait, and may retake', text(B, 'video-text').includes('Ждём решения') && labels(B).join() === 'Записать заново')
  ok('their camera is not left running', B.t.camera.stops >= 2)

  // Watching and deciding.
  click(A, '▶ Посмотреть видео')
  await until(() => A.window.document.querySelector('#video-stage video'), 'player', 12000)
  const played = A.t.urls.at(-1)
  const got = await readBlob(A, played)
  ok('the asker plays exactly the bytes that were recorded', Buffer.compare(got, sent) === 0, `${got.length} vs ${sent.length}`)
  ok('it was decrypted in the asker\'s browser as a video', played.type === 'video/webm')
  ok('only the asker gets the verdict buttons', labels(A).includes('Подтверждаю') && labels(A).includes('Не подтверждаю') && !labels(B).includes('Подтверждаю'))

  click(A, 'Подтверждаю')
  await until(() => cls(A) === 'video good' && cls(B) === 'video good', 'confirmed on both', 12000)
  ok('the verdict shows on both screens, naming the asker', text(A, 'video-text').startsWith('✅ Вы') && text(B, 'video-text').includes('подтвердил(а) личность'))
  ok('the asker can watch it again after deciding', labels(A).includes('▶ Посмотреть снова'))

  // Decline, and a second request in the other direction.
  click(B, 'Запросить снова')
  await until(() => labels(A).includes('Включить камеру'), 'B asks A', 12000)
  ok('either person can ask, and the roles swap', labels(B).join() === 'Отменить запрос')
  click(A, 'Отклонить')
  await until(() => cls(A) === 'video bad' && cls(B) === 'video bad', 'declined', 12000)
  ok('a refusal is explained to both', text(B, 'video-text').includes('отклонил(а) запрос') && text(A, 'video-text').includes('Вы отклонили'))

  // A denial warns.
  click(A, 'Запросить снова')
  await until(() => labels(B).includes('Включить камеру'), 'A asks again', 12000)
  click(B, 'Включить камеру'); await until(() => labels(B).includes('● Начать запись'), 'cam')
  click(B, '● Начать запись'); await until(() => labels(B).includes('■ Остановить'), 'rec')
  click(B, '■ Остановить'); await until(() => labels(B).some(l => l.startsWith('Отправить')), 'rev')
  click(B, 'Отправить Maria')
  await until(() => labels(A).includes('Не подтверждаю'), 'second recording', 15000)
  click(A, 'Не подтверждаю')
  await until(() => cls(B) === 'video bad' && text(B, 'video-text').includes('не подтвердил'), 'denied', 12000)
  ok('a denial warns both people not to share secrets', text(B, 'video-text').includes('Не передавайте секреты'))
  ok('no script errors on either page', A.errors.length === 0 && B.errors.length === 0, A.errors.concat(B.errors).join('; '))
  C.finish()
})().catch(C.crash)
