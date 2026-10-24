const C = require('./ui_common')
const { ok, sleep, until, api, openBrowser, $, visible, seatsFor } = C
const { DatabaseSync } = require('node:sqlite')
const toasts = (dom) => [...dom.window.document.querySelectorAll('#toasts .toast')].map(n => n.textContent)
const items = (dom) => dom.window.document.querySelectorAll('#room-items .item').length
const submit = (dom, fields) => {
  for (const [k, v] of Object.entries(fields)) $(dom, 'f-' + k).value = v
  $(dom, 'room-form').dispatchEvent(new dom.window.Event('submit', { cancelable: true, bubbles: true }))
}
const hasToast = (dom, part) => toasts(dom).some(t => t.includes(part))

;(async () => {
  const { code } = await api('POST', '/api/session/create')
  const seats = await seatsFor(code)
  const A = await openBrowser(`/result/${code}`, seats[0])      // Maria
  const B = await openBrowser(`/result/${code}`, seats[1])      // Ivan
  await until(() => visible(A, 'room-live') && visible(B, 'room-live'), 'both live')
  await until(() => $(A, 'room-presence').textContent.includes('в комнате'), 'presence')
  ok('presence: each side sees the other is in the room', $(A, 'room-presence').textContent.includes('● Ivan в комнате') && $(A, 'room-presence').className.includes('on'), $(A, 'room-presence').textContent)

  // Your own actions are silent.
  const SECRET = 'correct-horse-battery-staple-91'
  submit(A, { password: SECRET })
  await until(() => items(B) === 1, 'B has item 1')
  ok('the sender is not notified of their own action', !toasts(A).some(t => t.includes('отправил') || t.includes('удалил')) && A.t.notes.length === 0, 'A toasts=' + toasts(A).join('|'))
  ok('what the sender does see is about the other person or the channel', toasts(A).every(t => t.includes('Ivan') || t.includes('канал')), toasts(A).join('|'))
  ok('the receiver gets a toast, naming the sender', hasToast(B, 'Maria отправил(а) вам данные'), toasts(B).join('|'))
  ok('with notifications off nothing beeps or pops up', B.t.beeps === 0 && B.t.notes.length === 0 && B.t.vibes === 0)
  ok('a visible tab gets no unread count', !B.window.document.title.startsWith('('))

  // Turning notifications on.
  $(B, 'room-notify').click()
  await until(() => $(B, 'room-notify').textContent.includes('вкл') && B.t.beeps === 1, 'enabled and confirmed')
  ok('enabling asks permission, remembers the choice and confirms with a beep',
     B.window.Notification.permission === 'granted' && B.window.localStorage.getItem('notify:on') === '1' && B.t.beeps === 1, `perm=${B.window.Notification.permission} pref=${B.window.localStorage.getItem('notify:on')} beeps=${B.t.beeps}`)

  // A background tab.
  B.setHidden(true)
  const beepsBefore = B.t.beeps
  submit(A, { note: 'second item, ' + SECRET })
  await until(() => items(B) === 2, 'B has item 2')
  await until(() => B.t.notes.length === 1, 'system notification', 6000)
  ok('a background tab gets an unread count in its title', B.window.document.title.startsWith('(1) '), B.window.document.title)
  ok('and a system notification', B.t.notes.length === 1 && B.t.notes[0].title === 'Верификатор')
  const body = B.t.notes[0].body
  ok('the system notification names nobody', !body.includes('Maria') && body.startsWith('Собеседник'), body)
  ok('and reveals nothing that was shared', !body.includes(SECRET) && !body.includes(code) && !body.includes('second item'))
  ok('the device beeps and vibrates', B.t.beeps === beepsBefore + 1 && B.t.vibes >= 1, `beeps=${B.t.beeps} before=${beepsBefore} vibes=${B.t.vibes}`)
  ok('the toast waits for the person to come back', hasToast(B, 'отправил(а) вам данные'))

  B.setHidden(false)
  ok('returning clears the unread count', B.window.document.title.startsWith('Результат') && !B.window.document.title.startsWith('('), B.window.document.title)

  // Video: the asker, the answerer, and who hears about what.
  B.setHidden(true)
  const noteCount = B.t.notes.length
  $(A, 'video-buttons').querySelector('button').click()
  await until(() => B.t.notes.length === noteCount + 1, 'video notification', 6000)
  ok('a video request reaches the other person with a system notification', B.t.notes.at(-1).body === 'Собеседник просит записать короткое видео', B.t.notes.at(-1).body)
  ok('the asker is not told about their own request', !hasToast(A, 'просит'))
  B.setHidden(false)
  const btn = (dom, label) => [...$(dom, 'video-buttons').querySelectorAll('button')].find(x => x.textContent === label)
  const present = (dom, label) => !!btn(dom, label) || [...$(dom, 'video-buttons').querySelectorAll('button')].some(x => x.textContent.startsWith(label))
  await until(() => present(B, 'Включить камеру'), 'camera button')
  btn(B, 'Включить камеру').click()
  await until(() => present(B, '● Начать запись'), 'record button'); btn(B, '● Начать запись').click()
  await until(() => present(B, '■ Остановить'), 'stop button'); btn(B, '■ Остановить').click()
  await until(() => present(B, 'Отправить'), 'send button')
  ;[...$(B, 'video-buttons').querySelectorAll('button')].find(x => x.textContent.startsWith('Отправить')).click()
  await until(() => hasToast(A, 'записал(а) видео'), 'A told a video arrived', 15000)
  ok('the asker hears the video arrived', hasToast(A, 'Ivan записал(а) видео: посмотрите и решите'))
  ok('the person who recorded is not told about their own action', !hasToast(B, 'записал(а) видео'))

  // Deleting: the other person hears, you do not.
  const aItem = [...A.window.document.querySelectorAll('#room-items .item')].pop()
  ;[...aItem.querySelectorAll('.item-head button')][0].click()
  await until(() => items(B) === 1, 'deletion reaches B', 9000)
  ok('the other person hears an item was deleted', hasToast(B, 'Maria удалил(а) запись'), toasts(B).join('|'))
  ok('the person who deleted is not told', !hasToast(A, 'удалил(а) запись'), toasts(A).join('|'))

  // Catch-up after being away.
  const away = B.window.localStorage.getItem('room:' + code)
  B.window.close()
  submit(A, { login: 'while-you-were-out-1' }); await until(() => items(A) >= 2, 'A item'); await sleep(300)
  submit(A, { login: 'while-you-were-out-2' }); await sleep(900)
  const B2 = await openBrowser(`/result/${code}`, null, away)
  await until(() => visible(B2, 'room-live'), 'B2 live')
  await until(() => hasToast(B2, 'Пока вас не было'), 'catch-up toast', 8000)
  ok('coming back shows what was missed, with a count', hasToast(B2, 'отправил(а) вам данные (2)'), toasts(B2).join('|'))
  const again = B2.window.localStorage.getItem('room:' + code)
  B2.window.close()
  const B3 = await openBrowser(`/result/${code}`, null, again)
  await until(() => visible(B3, 'room-live'), 'B3 live'); await sleep(800)
  ok('reloading again does not repeat it', !hasToast(B3, 'Пока вас не было') && !hasToast(B3, 'отправил(а) вам данные'), toasts(B3).join('|'))

  // The room announcing its own end.
  const db = new DatabaseSync(process.env.DB_PATH)
  const setExpiry = (ms) => db.prepare('UPDATE sessions SET expires_at=? WHERE code=?').run(new Date(Date.now() + ms).toISOString(), code)
  setExpiry(4.5 * 60000)
  await until(() => hasToast(B3, 'меньше чем через 5 минут'), 'five minute warning', 9000)
  ok('a five-minute warning', true)
  setExpiry(50 * 1000)
  await until(() => hasToast(B3, 'меньше чем через минуту'), 'one minute warning', 9000)
  ok('and a one-minute warning', true)
  setExpiry(25 * 60000)

  // The other person closing the room.
  $(B3, 'room-notify').click()
  await until(() => $(B3, 'room-notify').textContent.includes('вкл'), 'B3 notifications on')
  B3.setHidden(true)
  const notesBefore = B3.t.notes.length
  A.window.confirm = () => true
  $(A, 'room-close').click()
  await until(() => B3.t.notes.length === notesBefore + 1, 'closed notification', 9000)
  ok('a closed room raises a system notification', B3.t.notes.at(-1).body === 'Комната закрыта: все данные удалены', B3.t.notes.at(-1).body)
  ok('the person who closed it is not notified', A.t.notes.length === 0 && !hasToast(A, 'Комната закрыта: все данные удалены'))
  ok('no script errors on any page', [A, B, B2, B3].every(d => d.errors.length === 0), [A, B, B2, B3].flatMap(d => d.errors).join('; '))

  C.finish()
})().catch(C.crash)
