// When recording in the page is not possible: permission refused, or no camera API.
const C = require('./ui_common')
const { ok, until, api, openBrowser, $, visible, seatsFor } = C

const text = (dom, id) => $(dom, id).textContent
const labels = (dom) => [...dom.window.document.querySelectorAll('#video-buttons button')].map(b => b.textContent)
const click = (dom, label) => [...dom.window.document.querySelectorAll('#video-buttons button')].find(b => b.textContent === label).click()
const readBlob = (dom, blob) => new Promise((resolve, reject) => {
  const reader = new dom.window.FileReader()
  reader.onload = () => resolve(Buffer.from(reader.result)); reader.onerror = reject
  reader.readAsArrayBuffer(blob)
})

;(async () => {
  // ── camera permission refused, then granted on retry
  {
    const { code } = await api('POST', '/api/session/create')
    const seats = await seatsFor(code)
    const A = await openBrowser(`/result/${code}`, seats[0])
    const B = await openBrowser(`/result/${code}`, seats[1], null, { denied: true })
    await until(() => visible(A, 'room-live') && visible(B, 'room-live'), 'live')
    click(A, 'Запросить видеопроверку')
    await until(() => labels(B).includes('Включить камеру'), 'asked')
    click(B, 'Включить камеру')
    await until(() => text(B, 'video-stage').includes('Не удалось включить камеру'), 'denied message')
    ok('a refused camera is explained, with what to do about it', text(B, 'video-stage').includes('Разрешите доступ к камере и микрофону'))
    ok('they can retry or decline instead of being stuck', labels(B).includes('Попробовать снова') && labels(B).includes('Отклонить'))
    ok('nothing was recorded or uploaded', B.t.recordings.length === 0 && B.t.camera.opens === 0)
    B.t.camera.denied = false
    click(B, 'Попробовать снова')
    await until(() => labels(B).includes('● Начать запись'), 'camera after retry')
    ok('after allowing access the retry works', B.t.camera.opens === 1)
    click(B, 'Отмена')
    await until(() => labels(B).includes('Включить камеру'), 'cancelled back to the start')
    ok('cancelling releases the camera and returns to the instructions', B.t.camera.stops === 1 && text(B, 'video-stage').includes('код сверки'))
    ok('no script errors (camera refusal)', A.errors.length === 0 && B.errors.length === 0, A.errors.concat(B.errors).join('; '))
  }

  // ── a browser with no recording API: the phone's own camera app is used
  {
    const { code } = await api('POST', '/api/session/create')
    const seats = await seatsFor(code, 1)
    const A = await openBrowser(`/result/${code}`, seats[0])
    const B = await openBrowser(`/result/${code}`, seats[1], null, { noCamera: true })
    await until(() => visible(A, 'room-live') && visible(B, 'room-live'), 'live 2')
    click(A, 'Запросить видеопроверку')
    await until(() => B.window.document.querySelector('#video-stage input[type=file]'), 'file fallback')
    const input = B.window.document.querySelector('#video-stage input[type=file]')
    ok('without a recording API they are pointed at the phone camera', input.accept === 'video/*' && input.getAttribute('capture') === 'user' && text(B, 'video-stage').includes('камерой телефона'))
    ok('declining is still offered', labels(B).includes('Отклонить'))

    const choose = (size) => {
      const file = new B.window.File([Buffer.alloc(size, 7)], 'clip.mp4', { type: 'video/mp4' })
      Object.defineProperty(input, 'files', { value: [file], configurable: true })
      input.dispatchEvent(new B.window.Event('change', { bubbles: true }))
      return file
    }
    choose(13 * 1024 * 1024)
    await until(() => text(B, 'room-error').includes('слишком большое'), 'too big')
    ok('a file over the limit is refused before anything is sent', text(B, 'room-error').includes('до 12 МБ') && !labels(B).some(l => l.startsWith('Отправить')))

    const small = choose(50000)
    await until(() => labels(B).some(l => l.startsWith('Отправить')), 'send offered')
    click(B, 'Отправить Maria')
    await until(() => labels(A).includes('▶ Посмотреть видео'), 'A has it', 15000)
    click(A, '▶ Посмотреть видео')
    await until(() => A.window.document.querySelector('#video-stage video'), 'player')
    const got = await readBlob(A, A.t.urls.at(-1))
    ok('the file travels encrypted and plays back byte for byte', got.length === 50000 && got.every(b => b === 7))
    ok('its type survives the round trip', A.t.urls.at(-1).type === 'video/mp4')
    ok('no script errors (no camera API)', A.errors.length === 0 && B.errors.length === 0, A.errors.concat(B.errors).join('; '))
  }
  C.finish()
})().catch(C.crash)
