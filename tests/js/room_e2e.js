// Two browsers, one live server, the real client crypto. Prints a JSON report.
const crypto = require('node:crypto')
const RC = require('../../templates/static/room-crypto.js')

const BASE = process.env.BASE
const USERS = JSON.parse(process.env.USERS)
const checks = {}
const ok = (name, value) => { checks[name] = Boolean(value) }

function base32(text) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const ch of text.replace(/=+$/, '')) bits += alphabet.indexOf(ch).toString(2).padStart(5, '0')
  const bytes = []
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2))
  return Buffer.from(bytes)
}
function totp(secret) {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)))
  const mac = crypto.createHmac('sha1', base32(secret)).update(counter).digest()
  const offset = mac[19] & 0xf
  const n = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3]
  return String(n % 1000000).padStart(6, '0')
}

async function api(method, path, token, body) {
  const res = await fetch(BASE + path, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { 'X-Room-Token': token } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  let json = null
  try { json = await res.json() } catch (e) {}
  return { status: res.status, json }
}

const rejects = async (promise) => { try { await promise; return false } catch (e) { return true } }

;(async () => {
  const SECRETS = { login: 'alice@example.com', password: 'c0rrect-h0rse-b4ttery!', code: '482913',
                    key: 'AKIA-NOT-REALLY-A-KEY-1234', note: 'vpn: ask Bob' }
  const { json: created } = await api('POST', '/api/session/create')
  const code = created.code
  const seats = []
  for (const user of USERS) {
    const { json } = await api('POST', `/api/session/${code}/verify/totp`, null, { user_id: user.id, code: totp(user.secret) })
    seats.push({ id: user.id, slot: json.slot, token: json.token })
  }
  ok('both people verified and got a seat token', seats.every(s => s.token && s.slot))
  const [A, B] = seats

  for (const seat of seats) Object.assign(seat, await RC.generateIdentity())
  const early = await api('POST', `/api/session/${code}/room/key`, seats[0].token, { public_key: seats[0].publicB64 })
  ok('a key is refused before the commitments exist', early.status === 409)
  for (const seat of seats) {
    const r = await api('POST', `/api/session/${code}/room/commit`, seat.token, { commit: seat.commit })
    ok(`${seat.id} committed to a key`, r.status === 200)
  }
  const liar = await RC.generateIdentity()
  const mismatch = await api('POST', `/api/session/${code}/room/key`, seats[0].token, { public_key: liar.publicB64 })
  ok('a key that does not match its commitment is refused', mismatch.status === 409)
  for (const seat of seats) {
    const r = await api('POST', `/api/session/${code}/room/key`, seat.token, { public_key: seat.publicB64 })
    ok(`${seat.id} revealed the committed key`, r.status === 200)
  }

  const stateA = (await api('GET', `/api/session/${code}/room`, A.token)).json
  const stateB = (await api('GET', `/api/session/${code}/room`, B.token)).json
  ok('room is ready for both', stateA.ready && stateB.ready)
  ok('each side sees the other\'s key', stateA.peer.public_key === B.publicB64 && stateB.peer.public_key === A.publicB64)
  ok('each side can check the revealed key against the pinned commitment',
     await RC.keyMatchesCommitment(stateA.peer.public_key, stateA.peer.commit) && await RC.keyMatchesCommitment(stateB.peer.public_key, stateB.peer.commit))
  ok('a key the server swapped in would fail that check', !(await RC.keyMatchesCommitment(liar.publicB64, stateA.peer.commit)))

  const safetyA = await RC.safetyCode(stateA.you.public_key, stateA.peer.public_key, code)
  const safetyB = await RC.safetyCode(stateB.you.public_key, stateB.peer.public_key, code)
  ok('both screens show the same safety code', safetyA === safetyB && /^\d{5} \d{5}$/.test(safetyA))

  const keyA = await RC.deriveRoomKey(A.privateJwk, stateA.peer.public_key, code)
  const keyB = await RC.deriveRoomKey(B.privateJwk, stateB.peer.public_key, code)

  // The video meeting's name: both browsers agree, nobody else can compute it.
  const nameA = await RC.videoRoomName(A.privateJwk, stateA.peer.public_key, code)
  const nameB = await RC.videoRoomName(B.privateJwk, stateB.peer.public_key, code)
  ok('both browsers derive the same video room name', nameA === nameB && /^verifier-[0-9a-f]{32}$/.test(nameA))
  ok('the name differs from room to room', nameA !== await RC.videoRoomName(A.privateJwk, stateA.peer.public_key, 'ZZZZ2345'))
  const outsider = await RC.generateIdentity()
  ok('someone with only the public keys cannot derive it',
     nameA !== await RC.videoRoomName(outsider.privateJwk, stateA.peer.public_key, code))
  const everythingServerSaw = JSON.stringify([stateA, stateB])
  ok('the server never saw the name or the secret behind it',
     !everythingServerSaw.includes(nameA) && !everythingServerSaw.includes(nameA.slice('verifier-'.length)))

  // A sends everything at once; B reads it.
  const sealed = await RC.encryptItem(keyA, code, A.slot, { ...SECRETS, junk: 'dropped' })
  const sent = await api('POST', `/api/session/${code}/room/items`, A.token, sealed)
  ok('server accepted the item', sent.status === 200)
  const seenByB = (await api('GET', `/api/session/${code}/room`, B.token)).json.items
  ok('B received one item from A', seenByB.length === 1 && seenByB[0].from === A.slot)
  const opened = await RC.decryptItem(keyB, code, seenByB[0].from, seenByB[0])
  ok('B decrypts all five fields exactly', JSON.stringify(opened) === JSON.stringify(SECRETS))
  const own = await RC.decryptItem(keyA, code, A.slot, seenByB[0])
  ok('the sender can read what they sent', own.password === SECRETS.password)

  const reply = await RC.encryptItem(keyB, code, B.slot, { note: 'got it, thanks' })
  await api('POST', `/api/session/${code}/room/items`, B.token, reply)
  const seenByA = (await api('GET', `/api/session/${code}/room`, A.token)).json.items
  const back = await RC.decryptItem(keyA, code, seenByA[1].from, seenByA[1])
  ok('the reply travels the other way', seenByA.length === 2 && back.note === 'got it, thanks')

  // Things that must fail.
  const item = seenByB[0]
  const flipped = Buffer.from(item.ciphertext, 'base64'); flipped[3] ^= 1
  ok('a tampered ciphertext is rejected', await rejects(RC.decryptItem(keyB, code, item.from, { ...item, ciphertext: flipped.toString('base64') })))
  ok('the same ciphertext does not open in another room', await rejects(
    RC.decryptItem(await RC.deriveRoomKey(B.privateJwk, stateB.peer.public_key, 'ZZZZ2345'), 'ZZZZ2345', item.from, item)))
  ok('it does not open if the direction is flipped', await rejects(RC.decryptItem(keyB, code, B.slot, item)))
  ok('an empty message is refused before it is sent', await rejects(RC.encryptItem(keyA, code, A.slot, { login: '   ' })))

  const imposter = await RC.generateIdentity()
  const swapped = await RC.safetyCode(stateA.you.public_key, imposter.publicB64, code)
  ok('a substituted public key changes the safety code', swapped !== safetyA)

  const huge = await api('POST', `/api/session/${code}/room/items`, A.token,
    await RC.encryptItem(keyA, code, A.slot, { note: 'x'.repeat(20000) }))
  ok('the server refuses an oversized item', huge.status === 400)
  ok('a stranger cannot read the room', (await api('GET', `/api/session/${code}/room`, 'nope')).status === 401)

  await api('DELETE', `/api/session/${code}/room/items/${item.id}`, B.token)
  ok('a deletion by the peer removes it for both', (await api('GET', `/api/session/${code}/room`, A.token)).json.items.every(i => i.id !== item.id))

  console.log(JSON.stringify({ checks, secrets: Object.values(SECRETS), code }))
})().catch(e => { console.log(JSON.stringify({ error: String(e && e.stack || e) })); process.exit(1) })
