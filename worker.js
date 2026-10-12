// TLSNotary verifier, run in a dedicated module worker: the wasm blocks on Atomics.wait,
// which browsers forbid on the main thread. Reports each step back to the page.
import init, { initialize, Verifier } from './pkg/tlsn_wasm.js'

const post = (type, data) => self.postMessage({ type, ...data })

// Bytes really exchanged with the prover: the MPC computation itself. Reported live to the page,
// so the creator SEES their browser doing the work (nothing simulated).
const traffic = { sent: 0, recv: 0 }

function wsIo(url) {
  const ws = new WebSocket(url, ['binary'])
  ws.binaryType = 'arraybuffer'
  const queue = []; let waiter = null; let closed = false
  const opened = new Promise((ok, ko) => { ws.onopen = ok; ws.onerror = () => ko(new Error('connexion au prouveur impossible')) })
  ws.onmessage = (e) => { const b = new Uint8Array(e.data); traffic.recv += b.byteLength; if (waiter) { const w = waiter; waiter = null; w(b) } else queue.push(b) }
  ws.onclose = () => { closed = true; if (waiter) { const w = waiter; waiter = null; w(null) } }
  return {
    opened,
    async read() { if (queue.length) return queue.shift(); if (closed) return null; return new Promise((r) => { waiter = r }) },
    async write(data) { await opened; traffic.sent += data.byteLength ?? data.length ?? 0; ws.send(data) },
    async close() { ws.close() },
  }
}

self.onmessage = async ({ data: { prover, threads } }) => {
  let label = ''
  const step = (l) => { label = l; post('step', { label }) }
  const ticker = setInterval(() => post('traffic', { ...traffic }), 400)
  try {
    step('Chargement du vérificateur TLSNotary'); await init(); await initialize(undefined, threads); post('done', { label })
    const v = new Verifier({ max_sent_data: 4096, max_recv_data: 32768, max_sent_records: undefined, max_recv_records_online: undefined, root_certs: undefined })
    step('Connexion au prouveur'); const io = wsIo(prover); await io.opened; await v.connect(io); post('done', { label })
    step('Préparation du calcul partagé'); const proxyHost = await v.setup()
    if (proxyHost) throw new Error('mode proxy refusé : seul le mode MPC est accepté')
    post('done', { label })
    step('Connexion chiffrée au serveur du casino et réception de la réponse'); await v.run(); post('done', { label })
    step('Vérification de la preuve'); const out = await v.verify(); post('done', { label })
    // Plain JSON copy for postMessage.
    post('traffic', { ...traffic })
    post('result', { out: JSON.parse(JSON.stringify(out, (_, x) => (typeof x === 'bigint' ? Number(x) : x))) })
  } catch (e) {
    post('error', { label, message: e?.message ?? String(e) })
  } finally { clearInterval(ticker) }
}
