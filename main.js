// Verification page (public code). Opened from the dashboard with, in the URL FRAGMENT (never sent
// to any server): #t=<ticket>&s=<secret>&c=<casino>&f=<filter>&from=YYYY-MM-DD&to=YYYY-MM-DD
// The TLSNotary verifier runs in worker.js; this file checks what it proved and shows it.

const hash = new URLSearchParams(location.hash.slice(1))
const qs = new URLSearchParams(location.search)
const CASINO = hash.get('c') || qs.get('c') || ''
const FILTER = hash.get('f') || ''
const FROM = hash.get('from') || ''
const TO = hash.get('to') || ''
const T = hash.get('t') || '', S = hash.get('s') || ''
// The expected server is fixed HERE, in public code: the prover can never choose it.
const HOSTS = { mystake: 'affiliateapi.cellxpert.com', rolletto: 'affiliateapi.cellxpert.com', celsius: 'celsiuspartner.com' }
const NAMES = { mystake: 'MyStake', rolletto: 'Rolletto', celsius: 'Celsius' }
const HOST = HOSTS[CASINO] || ''
const NAME = NAMES[CASINO] || 'le casino'
const PROVER = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws?t=${encodeURIComponent(T)}&s=${encodeURIComponent(S)}`
// Our commission: NEVER displayed, not even as a masked placeholder.
const NEVER_SHOW = ['income', 'Commissions']
// Local design review only (never on the real host): ?demo renders sample data, clearly labelled.
const DEMO = qs.has('demo') && ['localhost', '127.0.0.1'].includes(location.hostname)

const $ = (id) => document.getElementById(id)
const esc = (v) => String(v ?? '').replace(/[<>&"]/g, (ch) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[ch]))
const mdy = (d) => { const [y, m, day] = d.split('-'); return `${m}/${day}/${y}` }
const frDate = (d) => (d ? d.slice(0, 10).split('-').reverse().join('/') : '')
const eur = new Intl.NumberFormat('fr-FR', { style: 'currency', currency: 'EUR' })
const num = (v) => Number(v) || 0

// "septembre 2026" for a whole month, else "du 01/10 au 12/10/2026".
function periodLabel() {
  if (!FROM || !TO) return ''
  const a = new Date(FROM + 'T12:00:00'), b = new Date(TO + 'T12:00:00')
  const lastDay = new Date(a.getFullYear(), a.getMonth() + 1, 0).getDate()
  if (a.getDate() === 1 && b.getMonth() === a.getMonth() && b.getDate() === lastDay) {
    return a.toLocaleDateString('fr-FR', { month: 'long', year: 'numeric' })
  }
  return `du ${frDate(FROM)} au ${frDate(TO)}`
}
const PERIOD = periodLabel()
// "de septembre 2026" / "du 01/10/2026 au 12/10/2026": the preposition depends on the period.
const PERIOD_PHRASE = PERIOD ? (PERIOD.startsWith('du ') ? ` ${PERIOD}` : ` de ${PERIOD}`) : ''
// What the proven server IS, in words a creator understands (never claim more than that).
const SOURCES = {
  celsius: "l'espace affilié officiel de Celsius",
  rolletto: "la plateforme d'affiliation officielle de Rolletto (CellXpert)",
  mystake: "la plateforme d'affiliation officielle de MyStake (CellXpert)",
}

// ── Proof checks + statement ────────────────────────────────────────────────────────────
// Bytes → string where every byte NOT authenticated by the proof becomes \u0000.
function revealed(bytes, ranges) {
  const out = new Array(bytes.length).fill('\u0000')
  const dec = new TextDecoder()
  for (const { start, end } of ranges) {
    const s = dec.decode(new Uint8Array(bytes.slice(start, end)))
    for (let i = 0; i < s.length; i++) out[start + i] = s[i]
    for (let i = start + s.length; i < end; i++) out[i] = ''
  }
  return out.join('')
}
function stripNeverShow(s) {
  // Celsius campaign name: only the creator's prefix is revealed, the rest (our deal) stays masked.
  s = s.replace(/("campaign_name":"[^"\u0000]*)\u0000+"/g, '$1…"')
  for (const f of NEVER_SHOW) s = s.replace(new RegExp(`,?"${f}":\\u0000+`, 'g'), '')
  return s
}
// A chunked HTTP response carries "\r\n<hex size>\r\n" framing, which can fall in the middle of a
// row. Raw CR/LF never appears inside valid JSON, so removing that framing cannot alter a value.
const unchunk = (x) => x.replace(/\r\n[0-9a-fA-F]+\r\n/g, '')

function check(out) {
  const t = out.transcript
  const sent = revealed(t.sent, t.sent_authed).replace(/(authorization: Bearer )\u0000+/i, '$1[masqué]')
  const recvRaw = revealed(t.recv, t.recv_authed)
  const body = recvRaw.slice(recvRaw.indexOf('\r\n\r\n') + 4)
  const problems = []
  // 1. The server, from its TLS certificate.
  if (out.server_name !== HOST) problems.push(`la réponse vient de ${out.server_name ?? 'un serveur inconnu'}, pas de ${HOST}`)
  // 2. The period actually asked to the casino (revealed request line).
  {
    const first = sent.split('\r\n')[0] || ''
    const ok = CASINO === 'celsius'
      ? first.includes('/api/get-referral-activity?') && first.includes(`start_date=${FROM}&end_date=${TO}`)
      : first.includes('command=getActivity') && first.includes(`startdate=${mdy(FROM)}&enddate=${mdy(TO)}`)
    if (!ok) problems.push('la période demandée au casino ne correspond pas')
  }
  // 3. Every revealed row must belong to this creator, and none may be dropped silently.
  const rows = []
  let unreadable = 0
  for (const m of body.matchAll(/\{[^{}]*\}/g)) {
    const raw = unchunk(m[0])
    const clean = stripNeverShow(raw)
    if (clean.includes('\u0000')) continue
    if (!raw.includes(FILTER)) { problems.push('une ligne reçue ne t\'appartient pas'); continue }
    try { rows.push(JSON.parse(clean)) } catch { unreadable++ }
  }
  if (unreadable) problems.push(`${unreadable} ligne(s) reçue(s) illisible(s)`)
  const when = out.connection_info?.time ? new Date(Number(out.connection_info.time) * 1000) : null
  const recvLen = t.recv.length
  const recvProved = (t.recv_authed || []).reduce((n, r) => n + (r.end - r.start), 0)
  const tls = out.connection_info?.version === 'V1_3' ? 'TLS 1.3' : out.connection_info?.version === 'V1_2' ? 'TLS 1.2' : (out.connection_info?.version || '')
  return { problems, rows, sent, body: stripNeverShow(unchunk(body)), server: out.server_name, when, recvLen, recvProved, tls }
}

// Normalise a row, whatever the casino. `key` is the player id as the dashboard stores it.
function player(r) {
  if (CASINO === 'celsius') {
    return { key: String(r.referral_id ?? ''), who: r.username || `Joueur ${r.referral_id}`,
      deposits: num(r.dep_sum), count: num(r.dep_count), ngr: r.ngr == null ? null : num(r.ngr) }
  }
  const id = String(r.userId ?? '').replace(/^[a-z]+-/i, '')
  return { key: String(r.userId ?? ''), who: `Joueur ${id}`,
    deposits: num(r.Net_Deposits ?? r.Deposits), count: num(r.Deposit_Count), ngr: null }
}

// ── Dashboard vs casino ─────────────────────────────────────────────────────────────────
// The dashboard's figures were frozen in the ticket BEFORE the proof (GET /expected): we compare
// the casino's proven answer to what the dashboard showed, never to figures adjusted afterwards.
// Celsius answers LIFETIME totals for the players registered in the period; CellXpert answers the
// activity OF the period. Hence "dep"/"ngr" (lifetime) or "depp" (period deposits).
async function loadExpected() {
  if (DEMO) return DEMO_EXPECTED
  try {
    const r = await fetch(`/expected?t=${encodeURIComponent(T)}&s=${encodeURIComponent(S)}`, { cache: 'no-store' })
    return r.ok ? await r.json() : null
  } catch { return null }
}
const cents = (v) => Math.round(Number(v) * 100)
function compare(ps, expected) {
  const lifetime = CASINO === 'celsius'
  return ps.map((p) => {
    const e = expected?.[p.key]
    const dash = e ? { deposits: num(lifetime ? e.dep : e.depp), ngr: lifetime ? num(e.ngr) : null } : null
    const same = !!dash && cents(dash.deposits) === cents(p.deposits) && (p.ngr == null || cents(dash.ngr) === cents(p.ngr))
    return { ...p, dash, same }
  })
}
// ── Icons ───────────────────────────────────────────────────────────────────────────────
const svg = (d, w = 2, s = 24) => `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${w}" stroke-linecap="round" stroke-linejoin="round">${d}</svg>`
const I = {
  dice: svg('<rect width="18" height="18" x="3" y="3" rx="3"/><path d="M8 8h.01M16 8h.01M12 12h.01M8 16h.01M16 16h.01"/>', 2, 26),
  monitor: svg('<rect width="20" height="14" x="2" y="3" rx="2"/><path d="M8 21h8M12 17v4"/>', 2, 26),
  server: svg('<rect width="20" height="8" x="2" y="2" rx="2"/><rect width="20" height="8" x="2" y="14" rx="2"/><path d="M6 6h.01M6 18h.01"/>', 2, 18),
  lock: svg('<rect width="18" height="11" x="3" y="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>', 2.4, 12),
  check: svg('<path d="M20 6 9 17l-5-5"/>', 3.2, 12),
  checkL: svg('<path d="M20 6 9 17l-5-5"/>', 3.2, 18),
  cross: svg('<path d="M18 6 6 18M6 6l12 12"/>', 3, 18),
}

// ── The route (casino → encrypted line → your browser, Network Partners on the side) ──────
// Same drawing on the three screens; its parts light up as the real steps complete.
function drawRoutes() {
  document.querySelectorAll('[data-route]').forEach((el) => {
    el.innerHTML =
      `<div class="node" data-n="casino"><div class="ic">${I.dice}</div><b>${esc(NAMES[CASINO] || 'Le casino')}</b><span>envoie tes chiffres</span></div>` +
      `<div class="wire" data-n="wire"><span class="pill">${I.lock}<span>connexion chiffrée</span></span><i class="dot"></i><i class="dot"></i><i class="dot"></i></div>` +
      `<div class="node" data-n="you"><div class="ic">${I.monitor}</div><b>Ton navigateur</b><span>les vérifie</span></div>`
  })
}
function light(parts, cls = 'on') {
  document.querySelectorAll('[data-n]').forEach((n) => n.classList.toggle(cls, parts.includes(n.dataset.n)))
}

// ── Steps: what the creator reads while the worker runs ──────────────────────────────────
// Every step is a real event reported by the TLSNotary worker, never a timed animation.
const fmtMB = (b) => `${(b / 1048576).toLocaleString('fr-FR', { maximumFractionDigits: 1, minimumFractionDigits: 1 })} Mo`
const fmtBytes = (b) => (b >= 1024 ? `${(b / 1024).toLocaleString('fr-FR', { maximumFractionDigits: 1 })} Ko` : `${b} octets`)
let traffic = { sent: 0, recv: 0 }
const STEPS = {
  'Chargement du vérificateur TLSNotary': { n: 1, p: 0.08, lit: ['you'],
    title: 'Ton navigateur charge TLSNotary',
    text: "L'outil open source de la Fondation Ethereum qui va faire la vérification, ici, dans ton navigateur.",
    done: 'TLSNotary chargé dans ton navigateur', log: 'Moteur TLSNotary chargé dans ton navigateur' },
  'Connexion au prouveur': { n: 2, p: 0.15, lit: ['you', 'np'],
    title: 'Connexion à notre serveur de preuve',
    text: 'Il va faire le calcul avec ton navigateur. Seul, il ne peut rien modifier.',
    done: 'Connecté à notre serveur de preuve', log: 'Connecté au serveur de preuve' },
  'Préparation du calcul partagé': { n: 3, p: 0.3, lit: ['you', 'np'],
    title: 'Calcul partagé en cours',
    text: null, // live: megabytes exchanged
    done: 'Calcul partagé prêt', log: 'Calcul partagé prêt' },
  'Connexion chiffrée au serveur du casino et réception de la réponse': { n: 4, p: 0.65, lit: ['you', 'np', 'wire', 'casino'], flow: true,
    title: `Connexion à ${HOST || 'au casino'}`,
    text: `Ton navigateur contrôle le certificat de sécurité de ${NAME}, le même que le cadenas de ta barre d'adresse, et reçoit tes chiffres.`,
    done: `Réponse de ${NAME} reçue, certificat vérifié`, log: `Réponse de ${HOST || 'du casino'} reçue et authentifiée` },
  'Vérification de la preuve': { n: 5, p: 0.88, lit: ['you', 'np', 'wire', 'casino'],
    title: 'Vérification de la preuve',
    text: 'Ton navigateur contrôle que chaque chiffre est exactement celui envoyé par le casino. Un seul changé, et ça échoue.',
    done: 'Preuve vérifiée : rien n\'a été modifié', log: 'Preuve cryptographique vérifiée' },
}
const mpcText = () => `Ton navigateur et notre serveur préparent ensemble la connexion chiffrée : ${fmtMB(traffic.sent + traffic.recv)} échangés. Aucun des deux ne peut tricher seul.`
let current = null
function onStep(label) {
  const st = STEPS[label]; if (!st) return
  current = st
  $('nowTitle').textContent = st.title
  $('nowText').textContent = st.text ?? mpcText()
  $('step').textContent = `Étape ${st.n} sur 5`
  $('bar').style.width = `${st.p * 100}%`
  light(st.lit)
  document.querySelectorAll('[data-n="wire"]').forEach((w) => w.classList.toggle('flow', !!st.flow))
}
function onDone(label) {
  const st = STEPS[label]; if (!st) return
  const li = document.createElement('li')
  li.innerHTML = `<i>${I.check}</i><span>${esc(st.n === 3 ? `${st.done} (${fmtMB(traffic.sent + traffic.recv)} échangés)` : st.done)}</span>`
  $('done').append(li)
  logLine(st.n === 3 ? `Calcul partagé avec le serveur de preuve : ${fmtMB(traffic.sent + traffic.recv)} échangés` : st.log)
}
function onTraffic(m) {
  traffic = m
  if (current?.n === 3) {
    $('nowText').textContent = mpcText()
    $('bar').style.width = `${(0.3 + 0.32 * Math.min(1, (m.sent + m.recv) / 63e6)) * 100}%`
  }
}
const logs = []
function logLine(text, cls = '') {
  logs.push({ t: new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' }), text, cls })
  $('log').innerHTML = logs.map((l) => `<li><time>${l.t}</time><span class="${l.cls}">${esc(l.text)}</span></li>`).join('')
}

// ── Screens ─────────────────────────────────────────────────────────────────────────────
function show(id) { for (const s of ['intro', 'run', 'result']) $(s).hidden = s !== id }

drawRoutes()
document.querySelectorAll('.cname').forEach((e) => { e.textContent = NAME })
if (NAMES[CASINO]) $('title').textContent = `Vérifie tes chiffres ${NAME}${PERIOD_PHRASE}`
light([])
// A link missing any of these would skip a check (server, ownership, period): refuse it outright.
if ((!T || !S || !HOST || !FILTER || !FROM || !TO) && !DEMO) {
  $('go').disabled = true
  $('note').textContent = 'Ce lien est incomplet. Relance la vérification depuis ton dashboard.'
  $('note').hidden = false
}

// ── Result ──────────────────────────────────────────────────────────────────────────────
function renderCompare(ps, expected) {
  if (!expected) {
    $('cmpsum').innerHTML = '<span class="pill warn">indisponible</span> Les chiffres du dashboard n\'ont pas pu être chargés.'
    $('cmptable').innerHTML = ''
    return
  }
  const rows = compare(ps, expected)
  const ok = rows.filter((r) => r.same).length
  const withNgr = rows.some((r) => r.ngr != null)
  $('cmpsum').innerHTML = rows.length === 0
    ? `<span class="pill">rien à comparer</span> ${esc(NAME)} n'indique aucun joueur sur cette période.`
    : ok === rows.length
      ? `<span class="pill">identique</span> Les ${rows.length} joueur${rows.length > 1 ? 's ont' : ' a'} les mêmes chiffres des deux côtés.`
      : `<span class="pill warn">${rows.length - ok} écart${rows.length - ok > 1 ? 's' : ''}</span> ${ok} joueur${ok > 1 ? 's' : ''} sur ${rows.length} identique${ok > 1 ? 's' : ''}.`
  // When the dashboard was last reconciled with the casino's own report (frozen in the ticket).
  const synced = expected?._meta?.synced ? new Date(expected._meta.synced) : null
  const ago = synced && !Number.isNaN(synced.getTime()) ? Math.max(0, Date.now() - synced.getTime()) : null
  const agoText = ago == null ? '' : ago < 3600e3 ? `il y a ${Math.max(1, Math.round(ago / 60e3))} min` : `il y a ${Math.round(ago / 3600e3)} h`
  const syncLine = synced && ago != null
    ? `Dernière mise à jour du dashboard avec ${NAME} : ${synced.toLocaleString('fr-FR', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })} (${agoText}). Elle est refaite toutes les 3 heures.`
    : ''
  $('cmpwhy').hidden = ok === rows.length && !syncLine
  $('cmpwhy').textContent = ok === rows.length ? syncLine
    : `${syncLine} Un écart veut dire que ${NAME} a enregistré de l'activité pour ce joueur depuis : le dashboard la reprendra au prochain passage. Ta commission se calcule sur les chiffres du casino.`.trim()
  const cell = (v, d) => `${esc(eur.format(v))}${d != null && cents(d) !== cents(v) ? `<small>dashboard ${esc(eur.format(d))}</small>` : ''}`
  $('cmptable').innerHTML =
    `<thead><tr><th>Joueur</th><th>Déposé</th>${withNgr ? '<th>NGR</th>' : ''}<th>Dashboard</th></tr></thead><tbody>` +
    rows.sort((a, b) => Number(a.same) - Number(b.same) || b.deposits - a.deposits).map((r) =>
      `<tr><td>${esc(r.who)}</td><td>${cell(r.deposits, r.dash?.deposits)}</td>` +
      (withNgr ? `<td>${r.ngr == null ? '' : cell(r.ngr, r.dash?.ngr)}</td>` : '') +
      `<td>${!r.dash ? '<span class="s ko">absent</span>' : r.same ? '<span class="s">identique</span>' : '<span class="s ko">écart</span>'}</td></tr>`).join('') +
    '</tbody>'
}

async function showResult(v) {
  const ps = v.rows.map(player)
  const ok = v.problems.length === 0
  logLine(`Certificat de ${v.server} vérifié${v.tls ? `, connexion ${v.tls}` : ''}`)
  logLine(`Réponse du casino : ${fmtBytes(v.recvLen)}, dont ${fmtBytes(v.recvProved)} révélés, le reste masqué`)
  logLine(ok ? `Preuve valide : ${ps.length} joueur${ps.length > 1 ? 's' : ''}, rien n'a été modifié` : `Preuve refusée : ${v.problems.join(' ; ')}`, ok ? 'ok' : 'bad')
  if (!ok) return fail('Vérification refusée', `${v.problems.join(' ; ')}. Ne prends pas ces chiffres en compte et relance depuis ton dashboard.`)

  $('verdict').innerHTML = `<div class="ok">${I.checkL}</div><div><h1>Tes chiffres ${esc(NAME)}${esc(PERIOD_PHRASE)} sont confirmés</h1>` +
    `<p>Ils viennent de ${esc(v.server)}, ${esc(SOURCES[CASINO] || 'le serveur du casino')}, et personne ne les a modifiés.</p></div>`
  const hasNgr = ps.some((p) => p.ngr != null)
  const totalDep = ps.reduce((a, p) => a + p.deposits, 0)
  const totalCount = ps.reduce((a, p) => a + p.count, 0)
  const totalNgr = ps.reduce((a, p) => a + (p.ngr ?? 0), 0)
  // Players with at least one deposit. Celsius lists the players REGISTERED in the period, so these
  // are their first depositors (FTD); CellXpert lists the period's activity, so they are depositors.
  const depositors = ps.filter((p) => p.count > 0 || p.deposits > 0).length
  const depLabel = CASINO === 'celsius' ? 'FTD' : `déposant${depositors > 1 ? 's' : ''}`
  $('figures').innerHTML =
    `<div><b>${ps.length}</b><small>joueur${ps.length > 1 ? 's' : ''}</small></div>` +
    `<div><b>${depositors}</b><small>${depLabel}</small></div>` +
    `<div><b>${esc(eur.format(totalDep))}</b><small>déposés</small></div>` +
    (hasNgr ? `<div><b>${esc(eur.format(totalNgr))}</b><small>de NGR</small></div>`
            : `<div><b>${totalCount}</b><small>dépôt${totalCount > 1 ? 's' : ''}</small></div>`)
  $('why1').textContent = `Ton navigateur a vérifié le certificat de sécurité de ${v.server}, comme le cadenas de ta barre d'adresse.`

  // The proof: revealed text as received, masked runs as grey blocks. Short masked runs get a
  // fixed glyph (their length must not hint at anything); long ones say how much is hidden.
  $('proof').innerHTML = v.body.split(/(\u0000+)/).map((part) => {
    if (!part) return ''
    if (part[0] !== '\u0000') return esc(part)
    return part.length < 200 ? '<span class="mask">▒▒▒</span>' : `<span class="gap">▒ ${esc(fmtBytes(part.length))} masqués</span>`
  }).join('')
  $('facts').innerHTML =
    `<dt>Serveur prouvé</dt><dd>${esc(v.server)}, certificat vérifié par ton navigateur</dd>` +
    `<dt>Connexion</dt><dd>${esc(v.tls || 'TLS')}, le ${v.when ? esc(v.when.toLocaleString('fr-FR')) : '?'}</dd>` +
    `<dt>Période demandée</dt><dd>du ${esc(frDate(FROM))} au ${esc(frDate(TO))}</dd>` +
    `<dt>Requête prouvée</dt><dd><code class="rq">${esc((v.sent.split('\r\n')[0] || '').replace(/\u0000+/g, '[masqué]'))}</code></dd>` +
    `<dt>Réponse du casino</dt><dd>${esc(fmtBytes(v.recvLen))}, dont ${esc(fmtBytes(v.recvProved))} révélés</dd>` +
    `<dt>Calcul partagé</dt><dd>${esc(fmtMB(traffic.sent + traffic.recv))} échangés par ton navigateur</dd>` +
    `<dt>Technologie</dt><dd>TLSNotary (MPC-TLS), Fondation Ethereum</dd>`
  $('rawreq').textContent = v.sent.replace(/\u0000+/g, '[…]')

  // Plain-text version of exactly what the drawer shows (same masking: our commission never in it).
  proofText = [
    `Vérification TLSNotary de mes chiffres ${NAME}${PERIOD_PHRASE}`,
    `Serveur prouvé : ${v.server} (certificat vérifié par mon navigateur)`,
    `Connexion : ${v.tls || 'TLS'}, le ${v.when ? v.when.toLocaleString('fr-FR') : '?'}`,
    `Période demandée au casino : du ${frDate(FROM)} au ${frDate(TO)}`,
    `Réponse du casino : ${fmtBytes(v.recvLen)}, dont ${fmtBytes(v.recvProved)} révélés`,
    `Résultat affiché : ${ps.length} joueur(s) dont ${depositors} ${depLabel}, ${eur.format(totalDep)} déposés${hasNgr ? `, ${eur.format(totalNgr)} de NGR` : ''}`,
    `Requête envoyée au casino, telle que prouvée (jeton de connexion masqué) : ${(v.sent.split('\r\n')[0] || '').replace(/\u0000+/g, '[masqué]')}`,
    '',
    'Réponse du casino telle que prouvée (▒ = masqué par la preuve : autres créateurs et commission de l\'agence) :',
    v.body.split(/(\u0000+)/).map((part) => !part ? '' : part[0] !== '\u0000' ? part : part.length < 200 ? '▒▒▒' : `[${fmtBytes(part.length)} masqués]`).join(''),
  ].join('\n')
  // Compact form for the AI link: the proven rows as JSON, minus the campaign name (identical on
  // every row, said once), biggest deposits first; masked parts summed up in one line.
  const masked = (v.body.match(/\u0000+/g) || [])
  askData = {
    head: proofText.split('\n').slice(0, 7).join('\n'),
    prefix: CASINO === 'celsius' ? FILTER.replace('"campaign_name":"', '') : '',
    maskedLine: `Parties masquées par la preuve : ${masked.length} blocs, ${fmtBytes(masked.reduce((n, m) => n + m.length, 0))} au total. ` +
      `Selon l'agence, ce sont les lignes des joueurs de ses autres créateurs, l'enveloppe de la réponse et, dans mes lignes, ` +
      `${CASINO === 'celsius' ? "le champ income (sa commission) et la fin du nom de campagne (son accord avec le casino)" : 'le champ Commissions (sa commission)'}. ` +
      `La preuve ne permet pas de vérifier ce que contient un bloc masqué.`,
    rows: [...v.body.matchAll(/\{[^{}\u0000]*\}/g)].map((m) => {
      try { const o = JSON.parse(m[0]); delete o.campaign_name; return o } catch { return null }
    }).filter(Boolean).sort((a, b) => num(b.dep_sum ?? b.Net_Deposits ?? b.Deposits) - num(a.dep_sum ?? a.Net_Deposits ?? a.Deposits)),
  }
  light(['casino', 'wire', 'you', 'np'])
  document.querySelectorAll('[data-n="wire"]').forEach((w) => w.classList.remove('flow'))
  show('result')
  renderCompare(ps, await loadExpected())
}

function fail(title, text) {
  $('now').classList.add('fail')
  $('nowTitle').textContent = title
  $('nowText').textContent = text
  $('bar').style.background = 'var(--bad)'
  document.querySelectorAll('[data-n="wire"]').forEach((w) => w.classList.remove('flow'))
  show('run')
}
function showFailure(message) {
  logLine(`Arrêt : ${message}`, 'bad')
  console.error(message)
  fail('La vérification n\'a pas pu aller au bout', /ticket|expired|invalid|incomplet/i.test(message)
    ? 'Ce lien a déjà servi ou a expiré. Relance la vérification depuis ton dashboard.'
    : 'Relance-la depuis ton dashboard. Si ça se reproduit, préviens-nous.')
}

// ── Share the proof: copy it, or ask an independent AI about it ───────────────────────────
let proofText = ''
let askData = null
const ASK = {
  chatgpt: (q) => `https://chatgpt.com/?q=${encodeURIComponent(q)}`,
  claude: (q) => `https://claude.ai/new?q=${encodeURIComponent(q)}`,
}
// What the fields mean, per casino: without it an AI rightly asks whether totals are for the period.
const FIELDS = {
  celsius: "Pour Celsius, la liste contient les joueurs INSCRITS pendant la période demandée ; dep_count, dep_sum, ggr et ngr " +
    "sont leurs totaux depuis l'inscription (pas seulement sur la période). ngr est le NGR net tel que Celsius le calcule, " +
    "la base de ma commission en revenue share.",
  rolletto: "Pour Rolletto (plateforme CellXpert), chaque ligne est l'activité d'un de mes joueurs sur la période demandée ; " +
    "Deposits / Net_Deposits sont ses dépôts sur cette période.",
  mystake: "Pour MyStake (plateforme CellXpert), chaque ligne est l'activité d'un de mes joueurs sur la période demandée ; " +
    "Net_Deposits est le total de ses dépôts sur cette période.",
}
const askPrompt = (proof) =>
  `Je suis créateur de contenu, affilié à des casinos via l'agence Network Partners. Pour prouver que mon dashboard ` +
  `est juste, ils m'ont donné une page de vérification TLSNotary (open source, équipe de recherche de la Fondation ` +
  `Ethereum, mode MPC-TLS) : mon navigateur participe à la connexion chiffrée avec le site d'affiliation du casino, ` +
  `contrôle son certificat, puis vérifie une preuve que la réponse n'a pas été modifiée. Seules mes lignes sont révélées.\n\n` +
  `Mon navigateur (vérificateur TLSNotary en WebAssembly) a déclaré la preuve valide. La page refuse la preuve si le ` +
  `serveur n'est pas le bon, si la période demandée au casino n'est pas celle affichée, ou si une ligne révélée ne ` +
  `m'appartient pas. Le fichier de preuve brut n'est pas fourni : il laisserait déduire la taille des champs masqués ` +
  `(dont la commission de l'agence).\n\n${FIELDS[CASINO] ? FIELDS[CASINO] + '\n\n' : ''}` +
  `${CASINO === 'celsius' ? 'FTD affiché = joueurs inscrits sur la période avec au moins un dépôt (dep_count > 0).' : 'Déposants affichés = joueurs avec au moins un dépôt sur la période.'}\n\n` +
  `Code public de la page : https://github.com/NetworkPartners/verification-tlsnotary (recette pour recompiler le ` +
  `vérificateur depuis la source officielle de TLSNotary, empreintes SHA-256 des fichiers servis par ` +
  `https://verif.networkpartners.xyz).\n\n` +
  `Limite connue et assumée : la preuve garantit que les lignes affichées sont authentiques, pas que la liste est ` +
  `complète. Le casino renvoie en une seule réponse les joueurs de tous les créateurs de l'agence, sans filtre par ` +
  `créateur possible de son côté (testé) : le serveur de l'agence choisit les lignes à révéler, et prouver qu'aucune ` +
  `ligne masquée n'est à moi obligerait à révéler les autres créateurs. Parade : m'inscrire avec mon lien, déposer, ` +
  `vérifier que j'apparais.\n\n` +
  `Je ne te demande pas de valider mon contrat ni ma commission, seulement ce que cette preuve établit. Explique-moi ` +
  `simplement : 1. ce qu'elle garantit et ses limites ; 2. si les données ci-dessous sont cohérentes ; 3. ce que je ` +
  `peux vérifier moi-même.\n\nLa preuve :\n\n${proof}`
// The AI message carries the proof itself. A link has a size limit (servers refuse past ~16 000
// characters), so rows are dropped from the end (smallest deposits) only when they cannot all fit.
const LINK_MAX = 15000
function askMessage() {
  const d = askData
  if (!d) return askPrompt(proofText)
  const build = (n) => askPrompt([
    d.head,
    d.prefix ? `Toutes les lignes révélées ont un campaign_name qui commence par « ${d.prefix} » (retiré de chaque ligne ci-dessous pour la place, la suite du nom est masquée).` : '',
    d.maskedLine,
    `Lignes prouvées (JSON tel que reçu du casino), ${n < d.rows.length ? `${n} sur ${d.rows.length}, les plus gros dépôts d'abord` : `${d.rows.length} au total`} :`,
    ...d.rows.slice(0, n).map((r) => JSON.stringify(r)),
    n < d.rows.length ? `(${d.rows.length - n} autres lignes non incluses faute de place dans le lien${d.rows.slice(n).every((r) => !num(r.dep_sum ?? r.Net_Deposits ?? r.Deposits)) ? ', toutes sans dépôt' : ''} ; la page les affiche toutes.)` : '',
  ].filter(Boolean).join('\n'))
  let n = d.rows.length
  while (n > 0 && encodeURIComponent(build(n)).length > LINK_MAX) n--
  return build(n)
}
function toast(text) {
  $('toast').textContent = text; $('toast').hidden = false
  clearTimeout(toast.t); toast.t = setTimeout(() => { $('toast').hidden = true }, 2600)
}
async function copy(text) {
  try { await navigator.clipboard.writeText(text); return true } catch { return false }
}
$('copyProof').onclick = async () => toast(await copy(proofText) ? 'Preuve copiée' : 'Copie impossible dans ce navigateur')
document.querySelectorAll('[data-ask]').forEach((b) => {
  b.onclick = async () => {
    const q = askMessage()
    window.open(ASK[b.dataset.ask](q), '_blank', 'noopener')
    toast('Conversation ouverte avec la preuve')
  }
})

// ── Proof drawer ────────────────────────────────────────────────────────────────────────
function openDrawer(tab) {
  $('scrim').hidden = false; $('drawer').hidden = false
  document.querySelectorAll('.tab').forEach((t) => t.setAttribute('aria-selected', String(t.dataset.tab === tab)))
  document.querySelectorAll('[data-pane]').forEach((p) => { p.hidden = p.dataset.pane !== tab })
}
function closeDrawer() { $('scrim').hidden = true; $('drawer').hidden = true }
document.querySelectorAll('[data-open]').forEach((b) => { b.onclick = () => openDrawer(b.dataset.open) })
document.querySelectorAll('.tab').forEach((t) => { t.onclick = () => openDrawer(t.dataset.tab) })
$('close').onclick = closeDrawer
$('scrim').onclick = closeDrawer
addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer() })

// ── Run ─────────────────────────────────────────────────────────────────────────────────
$('go').onclick = () => {
  $('go').disabled = true
  show('run')
  const t0 = performance.now()
  const clock = setInterval(() => { $('clock').textContent = `${Math.round((performance.now() - t0) / 1000)} s` }, 250)
  const stop = () => clearInterval(clock)
  if (DEMO) return demo(stop)

  const w = new Worker('./worker.js', { type: 'module' })
  w.onmessage = ({ data: m }) => {
    if (m.type === 'step') onStep(m.label)
    else if (m.type === 'done') onDone(m.label)
    else if (m.type === 'traffic') onTraffic(m)
    else if (m.type === 'result') { stop(); w.terminate(); showResult(check(m.out)) }
    else if (m.type === 'error') { stop(); w.terminate(); showFailure(`${m.label} : ${m.message}`) }
  }
  w.onerror = (e) => { stop(); showFailure(e.message || 'erreur du vérificateur') }
  w.postMessage({ prover: PROVER, threads: Math.max(2, navigator.hardwareConcurrency || 4) })
}

// Local design review: plays the same states with sample rows. Never active on the real host.
const DEMO_EXPECTED = { 188209: { dep: 50, ngr: 196.36, depp: 50 }, 188150: { dep: 0, ngr: 0, depp: 0 }, 190012: { dep: 20, ngr: 4.1, depp: 20 }, _meta: { synced: new Date(Date.now() - 80 * 60e3).toISOString() } }
function demo(stop) {
  const labels = Object.keys(STEPS)
  let i = 0
  const next = () => {
    if (i > 0) onDone(labels[i - 1])
    if (i === labels.length) {
      stop()
      const M = (n) => '\u0000'.repeat(n)
      showResult({ problems: [], server: HOST || 'celsiuspartner.com', when: new Date(), sent: 'GET /api/get-referral-activity?start_date=… HTTP/1.0', tls: 'TLS 1.2', recvLen: 17284, recvProved: 1180,
        body: M(900) + '{"referral_id":188209,"campaign_name":"Loxmb95 - KICK","username":"Majron","dep_count":1,"dep_sum":"50.00","ngr":"196.35618"}' + M(3200) + '{"referral_id":188150,"campaign_name":"Loxmb95 - KICK","username":"miro151","dep_count":0,"dep_sum":0,"ngr":"0"}' + M(5000),
        rows: [
          { referral_id: 188209, username: 'Majron', dep_count: 1, dep_sum: '50.00', ngr: '196.35618' },
          { referral_id: 188150, username: 'miro151', dep_count: 0, dep_sum: 0, ngr: '0' },
          { referral_id: 190012, username: 'User908649', dep_count: 2, dep_sum: '45.00', ngr: '12.40' },
        ] })
      return
    }
    onStep(labels[i])
    if (STEPS[labels[i]].n === 3) {
      let mb = 0
      const t = setInterval(() => { mb += 4e6; onTraffic({ sent: mb / 2, recv: mb / 2 }); if (mb >= 60e6) { clearInterval(t); i++; next() } }, 150)
      return
    }
    i++
    setTimeout(next, 1400)
  }
  next()
}
