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
const NEVER_SHOW = ['income', 'offer_name', 'Commissions']
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
// The question a creator asks an AI. Context first (what agencies usually give), then the facts and the
// known limit, then a request to sort proven / claimed / checkable: an AI judges a limit in proportion
// only when it knows what the alternative is. Never ask it to downplay the limit.
const askPrompt = (proof) =>
  `Je suis créateur de contenu, affilié à des casinos via l'agence Network Partners, payé sur les joueurs que ` +
  `j'apporte. Dans ce secteur, une agence transmet d'habitude ses chiffres par capture d'écran ou tableau, sans ` +
  `aucun moyen pour le créateur de vérifier qu'ils viennent bien du casino. Network Partners m'a donné à la place ` +
  `une page de vérification TLSNotary (open source, équipe de recherche de la Fondation Ethereum, mode MPC-TLS) : ` +
  `mon navigateur participe à la connexion chiffrée avec le site d'affiliation du casino, contrôle son certificat, ` +
  `puis vérifie une preuve que la réponse n'a pas été modifiée. Seules mes lignes sont révélées.\n\n` +
  `Mon navigateur (vérificateur TLSNotary en WebAssembly) a déclaré la preuve valide. La page refuse la preuve si le ` +
  `serveur n'est pas le bon, si la période demandée au casino n'est pas celle affichée, ou si une ligne révélée ne ` +
  `m'appartient pas. Dans ce mode, le vérificateur est mon navigateur lui-même : il n'y a pas de fichier de preuve à ` +
  `faire contrôler ailleurs, et le fichier brut n'est pas partagé car il laisserait déduire la taille des champs ` +
  `masqués (dont la commission de l'agence).\n\n${FIELDS[CASINO] ? FIELDS[CASINO] + '\n\n' : ''}` +
  `${CASINO === 'celsius' ? 'FTD affiché = joueurs inscrits sur la période avec au moins un dépôt (dep_count > 0).' : 'Déposants affichés = joueurs avec au moins un dépôt sur la période.'}\n\n` +
  `Code public de la page : https://github.com/NetworkPartners/verification-tlsnotary (recette pour recompiler le ` +
  `vérificateur depuis la source officielle de TLSNotary, empreintes SHA-256 des fichiers servis par ` +
  `https://verif.networkpartners.xyz).\n\n` +
  `Limite connue, écrite par l'agence elle-même sur la page : la preuve garantit que les lignes affichées sont ` +
  `authentiques, pas que la liste est complète. Le casino renvoie en une seule réponse les joueurs de tous les ` +
  `créateurs de l'agence, sans filtre par créateur possible de son côté (testé) : le serveur de l'agence choisit les ` +
  `lignes à révéler, parce qu'elle ne peut pas divulguer les pseudos et les chiffres des joueurs de ses autres ` +
  `créateurs ; prouver qu'aucune ligne masquée n'est à moi obligerait à révéler les autres créateurs. ` +
  `Contrôle possible de mon côté : chaque joueur que je connais (un proche ou un ami inscrit avec mon lien) doit ` +
  `apparaître dans la liste.\n\n` +
  `Je ne te demande pas de valider mon contrat ni ma commission, seulement ce que cette vérification établit. ` +
  `Réponds simplement, en trois parties : 1. ce qui est prouvé mathématiquement ; 2. ce qui reste une affirmation ` +
  `de l'agence, et ce que je peux faire moi-même pour le contrôler ; 3. si les données ci-dessous sont cohérentes. ` +
  `Termine par ton avis sur cette vérification comparée à ce que les agences fournissent d'habitude, sans exagérer ` +
  `dans un sens ni dans l'autre.\n\nLa preuve :\n\n${proof}`
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
    d.compareLine,
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

// ── DOM helper: h('div', { class, onclick, … }, children…). Strings become text nodes, never HTML ──
function h(tag, attrs, ...kids) {
  const el = document.createElementNS(tag === 'svg' || tag === 'path' || tag === 'rect' || tag === 'circle' ? 'http://www.w3.org/2000/svg' : 'http://www.w3.org/1999/xhtml', tag)
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v)
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v)
    else el.setAttribute(k, v === true ? '' : String(v))
  }
  for (const kid of kids.flat(Infinity)) if (kid != null && kid !== false) el.append(kid instanceof Node ? kid : document.createTextNode(String(kid)))
  return el
}
const cx = (...a) => a.filter(Boolean).join(' ')
const NB = ' '
const fmtNum = (n, d = 0) => new Intl.NumberFormat('fr-FR', { minimumFractionDigits: d, maximumFractionDigits: d }).format(n).replace(/[  ]/g, NB)
const fmtEur = (n) => eur.format(n).replace(/[  ]/g, NB)
// Table cells: the € sign lives in the column header, so four amounts fit a phone width.
const amt = new Intl.NumberFormat('fr-FR', { minimumFractionDigits: 2, maximumFractionDigits: 2 })
const fmtAmt = (n) => amt.format(n).replace(/[  ]/g, NB)
const fmtMB = (b) => `${fmtNum(b / 1048576, 1)}${NB}Mo`
const fmtBytes = (b) => (b >= 1024 ? `${fmtNum(b / 1024, 1)}${NB}Ko` : `${b}${NB}octets`)
const fmtClock = (s) => { const t = Math.max(0, Math.floor(s)); return `${Math.floor(t / 60)}:${String(t % 60).padStart(2, '0')}` }
const hhmmss = (d = new Date()) => d.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' })

// ── Icons (same drawings as the design system) ───────────────────────────────────────────
const SHIELD = 'M12 3.25l7 2.9v5.35c0 4.3-2.9 7.95-7 9.25-4.1-1.3-7-4.95-7-9.25V6.15l7-2.9z'
const ICONS = {
  'shield-check': [['path', SHIELD], ['path', 'M8.75 12.1l2.3 2.3 4.2-4.45']],
  'shield-x': [['path', SHIELD], ['path', 'M9.75 9.75l4.5 4.5M14.25 9.75l-4.5 4.5']],
  lock: [['rect', 5, 10.5, 14, 10, 2.5], ['path', 'M8 10.5V8a4 4 0 0 1 8 0v2.5'], ['path', 'M12 14.75v1.75']],
  browser: [['rect', 3, 4.5, 18, 15, 2.5], ['path', 'M3 9h18'], ['path', 'M6.25 6.75h.01M8.75 6.75h.01']],
  server: [['rect', 4, 4, 16, 7, 2], ['rect', 4, 13, 16, 7, 2], ['path', 'M7.75 7.5h.01M7.75 16.5h.01M11.5 7.5h4.5M11.5 16.5h4.5']],
  check: [['path', 'M5 12.5l4.5 4.5L19 7.5']],
  x: [['path', 'M6.5 6.5l11 11M17.5 6.5l-11 11']],
  alert: [['path', 'M10.27 4.9L3.1 17.4a2 2 0 0 0 1.73 3h14.34a2 2 0 0 0 1.73-3L13.73 4.9a2 2 0 0 0-3.46 0z'], ['path', 'M12 9.75v4'], ['path', 'M12 17.1h.01']],
  info: [['circle', 12, 12, 9], ['path', 'M12 11v5'], ['path', 'M12 8h.01']],
  clock: [['circle', 12, 12, 9], ['path', 'M12 7.5V12l3 2']],
  copy: [['rect', 8.5, 8.5, 11.5, 11.5, 2], ['path', 'M15.5 8.5V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7.5a2 2 0 0 0 2 2h2.5']],
  code: [['path', 'M8.5 7.5L4 12l4.5 4.5M15.5 7.5L20 12l-4.5 4.5M13.5 5l-3 14']],
  'arrow-right': [['path', 'M5 12h14M13 6l6 6-6 6']],
  external: [['path', 'M14 4.5h5.5V10M19.5 4.5L11 13'], ['path', 'M17.5 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8.5a2 2 0 0 1 2-2h4']],
  eye: [['path', 'M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12z'], ['circle', 12, 12, 3]],
  'eye-off': [['path', 'M10.5 5.6A9.6 9.6 0 0 1 12 5.5c6 0 9.5 6.5 9.5 6.5a17.4 17.4 0 0 1-2.7 3.5M6.5 6.6C3.9 8.4 2.5 12 2.5 12S6 18.5 12 18.5c1.6 0 3.1-.5 4.4-1.2'], ['path', 'M3.5 3.5l17 17'], ['path', 'M9.9 9.9a3 3 0 0 0 4.2 4.2']],
  refresh: [['path', 'M19.5 11A7.5 7.5 0 0 0 6.2 6.9L4.5 8.5'], ['path', 'M4.5 4.5v4h4'], ['path', 'M4.5 13a7.5 7.5 0 0 0 13.3 4.1l1.7-1.6'], ['path', 'M19.5 19.5v-4h-4']],
  help: [['circle', 12, 12, 9], ['path', 'M9.6 9.4a2.5 2.5 0 1 1 3.4 2.4c-.6.3-1 .8-1 1.5v.5'], ['path', 'M12 16.9h.01']],
}
function Icon(name, size = 20, sw = 1.75, cls) {
  const parts = (ICONS[name] || ICONS.info).map((p) => p[0] === 'path' ? h('path', { d: p[1] })
    : p[0] === 'rect' ? h('rect', { x: p[1], y: p[2], width: p[3], height: p[4], rx: p[5] }) : h('circle', { cx: p[1], cy: p[2], r: p[3] }))
  return h('svg', { class: cx('np-icon', cls), viewBox: '0 0 24 24', width: size, height: size, fill: 'none', stroke: 'currentColor', 'stroke-width': sw, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' }, parts)
}

// ── Components ────────────────────────────────────────────────────────────────────────────
function Button({ variant = 'primary', size, icon, iconAfter, href, onclick, label }) {
  const s = size === 'lg' ? 22 : 18
  const body = [icon && Icon(icon, s), h('span', null, label), iconAfter && Icon(iconAfter, s, 1.75, 'np-btn__after')]
  const cls = cx('np-btn', 'np-btn--' + variant, size === 'lg' && 'np-btn--lg')
  return href ? h('a', { class: cls, href, target: '_blank', rel: 'noopener noreferrer' }, body) : h('button', { type: 'button', class: cls, onclick }, body)
}
const Card = (title, cls, ...kids) => h('section', { class: cx('np-card', cls) }, title && h('div', { class: 'np-card__head' }, h('h3', { class: 'np-card__title' }, title)), kids)

// The route: casino → encrypted connection → your browser. stage 1 browser, 2 connection, 3 casino.
function ProofPath({ status = 'idle', stage = 0, size = 'lg' }) {
  const running = status === 'running', c = status === 'done' || status === 'refused' ? 3 : running ? stage : 0
  const st = (f) => status === 'refused' ? (f === 2 ? 'error' : 'off') : c >= f ? (running && c === f ? 'active' : 'on') : 'off'
  const link = (f) => status === 'refused' ? 'error' : c >= f ? (running && c === f ? 'active' : 'on') : 'off'
  const isz = size === 'lg' ? 26 : 20
  const node = (s, icon, label, sub) => h('div', { class: cx('np-path__node', 'is-' + s) },
    h('div', { class: 'np-path__dot' }, Icon(s === 'error' ? 'x' : icon, isz),
      s === 'on' && (status === 'done' || running) && h('span', { class: 'np-path__badge' }, Icon('check', size === 'lg' ? 12 : 10, 2.5))),
    h('div', { class: 'np-path__label' }, label), h('div', { class: 'np-path__sub' }, sub))
  return h('div', { class: cx('np-path', 'np-path--' + size, 'np-path--' + status), role: 'img', 'aria-label': `Trajet : ton navigateur, connexion chiffrée, ${NAME} (${HOST}).` },
    node(st(1), 'browser', 'Ton navigateur', status === 'done' ? 'a tout vérifié' : 'vérifie la preuve'),
    h('div', { class: cx('np-path__link', 'is-' + link(2)) }, h('span', { class: 'np-path__flow' })),
    node(st(2), 'lock', 'Connexion chiffrée', status === 'refused' ? 'preuve refusée' : 'TLS'),
    h('div', { class: cx('np-path__link', 'is-' + link(3)) }, h('span', { class: 'np-path__flow' })),
    node(st(3), 'server', NAMES[CASINO] || 'Le casino', HOST))
}
function StepList(steps, current, failedAt, meter) {
  return h('ol', { class: 'np-steps' }, steps.map((s, i) => {
    const state = failedAt === i ? 'failed' : i < current ? 'done' : i === current ? 'active' : 'pending'
    return h('li', { class: cx('np-steps__item', 'is-' + state), 'aria-current': state === 'active' ? 'step' : null },
      h('span', { class: 'np-steps__mark', 'aria-hidden': 'true' }, state === 'done' ? Icon('check', 14, 2.5) : state === 'failed' ? Icon('x', 14, 2.5)
        : state === 'active' ? h('span', { class: 'np-steps__spin' }) : String(i + 1)),
      h('div', { class: 'np-steps__body' }, h('div', { class: 'np-steps__title' }, s.title),
        (state === 'active' || state === 'failed') && s.detail && h('div', { class: 'np-steps__detail' }, state === 'failed' && s.error ? s.error : s.detail),
        state === 'active' && meter && h('div', { class: 'np-steps__meter' },
          h('div', { class: 'np-steps__meter-track' }, h('div', { class: 'np-steps__meter-bar', id: 'meterBar', style: { width: '0%' } })),
          h('span', { class: 'np-steps__meter-value', id: 'meterValue' }, fmtMB(0)),
          h('span', { class: 'np-steps__meter-cap' }, 'Échangés avec notre serveur de preuve'))))
  }))
}
function Progress() {
  return h('div', { class: 'np-progress' },
    h('div', { class: 'np-progress__row' }, h('span', { class: 'np-progress__label', id: 'progLabel' }, 'Étape 1 sur 5'),
      h('span', { class: 'np-progress__clock' }, Icon('clock', 16), h('span', { id: 'progClock' }, '0:00'))),
    h('div', { class: 'np-progress__track', role: 'progressbar', 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-label': 'Progression de la vérification' },
      h('div', { class: 'np-progress__bar', id: 'progBar', style: { width: '3%' } })))
}
function Verdict(tone, title, text) {
  return h('div', { class: cx('np-verdict', 'np-verdict--' + tone), role: 'status' },
    h('span', { class: 'np-verdict__icon' }, Icon(tone === 'gap' ? 'alert' : 'shield-check', 28)),
    h('div', { class: 'np-verdict__body' }, h('h2', { class: 'np-verdict__title' }, title),
      h('div', { class: 'np-verdict__meta' },
        h('span', { class: 'np-verdict__server' }, Icon('lock', 14), h('span', { class: 'np-verdict__server-k' }, 'Serveur prouvé'), h('span', { class: 'np-verdict__server-v' }, HOST)),
        text && h('span', { class: 'np-verdict__text' }, text))))
}
const KeyFigure = (label, value, hint) => h('div', { class: 'np-figure' }, h('div', { class: 'np-figure__label' }, label), h('div', { class: 'np-figure__value' }, value), hint && h('div', { class: 'np-figure__hint' }, hint))
const PILL = { same: ['check', 'identique'], gap: ['alert', 'écart'], absent: ['alert', 'absent'], pending: ['clock', 'indisponible'] }
const StatusPill = (status) => { const [i, w] = PILL[status]; return h('span', { class: cx('np-pill', 'np-pill--' + (status === 'absent' ? 'gap' : status)) }, Icon(i, 14, 2.25), h('span', { class: 'np-pill__word' }, w)) }
const Guarantee = (icon, title, text) => h('div', { class: 'np-guarantee' }, h('span', { class: 'np-guarantee__icon' }, Icon(icon, 18)), h('div', null, h('div', { class: 'np-guarantee__title' }, title), h('div', { class: 'np-guarantee__text' }, text)))
const FactList = (items) => h('dl', { class: 'np-facts' }, items.map((it) => h('div', { class: 'np-facts__row' }, h('dt', null, it.label), h('dd', { class: it.mono ? 'is-mono' : null }, it.value))))
function Journal() {
  return h('ol', { class: 'np-journal', tabindex: 0, 'aria-label': 'Journal de la vérification' }, logs.map((l) => h('li', { class: 'is-' + l.status },
    h('time', null, l.t), h('span', { class: 'np-journal__mark', 'aria-hidden': 'true' }, l.status === 'ok' ? Icon('check', 12, 2.5) : l.status === 'error' ? Icon('x', 12, 2.5) : h('span', { class: 'np-journal__dot' })),
    h('span', { class: 'np-journal__text' }, l.text))))
}
function StateMessage(tone, title, text, actions) {
  return h('div', { class: cx('np-state', 'np-state--' + tone), role: tone === 'refused' ? 'alert' : 'status' },
    h('span', { class: 'np-state__icon' }, Icon(tone === 'refused' ? 'shield-x' : tone === 'failed' ? 'refresh' : 'info', 30)),
    h('h2', { class: 'np-state__title' }, title), text && h('div', { class: 'np-state__text' }, text),
    actions && h('div', { class: 'np-state__action' }, actions))
}

// Raw proof: the casino's answer as received. Proven rows in clear (green dot), masked parts as chips.
function jsonTokens(text) {
  const out = [], re = /("(?:[^"\\]|\\.)*")(\s*:)?|(-?\d+(?:\.\d+)?)/g
  let last = 0, m
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(text.slice(last, m.index))
    if (m[1] && m[2]) out.push(h('span', { class: 'np-raw__k' }, m[1]), m[2])
    else if (m[1]) out.push(h('span', { class: 'np-raw__s' }, m[1]))
    else out.push(h('span', { class: 'np-raw__n' }, m[3]))
    last = re.lastIndex
  }
  if (last < text.length) out.push(text.slice(last))
  return out
}
function RawProof(body) {
  const lines = []
  for (const part of body.split(/(\u0000+)/)) {
    if (!part) continue
    if (part[0] === '\u0000') {
      // A short masked run gets no size: its length must not hint at what it hides.
      lines.push({ masked: part.length < 200 ? 'masqué' : `${fmtBytes(part.length)} masqués` })
      continue
    }
    for (const seg of part.split(/(\{[^{}]*\})/)) {
      if (!seg || /^[\s,\[\]]*$/.test(seg)) continue
      lines.push(/^\{[^{}]*\}$/.test(seg) ? { mine: true, text: seg } : { text: seg.trim() })
    }
  }
  return h('div', { class: 'np-raw', tabindex: 0, 'aria-label': 'Réponse brute du casino', style: { maxHeight: '320px' } }, lines.map((l) => l.masked
    ? h('div', { class: 'np-raw__line is-masked' }, h('span', { class: 'np-raw__gut' }), h('span', { class: 'np-raw__mask' }, Icon('eye-off', 13), l.masked))
    : h('div', { class: cx('np-raw__line', l.mine && 'is-mine') }, h('span', { class: 'np-raw__gut' }, l.mine && h('span', { class: 'np-sr' }, 'Ta ligne : ')), h('code', null, jsonTokens(l.text)))))
}

// ── The steps, as the creator reads them while the worker runs ────────────────────────────
// Each one is a real event of the TLSNotary worker, never a timed animation.
const WORKER_STEPS = ['Chargement du vérificateur TLSNotary', 'Connexion au prouveur', 'Préparation du calcul partagé',
  'Connexion chiffrée au serveur du casino et réception de la réponse', 'Vérification de la preuve']
const STEPS = [
  { title: 'Ton navigateur charge TLSNotary', detail: 'Le programme de vérification, open source, se lance dans cet onglet. Rien à installer.', log: 'Moteur TLSNotary chargé dans ton navigateur' },
  { title: 'Connexion à notre serveur de preuve', detail: 'Il va faire le calcul avec ton navigateur, à deux.', log: 'Connecté au serveur de preuve' },
  { title: 'Calcul partagé en cours', detail: 'Ton navigateur et notre serveur fabriquent ensemble la clé de la connexion : aucun des deux ne la détient seul. C’est l’étape la plus longue.', log: null },
  { title: `Connexion à ${HOST || 'au casino'}`, detail: 'Ton navigateur contrôle le certificat du site, comme le cadenas de ta barre d’adresse.', log: `Réponse de ${HOST || 'du casino'} reçue et authentifiée` },
  { title: 'Vérification de la preuve', detail: `Ton navigateur vérifie que chaque chiffre est exactement celui envoyé par ${NAME}.`, log: 'Preuve cryptographique vérifiée' },
]
let traffic = { sent: 0, recv: 0 }
let cur = -1, t0 = 0, clockTimer = null
const logs = []
function logLine(text, status = 'info') { logs.push({ t: hhmmss(), text, status }) }
const stageOf = (i) => (i <= 1 ? 1 : i === 2 ? 2 : 3)
function progressValue() {
  if (cur < 2) return 0.05 + cur * 0.05
  if (cur === 2) return 0.15 + 0.55 * Math.min(1, (traffic.sent + traffic.recv) / 63e6)
  return cur === 3 ? 0.78 : 0.9
}
// The bar is drawn every frame: it eases toward the real progress and, inside a step, creeps toward
// that step's ceiling, so it never jumps nor freezes between two worker events.
const STEP_CEIL = [0.10, 0.15, 0.70, 0.88, 0.97]
let shown = 0, lastFrame = 0, drawing = false
function drawProgress(now) {
  const bar = $('progBar')
  if (!bar) { lastFrame = 0; drawing = false; return }
  const dt = lastFrame ? Math.min(0.1, (now - lastFrame) / 1000) : 0
  lastFrame = now
  const floor = progressValue(), ceil = Math.max(floor, STEP_CEIL[Math.min(cur, STEP_CEIL.length - 1)] ?? floor)
  if (shown < floor) shown += (floor - shown) * Math.min(1, dt * 3)
  else shown += (ceil - shown) * (1 - Math.exp(-dt / 8))
  bar.style.width = `${(shown * 100).toFixed(2)}%`
  requestAnimationFrame(drawProgress)
}
function updateProgress() {
  if (!$('progBar')) return
  if (!drawing) { drawing = true; requestAnimationFrame(drawProgress) }
  $('progLabel').textContent = `Étape ${Math.max(1, cur + 1)} sur ${STEPS.length}`
  const mb = traffic.sent + traffic.recv
  if ($('meterValue')) { $('meterValue').textContent = fmtMB(mb); $('meterBar').style.width = `${Math.min(100, (mb / 63e6) * 100)}%` }
}
// The running screen is built ONCE; each step only swaps the route and the step list in place.
// Rebuilding the whole screen replayed its entrance animation and flashed black at every step.
function renderRun(failedAt, error) {
  if (failedAt != null) STEPS[failedAt].error = error
  const status = failedAt != null ? 'refused' : 'running'
  if (!$('runPath')) {
    view(h('div', { class: 'vs-center' },
      h('h1', { class: 'vs-title vs-title--run', id: 'runTitle' }, 'Vérification en cours'),
      h('p', { class: 'vs-lead', id: 'runLead', style: { marginTop: '8px' } }, 'Laisse cet onglet ouvert, ça prend une vingtaine de secondes.'),
      h('div', { class: 'vs-path', id: 'runPath' }),
      h('div', { class: 'vs-run' }, Card(null, null, Progress(), h('div', { id: 'runSteps' })))))
  }
  if (failedAt != null) { $('runTitle').textContent = 'Vérification interrompue'; $('runLead').textContent = error }
  const stage = stageOf(Math.max(0, cur))
  if ($('runPath').dataset.k !== status + stage) {
    $('runPath').dataset.k = status + stage
    $('runPath').replaceChildren(ProofPath({ status, stage }))
  }
  $('runSteps').replaceChildren(StepList(STEPS, cur, failedAt, cur === 2))
  updateProgress()
}
function onStep(label) { const i = WORKER_STEPS.indexOf(label); if (i < 0) return; cur = i; renderRun() }
function onDone(label) {
  const i = WORKER_STEPS.indexOf(label); if (i < 0) return
  logLine(i === 2 ? `Calcul partagé terminé : ${fmtMB(traffic.sent + traffic.recv)} échangés` : STEPS[i].log, 'ok')
}
function onTraffic(m) { traffic = m; updateProgress() }

// ── Screens ───────────────────────────────────────────────────────────────────────────────
const main = $('main')
// dock: phone-only bar fixed at the bottom; kept outside the animated view, whose transform would trap it
function view(node, dock) { main.replaceChildren(node); $('dock').replaceChildren(...(dock ? [dock] : [])) }
const DASHBOARD = 'https://dashboard.networkpartners.xyz'
const REPO = 'https://github.com/NetworkPartners/verification-tlsnotary'

function renderBefore() {
  const bad = (!T || !S || !HOST || !FILTER || !FROM || !TO) && !DEMO
  if (bad) return renderState('failed', 'Ce lien est incomplet', 'Relance la vérification depuis ton dashboard.')
  view(h('div', { class: 'vs-center' },
    h('h1', { class: 'vs-title' }, `Vérifie tes chiffres ${NAME}${PERIOD_PHRASE}`),
    h('p', { class: 'vs-lead' }, `Ton navigateur va chercher tes chiffres directement chez ${NAME} et vérifie que personne n’y a touché. Tu n’as pas besoin de nous croire sur parole.`),
    h('div', { class: 'vs-path' }, ProofPath({ status: 'idle' })),
    h('div', { class: 'vs-cta' }, Button({ size: 'lg', iconAfter: 'arrow-right', label: 'Lancer la vérification', onclick: start })),
    h('div', { class: 'vs-trust' },
      h('a', { href: REPO, target: '_blank', rel: 'noopener noreferrer' }, Icon('code', 15), 'Code public sur GitHub'))))
}

function renderState(tone, title, text, extra) {
  const actions = tone === 'failed'
    ? [Button({ label: 'Retour au dashboard', iconAfter: 'arrow-right', href: DASHBOARD })]
    : tone === 'refused'
      ? [Button({ variant: 'secondary', icon: 'eye', label: 'Voir le journal', onclick: () => openSheet('did') }), Button({ variant: 'ghost', icon: 'help', label: 'Comment ça marche ?', onclick: () => openSheet('how') })]
      : [Button({ variant: 'secondary', icon: 'eye', label: 'Voir la preuve', onclick: () => openSheet('sent') })]
  view(h('div', { class: 'vs-state' }, extra, StateMessage(tone, title, text, actions)))
}

function ComparisonTable(ps, expected) {
  const rows = expected ? compare(ps, expected) : ps.map((p) => ({ ...p, dash: null, same: false }))
  const withNgr = rows.some((r) => r.ngr != null)
  const status = (r) => (!expected ? 'pending' : !r.dash ? 'absent' : r.same ? 'same' : 'gap')
  const gaps = expected ? rows.filter((r) => !r.same).length : 0
  const n = rows.length
  const summary = !expected ? 'Les chiffres du dashboard n’ont pas pu être chargés.'
    : gaps === 0 ? (n === 1 ? 'Ton joueur a les mêmes chiffres des deux côtés.' : `Les ${n} joueurs ont les mêmes chiffres des deux côtés.`)
      : `${gaps} ${gaps > 1 ? 'joueurs' : 'joueur'} sur ${n} ${gaps > 1 ? 'ont' : 'a'} un écart entre ton dashboard et ${NAME}.`
  const synced = expected?._meta?.synced ? new Date(expected._meta.synced) : null
  const ago = synced && !Number.isNaN(synced.getTime()) ? Math.max(0, Date.now() - synced.getTime()) : null
  const agoText = ago == null ? null : ago < 3600e3 ? `il y a ${Math.max(1, Math.round(ago / 60e3))}${NB}min` : `il y a ${Math.round(ago / 3600e3)}${NB}h`
  // One column for the casino's proven figure, one for the dashboard's, side by side.
  const pair = (v, d, r) => [
    h('td', { class: 'np-compare__num' }, v == null ? '' : fmtAmt(v)),
    h('td', { class: cx('np-compare__num', 'np-compare__dashcol', expected && r.dash && v != null && cents(d) !== cents(v) && 'is-gap') },
      !expected ? '' : !r.dash ? 'absent' : v == null ? '' : fmtAmt(d))]
  const sorted = [...rows].sort((a, b) => Number(a.same) - Number(b.same) || b.deposits - a.deposits)
  return { gaps, node: h('section', { class: 'np-compare' },
    h('div', { class: 'np-compare__head' }, h('h3', { class: 'np-compare__title' }, `Ton dashboard comparé à ${NAME}`), h('span', { class: 'np-compare__count' }, `${fmtNum(n)} ${n > 1 ? 'joueurs' : 'joueur'}`)),
    h('div', { class: 'np-compare__scroll', tabindex: 0, 'aria-label': `Comparaison joueur par joueur, ${n} lignes` },
      h('table', { class: 'np-compare__table' },
        h('thead', null,
          h('tr', null, h('th', { scope: 'col', rowspan: 2 }, 'Joueur'),
            h('th', { scope: 'colgroup', colspan: 2, class: 'np-compare__group' }, `Dépôts${NB}€`),
            withNgr && h('th', { scope: 'colgroup', colspan: 2, class: 'np-compare__group' }, `NGR${NB}€`)),
          h('tr', null, ...Array.from({ length: withNgr ? 2 : 1 }, () => [
            h('th', { scope: 'col', class: 'np-compare__num np-compare__sub' }, NAME),
            h('th', { scope: 'col', class: 'np-compare__num np-compare__sub' }, h('span', { class: 'vs-long' }, 'Dashboard'), h('span', { class: 'vs-short' }, 'Dash'))]).flat())),
        h('tbody', null, sorted.map((r) => h('tr', null, h('th', { scope: 'row', class: 'np-compare__player', title: r.who, onclick: (e) => e.currentTarget.classList.toggle('is-open') }, h('span', { class: 'np-compare__mark' }, StatusPill(status(r))), h('span', { class: 'np-compare__name' }, r.who)),
          ...pair(r.deposits, r.dash?.deposits, r),
          ...(withNgr ? pair(r.ngr, r.dash?.ngr, r) : [])))))),
    gaps > 0 && h('div', { class: 'np-note' }, Icon('info', 18),
      h('div', null, h('b', null, 'D\u2019où peut venir un écart ?'),
        ` Ton dashboard se synchronise avec ${NAME} toutes les 3${NB}h${agoText ? ` (dernière fois ${agoText})` : ''}. ` +
        `Un joueur qui a joué ou déposé depuis a déjà bougé chez ${NAME} : c\u2019est surtout le NGR, qui change à chaque mise. ` +
        `Si l\u2019écart est toujours là après la prochaine synchronisation, signale-le nous : c\u2019est le chiffre de ${NAME}, prouvé ci-dessus, qui fait foi.`)),
    h('div', { class: 'np-compare__foot' },
      h('span', { class: cx('np-compare__summary', gaps || !expected ? 'is-gap' : 'is-same') }, Icon(gaps || !expected ? 'alert' : 'check', 16, 2.25), summary),
      agoText && !gaps && h('span', { class: 'np-compare__updated' }, `Dernière mise à jour du dashboard avec ${NAME}${NB}: ${agoText} (toutes les 3${NB}heures)`))) }
}

function renderResult(v, ps, expected) {
  const hasNgr = ps.some((p) => p.ngr != null)
  const totalDep = ps.reduce((a, p) => a + p.deposits, 0)
  const totalCount = ps.reduce((a, p) => a + p.count, 0)
  const totalNgr = ps.reduce((a, p) => a + (p.ngr ?? 0), 0)
  const depositors = ps.filter((p) => p.count > 0 || p.deposits > 0).length
  const cmp = ComparisonTable(ps, expected)
  const at = v.when ? v.when.toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit' }) : hhmmss().slice(0, 5)
  const verdict = cmp.gaps
    ? Verdict('gap', `Tes chiffres ${NAME} sont prouvés, ton dashboard diffère sur ${cmp.gaps} joueur${cmp.gaps > 1 ? 's' : ''}`,
      `Le détail est dans le tableau : pour chaque joueur, la colonne ${NAME} et la colonne Dashboard côte à côte.`)
    : Verdict('confirmed', `Tes chiffres ${NAME}${PERIOD_PHRASE} sont confirmés`, `Vérifié par ton navigateur à ${at}`)
  view(h('div', { class: 'vs-result' },
    Card(null, 'vs-zone', verdict,
      h('div', { class: 'np-figures' },
        KeyFigure('Joueurs', fmtNum(ps.length), CASINO === 'celsius' ? 'inscrits sur la période' : 'actifs sur la période'),
        CASINO === 'celsius' ? KeyFigure('FTD', fmtNum(depositors), 'premiers dépôts') : KeyFigure('Déposants', fmtNum(depositors), 'sur la période'),
        KeyFigure('Déposés', fmtEur(totalDep)),
        hasNgr ? KeyFigure('NGR', fmtEur(totalNgr), 'base de ta commission') : KeyFigure('Dépôts', fmtNum(totalCount))),
      cmp.node),
    h('aside', { class: 'np-card vs-aside' },
      h('div', { class: 'np-card__head' }, h('h3', { class: 'np-card__title' }, 'Pourquoi tu peux y croire')),
      ProofPath({ status: 'done', size: 'sm' }),
      h('div', { class: 'vs-guarantees' },
        Guarantee('shield-check', `Ça vient bien de ${NAME}`, `Le certificat de ${HOST} a été contrôlé, comme le cadenas de ta barre d’adresse.`),
        Guarantee('browser', 'C’est ton navigateur qui a vérifié', 'Avec TLSNotary, un outil open source de la Fondation Ethereum.'),
        Guarantee('lock', 'Rien n’a été modifié', 'Un seul chiffre changé, et la vérification échoue.')),
      h('div', { class: 'vs-actions' },
        Button({ icon: 'eye', label: 'Voir la preuve', onclick: () => openSheet('sent') }),
        Button({ variant: 'secondary', icon: 'help', label: 'Comment ça marche ?', onclick: () => openSheet('how') })))),
    Button({ icon: 'eye', label: 'Voir la preuve', onclick: () => openSheet('sent') }))
}

// ── After the worker: check the proof, then show the result (or why it is refused) ───────────
let last = null
async function showResult(v) {
  const ps = v.rows.map(player)
  const ok = v.problems.length === 0
  last = v
  logLine(`Certificat de ${v.server} vérifié${v.tls ? `, connexion ${v.tls}` : ''}`, 'ok')
  logLine(`Réponse du casino : ${fmtBytes(v.recvLen)}, dont ${fmtBytes(v.recvProved)} révélés, le reste masqué`)
  logLine(ok ? `Preuve valide : ${ps.length} joueur${ps.length > 1 ? 's' : ''}, rien n’a été modifié` : `Preuve refusée : ${v.problems.join(' ; ')}`, ok ? 'ok' : 'error')
  prepareShare(v, ps)
  if (!ok) {
    return renderState('refused', 'La preuve ne passe pas le contrôle',
      [`Ton navigateur n’a pas pu confirmer ces chiffres (${v.problems.join(' ; ')}). `, h('strong', null, 'Ne prends pas ces chiffres en compte'), ' et préviens ton contact Network Partners.'],
      ProofPath({ status: 'refused', size: 'sm' }))
  }
  if (!ps.length) {
    return renderState('empty', `Aucun joueur${PERIOD_PHRASE}`,
      `${NAME} confirme qu’aucun joueur n’est rattaché à ton lien sur cette période. La preuve est valide : il n’y a simplement rien à afficher.`)
  }
  const expected = await loadExpected()
  if (expected) {
    const rows = compare(ps, expected), same = rows.filter((r) => r.same).length, missing = rows.filter((r) => !r.dash).length
    askData.compareLine = `Comparaison avec mon dashboard (ses chiffres ont été figés avant la preuve) : ${same} joueur(s) sur ${rows.length} identiques au centime` +
      `${rows.length - same - missing ? `, ${rows.length - same - missing} avec un écart` : ''}${missing ? `, ${missing} absent(s) du dashboard` : ''}.`
  }
  renderResult(v, ps, expected)
}
function showFailure(message) {
  logLine(`Arrêt : ${message}`, 'error')
  console.error(message)
  const expired = /ticket|expired|invalid|incomplet/i.test(message)
  if (expired) return renderState('failed', 'Ce lien a expiré', 'Chaque lien de vérification ne sert qu’une fois. Ce n’est pas un problème avec tes chiffres : relance la vérification depuis ton dashboard.')
  renderRun(Math.max(0, cur), 'La vérification n’a pas pu aller au bout. Relance-la depuis ton dashboard ; si ça se reproduit, préviens-nous.')
}

// Plain-text proof (copy button) and its compact form (AI link). Same masking as the screen:
// our commission is never in it.
function prepareShare(v, ps) {
  const totalDep = ps.reduce((a, p) => a + p.deposits, 0)
  const hasNgr = ps.some((p) => p.ngr != null)
  const totalNgr = ps.reduce((a, p) => a + (p.ngr ?? 0), 0)
  const depositors = ps.filter((p) => p.count > 0 || p.deposits > 0).length
  const depLabel = CASINO === 'celsius' ? 'FTD' : 'déposant(s)'
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
  const masked = (v.body.match(/\u0000+/g) || [])
  askData = {
    head: proofText.split('\n').slice(0, 7).join('\n'),
    prefix: CASINO === 'celsius' ? FILTER.replace('"campaign_name":"', '') : '',
    maskedLine: `Parties masquées par la preuve : ${masked.length} blocs, ${fmtBytes(masked.reduce((n, m) => n + m.length, 0))} au total. ` +
      `Selon l'agence, ce sont les lignes des joueurs de ses autres créateurs, l'enveloppe de la réponse et, dans mes lignes, ` +
      `${CASINO === 'celsius' ? "le champ income (sa commission), le nom de l'offre et la fin du nom de campagne (qui portent son accord avec le casino)" : 'le champ Commissions (sa commission)'}. ` +
      `La preuve ne permet pas de vérifier ce que contient un bloc masqué.`,
    rows: [...v.body.matchAll(/\{[^{}\u0000]*\}/g)].map((m) => {
      try { const o = JSON.parse(m[0]); delete o.campaign_name; return o } catch { return null }
    }).filter(Boolean).sort((a, b) => num(b.dep_sum ?? b.Net_Deposits ?? b.Deposits) - num(a.dep_sum ?? a.Net_Deposits ?? a.Deposits)),
  }
}

// ── The proof sheet ───────────────────────────────────────────────────────────────────────
const TABS = [['sent', 'Ce que le casino a envoyé', 'La réponse'], ['did', 'Ce que ton navigateur a fait', 'Le journal'], ['how', 'Comment ça marche', 'Comment ça marche']]
function sheetBody(tab) {
  const v = last
  if (tab === 'sent') {
    if (!v) return h('p', { class: 'vs-hint' }, 'La preuve apparaîtra ici une fois la vérification terminée.')
    return h('div', null,
      h('div', { class: 'vs-h3' }, 'Ce qui a été prouvé'),
      FactList([
        { label: 'Serveur', value: `${v.server}, certificat vérifié par ton navigateur`, mono: false },
        { label: 'Version TLS', value: v.tls || 'TLS' },
        { label: 'Date', value: v.when ? v.when.toLocaleString('fr-FR') : '?' },
        { label: 'Période', value: `du ${frDate(FROM)} au ${frDate(TO)}` },
        { label: 'Requête prouvée', value: (v.sent.split('\r\n')[0] || '').replace(/\u0000+/g, '[masqué]'), mono: true },
        { label: 'Réponse', value: `${fmtBytes(v.recvLen)}, dont ${fmtBytes(v.recvProved)} révélés` },
        { label: 'Calcul partagé', value: `${fmtMB(traffic.sent + traffic.recv)} échangés par ton navigateur` },
      ]),
      h('div', { class: 'vs-h3' }, `Réponse brute de ${NAME}`),
      RawProof(v.body),
      h('p', { class: 'vs-hint' }, 'Les lignes avec un point vert sont les tiennes, prouvées. Les blocs grisés sont masqués : les joueurs de nos autres créateurs (le casino renvoie tout notre compte d’un coup) et, dans tes lignes, notre commission, le nom de l\u2019offre et la fin du nom de campagne, qui portent notre accord avec le casino. La preuve ne laisse voir le contenu d’aucun bloc masqué.'),
      h('div', { class: 'vs-tools' },
        Button({ variant: 'secondary', icon: 'copy', label: 'Copier la preuve', onclick: async () => toast(await copy(proofText) ? 'Preuve copiée' : 'Copie impossible dans ce navigateur') }),
        Button({ variant: 'ghost', iconAfter: 'external', label: 'Demander à ChatGPT', onclick: () => ask('chatgpt') }),
        Button({ variant: 'ghost', iconAfter: 'external', label: 'Demander à Claude', onclick: () => ask('claude') })))
  }
  if (tab === 'did') return h('div', { style: { marginTop: 'var(--space-6)' } }, Journal(),
    h('p', { class: 'vs-hint' }, 'Chaque ligne est un événement réel du vérificateur, horodaté par ton navigateur.'))
  return h('div', { class: 'vs-prose' },
    h('p', null, `Quand tu ouvres le site de ${NAME}, la connexion est chiffrée : c’est le cadenas dans ta barre d’adresse. Ici, `,
      h('strong', null, 'ton navigateur participe lui-même à cette connexion'), ' avec notre serveur de preuve. Aucun des deux ne détient seul la clé, donc aucun des deux ne peut fabriquer une réponse.'),
    h('p', null, `Ton navigateur contrôle aussi le certificat de ${HOST}, puis vérifie une preuve mathématique : les chiffres affichés sont exactement ceux envoyés par ${NAME}. Un seul chiffre modifié, et la vérification échoue.`),
    h('p', null, 'Seules tes lignes sont révélées. Les autres créateurs et notre commission restent masqués par la preuve elle-même.'),
    h('h3', null, 'Les limites, honnêtement'),
    h('p', null, `La preuve garantit que ces chiffres sont ceux que ${HOST} a envoyés, à ce moment-là, pour la requête affichée. Elle ne dit pas si les calculs internes de ${NAME} sont justes : pour ça, seul ${NAME} peut répondre.`),
    h('p', null, 'Elle garantit que chaque ligne affichée est authentique, pas que la liste est complète. Le site du casino nous renvoie tous les joueurs de tous nos créateurs d’un coup, sans pouvoir filtrer par créateur : c’est notre serveur qui choisit quelles lignes révéler. On ne peut pas faire autrement sans te montrer les pseudos et les chiffres des joueurs de nos autres créateurs, qui doivent rester confidentiels. Pour le vérifier toi-même : demande à un proche ou un ami de s’inscrire avec ton lien et de faire un dépôt, puis relance une vérification ; son compte doit apparaître dans la liste.'),
    h('p', null, 'La technologie s’appelle TLSNotary. Elle est open source et développée au sein de la Fondation Ethereum. Le code de cette page est public, avec de quoi vérifier que c’est exactement lui qui tourne ici.'),
    Button({ variant: 'secondary', icon: 'code', iconAfter: 'external', label: 'Voir le code sur GitHub', href: REPO }))
}
let sheetTab = null
function openSheet(tab) {
  sheetTab = tab
  $('sheet').hidden = false
  document.body.classList.add('is-sheet-open')
  $('sheetTabs').replaceChildren(...TABS.map(([id, label, short]) => h('button', { type: 'button', role: 'tab', 'aria-selected': String(id === tab), tabindex: id === tab ? 0 : -1,
    class: cx('np-tabs__tab', id === tab && 'is-active'), onclick: () => openSheet(id) },
    h('span', { class: 'vs-long' }, label), h('span', { class: 'vs-short' }, short))))
  $('sheetBody').replaceChildren(sheetBody(tab))
  $('sheetPanel').focus()
}
function closeSheet() { $('sheet').hidden = true; document.body.classList.remove('is-sheet-open'); sheetTab = null }
$('sheetClose').onclick = closeSheet
$('sheetScrim').onclick = closeSheet
addEventListener('keydown', (e) => { if (e.key === 'Escape' && sheetTab) closeSheet() })
$('sheetSub').textContent = `Tes chiffres ${NAME}${PERIOD_PHRASE}, tels que ${NAME} les a envoyés.`
async function ask(which) {
  window.open(ASK[which](askMessage()), '_blank', 'noopener')
  toast('Conversation ouverte avec la preuve')
}

// ── Run ───────────────────────────────────────────────────────────────────────────────────
function start() {
  t0 = performance.now(); shown = 0
  cur = 0
  renderRun()
  clockTimer = setInterval(() => { if ($('progClock')) $('progClock').textContent = fmtClock((performance.now() - t0) / 1000) }, 250)
  const stop = () => clearInterval(clockTimer)
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

// Local design review (localhost only): ?demo plays the flow with sample rows; ?demo=ok has no gap,
// ?demo=refused, ?demo=empty, ?demo=failed show those states.
const DEMO_EXPECTED = { 188209: { dep: 50, ngr: 196.36, depp: 50 }, 188150: { dep: 0, ngr: 0, depp: 0 }, 190012: { dep: 20, ngr: 12.4, depp: 20 }, _meta: { synced: new Date(Date.now() - 7 * 60e3).toISOString() } }
function demo(stop) {
  const mode = qs.get('demo')
  let i = 0
  const next = () => {
    if (i > 0) onDone(WORKER_STEPS[i - 1])
    if (mode === 'failed' && i === 3) { stop(); return showFailure('Connexion chiffrée au serveur du casino : délai dépassé') }
    if (i === WORKER_STEPS.length) {
      stop()
      if (mode === 'ok') DEMO_EXPECTED[190012].dep = 45
      const M = (n) => '\u0000'.repeat(n)
      const rows = mode === 'empty' ? [] : [
        { referral_id: 188209, username: 'Majron', dep_count: 1, dep_sum: '50.00', ngr: '196.35618' },
        { referral_id: 188150, username: 'miro151', dep_count: 0, dep_sum: 0, ngr: '0' },
        { referral_id: 190012, username: 'User908649', dep_count: 2, dep_sum: '45.00', ngr: '12.40' }]
      return showResult({ problems: mode === 'refused' ? ['une ligne reçue ne t\'appartient pas'] : [], server: HOST || 'celsiuspartner.com', when: new Date(),
        sent: 'GET /api/get-referral-activity?start_date=2026-09-01&end_date=2026-09-30 HTTP/1.0', tls: 'TLS 1.2', recvLen: 17284, recvProved: 1180,
        body: '{"status":"success","data":[' + M(900) + rows.map((r) => JSON.stringify({ ...r, campaign_name: 'Loxmb95…' })).join(',' + M(3200) + ',') + M(5000) + ']}', rows })
    }
    onStep(WORKER_STEPS[i])
    if (i === 2) {
      let mb = 0
      const t = setInterval(() => { mb += 4e6; onTraffic({ sent: mb / 2, recv: mb / 2 }); if (mb >= 60e6) { clearInterval(t); i++; next() } }, 150)
      return
    }
    i++
    setTimeout(next, 1100)
  }
  next()
}

renderBefore()
