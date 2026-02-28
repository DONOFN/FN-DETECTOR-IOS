// ==========================================
// PERSONALIZADO POR: DONO FN
// CONTATO: 21967173601
// ==========================================

const VPS_HOSTING_KEYWORDS = [
  "hostinger", "hstgr", "locaweb", "kinghost", "umbler", "hostgator", "uol host", "uolhost",
  "bol", "bol.com.br", "redehost", "weblink", "brasileirohost", "br.host", "dialhost",
  "serverspace", "melhorhospedagem", "ibrcom", "masterweb", "superdomínios", "superdomin",
  "plankton", "vps.br", "digitalocean", "linode", "akamai", "vultr", "hetzner", "ovh",
  "ovhcloud", "contabo", "ionos", "godaddy", "siteground", "cloudways", "amazon", "aws",
  "amazonaws", "google cloud", "googlecloud", "microsoft azure", "azure", "alibaba cloud",
  "alibabacloud", "tencent cloud", "tencentcloud", "hstgr.cloud", "srv.umbler", "kinghost.net",
  "locaweb.com.br", "choopa", "psychz", "m247", "serverius", "frantech", "buyvm", "sharktech",
  "quadranet", "nexeon", "servermania", "hostwinds", "racknerd", "dedipath", "spartanhost",
  "cloudie", "tsohost", "wavenet", "fasthosts", "multacom", "telus", "fdcservers", "fdc servers",
  "leaseweb", "colocation america", "b2 net", "b2net", "path.net", "datacamp", "tzulo", "coresite",
]

const CHEAT_PROXY_ASN = {
  "AS35916": "Multacom Corporation (cheat proxy LA)",
  "AS47583": "Hostinger International (cheat proxy BR)",
  "AS60781": "LeaseWeb Netherlands",
  "AS28753": "LeaseWeb Deutschland",
  "AS16276": "OVH SAS",
  "AS14061": "DigitalOcean",
  "AS20473": "Choopa / Vultr",
  "AS8100":  "QuadraNet",
  "AS40065": "Cnservers / FDC Servers",
  "AS53667": "FranTech Solutions",
  "AS395954": "Leaseweb USA",
  "AS13335": "Cloudflare (CDN/Proxy — comum em cheats)",
  "AS209": "CenturyLink / Lumen",
  "AS7203": "Sharktech",
}

const RDNS_HOSTING_PATTERNS = [
  "hstgr.cloud", "staticip", "srv.", "vps.", "cloud.", "host.", "server.", "dedicated.",
  ".kinghost.net", ".locaweb.com.br", ".umbler.net", ".hostgator.com.br", ".digitalocean.com",
  ".vultr.com", ".linode.com", ".hetzner.com", ".contabo.net",
]

const CHEAT_APPS = {
  "com.touchingapp.potatsolite":  "PotatsoLite — app de proxy iOS (mitmproxy cheat)",
  "com.touchingapp.potatso":      "Potatso — app de proxy iOS",
  "com.privateinternetaccess.ios": "PIA VPN",
  "com.anonymousiphone.detoxme":  "Detox — proxy iOS",
  "com.nssurge.inc.surge-ios":    "Surge — proxy/MITM iOS",
  "com.luo.quantumultx":          "Quantumult X — proxy iOS",
  "com.github.shadowsocks":       "Shadowsocks",
  "com.futureland.vpnmaster":     "VPN Master",
  "com.cloudflare.1dot1dot1dot1": "Cloudflare 1.1.1.1 (proxy/warp)",
  "group.com.luo.quantumult":     "Quantumult — proxy iOS",
  "com.netease.trojan":           "Trojan proxy",
  "com.hiddify.app":              "Hiddify — proxy",
  "com.karing.app":               "Karing — proxy",
  "com.metacubex.ClashX":         "ClashX — proxy",
  "com.ssrss.Ssrss":              "SSR iOS proxy",
  "com.adguard.ios.AdguardPro":   "AdGuard Pro (pode ser usado como proxy MITM)",
  "com.monite.proxyff":           "ProxyFF — app de proxy iOS (cheat confirmado)",
}

const SUSPICIOUS_TLDS = [
  ".site", ".store", ".netlify.app", ".netlify", ".xyz", ".pw",
  ".top", ".click", ".bid", ".win", ".stream", ".download",
  ".icu", ".gq", ".cf", ".ml", ".ga", ".tk",
  ".monster", ".fun", ".rest", ".bar", ".lol",
]

const SUSPICIOUS_DOMAIN_WORDS = [
  "proxy", "cheat", "hack", "bypass", "mitm", "inject",
  "spoof", "crack", "exploit", "payload", "tunnel",
  "vpn", "socks", "relay", "forward", "gate",
]

const FALSE_POSITIVE_IPS = new Set([
  "104.29.152.79",  "104.29.152.107", "92.223.118.254",  "23.221.214.168",
  "23.192.36.217",  "54.69.69.125",   "104.29.152.189",  "104.29.137.146",
  "104.29.155.56",  "104.29.137.203", "104.29.155.129",  "104.29.137.125",
  "104.29.158.97",  "104.29.152.95",  "104.29.153.53",   "104.29.159.185",
  "104.29.157.123", "104.29.152.27",  "104.29.157.107",  "104.29.137.16",
  "104.29.152.164", "104.29.137.53",  "104.29.135.227",  "104.29.158.139",
  "104.29.152.157", "104.29.156.174", "104.29.156.24",   "104.29.154.91",
  "104.29.155.27",  "104.29.156.120", "104.29.137.112",
])

async function findNdjsonFile() {
  let path = await DocumentPicker.openFile()
  if (!path) return null
  return { path: path, fm: FileManager.local() }
}

function parseNdjson(content) {
  let trimmed = content.trim()
  if (trimmed.startsWith("[")) {
    try { return JSON.parse(trimmed) } catch(e) {}
  }
  return trimmed.split("\n").map(l => l.trim()).filter(l => l.length > 0).map(l => { try { return JSON.parse(l) } catch(e) { return null } }).filter(Boolean)
}

function validateReport(entries) {
  if (!entries || entries.length === 0) return { ok: false, reason: "Arquivo vazio." }
  let hasNet = entries.some(e => e.type === "networkActivity")
  let hasAccess = entries.some(e => e.type === "access")
  if (!hasNet && !hasAccess) return { ok: false, reason: "Não é um App Privacy Report válido." }
  return { ok: true }
}

const FIELDS = "status,country,city,isp,org,hosting,proxy,query,reverse,as"
async function lookupBatch(targets) {
  try {
    let req = new Request(`http://ip-api.com/batch?fields=${FIELDS}`)
    req.method = "POST"
    req.body = Data.fromString(JSON.stringify(targets))
    req.headers = { "Content-Type": "application/json" }
    req.timeoutInterval = 15
    let results = await req.loadJSON()
    return Array.isArray(results) ? results : []
  } catch(e) { return [] }
}

function classifyIP(info, domain) {
  if (!info) return { severity: null, reasons: [] }
  let reasons = []; let severity = null
  let domLow = (domain || "").toLowerCase()
  for (let tld of SUSPICIOUS_TLDS) { if (domLow.endsWith(tld)) { severity = "HIGH"; reasons.push(`TLD suspeito: "${tld}"`); break } }
  if (info.hosting) { severity = "HIGH"; reasons.push(`VPS/HOSTING — ISP: ${info.isp}`) }
  if (info.proxy) { severity = "HIGH"; reasons.push("PROXY / VPN detectado") }
  return { severity, reasons }
}

async function analyze(entries) {
  let netEntries = entries.filter(e => e.type === "networkActivity")
  let domainHits = {}
  let domainBundles = {}
  for (let e of netEntries) {
    let d = e.domain || ""; if (!d) continue
    domainHits[d] = (domainHits[d] || 0) + (e.hits || 1)
    if (!domainBundles[d]) domainBundles[d] = new Set()
    domainBundles[d].add(e.bundleID || "?")
  }
  let allDomains = Object.entries(domainHits).sort((a, b) => b[1] - a[1]).map(([d]) => d)
  let allBundles = new Set(); for (let e of netEntries) { if (e.bundleID) allBundles.add(e.bundleID) }
  let cheatAppFindings = []
  for (let [bundleID, desc] of Object.entries(CHEAT_APPS)) {
    if (allBundles.has(bundleID)) {
      let appEntries = netEntries.filter(e => e.bundleID === bundleID)
      cheatAppFindings.push({ bundleID, desc, hits: appEntries.reduce((s, e) => s + (e.hits || 1), 0), domains: [...new Set(appEntries.map(e => e.domain).filter(Boolean))] })
    }
  }
  const FF_BUNDLES_A = ["com.dts.freefiremax", "com.dts.freefireth"]
  let ffLoginEntries = netEntries.filter(e => FF_BUNDLES_A.includes(e.bundleID) && e.domain === "app-measurement.com" && e.timeStamp).sort((a, b) => b.timeStamp.localeCompare(a.timeStamp))
  let ffLoginTs = ffLoginEntries.length ? new Date(ffLoginEntries[0].timeStamp) : null
  let results = await lookupBatch(allDomains.slice(0, 100))
  let findings = []
  for (let j = 0; j < results.length; j++) {
    let info = results[j]; if (!info || info.status !== "success") continue
    let { severity, reasons } = classifyIP(info, allDomains[j])
    if (severity) findings.push({ severity, domain: allDomains[j], ip: info.query, country: info.country, isp: info.isp, hits: domainHits[allDomains[j]], reasons, bundles: [...domainBundles[allDomains[j]]].slice(0, 3) })
  }
  return { findings, netEntries, cheatAppFindings, ffLoginTs }
}

function buildHTML(findings, netEntries, cheatAppFindings, ffLoginTs, filename) {
  let allDomainsCount = new Set(netEntries.map(e => e.domain || "")).size
  let allTimestamps = netEntries.map(e => e.timeStamp).filter(Boolean).sort()
  let firstTs = allTimestamps.length ? new Date(allTimestamps[0]) : null
  let lastTs  = allTimestamps.length ? new Date(allTimestamps[allTimestamps.length - 1]) : null
  function fmtDt(d) { return d ? d.toLocaleString("pt-BR", { day:"2-digit", month:"2-digit", year:"numeric", hour:"2-digit", minute:"2-digit" }) : "?" }
  let startStr = fmtDt(firstTs); let endStr = fmtDt(lastTs)
  
  let cards = findings.map(f => `
    <div class="card ${f.severity.toLowerCase()}">
      <div class="card-header"><span class="badge ${f.severity.toLowerCase()}">${f.severity === "HIGH" ? "SUSPEITO" : "POSSÍVEL"}</span><span class="conns">${f.hits} conexões</span></div>
      <div class="card-domain">${f.domain}</div>
      <div class="grid">
        <div class="row"><span class="label">IP</span><span class="val">${f.ip}</span></div>
        <div class="row"><span class="label">Provedor</span><span class="val isp">${f.isp}</span></div>
        <div class="row"><span class="label">Motivo</span><span class="val reason">${f.reasons.join("<br>")}</span></div>
      </div>
    </div>`).join("")

  return `<!DOCTYPE html><html><head><meta name="viewport" content="width=device-width, initial-scale=1"><meta charset="utf-8">
<style>
  * { box-sizing:border-box; margin:0; padding:0; }
  body { background:#0a0a0f; color:#e0e0e0; font-family:-apple-system,ui-monospace,monospace; font-size:13px; }
  .hero { background: linear-gradient(160deg, #0d1b2a 0%, #0a0a12 70%); border-bottom: 1px solid #1a2a3a; padding: 28px 16px 20px; text-align: center; position: relative; }
  .hero-eyebrow { font-size:9px; letter-spacing:3px; color:#00e5ff55; text-transform:uppercase; margin-bottom:8px; }
  .hero-name { font-size:30px; font-weight:700; color:#fff; letter-spacing:-0.5px; margin-bottom:2px; }
  .hero-name span { color:#00e5ff; }
  .hero-contact { font-size:12px; color:#00e5ff; font-weight:bold; letter-spacing:1px; margin-bottom:15px; }
  .hero-file { font-size:10px; color:#556; padding:7px 10px; background:#0d1520; border-radius:7px; border-left:3px solid #00e5ff33; margin-bottom:14px; text-align:left; overflow:hidden; text-overflow:ellipsis; }
  .hero-grid { display:grid; grid-template-columns:1fr 1fr; gap:8px; }
  .hg-card { background:#0d1520; border-radius:8px; padding:9px 12px; border:1px solid #1a2a3a; text-align:left; }
  .hg-label { font-size:9px; color:#446; text-transform:uppercase; margin-bottom:3px; }
  .hg-val { font-size:12px; color:#ccd; }
  .hg-val.cyan { color:#00e5ff; font-weight:bold; }
  .content { padding:16px; }
  .card { background:#0d1520; border-radius:12px; margin-bottom:12px; overflow:hidden; border:1px solid #1a2a3a; border-left:4px solid #333; }
  .card.high { border-left-color:#ff4444; }
  .badge { font-size:9px; font-weight:bold; padding:3px 9px; border-radius:20px; }
  .badge.high { background:#2a0808; color:#ff5555; }
  .card-domain { font-size:13px; font-weight:bold; color:#fff; padding:10px 14px 6px; word-break:break-all; }
  .grid { padding:0 14px 12px; }
  .row { display:flex; gap:8px; padding:5px 0; border-top:1px solid #1a2a3a; }
  .label { color:#446; width:70px; font-size:10px; }
  .val { color:#bbc; flex:1; font-size:11px; }
  .isp { color:#ffbb00; }
  .reason { color:#ff8a80; }
</style>
</head><body>
<div class="hero">
  <div class="hero-eyebrow">Detector de Proxy</div>
  <div class="hero-name">DONO <span>FN</span></div>
  <div class="hero-contact">21967173601</div>
  <div class="hero-file"><strong>Arquivo:</strong> ${filename}</div>
  <div class="hero-grid">
    <div class="hg-card"><div class="hg-label">Início</div><div class="hg-val">${startStr}</div></div>
    <div class="hg-card"><div class="hg-label">Fim</div><div class="hg-val">${endStr}</div></div>
    <div class="hg-card"><div class="hg-label">Domínios</div><div class="hg-val cyan">${allDomainsCount}</div></div>
    <div class="hg-card"><div class="hg-label">Total Conexões</div><div class="hg-val">${netEntries.length}</div></div>
  </div>
</div>
<div class="content">${cards || '<div style="text-align:center;padding:40px;color:#446">Nenhum IP suspeito detectado.</div>'}</div>
</body></html>`
}

async function main() {
  let file = await findNdjsonFile(); if (!file) return
  let content = file.fm.readString(file.path); let entries = parseNdjson(content)
  if (!validateReport(entries).ok) return
  let { findings, netEntries, cheatAppFindings, ffLoginTs } = await analyze(entries)
  let html = buildHTML(findings, netEntries, cheatAppFindings, ffLoginTs, file.path.split("/").pop())
  let wv = new WebView(); await wv.loadHTML(html); await wv.present(false)
}
await main()
