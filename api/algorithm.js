/*
 * ArixAI Precision Page Algorithm
 * v2.0.0
 *
 * Scope: page acquisition + high-recall human-content extraction + soft query ranking.
 * This file is intentionally self-contained so another crawler can import it without
 * changing its own discovery/search logic.
 *
 * Core rules:
 *   1. Never treat search snippets, titles, meta descriptions, analytics, JS, CSS,
 *      tracking payloads, consent text, or bot challenges as pageContent.
 *   2. Try the publisher directly and a rendered/readable fetch path (Jina Reader).
 *   3. Prefer structured article bodies / article containers when present.
 *   4. Recover SPA/hydration content from common JSON application state when HTML
 *      contains little visible text.
 *   5. Remove navigation, ads, trackers, dialogs, cookie walls, social widgets,
 *      repeated chrome, and script/config noise before accepting content.
 *   6. Return the actual readable content fetched; query comparison ranks it but does
 *      not delete an otherwise real page solely because its wording differs.
 */

export const runtime = 'edge';
export const config = { runtime: 'edge' };
export const maxDuration = 300;

const VERSION = 'arix-content-algorithm-2.0.1';
const MAX_RESULTS = 40;
const MAX_QUERY_LEN = 700;
const MAX_CANDIDATES = 500;
const MAX_PAGE_BYTES = 2_000_000;
const MAX_TEXT_CHARS = 80_000;
const MIN_REAL_CONTENT = 180;
const DEFAULT_BUDGET_MS = 8_900;
const PAGE_TIMEOUT_MS = 3_000;
const READER_TIMEOUT_MS = 3_500;
const READER_RETRY_TIMEOUT_MS = 2_500;
const CONTENT_CONCURRENCY = 20;
const RECOVERY_CONCURRENCY = 12;
const CACHE_TTL_MS = 180_000;
const CACHE_MAX = 220;
const CONTENT_CACHE = new Map();

const BLOCKED_HOSTS = new Set([
  'google-analytics.com', 'googletagmanager.com', 'googlesyndication.com',
  'googleadservices.com', 'doubleclick.net', 'gstatic.com', 'googleapis.com',
  'googleusercontent.com', 'facebook.net', 'connect.facebook.net',
  'scorecardresearch.com', 'pixel.wp.com', 'adsrvr.org', 'amazon-adsystem.com',
  'taboola.com', 'outbrain.com', 'segment.io', 'hotjar.com', 'clarity.ms',
  'adnxs.com', 'rubiconproject.com', 'pubmatic.com', 'criteo.com',
  'quantserve.com', '2mdn.net', 'mathtag.com', 'demdex.net'
]);

const BLOCKED_EXT = /\.(?:js|mjs|cjs|css|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|tiff?|woff2?|woff|ttf|otf|eot|mp3|wav|m4a|mp4|webm|mov|avi|zip|rar|7z|exe|dmg|bin)(?:\?|#|$)/i;
const DATA_PATH = /(?:^|[\/_-])(?:analytics|gtag|ga4|collect|pixel|beacon|tracking|tracker|telemetry|consent|ads?|adservice|doubleclick)(?:[\/_-]|$)/i;
const ARTICLE_PATH = /(?:article|articles|story|stories|news|post|posts|blog|blogs|report|reports|press[-_]?release|explained|timeline|history|wiki|paper|research|docs?|documentation|guide|guides)/i;

const NOISE_WORDS = /\b(?:navigation|nav-menu|navbar|site-nav|breadcrumb|breadcrumbs|footer|site-footer|header|site-header|sidebar|side-bar|menu|mega-menu|mobile-menu|cookie|cookies|consent|privacy-banner|cookie-banner|gdpr|advert|advertisement|advertising|ad-container|ad-slot|ad-wrapper|adsbygoogle|sponsor|sponsored|promo|promotion|newsletter|subscribe|subscription|paywall|modal|popup|pop-up|dialog|overlay|share-menu|social-share|social-links|follow-us|related-posts|related-content|recommended|trending|most-read|comments?|comment-list|pagination|login|signin|sign-in|register|account-menu|search-form|search-box)\b/i;
const STRONG_CONTENT_WORDS = /\b(?:article|article-body|article-content|story-body|story-content|post-body|post-content|entry-content|entry-body|main-content|main-article|content-body|content-main|prose|rich-text|wysiwyg|markdown-body|documentation|docs-content|paper-content|report-body|transcript|description-body)\b/i;
const GENERIC_UI_TEXT = /^(?:home|menu|search|login|sign in|sign up|subscribe|share|follow|next|previous|read more|learn more|advertisement|sponsored|loading\.\.\.|skip to content|accept|reject|close|privacy|terms|cookie settings)$/i;
const JS_NOISE = /(?:\b(?:window|document|navigator|localStorage|sessionStorage)\s*\.|\b(?:const|let|var|function|class)\s+[A-Za-z_$][\w$]*\s*=|\b(?:gtag|ga|googletag|dataLayer|fbq|clarity|analytics)\s*\(|\b(?:collect|telemetry|tracking|pixel|beacon)\b.{0,80}\b(?:event|send|measurement|client_id|page_view)\b|\{\s*"?(?:event|event_name|client_id|measurement_id|gtm|ga4|analytics)"?\s*:)/is;
const BOT_MARKERS = /(?:just a moment|checking your browser before accessing|enable javascript and cookies|enable javascript to continue|please enable js|cf-browser-verification|verify you are human|security check to access|captcha required|attention required!|unusual traffic|access denied|automated requests|bot detection|ray id\b)/i;
const TRACKING_MARKERS = /(?:google-analytics|googletagmanager|gtag\(|dataLayer|doubleclick|googlesyndication|adsbygoogle|facebook pixel|fbq\(|hotjar|clarity\.|segment\.|amplitude\.|mixpanel|snowplow|tealium|newrelic|datadog|sentry|telemetry)/i;
const URL_WRAPPER_HOSTS = new Set([
  'www.google.com', 'google.com', 'news.google.com', 'www.google.co.in', 'google.co.in',
  'bing.com', 'www.bing.com', 'duckduckgo.com', 'www.duckduckgo.com', 'search.yahoo.com',
  'www.yahoo.com', 'mojeek.com', 'www.mojeek.com'
]);

const GOV_DOMAINS = [
  'gov.in', 'nic.in', 'mygov.in', 'india.gov.in', 'pib.gov.in', 'mca.gov.in',
  'gst.gov.in', 'incometax.gov.in', 'msme.gov.in', 'education.gov.in', 'meity.gov.in',
  'rbi.org.in', 'sebi.gov.in', 'supremecourt.gov.in', 'indiacode.nic.in'
];

const TRUSTED_DOMAINS = [
  'who.int', 'un.org', 'nasa.gov', 'oecd.org', 'worldbank.org', 'imf.org',
  'w3.org', 'ietf.org', 'mozilla.org', 'developer.mozilla.org'
];

const STOPWORDS = new Set([
  'a','an','the','and','or','of','to','in','on','for','with','from','by','as','at',
  'is','are','was','were','be','been','being','this','that','these','those','what',
  'when','where','how','why','who','which','about','into','near','over','under','than',
  'then','during','through','latest','current','recent','today','news','update','updates',
  'please','show','find','give','tell','me','can','you','i','we','it','its','their','our',
  'your','my','more','information','info','details','best','all','some','does','do','did',
  'explain','explanation','using','use','used','also','from'
]);

const SYNONYM_GROUPS = [
  ['car','cars','automobile','automobiles','motorcar','motorcars','vehicle','vehicles'],
  ['history','historical','timeline','timelines','origins','origin','evolution','development','heritage'],
  ['india','indian'],
  ['price','prices','cost','costs','rate','rates','pricing','priced'],
  ['law','laws','legal','legislation','act','acts','regulation','regulations','rule','rules'],
  ['policy','policies','framework','initiative','initiatives','programme','program','programs'],
  ['company','companies','firm','firms','business','businesses','corporation','corporations'],
  ['founder','founders','created','creator','cofounder','co-founder','originator'],
  ['population','people','residents','inhabitants','demographics'],
  ['economy','economic','economics','gdp','market','markets'],
  ['education','school','schools','student','students','curriculum','syllabus'],
  ['research','study','studies','paper','papers','report','reports','analysis'],
  ['technology','technologies','tech','technical'],
  ['electric','ev','electricity','battery','battery-powered'],
  ['manufacturing','manufacture','production','factory','factories'],
  ['video','videos','watch','youtube','interview','podcast'],
  ['guide','guides','tutorial','tutorials','manual','documentation','docs']
];

const SYNONYM_INDEX = new Map();
for (const group of SYNONYM_GROUPS) {
  const canonical = group[0];
  for (const term of group) SYNONYM_INDEX.set(term, canonical);
}

function clamp(n, a, b) { return Math.min(b, Math.max(a, Number(n) || 0)); }
function truncate(v, max) {
  const s = String(v ?? '').trim();
  return s.length <= max ? s : `${s.slice(0, Math.max(0, max - 1))}…`;
}
function left(deadline) { return Math.max(0, deadline - Date.now()); }
function sleep(ms) { return new Promise(resolve => setTimeout(resolve, ms)); }
function safeInt(v, fallback, min, max) {
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : fallback;
}
function unique(arr) { return [...new Set((arr || []).filter(Boolean))]; }

function normalizeText(v) {
  return String(v || '')
    .normalize('NFKC')
    .replace(/\u0000/g, ' ')
    .toLowerCase()
    .replace(/[^\p{L}\p{N}]+/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function tokens(v) {
  return normalizeText(v).split(' ').filter(x => x.length > 1 && !STOPWORDS.has(x));
}

function safeUrl(url) {
  try {
    const u = new URL(String(url || ''));
    if (!/^https?:$/i.test(u.protocol)) return false;
    const h = u.hostname.toLowerCase();
    if (!h || h === 'localhost' || h.endsWith('.localhost')) return false;
    if (/^(0\.0\.0\.0|127\.|10\.|192\.168\.|169\.254\.)/.test(h)) return false;
    if (/^172\.(?:1[6-9]|2[0-9]|3[0-1])\./.test(h)) return false;
    if (h === '[::1]' || h === '::1') return false;
    return true;
  } catch { return false; }
}

function host(url) {
  try { return new URL(String(url || '')).hostname.toLowerCase().replace(/^www\./, ''); }
  catch { return ''; }
}

function hostRoot(h) {
  const labels = String(h || '').split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const twoPart = new Set(['co.in','com.au','co.uk','co.nz','co.jp','com.sg','com.br','co.za','com.tr','com.mx']);
  const suffix2 = labels.slice(-2).join('.');
  return twoPart.has(suffix2) && labels.length >= 3 ? labels.slice(-3).join('.') : labels.slice(-2).join('.');
}

function samePublisher(a, b) {
  const ha = host(a), hb = host(b);
  if (!ha || !hb) return false;
  return ha === hb || hostRoot(ha) === hostRoot(hb) || ha.endsWith(`.${hb}`) || hb.endsWith(`.${ha}`);
}

function blocked(url) {
  if (!safeUrl(url)) return true;
  const h = host(url);
  if ([...BLOCKED_HOSTS].some(x => h === x || h.endsWith(`.${x}`))) return true;
  try {
    const u = new URL(url);
    const target = `${u.pathname}${u.search}`;
    if (BLOCKED_EXT.test(target)) return true;
    if (DATA_PATH.test(u.pathname)) return true;
  } catch { return true; }
  return false;
}

function isGov(url) {
  const h = host(url);
  return GOV_DOMAINS.some(x => h === x || h.endsWith(`.${x}`));
}
function isTrusted(url) {
  const h = host(url);
  return TRUSTED_DOMAINS.some(x => h === x || h.endsWith(`.${x}`)) ||
    /\.edu(?:\.|$)/i.test(h) || /\.ac\.(?:in|uk|jp|nz)$/i.test(h);
}
function isYouTube(url) {
  const h = host(url);
  return h === 'youtube.com' || h.endsWith('.youtube.com') || h === 'youtu.be';
}
function isVideo(url) {
  const h = host(url);
  return isYouTube(url) || h === 'vimeo.com' || h.endsWith('.vimeo.com') || h === 'dailymotion.com' || h.endsWith('.dailymotion.com');
}
function isDoc(url) {
  return /\.(?:pdf|docx?|xlsx?|pptx?)(?:\?|$)/i.test(String(url || '')) ||
    /(?:\/|^|[\W_])(?:pdf|documentation|docs?|manual|report|paper)(?:[\/\W_]|$)/i.test(String(url || ''));
}

function normalizedUrl(url) {
  try {
    const u = new URL(String(url || ''));
    u.hash = '';
    for (const k of [...u.searchParams.keys()]) {
      if (/^(utm_[^=]+|gclid|dclid|fbclid|msclkid|ref|referrer|cmpid|src|source|igshid|mc_cid|mc_eid)$/i.test(k)) u.searchParams.delete(k);
    }
    return u.href;
  } catch { return ''; }
}

function normalizedKey(url) {
  const u = normalizedUrl(url);
  if (!u) return '';
  try {
    const parsed = new URL(u);
    return `${host(u)}${parsed.pathname.replace(/\/{2,}/g, '/').replace(/\/$/, '') || '/'}${parsed.search}`;
  } catch { return ''; }
}

function decodeHtml(v = '') {
  return String(v)
    .replace(/&nbsp;/gi, ' ')
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/&apos;/gi, "'")
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&#x([0-9a-f]+);?/gi, (full, x) => {
      const n = Number.parseInt(x, 16);
      return Number.isFinite(n) && n <= 0x10ffff ? String.fromCodePoint(n) : full;
    })
    .replace(/&#(\d+);?/g, (full, x) => {
      const n = Number.parseInt(x, 10);
      return Number.isFinite(n) && n <= 0x10ffff ? String.fromCodePoint(n) : full;
    });
}

function decodeEntitiesAndText(v = '') {
  return decodeHtml(String(v))
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/p\s*>/gi, '\n')
    .replace(/<\/h[1-6]\s*>/gi, '\n')
    .replace(/<\/li\s*>/gi, '\n')
    .replace(/<[^>]*>/g, ' ')
    .replace(/[\t\r ]+/g, ' ')
    .replace(/\n[ \t]+/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

function strip(v = '') { return decodeEntitiesAndText(String(v)); }

function cleanContent(v, max = MAX_TEXT_CHARS) {
  let text = String(v || '').replace(/\u0000/g, ' ');
  text = text
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/!\[[^\]]*\]\([^)]*\)/g, ' ')
    .replace(/\[([^\]]{1,300})\]\([^)]{0,1000}\)/g, '$1')
    .replace(/\[\^\d+\]/g, ' ')
    .replace(/^[ \t]*(?:Title|URL Source|Published Time|Markdown Content)\s*:\s*[^\n]{0,500}\n?/gim, ' ')
    .replace(/\b(?:skip to content|accept cookies|cookie settings|privacy settings|sign in|log in|subscribe to our newsletter|enable javascript)\b/gi, ' ')
    .replace(/[ \t]+/g, ' ')
    .replace(/[ \t]*\n[ \t]*/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();

  // Remove obvious code/config lines while preserving ordinary prose containing words like "function".
  const lines = text.split(/\n+/);
  const kept = [];
  for (const line of lines) {
    const s = line.trim();
    if (!s) continue;
    if (s.length < 8 && GENERIC_UI_TEXT.test(s)) continue;
    if (JS_NOISE.test(s) && (s.length < 900 || /[{};=]{3,}/.test(s))) continue;
    if (/^(?:\{\s*"|\[\s*\{|function\s*\(|(?:const|let|var)\s+)/.test(s)) continue;
    kept.push(s);
  }
  text = kept.join('\n\n');
  return truncate(text, max);
}

function extractTitle(html = '') {
  const m = String(html).match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
  return strip(m?.[1] || '');
}

function extractMeta(html, name) {
  const e = String(name).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const h = String(html || '');
  const patterns = [
    new RegExp(`<meta\\b[^>]*(?:name|property|itemprop)\\s*=\\s*["']${e}["'][^>]*content\\s*=\\s*["']([\\s\\S]*?)["'][^>]*>`, 'i'),
    new RegExp(`<meta\\b[^>]*content\\s*=\\s*["']([\\s\\S]*?)["'][^>]*(?:name|property|itemprop)\\s*=\\s*["']${e}["'][^>]*>`, 'i')
  ];
  for (const re of patterns) {
    const m = h.match(re);
    if (m?.[1]) return decodeHtml(m[1]).trim();
  }
  return '';
}

function extractCanonical(html, base) {
  const h = String(html || '');
  const m = h.match(/<link\b[^>]*rel\s*=\s*["'][^"']*\bcanonical\b[^"']*["'][^>]*href\s*=\s*["']([^"']+)["'][^>]*>/i) ||
    h.match(/<link\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*rel\s*=\s*["'][^"']*\bcanonical\b[^"']*["'][^>]*>/i);
  try { return m?.[1] ? normalizedUrl(new URL(decodeHtml(m[1]), base).href) : null; }
  catch { return null; }
}

function extractHtmlLang(html = '') {
  const m = String(html).match(/<html\b[^>]*\blang\s*=\s*["']([^"']+)["']/i);
  return m?.[1] || '';
}

function extractJsonScriptBlocks(html = '') {
  const out = [];
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(String(html))) && out.length < 80) {
    const attrs = m[1] || '';
    const body = m[2] || '';
    const type = (attrs.match(/\btype\s*=\s*["']([^"']+)["']/i)?.[1] || '').toLowerCase();
    const id = (attrs.match(/\bid\s*=\s*["']([^"']+)["']/i)?.[1] || '').toLowerCase();
    const keyish = /(?:json|state|data|props|nuxt|next|apollo|redux|initial|hydration|payload)/i.test(`${type} ${id}`);
    const jsonish = /^[\s\r\n]*[\[{]/.test(body);
    if (type === 'application/ld+json' || keyish || jsonish) out.push({ attrs, body, type, id });
  }
  return out;
}

function collectHumanStrings(value, out, depth = 0, key = '') {
  if (out.length >= 1000 || depth > 14 || value == null) return;
  if (typeof value === 'string') {
    const s = cleanContent(value, 5000);
    if (!s || s.length < 55 || s.length > 12000) return;
    if (TRACKING_MARKERS.test(s) || JS_NOISE.test(s)) return;
    if (/^(?:https?:\/\/|javascript:|data:|\/\/)/i.test(s)) return;
    const wordCount = s.split(/\s+/).length;
    const sentenceLike = /[.!?।！？]/.test(s);
    const alpha = (s.match(/[\p{L}]/gu) || []).length;
    if (wordCount >= 8 && alpha >= 30 && (sentenceLike || /(?:title|headline|body|text|content|description|article|paragraph|summary|caption|transcript|answer|question)/i.test(key))) {
      out.push({ text: s, key: String(key || '') });
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const x of value) collectHumanStrings(x, out, depth + 1, key);
    return;
  }
  if (typeof value !== 'object') return;
  for (const [k, v] of Object.entries(value)) collectHumanStrings(v, out, depth + 1, k);
}

function parseLooseJson(raw) {
  const s = String(raw || '').trim();
  if (!s) return null;
  try { return JSON.parse(s); } catch {}
  return null;
}

function extractStructuredContent(html = '') {
  const candidates = [];
  const blocks = extractJsonScriptBlocks(html);
  for (const block of blocks) {
    const t = block.type;
    if (t === 'application/ld+json') {
      const value = parseLooseJson(block.body);
      if (value) {
        const vals = [];
        const walk = x => {
          if (!x || typeof x !== 'object') return;
          if (Array.isArray(x)) { for (const v of x) walk(v); return; }
          if (typeof x.articleBody === 'string') vals.push(x.articleBody);
          if (typeof x.text === 'string' && x.text.length > 120) vals.push(x.text);
          if (typeof x.description === 'string' && x.description.length > 180) vals.push(x.description);
          for (const v of Object.values(x)) if (v && typeof v === 'object') walk(v);
        };
        walk(value);
        for (const text of vals) candidates.push(cleanContent(text));
      }
    } else if (block.body && block.body.length > 120) {
      const value = parseLooseJson(block.body);
      if (value) {
        const strings = [];
        collectHumanStrings(value, strings);
        const strong = strings
          .sort((a, b) => b.text.length - a.text.length)
          .slice(0, 80)
          .map(x => x.text);
        if (strong.length) candidates.push(cleanContent(strong.join('\n\n')));
      }
    }
  }
  return unique(candidates.filter(x => x && x.length >= 150));
}

function isNoiseTag(name) {
  return /^(?:script|style|noscript|template|iframe|object|embed|canvas|svg|nav|footer|header|aside|form|dialog|menu|select|option|button)$/i.test(name);
}
function isBlockTag(name) {
  return /^(?:article|main|section|div|p|h[1-6]|li|blockquote|pre|td|th|dt|dd|figure|figcaption|details|summary|address)$/i.test(name);
}
function attrsText(attrs = '') {
  return String(attrs).replace(/\s+/g, ' ').toLowerCase();
}
function isNoiseAttrs(attrs = '') {
  const a = attrsText(attrs);
  const id = a.match(/\bid\s*=\s*["']([^"']*)["']/i)?.[1] || '';
  const cls = a.match(/\bclass\s*=\s*["']([^"']*)["']/i)?.[1] || '';
  const combined = `${id} ${cls}`;
  return NOISE_WORDS.test(combined);
}
function isStrongContentAttrs(attrs = '') {
  const a = attrsText(attrs);
  const id = a.match(/\bid\s*=\s*["']([^"']*)["']/i)?.[1] || '';
  const cls = a.match(/\bclass\s*=\s*["']([^"']*)["']/i)?.[1] || '';
  const role = a.match(/\brole\s*=\s*["']([^"']*)["']/i)?.[1] || '';
  return STRONG_CONTENT_WORDS.test(`${id} ${cls} ${role}`) || /role\s*=\s*["']main["']/i.test(a);
}

function visibleBlockExtraction(html = '') {
  const source = String(html || '');
  const blocks = [];
  const stack = [];
  const excludedStack = [];
  let visibleText = [];
  let pos = 0;

  function currentExcluded() { return excludedStack.length > 0; }
  function addText(text) {
    if (currentExcluded()) return;
    const decoded = decodeHtml(text)
      .replace(/\s+/g, ' ')
      .trim();
    if (!decoded) return;
    visibleText.push(decoded);
    for (let i = stack.length - 1; i >= 0; i--) {
      const entry = stack[i];
      if (entry.block) {
        entry.parts.push(decoded);
        break;
      }
    }
  }
  function finalize(entry) {
    const text = cleanContent(entry.parts.join(' '));
    if (!text) return;
    const words = text.split(/\s+/).length;
    const letters = (text.match(/[\p{L}]/gu) || []).length;
    const punctuation = (text.match(/[.,;:!?()\-–—%]/g) || []).length;
    const attr = `${entry.attrsText} ${entry.name}`;
    const strong = isStrongContentAttrs(entry.attrs);
    const noise = entry.noise || isNoiseAttrs(entry.attrs) || isNoiseTag(entry.name);
    const shortUi = text.length < 90 && (GENERIC_UI_TEXT.test(text) || words <= 8);
    const density = letters / Math.max(1, text.length);
    const score =
      Math.min(35, Math.log10(text.length + 10) * 8) +
      Math.min(25, words / 12) +
      Math.min(10, punctuation / 4) +
      (strong ? 25 : 0) +
      (/^(?:article|main|p|h[1-6]|blockquote|pre)$/i.test(entry.name) ? 7 : 0) +
      (entry.insideStrong ? 12 : 0) +
      Math.min(5, density * 8) -
      (noise ? 55 : 0) -
      (shortUi ? 30 : 0);
    if (!noise && !shortUi && letters >= 30 && (text.length >= 45 || /^h[1-6]$/i.test(entry.name))) {
      blocks.push({
        tag: entry.name,
        text,
        score,
        depth: entry.depth,
        strong: Boolean(strong || entry.insideStrong),
        insideArticle: Boolean(entry.insideArticle)
      });
    }
  }

  const tagRe = /<!--[\s\S]*?-->|<([/!]?)([A-Za-z][\w:-]*)([^>]*)>/g;
  let m;
  while ((m = tagRe.exec(source))) {
    if (left(Infinity) < 0) break;
    const textBefore = source.slice(pos, m.index);
    if (textBefore) addText(textBefore);
    pos = tagRe.lastIndex;
    const whole = m[0];
    if (whole.startsWith('<!--')) continue;
    const closing = m[1] === '/';
    const rawName = m[2] || '';
    const name = rawName.toLowerCase();
    const attrs = m[3] || '';
    const selfClosing = /\/\s*>$/.test(whole) || /^(?:meta|link|img|br|hr|input|source|track|wbr|area|base|col|embed|param)$/i.test(name);

    if (closing) {
      let idx = -1;
      for (let i = stack.length - 1; i >= 0; i--) {
        if (stack[i].name === name) { idx = i; break; }
      }
      if (idx >= 0) {
        for (let i = stack.length - 1; i >= idx; i--) {
          const entry = stack.pop();
          if (entry.exclude) excludedStack.pop();
          if (entry.block) finalize(entry);
        }
      }
      continue;
    }

    const noise = isNoiseAttrs(attrs) || isNoiseTag(name);
    const parentInsideStrong = stack.some(x => x.insideStrong || isStrongContentAttrs(x.attrs));
    const entry = {
      name,
      attrs,
      attrsText: attrsText(attrs),
      noise,
      exclude: noise,
      block: isBlockTag(name),
      parts: [],
      depth: stack.length,
      insideStrong: parentInsideStrong || isStrongContentAttrs(attrs),
      insideArticle: stack.some(x => x.name === 'article' || x.name === 'main') || /^(?:article|main)$/i.test(name)
    };
    stack.push(entry);
    if (entry.exclude) excludedStack.push(entry);

    if (selfClosing) {
      const popped = stack.pop();
      if (popped?.exclude) excludedStack.pop();
      if (popped?.block) finalize(popped);
    }
  }
  if (pos < source.length) addText(source.slice(pos));
  while (stack.length) {
    const entry = stack.pop();
    if (entry.exclude) excludedStack.pop();
    if (entry.block) finalize(entry);
  }

  return { blocks, visibleText: visibleText.join(' '), title: extractTitle(source) };
}

function dedupeParagraphs(parts) {
  const out = [];
  const seen = new Set();
  const sorted = [...parts];
  for (const raw of sorted) {
    const text = cleanContent(raw);
    if (!text) continue;
    const key = normalizeText(text);
    if (key.length < 30 || seen.has(key)) continue;
    let contained = false;
    for (const prior of out) {
      const p = normalizeText(prior);
      if (p.length > key.length + 80 && p.includes(key)) { contained = true; break; }
    }
    if (!contained) {
      const trimmed = out.filter(prior => {
        const p = normalizeText(prior);
        return !(key.length > p.length + 80 && key.includes(p));
      });
      out.length = 0;
      out.push(...trimmed, text);
      seen.add(key);
    }
  }
  return out;
}

function chooseVisibleContent(html = '') {
  const parsed = visibleBlockExtraction(html);
  const blocks = parsed.blocks;
  if (!blocks.length) return '';

  const strongBlocks = blocks.filter(b => b.strong && b.text.length >= 80);
  const articleBlocks = blocks.filter(b => b.insideArticle && b.text.length >= 80);
  const normalBlocks = blocks.filter(b => b.text.length >= 60 && b.score > 4);

  let selected;
  if (strongBlocks.length >= 2) selected = strongBlocks;
  else if (articleBlocks.length >= 2) selected = articleBlocks;
  else selected = normalBlocks;

  selected = selected.filter(b => !BOT_MARKERS.test(b.text) && !TRACKING_MARKERS.test(b.text));
  if (!selected.length) return '';

  // Prefer document order. We deliberately keep all good content blocks rather than
  // selecting a single "best" paragraph; this is what prevents title-only output.
  const texts = [];
  for (const b of selected) {
    if (/^h[1-6]$/i.test(b.tag) || b.text.length >= 45) texts.push(b.text);
  }
  const merged = dedupeParagraphs(texts);
  const result = cleanContent(merged.join('\n\n'), MAX_TEXT_CHARS);

  // If the block strategy was sparse, use the accumulated visible document text as a
  // secondary high-recall route. It is still cleaned and checked for junk before use.
  if (result.length >= 300) return result;
  const visible = cleanContent(parsed.visibleText, MAX_TEXT_CHARS);
  if (visible.length >= 300 && !BOT_MARKERS.test(visible) && !TRACKING_MARKERS.test(visible)) return visible;
  return result;
}

function extractBodyTextFallback(html = '') {
  const h = String(html || '')
    .replace(/<!--([\s\S]*?)-->/g, ' ')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript\b[^>]*>[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<(?:svg|canvas|iframe|object|embed)\b[^>]*>[\s\S]*?<\/(?:svg|canvas|iframe|object|embed)>/gi, ' ')
    .replace(/<\/(?:p|div|section|article|li|h[1-6]|blockquote|br|tr)>/gi, '\n')
    .replace(/<[^>]+>/g, ' ');
  return cleanContent(decodeHtml(h), MAX_TEXT_CHARS);
}

function contentQuality(text, meta = {}) {
  const s = String(text || '').trim();
  if (!s) return { score: 0, accepted: false, reasons: ['empty'] };
  const normalized = normalizeText(s);
  const wordCount = normalized ? normalized.split(' ').length : 0;
  const uniqueCount = new Set(normalized.split(' ')).size;
  const uniqueRatio = uniqueCount / Math.max(1, wordCount);
  const sentenceCount = (s.match(/[.!?।！？](?:\s|$)/g) || []).length;
  const punctuation = (s.match(/[.,;:!?()\-–—%]/g) || []).length;
  const alpha = (s.match(/[\p{L}]/gu) || []).length;
  const codeish = (s.match(/[{}<>]{6,}|=>|===|&&|\|\||;\s*(?:const|let|var)\b/gi) || []).length;
  const repeatedUi = (s.match(/\b(?:home|menu|search|login|subscribe|privacy|cookie|advertisement|sponsored|share)\b/gi) || []).length;
  const urlCount = (s.match(/https?:\/\/|www\./gi) || []).length;
  let score = 0;
  score += Math.min(30, s.length / 300 * 20);
  score += Math.min(20, wordCount / 80 * 20);
  score += uniqueRatio * 15;
  score += Math.min(15, sentenceCount * 1.8);
  score += Math.min(10, punctuation / 8);
  if (alpha > 200) score += 5;
  if (meta.structured) score += 8;
  if (meta.articleContainer) score += 8;
  if (meta.reader) score += 6;
  if (meta.direct) score += 5;
  if (s.length < 260) score -= 25;
  if (wordCount < 40) score -= 20;
  if (codeish > 3) score -= 45;
  if (TRACKING_MARKERS.test(s)) score -= 60;
  if (BOT_MARKERS.test(s)) score -= 80;
  if (repeatedUi > Math.max(8, wordCount / 7)) score -= 20;
  if (urlCount > Math.max(5, wordCount / 30)) score -= 15;
  const accepted = s.length >= MIN_REAL_CONTENT && wordCount >= 30 && alpha >= 80 && !BOT_MARKERS.test(s) && !TRACKING_MARKERS.test(s) && codeish <= 6 && score >= 25;
  const reasons = [];
  if (s.length < MIN_REAL_CONTENT) reasons.push('too-short');
  if (wordCount < 30) reasons.push('too-few-words');
  if (uniqueRatio < 0.18) reasons.push('high-repetition');
  if (codeish > 3) reasons.push('code-noise');
  if (TRACKING_MARKERS.test(s)) reasons.push('tracking-noise');
  if (BOT_MARKERS.test(s)) reasons.push('bot-challenge');
  return { score: Number(clamp(score, 0, 100).toFixed(2)), accepted, reasons };
}

function isBotChallenge(text) {
  const t = String(text || '').trim();
  if (!t) return true;
  if (t.length > 5000 && !TRACKING_MARKERS.test(t)) return false;
  return BOT_MARKERS.test(t);
}

function textFromMarkdown(v = '') {
  let text = String(v || '')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/^\s*(?:Title|URL Source|Published Time|Markdown Content)\s*:\s*.*$/gim, ' ')
    .replace(/^\s*#+\s*/gm, '')
    .replace(/!?\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/\[([^\]]+)\]\[[^\]]*\]/g, '$1')
    .replace(/[*_`~]/g, '')
    .replace(/^\s*>\s?/gm, '')
    .replace(/<[^>]+>/g, ' ');
  return cleanContent(text, MAX_TEXT_CHARS);
}

function extractReaderMetadata(raw, fallbackUrl, fallbackTitle) {
  const text = String(raw || '');
  const title = text.match(/^Title:\s*(.+)$/im)?.[1]?.trim() || fallbackTitle || '';
  const source = text.match(/^URL Source:\s*(\S+)$/im)?.[1]?.trim() || fallbackUrl || '';
  const published = text.match(/^(?:Published Time|Date):\s*(.+)$/im)?.[1]?.trim() || '';
  let sourceUrl = source;
  try { sourceUrl = new URL(source, fallbackUrl).href; } catch {}
  return { title: truncate(decodeHtml(title), 400), sourceUrl: normalizedUrl(sourceUrl) || fallbackUrl, publishedAt: published || null };
}

function decodeBase64UrlLoose(value) {
  const raw = String(value || '').trim();
  if (!raw) return null;
  const variants = [];
  const push = v => {
    const x = String(v || '').trim();
    if (x && !variants.includes(x)) variants.push(x);
  };
  try { push(decodeURIComponent(raw)); } catch {}
  push(raw);
  if (raw.length > 2 && /^a1/i.test(raw)) {
    const tail = raw.slice(2);
    try { push(decodeURIComponent(tail)); } catch {}
    push(tail);
  }

  for (const variant of variants) {
    if (/^https?:\/\//i.test(variant)) return variant;
    try {
      let s = variant.replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
      while (s.length % 4) s += '=';
      if (!/^[A-Za-z0-9+/]+={0,2}$/.test(s)) continue;
      if (typeof atob !== 'function') continue;
      const bin = atob(s);
      if (!bin || bin.length < 8) continue;
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      const decoded = new TextDecoder('utf-8', { fatal: false }).decode(bytes).trim();
      if (/^https?:\/\//i.test(decoded)) return decoded;
    } catch {}
  }
  return null;
}

function searchWrapperTarget(url) {
  if (!safeUrl(url)) return null;
  try {
    const u = new URL(decodeHtml(String(url || '')));
    const h = u.hostname.toLowerCase().replace(/^www\./, '');
    const path = u.pathname || '';

    // Bing's modern click URLs are not normal URL-encoded redirects. The `u`
    // parameter is commonly `a1` + base64url(target). This must be decoded before
    // any page acquisition begins; otherwise the crawler fetches bing.com/ck/a.
    if (h === 'bing.com' && /^\/ck\/a(?:\/|$)/i.test(path)) {
      const encoded = u.searchParams.get('u') || u.searchParams.get('url') || u.searchParams.get('target');
      const target = decodeBase64UrlLoose(encoded);
      if (target && safeUrl(target) && host(target) !== h && !blocked(target)) return normalizedUrl(target) || null;
      return null;
    }

    if ((h.startsWith('google.') || h === 'news.google.com') && /^\/url\/?$/i.test(path)) {
      const v = u.searchParams.get('q') || u.searchParams.get('url') || u.searchParams.get('target');
      const target = decodeURIComponentSafe(v || '');
      if (safeUrl(target) && host(target) !== h && !blocked(target)) return normalizedUrl(target) || null;
      return null;
    }

    if ((h === 'duckduckgo.com' || h === 'html.duckduckgo.com') && /^\/l\/?$/i.test(path)) {
      const v = u.searchParams.get('uddg') || u.searchParams.get('u');
      const target = decodeURIComponentSafe(v || '');
      if (safeUrl(target) && host(target) !== h && !blocked(target)) return normalizedUrl(target) || null;
      return null;
    }

    if (h === 'search.yahoo.com' || h === 'r.search.yahoo.com') {
      const ru = path.match(/\/RU=([^/]+)(?:\/|$)/i)?.[1] || u.searchParams.get('RU') || u.searchParams.get('url');
      const target = decodeURIComponentSafe(ru || '');
      if (safeUrl(target) && host(target) !== h && !blocked(target)) return normalizedUrl(target) || null;
      return null;
    }

    return url;
  } catch {
    return null;
  }
}

function candidateUrl(raw) {
  const rawUrl = raw?.url || raw?.link || raw?.sourceUrl || raw?.href || raw?.source || '';
  return normalizedUrl(searchWrapperTarget(rawUrl) || '');
}

function unwrapSearchWrapper(url) {
  const target = searchWrapperTarget(url);
  return target || (safeUrl(url) && !URL_WRAPPER_HOSTS.has(host(url)) ? normalizedUrl(url) : null);
}

function redirectLooksWrong(originalUrl, finalUrl) {
  if (!safeUrl(finalUrl)) return true;
  if (samePublisher(originalUrl, finalUrl)) {
    try {
      const a = new URL(originalUrl), b = new URL(finalUrl);
      const aPath = a.pathname.replace(/\/$/, '');
      const bPath = b.pathname.replace(/\/$/, '');
      if (aPath.length > 8 && (bPath === '' || bPath === '/')) return true;
      if (ARTICLE_PATH.test(aPath) && !ARTICLE_PATH.test(bPath) && bPath.length < 8) return true;
    } catch {}
  }
  return false;
}

function charsetFromHtml(html = '') {
  return String(html).match(/<meta\b[^>]*charset\s*=\s*["']?\s*([A-Za-z0-9._-]+)/i)?.[1] ||
    String(html).match(/<meta\b[^>]*content\s*=\s*["'][^"']*charset\s*=\s*([A-Za-z0-9._-]+)/i)?.[1] || '';
}

async function fetchResponse(url, timeout, deadline, headers = {}) {
  const available = Math.max(0, left(deadline));
  const budget = Math.min(timeout, available > 450 ? available - 60 : available);
  if (budget < 250) throw new Error('BUDGET_EXHAUSTED');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), budget);
  try {
    return await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0 Safari/537.36 ArixAIContentFetcher/2.0',
        'accept': 'text/html,application/xhtml+xml,application/pdf,text/plain,text/markdown;q=0.9,*/*;q=0.1',
        'accept-language': 'en-IN,en;q=0.9,en-US;q=0.8',
        'cache-control': 'no-cache',
        ...headers
      }
    });
  } finally {
    clearTimeout(timer);
  }
}

async function readTextResult(res, maxBytes, deadline, preferredCharset = '') {
  const reader = res.body?.getReader?.();
  let truncated = false;
  if (!reader) {
    const text = await res.text();
    return { text: truncate(text, maxBytes), truncated: text.length > maxBytes };
  }
  const chunks = [];
  let total = 0;
  try {
    while (total < maxBytes && left(deadline) > 90) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      const room = maxBytes - total;
      const chunk = value.byteLength > room ? value.slice(0, room) : value;
      chunks.push(chunk);
      total += chunk.byteLength;
      if (value.byteLength > room) { truncated = true; break; }
    }
  } finally {
    try { await reader.cancel(); } catch {}
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) { bytes.set(c, offset); offset += c.byteLength; }
  let charset = preferredCharset || 'utf-8';
  try {
    const lower = charset.toLowerCase();
    if (!['utf-8','utf8','utf-16','utf-16le','utf-16be','us-ascii','iso-8859-1','windows-1252'].includes(lower)) charset = 'utf-8';
    const text = new TextDecoder(charset).decode(bytes);
    return { text, truncated };
  } catch {
    try { return { text: new TextDecoder('utf-8').decode(bytes), truncated }; }
    catch { return { text: '', truncated }; }
  }
}

async function readBytes(res, maxBytes, deadline) {
  const reader = res.body?.getReader?.();
  if (!reader) {
    const b = new Uint8Array(await res.arrayBuffer());
    return { bytes: b.slice(0, maxBytes), truncated: b.byteLength > maxBytes };
  }
  const chunks = [];
  let total = 0;
  let truncated = false;
  try {
    while (total < maxBytes && left(deadline) > 90) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      const room = maxBytes - total;
      const chunk = value.byteLength > room ? value.slice(0, room) : value;
      chunks.push(chunk);
      total += chunk.byteLength;
      if (value.byteLength > room) { truncated = true; break; }
    }
  } finally { try { await reader.cancel(); } catch {} }
  const bytes = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) { bytes.set(c, off); off += c.byteLength; }
  return { bytes, truncated };
}

function bytesLatin1(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 8192) out += String.fromCharCode(...bytes.subarray(i, Math.min(i + 8192, bytes.length)));
  return out;
}
function pdfLiteral(s) {
  return String(s || '')
    .replace(/\\([nrtbf\\()])/g, (_, c) => ({ n:'\n', r:'\r', t:'\t', b:'\b', f:'\f', '\\':'\\', '(':'(', ')':')' }[c] || c))
    .replace(/\\([0-7]{1,3})/g, (_, o) => String.fromCharCode(Number.parseInt(o, 8)));
}
function pdfHex(s) {
  const h = String(s || '').replace(/[^0-9a-f]/gi, '');
  if (!h) return '';
  const even = h.length % 2 ? `${h}0` : h;
  const b = new Uint8Array(even.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = Number.parseInt(even.slice(i * 2, i * 2 + 2), 16);
  try {
    if (b[0] === 0xfe && b[1] === 0xff) return new TextDecoder('utf-16be').decode(b.slice(2));
    if (b[0] === 0xff && b[1] === 0xfe) return new TextDecoder('utf-16le').decode(b.slice(2));
  } catch {}
  try { return new TextDecoder('utf-8').decode(b); } catch { return ''; }
}

async function inflate(bytes, deadline) {
  if (typeof DecompressionStream === 'undefined' || left(deadline) < 450) return null;
  for (const format of ['deflate','gzip']) {
    try {
      const ds = new DecompressionStream(format);
      const writer = ds.writable.getWriter();
      await writer.write(bytes);
      await writer.close();
      return new Uint8Array(await new Response(ds.readable).arrayBuffer());
    } catch {}
  }
  return null;
}

async function extractPdfText(bytes, deadline) {
  const raw = bytesLatin1(bytes);
  const parts = [];
  const re = /<<(?:[\s\S]{0,10000}?)>>\s*stream\r?\n([\s\S]*?)\r?\nendstream/g;
  let m;
  while ((m = re.exec(raw)) && parts.length < 120 && left(deadline) > 320) {
    const headerStart = m[0].indexOf('stream');
    const header = headerStart >= 0 ? m[0].slice(0, headerStart) : '';
    const dataText = m[1] || '';
    const start = m.index + Math.max(0, headerStart) + 'stream'.length + (raw.slice(m.index + Math.max(0, headerStart) + 'stream'.length).match(/^\r?\n/)?.[0].length || 0);
    const source = bytes.slice(start, start + dataText.length);
    let data = dataText;
    if (/\/FlateDecode/i.test(header)) {
      const inflated = await inflate(source, deadline);
      if (inflated) data = bytesLatin1(inflated);
    }
    const found = [];
    for (let i = 0; i < data.length; i++) {
      if (data[i] === '(') {
        let depth = 1, j = i + 1, escaped = false;
        for (; j < data.length; j++) {
          const ch = data[j];
          if (escaped) { escaped = false; continue; }
          if (ch === '\\') { escaped = true; continue; }
          if (ch === '(') depth++;
          else if (ch === ')') { depth--; if (!depth) break; }
        }
        if (j < data.length) { found.push(pdfLiteral(data.slice(i + 1, j))); i = j; }
      } else if (data[i] === '<' && data[i + 1] !== '<') {
        const j = data.indexOf('>', i + 1);
        if (j > i) { found.push(pdfHex(data.slice(i + 1, j))); i = j; }
      }
    }
    if (found.length) parts.push(found.join(' '));
  }
  if (!cleanContent(parts.join(' '))) {
    const loose = [];
    for (const m2 of raw.matchAll(/\(([^\\]{3,700})\)/g)) loose.push(pdfLiteral(m2[1]));
    parts.push(loose.join(' '));
  }
  return cleanContent(parts.join('\n\n'), MAX_TEXT_CHARS);
}

function extractHtmlContent(html, baseUrl = '') {
  const title = extractTitle(html);
  const canonical = extractCanonical(html, baseUrl || 'https://example.invalid/');
  const structured = extractStructuredContent(html);
  let bestStructured = '';
  if (structured.length) bestStructured = structured.sort((a,b) => b.length - a.length).join('\n\n');

  // Strong extraction path: article/main/body-like visible HTML, with noise removed.
  const visible = chooseVisibleContent(html);

  // Article-body HTML markers that are often used by news/CMS sites.
  const markerTexts = [];
  const markerRe = /<(?:div|section|article)\b([^>]*(?:article-body|article-content|story-body|story-content|entry-content|post-content|content-body|main-content|wysiwyg|rich-text|markdown-body)[^>]*)>([\s\S]*?)<\/(?:div|section|article)>/gi;
  let mm;
  while ((mm = markerRe.exec(String(html))) && markerTexts.length < 30) {
    const t = chooseVisibleContent(`<article ${mm[1]}>${mm[2]}</article>`);
    if (t.length >= 220) markerTexts.push(t);
  }

  const candidates = [];
  if (bestStructured.length >= 220) candidates.push({ text: bestStructured, kind: 'structured', bonus: 12 });
  for (const t of markerTexts) if (t.length >= 220) candidates.push({ text: t, kind: 'article-marker', bonus: 12 });
  if (visible.length >= 220) candidates.push({ text: visible, kind: 'html-visible', bonus: 6 });
  const fallback = extractBodyTextFallback(html);
  if (fallback.length >= 220) candidates.push({ text: fallback, kind: 'html-fallback', bonus: 0 });

  // Pick content by quality, not just raw length. A huge menu is worse than a shorter article body.
  let best = null;
  for (const c of candidates) {
    const cleaned = cleanContent(c.text, MAX_TEXT_CHARS);
    const quality = contentQuality(cleaned, {
      structured: c.kind === 'structured',
      articleContainer: c.kind === 'article-marker' || c.kind === 'html-visible',
      direct: true
    });
    const q = quality.score + c.bonus;
    if (!quality.accepted) continue;
    if (!best || q > best.quality.score + best.bonus || (Math.abs(q - (best.quality.score + best.bonus)) < 2 && cleaned.length > best.text.length)) {
      best = { text: cleaned, kind: c.kind, quality, bonus: c.bonus };
    }
  }
  return {
    title,
    canonical,
    content: best?.text || '',
    method: best?.kind || '',
    quality: best?.quality || contentQuality(''),
    language: extractHtmlLang(html)
  };
}

async function readerContent(candidate, plan, deadline, timeout = READER_TIMEOUT_MS) {
  const url = candidateUrl(candidate);
  if (!url || blocked(url) || left(deadline) < 350) return null;
  const target = unwrapSearchWrapper(url);
  if (!safeUrl(target) || blocked(target)) return null;

  const schemes = [target];
  try {
    const u = new URL(target);
    const alt = new URL(target);
    alt.protocol = u.protocol === 'https:' ? 'http:' : 'https:';
    schemes.push(alt.href);
  } catch {}

  for (let i = 0; i < schemes.length && left(deadline) > 320; i++) {
    const targetUrl = schemes[i];
    const jinaUrl = `https://r.jina.ai/${targetUrl}`;
    const perDeadline = Math.min(deadline, Date.now() + timeout);
    try {
      const res = await fetchResponse(jinaUrl, timeout, perDeadline, {
        accept: 'text/plain,text/markdown;q=0.9,*/*;q=0.1'
      });
      if (!res.ok) continue;
      const rr = await readTextResult(res, MAX_PAGE_BYTES, perDeadline);
      const raw = rr.text;
      const meta = extractReaderMetadata(raw, target, candidate.title || '');
      if (!meta.sourceUrl || !samePublisher(target, meta.sourceUrl)) continue;
      const text = textFromMarkdown(raw);
      if (rr.truncated || text.length < MIN_REAL_CONTENT || isBotChallenge(text)) continue;
      if (TRACKING_MARKERS.test(text) || JS_NOISE.test(text)) continue;
      const quality = contentQuality(text, { reader: true });
      if (!quality.accepted) continue;
      const rel = comparePageToQuery(plan.query, { ...candidate, url: meta.sourceUrl, title: meta.title || candidate.title, pageContent: text });
      return {
        ...candidate,
        url: normalizedUrl(meta.sourceUrl) || target,
        title: truncate(meta.title || candidate.title || '', 400),
        publishedAt: meta.publishedAt || candidate.publishedAt || null,
        domain: host(meta.sourceUrl || target),
        pageContent: text,
        extractedText: text,
        contentStatus: 'reader',
        contentMethod: 'jina-reader',
        contentSourceUrl: normalizedUrl(meta.sourceUrl) || target,
        contentLength: text.length,
        contentConfidence: Number(clamp(0.78 + quality.score / 500, 0.78, 0.96).toFixed(3)),
        contentTargetMatched: true,
        contentTitleSimilarity: rel.titleCoverage,
        contentConceptCoverage: rel.conceptCoverage,
        relevanceScore: rel.score,
        relevanceBand: rel.band,
        relevance: rel,
        qualityScore: quality.score,
        qualityReasons: quality.reasons,
        verified: true,
        httpStatus: res.status,
        contentType: 'text/markdown',
        verificationMethod: 'jina-reader'
      };
    } catch {}
  }
  return null;
}

async function directContent(candidate, plan, deadline) {
  const original = candidateUrl(candidate);
  if (!original || blocked(original) || left(deadline) < 300) return null;
  const target = unwrapSearchWrapper(original);
  if (!target || !safeUrl(target) || blocked(target)) return null;

  const cached = contentCacheGet(target);
  if (cached && isRealSourceContent(cached)) return { ...candidate, ...cached };

  const perDeadline = Math.min(deadline, Date.now() + PAGE_TIMEOUT_MS);
  try {
    const res = await fetchResponse(target, PAGE_TIMEOUT_MS, perDeadline);
    const finalUrl = normalizedUrl(res.url || target) || target;
    if (!safeUrl(finalUrl) || blocked(finalUrl) || redirectLooksWrong(target, finalUrl)) return null;
    const ct = String(res.headers.get('content-type') || '').toLowerCase();
    const xRobots = String(res.headers.get('x-robots-tag') || '').toLowerCase();

    if (/application\/pdf|application\/x-pdf/i.test(ct) || /\.pdf(?:\?|$)/i.test(finalUrl)) {
      const rb = await readBytes(res, MAX_PAGE_BYTES, perDeadline);
      if (rb.truncated) return null;
      const text = await extractPdfText(rb.bytes, perDeadline).catch(() => '');
      const quality = contentQuality(text, { direct: true });
      if (!quality.accepted) return null;
      const rel = comparePageToQuery(plan.query, { ...candidate, url: finalUrl, pageContent: text });
      const out = {
        ...candidate, url: finalUrl, domain: host(finalUrl), pageContent: text, extractedText: text,
        contentStatus: 'full', contentMethod: 'direct-pdf-text', contentSourceUrl: finalUrl,
        contentLength: text.length, contentConfidence: Number(clamp(0.88 + quality.score / 1000, 0.88, 0.98).toFixed(3)),
        contentTargetMatched: true, contentTitleSimilarity: rel.titleCoverage, contentConceptCoverage: rel.conceptCoverage,
        relevanceScore: rel.score, relevanceBand: rel.band, relevance: rel, qualityScore: quality.score, qualityReasons: quality.reasons,
        verified: res.ok, httpStatus: res.status, contentType: ct || 'application/pdf', verificationMethod: 'direct-pdf-text', truncated: false
      };
      contentCacheSet(target, stripCached(out));
      return out;
    }

    if (!res.ok) return null;
    if (/(?:javascript|ecmascript|css|json|xml|octet-stream)/i.test(ct)) return null;
    if (xRobots.includes('noindex') && /application\/json/i.test(ct)) return null;

    const rr = await readTextResult(res, MAX_PAGE_BYTES, perDeadline, 'utf-8');
    if (rr.truncated) {
      // A partial HTML document is unsafe to call "full page content". Let readerContent handle it.
      return null;
    }
    const body = rr.text;
    if (!body || body.length < 80) return null;

    // Plain-text endpoints can legitimately be the whole source. They still must not be telemetry/JS.
    if (/text\/plain/i.test(ct) && !JS_NOISE.test(body) && !TRACKING_MARKERS.test(body) && !isBotChallenge(body)) {
      const text = cleanContent(body, MAX_TEXT_CHARS);
      const quality = contentQuality(text, { direct: true });
      if (quality.accepted) {
        const rel = comparePageToQuery(plan.query, { ...candidate, url: finalUrl, pageContent: text });
        const out = {
          ...candidate, url: finalUrl, title: truncate(candidate.title || 'Text page', 400), domain: host(finalUrl),
          pageContent: text, extractedText: text, contentStatus: 'full', contentMethod: 'direct-text',
          contentSourceUrl: finalUrl, contentLength: text.length, contentConfidence: 0.9,
          contentTargetMatched: true, contentTitleSimilarity: rel.titleCoverage, contentConceptCoverage: rel.conceptCoverage,
          relevanceScore: rel.score, relevanceBand: rel.band, relevance: rel, qualityScore: quality.score, qualityReasons: quality.reasons,
          verified: true, httpStatus: res.status, contentType: ct || 'text/plain', verificationMethod: 'direct-text'
        };
        contentCacheSet(target, stripCached(out));
        return out;
      }
    }

    const html = body;
    const extracted = extractHtmlContent(html, finalUrl);
    if (extracted.content.length < MIN_REAL_CONTENT || isBotChallenge(extracted.content)) return null;
    if (TRACKING_MARKERS.test(extracted.content) || JS_NOISE.test(extracted.content)) return null;

    const title = extracted.title || extractMeta(html, 'og:title') || extractMeta(html, 'twitter:title') || candidate.title || '';
    const canonical = extracted.canonical && safeUrl(extracted.canonical) && !blocked(extracted.canonical) ? extracted.canonical : finalUrl;
    const publishedAt = extractMeta(html, 'article:published_time') || extractMeta(html, 'datePublished') || extractMeta(html, 'publish-date') ||
      ((html.match(/<time\b[^>]*datetime=["']([^"']+)["'][^>]*>/i) || [])[1] || null);
    const description = extractMeta(html, 'description') || extractMeta(html, 'og:description') || candidate.snippet || '';
    const quality = contentQuality(extracted.content, { structured: extracted.method === 'structured', articleContainer: /article/.test(extracted.method), direct: true });
    if (!quality.accepted) return null;
    const rel = comparePageToQuery(plan.query, { ...candidate, url: canonical, title, pageContent: extracted.content });
    const out = {
      ...candidate,
      url: canonical,
      title: truncate(title, 400),
      snippet: truncate(description, 1800),
      publishedAt,
      domain: host(canonical),
      pageContent: extracted.content,
      extractedText: extracted.content,
      contentStatus: 'full',
      contentMethod: extracted.method === 'structured' ? 'direct-html-structured' : extracted.method === 'article-marker' ? 'direct-html-article' : 'direct-html',
      contentSourceUrl: canonical,
      contentLength: extracted.content.length,
      contentConfidence: Number(clamp(0.82 + quality.score / 500, 0.82, 0.98).toFixed(3)),
      contentTargetMatched: true,
      contentTitleSimilarity: rel.titleCoverage,
      contentConceptCoverage: rel.conceptCoverage,
      relevanceScore: rel.score,
      relevanceBand: rel.band,
      relevance: rel,
      qualityScore: quality.score,
      qualityReasons: quality.reasons,
      verified: true,
      httpStatus: res.status,
      contentType: ct || 'text/html',
      verificationMethod: 'direct-html',
      language: extracted.language,
      truncated: false
    };
    contentCacheSet(target, stripCached(out));
    if (canonical !== target) contentCacheSet(canonical, stripCached(out));
    return out;
  } catch { return null; }
}

function contentCacheGet(url) {
  const key = normalizedKey(url);
  if (!key) return null;
  const hit = CONTENT_CACHE.get(key);
  if (!hit) return null;
  if (Date.now() - hit.at > CACHE_TTL_MS) { CONTENT_CACHE.delete(key); return null; }
  return hit.value;
}
function contentCacheSet(url, value) {
  const key = normalizedKey(url);
  if (!key || !value) return;
  CONTENT_CACHE.set(key, { at: Date.now(), value });
  while (CONTENT_CACHE.size > CACHE_MAX) CONTENT_CACHE.delete(CONTENT_CACHE.keys().next().value);
}

function stripCached(v) {
  const keep = {};
  for (const k of [
    'url','title','snippet','publishedAt','domain','pageContent','extractedText','contentStatus','contentMethod','contentSourceUrl',
    'contentLength','contentConfidence','contentTargetMatched','contentTitleSimilarity','contentConceptCoverage','relevanceScore',
    'relevanceBand','relevance','qualityScore','qualityReasons','verified','httpStatus','contentType','verificationMethod','language',
    'truncated','type','source','publisherResolved','publisherWrapperUrl','publisherResolutionMethod'
  ]) if (v[k] !== undefined) keep[k] = v[k];
  return keep;
}

export function isRealSourceContent(result) {
  const c = String(result?.pageContent || result?.extractedText || '').trim();
  if (!c || c.length < MIN_REAL_CONTENT) return false;
  if (result?.truncated) return false;
  if (isBotChallenge(c) || TRACKING_MARKERS.test(c) || JS_NOISE.test(c)) return false;
  const status = String(result?.contentStatus || '').toLowerCase();
  const method = String(result?.contentMethod || '').toLowerCase();
  if (['snippet','search-snippet','metadata','metadata-fallback','title-only'].includes(status)) return false;
  if (method === 'search-snippet' || method === 'metadata-fallback' || method === 'title-only') return false;
  if (blocked(result?.contentSourceUrl || result?.url)) return false;
  try {
    const h = host(result?.contentSourceUrl || result?.url);
    const pth = new URL(result?.contentSourceUrl || result?.url).pathname;
    if ((h === 'bing.com' && /^\/ck\/a(?:\/|$)/i.test(pth)) || /^\/url$/i.test(pth) || /^\/l\/?$/i.test(pth)) return false;
  } catch {}
  const quality = contentQuality(c, { reader: /jina-reader/i.test(method), direct: /direct-/i.test(method) });
  return quality.accepted && (['full','reader'].includes(status) || /direct-html|direct-pdf|jina-reader|direct-text/i.test(method));
}

function queryPlanTokens(query) {
  const raw = tokens(query);
  const canonical = raw.map(x => SYNONYM_INDEX.get(x) || x);
  return { raw, canonical };
}
function phraseHit(text, query) {
  const a = normalizeText(text);
  const b = normalizeText(query);
  return Boolean(b && a.includes(b));
}
function canonicalHits(text, planTokens) {
  const set = new Set(tokens(text).map(x => SYNONYM_INDEX.get(x) || x));
  let hits = 0;
  const matched = [];
  for (const t of planTokens) {
    const c = SYNONYM_INDEX.get(t) || t;
    if (set.has(c) || set.has(t)) { hits++; matched.push(c); }
  }
  return { hits, matched: unique(matched), ratio: planTokens.length ? hits / planTokens.length : 1 };
}

export function analyzeQuery(query, options = {}) {
  const q = truncate(String(query || '').trim(), MAX_QUERY_LEN);
  const requested = String(options.type || '').toLowerCase();
  const mode = String(options.mode || 'auto').toLowerCase();
  let type = requested;
  if (!type || type === 'mixed' || type === 'all') {
    if (mode === 'news') type = 'news';
    else if (mode === 'video') type = 'video';
    else if (mode === 'gov') type = 'gov';
    else if (mode === 'doc' || mode === 'docs' || mode === 'document') type = 'doc';
    else type = 'web';
  }
  const p = queryPlanTokens(q);
  const concepts = unique(p.canonical).map(x => ({ id:x, core:x, terms:SYNONYM_GROUPS.find(g => g[0] === x) || [x] }));
  const history = /\b(history|historical|timeline|origins?|evolution)\b/i.test(q);
  const official = /\b(official|government|govt|ministry|scheme|policy|law|act|rule|regulation|tax|gst|rbi|sebi|mca)\b/i.test(q);
  const academic = /\b(research|study|paper|academic|journal|thesis|evidence)\b/i.test(q);
  const live = /\b(latest|today|current|recent|breaking|this week|yesterday)\b/i.test(q);
  const wantsNews = /\b(news|latest|breaking|announc(?:ed|ement)|updates?)\b/i.test(q);
  const anchors = unique(q.match(/\b(?:India|Indian|[A-Z][a-z]{2,}|20\d{2})\b/g) || []);
  return {
    query:q, type, requestedType:requested, mode, tokens:p.raw, canonicalTokens:p.canonical, concepts, anchors,
    dateIntent:{ live, kind:live ? 'live' : 'none' },
    flags:{ wantsHistory:history, wantsOfficial:official, wantsAcademic:academic, wantsNews, explicitNews:type === 'news', explicitVideo:type === 'video', explicitDoc:type === 'doc', explicitGov:type === 'gov' }
  };
}

export function buildPreciseQueries(query, options = {}) {
  const plan = options.plan || analyzeQuery(query, options);
  const set = new Set();
  const add = value => {
    const x = String(value || '').replace(/"/g, '').trim();
    if (x && x.length >= 3 && x.length < 500) set.add(x);
  };
  add(plan.query);
  if (plan.canonicalTokens.length >= 2) add(`"${plan.canonicalTokens.slice(0,8).join(' ')}"`);
  if (plan.flags.wantsHistory) { add(`${plan.query} history timeline origins evolution`); add(`${plan.query} historical overview milestones`); }
  if (plan.flags.wantsOfficial) { add(`${plan.query} official source`); if (plan.flags.explicitGov) add(`${plan.query} site:gov.in`); }
  if (plan.flags.wantsAcademic) add(`${plan.query} research paper evidence`);
  if (plan.flags.wantsNews || plan.flags.explicitNews) { add(`${plan.query} latest news`); add(`${plan.query} recent developments`); }
  if (plan.flags.explicitVideo) add(`${plan.query} video YouTube`);
  if (plan.flags.explicitDoc) { add(`${plan.query} filetype:pdf`); add(`${plan.query} official PDF`); }
  return [...set].slice(0, 8);
}

function typeFits(c, plan) {
  if (plan.type === 'gov') return isGov(c.url) || c.type === 'gov';
  if (plan.type === 'doc') return isDoc(c.url) || c.type === 'doc';
  if (plan.type === 'video') return isVideo(c.url) || c.type === 'video';
  if (plan.type === 'news') return c.type === 'news' || ARTICLE_PATH.test(String(c.url || ''));
  return true;
}

export function comparePageToQuery(query, page = {}) {
  const plan = analyzeQuery(query, { type: page.type || '' });
  const title = String(page.title || '');
  const body = String(page.pageContent || page.extractedText || page.content || page.rawContent || '');
  const all = `${title} ${body}`;
  const canon = value => new Set(tokens(value).map(x => SYNONYM_INDEX.get(x) || x));
  const tset = canon(title), bset = canon(body);
  let titleHits = 0, bodyHits = 0;
  const matched = [], missing = [];
  for (const raw of plan.canonicalTokens) {
    const c = SYNONYM_INDEX.get(raw) || raw;
    if (tset.has(c)) titleHits++;
    if (bset.has(c)) { bodyHits++; matched.push(c); } else missing.push(c);
  }
  const n = Math.max(1, plan.canonicalTokens.length);
  const titleCoverage = titleHits / n;
  const bodyCoverage = bodyHits / n;
  const phrase = phraseHit(all, plan.query);
  const concept = canonicalHits(all, plan.canonicalTokens);
  let score = titleCoverage * 42 + bodyCoverage * 42 + (phrase ? 8 : 0) + concept.ratio * 18;
  if (isGov(page.url) && plan.flags.wantsOfficial) score += 7;
  if (isTrusted(page.url) && (plan.flags.wantsOfficial || plan.flags.wantsAcademic)) score += 5;
  if (ARTICLE_PATH.test(String(page.url || '')) && (plan.flags.wantsHistory || plan.flags.wantsAcademic)) score += 3;
  if (plan.flags.wantsHistory && !concept.matched.includes('history') && /\b(new cars?|upcoming cars?|car prices?|buy a car|best cars?)\b/i.test(all)) score -= 18;
  if (plan.type === 'gov' && !isGov(page.url) && page.type !== 'gov') score -= 10;
  if (plan.type === 'doc' && !isDoc(page.url) && page.type !== 'doc') score -= 10;
  if (plan.type === 'video' && !isVideo(page.url) && page.type !== 'video') score -= 12;
  if (plan.type === 'news' && page.type !== 'news' && !ARTICLE_PATH.test(String(page.url || ''))) score -= 12;
  const hasAny = titleHits > 0 || bodyHits > 0 || phrase;
  const acceptable = hasAny && body.length >= MIN_REAL_CONTENT;
  const band = score >= 78 ? 'excellent' : score >= 58 ? 'strong' : score >= 36 ? 'usable' : score > 2 ? 'related' : 'weak';
  return {
    score:Number(clamp(score,0,100).toFixed(2)), titleCoverage:Number(titleCoverage.toFixed(3)), bodyCoverage:Number(bodyCoverage.toFixed(3)),
    conceptCoverage:Number(concept.ratio.toFixed(3)), matchedConcepts:unique(matched), missingConcepts:unique(missing), exactPhrase:phrase,
    acceptable, band
  };
}

export function rankCandidates(candidates, queryOrPlan, options = {}) {
  const plan = typeof queryOrPlan === 'string' ? analyzeQuery(queryOrPlan, options) : (queryOrPlan || analyzeQuery('', options));
  const list = (Array.isArray(candidates) ? candidates : []).slice(0, MAX_CANDIDATES);
  const ranked = [];
  for (const raw of list) {
    const url = candidateUrl(raw);
    if (!url || blocked(url) || !typeFits({ ...raw, url }, plan)) continue;
    const c = { ...raw, url, title:truncate(raw?.title || raw?.name || '',500), snippet:truncate(raw?.snippet || raw?.description || '',2500), type:raw?.type || 'web' };
    const preview = { ...c, pageContent:raw?.pageContent || raw?.extractedText || raw?.rawContent || '' };
    const rel = comparePageToQuery(plan.query, preview);
    ranked.push({ ...c, _relevance:rel });
  }
  ranked.sort((a,b) => (Number(b._relevance?.score||0)-Number(a._relevance?.score||0)) || (Number(b.qualityScore||0)-Number(a.qualityScore||0)) || (Number(b.semanticSearchScore||0)-Number(a.semanticSearchScore||0)));
  return ranked;
}

async function acquireCandidate(candidate, plan, deadline) {
  const original = candidateUrl(candidate);
  if (!original || blocked(original) || left(deadline) < 280) return null;

  const directJob = directContent(candidate, plan, deadline);
  const readerJob = readerContent(candidate, plan, Math.min(deadline, Date.now() + READER_TIMEOUT_MS));
  const rows = await Promise.allSettled([directJob, readerJob]);
  const valid = rows.map(r => r.status === 'fulfilled' ? r.value : null).filter(isRealSourceContent);
  if (!valid.length) return null;
  valid.sort((a,b) => {
    const methodBonus = x => /direct-html-article|direct-html-structured|direct-pdf/i.test(String(x?.contentMethod || '')) ? 5 : /jina-reader/i.test(String(x?.contentMethod || '')) ? 2 : 0;
    return (Number(b.qualityScore||0)+Number(b.relevanceScore||0)*0.2+methodBonus(b)) -
      (Number(a.qualityScore||0)+Number(a.relevanceScore||0)*0.2+methodBonus(a)) ||
      String(b.pageContent||'').length - String(a.pageContent||'').length;
  });
  const best = valid[0];
  if (best) contentCacheSet(original, stripCached(best));
  return best;
}

async function mapConcurrent(list, limit, worker) {
  const arr = Array.isArray(list) ? list : [];
  const out = new Array(arr.length);
  let cursor = 0;
  const n = Math.max(1, Math.min(limit, arr.length || 1));
  const runner = async () => {
    while (true) {
      const i = cursor++;
      if (i >= arr.length) return;
      try { out[i] = await worker(arr[i], i); } catch { out[i] = null; }
    }
  };
  await Promise.all(Array.from({ length:n }, runner));
  return out;
}

export async function enrichCandidates(candidates, queryOrPlan, options = {}) {
  const started = Date.now();
  const budgetMs = safeInt(options.budgetMs, DEFAULT_BUDGET_MS, 1_800, 9_000);
  const deadline = started + budgetMs;
  const count = safeInt(options.count, 10, 1, MAX_RESULTS);
  const plan = typeof queryOrPlan === 'string' ? analyzeQuery(queryOrPlan, options) : (queryOrPlan || analyzeQuery('', options));

  const dedupe = new Map();
  for (const raw of Array.isArray(candidates) ? candidates : []) {
    const rawUrl = candidateUrl(raw);
    const url = unwrapSearchWrapper(rawUrl);
    if (!url || blocked(url) || !typeFits({ ...raw, url }, plan)) continue;
    const key = normalizedKey(url);
    if (!key) continue;
    if (!dedupe.has(key)) {
      dedupe.set(key, {
        ...raw,
        url,
        title:truncate(raw?.title || raw?.name || '',500),
        snippet:truncate(raw?.snippet || raw?.description || '',2500),
        type:raw?.type || 'web'
      });
    }
  }

  const all = [...dedupe.values()].slice(0, MAX_CANDIDATES);
  const enriched = [];

  // A few high-value candidates can be attempted immediately, then the rest use the same
  // worker pool. We never change the candidate ranking to satisfy "count"; count is only metadata.
  const firstPass = await mapConcurrent(all, CONTENT_CONCURRENCY, c => acquireCandidate(c, plan, deadline));
  for (const row of firstPass) if (isRealSourceContent(row)) enriched.push(row);

  // A tiny retry lane catches pages that lost the direct request to a slow/JS-heavy origin.
  const got = new Set(enriched.map(x => normalizedKey(x.url)));
  const failed = all.filter(c => !got.has(normalizedKey(c.url)));
  if (failed.length && left(deadline) > 900) {
    const retryRows = await mapConcurrent(failed.slice(0, Math.min(RECOVERY_CONCURRENCY, failed.length)), RECOVERY_CONCURRENCY, c => readerContent(c, plan, deadline, READER_RETRY_TIMEOUT_MS));
    for (const row of retryRows) if (isRealSourceContent(row)) enriched.push(row);
  }

  const uniqueMap = new Map();
  for (const x of enriched) {
    const key = normalizedKey(x.url);
    if (!key) continue;
    const rel = x.relevance || comparePageToQuery(plan.query, x);
    const candidate = { ...x, relevance:rel, relevanceScore:Number(rel.score||0), relevanceBand:rel.band || 'related', contentTargetMatched:true, contentAvailable:true, relevanceAccepted:false };
    const old = uniqueMap.get(key);
    if (!old || (Number(candidate.qualityScore||0)+Number(candidate.relevanceScore||0)*0.2) > (Number(old.qualityScore||0)+Number(old.relevanceScore||0)*0.2)) uniqueMap.set(key, candidate);
  }

  const results = [...uniqueMap.values()].sort((a,b) =>
    (Number(b.relevanceScore||0)-Number(a.relevanceScore||0)) ||
    (Number(b.qualityScore||0)-Number(a.qualityScore||0)) ||
    (String(b.pageContent||'').length-String(a.pageContent||'').length)
  );

  return {
    ok:true,
    version:VERSION,
    query:plan.query,
    requestedResults:count,
    returnedResults:results.length,
    fetchedSources:results.length,
    latencyMs:Date.now()-started,
    results,
    plan,
    contentPolicy:'real-content-only',
    sourceChecker:'direct-plus-rendered-reader-acquisition-with-noise-safe-full-text-extraction',
    warnings:results.length < count ? [`${results.length} real-content pages were fetched; ${count} requested. Unreachable, blocked, title-only, analytics-only, script-only, truncated, or bot-challenge pages were not fabricated.`] : []
  };
}

export async function runAlgorithm(input = {}) {
  const query = truncate(String(input.query || input.q || '').trim(), MAX_QUERY_LEN);
  if (!query) throw new Error('MISSING_QUERY');
  const count = safeInt(input.count ?? input.limit, 10, 1, MAX_RESULTS);
  const plan = analyzeQuery(query, input);
  const candidates = Array.isArray(input.candidates) ? input.candidates : Array.isArray(input.sources) ? input.sources : [];
  return enrichCandidates(candidates, plan, { ...input, count, budgetMs:safeInt(input.budgetMs, DEFAULT_BUDGET_MS, 1_200, 9_000) });
}

function response(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers:{
      'content-type':'application/json; charset=utf-8',
      'cache-control':'no-store',
      'access-control-allow-origin':'*',
      'access-control-allow-methods':'GET, POST, OPTIONS',
      'access-control-allow-headers':'content-type, authorization, x-arix-search-key',
      'x-arix-algorithm-version':VERSION
    }
  });
}

async function readInput(req) {
  const url = new URL(req.url);
  if (req.method === 'GET') return Object.fromEntries(url.searchParams.entries());
  const raw = await req.text();
  if (raw.length > 120000) throw new Error('REQUEST_BODY_TOO_LARGE');
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return Object.fromEntries(new URLSearchParams(raw).entries()); }
}

export default async function handler(req) {
  if (req.method === 'OPTIONS') return response({ ok:true, version:VERSION });
  if (!['GET','POST'].includes(req.method)) return response({ ok:false, version:VERSION, error:'METHOD_NOT_ALLOWED' }, 405);
  try {
    return response(await runAlgorithm(await readInput(req)));
  } catch (error) {
    return response({ ok:false, version:VERSION, error:error?.message || 'ALGORITHM_FAILED' }, error?.message === 'MISSING_QUERY' ? 400 : 500);
  }
}

export const ALGORITHM_CONTRACT = Object.freeze({
  version:VERSION,
  maxResults:MAX_RESULTS,
  maxCandidates:MAX_CANDIDATES,
  realContentMinimumChars:MIN_REAL_CONTENT,
  maxPageBytes:MAX_PAGE_BYTES,
  maxTextChars:MAX_TEXT_CHARS,
  defaultBudgetMs:DEFAULT_BUDGET_MS,
  contentConcurrency:CONTENT_CONCURRENCY,
  acquisition:'direct-publisher + Jina Reader in parallel with retry',
  extraction:'structured-data + semantic-block + article-marker + visible-body fallback',
  rejection:'reject title-only, snippets, metadata, analytics, tracking, script/config, bot challenges, and truncated reads',
  ranking:'soft query comparison after content acquisition; real fetched content is not rejected solely for low relevance'
});
