/*
 * ArixAI Live Web Search / Crawler — v1.10.0
 * Vercel Edge Function, dependency-free orchestration layer.
 *
 * IMPORTANT ARCHITECTURE
 * - api/algorithm.js is the precision/content engine.
 * - This file is the discovery/orchestration layer.
 * - There is NO extra HTTP hop to algorithm.js; it is imported directly.
 * - Search snippets are discovery evidence only.
 * - When requireRealContent=true, every final result has validated source content.
 *
 * FAST PATH
 * - Parallel discovery across independent public search surfaces.
 * - No paid search dependency; discovery is keyless.
 * - Algorithm fetches page content first, then performs a light query comparison.
 * - Small bounded recovery waves only for content that failed first-pass extraction.
 * - Short warm caches for repeated queries and recently validated pages.
 *
 * COMPATIBILITY
 * - Preserves GET/POST inputs and the existing high-level response contract.
 * - Preserves mode/type/count/deep/verify/ai/commonCrawl controls.
 * - Preserves streaming JSON behavior by default.
 * - Optional SSE log mode: ?logStream=true or Accept: text/event-stream.
 */

import {
  analyzeQuery,
  buildPreciseQueries,
  enrichCandidates,
  isRealSourceContent,
} from './algorithm.js';

export const runtime = 'edge';
export const config = { runtime: 'edge' };
export const maxDuration = 300;

const VERSION = 'arix-crawler-1.11.1';
const MAX_RESULTS = 40;
const DEFAULT_RESULTS = 10;
const MAX_QUERY_LEN = 700;
const MAX_REQUEST_BODY = 100_000;

// The crawler's own wall-clock objective. External sites can still be slow or blocked.
const SEARCH_BUDGET_MS = 9_500;
const OUTPUT_MAX_SOURCES = 500;
const SEARCH_TIMEOUT_MS = 1_450;
const COMMON_CRAWL_TIMEOUT_MS = 650;
const STREAM_HEARTBEAT_MS = 1_000;

const MAX_ENGINE_REQUESTS = 24;
const SEARCH_CONCURRENCY = 24;
const MAX_DISCOVERY_RESULTS = 500;
const MAX_COMMON_CRAWL = 4;
const MAX_LIVE_LOG = 80;

const DISCOVERY_CUTOFF_MS = 2_300;
const ALGORITHM_BUDGET_MIN_MS = 1_350;
const AI_RERANK_TIMEOUT_MS = 900;

const SEARCH_CACHE_TTL_MS = 8_000;
const LIVE_SEARCH_CACHE_TTL_MS = 2_500;
const CACHE_MAX = 100;
const SEARCH_CACHE = new Map();

const COMMON_CRAWL_INDEXES = ['CC-MAIN-2026-34', 'CC-MAIN-2026-30'];

const BLOCKED_HOSTS = new Set([
  'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
  'googlesyndication.com', 'googleadservices.com', 'gstatic.com',
  'googleapis.com', 'facebook.net', 'connect.facebook.net',
  'scorecardresearch.com', 'pixel.wp.com', 'adsrvr.org',
  'amazon-adsystem.com', 'taboola.com', 'outbrain.com',
]);

const BLOCKED_EXT = /\.(?:js|mjs|cjs|css|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|tiff?|woff2?|woff|ttf|otf|eot|mp3|wav|m4a|mp4|webm|mov|avi|zip|rar|7z|exe|dmg)(?:$|[?#])/i;
const DATA_PATH = /(?:^|[\/_-])(?:analytics|gtag|ga4|collect|pixel|beacon|tracking|tracker|telemetry|consent|ads?)(?:[\/_-]|$)/i;
const ARTICLE_PATH = /(?:article|articles|story|stories|news|post|posts|blog|blogs|report|reports|press[-_]?release|explained|timeline|history)/i;

const GOV_DOMAINS = [
  'gov.in', 'nic.in', 'mygov.in', 'india.gov.in', 'pib.gov.in', 'mca.gov.in',
  'gst.gov.in', 'incometax.gov.in', 'msme.gov.in', 'education.gov.in', 'meity.gov.in',
  'rbi.org.in', 'sebi.gov.in', 'supremecourt.gov.in', 'indiacode.nic.in',
];

const TRUSTED_DOMAINS = [
  'nasa.gov', 'who.int', 'un.org', 'europa.eu', 'oecd.org', 'worldbank.org',
  'imf.org', 'ietf.org', 'w3.org', 'mozilla.org', 'developer.mozilla.org',
];

const USER_AGENT =
  'Mozilla/5.0 (compatible; ArixAI-LiveSearch/1.10.4; +https://lexis-ai-chatini.vercel.app/)';

function nowIso() { return new Date().toISOString(); }
function left(deadline) { return Math.max(0, deadline - Date.now()); }
function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
function clamp(v, a, b) { return Math.min(b, Math.max(a, v)); }
function safeInt(v, fallback, min, max) {
  const n = Number.parseInt(v, 10);
  if (!Number.isFinite(n)) return fallback;
  return clamp(n, min, max);
}
function truncate(v, max) {
  const s = String(v ?? '').trim();
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}
function encode(v) { return JSON.stringify(v); }
function env(name) {
  try { return typeof process !== 'undefined' ? String(process.env?.[name] || '').trim() : ''; }
  catch { return ''; }
}

function normalizeHost(url) {
  try { return new URL(url).hostname.toLowerCase().replace(/^www\./, ''); }
  catch { return ''; }
}
function safeUrl(url) {
  try {
    const u = new URL(url);
    if (!/^https?:$/i.test(u.protocol)) return false;
    const h = u.hostname.toLowerCase();
    if (!h || h === 'localhost' || h.endsWith('.localhost')) return false;
    if (/^(127\.|10\.|192\.168\.|169\.254\.)/.test(h)) return false;
    if (/^172\.(?:1[6-9]|2\d|3[0-1])\./.test(h)) return false;
    if (h === '::1' || h.startsWith('fc') || h.startsWith('fd')) return false;
    return true;
  } catch { return false; }
}
function blocked(url) {
  if (!url || !safeUrl(url)) return true;
  const h = normalizeHost(url);
  if ([...BLOCKED_HOSTS].some(d => h === d || h.endsWith(`.${d}`))) return true;
  try {
    const u = new URL(url);
    if (BLOCKED_EXT.test(`${u.pathname}${u.search}`)) return true;
    if (DATA_PATH.test(u.pathname)) return true;
    return false;
  } catch { return true; }
}
function isGov(url) {
  const h = normalizeHost(url);
  return GOV_DOMAINS.some(d => h === d || h.endsWith(`.${d}`));
}
function isTrusted(url) {
  const h = normalizeHost(url);
  return TRUSTED_DOMAINS.some(d => h === d || h.endsWith(`.${d}`)) || /\.edu(?:\.|$)/i.test(h) || /\.ac\.(?:in|uk|jp|nz)$/i.test(h);
}
function isYouTube(url) {
  const h = normalizeHost(url);
  return h === 'youtube.com' || h.endsWith('.youtube.com') || h === 'youtu.be';
}
function isDoc(url) { return /\.(?:pdf|docx?|xlsx?|pptx?)(?:\?|$)/i.test(url || ''); }
function isVideo(url) { return isYouTube(url) || /(?:vimeo\.com|dailymotion\.com)/i.test(normalizeHost(url)); }
function normalizedKey(url) {
  try {
    const u = new URL(url);
    u.hash = '';
    for (const k of [...u.searchParams.keys()]) if (/^(utm_|gclid$|fbclid$|msclkid$|ref$|referrer$|cmpid$|src$)/i.test(k)) u.searchParams.delete(k);
    return `${normalizeHost(u.href)}${u.pathname.replace(/\/{2,}/g, '/').replace(/\/$/, '')}${u.search}`;
  } catch { return String(url || '').toLowerCase(); }
}
function absoluteUrl(raw, base) {
  try { return new URL(String(raw || ''), base).href; } catch { return null; }
}
function unwrap(raw, base) {
  let current = absoluteUrl(raw, base);
  if (!current) return null;
  for (let depth = 0; depth < 4; depth++) {
    let u;
    try { u = new URL(current); } catch { return null; }
    const host = normalizeHost(u.href);
    let next = null;
    if (host === 'bing.com' && /^\/ck\/a/i.test(u.pathname)) {
      const encoded = u.searchParams.get('u') || u.searchParams.get('url') || u.searchParams.get('target');
      if (encoded) {
        const opts = [encoded, encoded.replace(/^a1/, '')];
        for (const opt of opts) {
          try {
            if (/^https?:\/\//i.test(decodeURIComponent(opt))) { next = decodeURIComponent(opt); break; }
          } catch {}
          try {
            let s = opt.replace(/-/g, '+').replace(/_/g, '/');
            while (s.length % 4) s += '=';
            const bin = atob(s);
            const bytes = new Uint8Array(bin.length);
            for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
            const dec = new TextDecoder().decode(bytes);
            if (/^https?:\/\//i.test(dec)) { next = dec; break; }
          } catch {}
        }
      }
    }
    if (!next && /^google\./i.test(host) && /^\/url$/i.test(u.pathname)) next = u.searchParams.get('q') || u.searchParams.get('url');
    if (!next && (host === 'duckduckgo.com' || host === 'html.duckduckgo.com') && /^\/l\/?$/i.test(u.pathname)) next = u.searchParams.get('uddg') || u.searchParams.get('u');
    if (!next && (host === 'search.yahoo.com' || host === 'r.search.yahoo.com')) {
      const ru = u.pathname.match(/\/RU=([^/]+)(?:\/|$)/i)?.[1];
      next = ru || u.searchParams.get('RU') || u.searchParams.get('url');
    }
    if (!next) break;
    const clean = absoluteUrl(decodeURIComponentSafe(next), current);
    if (!clean || clean === current) break;
    current = clean;
  }
  try {
    const u = new URL(current);
    u.hash = '';
    for (const k of [...u.searchParams.keys()]) if (/^(utm_|gclid$|fbclid$|msclkid$|ref$|referrer$|cmpid$|src$)/i.test(k)) u.searchParams.delete(k);
    return u.href;
  } catch { return null; }
}
function decodeURIComponentSafe(v) { try { return decodeURIComponent(String(v || '')); } catch { return String(v || ''); } }

async function fetchResponse(url, timeout, deadline, headers = {}) {
  const budget = Math.min(timeout, Math.max(250, left(deadline) - 100));
  if (budget <= 0) throw new Error('BUDGET_EXHAUSTED');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), budget);
  try {
    return await fetch(url, {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: {
        'user-agent': USER_AGENT,
        accept: 'text/html,application/xhtml+xml,application/xml,application/rss+xml,text/plain;q=0.9,application/pdf;q=0.85,*/*;q=0.2',
        'accept-language': 'en-IN,en;q=0.9',
        ...headers,
      },
    });
  } finally { clearTimeout(timer); }
}

async function readBody(response, maxBytes, deadline) {
  const reader = response.body?.getReader?.();
  if (!reader) return truncate(await response.text(), maxBytes);
  const chunks = [];
  let total = 0;
  try {
    while (left(deadline) > 80 && total < maxBytes) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      const room = maxBytes - total;
      const piece = value.byteLength > room ? value.slice(0, room) : value;
      chunks.push(piece);
      total += piece.byteLength;
    }
  } finally { try { await reader.cancel(); } catch {} }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder('utf-8', { fatal: false }).decode(bytes);
}

async function fetchText(url, timeout, deadline, maxBytes = 600_000, headers = {}) {
  const res = await fetchResponse(url, timeout, deadline, headers);
  if (!res.ok) throw new Error(`HTTP_${res.status}`);
  return readBody(res, maxBytes, deadline);
}

function strip(html) {
  return String(html || '')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript\b[^>]*>[\s\S]*?<\/noscript>/gi, ' ')
    .replace(/<svg\b[^>]*>[\s\S]*?<\/svg>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&').replace(/&quot;/gi, '"').replace(/&#39;/gi, "'").replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
    .replace(/\s+/g, ' ').trim();
}
function titleFromHtml(html) { return strip((String(html).match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [, ''])[1]); }
function metaFromHtml(html, name) {
  const e = String(name).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return strip((String(html).match(new RegExp(`<meta[^>]+(?:name|property)=["']${e}["'][^>]*content=["']([\\s\\S]*?)["']`, 'i')) || [, ''])[1]);
}
function dateFromHtml(html) {
  const vals = [metaFromHtml(html, 'article:published_time'), metaFromHtml(html, 'datePublished'), metaFromHtml(html, 'date'), (String(html).match(/<time[^>]+datetime=["']([^"']+)["']/i) || [, ''])[1]];
  for (const x of vals) { const t = Date.parse(x || ''); if (!Number.isNaN(t)) return new Date(t).toISOString(); }
  return null;
}

function extractSnippetAround(html, index) {
  const s = String(html || '');
  const start = Math.max(0, index - 250);
  const end = Math.min(s.length, index + 2000);
  return strip(s.slice(start, end));
}

function candidate(url, title, snippet, source, type = 'web', extra = {}) {
  const clean = unwrap(url, extra.base || 'https://example.com/');
  if (!clean || blocked(clean)) return null;
  const result = {
    title: truncate(strip(title || ''), 500),
    url: clean,
    snippet: truncate(strip(snippet || ''), 3000),
    source,
    type: ((type === 'gov' && !isGov(clean)) || (type === 'doc' && !isDoc(clean)) || (type === 'video' && !isVideo(clean))) ? 'web' : type,
    ...extra,
  };
  delete result.base;
  if (!result.title || result.title.length < 3) return null;
  return result;
}

function parseBing(html, forcedType = 'web') {
  const out = [];
  const blocks = String(html).match(/<li[^>]+class=["'][^"']*b_algo[^"']*["'][\s\S]*?<\/li>/gi) || [];
  for (const block of blocks) {
    const m = block.match(/<h2[^>]*>\s*<a[^>]+href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/i);
    if (!m) continue;
    const r = candidate(m[1], m[2], (block.match(/<p[^>]*>([\s\S]*?)<\/p>/i) || [, ''])[1], 'bing', forcedType, { base: 'https://www.bing.com/' });
    if (r) { r.searchWrapperResolved = r.url !== absoluteUrl(m[1], 'https://www.bing.com/'); out.push(r); }
  }
  return out.slice(0, 20);
}

function parseDuck(html, forcedType = 'web') {
  const out = [];
  for (const m of String(html).matchAll(/<a[^>]+class=["'][^"']*result__a[^"']*["'][^>]+href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi)) {
    const idx = m.index || 0;
    const r = candidate(m[1], m[2], extractSnippetAround(html, idx), 'duckduckgo', forcedType, { base: 'https://html.duckduckgo.com/' });
    if (r) out.push(r);
    if (out.length >= 20) break;
  }
  return out;
}

function parseYahoo(html, forcedType = 'web') {
  const out = [];
  for (const m of String(html).matchAll(/<h3[^>]*>\s*<a[^>]+href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi)) {
    const idx = m.index || 0;
    const r = candidate(m[1], m[2], extractSnippetAround(html, idx), 'yahoo', forcedType, { base: 'https://search.yahoo.com/' });
    if (r) out.push(r);
    if (out.length >= 20) break;
  }
  return out;
}

function parseMojeek(html, forcedType = 'web') {
  const out = [];
  for (const m of String(html).matchAll(/<a[^>]+class=["'][^"']*(?:ob|title|result)[^"']*["'][^>]+href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi)) {
    const r = candidate(m[1], m[2], '', 'mojeek', forcedType, { base: 'https://www.mojeek.com/' });
    if (r) out.push(r);
    if (out.length >= 20) break;
  }
  return out;
}

function parseGoogle(html, source = 'google', forcedType = 'web') {
  const out = [];
  const seen = new Set();
  const s = String(html || '');
  // Preferred parser: actual result title (<h3>) inside an outbound anchor.
  for (const m of s.matchAll(/<a[^>]+href=["']([^"']+)["'][^>]*>[\s\S]*?<h3[^>]*>([\s\S]*?)<\/h3>[\s\S]*?<\/a>/gi)) {
    let raw = m[1];
    try {
      if (raw.startsWith('/url?')) {
        const u = new URL(raw, 'https://www.google.com/');
        raw = u.searchParams.get('q') || u.searchParams.get('url') || '';
      }
    } catch {}
    const url = unwrap(raw, 'https://www.google.com/');
    if (!url || blocked(url)) continue;
    if (/google\.com$/i.test(normalizeHost(url)) && /\/search|\/url/i.test(new URL(url).pathname + new URL(url).search)) continue;
    const key = normalizedKey(url);
    if (seen.has(key)) continue;
    seen.add(key);
    const r = candidate(url, m[2], extractSnippetAround(s, m.index || 0), source, forcedType, { base: 'https://www.google.com/' });
    if (r) out.push(r);
    if (out.length >= 20) break;
  }
  // Secondary parser: title/link structures where <h3> is adjacent rather than nested.
  if (!out.length) {
    for (const m of s.matchAll(/<h3[^>]*>([\s\S]*?)<\/h3>/gi)) {
      const idx = m.index || 0;
      const window = s.slice(Math.max(0, idx - 1200), Math.min(s.length, idx + 1200));
      const href = window.match(/href=["']([^"']+)["']/i)?.[1];
      if (!href) continue;
      const url = unwrap(href, 'https://www.google.com/');
      if (!url || blocked(url)) continue;
      const r = candidate(url, m[1], strip(window), source, forcedType, { base: 'https://www.google.com/' });
      if (r && !seen.has(normalizedKey(r.url))) { seen.add(normalizedKey(r.url)); out.push(r); }
      if (out.length >= 20) break;
    }
  }
  return out;
}

function parseGoogleNews(xml) {
  const out = [];
  for (const item of String(xml || '').match(/<item>[\s\S]*?<\/item>/gi) || []) {
    const title = strip((item.match(/<title>([\s\S]*?)<\/title>/i) || [, ''])[1]);
    const link = strip((item.match(/<link>([\s\S]*?)<\/link>/i) || [, ''])[1]);
    const pub = strip((item.match(/<pubDate>([\s\S]*?)<\/pubDate>/i) || [, ''])[1]);
    const desc = strip((item.match(/<description>([\s\S]*?)<\/description>/i) || [, ''])[1]);
    const sm = item.match(/<source[^>]*url=["']([^"']+)["'][^>]*>([\s\S]*?)<\/source>/i) || item.match(/<source[^>]*>([\s\S]*?)<\/source>/i);
    const sourceName = strip(sm?.[2] || sm?.[1] || '');
    const sourceUrl = sm?.[1] ? unwrap(sm[1], 'https://news.google.com/') : null;
    const url = unwrap(link, 'https://news.google.com/');
    if (!title || !url) continue;
    const r = candidate(url, title, desc, sourceName ? `google-news:${sourceName}` : 'google-news', 'news');
    if (!r) continue;
    r.publishedAt = safeDate(pub);
    r.publisherUrl = sourceUrl || null;
    out.push(r);
    if (out.length >= 80) break;
  }
  return out;
}

function parseYoutube(html) {
  const out = [];
  const seen = new Set();
  const s = String(html || '');
  for (const m of s.matchAll(/"videoRenderer":\{[\s\S]*?"videoId":"([A-Za-z0-9_-]{6,20})"[\s\S]*?"title":\{"runs":\[\{"text":"((?:\\.|[^"\\])*)"/g)) {
    const id = m[1];
    if (seen.has(id)) continue;
    seen.add(id);
    const title = m[2].replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    const r = candidate(`https://www.youtube.com/watch?v=${id}`, title, 'YouTube result', 'youtube', 'video');
    if (r) out.push(r);
    if (out.length >= 20) break;
  }
  if (!out.length) {
    for (const m of s.matchAll(/"videoId":"([A-Za-z0-9_-]{6,20})"/g)) {
      const id = m[1];
      if (seen.has(id)) continue;
      seen.add(id);
      const r = candidate(`https://www.youtube.com/watch?v=${id}`, `YouTube video ${id}`, 'YouTube result', 'youtube', 'video');
      if (r) out.push(r);
      if (out.length >= 20) break;
    }
  }
  return out;
}

function safeDate(value) {
  const t = Date.parse(String(value || ''));
  return Number.isNaN(t) ? null : new Date(t).toISOString();
}
function freshness(publishedAt) {
  if (!publishedAt) return 'unknown';
  const age = Math.max(0, (Date.now() - Date.parse(publishedAt)) / 86400000);
  if (age <= 1) return 'last_24h';
  if (age <= 7) return 'last_7d';
  if (age <= 30) return 'last_30d';
  if (age <= 90) return 'last_90d';
  if (age <= 365) return 'last_year';
  return 'older';
}

function providerRequests(queries, plan, count) {
  const final = [];
  const seen = new Set();
  const add = (provider, q, type, url) => {
    if (final.length >= MAX_ENGINE_REQUESTS || seen.has(url)) return;
    seen.add(url); final.push({ provider, query:q, type, url });
  };
  const qs = queries.slice(0, 4);
  const isSpecial = plan.type === 'news' || plan.type === 'video' || plan.type === 'doc' || plan.type === 'gov';

  // Give Bing a few result pages because it is often the only public HTML surface
  // available from a serverless runtime. Pagination is parallel and still bounded.
  const e0 = encodeURIComponent(qs[0] || '');
  for (const first of [0,10,20,30]) add('bing', qs[0], plan.type === 'news' ? 'news' : 'web', `https://www.bing.com/search?q=${e0}&count=10&first=${first}&setlang=en-IN&cc=in`);

  // Other engines receive the precise query variants, providing domain diversity.
  for (const q of qs) {
    const e = encodeURIComponent(q);
    add('google', q, plan.type === 'news' ? 'news' : 'web', `https://www.google.com/search?q=${e}&num=20&hl=en&gl=in`);
    add('duckduckgo', q, plan.type === 'news' ? 'news' : 'web', `https://html.duckduckgo.com/html/?q=${e}&kl=in-en`);
    add('yahoo', q, plan.type === 'news' ? 'news' : 'web', `https://search.yahoo.com/search?p=${e}`);
    add('mojeek', q, plan.type === 'news' ? 'news' : 'web', `https://www.mojeek.com/search?q=${e}`);
  }

  // Requested special surfaces are additive, never a replacement for core web search.
  if (plan.type === 'news' || plan.flags?.explicitNews) {
    for (const q of qs.slice(0,2)) add('google-news', q, 'news', `https://news.google.com/rss/search?q=${encodeURIComponent(q)}&hl=en-IN&gl=IN&ceid=IN:en`);
  }
  if (plan.type === 'video' || plan.flags?.explicitVideo) {
    for (const q of qs.slice(0,2)) {
      add('youtube', q, 'video', `https://www.youtube.com/results?search_query=${encodeURIComponent(q)}&hl=en-IN`);
      add('google-video', q, 'video', `https://www.google.com/search?q=${encodeURIComponent(`site:youtube.com ${q}`)}&num=20&hl=en&gl=in`);
    }
  }
  if (plan.type === 'doc' || plan.flags?.explicitDoc) {
    for (const q of qs.slice(0,2)) add('google-doc', q, 'doc', `https://www.google.com/search?q=${encodeURIComponent(`${q} filetype:pdf`)}&num=20&hl=en&gl=in`);
  }
  if (plan.type === 'gov' || plan.flags?.explicitGov) {
    for (const q of qs.slice(0,2)) add('google-gov', q, 'gov', `https://www.google.com/search?q=${encodeURIComponent(`${q} site:gov.in`)}&num=20&hl=en&gl=in`);
  }

  void count; void isSpecial;
  return final.slice(0, MAX_ENGINE_REQUESTS);
}
async function discoverOne(req, deadline) {
  try {
    const body = await fetchText(req.url, SEARCH_TIMEOUT_MS, deadline, 700_000);
    let results = [];
    if (req.provider === 'bing') results = parseBing(body, req.type);
    else if (req.provider === 'google') results = parseGoogle(body, 'google', req.type);
    else if (req.provider === 'google-video') results = parseGoogle(body, 'google-video', 'video');
    else if (req.provider === 'duckduckgo') results = parseDuck(body, req.type);
    else if (req.provider === 'yahoo') results = parseYahoo(body, req.type);
    else if (req.provider === 'mojeek') results = parseMojeek(body, req.type);
    else if (req.provider === 'google-news') results = parseGoogleNews(body);
    else if (req.provider === 'youtube') results = parseYoutube(body);
    else if (req.provider === 'google-doc') results = parseGoogle(body, 'google-doc', 'doc');
    else if (req.provider === 'google-gov') results = parseGoogle(body, 'google-gov', 'gov');
    return { provider: req.provider, ok: true, results };
  } catch (error) {
    return { provider: req.provider, ok: false, results: [], error: error?.message || 'DISCOVERY_FAILED' };
  }
}

function dedupeCandidates(list) {
  const map = new Map();
  for (const raw of list || []) {
    if (!raw) continue;
    const url = unwrap(raw.url || raw.link || raw.sourceUrl || '', raw.base || 'https://example.com/');
    if (!url || blocked(url)) continue;
    const item = { ...raw, url };
    const key = normalizedKey(url);
    const old = map.get(key);
    if (!old) map.set(key, item);
    else {
      const oldContent = String(old.rawContent || old.pageContent || '').length;
      const newContent = String(item.rawContent || item.pageContent || '').length;
      const merged = { ...old, ...item };
      if (newContent < oldContent) {
        merged.rawContent = old.rawContent;
        merged.pageContent = old.pageContent;
      }
      if (!merged.snippet && old.snippet) merged.snippet = old.snippet;
      map.set(key, merged);
    }
  }
  return [...map.values()].slice(0, MAX_DISCOVERY_RESULTS);
}

async function groqRerank(query, results, deadline) {
  const key = env('GROQ_API_KEY');
  if (!key || results.length < 3 || left(deadline) < 520) return null;
  const controller = new AbortController();
  const timeout = Math.min(AI_RERANK_TIMEOUT_MS, Math.max(450, left(deadline) - 100));
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const payload = results.slice(0, 30).map((r, i) => ({ id: i, title: truncate(r.title, 180), domain: normalizeHost(r.url), type: r.type, relevanceScore: r.relevanceScore, snippet: truncate(r.snippet, 240) }));
    const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      signal: controller.signal,
      headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        model: 'openai/gpt-oss-20b',
        messages: [
          { role: 'system', content: 'Return JSON only. Reorder provided source IDs for relevance to the user query. Never invent or remove IDs. Prefer exact topic, source quality, requested type and direct evidence.' },
          { role: 'user', content: JSON.stringify({ query, results: payload, output: { order: [0, 1, 2] } }) },
        ],
        temperature: 0,
        max_completion_tokens: 450,
      }),
    });
    if (!res.ok) return null;
    const data = await res.json();
    const text = String(data?.choices?.[0]?.message?.content || '');
    const obj = JSON.parse(text.match(/\{[\s\S]*\}/)?.[0] || text);
    if (!Array.isArray(obj?.order)) return null;
    return obj.order.map(Number).filter(Number.isInteger).filter(i => i >= 0 && i < results.length);
  } catch { return null; }
  finally { clearTimeout(timer); }
}

function relevanceAcceptable(result, plan) {
  if (!result || !isRealSourceContent(result)) return false;
  const type = plan.type;
  if (type === 'gov' && !(isGov(result.url) || result.type === 'gov')) return false;
  if (type === 'doc' && !(isDoc(result.url) || result.type === 'doc')) return false;
  if (type === 'video' && !(isVideo(result.url) || result.type === 'video')) return false;
  if (type === 'news' && !(result.type === 'news' || ARTICLE_PATH.test(result.url))) return false;

  const rel = result.relevance || {};
  const score = Number(result.relevanceScore || 0);
  const concept = Number(result.contentConceptCoverage ?? rel.conceptCoverage ?? 0);
  const title = Number(result.contentTitleSimilarity ?? rel.titleCoverage ?? 0);
  const band = String(result.relevanceBand || '').toLowerCase();

  if (band === 'excellent' || band === 'strong') return true;
  if (score >= 54 && concept >= 0.35) return true;
  if (score >= 46 && concept >= 0.45 && title >= 0.2) return true;
  if (plan.flags?.wantsHistory && Array.isArray(rel.mismatchTerms) && rel.mismatchTerms.length) return false;
  if (score >= 42 && concept >= 0.5) return true;
  return false;
}

function diversifyFinal(results, count) {
  const pool = [...results].sort((a, b) => Number(b.relevanceScore || 0) - Number(a.relevanceScore || 0));
  const selected = [];
  const domainCounts = new Map();
  const topicSeen = new Map();
  while (selected.length < count && pool.length) {
    let bestIndex = 0;
    let bestScore = -Infinity;
    for (let i = 0; i < pool.length; i++) {
      const r = pool[i];
      const d = normalizeHost(r.url);
      const base = Number(r.relevanceScore || 0);
      const domainPenalty = Math.min(8, (domainCounts.get(d) || 0) * 2.2);
      const freshnessBonus = freshness(r.publishedAt) === 'last_24h' ? 3 : freshness(r.publishedAt) === 'last_7d' ? 2 : 0;
      const typeBonus = r.type === 'news' || r.type === 'gov' || r.type === 'doc' ? 1 : 0;
      const novelty = (r.relevance?.matchedConcepts || []).reduce((sum, x) => sum + 1 / (1 + (topicSeen.get(x) || 0)), 0);
      const adjusted = base - domainPenalty + freshnessBonus + typeBonus + novelty;
      if (adjusted > bestScore) { bestScore = adjusted; bestIndex = i; }
    }
    const chosen = pool.splice(bestIndex, 1)[0];
    selected.push(chosen);
    const d = normalizeHost(chosen.url);
    domainCounts.set(d, (domainCounts.get(d) || 0) + 1);
    for (const g of chosen.relevance?.matchedConcepts || []) topicSeen.set(g, (topicSeen.get(g) || 0) + 1);
  }
  return selected;
}

async function commonCrawlMeta(url, deadline) {
  if (!safeUrl(url) || left(deadline) < 350) return null;
  const encoded = encodeURIComponent(url);
  for (const index of COMMON_CRAWL_INDEXES) {
    if (left(deadline) < 300) break;
    try {
      const body = await fetchText(`https://index.commoncrawl.org/${index}-index?url=${encoded}&output=json&filter=status:200&limit=1`, COMMON_CRAWL_TIMEOUT_MS, deadline, 40_000, { accept: 'application/json,text/plain;q=0.8' });
      const row = body.split('\n').map(x => { try { return JSON.parse(x); } catch { return null; } }).find(Boolean);
      if (row) return { index, timestamp: row.timestamp || null, digest: row.digest || null };
    } catch {}
  }
  return null;
}

function createLogger() {
  const logs = [];
  const add = (event, message, extra = {}) => {
    const item = { at: nowIso(), event, message, ...extra };
    logs.push(item);
    if (logs.length > MAX_LIVE_LOG) logs.shift();
    try { console.log(`[ArixAI ${event}] ${message}`); } catch {}
  };
  return { logs, add };
}

function cacheGet(key) {
  const item = SEARCH_CACHE.get(key);
  if (!item) return null;
  if (Date.now() - item.at > item.ttl) { SEARCH_CACHE.delete(key); return null; }
  return item.value;
}
function cacheSet(key, value, ttl) {
  SEARCH_CACHE.set(key, { at: Date.now(), value, ttl });
  while (SEARCH_CACHE.size > CACHE_MAX) SEARCH_CACHE.delete(SEARCH_CACHE.keys().next().value);
}

function cacheKey(input, query, count, plan) {
  return JSON.stringify({
    q: query, c: count, mode: String(input.mode || 'auto').toLowerCase(), type: plan.type,
    deep: String(input.deep || '').toLowerCase(), verify: String(input.verify ?? true).toLowerCase(),
    requireRealContent: String(input.requireRealContent ?? true).toLowerCase(),
  });
}

function selectCacheTtl(plan) { return plan.dateIntent?.kind === 'live' ? LIVE_SEARCH_CACHE_TTL_MS : SEARCH_CACHE_TTL_MS; }

async function resolveNewsCandidate(candidate, deadline) {
  if (normalizeHost(candidate.url) !== 'news.google.com') return candidate;
  try {
    const res = await fetchResponse(candidate.url, 1000, deadline, { accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1' });
    const finalUrl = unwrap(res.url || candidate.url, candidate.url);
    if (finalUrl && normalizeHost(finalUrl) !== 'news.google.com' && safeUrl(finalUrl) && !blocked(finalUrl)) {
      try { await res.body?.cancel?.(); } catch {}
      return { ...candidate, url: finalUrl, publisherResolved: true, publisherWrapperUrl: candidate.url, publisherResolutionMethod: 'redirect', contentSourceUrl: finalUrl };
    }
    const raw = await readBody(res, 220_000, deadline).catch(() => '');
    const link = raw.match(/<a[^>]+href=["']([^"']+)["'][^>]*>([\s\S]*?)<\/a>/gi)
      ?.map(x => {
        const href = x.match(/href=["']([^"']+)["']/i)?.[1];
        const text = strip(x.replace(/<[^>]+>/g, ' '));
        return { href: unwrap(href, candidate.url), text };
      })
      .filter(x => x.href && normalizeHost(x.href) !== 'news.google.com' && x.text.length > 8)
      .sort((a,b) => tokenSimilarity(candidate.title, a.text) - tokenSimilarity(candidate.title, b.text))
      .pop();
    if (link?.href) return { ...candidate, url: link.href, publisherResolved: true, publisherWrapperUrl: candidate.url, publisherResolutionMethod: 'embedded-link', contentSourceUrl: link.href };
  } catch {}
  return { ...candidate, _newsWrapperUnresolved: true };
}

function tokenSimilarity(a, b) {
  const aa = new Set(String(a || '').toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(x => x.length > 2));
  const bb = new Set(String(b || '').toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(x => x.length > 2));
  if (!aa.size || !bb.size) return 0;
  let hit = 0; for (const x of aa) if (bb.has(x)) hit++;
  return hit / Math.max(aa.size, bb.size);
}

async function performSearch(input, started, logger) {
  const deadline = started + SEARCH_BUDGET_MS;
  const query = truncate(String(input.query ?? input.q ?? '').trim(), MAX_QUERY_LEN);
  const count = safeInt(input.count ?? input.limit, DEFAULT_RESULTS, 1, MAX_RESULTS);
  const mode = String(input.mode || 'auto').toLowerCase();
  const requestedType = String(input.type || '').toLowerCase();
  const deep = String(input.deep ?? 'false').toLowerCase() === 'true';
  const aiRequested = String(input.ai ?? input.useAi ?? 'auto').toLowerCase();
  const verifyRequested = input.verify == null ? true : String(input.verify).toLowerCase() !== 'false';
  const useCc = String(input.commonCrawl ?? 'false').toLowerCase() === 'true';
  const requireRealContent = input.requireRealContent == null ? true : String(input.requireRealContent).toLowerCase() !== 'false';

  const plan = analyzeQuery(query, { mode, type: requestedType });
  const key = cacheKey(input, query, count, plan);
  const cached = cacheGet(key);
  if (cached) {
    logger.add('cache-hit', `Returned warm cached search for ${query}.`, { count: cached.returnedResults });
    return { ...cached, generatedAt: nowIso(), latencyMs: Date.now() - started, cached: true, liveLog: logger.logs };
  }

  logger.add('query-analyzed', 'Precision query analysis completed.', {
    type: plan.type,
    concepts: plan.concepts.map(x => x.id),
    dateIntent: plan.dateIntent.kind,
  });

  const preciseQueries = buildPreciseQueries(query, { plan });
  const requests = providerRequests(preciseQueries, plan, count);
  logger.add('discovery-start', `Launching ${requests.length} parallel discovery requests.`, { queries: preciseQueries.slice(0, 8) });

  const discoveryDeadline = Math.min(deadline, started + DISCOVERY_CUTOFF_MS);
  const discoveries = await Promise.allSettled(requests.map(r => discoverOne(r, discoveryDeadline)));

  const providerStats = {};
  let discovered = [];
  let discoveryOk = 0;
  for (const entry of discoveries) {
    if (entry.status !== 'fulfilled') continue;
    const item = entry.value;
    providerStats[item.provider] = providerStats[item.provider] || { ok: 0, failed: 0, results: 0 };
    if (item.ok) { providerStats[item.provider].ok++; discoveryOk++; }
    else providerStats[item.provider].failed++;
    providerStats[item.provider].results += item.results.length;
    discovered.push(...item.results);
  }
  discovered = dedupeCandidates(discovered);
  logger.add('url-normalization', `Normalized discovery URLs before content acquisition.`, {
    candidates: discovered.length,
    bingWrappersRemaining: discovered.filter(r => /(?:^https?:\/\/)?(?:www\.)?bing\.com\/ck\/a(?:[/?]|$)/i.test(String(r?.url || ''))).length,
  });

  const newsWrappers = discovered.filter(r => r.type === 'news' && normalizeHost(r.url) === 'news.google.com').slice(0, 8);
  if (newsWrappers.length && left(deadline) > 6_000) {
    logger.add('news-resolution-start', `Resolving ${newsWrappers.length} news aggregator links in parallel.`);
    const resolved = await Promise.all(newsWrappers.map(r => resolveNewsCandidate(r, deadline)));
    const by = new Map(resolved.map(r => [normalizedKey(r.publisherWrapperUrl || r.url), r]));
    discovered = discovered.map(r => by.get(normalizedKey(r.url)) || r).filter(r => !r._newsWrapperUnresolved);
    logger.add('news-resolution-complete', `News resolution left ${discovered.filter(r => r.type === 'news').length} usable news candidates.`);
  } else {
    discovered = discovered.filter(r => normalizeHost(r.url) !== 'news.google.com' || r.publisherResolved);
  }

  logger.add('discovery-complete', `Discovery produced ${discovered.length} unique candidates.`, {
    successfulProviders: discoveryOk,
    sourceCandidates: discovered.length,
  });

  if (!discovered.length) {
    logger.add('discovery-empty', 'No search candidates were returned by the available public surfaces.');
  }

  // Preserve the complete discovered pool. The decisive relevance comparison happens only AFTER page fetch.
  const ranked = [...discovered];
  const acquisitionPool = [...discovered].sort((a,b) => {
    const ap = Number(a?.semanticSearchScore ?? 0), bp = Number(b?.semanticSearchScore ?? 0);
    if (bp !== ap) return bp - ap;
    return String(a?.title || '').length - String(b?.title || '').length;
  });
  logger.add('ranking-complete', `Prepared ${acquisitionPool.length} candidates for page acquisition; no relevance cutoff is applied before fetch.`);

  if (!verifyRequested) {
    const metadataOnly = diversifyFinal(ranked.slice(0, count).map(r => ({
      ...r,
      relevanceScore: Math.round(r._relevance?.score || 0),
      relevanceBand: r._relevance?.band || 'weak-match',
      verified: false,
      pageContent: '', extractedText: '', contentAvailable: false,
    })), count);
    const final = metadataOnly.map((r, i) => formatResult(r, i, plan, false));
    const result = buildResponse({ query, count, mode, requestedType, plan, preciseQueries, providerStats, final, logger, started, verifyRequested, requireRealContent, useCc, deep, aiRequested });
    cacheSet(key, result, selectCacheTtl(plan));
    return result;
  }

  // Fetch pages first. The checker then performs only a lightweight query comparison.
  const contentCandidates = acquisitionPool.slice(0, MAX_DISCOVERY_RESULTS);
  logger.add('content-start', `Fetching real page content for ${contentCandidates.length} candidates concurrently.`);

  const algorithmBudget = Math.max(1_350, Math.min(7_800, left(deadline) - 160));
  let enriched = [];
  try {
    const checked = await enrichCandidates(contentCandidates, plan, {
      count,
      requireRealContent: true,
      budgetMs: algorithmBudget,
    });
    enriched = Array.isArray(checked?.results) ? checked.results.filter(isRealSourceContent) : [];
  } catch (error) {
    logger.add('content-failed', 'The page-content checker failed safely.', { error: error?.message || 'CONTENT_CHECK_FAILED' });
  }
  logger.add('content-complete', `Page fetch + query comparison produced ${enriched.length} real-content sources.`, {
    candidates: contentCandidates.length,
    returned: enriched.length,
  });

  // Final selection is intentionally soft: all returned sources have real page content;
  // relevance only determines ordering, not a brittle score cutoff.
  const finalPool = [...new Map(enriched.filter(isRealSourceContent).map(r => [normalizedKey(r.url), r])).values()].slice(0, OUTPUT_MAX_SOURCES)
    .map(r => ({ ...r, _score: Number(r.relevanceScore || 0) }))
    .sort((a, b) => Number(b.relevanceScore || 0) - Number(a.relevanceScore || 0));

  // Requested count controls how many the user asked for, but does NOT truncate the fetched source set.
  // Return every unique source for which real page content was obtained.
  const chosen = finalPool;
  const contentAcquisition = {
    discoveredCandidates: acquisitionPool.length,
    attemptedCandidates: contentCandidates.length,
    realContentSources: enriched.length,
    wrapperCandidatesBeforeFetch: contentCandidates.filter(r => /(?:^https?:\/\/)?(?:www\.)?bing\.com\/ck\/a(?:[/?]|$)/i.test(String(r?.url || ''))).length,
    contentPolicy: 'real-content-only',
  };
  let commonCrawlRows = [];
  if (useCc && chosen.length && left(deadline) > 550) {
    const ccDeadline = Date.now() + Math.min(500, left(deadline) - 50);
    commonCrawlRows = await Promise.all(chosen.slice(0, MAX_COMMON_CRAWL).map(async r => ({ url: r.url, cc: await commonCrawlMeta(r.url, ccDeadline) })));
  }
  const ccMap = new Map(commonCrawlRows.filter(x => x?.cc).map(x => [normalizedKey(x.url), x.cc]));

  const final = chosen.map((r, i) => formatResult({ ...r, commonCrawl: ccMap.get(normalizedKey(r.url)) || null }, i, plan, true));
  const result = buildResponse({ query, count, mode, requestedType, plan, preciseQueries, providerStats, final, logger, started, verifyRequested, requireRealContent, useCc, deep, aiRequested, contentAcquisition });
  cacheSet(key, result, selectCacheTtl(plan));
  return result;
}

function formatResult(r, i, plan, realContent) {
  const content = realContent ? String(r.pageContent || r.extractedText || '').trim() : '';
  const relevanceScore = Math.round(Number(r.relevanceScore ?? r._relevance?.score ?? 0));
  const rel = r.relevance || {
    titleCoverage: r._relevance?.titleCoverage ?? 0,
    bodyCoverage: r._relevance?.bodyCoverage ?? 0,
    conceptCoverage: r._relevance?.conceptCoverage ?? 0,
    matchedConcepts: r._relevance?.hits ?? [],
    missingConcepts: r._relevance?.missing ?? [],
    exactPhrase: Boolean(r._relevance?.phraseExact),
    mismatchTerms: r._relevance?.mismatchTerms ?? [],
  };
  return {
    rank: i + 1,
    title: truncate(r.title || 'Untitled', 300),
    url: r.url,
    domain: normalizeHost(r.url),
    type: isGov(r.url) ? 'gov' : isDoc(r.url) ? 'doc' : isVideo(r.url) ? 'video' : (r.type || 'web'),
    source: r.source || 'search',
    snippet: truncate(r.snippet || '', 1200),
    publishedAt: r.publishedAt || null,
    freshness: freshness(r.publishedAt),
    verified: Boolean(realContent && (r.verified !== false)),
    httpStatus: r.httpStatus || null,
    contentType: r.contentType || null,
    trust: Number((r.trust ?? (isGov(r.url) ? 1 : isTrusted(r.url) ? 0.95 : 0.6)).toFixed(2)),
    relevanceScore: relevanceScore,
    relevanceBand: r.relevanceBand || r._relevance?.band || (relevanceScore >= 75 ? 'excellent' : relevanceScore >= 58 ? 'strong' : relevanceScore >= 42 ? 'usable' : 'weak-match'),
    relevance: rel,
    publisherResolved: Boolean(r.publisherResolved),
    publisherWrapperUrl: r.publisherWrapperUrl || null,
    publisherResolutionMethod: r.publisherResolutionMethod || null,
    searchWrapperResolved: Boolean(r.searchWrapperResolved),
    searchWrapperProvider: r.searchWrapperProvider || null,
    extractedText: content,
    pageContent: content,
    contentAvailable: Boolean(realContent && content),
    contentStatus: r.contentStatus || (realContent ? 'full' : 'metadata'),
    contentMethod: r.contentMethod || r.validatedBy || 'algorithm',
    contentLength: content.length,
    contentConfidence: Number(r.contentConfidence ?? (realContent ? 0.9 : 0)),
    contentSourceUrl: r.contentSourceUrl || r.url,
    contentTargetMatched: Boolean(r.contentTargetMatched ?? realContent),
    contentTitleSimilarity: Number(r.contentTitleSimilarity ?? r.contentTitleSimilarity ?? rel.titleCoverage ?? 0).toFixed(3),
    contentConceptCoverage: Number(r.contentConceptCoverage ?? rel.conceptCoverage ?? 0).toFixed(3),
    contentFormat: 'plain_text',
    contentRole: realContent ? 'publisher_page_content' : 'search_metadata_only',
    contentForAI: realContent ? `SOURCE_URL: ${r.contentSourceUrl || r.url}\nTITLE: ${truncate(r.title || '', 300)}\nCONTENT_STATUS: ${r.contentStatus || 'full'}\n\n${content}` : '',
    verificationMethod: r.verificationMethod || r.validatedBy || null,
    transcript: r.transcript || null,
    transcriptAvailable: Boolean(r.transcriptAvailable),
    transcriptLanguage: r.transcriptLanguage || null,
    commonCrawl: r.commonCrawl || null,
    queryMatch: {
      planType: plan.type,
      dateIntent: plan.dateIntent?.kind || 'none',
      concepts: plan.concepts.map(x => x.id),
    },
  };
}

function buildResponse({ query, count, mode, requestedType, plan, preciseQueries, providerStats, final, logger, started, verifyRequested, requireRealContent, useCc, deep, aiRequested, contentAcquisition = null }) {
  const validationCount = final.filter(r => r.contentAvailable).length;
  const result = {
    ok: true,
    version: VERSION,
    query,
    requestedResults: count,
    returnedResults: final.length,
    sourceCountMode: 'all-fetched-real-content',
      resultSelectionPolicy: 'return-all-fetched-real-content-ranked-by-query-match',
    mode,
    intent: {
      type: requestedType || plan.type,
      wantsNews: plan.type === 'news' || Boolean(plan.flags?.explicitNews) || Boolean(plan.flags?.wantsNews),
      wantsVideo: plan.type === 'video' || Boolean(plan.flags?.explicitVideo),
      wantsGov: plan.type === 'gov' || Boolean(plan.flags?.explicitGov) || Boolean(plan.flags?.wantsOfficial && plan.flags?.explicitGov),
      wantsDocs: plan.type === 'doc' || Boolean(plan.flags?.explicitDoc),
      wantsHistory: Boolean(plan.flags?.wantsHistory),
      wantsAcademic: Boolean(plan.flags?.wantsAcademic),
    },
    generatedAt: nowIso(),
    latencyMs: Date.now() - started,
    keylessCoreSearch: true,
    groqUsed: aiRequested === 'true' && logger.logs.some(x => x.event === 'ai-rerank-complete'),
    cached: false,
    providers: providerStats,
    quality: {
      validatedResults: validationCount,
      relevantResults: final.filter(r => r.relevanceScore >= 54).length,
      requestedResults: count,
      realContentOnly: requireRealContent,
      contentGuarantee: 'Every returned result contains fetched source content; relevance only ranks results and never removes fetched content.',
    },
    searchPlan: {
      queryVariants: preciseQueries,
      engineRequests: Object.values(providerStats).reduce((s, p) => s + Number(p.ok || 0) + Number(p.failed || 0), 0),
      verificationRequested: verifyRequested,
      verificationPerformed: validationCount,
      verificationSucceeded: validationCount,
      commonCrawlEnabled: useCc,
      commonCrawlPerformed: final.filter(r => r.commonCrawl).length,
      dateIntent: plan.dateIntent,
      streamed: true,
      logStreamSupported: true,
      requireRealContent,
      latencyTargetMs: SEARCH_BUDGET_MS,
      deep,
      aiRequested,
    },
    liveLog: logger.logs,
    results: final,
    allFetchedSources: final.length,
    contentAcquisition,
    warnings: [],
  };
  if (requireRealContent && final.length < count) result.warnings.push(`${final.length} fetched pages produced real content within the crawler budget; ${count} were requested. Unreadable pages were excluded and never replaced with snippets.`);
  if (requireRealContent && final.length === 0) result.warnings.push('No real page content was accepted. Check contentAcquisition.wrapperCandidatesBeforeFetch, the resolved publisher URLs, and the deployed algorithm.js version.');
  if (!final.length) result.warnings.push('No real page content completed within the crawler budget; search snippets were never promoted to pageContent.');
  if (result.latencyMs > SEARCH_BUDGET_MS) result.warnings.push('The outer platform/runtime may have added latency beyond the crawler work budget.');
  return result;
}

async function readInput(req) {
  const url = new URL(req.url);
  if (req.method === 'GET') return Object.fromEntries(url.searchParams.entries());
  const raw = await req.text();
  if (raw.length > MAX_REQUEST_BODY) throw new Error('REQUEST_BODY_TOO_LARGE');
  if (!raw) return {};
  try { return JSON.parse(raw); } catch { return Object.fromEntries(new URLSearchParams(raw).entries()); }
}

function corsHeaders(contentType = 'application/json; charset=utf-8') {
  return {
    'content-type': contentType,
    'cache-control': 'no-store, no-transform',
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET,POST,OPTIONS',
    'access-control-allow-headers': 'content-type, authorization, x-arix-search-key',
    'x-arix-crawler-version': VERSION,
  };
}

function jsonResponse(body, status = 200) { return new Response(JSON.stringify(body, null, 2), { status, headers: corsHeaders() }); }

function streamJsonSearch(input) {
  const encoder = new TextEncoder();
  const started = Date.now();
  const logger = createLogger();
  const query = truncate(String(input.query ?? input.q ?? '').trim(), MAX_QUERY_LEN);
  const count = safeInt(input.count ?? input.limit, DEFAULT_RESULTS, 1, MAX_RESULTS);
  const mode = String(input.mode || 'auto').toLowerCase();
  const deadline = started + SEARCH_BUDGET_MS;

  const stream = new ReadableStream({
    start(controller) {
      let closed = false;
      const send = chunk => { if (!closed) { try { controller.enqueue(encoder.encode(chunk)); } catch { closed = true; } } };
      logger.add('request-start', `Starting live search for ${query}.`, { count, mode });
      send(`{"ok":true,"version":${encode(VERSION)},"query":${encode(query)},"requestedResults":${count},"mode":${encode(mode)},"streaming":true,"results":[`);
      const heartbeat = setInterval(() => send('\n'), STREAM_HEARTBEAT_MS);
      Promise.resolve().then(() => performSearch(input, started, logger, deadline)).then(result => {
        clearInterval(heartbeat);
        const results = Array.isArray(result.results) ? result.results : [];
        results.forEach((r, i) => send(`${i ? ',' : ''}${JSON.stringify(r)}`));
        const metadata = { ...result };
        delete metadata.results;
        send('],');
        const entries = Object.entries(metadata);
        entries.forEach(([k, v], i) => send(`${JSON.stringify(k)}:${JSON.stringify(v)}${i === entries.length - 1 ? '' : ','}`));
        send('}');
        try { controller.close(); } catch {}
        closed = true;
      }).catch(error => {
        clearInterval(heartbeat);
        send(`],"returnedResults":0,"generatedAt":${encode(nowIso())},"latencyMs":${Date.now() - started},"keylessCoreSearch":true,"groqUsed":false,"resultsError":${encode(error?.message || 'SEARCH_FAILED')},"liveLog":${JSON.stringify(logger.logs)},"warnings":[${encode('The crawler failed safely after the stream had already started.').replace(/\[|\]/g,'')}]}`);
        try { controller.close(); } catch {}
        closed = true;
      });
    },
  });
  return new Response(stream, { status: 200, headers: { ...corsHeaders(), 'x-arix-search-stream': '1', 'x-arix-stream-heartbeat-ms': String(STREAM_HEARTBEAT_MS) } });
}

function streamSseSearch(input) {
  const encoder = new TextEncoder();
  const started = Date.now();
  const logger = createLogger();
  const stream = new ReadableStream({
    start(controller) {
      let closed = false;
      const sendEvent = (event, data) => {
        if (closed) return;
        try { controller.enqueue(encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)); } catch { closed = true; }
      };
      const heartbeat = setInterval(() => sendEvent('heartbeat', { at: nowIso(), version: VERSION }), STREAM_HEARTBEAT_MS);
      const originalAdd = logger.add;
      logger.add = (event, message, extra = {}) => {
        originalAdd(event, message, extra);
        sendEvent('log', logger.logs[logger.logs.length - 1]);
      };
      Promise.resolve().then(() => performSearch(input, started, logger)).then(result => {
        clearInterval(heartbeat);
        sendEvent('result', result);
        sendEvent('done', { ok: true, latencyMs: Date.now() - started });
        try { controller.close(); } catch {}
        closed = true;
      }).catch(error => {
        clearInterval(heartbeat);
        sendEvent('error', { ok: false, error: error?.message || 'SEARCH_FAILED', latencyMs: Date.now() - started });
        try { controller.close(); } catch {}
        closed = true;
      });
    },
  });
  return new Response(stream, { status: 200, headers: { ...corsHeaders('text/event-stream; charset=utf-8'), 'x-arix-log-stream': 'sse' } });
}

export default async function handler(req) {
  if (req.method === 'OPTIONS') return jsonResponse({ ok: true, version: VERSION });
  if (!['GET', 'POST'].includes(req.method)) return jsonResponse({ ok: false, version: VERSION, error: 'METHOD_NOT_ALLOWED', message: 'Use GET or POST.' }, 405);
  try {
    const input = await readInput(req);
    const query = truncate(String(input.query ?? input.q ?? '').trim(), MAX_QUERY_LEN);
    if (!query) return jsonResponse({ ok: false, version: VERSION, error: 'MISSING_QUERY' }, 400);
    if (query.length < 2) return jsonResponse({ ok: false, version: VERSION, error: 'QUERY_TOO_SHORT' }, 400);
    const wantsSse = String(input.logStream || '').toLowerCase() === 'true' || req.headers.get('accept')?.includes('text/event-stream');
    return wantsSse ? streamSseSearch(input) : streamJsonSearch(input);
  } catch (error) {
    const status = error?.message === 'REQUEST_BODY_TOO_LARGE' ? 413 : 500;
    return jsonResponse({ ok: false, version: VERSION, error: error?.message || 'SEARCH_FAILED' }, status);
  }
}
