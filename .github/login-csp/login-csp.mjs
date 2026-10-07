// Production Login CSP controls; run with the pinned Playwright 1.55.0 package.
// Anonymous document proof only; actual human/OIDC journeys run separately.
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
const require = createRequire(process.env.LOGIN_CSP_PACKAGE_JSON);
const { chromium } = require('playwright');
const base = process.env.LOGIN_CSP_BASE || 'https://localhost:8443';
assert(['https://localhost:8443', 'http://127.0.0.1:13000'].includes(base));
const result = { requests: 0, blocked: 0, documents: [], naturalScriptViolations: 0, probeViolations: 0 };
const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
const context = await browser.newContext({ ignoreHTTPSErrors: true });
const timer = setTimeout(() => { console.error('CSP proof timeout'); process.exit(1); }, 150_000);
let lastRequest = 0;
let requestQueue = Promise.resolve();
await context.route('**/*', async route => {
  const previous = requestQueue;
  let release;
  requestQueue = new Promise(resolve => { release = resolve; });
  await previous;
  try {
  const url = new URL(route.request().url());
  if (url.origin !== base || ++result.requests > 160) {
    result.blocked++; await route.abort(); return;
  }
  const delay = Math.max(0, 500 - (Date.now() - lastRequest));
  await new Promise(resolve => setTimeout(resolve, delay)); lastRequest = Date.now();
  if (url.pathname === '/ui/v2/login/csp-owned-fixture.js') {
    await route.fulfill({ contentType: 'application/javascript', body: 'window.__cspExternal = 1' });
  } else await route.continue();
  } finally { release(); }
});
await context.exposeBinding('__captureCsp', (_, event) => {
  if (event.probe) result.probeViolations++;
  else if (event.directive.startsWith('script')) result.naturalScriptViolations++;
});
await context.addInitScript(() => {
  window.addEventListener('securitypolicyviolation', e => {
    if (e.isTrusted) window.__captureCsp({ directive: e.effectiveDirective, probe: !!window.__cspProbe });
  });
});
const page = await context.newPage();
async function document(path, spoof = false) {
  await page.setExtraHTTPHeaders(spoof ? {
    'x-zitadel-csp-nonce': 'caller-selected',
    'content-security-policy': "script-src 'nonce-caller-selected'",
    'content-security-policy-report-only': "script-src 'nonce-caller-selected'",
  } : {});
  const response = await page.goto(base + path, { waitUntil: 'networkidle', timeout: 60_000 });
  const headers = await response.allHeaders();
  const nonce = headers['content-security-policy']?.match(/'nonce-([^']+)'/)?.[1];
  assert(nonce && Buffer.from(nonce, 'base64').length >= 16 && nonce !== 'caller-selected');
  assert(!headers['content-security-policy-report-only']);
  assert(headers['cache-control'].includes('private') && headers['cache-control'].includes('no-store'));
  const scripts = headers['content-security-policy'].split(';').find(s => s.trim().startsWith('script-src '));
  assert(scripts.includes("'strict-dynamic'") && !scripts.includes('unsafe-'));
  const body = await response.text();
  result.staticChunk ||= body.match(/<script[^>]+src="([^"]*\/_next\/static\/[^"]+)"/)?.[1];
  assert(Buffer.byteLength(body) <= 1 << 20);
  const tags = [...body.matchAll(/<script\b([^>]*)>/g)];
  assert(tags.length > 0 && tags.every(t => t[1].includes(`nonce="${nonce}"`)));
  const dom = await page.evaluate(() => [...document.scripts].map(s => s.nonce));
  assert(dom.length > 0 && dom.every(n => n === nonce));
  result.documents.push({ path, status: response.status(), scripts: tags.length, nonceMatches: tags.length, cache: headers['cache-control'] });
  return nonce;
}
// The positive control must use the same mechanism as each adversarial control.
async function controls(target, nonce) {
  const cdp = await context.newCDPSession(target);
  const fn = nonce => {
    window.__cspProbe = true;
    window.__cspGood = window.__cspInline = window.__cspWrong = window.__cspHandler = window.__cspEval = 0;
    const scripts = [
      [nonce, 'window.__cspGood=1'],
      ['', 'window.__cspInline=1'],
      ['wrong', 'window.__cspWrong=1'],
      [nonce, "try { eval('window.__cspEval=1') } catch {}"],
    ].map(([n, text]) => `<script nonce="${n}">${text}<\/script>`).join('');
    // Parser-inserted markup represents injection. DOM-created scripts from a
    // trusted DevTools/loader context inherit strict-dynamic trust and are not
    // a valid negative control for markup injection.
    document.open();
    window.addEventListener('securitypolicyviolation', e => {
      if (e.isTrusted) window.__captureCsp({ directive: e.effectiveDirective, probe: true });
    });
    document.write(scripts + '<button onclick="window.__cspHandler=1">Probe</button>'); document.close();
    document.querySelector('button').click();
    return { nonced: !!window.__cspGood, inline: !!window.__cspInline, wrong: !!window.__cspWrong, handler: !!window.__cspHandler, eval: !!window.__cspEval };
  };
  const response = await cdp.send('Runtime.evaluate', {
    expression: `(${fn.toString()})(${JSON.stringify(nonce)})`,
    allowUnsafeEvalBlockedByCSP: false, returnByValue: true,
  });
  await cdp.detach(); return response.result.value;
}
async function injectedExternal(target) {
  // Parser-inserted markup models an injected external script. A trusted
  // dynamic chunk loader is intentionally admitted by strict-dynamic.
  await target.evaluate(base => {
    window.__cspProbe = true; window.__cspExternal = 0;
    document.open();
    window.addEventListener('securitypolicyviolation', e => {
      if (e.isTrusted) window.__captureCsp({ directive: e.effectiveDirective, probe: true });
    });
    document.write(`<script src="${base}/ui/v2/login/csp-owned-fixture.js"><\/script>`); document.close();
  }, base);
  await target.waitForTimeout(1500);
  return target.evaluate(() => !!window.__cspExternal);
}
try {
  const first = await document('/ui/v2/login/logout/done');
  const second = await document('/ui/v2/login/logout/done', true); assert.notEqual(first, second);
  await document('/ui/v2/login/unknown-csp-fixture');
  const cachePage = await context.newPage();
  await cachePage.goto(base + '/ui/v2/login/logout/done', { waitUntil: 'networkidle' });
  result.assets = await cachePage.evaluate(async paths => {
    const rows = [];
    for (const path of paths) {
      const response = await fetch(path, { redirect: 'error' });
      rows.push({ path, status: response.status, type: response.headers.get('content-type'), cache: response.headers.get('cache-control') });
    }
    return rows;
  }, [result.staticChunk, '/ui/v2/login/grid-light.svg']);
  assert(result.assets.every(a => a.status === 200 && !/private|no-store/.test(a.cache || '')));
  result.rendering = await cachePage.evaluate(async () => {
    const rows = [];
    for (const headers of [{ Accept: '' }, { RSC: '1', Accept: 'text/x-component' }]) {
      const response = await fetch('/ui/v2/login/logout/done', { headers, redirect: 'error' });
      rows.push({ status: response.status, type: response.headers.get('content-type'), cache: response.headers.get('cache-control') });
    }
    return rows;
  });
  assert(result.rendering.every(r => r.status === 200 && r.cache.includes('private') && r.cache.includes('no-store')));
  await cachePage.close();
  await document('/ui/v2/login/favicon/owned-missing.svg');
  result.staticMissing = await page.evaluate(async () => {
    const r = await fetch('/ui/v2/login/_next/static/owned-missing.js', { redirect: 'error' });
    return { status: r.status, empty: (await r.text()) === '', cache: r.headers.get('cache-control') };
  });
  assert.deepEqual(result.staticMissing, { status: 404, empty: true, cache: 'private, no-store' });
  result.negative = await controls(page, await page.evaluate(() => document.querySelector('script[nonce]').nonce));
  assert.deepEqual(result.negative, { nonced: true, inline: false, wrong: false, handler: false, eval: false });
  result.injectedExternal = await injectedExternal(page); assert.equal(result.injectedExternal, false);
  const positive = await context.newPage();
  await positive.setContent('<title>Owned local positive control</title>');
  result.positive = await controls(positive, 'positive'); assert(Object.values(result.positive).every(Boolean));
  // Give the control a local base URL without issuing a request.
  await positive.setContent(`<base href="${base}/"><title>Positive external control</title>`);
  result.positiveExternal = await injectedExternal(positive); assert.equal(result.positiveExternal, true);
  assert.equal(result.naturalScriptViolations, 0); assert.equal(result.blocked, 0);
  assert(result.probeViolations >= 5);
  result.browser = browser.version(); result.passed = true;
} finally {
  clearTimeout(timer); await context.close(); await browser.close();
  console.log(JSON.stringify(result, null, 2));
}
