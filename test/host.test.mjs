/**
 * Host-half verification for @local/dsh-network-proxy.
 *
 * Runs inside the Electron-as-Node runtime so `loadUndici()` can resolve the
 * Harness's bundled undici from app.asar, exactly as the real Host does. It
 * mocks only the Cordis context: one `connection.fetch.register` capture and
 * one `effect` capture. Everything else — detection, the dispatcher swap, the
 * environment publication, the route handler — is the production code.
 *
 * Run:  $env:ELECTRON_RUN_AS_NODE='1'; & 'E:\DeepSeek Harness\DeepSeek Harness.exe' <this file>
 */
import { createServer } from 'node:http'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

// Electron exposes its resources directory even under ELECTRON_RUN_AS_NODE, so
// the harness can be found without hardcoding this machine's install path.
const HOST_ENTRY = process.env.DSH_HOST_ENTRY ?? join(
  process.resourcesPath ?? 'E:\\DeepSeek Harness\\resources',
  'app.asar', 'dsh', 'node_modules', '@deepseek-ai', 'dsh-desktop-host', 'lib', 'index.js',
)
if (!existsSync(HOST_ENTRY)) {
  console.error(`Cannot find the Harness Host entry: ${HOST_ENTRY}\nSet DSH_HOST_ENTRY to <Harness>/resources/app.asar/dsh/node_modules/@deepseek-ai/dsh-desktop-host/lib/index.js`)
  process.exit(1)
}
const here = dirname(fileURLToPath(import.meta.url))
process.argv[1] = HOST_ENTRY
const home = mkdtempSync(join(tmpdir(), 'np-test-'))
process.env.DSH_HOME = home
// A launch-time proxy value must survive the plugin's env publication/restore.
process.env.HTTPS_PROXY = 'http://baseline.invalid:1'

const results = []
function check(name, passed, detail) {
  results.push({ name, passed, detail })
  console.log(`${passed ? 'PASS' : 'FAIL'}  ${name}${detail === undefined ? '' : `  (${detail})`}`)
}

const plugin = await import(pathToFileURL(join(here, '..', 'index.js')).href)

const requireFromHost = (await import('node:module')).createRequire(HOST_ENTRY)
const undici = await import(pathToFileURL(requireFromHost.resolve('undici')).href)
const launchDispatcher = undici.getGlobalDispatcher()

let route
let disposeRoute
let disposeEffect
const ctx = {
  connection: { fetch: { register(definition) {
    route = definition
    return async () => { route = null }
  } } },
  effect(fn) {
    disposeEffect = fn()
    return () => {}
  },
  get() { return undefined },
}

plugin.apply(ctx)
await new Promise((resolve) => setTimeout(resolve, 600))

async function call(body) {
  const response = await route.fetch(new Request('http://127.0.0.1/api/network-proxy', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  }))
  const text = await response.text()
  return { status: response.status, body: JSON.parse(text) }
}

// A recording forward proxy: absolute-form requests for http targets, CONNECT for https targets.
const seen = []
const connects = []
const proxy = createServer((request, response) => {
  seen.push(`${request.method} ${request.url}`)
  response.writeHead(200, { 'content-type': 'text/plain' })
  response.end('proxied-ok')
})
proxy.on('connect', (request, socket) => {
  connects.push(request.url)
  socket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
})
await new Promise((resolve) => proxy.listen(0, '127.0.0.1', resolve))
const proxyPort = proxy.address().port
const proxyUrl = `http://127.0.0.1:${proxyPort}`

// A plain local server that must stay direct because it is loopback.
const local = createServer((request, response) => {
  response.writeHead(200, { 'content-type': 'text/plain' })
  response.end('local-ok')
})
await new Promise((resolve) => local.listen(0, '127.0.0.1', resolve))
const localUrl = `http://127.0.0.1:${local.address().port}/local`

try {
  const initial = await call({ action: 'get' })
  check('get returns ok', initial.body.ok === true)
  check('default mode follows the system', initial.body.settings.mode === 'system', initial.body.settings.mode)
  check('get reports a detection payload', initial.body.detection !== null && typeof initial.body.detection.enabled === 'boolean')

  const detected = await call({ action: 'detect' })
  check('detect returns ok', detected.body.ok === true)
  console.log('    detection:', JSON.stringify(detected.body.detection))

  const helpers = plugin.__test
  check('bypass matches 127.*', helpers.bypassesProxy('localhost;127.*;<local>', new URL('http://127.0.0.2/x')) === true)
  check('bypass matches <local>', helpers.bypassesProxy('<local>', new URL('http://intranet/')) === true)
  check('bypass matches a subdomain entry', helpers.bypassesProxy('example.com', new URL('https://api.example.com/')) === true)
  check('bypass matches CIDR', helpers.bypassesProxy('10.0.0.0/8', new URL('http://10.1.2.3/')) === true)
  check('bypass leaves an unrelated host proxied', helpers.bypassesProxy('example.com', new URL('https://api.deepseek.com/')) === false)
  const servers = helpers.parseProxyServer('http=127.0.0.1:7890;https=127.0.0.1:7891;socks=127.0.0.1:1080')
  check('parses per-scheme proxy servers', servers.http === 'http://127.0.0.1:7890' && servers.https === 'http://127.0.0.1:7891' && servers.socks === '127.0.0.1:1080', JSON.stringify(servers))
  check('normalizes a custom proxy with credentials', helpers.normalizeCustomProxy('http://user:pass@127.0.0.1:7890/') === 'http://user:pass@127.0.0.1:7890')
  check('rejects a custom proxy without a port', helpers.normalizeCustomProxy('http://127.0.0.1') === null)

  const pac = helpers.createPacEvaluator(`
    function FindProxyForURL(url, host) {
      if (host === 'internal.test') return 'DIRECT'
      if (shExpMatch(host, '*.example.cn')) return 'PROXY 127.0.0.1:3128'
      if (isInNet(host, '10.0.0.0', '255.0.0.0')) return 'DIRECT'
      if (dnsDomainIs(host, '.corp.test')) return 'HTTPS proxy.corp.test:8443'
      return 'PROXY 127.0.0.1:7897; DIRECT'
    }
  `, 'http://127.0.0.1/pac')
  check('PAC default branch', pac(new URL('https://api.deepseek.com/')).proxy === 'http://127.0.0.1:7897')
  check('PAC DIRECT branch', pac(new URL('http://internal.test/')).proxy === null)
  check('PAC shExpMatch branch', pac(new URL('http://www.example.cn/')).proxy === 'http://127.0.0.1:3128')
  check('PAC isInNet branch', pac(new URL('http://10.2.3.4/')).proxy === null)
  check('PAC HTTPS branch', pac(new URL('http://a.corp.test/')).proxy === 'https://proxy.corp.test:8443')

  const failing = helpers.createPacEvaluator('function FindProxyForURL() { throw new Error("boom") }', 'http://127.0.0.1/bad.pac')
  check('PAC errors are contained', failing(new URL('https://example.com/')).failed === true)
  const loopStarted = Date.now()
  const looping = helpers.createPacEvaluator('function FindProxyForURL() { while (true) {} }', 'http://127.0.0.1/loop.pac')
  const loopResult = looping(new URL('https://example.com/'))
  const loopElapsed = Date.now() - loopStarted
  check('PAC evaluation is time-bounded', loopResult.failed === true && loopElapsed < 2000, `${loopElapsed}ms`)

  const escapePac = helpers.createPacEvaluator(
    'function FindProxyForURL() { return "PROXY " + alert.constructor("return process")().version + ":1" }',
    'http://127.0.0.1/escape.pac',
  )
  const escapeResult = escapePac(new URL('https://example.com/'))
  check('PAC cannot reach the Host realm', escapeResult.failed === true && escapeResult.proxy === null)
  const argsEscape = helpers.createPacEvaluator(
    'function FindProxyForURL() { return "PROXY " + __npArgs.constructor.constructor("return process")().version + ":1" }',
    'http://127.0.0.1/escape2.pac',
  )
  check('PAC cannot reach the Host realm through its arguments', argsEscape(new URL('https://example.com/')).failed === true)

  check('rejects malformed percent credentials', helpers.normalizeCustomProxy('http://a%zz:p@127.0.0.1:7890') === null)
  const malformedPac = helpers.createPacEvaluator(
    'function FindProxyForURL() { return "PROXY a%zz:p@127.0.0.1:7890" }',
    'http://127.0.0.1/malformed.pac',
  )
  check('rejects malformed PAC proxy addresses', malformedPac(new URL('https://example.com/')).failed === true)

  const failedPolicy = { kind: 'proxy', http: 'http://static.proxy:1', https: 'http://static.proxy:1', noProxy: '', pac: () => ({ proxy: null, socks: false, failed: true }) }
  check('PAC failure falls back to the static proxy', helpers.proxyForUrl(new URL('https://example.com/'), failedPolicy) === 'http://static.proxy:1')
  const failedOnly = { kind: 'proxy', http: null, https: null, noProxy: '', pac: () => ({ proxy: null, socks: false, failed: true }) }
  check('PAC failure without a fallback goes direct', helpers.proxyForUrl(new URL('https://example.com/'), failedOnly) === null)

  check('bypass matches an IPv6 CIDR', helpers.bypassesProxy('fc00::/7', new URL('http://[fd12:3456::1]/')) === true)
  check('bypass rejects an IPv6 host outside the CIDR', helpers.bypassesProxy('fd00::/8', new URL('http://[2001:db8::1]/')) === false)

  check('preserves credentials in a proxy URL', helpers.toProxyUrl('http://user:pass@127.0.0.1:7890') === 'http://user:pass@127.0.0.1:7890')
  check('defaults a missing proxy port', helpers.toProxyUrl('http://proxy.local') === 'http://proxy.local:80')

  const pacOnlyPolicy = helpers.buildPolicy({ mode: 'system', custom: '' }, {
    enabled: true,
    http: null,
    https: null,
    bypass: '',
    pacUrl: 'http://127.0.0.1/pac',
    pacKey: 'k1',
    pacEvaluator: () => ({ proxy: 'http://127.0.0.1:1', socks: false, failed: false }),
  })
  check('PAC-only system policy is proxied', pacOnlyPolicy.kind === 'proxy' && typeof pacOnlyPolicy.pac === 'function')
  check('identical policies share a fingerprint', helpers.policyFingerprint(pacOnlyPolicy) === helpers.policyFingerprint({ ...pacOnlyPolicy }))
  check('different proxies get different fingerprints', helpers.policyFingerprint({ kind: 'proxy', http: 'http://a:1', https: 'http://a:1', noProxy: '' }) !== helpers.policyFingerprint({ kind: 'proxy', http: 'http://b:1', https: 'http://b:1', noProxy: '' }))
  const pacSampleA = helpers.policyFingerprint({ kind: 'proxy', http: 'http://a:1', https: 'http://a:1', noProxy: 'x', pac: () => ({}), pacUrl: 'http://p/pac', pacKey: 'k' })
  const pacSampleB = helpers.policyFingerprint({ kind: 'proxy', http: 'http://b:2', https: 'http://b:2', noProxy: 'x', pac: () => ({}), pacUrl: 'http://p/pac', pacKey: 'k' })
  check('PAC fingerprints ignore sampled addresses', pacSampleA === pacSampleB)
  check('system mode without a proxy resolves direct', helpers.buildPolicy({ mode: 'system', custom: '' }, { enabled: false, http: null, https: null, bypass: '' }).kind === 'direct')

  const invalid = await call({ action: 'set', mode: 'custom', custom: 'socks5://127.0.0.1:1080' })
  check('rejects a non-http custom proxy', invalid.status === 400 && invalid.body.error.code === 'invalid-custom', invalid.body.error?.code)

  const applied = await call({ action: 'set', mode: 'custom', custom: proxyUrl })
  check('custom mode applies', applied.body.ok === true && applied.body.status.active === true, applied.body.status?.source)
  check('status reports the custom proxy', applied.body.status.http === proxyUrl, applied.body.status.http)
  check('dispatcher was swapped', undici.getGlobalDispatcher() !== launchDispatcher)
  check('proxy env is published to children', process.env.HTTPS_PROXY === proxyUrl && process.env.NODE_USE_ENV_PROXY === '1', process.env.HTTPS_PROXY)

  const keptDispatcher = undici.getGlobalDispatcher()
  const reapplied = await call({ action: 'set', mode: 'custom', custom: proxyUrl })
  check('re-applying the same policy keeps the dispatcher', reapplied.body.ok === true && undici.getGlobalDispatcher() === keptDispatcher)

  const credentialUrl = `http://user:pass@127.0.0.1:${proxyPort}`
  const credentialApplied = await call({ action: 'set', mode: 'custom', custom: credentialUrl })
  check('status hides proxy credentials', credentialApplied.body.status.http === proxyUrl && credentialApplied.body.settings.custom === credentialUrl, credentialApplied.body.status.http)
  await call({ action: 'set', mode: 'custom', custom: proxyUrl })

  const viaProxy = await fetch('http://probe.invalid/through')
  check('http fetch goes through the proxy', (await viaProxy.text()) === 'proxied-ok' && seen.includes('GET http://probe.invalid/through'), seen.join(' | '))

  const directLocal = await fetch(localUrl)
  check('loopback stays direct', (await directLocal.text()) === 'local-ok' && !seen.some((entry) => entry.includes('127.0.0.1')))

  await fetch('https://probe.invalid/secure').catch(() => {})
  check('https fetch tunnels through the proxy', connects.includes('probe.invalid:443'), connects.join(' | '))

  const persisted = JSON.parse((await import('node:fs')).readFileSync(join(home, 'network-proxy.json'), 'utf8'))
  check('preference is persisted', persisted.mode === 'custom' && persisted.custom === proxyUrl)

  const direct = await call({ action: 'set', mode: 'direct' })
  check('direct mode applies', direct.body.ok === true && direct.body.status.active === false, direct.body.status?.source)
  check('proxy env is cleared in direct mode', process.env.HTTPS_PROXY === undefined && process.env.NODE_USE_ENV_PROXY === undefined, String(process.env.HTTPS_PROXY))
  const directAgain = await fetch(localUrl)
  check('direct mode still reaches loopback', (await directAgain.text()) === 'local-ok')

  const backToSystem = await call({ action: 'set', mode: 'system' })
  check('system mode responds with codes', backToSystem.body.ok === true && Array.isArray(backToSystem.body.status.codes), backToSystem.body.status?.codes?.join(','))

  await disposeEffect()
  check('unload restores the original dispatcher', undici.getGlobalDispatcher() === launchDispatcher)
  check('unload restores the launch proxy env', process.env.HTTPS_PROXY === 'http://baseline.invalid:1', String(process.env.HTTPS_PROXY))
  check('route is unregistered on unload', route === null)
} catch (error) {
  console.error('TEST ERROR', error)
  results.push({ name: 'unexpected error', passed: false, detail: String(error) })
} finally {
  await new Promise((resolve) => proxy.close(resolve))
  await new Promise((resolve) => local.close(resolve))
  try { rmSync(home, { recursive: true, force: true }) } catch { /* temp dir */ }
}

const failed = results.filter((entry) => entry.passed !== true)
console.log(`\n${results.length - failed.length}/${results.length} checks passed`)
process.exit(failed.length === 0 ? 0 : 1)
