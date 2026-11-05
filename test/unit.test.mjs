/**
 * Pure-host unit tests for @local/dsh-network-proxy.
 *
 * These cover the parsers and matchers that the Electron-as-Node harness test
 * cannot exercise directly (registry output, `scutil` output, URL
 * normalization), so they run under plain Node with `npm test` and in CI.
 *
 * Run:  node --test test/unit.test.mjs
 */
import assert from 'node:assert/strict'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath, pathToFileURL } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const { __test: t } = await import(pathToFileURL(join(here, '..', 'index.js')).href)

// ------------------------------------------------------------------ settings

test('custom proxy keeps an explicitly written default port', () => {
  assert.equal(t.normalizeCustomProxy('http://127.0.0.1:80'), 'http://127.0.0.1:80')
  assert.equal(t.normalizeCustomProxy('https://proxy.local:443'), 'https://proxy.local:443')
  assert.equal(t.normalizeCustomProxy('http://127.0.0.1:8080'), 'http://127.0.0.1:8080')
})

test('custom proxy still requires a port', () => {
  assert.equal(t.normalizeCustomProxy('http://127.0.0.1'), null)
  assert.equal(t.normalizeCustomProxy('https://proxy.local'), null)
})

test('custom proxy normalizes path, trailing slash and credentials', () => {
  assert.equal(t.normalizeCustomProxy('http://127.0.0.1:7890/'), 'http://127.0.0.1:7890')
  assert.equal(t.normalizeCustomProxy('http://127.0.0.1:7890/path?x=1'), 'http://127.0.0.1:7890')
  assert.equal(t.normalizeCustomProxy('http://user:pass@127.0.0.1:7890'), 'http://user:pass@127.0.0.1:7890')
  assert.equal(t.normalizeCustomProxy('http://user:pass@127.0.0.1:80'), 'http://user:pass@127.0.0.1:80')
  assert.equal(t.normalizeCustomProxy('http://[::1]:8080'), 'http://[::1]:8080')
})

test('custom proxy rejects unusable schemes and credentials', () => {
  assert.equal(t.normalizeCustomProxy('socks5://127.0.0.1:1080'), null)
  assert.equal(t.normalizeCustomProxy('ftp://127.0.0.1:21'), null)
  assert.equal(t.normalizeCustomProxy('127.0.0.1:7890'), null)
  assert.equal(t.normalizeCustomProxy('http://a%zz:p@127.0.0.1:7890'), null)
  assert.equal(t.normalizeCustomProxy(''), null)
})

test('buildPolicy accepts a default-port custom proxy', () => {
  const policy = t.buildPolicy({ mode: 'custom', custom: 'http://127.0.0.1:80' }, { enabled: false })
  assert.equal(policy.kind, 'proxy')
  assert.equal(policy.http, 'http://127.0.0.1:80')
  assert.equal(policy.https, 'http://127.0.0.1:80')
  assert.equal(policy.source, 'custom')
})

test('explicitPort only reads the authority', () => {
  assert.equal(t.explicitPort('http://127.0.0.1:80'), '80')
  assert.equal(t.explicitPort('http://user:pass@127.0.0.1:80/x:1'), '80')
  assert.equal(t.explicitPort('http://[::1]:443'), '443')
  assert.equal(t.explicitPort('http://127.0.0.1'), null)
  assert.equal(t.explicitPort('http://127.0.0.1/path:8080'), null)
})

// ------------------------------------------------------------ proxy parsing

test('parses a bare Windows ProxyServer value for both schemes', () => {
  const servers = t.parseProxyServer('127.0.0.1:7890')
  assert.deepEqual(servers, { http: 'http://127.0.0.1:7890', https: 'http://127.0.0.1:7890', socks: null })
})

test('parses per-scheme Windows ProxyServer values', () => {
  const servers = t.parseProxyServer('http=127.0.0.1:7890;https=127.0.0.1:7891;socks=127.0.0.1:1080;ftp=127.0.0.1:21')
  assert.equal(servers.http, 'http://127.0.0.1:7890')
  assert.equal(servers.https, 'http://127.0.0.1:7891')
  assert.equal(servers.socks, '127.0.0.1:1080')
})

test('keeps credentials and default ports in ProxyServer values', () => {
  assert.equal(t.parseProxyServer('http=http://user:pass@127.0.0.1:80').http, 'http://user:pass@127.0.0.1:80')
  assert.equal(t.parseProxyServer('http://proxy.local').http, 'http://proxy.local:80')
  assert.equal(t.parseProxyServer('socks5://127.0.0.1:1080').http, null)
})

test('toProxyUrl normalizes without inventing credentials', () => {
  assert.equal(t.toProxyUrl('127.0.0.1:7890'), 'http://127.0.0.1:7890')
  assert.equal(t.toProxyUrl('[::1]:8080'), 'http://[::1]:8080')
  assert.equal(t.toProxyUrl('::1'), null)
  assert.equal(t.toProxyUrl('http://proxy.local'), 'http://proxy.local:80')
  assert.equal(t.toProxyUrl('socks5h://127.0.0.1:1080'), null)
  // WinINET also stores credentials without a scheme.
  assert.equal(t.toProxyUrl('user:pass@127.0.0.1:7890'), 'http://user:pass@127.0.0.1:7890')
  assert.equal(t.toProxyUrl('user@127.0.0.1:7890'), 'http://user@127.0.0.1:7890')
  assert.equal(t.toProxyUrl('user:pass@127.0.0.1'), null)
})

test('sanitizeProxy removes credentials for the status line', () => {
  assert.equal(t.sanitizeProxy('http://user:pass@127.0.0.1:7890'), 'http://127.0.0.1:7890')
  assert.equal(t.sanitizeProxy(null), null)
})

// ------------------------------------------------------------ bypass matching

test('bypassesProxy matches OS bypass syntax', () => {
  assert.equal(t.bypassesProxy('localhost;127.*;<local>', new URL('http://127.0.0.2/x')), true)
  assert.equal(t.bypassesProxy('<local>', new URL('http://intranet/')), true)
  assert.equal(t.bypassesProxy('<local>', new URL('http://intranet.example/')), false)
  assert.equal(t.bypassesProxy('example.com', new URL('https://api.example.com/')), true)
  assert.equal(t.bypassesProxy('*.example.com', new URL('https://example.com/')), false)
  assert.equal(t.bypassesProxy('*', new URL('https://api.deepseek.com/')), true)
  assert.equal(t.bypassesProxy('example.com', new URL('https://api.deepseek.com/')), false)
})

test('bypassesProxy matches IPv4 and IPv6 CIDR blocks', () => {
  assert.equal(t.bypassesProxy('10.0.0.0/8', new URL('http://10.1.2.3/')), true)
  assert.equal(t.bypassesProxy('10.0.0.0/8', new URL('http://11.1.2.3/')), false)
  assert.equal(t.bypassesProxy('fc00::/7', new URL('http://[fd12:3456::1]/')), true)
  assert.equal(t.bypassesProxy('fd00::/8', new URL('http://[2001:db8::1]/')), false)
})

test('bypassesProxy honours a port on an entry', () => {
  assert.equal(t.bypassesProxy('example.com:8443', new URL('https://example.com:8443/')), true)
  assert.equal(t.bypassesProxy('example.com:8443', new URL('https://example.com/')), false)
  assert.equal(t.bypassesProxy('[fd00::1]:8080', new URL('http://[fd00::1]:8080/')), true)
  // A bare IPv6 literal with a trailing port is split only when the head is IPv6.
  assert.equal(t.bypassesProxy('fd00::1:8080', new URL('http://[fd00::1]:8080/')), true)
  assert.equal(t.bypassesProxy('fd00::1:8080', new URL('http://[fd00::1]/')), false)
  assert.equal(t.bypassesProxy('::ffff:1.2.3.4', new URL('http://[::ffff:1.2.3.4]/')), true)
})

test('bypassesProxy treats an empty list as no bypass', () => {
  assert.equal(t.bypassesProxy('', new URL('http://0.0.0.0/')), false)
})

test('proxyForUrl keeps loopback direct and proxies everything else', () => {
  const policy = { kind: 'proxy', http: 'http://127.0.0.1:7890', https: 'http://127.0.0.1:7890', noProxy: '' }
  assert.equal(t.proxyForUrl(new URL('http://0.0.0.0/'), policy), null)
  assert.equal(t.proxyForUrl(new URL('http://app.localhost/'), policy), null)
  assert.equal(t.proxyForUrl(new URL('http://[::1]/'), policy), null)
  assert.equal(t.proxyForUrl(new URL('http://127.0.0.2/'), policy), null)
  assert.equal(t.proxyForUrl(new URL('https://api.deepseek.com/'), policy), 'http://127.0.0.1:7890')
})

// ------------------------------------------------------- Windows registry read

test('parseRegQuery reads the real value table layout', () => {
  const stdout = [
    'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings',
    '    ProxyEnable    REG_DWORD    0x1',
    '    ProxyServer    REG_SZ    http=127.0.0.1:7890;https=127.0.0.1:7891',
    '    ProxyOverride    REG_SZ    localhost;127.*;<local>',
    '    AutoConfigURL    REG_SZ',
    '    User Agent    REG_SZ    Mozilla/4.0 (compatible; MSIE 8.0; Win32)',
    '',
    'HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\5.0',
  ].join('\r\n')
  const values = t.parseRegQuery(stdout)
  assert.equal(values.get('ProxyEnable'), '0x1')
  assert.equal(values.get('ProxyServer'), 'http=127.0.0.1:7890;https=127.0.0.1:7891')
  assert.equal(values.get('ProxyOverride'), 'localhost;127.*;<local>')
  assert.equal(values.get('AutoConfigURL'), '')
  assert.equal(values.get('User Agent'), 'Mozilla/4.0 (compatible; MSIE 8.0; Win32)')
  assert.equal(values.size, 5)
})

// ----------------------------------------------------------- macOS scutil read

const scutilSample = [
  '<dictionary> {',
  '  ExceptionsList : <array> {',
  '    0 : localhost',
  '    1 : *.corp.test',
  '  }',
  '  ExcludeSimpleHostnames : 0',
  '  HTTPEnable : 1',
  '  HTTPPort : 7890',
  '  HTTPProxy : 127.0.0.1',
  '  HTTPSEnable : 1',
  '  HTTPSPort : 7891',
  '  HTTPSProxy : 127.0.0.1',
  '  ProxyAutoConfigEnable : 0',
  '}',
].join('\n')

test('parseMacProxy reads enabled servers and the exceptions array', () => {
  const mac = t.parseMacProxy(scutilSample)
  assert.equal(mac.enabled, true)
  assert.equal(mac.servers.http, 'http://127.0.0.1:7890')
  assert.equal(mac.servers.https, 'http://127.0.0.1:7891')
  assert.equal(mac.bypass, 'localhost;*.corp.test')
  assert.equal(mac.pacUrl, '')
  assert.equal(mac.dormant, 'http://127.0.0.1:7890')
})

test('parseMacProxy brackets an IPv6 proxy address', () => {
  const mac = t.parseMacProxy(scutilSample.replace('HTTPProxy : 127.0.0.1', 'HTTPProxy : fd00::1'))
  assert.equal(mac.servers.http, 'http://[fd00::1]:7890')
  assert.equal(mac.dormant, 'http://[fd00::1]:7890')
  assert.doesNotThrow(() => new URL(mac.servers.http))
})

test('parseMacProxy reports a dormant proxy when the switch is off', () => {
  const mac = t.parseMacProxy(scutilSample
    .replace('HTTPEnable : 1', 'HTTPEnable : 0')
    .replace('HTTPSEnable : 1', 'HTTPSEnable : 0'))
  assert.equal(mac.enabled, false)
  assert.equal(mac.servers.http, null)
  assert.equal(mac.dormant, 'http://127.0.0.1:7890')
})

test('parseMacProxy reads a PAC URL and ExcludeSimpleHostnames', () => {
  const pacSample = [
    '<dictionary> {',
    '  ExceptionsList : <array> {',
    '    0 : localhost',
    '  }',
    '  ExcludeSimpleHostnames : 1',
    '  HTTPEnable : 0',
    '  HTTPSEnable : 0',
    '  ProxyAutoConfigEnable : 1',
    '  ProxyAutoConfigURLString : http://pac.corp.test/proxy.pac',
    '}',
  ].join('\n')
  const mac = t.parseMacProxy(pacSample)
  assert.equal(mac.enabled, true)
  assert.equal(mac.pacUrl, 'http://pac.corp.test/proxy.pac')
  assert.equal(mac.bypass, 'localhost;<local>')
})

test('system mode inherits the launch proxy only when the OS has none', () => {
  const empty = { enabled: false, http: null, https: null, bypass: '' }
  assert.equal(t.buildPolicy({ mode: 'system', custom: '' }, empty).kind, 'direct')
  assert.equal(t.buildPolicy({ mode: 'system', custom: '' }, empty, true).kind, 'inherit')
  assert.equal(t.policyFingerprint({ kind: 'inherit' }), 'inherit')
  assert.notEqual(t.policyFingerprint({ kind: 'inherit' }), t.policyFingerprint({ kind: 'direct' }))
})

test('an OS proxy wins over the launch policy', () => {
  const policy = t.buildPolicy(
    { mode: 'system', custom: '' },
    { enabled: true, http: 'http://os:1', https: 'http://os:1', bypass: '' },
    true,
  )
  assert.equal(policy.kind, 'proxy')
  assert.equal(policy.http, 'http://os:1')
  assert.equal(policy.source, 'system')
})

test('an OS proxy naming only SOCKS still falls back to the launch policy', () => {
  const detection = { enabled: true, http: null, https: null, bypass: '', codes: ['socks-unsupported'] }
  assert.equal(t.buildPolicy({ mode: 'system', custom: '' }, detection, true).kind, 'inherit')
})

// ------------------------------------------------------------------- PAC eval

test('PAC evaluator reads DIRECT, PROXY, HTTPS and SOCKS tokens', () => {
  const pac = t.createPacEvaluator(`
    function FindProxyForURL(url, host) {
      if (host === 'direct.test') return 'DIRECT'
      if (host === 'socks.test') return 'SOCKS 127.0.0.1:1080'
      if (host === 'v6.test') return 'PROXY [::1]:8080'
      return 'PROXY 127.0.0.1:7890; DIRECT'
    }
  `, 'http://127.0.0.1/pac')
  assert.deepEqual(pac(new URL('http://direct.test/')), { proxy: null, socks: false, failed: false })
  assert.equal(pac(new URL('http://socks.test/')).socks, true)
  assert.equal(pac(new URL('http://v6.test/')).proxy, 'http://[::1]:8080')
  assert.equal(pac(new URL('https://api.deepseek.com/')).proxy, 'http://127.0.0.1:7890')
})

test('PAC evaluator contains failures and hostile scripts', () => {
  const failing = t.createPacEvaluator('function FindProxyForURL() { throw new Error("boom") }', 'http://127.0.0.1/bad.pac')
  assert.equal(failing(new URL('https://example.com/')).failed, true)
  const escape = t.createPacEvaluator(
    'function FindProxyForURL() { return "PROXY " + alert.constructor("return process")().version + ":1" }',
    'http://127.0.0.1/escape.pac',
  )
  assert.equal(escape(new URL('https://example.com/')).failed, true)
})

test('PAC evaluator rejects an oversized script', () => {
  const oversized = 'function FindProxyForURL() { return "DIRECT" }\n//' + 'x'.repeat(1024 * 1024)
  assert.throws(() => t.createPacEvaluator(oversized, 'http://127.0.0.1/big.pac'), /too large/)
})
