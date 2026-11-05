/**
 * Client-half unit tests for @local/dsh-network-proxy.
 *
 * The browser bundle registers itself through `window.__ModuleLoader__`, so the
 * loader is stubbed and the factory is called with a stub React. Only the pure
 * helpers are exercised; no component is rendered.
 *
 * Run:  node --test test/client.test.mjs
 */
import assert from 'node:assert/strict'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath, pathToFileURL } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))

let definition = null
globalThis.window = { __ModuleLoader__: { load: (value) => { definition = value } } }
await import(pathToFileURL(join(here, '..', 'client.js')).href)

const factory = definition.factory
const plugin = factory((id) => (id === 'react' ? { createElement: () => null } : {}))
const t = plugin.__test

/** A translator that keeps the key visible and renders its variables. */
const translate = (key, vars) => (vars === undefined ? `[${key}]` : `[${key}]${JSON.stringify(vars)}`)

test('the plugin declares the services it needs', () => {
  assert.deepEqual(plugin.inject, ['slots', 'locale'])
  assert.equal(typeof plugin.apply, 'function')
})

test('both dictionaries carry the same keys', () => {
  const zh = Object.keys(t.dictionaries.zh).sort()
  const en = Object.keys(t.dictionaries.en).sort()
  assert.deepEqual(zh, en)
})

test('every diagnostic code has copy in both dictionaries', () => {
  for (const key of Object.values(t.codeKeys)) {
    assert.ok(key in t.dictionaries.zh, `missing zh copy for ${key}`)
    assert.ok(key in t.dictionaries.en, `missing en copy for ${key}`)
  }
})

test('fill replaces every occurrence of a placeholder', () => {
  assert.equal(t.fill('a {url} b {url}', { url: 'http://p:1' }), 'a http://p:1 b http://p:1')
  assert.equal(t.fill('plain', undefined), 'plain')
  assert.equal(t.fill(undefined, {}), '')
})

test('isProxyUrl accepts default ports and rejects a missing port', () => {
  assert.equal(t.isProxyUrl('http://127.0.0.1:80'), true)
  assert.equal(t.isProxyUrl('https://proxy.local:443'), true)
  assert.equal(t.isProxyUrl('http://127.0.0.1:7890/path'), true)
  assert.equal(t.isProxyUrl('http://user:pass@127.0.0.1:7890'), true)
  assert.equal(t.isProxyUrl('http://[::1]:8080'), true)
  assert.equal(t.isProxyUrl('http://127.0.0.1'), false)
  assert.equal(t.isProxyUrl('socks5://127.0.0.1:1080'), false)
  assert.equal(t.isProxyUrl('http://a%zz:p@127.0.0.1:7890'), false)
  assert.equal(t.isProxyUrl(''), false)
})

test('explicitPort reads only the authority', () => {
  assert.equal(t.explicitPort('http://127.0.0.1:80'), '80')
  assert.equal(t.explicitPort('http://127.0.0.1'), null)
})

test('normalizeSettings falls back to the follow-the-system default', () => {
  assert.deepEqual(t.normalizeSettings(null), { mode: 'system', custom: '' })
  assert.deepEqual(t.normalizeSettings({ mode: 'nonsense', custom: 'http://p:1' }), { mode: 'system', custom: 'http://p:1' })
  assert.deepEqual(t.normalizeSettings({ mode: 'custom', custom: 42 }), { mode: 'custom', custom: '' })
})

test('summarizeStatus projects the applied status', () => {
  const summary = t.summarizeStatus({
    active: true,
    source: 'custom',
    sample: 'http://p:1',
    http: 'http://p:1',
    reachable: false,
    pac: true,
    codes: ['bypass-all', 7, ''],
  })
  assert.equal(summary.active, true)
  assert.equal(summary.source, 'custom')
  assert.equal(summary.url, 'http://p:1')
  assert.equal(summary.reachable, false)
  assert.equal(summary.pac, true)
  assert.deepEqual(summary.codes, ['bypass-all'])
})

test('summarizeStatus keeps the launch source visible while inactive', () => {
  const summary = t.summarizeStatus({ active: false, source: 'launch', http: null, https: null })
  assert.equal(summary.active, false)
  assert.equal(summary.source, 'launch')
  assert.equal(summary.url, null)
})

test('systemText prefers an unreadable notice, then the detected address', () => {
  assert.equal(t.systemText(null, translate), '[system.none]')
  assert.equal(t.systemText({ codes: ['system-unreadable'] }, translate), '[code.systemUnreadable]')
  assert.equal(
    t.systemText({ enabled: true, http: 'http://p:1', codes: [] }, translate),
    '[system.detected]{"url":"http://p:1"}',
  )
  assert.equal(
    t.systemText({ enabled: true, http: null, https: null, pacUrl: 'http://pac/p', codes: ['pac-detected'] }, translate),
    '[system.pac]{"url":"http://pac/p"}',
  )
  assert.equal(
    t.systemText({ enabled: false, dormant: 'http://p:1', codes: ['system-disabled'] }, translate),
    '[system.dormant]{"url":"http://p:1"}',
  )
  assert.equal(t.systemText({ enabled: false, codes: [] }, translate), '[system.none]')
})

test('failureText prefers the localized code and falls back to the message', () => {
  assert.equal(t.failureText({ offline: true }, translate), '[error.offline]')
  assert.equal(t.failureText({ code: 'invalid-custom', message: 'raw' }, translate), '[code.invalidCustom]')
  assert.equal(t.failureText({ code: 'not-mapped', message: 'raw' }, translate), 'raw')
  assert.equal(t.failureText({}, translate), '[code.unknown]')
  assert.equal(t.failureText(null, translate), '')
})

test('unknown diagnostic codes localize as unknown', () => {
  assert.equal(t.codeText('nope', translate), '[code.unknown]')
  assert.equal(t.codeText('bypass-all', translate), '[code.bypassAll]')
})
