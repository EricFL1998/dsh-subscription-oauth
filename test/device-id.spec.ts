/** Device-id persistence and the identity headers every Kimi request carries. */

import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { after, before, describe, test } from 'node:test'

import { loadOrCreateDeviceId, mintDeviceId, readDeviceId } from '../src/auth/device-id.js'
import { deviceModel, byteStringSafe, kimiIdentityHeaders, kimiRequestHeaders, platformWord } from '../src/auth/headers.js'
import { KIMI_CLI_VERSION } from '../src/constants.js'

let directory: string

before(async () => {
  directory = await mkdtemp(path.join(tmpdir(), 'kimi-device-'))
})

after(async () => {
  await rm(directory, { recursive: true, force: true })
})

describe('mintDeviceId', () => {
  test('matches the CLI format: 32 lowercase hex characters', () => {
    assert.match(mintDeviceId(), /^[0-9a-f]{32}$/)
    assert.notEqual(mintDeviceId(), mintDeviceId())
  })
})

describe('loadOrCreateDeviceId', () => {
  test('creates once and reuses the stored id', async () => {
    const dir = path.join(directory, 'reuse')
    const first = await loadOrCreateDeviceId(dir)
    assert.match(first, /^[0-9a-f]{32}$/)
    const stored = await readFile(path.join(dir, 'kimi-device-id'), 'utf8')
    assert.equal(stored.trim(), first)
    assert.equal(await loadOrCreateDeviceId(dir), first)
  })

  test('replaces a malformed file instead of failing', async () => {
    const dir = path.join(directory, 'malformed')
    await loadOrCreateDeviceId(dir)
    await writeFile(path.join(dir, 'kimi-device-id'), 'not-a-device-id', 'utf8')
    const replaced = await loadOrCreateDeviceId(dir)
    assert.match(replaced, /^[0-9a-f]{32}$/)
    assert.equal(await readDeviceId(path.join(dir, 'kimi-device-id')), replaced)
  })

  test('readDeviceId reports absence rather than throwing', async () => {
    assert.equal(await readDeviceId(path.join(directory, 'missing', 'kimi-device-id')), undefined)
  })
})

describe('identity headers', () => {
  test('names the platform the way the CLI does', () => {
    assert.equal(platformWord('win32'), 'Windows')
    assert.equal(platformWord('darwin'), 'macOS')
    assert.equal(platformWord('linux'), 'Linux')
    assert.equal(platformWord('freebsd'), 'freebsd')
    assert.match(deviceModel('win32'), /^Windows .+ \S+$/)
  })

  test('carries the CLI product token and the device id', () => {
    const deviceId = 'a'.repeat(32)
    const headers = kimiIdentityHeaders(deviceId)
    assert.equal(headers['User-Agent'], `KimiCLI/${KIMI_CLI_VERSION}`)
    assert.equal(headers['X-Msh-Platform'], 'kimi_code_cli')
    assert.equal(headers['X-Msh-Version'], KIMI_CLI_VERSION)
    assert.equal(headers['X-Msh-Device-Id'], deviceId)
    assert.ok((headers['X-Msh-Device-Name'] ?? '').length > 0)
    assert.match(headers['X-Msh-Device-Model'] ?? '', /\S+ .+ \S+/)
    assert.ok((headers['X-Msh-Os-Version'] ?? '').length > 0)
  })

  test('joins the CLI product and the harness attribution into one User-Agent', () => {
    const headers = kimiRequestHeaders(kimiIdentityHeaders('a'.repeat(32)), { authorization: 'Bearer token' })
    assert.equal(headers.authorization, 'Bearer token')
    assert.match(headers['User-Agent'] ?? '', /^KimiCLI\/\S+ deepseek-harness\/\S+ \(\+https:\/\//)
    // The attribution header must not survive as a second, competing field.
    assert.equal(headers['user-agent'], undefined)
    assert.deepEqual(Object.keys(headers).filter((key) => key.toLowerCase() === 'user-agent'), ['User-Agent'])
  })

  test('keeps machine-derived headers within the ByteString range', () => {
    // Regression: a CJK Windows hostname (COMPUTERNAME="小星") used to make
    // `new Headers(...)` throw before the device-authorization request was sent.
    assert.equal(byteStringSafe('plain-host'), 'plain-host')
    assert.equal(byteStringSafe('小星'), '%E5%B0%8F%E6%98%9F')
    for (const value of Object.values(kimiIdentityHeaders('a'.repeat(32)))) {
      for (const char of value) assert.ok(char.codePointAt(0)! <= 0xff, `unsafe header value: ${value}`)
    }
    assert.doesNotThrow(() => new Headers(kimiIdentityHeaders('a'.repeat(32))))
  })

  test('truncation never leaves a dangling percent escape', () => {
    // '小' encodes to 9 chars; 30 of them encode to 270 chars, so the
    // 200-char cut lands mid-escape ('…%E'). The trimmed value must end
    // on a complete escape.
    const long = byteStringSafe('小'.repeat(30))
    assert.equal(long.length, 198)
    assert.ok(long.endsWith('%8F'))
    assert.doesNotMatch(long, /%[0-9A-F]?$/)
    assert.doesNotThrow(() => new Headers({ 'X-Msh-Device-Name': long }))
    // A value that already ends on a complete escape keeps it.
    assert.equal(byteStringSafe('小'.repeat(22)).length, 198)
    assert.ok(byteStringSafe('小'.repeat(22)).endsWith('%8F'))
  })
  })
})
