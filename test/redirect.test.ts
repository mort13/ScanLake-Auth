import { describe, expect, it } from 'vitest'
import { isAllowedClientId, isAllowedRedirectUri } from '../src/desktop/redirect'

describe('isAllowedRedirectUri', () => {
  it.each([
    'http://127.0.0.1:1024/callback',
    'http://127.0.0.1:53682/callback',
    'http://127.0.0.1:65535/callback',
    'http://[::1]:1024/callback',
    'http://[::1]:49152/callback',
  ])('accepts %s', (uri) => {
    expect(isAllowedRedirectUri(uri)).toBe(true)
  })

  it.each([
    ['localhost', 'http://localhost:53682/callback'],
    ['https', 'https://127.0.0.1:53682/callback'],
    ['no port', 'http://127.0.0.1/callback'],
    ['port 80', 'http://127.0.0.1:80/callback'],
    ['port below 1024', 'http://127.0.0.1:1023/callback'],
    ['port above 65535', 'http://127.0.0.1:65536/callback'],
    ['port 0', 'http://127.0.0.1:0/callback'],
    ['leading zero port', 'http://127.0.0.1:01024/callback'],
    ['six-digit port', 'http://127.0.0.1:100000/callback'],
    ['userinfo', 'http://user@127.0.0.1:53682/callback'],
    ['userinfo with password', 'http://user:pw@127.0.0.1:53682/callback'],
    ['query', 'http://127.0.0.1:53682/callback?x=1'],
    ['empty query', 'http://127.0.0.1:53682/callback?'],
    ['fragment', 'http://127.0.0.1:53682/callback#x'],
    ['other path', 'http://127.0.0.1:53682/other'],
    ['trailing slash', 'http://127.0.0.1:53682/callback/'],
    ['sub path', 'http://127.0.0.1:53682/callback/x'],
    ['path traversal', 'http://127.0.0.1:53682/x/../callback'],
    ['other loopback address', 'http://127.0.0.2:53682/callback'],
    ['short IPv4 form', 'http://127.1:53682/callback'],
    ['public host', 'http://example.com:53682/callback'],
    ['scanlake host', 'https://auth.scanlake.rocks/callback'],
    ['long IPv6 loopback', 'http://[0:0:0:0:0:0:0:1]:53682/callback'],
    ['upper-case scheme', 'HTTP://127.0.0.1:53682/callback'],
    ['encoded path', 'http://127.0.0.1:53682/%63allback'],
    ['whitespace', ' http://127.0.0.1:53682/callback'],
    ['trailing newline', 'http://127.0.0.1:53682/callback\n'],
    ['empty', ''],
  ])('rejects %s', (_label, uri) => {
    expect(isAllowedRedirectUri(uri)).toBe(false)
  })

  it('rejects non-strings', () => {
    expect(isAllowedRedirectUri(undefined)).toBe(false)
    expect(isAllowedRedirectUri(null)).toBe(false)
    expect(isAllowedRedirectUri(['http://127.0.0.1:53682/callback'])).toBe(false)
  })
})

describe('isAllowedClientId', () => {
  it('accepts only scanlake-desktop', () => {
    expect(isAllowedClientId('scanlake-desktop')).toBe(true)
    expect(isAllowedClientId('ScanLake-Desktop')).toBe(false)
    expect(isAllowedClientId('scanlake-desktop ')).toBe(false)
    expect(isAllowedClientId('')).toBe(false)
    expect(isAllowedClientId(undefined)).toBe(false)
  })
})
