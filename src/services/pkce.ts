import { base64Url } from './session'

// RFC 7636: only S256 is accepted. A challenge is base64url(SHA-256) without padding,
// a verifier 43-128 unreserved characters.
const CHALLENGE_RE = /^[A-Za-z0-9_-]{43}$/
const VERIFIER_RE = /^[A-Za-z0-9._~-]{43,128}$/

const encoder = new TextEncoder()

export function isValidChallenge(challenge: unknown): challenge is string {
  return typeof challenge === 'string' && CHALLENGE_RE.test(challenge)
}

export function isValidVerifier(verifier: unknown): verifier is string {
  return typeof verifier === 'string' && VERIFIER_RE.test(verifier)
}

/** The S256 code challenge for `verifier`: BASE64URL(SHA-256(ASCII(verifier))). */
export async function s256Challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', encoder.encode(verifier))
  return base64Url(new Uint8Array(digest))
}

/** True when `verifier` hashes to `challenge`, compared in constant time. */
export async function verifyPkce(verifier: string, challenge: string): Promise<boolean> {
  if (!isValidVerifier(verifier) || !isValidChallenge(challenge)) return false
  const a = encoder.encode(await s256Challenge(verifier))
  const b = encoder.encode(challenge)
  return a.byteLength === b.byteLength && crypto.subtle.timingSafeEqual(a, b)
}
