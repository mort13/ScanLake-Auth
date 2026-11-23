/**
 * Gateway API tiers. This is the only place the limits live: they are copied into each
 * key's KV entry, and the Gateway enforces whatever the entry says. Limits count per
 * account, so all keys of one account share them.
 */
export type Tier = 'verified' | 'trusted' | 'blocked'

export interface TierLimits {
  /** Active keys an account may hold at once. */
  maxKeys: number
  perMinute: number
  perDay: number
}

export const TIERS: Record<Tier, TierLimits> = {
  // Every Discord login
  verified: { maxKeys: 2, perMinute: 60, perDay: 2_000 },
  // Set by an admin
  trusted: { maxKeys: 5, perMinute: 600, perDay: 20_000 },
  // Set by an admin: all keys are revoked and no new ones can be made
  blocked: { maxKeys: 0, perMinute: 0, perDay: 0 },
}

export const TIER_NAMES = Object.keys(TIERS) as Tier[]

export function isTier(value: unknown): value is Tier {
  return typeof value === 'string' && (TIER_NAMES as string[]).includes(value)
}

const MINUTE_MS = 60_000
const DAY_MS = 86_400_000

/** The rate-limit windows the Gateway checks for a key of this tier. */
export function gatewayLimits(tier: Tier): { limit: number; windowMs: number }[] {
  const { perMinute, perDay } = TIERS[tier]
  return [
    { limit: perMinute, windowMs: MINUTE_MS },
    { limit: perDay, windowMs: DAY_MS },
  ]
}
