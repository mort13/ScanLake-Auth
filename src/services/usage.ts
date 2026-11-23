/**
 * Reads the Gateway's per-key request counts from Workers Analytics Engine through the
 * Analytics SQL binding. The Gateway writes one data point per authenticated request:
 *
 *   index1 = key hash (sha256 hex)
 *   blob1 = kind ('user' | 'internal'), blob2 = ownerId, blob3 = discordId, blob4 = tier,
 *   blob5 = method, blob6 = path, blob7 = HTTP status
 *   double1 = 1, double2 = response bytes
 *
 * The SQL API weights COUNT/SUM by the sample interval itself, so the queries don't.
 */

const DAY_MS = 86_400_000
const HOUR_MS = 3_600_000
export const USAGE_DAYS = 30
const CACHE_MS = 60_000
const DATASET_RE = /^[A-Za-z0-9_]+$/

export interface KeyUsage {
  requests24h: number
  requests7d: number
  requests30d: number
  bytes30d: number
  /** Requests answered with 429 in the last 30 days. */
  limited30d: number
  /** Start of the last hour with a request (unix seconds), or null. */
  lastUsedAt: number | null
  /** Requests per UTC day, oldest first, aligned with `UsageReport.days`. */
  daily: number[]
}

export interface KeyUsageEntry {
  kind: string
  ownerId: string
  discordId: string
  usage: KeyUsage
}

export interface UsageReport {
  available: boolean
  /** Why usage is unavailable (missing binding, query error). */
  error?: string
  /** UTC days covered by `daily`, as YYYY-MM-DD, oldest first. */
  days: string[]
  /** By key hash. */
  keys: Record<string, KeyUsageEntry>
}

interface HourRow {
  key_hash: string
  kind: string
  owner_id: string
  discord_id: string
  hour: string | number
  requests: string | number
  bytes: string | number
  limited: string | number
}

let cache: { at: number; dataset: string; report: UsageReport } | null = null

/** Drops the cached report (tests). */
export function clearUsageCache(): void {
  cache = null
}

function toNumber(value: unknown): number {
  const n = typeof value === 'number' ? value : Number(value)
  return Number.isFinite(n) ? n : 0
}

/** DateTime values come back as "YYYY-MM-DD HH:MM:SS" (UTC); accept ISO strings and epochs too. */
export function parseTimestamp(value: string | number): number | null {
  if (typeof value === 'number') return value < 1e12 ? value * 1000 : value
  const text = value.includes('T') ? value : value.replace(' ', 'T')
  const ms = Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(text) ? text : `${text}Z`)
  return Number.isNaN(ms) ? null : ms
}

function dayList(now: number): string[] {
  const today = Math.floor(now / DAY_MS) * DAY_MS
  const days: string[] = []
  for (let i = USAGE_DAYS - 1; i >= 0; i--) days.push(new Date(today - i * DAY_MS).toISOString().slice(0, 10))
  return days
}

function emptyUsage(): KeyUsage {
  return {
    requests24h: 0,
    requests7d: 0,
    requests30d: 0,
    bytes30d: 0,
    limited30d: 0,
    lastUsedAt: null,
    daily: new Array<number>(USAGE_DAYS).fill(0),
  }
}

/** Folds hourly rows into per-key totals and a daily series. */
export function buildReport(rows: HourRow[], now: number): UsageReport {
  const days = dayList(now)
  const firstDay = Date.parse(`${days[0]}T00:00:00Z`)
  const keys: Record<string, KeyUsageEntry> = {}

  for (const row of rows) {
    const hourMs = parseTimestamp(row.hour)
    if (hourMs === null || !row.key_hash) continue
    const requests = toNumber(row.requests)
    const entry = (keys[row.key_hash] ??= {
      kind: row.kind || 'internal',
      ownerId: row.owner_id ?? '',
      discordId: row.discord_id ?? '',
      usage: emptyUsage(),
    })
    const usage = entry.usage
    const age = now - hourMs
    usage.requests30d += requests
    usage.bytes30d += toNumber(row.bytes)
    usage.limited30d += toNumber(row.limited)
    // An hour bucket counts as "within 24 h" if it ends inside the window
    if (age < DAY_MS + HOUR_MS) usage.requests24h += requests
    if (age < 7 * DAY_MS + HOUR_MS) usage.requests7d += requests
    if (requests > 0) {
      const hourS = Math.floor(hourMs / 1000)
      if (usage.lastUsedAt === null || hourS > usage.lastUsedAt) usage.lastUsedAt = hourS
    }
    const dayIndex = Math.floor((hourMs - firstDay) / DAY_MS)
    if (dayIndex >= 0 && dayIndex < USAGE_DAYS) usage.daily[dayIndex] += requests
  }
  return { available: true, days, keys }
}

/**
 * Usage of every key over the last 30 days, cached for a minute per isolate.
 * Never throws: without the binding or on a query error the report says unavailable.
 */
export async function loadUsage(
  binding: AnalyticsSQLBinding | undefined,
  dataset: string | undefined,
  now = Date.now(),
): Promise<UsageReport> {
  const days = dayList(now)
  if (!binding) return { available: false, error: 'Analytics binding not configured', days, keys: {} }
  if (!dataset || !DATASET_RE.test(dataset)) return { available: false, error: 'Invalid USAGE_DATASET', days, keys: {} }
  if (cache && cache.dataset === dataset && now - cache.at < CACHE_MS) return cache.report

  // Whole UTC days, so the first day of the series is complete
  const start = new Date(Date.parse(`${days[0]}T00:00:00Z`)).toISOString()
  try {
    const result = await binding.query<Record<string, unknown>>({
      query: `
        SELECT index1 AS key_hash, blob1 AS kind, blob2 AS owner_id, blob3 AS discord_id,
               toStartOfInterval(timestamp, INTERVAL '1' HOUR) AS hour,
               COUNT(*) AS requests, SUM(double2) AS bytes, countIf(blob7 = '429') AS limited
        FROM events.analyticsEngine.${dataset}
        WHERE timestamp >= $start
        GROUP BY index1, blob1, blob2, blob3, hour
        LIMIT 100000`,
      params: { start },
    })
    const report = buildReport(result.data as unknown as HourRow[], now)
    cache = { at: now, dataset, report }
    return report
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    console.warn('[usage] analytics query failed:', message)
    return { available: false, error: message, days, keys: {} }
  }
}
