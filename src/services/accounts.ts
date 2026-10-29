import type { Me } from '../types'
import { avatarUrl, type DiscordUser } from './discord'
import { nowS } from './session'

export const MAX_USER_IDS = 20

interface AccountRow {
  discord_id: string
  username: string
  global_name: string | null
  avatar: string | null
  primary_user_id: string | null
  user_name: string
  org: string
}

/** Creates the account on first login, or refreshes the Discord name and avatar. */
export async function upsertAccount(db: D1Database, user: DiscordUser): Promise<void> {
  await db
    .prepare(
      `INSERT INTO accounts (discord_id, username, global_name, avatar, created_at, updated_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?5)
       ON CONFLICT (discord_id) DO UPDATE SET
         username = excluded.username,
         global_name = excluded.global_name,
         avatar = excluded.avatar,
         updated_at = excluded.updated_at`,
    )
    .bind(user.id, user.username, user.global_name, user.avatar, nowS())
    .run()
}

export async function loadMe(db: D1Database, discordId: string): Promise<Me | null> {
  const [account, ids] = await db.batch([
    db
      .prepare(
        `SELECT discord_id, username, global_name, avatar, primary_user_id, user_name, org
         FROM accounts WHERE discord_id = ?`,
      )
      .bind(discordId),
    db.prepare('SELECT user_id FROM user_ids WHERE discord_id = ? ORDER BY linked_at').bind(discordId),
  ])
  const row = account.results[0] as AccountRow | undefined
  if (!row) return null

  return {
    discord: {
      id: row.discord_id,
      username: row.username,
      globalName: row.global_name,
      avatarUrl: avatarUrl(row.discord_id, row.avatar),
    },
    primaryUserId: row.primary_user_id,
    userIds: (ids.results as { user_id: string }[]).map((r) => r.user_id),
    profile: { userName: row.user_name, org: row.org },
  }
}

/**
 * Links a ScanLake userId to the account; the first linked ID becomes the primary.
 * 'taken' means another account already owns the ID.
 */
export async function linkUserId(
  db: D1Database,
  discordId: string,
  userId: string,
): Promise<'linked' | 'taken' | 'limit'> {
  const owner = await db
    .prepare('SELECT discord_id FROM user_ids WHERE user_id = ?')
    .bind(userId)
    .first<{ discord_id: string }>()
  if (owner) return owner.discord_id === discordId ? 'linked' : 'taken'

  const count = await db
    .prepare('SELECT COUNT(*) AS n FROM user_ids WHERE discord_id = ?')
    .bind(discordId)
    .first<{ n: number }>()
  if ((count?.n ?? 0) >= MAX_USER_IDS) return 'limit'

  const now = nowS()
  const [insert] = await db.batch([
    db
      .prepare('INSERT INTO user_ids (user_id, discord_id, linked_at) VALUES (?, ?, ?) ON CONFLICT (user_id) DO NOTHING')
      .bind(userId, discordId, now),
    db
      .prepare(
        `UPDATE accounts SET primary_user_id = ?2, updated_at = ?3
         WHERE discord_id = ?1 AND primary_user_id IS NULL
           AND EXISTS (SELECT 1 FROM user_ids WHERE user_id = ?2 AND discord_id = ?1)`,
      )
      .bind(discordId, userId, now),
  ])
  // Someone linked the ID between the check and the insert: report who owns it now
  if (!insert.meta.changes) return linkUserId(db, discordId, userId)
  return 'linked'
}

export async function saveProfile(
  db: D1Database,
  discordId: string,
  userName: string,
  org: string,
): Promise<void> {
  await db
    .prepare('UPDATE accounts SET user_name = ?, org = ?, updated_at = ? WHERE discord_id = ?')
    .bind(userName, org, nowS(), discordId)
    .run()
}

/**
 * Removes everything stored about the Discord user: account, linked IDs, sessions
 * (web and desktop) and unused desktop login codes.
 */
export async function deleteAccount(db: D1Database, discordId: string): Promise<void> {
  await db.batch([
    db.prepare('DELETE FROM sessions WHERE discord_id = ?').bind(discordId),
    db.prepare('DELETE FROM desktop_codes WHERE discord_id = ?').bind(discordId),
    db.prepare('DELETE FROM user_ids WHERE discord_id = ?').bind(discordId),
    db.prepare('DELETE FROM accounts WHERE discord_id = ?').bind(discordId),
  ])
}
