import { Hono } from 'hono'
import type { AppEnv, Env } from './types'
import { corsMiddleware, originGuard } from './middleware/cors'
import { requireSession } from './middleware/requireSession'
import { requireAdmin } from './middleware/requireAdmin'
import { createApiKeyRoute, listApiKeysRoute, revokeApiKeyRoute } from './routes/apiKeys'
import {
  adminGetSettingsRoute,
  adminListRoute,
  adminPutSettingsRoute,
  adminRevokeRoute,
  adminSetTierRoute,
} from './routes/admin'
import { callbackRoute, loginRoute, logoutRoute } from './routes/oauth'
import { deleteMeRoute, getMeRoute, linkUserIdRoute, saveProfileRoute } from './routes/me'
import { authorizeDecisionRoute, authorizePageRoute, desktopHeaders, tokenRoute } from './routes/desktop'
import { deleteExpiredSessions } from './services/session'

const app = new Hono<AppEnv>()

app.use('*', corsMiddleware)
app.use('*', originGuard)

// ── Login flow (browser navigations) ──────────────────────────────────────────
app.get('/login', loginRoute)
app.get('/callback', callbackRoute)
app.post('/logout', logoutRoute)

// ── Desktop login (RFC 8252 loopback redirect + PKCE) ─────────────────────────
app.use('/desktop/*', desktopHeaders)
app.get('/desktop/authorize', authorizePageRoute)
app.post('/desktop/authorize', authorizeDecisionRoute)
app.post('/desktop/token', tokenRoute)

// ── Account API (credentials: 'include', or Authorization: Bearer from desktop) ─
app.use('/api/*', async (c, next) => {
  await next()
  c.header('Cache-Control', 'no-store')
})
app.use('/api/me', requireSession)
app.use('/api/me/*', requireSession)
app.get('/api/me', getMeRoute)
app.delete('/api/me', deleteMeRoute)
app.post('/api/me/user-ids', linkUserIdRoute)
app.put('/api/me/profile', saveProfileRoute)

// ── Gateway API keys of the logged-in account ─────────────────────────────────
app.get('/api/me/api-keys', listApiKeysRoute)
app.post('/api/me/api-keys', createApiKeyRoute)
app.delete('/api/me/api-keys/:id', revokeApiKeyRoute)

// ── Admin (Discord IDs in ADMIN_DISCORD_IDS) ──────────────────────────────────
app.use('/api/admin/*', requireSession, requireAdmin)
app.get('/api/admin/api-keys', adminListRoute)
app.post('/api/admin/api-keys/:id/revoke', adminRevokeRoute)
app.put('/api/admin/accounts/:discordId/tier', adminSetTierRoute)
app.get('/api/admin/settings', adminGetSettingsRoute)
app.put('/api/admin/settings', adminPutSettingsRoute)

app.get('/', (c) => c.text('ScanLake Auth'))
app.all('*', (c) => c.json({ error: 'Not found' }, 404))

export default {
  fetch: app.fetch,
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(deleteExpiredSessions(env.AUTH_DB))
  },
} satisfies ExportedHandler<Env>
