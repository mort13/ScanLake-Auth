import { Hono } from 'hono'
import type { AppEnv, Env } from './types'
import { corsMiddleware, originGuard } from './middleware/cors'
import { requireSession } from './middleware/requireSession'
import { callbackRoute, loginRoute, logoutRoute } from './routes/oauth'
import { deleteMeRoute, getMeRoute, linkUserIdRoute, saveProfileRoute } from './routes/me'
import { deleteExpiredSessions } from './services/session'

const app = new Hono<AppEnv>()

app.use('*', corsMiddleware)
app.use('*', originGuard)

// ── Login flow (browser navigations) ──────────────────────────────────────────
app.get('/login', loginRoute)
app.get('/callback', callbackRoute)
app.post('/logout', logoutRoute)

// ── Account API (fetch with credentials: 'include') ───────────────────────────
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

app.get('/', (c) => c.text('ScanLake Auth'))
app.all('*', (c) => c.json({ error: 'Not found' }, 404))

export default {
  fetch: app.fetch,
  async scheduled(_event, env, ctx) {
    ctx.waitUntil(deleteExpiredSessions(env.AUTH_DB))
  },
} satisfies ExportedHandler<Env>
