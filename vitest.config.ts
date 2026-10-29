import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin'
import { defineConfig } from 'vitest/config'

export default defineConfig(async () => {
  const migrations = await readD1Migrations('./migrations')
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: './wrangler.toml' },
        miniflare: {
          // Production vars from wrangler.toml, plus what the tests need
          bindings: { TEST_MIGRATIONS: migrations, DISCORD_CLIENT_SECRET: 'test-secret' },
          // The real limit (20/min) would trip on the test suite's many requests
          ratelimits: { DESKTOP_RATE_LIMIT: { namespace_id: '2401', simple: { limit: 1000, period: 60 } } },
        },
      }),
    ],
    test: {
      setupFiles: ['./test/apply-migrations.ts'],
      // Test files share one D1 database and reset it before each test
      fileParallelism: false,
    },
  }
})
