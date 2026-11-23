import { cloudflareTest, readD1Migrations } from '@cloudflare/vitest-plugin'
import { defineConfig } from 'vitest/config'

export default defineConfig(async () => {
  const migrations = await readD1Migrations('./migrations')
  return {
    plugins: [
      cloudflareTest({
        wrangler: { configPath: './wrangler.toml' },
        // Never connect to the Cloudflare account
        remoteBindings: false,
        miniflare: {
          // Production vars from wrangler.toml, plus what the tests need
          bindings: {
            TEST_MIGRATIONS: migrations,
            DISCORD_CLIENT_SECRET: 'test-secret',
            ADMIN_DISCORD_IDS: '100000000000000009',
            // Not a valid dataset name, so the admin list never touches the Analytics SQL
            // binding (remote only); usage reading is tested with a fake binding
            USAGE_DATASET: 'disabled-in-tests',
          },
          // The real limits (20/min, 5/min) would trip on the test suite's many requests
          ratelimits: {
            DESKTOP_RATE_LIMIT: { namespace_id: '2401', simple: { limit: 1000, period: 60 } },
            API_KEY_RATE_LIMIT: { namespace_id: '2405', simple: { limit: 1000, period: 60 } },
          },
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
