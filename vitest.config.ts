// vitest.config.ts

import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true, // Enables global test functions like describe, it, expect
    environment: 'node' // Sets the environment to Node.js
  }
})
