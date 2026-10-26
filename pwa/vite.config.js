import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
  },
  worker: {
    format: 'es',
  },
  optimizeDeps: {
    exclude: ['@noir-lang/noir_js', '@aztec/bb.js'],
  },
})
