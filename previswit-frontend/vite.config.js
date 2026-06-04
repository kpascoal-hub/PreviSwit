import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vitejs.dev/config/
export default defineConfig({
  root: 'src',
  plugins: [react()],
  server: {
    host: '0.0.0.0', // Necessário para Docker
    port: 3000
  },
  build: {
    outDir: '../dist',
    emptyOutDir: true
  }
})
