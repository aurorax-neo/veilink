import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'
import basicSsl from '@vitejs/plugin-basic-ssl'

// Dev server only. Production HTML is written to ../html and served by the veilink binary.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const target = env.VEILINK_API || 'https://127.0.0.1:8443'
  const proxy = {
    '/api': { target, changeOrigin: true, secure: false },
  }
  return {
    plugins: [vue(), basicSsl()],
    base: './',
    build: { outDir: 'dist', emptyOutDir: true },
    server: { host: '127.0.0.1', port: 5173, proxy },
    preview: { host: '127.0.0.1', port: 4173, proxy },
  }
})
