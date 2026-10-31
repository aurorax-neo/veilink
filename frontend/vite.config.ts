import { defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'
import basicSsl from '@vitejs/plugin-basic-ssl'

// Development proxy only. Production assets are bundled into the unified image.
export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const target = env.VEILINK_API || 'http://127.0.0.1:2545'
  const proxy = {
    '/api': { target, changeOrigin: true, secure: target.startsWith('https:') },
  }
  return {
    plugins: [vue(), basicSsl()],
    base: './',
    build: { outDir: 'dist', emptyOutDir: true },
    server: { host: '127.0.0.1', port: 5173, proxy },
    preview: { host: '127.0.0.1', port: 4173, proxy },
  }
})
