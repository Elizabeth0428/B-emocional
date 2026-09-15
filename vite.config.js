import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import history from 'connect-history-api-fallback'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    host: '0.0.0.0', // 👈 necesario si quieres entrar desde otra PC usando tu IP LAN
    middlewareMode: false,
    setupMiddlewares: (middlewares, devServer) => {
      middlewares.use(
        history({
          index: '/index.html', // fallback para SPA
          verbose: true,        // logs en consola para debug
        })
      )
      return middlewares
    },
  },
})
