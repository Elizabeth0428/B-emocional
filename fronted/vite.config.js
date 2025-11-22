// vite.config.js
// ✅ Configuración de Vite para React con protección básica en desarrollo.

import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import history from 'connect-history-api-fallback'

export default defineConfig({
  plugins: [react()],

  server: {
    port: 5173,

    // ❌ '0.0.0.0' permitía que otras computadoras en la red entren a tu frontend.
    // ✅ 'localhost' hace que solo funcione desde tu propia PC.
    host: 'localhost',

    middlewareMode: false,

    // ✅ Permite que al actualizar la pagina en rutas como /login o /dashboard no aparezca error 404.
    setupMiddlewares: (middlewares, devServer) => {
      middlewares.use(
        history({
          index: '/index.html', // Página fallback para SPA
          verbose: true,        // Muestra logs en consola
        })
      )
      return middlewares
    },
  },
})
