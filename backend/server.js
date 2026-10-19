// ==================================================
// server.js
// ==================================================

import "dotenv/config";

import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import cleaverRoutes from "./routes/cleaver.js";
import ravenRoutes from "./routes/raven.js";
import beta3Routes from "./routes/beta3.js";
import http from "http";
import path from "path";
import fsExtra from "fs-extra";
import { ExpressPeerServer } from "peer";
import { fileURLToPath } from "url";

// ==================================================
// ROUTES
// ==================================================

import reporteRoutes from "./routes/reportes.js";
import iaRoutes from "./routes/ia.js";
import authRoutes from "./routes/auth.js";

import pacientesRoutes from "./routes/pacientes.js";
import sesionesRoutes from "./routes/sesiones.js";

import historialRoutes from "./routes/historial.js";
import seguimientoRoutes from "./routes/seguimiento.js";
import notasRoutes from "./routes/notas.js";

import archivosRoutes from "./routes/archivos.js";
import citasRoutes from "./routes/citas.js";
import psicologosRoutes from "./routes/psicologos.js";

import evaluationRoutes from "./routes/evaluation.js";

import streamRoutes from "./routes/stream.js";

// ==================================================
// NUEVAS RUTAS DE USUARIOS POR ÁREA
// ==================================================

// RH
import usuarioRHRoutes from "./routes/usuarioRH.js";

// Educativo
import usuariosEducativoRoutes from "./routes/usuarioEducativo.js";

// Independiente
import usuariosIndependienteRoutes from "./routes/usuarioIndependiente.js";

// ==================================================
// PROSPECTOS RH
// ==================================================

import prospectosRoutes from "./routes/prospectos.js";
import documentosProspectoRoutes
from "./routes/documentosProspecto.js";

// ==================================================
// EMPLEADOS RH
// ==================================================

import empleadosRoutes from "./routes/empleados.js";

import archivosEntrevistaRHRoutes
from "./routes/archivosEntrevistaRH.js";

// ==================================================
// APP
// ==================================================

const app = express();
app.set('trust proxy', 1);

// ==================================================
// SEGURIDAD
// ==================================================

app.use(helmet());

// ==================================================
// CORS
// ==================================================

const allowedOrigins = [

   // Producción (Hostinger)
  "https://reflejoyalma.com",
  "https://www.reflejoyalma.com",
  "https://red-caribou-571136.hostingersite.com", // <-- El nuevo dominio autorizado
  "http://localhost:5173",


  // Casa
  "http://localhost:5173",
  "http://localhost:5174",
  "http://localhost:5175",

  "http://192.168.0.13:5173",
  "http://192.168.0.13:5174",
  "http://192.168.0.13:5175",

  "http://192.168.1.243:5175",

  // Red actual
  "http://192.168.1.79:5175",

  "http://192.168.100.21:5175",

  "http://192.168.100.31:5175",

  "http://192.168.11.157:5175",

  // Red actual CASA
  "http://192.168.1.67:5175",

  // casa de Karen
  "http://10.0.0.14:5175"
];

app.use(
  cors({
    origin: function (
      origin,
      callback
    ) {

      // Permitir peticiones sin origin
      // como Postman o algunas herramientas
      if (!origin) {
        return callback(
          null,
          true
        );
      }

      if (
        allowedOrigins.includes(
          origin
        )
      ) {
        return callback(
          null,
          true
        );
      }

      return callback(
        new Error(
          "No permitido por CORS: " +
          origin
        )
      );
    },

    credentials: true,

    exposedHeaders: [
      "Content-Range",
      "Accept-Ranges"
    ]
  })
);

// ==================================================
// HTTP SERVER
// ==================================================

const server =
  http.createServer(
    app
  );

// ==================================================
// PEERJS
// ==================================================

const peerServer =
  ExpressPeerServer(
    server,
    {
      path: "/myapp"
    }
  );

app.use(
  "/peerjs",
  peerServer
);

// ==================================================
// RATE LIMIT
// ==================================================

app.use(
  rateLimit({
    windowMs:
      15 * 60 * 1000,

    max: 500,

    message:
      "Demasiadas solicitudes desde esta IP, intenta de nuevo más tarde."
  })
);

// ==================================================
// BODY PARSERS
// ==================================================

app.use(
  express.json()
);

app.use(
  express.urlencoded({
    extended: true
  })
);

// ==================================================
// __dirname PARA ES MODULES
// ==================================================

const __filename =
  fileURLToPath(
    import.meta.url
  );

const __dirname =
  path.dirname(
    __filename
  );

// ==================================================
// CARPETAS UPLOADS
// ==================================================

fsExtra.ensureDirSync(
  path.join(
    __dirname,
    "uploads/multimedia"
  )
);

fsExtra.ensureDirSync(
  path.join(
    __dirname,
    "uploads/imagenes"
  )
);

fsExtra.ensureDirSync(
  path.join(
    __dirname,
    "uploads/pdfs"
  )
);

// ==================================================
// RUTAS API
// ==================================================

// ==================================================
// REPORTES
// ==================================================

app.use(
  "/api/reportes",
  reporteRoutes
);

console.log(
  "✅ Ruta reportes cargada"
);

// ==================================================
// INTELIGENCIA ARTIFICIAL
// ==================================================

app.use(
  "/api/ia",
  iaRoutes
);

console.log(
  "✅ Ruta IA cargada"
);

// ==================================================
// AUTENTICACIÓN
// ==================================================

app.use(
  "/api",
  authRoutes
);

console.log(
  "✅ Rutas de autenticación cargadas"
);

// ==================================================
// PACIENTES
// ==================================================

app.use(
  "/api/pacientes",
  pacientesRoutes
);

// ==================================================
// SESIONES
// ==================================================

app.use(
  "/api/sesiones",
  sesionesRoutes
);

// ==================================================
// HISTORIAL CLÍNICO INICIAL
// ==================================================

app.use(
  "/api/historial-inicial",
  historialRoutes
);

// ==================================================
// SEGUIMIENTO
// ==================================================

app.use(
  "/api/seguimiento",
  seguimientoRoutes
);

// ==================================================
// NOTAS
// ==================================================

app.use(
  "/api/notas",
  notasRoutes
);

// ==================================================
// ARCHIVOS
// ==================================================

app.use(
  "/api/archivos",
  archivosRoutes
);

// ==================================================
// CITAS
// ==================================================

app.use(
  "/api/citas",
  citasRoutes
);

// ==================================================
// PSICÓLOGOS
// ==================================================

app.use(
  "/api/psicologos",
  psicologosRoutes
);

// ==================================================
// EVALUACIONES / PRUEBAS
// ==================================================
//
// evaluation.js contiene rutas como:
//
// /pruebas
// /pruebas/habilitadas/:id_paciente
// /resultados/:id_paciente
//
// Resultado:
//
// /api/evaluation/pruebas
// /api/evaluation/pruebas/habilitadas/:id_paciente
// /api/evaluation/resultados/:id_paciente
//
// ==================================================

app.use(
  "/api/evaluation",
  evaluationRoutes
);

console.log(
  "✅ Rutas de evaluaciones cargadas"
);

// ==================================================
// CLEAVER
// ==================================================

app.use(
  "/api/cleaver",
  cleaverRoutes
);

console.log(
  "✅ Rutas Cleaver cargadas"
);

// ==================================================
// RAVEN
// ==================================================

app.use("/api/raven", ravenRoutes);

console.log(
  "✅ Rutas Raven cargadas"
);

// ==================================================
// BETA
// ==================================================

app.use(
  "/api/beta3",
  beta3Routes
);

// ==================================================
// STREAM
// ==================================================

app.use(
  "/stream",
  streamRoutes
);

// ==================================================
// USUARIO RH
// ==================================================
//
// Archivo:
//
// routes/usuarioRH.js
//
// Endpoint:
//
// /api/usuario-rh
//
// ==================================================

app.use(
  "/api/usuario-rh",
  usuarioRHRoutes
);

console.log(
  "✅ Ruta de usuario RH cargada"
);

// ==================================================
// USUARIOS EDUCATIVOS
// ==================================================
//
// Endpoint:
//
// /api/usuario-educativo
//
// ==================================================

app.use(
  "/api/usuario-educativo",
  usuariosEducativoRoutes
);

console.log(
  "✅ Rutas de usuarios educativos cargadas"
);

// ==================================================
// USUARIOS INDEPENDIENTES
// ==================================================
//
// Endpoint:
//
// /api/usuario-independiente
//
// ==================================================

app.use(
  "/api/usuarios-independiente",
  usuariosIndependienteRoutes
);

console.log(
  "✅ Rutas de usuarios independientes cargadas"
);

// ==================================================
// PROSPECTOS RH
// ==================================================
//
// Archivo:
//
// routes/prospectos.js
//
// Endpoint base:
//
// /api/prospectos
//
// Por ejemplo:
//
// POST /api/prospectos
// GET  /api/prospectos
// GET  /api/prospectos/:id
//
// ==================================================

app.use(
  "/api/prospectos",
  prospectosRoutes
);

console.log(
  "✅ Rutas de prospectos RH cargadas"
);

// ==================================================
// DOCUMENTOS DE PROSPECTOS RH
// ==================================================

app.use(
  "/api/prospectos",
  documentosProspectoRoutes
);

console.log(
  "✅ Rutas de documentos de prospectos RH cargadas"
);

// ==================================================
// EMPLEADOS RH
// ==================================================
//
// Archivo:
//
// routes/empleados.js
//
// Endpoint base:
//
// /api/empleados
//
// Por ejemplo:
//
// GET /api/empleados
// GET /api/empleados/:id
//
// ==================================================

app.use(
  "/api/empleados",
  empleadosRoutes
);

console.log(
  "✅ Rutas de empleados RH cargadas"
);

// ==================================================
// ARCHIVOS UPLOADS
// ==================================================

app.use(
  "/uploads",
  express.static(
    path.join(
      __dirname,
      "uploads"
    )
  )
);

// ==================================================
// RUTA PRINCIPAL
// ==================================================



// ==================================================
// ARCHIVOS / GRABACIONES DE ENTREVISTAS RH
// ==================================================

app.use(
  "/api/archivos-rh",
  archivosEntrevistaRHRoutes
);

console.log(
  "✅ Rutas de grabaciones RH cargadas"
);

// ==========================================
// SERVIR FRONTEND EN PRODUCCIÓN (ARCHIVOS ESTÁTICOS)
// ==========================================
app.use(express.static(path.join(__dirname, 'dist')));

// ==================================================
// MANEJO DE RUTA NO ENCONTRADA (¡SOLO PARA LA API!)
// ==================================================
app.use(
  "/api",
  (req, res) => {
    console.log(`⚠️ Ruta de API no encontrada: ${req.method} ${req.originalUrl}`);
    res.status(404).json({
      success: false,
      message: "Ruta de API no encontrada",
      ruta: req.originalUrl
    });
  }
);

// ==========================================
// FALLBACK PARA REACT ROUTER (EL PUENTE AL FRONTEND)
// ==========================================
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

// ==================================================
// MANEJO GLOBAL DE ERRORES
// ==================================================
app.use(
  (err, req, res, next) => {
    console.error("❌ Error del servidor:", err);
    if (res.headersSent) {
      return next(err);
    }
    res.status(err.status || 500).json({
      success: false,
      message: err.message || "Error interno del servidor"
    });
  }
);

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Servidor de Mirror Soul corriendo en el puerto ${PORT}`);
});