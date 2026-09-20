// ==================================================
// server.js
// ==================================================

import "dotenv/config";

import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

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


// ==================================================
// APP
// ==================================================

const app = express();

const PORT = process.env.PORT || 5000;


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

  "http://192.168.100.19:5175",

  "http://192.168.100.31:5175",
  // Red actual CASA
  "http://169.254.83.107:5175"

];


app.use(
  cors({

    origin: function (origin, callback) {

      // Permitir peticiones sin origin
      // como Postman o algunas herramientas
      if (!origin) {

        return callback(
          null,
          true
        );

      }


      if (
        allowedOrigins.includes(origin)
      ) {

        return callback(
          null,
          true
        );

      }


      return callback(
        new Error(
          "No permitido por CORS: " + origin
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
  http.createServer(app);


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
  fileURLToPath(import.meta.url);

const __dirname =
  path.dirname(__filename);


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
  "/api/usuario-independiente",
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

app.get(
  "/",
  (_req, res) => {

    res.send(
      "✅ Backend de B-emocional corriendo"
    );

  }
);


// ==================================================
// MANEJO DE RUTA NO ENCONTRADA
// ==================================================

app.use(
  (req, res) => {

    console.log(
      `⚠️ Ruta no encontrada: ${req.method} ${req.originalUrl}`
    );

    res.status(404).json({

      success: false,

      message:
        "Ruta no encontrada",

      ruta:
        req.originalUrl

    });

  }
);


// ==================================================
// MANEJO GLOBAL DE ERRORES
// ==================================================

app.use(
  (err, req, res, next) => {

    console.error(
      "❌ Error del servidor:",
      err
    );


    if (
      res.headersSent
    ) {

      return next(err);

    }


    res.status(
      err.status || 500
    ).json({

      success: false,

      message:
        err.message ||
        "Error interno del servidor"

    });

  }
);


// ==========================================
// SERVIR FRONTEND EN PRODUCCIÓN
// ==========================================
app.use(express.static(path.join(__dirname, 'dist')));

app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});