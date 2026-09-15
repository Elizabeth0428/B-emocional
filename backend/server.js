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

  "http://192.168.100.31:5175"

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

app.use(
  "/api/reportes",
  reporteRoutes
);

console.log(
  "✅ Ruta reportes cargada"
);


app.use(
  "/api/ia",
  iaRoutes
);

console.log(
  "✅ Ruta IA cargada"
);


app.use(
  "/api",
  authRoutes
);

console.log(
  "✅ Rutas de autenticación cargadas"
);


app.use(
  "/api/pacientes",
  pacientesRoutes
);


app.use(
  "/api/sesiones",
  sesionesRoutes
);


app.use(
  "/api/historial-inicial",
  historialRoutes
);


app.use(
  "/api/seguimiento",
  seguimientoRoutes
);


app.use(
  "/api/notas",
  notasRoutes
);


app.use(
  "/api/archivos",
  archivosRoutes
);


app.use(
  "/api/citas",
  citasRoutes
);


app.use(
  "/api/psicologos",
  psicologosRoutes
);


// ==================================================
// EVALUACIONES / PRUEBAS
// ==================================================
//
// IMPORTANTE:
//
// evaluation.js contiene rutas como:
//
// /pruebas
// /pruebas/habilitadas/:id_paciente
// /resultados/:id_paciente
//
// Por eso el router debe montarse en:
//
// /api/evaluation
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


// ==================================================
// INICIAR SERVIDOR
// ==================================================

server.listen(
  PORT,
  "0.0.0.0",
  () => {

    console.log(
      `✅ Servidor backend corriendo en http://0.0.0.0:${PORT}`
    );

    console.log(
      `✅ PeerJS corriendo en ws://0.0.0.0:${PORT}/peerjs/myapp`
    );

  }
);