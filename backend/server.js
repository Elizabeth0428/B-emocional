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

import agendaRHRoutes from "./routes/agendaRH.js";


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

import documentosProspectoRoutes from "./routes/documentosProspecto.js";


// ==================================================
// EMPLEADOS RH
// ==================================================

import empleadosRoutes from "./routes/empleados.js";


// ==================================================
// NOM-035
// ==================================================

import nom035Routes from "./routes/nom035.js";

import transferenciasRoutes from "./routes/transferencias.js";

import archivosEntrevistaRHRoutes from "./routes/archivosEntrevistaRH.js";


// ==================================================
// CANALIZACION
// ==================================================

import canalizacionRoutes from "./routes/canalizacionRoutes.js";


// ==================================================
// CÓDIGOS POSTALES MÉXICO
// ==================================================

import codigoPostalRoutes from "./routes/codigoPostalRoutes.js";


// ==================================================
// ORGANIZACIONES
// ==================================================

import organizacionesRoutes from "./routes/organizaciones.js";

import psicologoEstadoRoutes from "./routes/psicologoEstadoRoutes.js";

// ==================================================
// JOB SUSCRIPCIONES
// ==================================================

import {iniciarRevisionSuscripciones} from "./jobs/suscripcionesJob.js";

import planesRoutes from "./routes/planes.js";

import backupsRoutes from "./routes/backups.js";

import {iniciarBackupsAutomaticos} from "./jobs/backupsJob.js";

import checkoutRoutes from "./routes/checkout.js";

// ============================================================
// PAGOS MIRRORSOUL / MERCADO PAGO
// ============================================================

import pagosRoutes from "./routes/pagosRoutes.js";
import passwordInicialRoutes from "./routes/passwordInicialRoutes.js";
// ==================================================
// APP
// ==================================================

const app = express();


const PORT =
  process.env.PORT ||
  5000;


// ==================================================
// REVISIÓN AUTOMÁTICA DE SUSCRIPCIONES
// ==================================================

iniciarRevisionSuscripciones();

iniciarBackupsAutomaticos();


// ==================================================
// SEGURIDAD
// ==================================================

const esProduccion =
  process.env.NODE_ENV ===
  "production";


app.use(
  helmet({

    contentSecurityPolicy:
      esProduccion
        ? undefined
        : {

            directives: {

              "upgrade-insecure-requests":
                null

            }

          },


    crossOriginOpenerPolicy:
      esProduccion
        ? undefined
        : false,


    originAgentCluster:
      esProduccion
        ? undefined
        : false,


    crossOriginResourcePolicy: {

      policy:
        "cross-origin"

    }

  })
);


// ==================================================
// CORS
// ==================================================

const allowedOrigins = [

  "http://localhost:5173",
  "http://localhost:5174",
  "http://localhost:5175",

  "http://192.168.0.13:5173",
  "http://192.168.0.13:5174",
  "http://192.168.0.13:5175",

  "http://192.168.1.243:5175",

  "http://192.168.1.79:5175",

  "http://192.168.100.21:5175",

  "http://192.168.100.31:5175",

  "http://192.168.11.157:5175",

  "http://192.168.1.67:5175",

  "http://192.168.100.24:5175",

  "http://192.168.25.213:5175",

  "http://10.0.0.14:5175"

];


app.use(
  cors({

    origin: function (
      origin,
      callback
    ) {

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


    credentials:
      true,


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

      path:
        "/myapp"

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

    max:
      500,

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

    extended:
      true

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

app.use(
  "/api/raven",
  ravenRoutes
);


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

app.use(
  "/api/empleados",
  empleadosRoutes
);


console.log(
  "✅ Rutas de empleados RH cargadas"
);


// ==================================================
// NOM-035
// ==================================================

app.use(
  "/api/empleados",
  nom035Routes
);


console.log(
  "✅ Rutas NOM-035 cargadas"
);


// ==================================================
// CANALIZACIÓN
// ==================================================

app.use(
  "/api/empleados",
  canalizacionRoutes
);


console.log(
  "✅ Rutas de canalización cargadas"
);


// ==================================================
// CÓDIGOS POSTALES MÉXICO
// ==================================================
//
// GET /api/codigos-postales/:cp
//
// Ejemplo:
// GET /api/codigos-postales/56400
//
// ==================================================

app.use(
  "/api/codigos-postales",
  codigoPostalRoutes
);


console.log(
  "✅ Rutas de códigos postales cargadas"
);


// ==================================================
// AGENDA RH
// ==================================================

app.use(
  "/api/agenda-rh",
  agendaRHRoutes
);


console.log(
  "✅ Rutas de Agenda RH cargadas"
);


// ==================================================
// TRANSFERENCIAS DE EXPEDIENTES
// ==================================================

app.use(
  "/api/transferencias",
  transferenciasRoutes
);


console.log(
  "✅ Rutas de transferencias cargadas"
);


// ==================================================
// ORGANIZACIONES
// ==================================================

app.use(
  "/api/organizaciones",
  organizacionesRoutes
);


console.log(
  "✅ Rutas de organizaciones cargadas"
);

// ==================================================
// RESPALDOS DE BASE DE DATOS
// ==================================================

app.use(
  "/api/backups",
  backupsRoutes
);

console.log(
  "✅ Rutas de respaldos cargadas"
);

// ==================================================
// PLANES
// ==================================================

app.use(
  "/api/planes",
  planesRoutes
);

console.log(
  "✅ Rutas de planes cargadas"
);


// ==================================================
// checkout
// ==================================================


app.use(
  "/api/checkout",
  checkoutRoutes
);

console.log(
  "✅ Rutas de checkout cargadas"
);
// ==================================================
// ESTADO PSICÓLOGOS
// ==================================================

app.use(
  "/api/psicologos",
  psicologoEstadoRoutes
);


console.log(
  "✅ Rutas de psicologoEstado cargadas"
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
    ),

    {

      acceptRanges:
        true,


      setHeaders:
        (
          res,
          filePath
        ) => {


          const extension =
            path.extname(
              filePath
            )
              .toLowerCase();


          if (
            extension ===
            ".webm"
          ) {

            res.setHeader(
              "Content-Type",
              "video/webm"
            );

          }


          if (
            extension ===
            ".mp4"
          ) {

            res.setHeader(
              "Content-Type",
              "video/mp4"
            );

          }


          if (
            extension ===
            ".ogg"
          ) {

            res.setHeader(
              "Content-Type",
              "audio/ogg"
            );

          }


          if (
            extension ===
            ".mp3"
          ) {

            res.setHeader(
              "Content-Type",
              "audio/mpeg"
            );

          }


          res.setHeader(
            "Cross-Origin-Resource-Policy",
            "cross-origin"
          );


          res.setHeader(
            "Accept-Ranges",
            "bytes"
          );

        }

    }

  )

);

// ==================================================
// ARCHIVOS STORAGE
//
// Documentos heredados del proceso de selección.
// Ejemplo:
// /storage/documentos-prospectos/archivo.pdf
// ==================================================

app.use(
  "/storage",
  express.static(
    path.join(
      __dirname,
      "storage"
    )
  )
);

// ==================================================
// RUTA PRINCIPAL
// ==================================================

app.get(

  "/",

  (
    _req,
    res
  ) => {

    res.send(
      "✅ Backend de B-emocional corriendo"
    );

  }

);


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

// ============================================================
// PAGOS MIRRORSOUL / MERCADO PAGO
// ============================================================

app.use(
  "/api/pagos",
  pagosRoutes
);

console.log(
  "✅ Rutas de pagos MirrorSoul cargadas"
);

app.use(
  "/api/auth/password-inicial",
  passwordInicialRoutes
);

console.log(
  "✅ Rutas de contraseña inicial cargadas"
);

// ==================================================
// MANEJO DE RUTA NO ENCONTRADA
// ==================================================

app.use(

  (
    req,
    res
  ) => {


    console.log(
      `⚠️ Ruta no encontrada: ${req.method} ${req.originalUrl}`
    );


    res
      .status(
        404
      )
      .json({

        success:
          false,


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

  (
    err,
    req,
    res,
    next
  ) => {


    console.error(
      "❌ Error del servidor:",
      err
    );


    if (
      res.headersSent
    ) {

      return next(
        err
      );

    }


    res
      .status(
        err.status ||
        500
      )
      .json({

        success:
          false,


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