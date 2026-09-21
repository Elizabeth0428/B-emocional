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
import usuarioRHRoutes from "./routes/usuarioRH.js";
import usuariosEducativoRoutes from "./routes/usuarioEducativo.js";
import usuariosIndependienteRoutes from "./routes/usuarioIndependiente.js";
import prospectosRoutes from "./routes/prospectos.js";

// ==================================================
// APP
// ==================================================
const app = express();

// CONFIANZA EN EL PROXY DE HOSTINGER (Soluciona la advertencia de express-rate-limit)
app.set('trust proxy', 1);

// ==================================================
// SEGURIDAD
// ==================================================
app.use(helmet());

// ==================================================
// CORS
// ==================================================
const allowedOrigins = [
  "https://reflejoyalma.com",
  "https://www.reflejoyalma.com",
  "http://localhost:5173",
  "http://localhost:5174",
  "http://localhost:5175",
  "http://192.168.0.13:5173",
  "http://192.168.0.13:5174",
  "http://192.168.0.13:5175",
  "http://192.168.1.243:5175",
  "http://192.168.1.79:5175",
  "http://192.168.100.19:5175",
  "http://192.168.100.31:5175",
  "http://169.254.83.107:5175"
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("No permitido por CORS: " + origin));
    },
    credentials: true,
    exposedHeaders: ["Content-Range", "Accept-Ranges"]
  })
);

// ==================================================
// HTTP SERVER & PEERJS
// ==================================================
const server = http.createServer(app);
const peerServer = ExpressPeerServer(server, { path: "/myapp" });
app.use("/peerjs", peerServer);

// ==================================================
// RATE LIMIT & BODY PARSERS
// ==================================================
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 500,
    message: "Demasiadas solicitudes desde esta IP, intenta de nuevo más tarde."
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==================================================
// DIRECTORIOS Y CARPETAS UPLOADS
// ==================================================
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

fsExtra.ensureDirSync(path.join(__dirname, "uploads/multimedia"));
fsExtra.ensureDirSync(path.join(__dirname, "uploads/imagenes"));
fsExtra.ensureDirSync(path.join(__dirname, "uploads/pdfs"));

// ==================================================
// RUTAS API
// ==================================================
app.use("/api/reportes", reporteRoutes);
app.use("/api/ia", iaRoutes);
app.use("/api", authRoutes);
app.use("/api/pacientes", pacientesRoutes);
app.use("/api/sesiones", sesionesRoutes);
app.use("/api/historial-inicial", historialRoutes);
app.use("/api/seguimiento", seguimientoRoutes);
app.use("/api/notas", notasRoutes);
app.use("/api/archivos", archivosRoutes);
app.use("/api/citas", citasRoutes);
app.use("/api/psicologos", psicologosRoutes);
app.use("/api/evaluation", evaluationRoutes);
app.use("/stream", streamRoutes);
app.use("/api/usuario-rh", usuarioRHRoutes);
app.use("/api/usuario-educativo", usuariosEducativoRoutes);
app.use("/api/usuario-independiente", usuariosIndependienteRoutes);
app.use("/api/prospectos", prospectosRoutes);

app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ==================================================
// MANEJO DE RUTAS NO ENCONTRADAS (SOLO PARA LA API)
// ==================================================
app.use("/api", (req, res) => {
  console.log(`⚠️ Ruta API no encontrada: ${req.method} ${req.originalUrl}`);
  res.status(404).json({
    success: false,
    message: "Ruta de API no encontrada",
    ruta: req.originalUrl
  });
});

// ==================================================
// SERVIR FRONTEND EN PRODUCCIÓN Y COMODÍN DE REACT
// ==================================================
app.use(express.static(path.join(__dirname, 'dist')));

app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'dist', 'index.html'));
});

// ==================================================
// MANEJO GLOBAL DE ERRORES
// ==================================================
app.use((err, req, res, next) => {
  console.error("❌ Error del servidor:", err);
  if (res.headersSent) return next(err);
  res.status(err.status || 500).json({
    success: false,
    message: err.message || "Error interno del servidor"
  });
});

// ==================================================
// ARRANQUE DEL SERVIDOR (Movido al final)
// ==================================================
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Servidor de Mirror Soul corriendo en el puerto ${PORT}`);
});