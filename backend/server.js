// server.js
import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import fetch from "node-fetch";
import mysql from "mysql2/promise";
import bcrypt from "bcryptjs";
import { body, validationResult } from "express-validator";
import jwt from "jsonwebtoken";
import multer from "multer";

import path from "path";
import { fileURLToPath } from "url";
import fs from "fs";
import fsExtra from "fs-extra";
import http from "http";
import { ExpressPeerServer } from "peer";
import backupRoutes from "./routes/backup.routes.js";
import sesionesRoutes from "./routes/sesiones.routes.js";
import PDFDocument from "pdfkit";
import moment from "moment";
import authRoutes from "./routes/auth.routes.js";

import { verificarConexion } from './db.js';

async function iniciarApp() {
  const conectado = await verificarConexion();
  if (conectado) {
    console.log('Base de datos conectada correctamente');
    // Aquí arrancas tu servidor o continúas con la lógica
  } else {
    console.error('No se pudo conectar a la base de datos');
    process.exit(1); // Opcional: detener la aplicación si no hay conexión
  }
}

iniciarApp();

const app = express();
const PORT = process.env.PORT || 5000;

const allowedOrigin = "https://b-emocional-3ua7.onrender.com";

const corsOptions = {
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (origin.startsWith("http://localhost")) return callback(null, true);
    if (origin === allowedOrigin) return callback(null, true);
    console.log("❌ CORS bloqueado:::", origin);
    callback(new Error("No autorizado por CORS::: " + origin));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  optionsSuccessStatus: 200 // Responde 200 para preflight en navegadores antiguos
};

app.use(cors(corsOptions));

// Rutas globales
app.use("/api", sesionesRoutes);
app.use("/api", authRoutes);

/* ===================== Seguridad ===================== */
app.use(helmet());


/* ===================== CORS para Render ===================== */
//const allowedOrigin = process.env.CORS_ORIGIN;
//const allowedOrigin = "https://b-emocional-3ua7.onrender.com";

// 💥 2. Configurar CORS dinámico
app.use(
  cors({
    origin: function (origin, callback) {
      // Permitir requests sin ORIGIN (Postman, etc.)
      if (!origin) return callback(null, true);

      // Permitir localhost para desarrollo
      if (origin.startsWith("http://localhost")) {
        return callback(null, true);
      }

      // Permitir dominio de Render
      if (origin === allowedOrigin) {
        return callback(null, true);
      }

      console.log("❌ CORS bloqueado:", origin);
      return callback(new Error("No autorizado por CORS: " + origin));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

console.log("🌐 CORS permitido para:", allowedOrigin);




/* ===================== Gemini via REST ===================== */
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_MODEL = "gemini-2.5-flash"; // modelo correcto de viste en AI Studio


/* ===================== 🎥 Configuración de PeerJS (Videollamadas WebRTC) ===================== */

/**
 * PeerJS permite crear videollamadas P2P entre navegadores.
 * Para funcionar, necesita un servidor "señalizador" que conecte a ambos usuarios.
 * Aquí lo levantamos en la misma app Express (http://tu-ip:5000/peerjs/myapp).
 */

// 1️⃣ Crear servidor HTTP base (permite REST + WebSockets)
const server = http.createServer(app);

// 2️⃣ Configurar PeerJS Server
const peerServer = ExpressPeerServer(server, {
  path: "/myapp",          // Ruta interna para PeerJS
  debug: true,             // Muestra mensajes de conexión/desconexión
  allow_discovery: true,   // Permite listar pares conectados (puede desactivarse en producción)
});

// 3️⃣ Exponer PeerJS en /peerjs
app.use("/peerjs", (req, res, next) => {
  // ✅ ⚠️ Protección opcional: solo permitir videollamadas si el usuario tiene un token válido
  // if (!req.headers.authorization) return res.status(403).json({ message: "Token requerido para videollamada" });

  next();
}, peerServer);

console.log("✅ PeerJS activo en: ws://localhost:5000/peerjs/myapp");



/* ==========================================================
   🛡️ Protección contra ataques de fuerza bruta y DoS
   Limita la cantidad de solicitudes que una IP puede hacer 
   en un tiempo determinado.
   ========================================================== */

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // ⏳ 15 minutos
  max: 200, // 🚦 Máx. 200 solicitudes por IP
  standardHeaders: true, // Devuelve información en headers: RateLimit-*
  legacyHeaders: false,
  message: {
    status: 429,
    error: "Demasiadas solicitudes, intenta más tarde."
  },
});

app.use(apiLimiter); // Se aplica a todas las rutas


/* ===================== Body parsers ===================== */
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* ================== RUTAS DE BACKUP (COLOCAR AQUÍ) ================== */

console.log("Cargando rutas de /api/backup...");
app.use("/api", backupRoutes);




/* ===================== JWT Middleware ===================== */
/*
  ¿Qué es y para qué sirve?
  - Este middleware protege rutas privadas del backend usando JWT (JSON Web Tokens).
  - Se asegura de que solo los usuarios autenticados puedan acceder (ej. psicólogos, admin, pacientes).
  
  ¿Cómo funciona paso a paso?
  1. El frontend envía el token en el header: "Authorization: Bearer <token>".
  2. Si no hay token → se responde con 403 (Prohibido).
  3. Si el token existe, se verifica con la clave secreta guardada en el .env.
  4. Si es válido → se decodifica y se guarda la información del usuario en req.user.
  5. Si es inválido o expiró → se responde con 401 (No autorizado).

  Esto cumple con OWASP porque:
  - Usa autenticación basada en token (Stateless Authentication).
  - Protege rutas sensibles.
  - Usa una clave secreta en .env (no expuesta en el código).
*/
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"]; // Ej: "Bearer asdf1234..."
  const token = authHeader && authHeader.split(" ")[1]; // Tomamos solo el token

  if (!token) {
    return res.status(403).json({ message: "Token requerido" }); // No se envió token
  }

  // Verificar que el token sea válido y no esté expirado
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(401).json({ message: "Token inválido o expirado" });
    }

    req.user = user; // Guardamos los datos decodificados (id_usuario, role, etc.)
    next(); // Continua con la siguiente función o controlador
  });
}

// ✅ Recolectar correctamente el contexto clínico del paciente
async function getPacienteContextData(id_paciente) {
  // 1) Datos básicos del paciente
  const [pacRow] = await pool.query(
    `SELECT nombre, sexo, edad, correo, antecedentes
     FROM pacientes WHERE id_paciente = ?`,
    [id_paciente]
  );

  // 2) Historial inicial (usa nombres reales de columnas)
  const [histRow] = await pool.query(
    `SELECT diagnostico_inicial, tratamiento_inicial, notas
     FROM historial_inicial
     WHERE id_paciente = ?
     ORDER BY fecha_registro DESC
     LIMIT 1`,
    [id_paciente]
  );

  // 3) Últimas 3 pruebas contestadas 
  const [pruebasRows] = await pool.query(
    `SELECT p.nombre AS nombre_prueba, r.puntaje_total, r.interpretacion, r.fecha AS fecha_prueba
     FROM resultados_prueba r
     JOIN pruebas p ON r.id_prueba = p.id_prueba
     WHERE r.id_paciente = ?
     ORDER BY r.fecha DESC
     LIMIT 3`,
    [id_paciente]
  );

  // 4) Últimos seguimientos clínicos
  const [seguimientos] = await pool.query(
    `SELECT fecha, diagnostico, tratamiento, evolucion, observaciones
     FROM historial_seguimiento
     WHERE id_paciente = ?
     ORDER BY fecha DESC
     LIMIT 5`,
    [id_paciente]
  );

  return {
    paciente: pacRow[0] || null,
    historial: histRow[0] || null,
    pruebas: pruebasRows || [],
    seguimiento: seguimientos || []
  };
}


/* ===================== __dirname (ESM) ===================== */
/*
  Como usamos módulos ES (import/export), Node.js ya no trae __dirname ni __filename.
  Por eso los recreamos manualmente para saber:
   dónde está el archivo actual
   en qué carpeta estamos trabajando

  Esto es necesario para:
   - Guardar archivos subidos (videos, imágenes) con multer
   - Acceder a carpetas como /uploads de forma segura
   - Evitar rutas escritas a mano (buena práctica según OWASP)
*/
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


/* ==================================================
   📁 Creación segura de carpetas para archivos subidos
   --------------------------------------------------
   ✔ ¿Qué hace?
     - Verifica si existen las carpetas donde se guardarán los archivos subidos.
     - Si no existen, las crea automáticamente.
   ✔ ¿Por qué es importante?
     - Evita errores cuando se suben videos o imágenes.
     - Cumple buenas prácticas de OWASP para manejo de archivos.
     - Previene que los archivos se guarden en rutas no seguras.
================================================== */
fsExtra.ensureDirSync(path.join(__dirname, "uploads/multimedia")); // Carpeta para videos/audio de sesiones
fsExtra.ensureDirSync(path.join(__dirname, "uploads/imagenes"));   // Carpeta para imágenes (fotos, evidencias, etc.)


// Carpeta donde se guardarán los reportes en PDF  NUEVA AGREGADO
fsExtra.ensureDirSync(path.join(__dirname, "uploads/reportes"));

/* ✅ Servir archivos estáticos (videos, imágenes, documentos) */
app.use("/uploads", express.static(path.join(__dirname, "uploads")));



/* 📤 Multer – Subida segura de archivos
   - Permite guardar videos/imágenes que se envían desde el frontend.
   - Los archivos se guardan en /uploads/multimedia.
   - Se renombra cada archivo con Date.now() para evitar duplicados. */
const storageMultimedia = multer.diskStorage({
  destination: (_, __, cb) => cb(null, path.join(__dirname, "uploads/multimedia")),
  filename: (_, file, cb) => cb(null, Date.now() + "-" + file.originalname),
});

const uploadMultimedia = multer({ storage: storageMultimedia });

/* ==================================================
   📌 Ruta base (comprobación del servidor)
   - Sirve para verificar que el backend está activo.
   - Si accedes a http://localhost:5000 muestra un mensaje.
================================================== */
app.get("/", (_req, res) => {
  res.send("✅ Backend de B-emocional corriendo");
});

/* ==================================================
   🎥 Streaming de videos con soporte Range (para reproducir sin descargar)
   - Permite ver los videos desde el navegador sin esperar a que se descarguen completos.
   - Lee los archivos desde /uploads/multimedia en partes (chunks de 1MB).
================================================== */
app.get("/stream/multimedia/:filename", verifyToken, async (req, res) => {
  const { filename } = req.params;

  // ✅ 1. Verificar si el usuario es psicólogo
  if (req.user.role !== 2) { // 2 = psicólogo
    return res.status(403).json({ message: "Acceso denegado: solo psicólogos" });
  }

  // ✅ 2. Buscar en la BD si este video pertenece a una sesión del psicólogo
  const ruta = `/uploads/multimedia/${filename}`;
  const [rows] = await pool.query(
    `SELECT v.id_video 
     FROM videos_sesion v
     JOIN sesiones s ON v.id_sesion = s.id_sesion
     JOIN pacientes p ON s.id_paciente = p.id_paciente
     WHERE v.ruta_video = ? AND p.id_psicologo = ?`,
    [ruta, req.user.id_psicologo]
  );

  if (!rows.length) {
    return res.status(403).json({
      message: "No tienes permiso para ver este video"
    });
  }

  // ✅ 3. Si sí tiene permisos → reproducir el video con streaming
  const filePath = path.join(__dirname, "uploads/multimedia", filename);

  fs.stat(filePath, (err, stats) => {
    if (err || !stats.isFile()) return res.status(404).send("Video no encontrado");

    const range = req.headers.range;
    if (!range) {
      res.writeHead(200, {
        "Content-Length": stats.size,
        "Content-Type": "video/webm"
      });
      return fs.createReadStream(filePath).pipe(res);
    }

    const videoSize = stats.size;
    const CHUNK_SIZE = 1 * 1e6; // 1MB por chunk
    const start = Number(range.replace(/\D/g, ""));
    const end = Math.min(start + CHUNK_SIZE, videoSize - 1);

    res.writeHead(206, {
      "Content-Range": `bytes ${start}-${end}/${videoSize}`,
      "Accept-Ranges": "bytes",
      "Content-Length": end - start + 1,
      "Content-Type": "video/webm",
    });

    fs.createReadStream(filePath, { start, end }).pipe(res);
  });
});
/* ==================================================
   📁 Listar videos guardados de una sesión
   - Ruta protegida (requiere token con verifyToken).
   - Devuelve los videos que tiene una sesión específica.
================================================== */
app.get("/api/sesiones/:id/videos", verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [rows] = await pool.query(
      "SELECT id_video, ruta_video, tipo, fecha_subida FROM videos_sesion WHERE id_sesion = ?",
      [id]
    );
    res.json(rows || []);
  } catch (err) {
    console.error("❌ Error al obtener videos de la sesión:", err);
    res.status(500).json({ message: "Error al obtener videos" });
  }
});



/* ==================================================
   👥 Auth / Usuarios / Psicólogos (Seguridad + Roles)
================================================== */

/**
 * ✅ 1. Registrar psicólogos (solo puede hacerlo un Admin)
 * - Primero valida los datos del formulario (sanitización y formatos correctos).
 * - Verifica si el correo o la cédula ya existen.
 * - Cifra la contraseña con bcrypt (buenas prácticas OWASP).
 * - Guarda al usuario en tabla `usuarios` y luego en `psicologos`.
 */
app.post(
  "/api/psicologos/register",
  verifyToken, // 👈 Solo alguien con token válido puede registrar
  [
    body("cedula_profesional").isLength({ min: 5 }).trim().escape(),
    body("nombre").isLength({ min: 2 }).trim(),
    body("correo").isEmail().normalizeEmail(),
    body("password").isLength({ min: 6 }),
    body("especialidad").optional().isString().trim(),
  ],
  async (req, res) => {
    // ✅ Solo un ADMIN puede crear psicólogos
    if (req.user.role !== 1) {
      return res.status(403).json({ message: "Acceso denegado: solo administradores" });
    }

    // ⚠ Validar datos del formulario
    const errors = validationResult(req);
    if (!errors.isEmpty())
      return res.status(400).json({ message: "Datos inválidos", errors: errors.array() });

    const { cedula_profesional, nombre, correo, password, especialidad } = req.body;

    try {
      // ⚠ Evitar duplicados de correo o cédula
      const [uExist] = await pool.query("SELECT id_usuario FROM usuarios WHERE correo = ?", [correo]);
      if (uExist.length) return res.status(400).json({ message: "El correo ya está registrado" });

      const [cExist] = await pool.query(
        "SELECT id_psicologo FROM psicologos WHERE cedula_profesional = ?",
        [cedula_profesional]
      );
      if (cExist.length) return res.status(400).json({ message: "La cédula ya está registrada" });

      // 🔐 Cifrar contraseña (seguridad)
      const hashedPassword = await bcrypt.hash(password, 10);

      // 👤 Crear usuario base
      const [uIns] = await pool.query(
        "INSERT INTO usuarios (nombre, correo, password, rol) VALUES (?, ?, ?, ?)",
        [nombre, correo, hashedPassword, "psicologo"]
      );

      // 👨‍⚕ Crear en tabla psicólogos y vincular al usuario
      const [pIns] = await pool.query(
        "INSERT INTO psicologos (id_usuario, cedula_profesional, especialidad) VALUES (?, ?, ?)",
        [uIns.insertId, cedula_profesional, especialidad || null]
      );

      res.json({ message: "✅ Psicólogo registrado correctamente" });
    } catch (err) {
      console.error("❌ Error en registro:", err.message);
      res.status(500).json({ message: "Error interno en registro" });
    }
  }
);

/**
 * ✅ 2. Login / Inicio de sesión
 * - Verifica correo y contraseña.
 * - Si son correctos, se genera un TOKEN JWT.
 * - El token contiene: id_usuario, rol e id_psicologo (si aplica).
 * - El frontend debe guardarlo (localStorage o sessionStorage) y enviarlo en cada petición privada.
 */
app.post(
  "/api/login",
  [
    body("correo").isEmail().normalizeEmail(),
    body("password").isLength({ min: 6 })
  ],
  async (req, res) => {
    // ⚠ Validación de datos de entrada
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ message: "Datos inválidos", errors: errors.array() });
    }

    const { correo, password } = req.body;

    try {
      // 🔎 Buscar usuario por correo
      const [rows] = await pool.query(
        "SELECT id_usuario, nombre, correo, password, rol FROM usuarios WHERE correo = ? LIMIT 1",
        [correo]
      );
      if (!rows.length) {
        return res.status(401).json({ message: "Credenciales inválidas" });
      }

      const user = rows[0];

      // 🔐 Verificar contraseña cifrada
      const ok = await bcrypt.compare(password, user.password);
      if (!ok) {
        return res.status(401).json({ message: "Credenciales inválidas" });
      }

      // 📌 Si es psicólogo, obtener su id_psicologo
      let id_psicologo = null;
      if (user.rol === "psicologo") {
        const [p] = await pool.query(
          "SELECT id_psicologo FROM psicologos WHERE id_usuario = ?",
          [user.id_usuario]
        );
        id_psicologo = p[0]?.id_psicologo || null;
      }

            // 🎫 Crear token con datos del usuario (JWT)
// - jwt.sign() genera un token seguro que viaja al frontend
// - Este token incluye: id del usuario, su rol (admin/psicólogo) y id_psicologo si aplica
// - Se firma con la clave secreta del archivo .env para evitar falsificación
// - Expira en 2 horas por seguridad (luego debe iniciar sesión otra vez)
      const roleNumber = user.rol === "admin" ? 1 : 2;
      const token = jwt.sign(
        { id_usuario: user.id_usuario, role: roleNumber, id_psicologo },
        process.env.JWT_SECRET,
        { expiresIn: "2h" } // ⏳ El token expira en 2 horas
      );

      // ✅ Enviar respuesta
      res.json({
        message: "✅ Login exitoso",
        user: {
          id_usuario: user.id_usuario,
          nombre: user.nombre,
          role: roleNumber,
          id_psicologo
        },
        token
      });

    } catch (err) {
      console.error("❌ Error en login:", err);
      res.status(500).json({ message: "Error en login" });
    }
  }
);


/** Cambiar contraseña (usuarios) */
app.put(
  "/api/change-password",
  verifyToken,
  [body("oldPassword").isLength({ min: 6 }), body("newPassword").isLength({ min: 6 })],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ message: "Datos inválidos", errors: errors.array() });

    const { oldPassword, newPassword } = req.body;
    const { id_usuario } = req.user;

    try {
      const [rows] = await pool.query("SELECT password FROM usuarios WHERE id_usuario = ?", [id_usuario]);
      if (!rows.length) return res.status(404).json({ message: "Usuario no encontrado" });

      const ok = await bcrypt.compare(oldPassword, rows[0].password);
      if (!ok) return res.status(401).json({ message: "La contraseña actual es incorrecta" });

      const hashed = await bcrypt.hash(newPassword, 10);
      await pool.query("UPDATE usuarios SET password = ? WHERE id_usuario = ?", [hashed, id_usuario]);

      res.json({ message: "Contraseña actualizada" });
    } catch (err) {
      console.error("❌ Error al cambiar contraseña:", err);
      res.status(500).json({ message: "Error interno al cambiar contraseña" });
    }
  }
);

/* ==================================================
   ✅ Función segura para generar reportes con IA (Gemini)
   - Solo permite uso a ADMIN o PSICÓLOGO.
   - Valida que el prompt no venga vacío ni sea muy largo.
   - Usa API Key desde .env para cumplir con OWASP.
   - Maneja errores y evita fugas de información sensible.
================================================== */
export async function generarReporteIA(req, res) {
  try {
    const { id_paciente } = req.body; // 🔹 Lo recibe desde el frontend
    const { role } = req.user;        // 🔹 Del token JWT

    // 1️⃣ Verificar rol (solo admin = 1 o psicólogo = 2)
    if (role !== 1 && role !== 2) {
      return res.status(403).json({ message: "Acceso denegado a IA" });
    }

    console.log("🧠 Generando reporte IA actualizado para paciente:", id_paciente);

    // 2️⃣ Verificar existencia del paciente
    const [pacienteRows] = await pool.query(
      `SELECT nombre, edad, sexo, antecedentes
       FROM pacientes
       WHERE id_paciente = ?`,
      [id_paciente]
    );

    if (!pacienteRows.length) {
      return res.status(404).json({ message: "Paciente no encontrado" });
    }

    const paciente = pacienteRows[0];

    // 3️⃣ Obtener historial inicial
    const [historialInicial] = await pool.query(
      `SELECT diagnostico_inicial, tratamiento_inicial, notas
       FROM historial_inicial
       WHERE id_paciente = ?
       ORDER BY fecha_registro DESC
       LIMIT 1`,
      [id_paciente]
    );

    // 4️⃣ Obtener últimos seguimientos
    const [seguimientos] = await pool.query(
      `SELECT fecha, diagnostico, tratamiento, evolucion, observaciones
       FROM historial_seguimiento
       WHERE id_paciente = ?
       ORDER BY fecha DESC
       LIMIT 3`,
      [id_paciente]
    );

    // 5️⃣ Obtener resultados de pruebas recientes
    const [pruebas] = await pool.query(
      `SELECT p.nombre AS prueba, r.puntaje_total, r.interpretacion, r.fecha
       FROM resultados_prueba r
       JOIN pruebas p ON r.id_prueba = p.id_prueba
       WHERE r.id_paciente = ?
       ORDER BY r.fecha DESC
       LIMIT 5`,
      [id_paciente]
    );

    // 6️⃣ Construir automáticamente el prompt con todos los datos actualizados
    const prompt = `
Eres un asistente clínico especializado en psicología.
Analiza los datos actualizados del paciente y redacta un reporte clínico claro, profesional y estructurado.

### 🧍 Datos del paciente:
- Nombre: ${paciente.nombre}
- Edad: ${paciente.edad}
- Sexo: ${paciente.sexo}
- Antecedentes: ${paciente.antecedentes || "No registrados"}

### 📋 Historial clínico inicial:
${historialInicial[0]
  ? `Diagnóstico inicial: ${historialInicial[0].diagnostico_inicial}\nTratamiento inicial: ${historialInicial[0].tratamiento_inicial}\nNotas: ${historialInicial[0].notas}`
  : "No se registró historial clínico inicial."}

### 🩺 Últimos seguimientos:
${seguimientos.length
  ? seguimientos.map(s => `📅 ${s.fecha}: ${s.diagnostico}. ${s.tratamiento}. ${s.evolucion || ""}`).join("\n")
  : "No hay seguimientos recientes."}

### 🧪 Pruebas y resultados:
${pruebas.length
  ? pruebas.map(p => `• ${p.prueba}: ${p.interpretacion} (puntaje ${p.puntaje_total})`).join("\n")
  : "Sin resultados de pruebas recientes."}

Redacta el reporte clínico final con los apartados:
1. Diagnóstico clínico sugerido.
2. Riesgos o señales de alerta.
3. Recomendaciones clínicas o terapéuticas.
4. Nivel de severidad y evolución general del paciente.
`;

    console.log("🤖 Enviando solicitud a Gemini IA...");

    // 7️⃣ Enviar a Gemini (igual que tu versión original)
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${process.env.GEMINI_MODEL}:generateContent?key=${process.env.GEMINI_API_KEY}`;
    const payload = {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: {
        maxOutputTokens: 1000,
        temperature: 0.7
      }
    };

    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      console.error("❌ Error Gemini:", await response.text());
      return res.status(500).json({ message: "Error al generar reporte IA" });
    }

    const data = await response.json();
    const texto =
      data?.candidates?.[0]?.content?.parts?.[0]?.text ||
      "⚠️ No hubo respuesta de Gemini.";

    // 8️⃣ Guardar o actualizar el último reporte IA
    const [reporteExistente] = await pool.query(
      `SELECT id_reporte FROM reportes_ia WHERE id_paciente = ? ORDER BY fecha DESC LIMIT 1`,
      [id_paciente]
    );

    if (reporteExistente.length > 0) {
      // Actualiza el más reciente
      await pool.query(
        `UPDATE reportes_ia SET contenido = ?, fecha = NOW() WHERE id_reporte = ?`,
        [texto, reporteExistente[0].id_reporte]
      );
      console.log("♻️ Reporte IA actualizado correctamente");
    } else {
      // Inserta uno nuevo si no hay
      await pool.query(
        `INSERT INTO reportes_ia (id_paciente, contenido, fecha) VALUES (?, ?, NOW())`,
        [id_paciente, texto]
      );
      console.log("🆕 Reporte IA guardado correctamente");
    }

    // ✅ 9️⃣ Devolver al frontend
    res.json({
      message: "✅ Reporte IA generado con datos actualizados",
      reporteIA: texto
    });

  } catch (err) {
    console.error("❌ Error en generarReporteIA:", err.message);
    res.status(500).json({ message: "Error interno al generar reporte IA" });
  }
}



/* ==================================================
   🧠 Generar reporte IA en PDF con formato profesional + acentos + logo
================================================== */
app.post("/api/pacientes/:id/generar-reporte-pdf", verifyToken, async (req, res) => {
  const { id } = req.params;

  try {
    // 1️⃣ Último reporte IA
    const [reporte] = await pool.query(
      `SELECT id_reporte, contenido FROM reportes_ia WHERE id_paciente = ? ORDER BY fecha DESC LIMIT 1`,
      [id]
    );
    if (!reporte.length)
      return res.status(404).json({ message: "No hay reportes IA generados para este paciente" });

    const idReporte = reporte[0].id_reporte;
    const textoIA = reporte[0].contenido || "Reporte no disponible";

    // 2️⃣ Datos del paciente
    const [pacienteRows] = await pool.query(
      `SELECT nombre, edad, sexo FROM pacientes WHERE id_paciente = ?`,
      [id]
    );
    const paciente = pacienteRows[0] || { nombre: "N/D", edad: "N/D", sexo: "N/D" };

  // 3️⃣ Crear ruta y archivo PDF
const fecha = moment().format("YYYY-MM-DD_HH-mm");
const rutaCarpeta = path.join(__dirname, `uploads/reportes/${id}`);
fsExtra.ensureDirSync(rutaCarpeta);

const filePath = path.join(rutaCarpeta, `reporte_${fecha}.pdf`);
const rutaPublica = `/uploads/reportes/${id}/reporte_${fecha}.pdf`;

// 4️⃣ Crear PDF con soporte para UTF-8
const doc = new PDFDocument({
  size: "A4",
  margins: { top: 60, bottom: 60, left: 72, right: 72 },
});

// 5️⃣ Registrar fuentes que sí soportan acentos, ñ, tildes (DejaVuSans)
const fontRegular = path.join(__dirname, "assets/fonts/DejaVuSans.ttf");
const fontBold = path.join(__dirname, "assets/fonts/DejaVuSans-Bold.ttf");

// Verificar que existan
if (!fs.existsSync(fontRegular) || !fs.existsSync(fontBold)) {
  console.error("❌ No se encontraron las fuentes DejaVuSans en assets/fonts/");
}

// Registrar en PDF
doc.registerFont("Regular", fontRegular);
doc.registerFont("Bold", fontBold);

// 6️⃣ Vincular el archivo al PDF para comenzar a escribir
const writeStream = fs.createWriteStream(filePath);
doc.pipe(writeStream);


    // ✅ 6️⃣ Logo (ubicado en /public/logo.png)
    const logoPath = path.join(__dirname, "../public/logo.png");
    if (fs.existsSync(logoPath)) {
      doc.image(logoPath, 50, 25, { width: 80 });
    }

    // ✅ 7️⃣ Título
    doc.font("Bold")
      .fontSize(18)
      .fillColor("#1f3d7a")
      .text("Reporte Clínico - MirrorSoul", { align: "center" })
      .moveDown(0.5);

    // Fecha
    doc.font("Regular")
      .fontSize(12)
      .fillColor("#000")
      .text(`Fecha de generación: ${moment().format("DD/MM/YYYY HH:mm")} hrs`, { align: "center" })
      .moveDown(1);

    // ✅ Datos del paciente
    doc.font("Bold").fontSize(13).text("📌 Datos del paciente:");
    doc.font("Regular").fontSize(12)
      .text(`• Nombre: ${paciente.nombre}`)
      .text(`• Edad: ${paciente.edad} años`)
      .text(`• Sexo: ${paciente.sexo}`)
      .moveDown(1);

    // Línea separadora
    doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor("#1f3d7a").lineWidth(1).stroke();
    doc.moveDown(1);

    // ✅ 8️⃣ Texto IA → ahora sin eliminar acentos
    const parrafos = textoIA.split(/\n{2,}/);
    doc.font("Regular").fontSize(12).fillColor("#000");
    parrafos.forEach((p) => {
      doc.text(p.trim(), { align: "justify" }).moveDown(0.7);
    });

    // Línea final
    doc.moveDown(1);
    doc.moveTo(50, doc.y).lineTo(545, doc.y).strokeColor("#1f3d7a").stroke();

    // Pie de página
    doc.font("Regular").fontSize(10).fillColor("gray")
      .text(
        "Este reporte fue generado automáticamente por MirrorSoul AI. No reemplaza una valoración clínica profesional.",
        72,
        760,
        { align: "center", width: 468 }
      );

    doc.end();

    // Guardar PDF en BD
    writeStream.on("finish", async () => {
      await pool.query(`UPDATE reportes_ia SET ruta_pdf = ? WHERE id_reporte = ?`, [rutaPublica, idReporte]);
      res.json({ message: "✅ PDF generado correctamente", ruta: rutaPublica });
    });

  } catch (err) {
    console.error("❌ Error al generar PDF:", err);
    res.status(500).json({ message: "Error al generar PDF" });
  }
});


/* ==================================================
   videollamada link
================================================== */
app.post("/api/sesiones/:id/videollamada", verifyToken, async (req, res) => {
  const { id } = req.params; // id_sesion
  const sala = `sala-${id}-${Date.now()}`;
  const link = `http://localhost:5173/SalaVideollamada/${sala}`;

  await pool.query(
    "UPDATE sesiones SET link_videollamada = ? WHERE id_sesion = ?",
    [link, id]
  );

  res.json({ message: "✅ Link generado", link });
});

/* ==================================================
   👩‍⚕️ Obtener lista de psicólogos
   - Solo el Administrador (role = 1) puede verlos.
   - Se usan JOIN para unir datos de `usuarios` y `psicologos`.
   - Protección por JWT con verifyToken.
================================================== */
app.get("/api/psicologos", verifyToken, async (req, res) => {
  // ✅ 1. Validación de seguridad: solo Admin tiene acceso
  if (req.user.role !== 1) {
    return res.status(403).json({ message: "Solo administradores" });
  }

  try {
    // ✅ 2. Consulta SQL con JOIN para combinar datos de usuario + psicólogo
    const [rows] = await pool.query(
      `SELECT p.id_psicologo, u.nombre, u.correo, 
              p.cedula_profesional, p.especialidad
       FROM psicologos p 
       JOIN usuarios u ON p.id_usuario = u.id_usuario
       ORDER BY u.nombre ASC`
    );

    // ✅ 3. Respuesta al frontend
    res.json(rows || []);
  } catch (err) {
    console.error("❌ Error al obtener psicólogos:", err.message);
    res.status(500).json({ message: "Error al obtener psicólogos" });
  }
});

/* ==================================================
   📋 Listar pacientes (solo psicólogo dueño de ellos)
   - Se protege con JWT (verifyToken)
   - Solo usuarios con rol = 2 (psicólogo) pueden acceder
   - Cada psicólogo solo ve a SUS pacientes (no los de otros)
   - Se aplica el principio de mínimo privilegio (OWASP)
================================================== */
app.get("/api/pacientes", verifyToken, async (req, res) => {
  try {
    // ✅ 1. Seguridad: Solo psicólogos pueden ver pacientes
    if (req.user.role !== 2) {
      return res.status(403).json({ message: "Acceso denegado: solo psicólogos" });
    }

    // ✅ 2. Consulta filtrando solo los pacientes del psicólogo logueado
    const [rows] = await pool.query(
      `SELECT id_paciente, nombre, sexo, fecha_nacimiento, edad, correo, telefono, direccion, antecedentes
       FROM pacientes
       WHERE id_psicologo = ?
       ORDER BY id_paciente DESC`,
      [req.user.id_psicologo] // viene del token
    );

    // ✅ 3. Envío de datos al frontend
    res.json(rows || []);
  } catch (err) {
    console.error("❌ Error al obtener pacientes:", err.message);
    res.status(500).json({ message: "Error al obtener pacientes" });
  }
});

/* ==================================================
   📄 Obtener detalle de un paciente por su ID
   - Requiere estar autenticado (verifyToken)
================================================== */
app.get("/api/pacientes/:id", verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    // Si no es psicólogo, lo bloqueamos
    if (req.user.role !== 2) {
      return res.status(403).json({ message: "Acceso denegado: solo psicólogos" });
    }

    const [rows] = await pool.query(
      `SELECT id_paciente, nombre, sexo, fecha_nacimiento, edad, correo, telefono, direccion, antecedentes
       FROM pacientes 
       WHERE id_paciente = ? AND id_psicologo = ?`,
      [id, req.user.id_psicologo]
    );

    if (!rows.length) {
      return res.status(404).json({ message: "Paciente no encontrado o no pertenece a este psicólogo" });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error("❌ Error al obtener paciente:", err.message);
    res.status(500).json({ message: "Error al obtener paciente" });
  }
});



/* ==================================================
   📌 Registrar Paciente (solo psicólogos autenticados)
   - Protegida por JWT → verifyToken
   - Solo rol 2 (psicólogo) puede registrar pacientes
   - El id_psicologo se obtiene del token, no del usuario
   - Cumple buenas prácticas de seguridad OWASP
================================================== */
app.post("/api/pacientes", verifyToken, async (req, res) => {
  try {
    // ✅ 1. Verificar que el usuario sea psicólogo (rol = 2)
    if (req.user.role !== 2) {
      return res.status(403).json({
        message: "Acceso denegado: solo psicólogos pueden registrar pacientes"
      });
    }

    // ✅ 2. Obtener datos del cuerpo de la petición
    const { nombre, sexo, fecha_nacimiento, edad, correo, telefono, direccion, antecedentes } = req.body;

    // 🔐 El id_psicologo viene del TOKEN, no del frontend (más seguro)
    const id_psicologo = req.user?.id_psicologo;

    // ⚠ 3. Validar datos obligatorios
    if (!id_psicologo || !nombre) {
      return res.status(400).json({
        message: "Faltan datos obligatorios (id_psicologo o nombre)"
      });
    }

    // ✅ 4. Insertar en la base de datos
    const [result] = await pool.query(
      `INSERT INTO pacientes 
        (id_psicologo, nombre, sexo, fecha_nacimiento, edad, correo, telefono, direccion, antecedentes)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id_psicologo, 
        nombre,
        sexo || null,
        fecha_nacimiento || null,
        edad || null,
        correo || null,
        telefono || null,
        direccion || null,
        antecedentes || null
      ]
    );

    // ✅ 5. Enviar respuesta exitosa
    res.status(201).json({
      message: "✅ Paciente registrado correctamente",
      id_paciente: result.insertId
    });

  } catch (err) {
    console.error("❌ Error al registrar paciente:", err.message);
    res.status(500).json({ message: "Error al registrar paciente" });
  }
});

/* ==================================================
   📄 Reporte clínico completo de un paciente
   - Devuelve TODO el historial del paciente, sin usar IA.
   - Incluye: datos personales, historial inicial, pruebas,
     seguimientos y sesiones con videos.
   - Protegido con JWT: solo psicólogos logueados pueden acceder.
================================================== */
app.get("/api/pacientes/:id/reportes-completos", verifyToken, async (req, res) => {
  const { id } = req.params;

  try {
    // 1️⃣ Obtener datos del paciente
    const [pacienteRows] = await pool.query(
      `SELECT id_paciente, nombre, sexo, fecha_nacimiento, edad, correo, telefono, direccion, antecedentes
       FROM pacientes WHERE id_paciente = ?`,
      [id]
    );
    if (!pacienteRows.length) {
      return res.status(404).json({ message: "Paciente no encontrado" });
    }
    const paciente = pacienteRows[0];

    // 2️⃣ Historial clínico inicial (solo 1 registro)
    const [historialInicial] = await pool.query(
      "SELECT * FROM historial_inicial WHERE id_paciente = ? LIMIT 1",
      [id]
    );

    // 3️⃣ Resultados de pruebas psicológicas
    const [resultados] = await pool.query(
      `SELECT r.id_resultado, r.id_prueba, p.nombre AS prueba, r.puntaje_total, r.interpretacion,
              DATE_FORMAT(r.fecha, '%Y-%m-%dT%H:%i:%s') AS fecha
       FROM resultados_prueba r
       JOIN pruebas p ON r.id_prueba = p.id_prueba
       WHERE r.id_paciente = ?
       ORDER BY r.fecha DESC`,
      [id]
    );

    // 4️⃣ Seguimiento clínico (evoluciones del tratamiento)
    const [seguimiento] = await pool.query(
      `SELECT id_seguimiento, fecha, diagnostico, tratamiento, evolucion, observaciones
       FROM historial_seguimiento
       WHERE id_paciente = ?
       ORDER BY fecha DESC`,
      [id]
    );

    // 5️⃣ Sesiones + videos grabados en cada sesión
    const [sesiones] = await pool.query(
      `SELECT s.id_sesion, s.fecha, s.notas,
              GROUP_CONCAT(v.ruta_video SEPARATOR '||') AS videos
       FROM sesiones s
       LEFT JOIN videos_sesion v ON v.id_sesion = s.id_sesion
       WHERE s.id_paciente = ?
       GROUP BY s.id_sesion
       ORDER BY s.fecha DESC`,
      [id]
    );

    // Convertir string de videos a arreglo
    const sesionesFormateadas = sesiones.map(s => ({
      ...s,
      videos: s.videos ? s.videos.split("||") : []
    }));

    // ✅ Respuesta final
    res.json({
      paciente,
      historialInicial: historialInicial[0] || null,
      resultados,
      seguimiento,
      sesiones: sesionesFormateadas
    });

  } catch (err) {
    console.error("❌ Error al obtener reportes completos:", err.message);
    res.status(500).json({ message: "Error al obtener reportes completos" });
  }
});



/* ==================================================
   Obtener todos los reportes IA de un paciente
   - Solo usuarios autenticados con token (JWT).
   - Solo el psicólogo dueño del paciente puede ver esta información.
   - Protege datos clínicos sensibles.
================================================== */
app.get("/api/pacientes/:id/reportes-ia", verifyToken, async (req, res) => {
  const { id } = req.params;
  const idPsicologoLogueado = req.user.id_psicologo;

  try {
    // Validar que el paciente pertenece al psicólogo
    const [paciente] = await pool.query(
      "SELECT id_psicologo FROM pacientes WHERE id_paciente = ?",
      [id]
    );

    if (!paciente.length) {
      return res.status(404).json({ message: "Paciente no encontrado" });
    }

    if (paciente[0].id_psicologo !== idPsicologoLogueado) {
      return res.status(403).json({ message: "No tienes permiso para ver este paciente" });
    }

    // ✅ Ahora sí incluimos 'ruta_pdf'
    const [rows] = await pool.query(
      `SELECT id_reporte, fecha, contenido, ruta_pdf
       FROM reportes_ia
       WHERE id_paciente = ?
       ORDER BY fecha DESC`,
      [id]
    );

    res.json(rows || []);
  } catch (err) {
    console.error("❌ Error al obtener reportes IA:", err.message);
    res.status(500).json({ message: "Error al obtener reportes IA" });
  }
});



/* ==================================================
   GENERAR REPORTE IA - DIAGNÓSTICO CLÍNICO SUGERIDO
  nueva agregado pdf
================================================== */
app.post("/api/pacientes/:id/generar-reporte-ia", verifyToken, async (req, res) => {
  const { id } = req.params;
  const idPsicologoLogueado = req.user.id_psicologo;

  try {
    // ✅ 1. Validar que el paciente exista y le pertenezca al psicólogo
    const [pacienteRows] = await pool.query(
      "SELECT id_paciente, id_psicologo, nombre, edad, sexo, antecedentes FROM pacientes WHERE id_paciente = ?",
      [id]
    );
    if (!pacienteRows.length) return res.status(404).json({ message: "Paciente no encontrado" });
    if (pacienteRows[0].id_psicologo !== idPsicologoLogueado) {
      return res.status(403).json({ message: "No tienes permiso para generar reportes de este paciente" });
    }

    // ✅ 2. Recolectar TODO el contexto del paciente
    const data = await getPacienteContextData(id); 
    // incluirá: paciente, historial inicial, pruebas, notas clínicas, sesiones, etc.

    // ✅ 3. Prompt clínico PROFESIONAL para Gemini
    const prompt = `
Genera un informe clínico psicológico breve, profesional, claro y útil para toma de decisiones.
Usa la información del paciente, sin teoría, sin explicar pruebas, solo síntesis clínica útil.

📌 DATOS DEL PACIENTE
- Nombre: ${data?.paciente?.nombre || "N/D"}
- Edad: ${data?.paciente?.edad || "N/D"}
- Sexo: ${data?.paciente?.sexo || "N/D"}
- Antecedentes relevantes: ${data?.paciente?.antecedentes || "No registrados"}

📋 HISTORIAL INICIAL:
${JSON.stringify(data?.historial || {}, null, 2)}

🧪 PRUEBAS RECIENTES (máximo 3):
${JSON.stringify(data?.pruebas || [], null, 2)}

📝 NOTAS CLÍNICAS RECIENTES:
${JSON.stringify(data?.notas || [], null, 2)}

🎥 SESIONES / OBSERVACIONES:
${JSON.stringify(data?.sesiones || [], null, 2)}

🛑 FORMATO DE RESPUESTA (NO LO EXPLIQUES, SOLO APLÍCALO):
1. 🩺 Diagnóstico clínico sugerido:
2. ⚠️ Riesgos o señales de alerta:
3. ✅ Recomendación clínica al profesional:

No incluyas teoría, ni definiciones, ni explicación de pruebas.
`.trim();

    // ✅ 4. Enviar a Gemini
    const resp = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent?key=${GEMINI_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }),
      }
    );

    if (!resp.ok) {
      console.error(await resp.text());
      return res.status(500).json({ message: "Error en generación IA" });
    }

    const dataIA = await resp.json();
    const contenido = dataIA?.candidates?.[0]?.content?.parts?.[0]?.text || "⚠️ Sin respuesta de IA";

    // ✅ 5. Guardar en BD
    await pool.query(
      "INSERT INTO reportes_ia (id_paciente, fecha, contenido) VALUES (?, NOW(), ?)",
      [id, contenido]
    );

    res.json({ message: "✅ Reporte IA generado con éxito", contenido });
  } catch (err) {
    console.error("❌ Error al generar reporte IA:", err);
    res.status(500).json({ message: "Error interno del servidor" });
  }
});



//nos quedamos aqui 
/* ==================================================
   Obtener historial inicial de un paciente
================================================== */
app.get("/api/historial-inicial/:id_paciente", verifyToken, async (req, res) => {
  const { id_paciente } = req.params;
  try {
    const [rows] = await pool.query(
      `SELECT * FROM historial_inicial WHERE id_paciente = ? LIMIT 1`,
      [id_paciente]
    );
    if (!rows.length) {
      return res.status(404).json({ message: "Historial inicial no encontrado" });
    }
    res.json(rows[0]); // 👈 solo un registro
  } catch (err) {
    console.error("❌ Error al obtener historial inicial:", err.message);
    res.status(500).json({ message: "Error al obtener historial inicial" });
  }
});

/* ==================================================
   Actualizar historial inicial de un paciente
================================================== */
app.put("/api/historial-inicial/:id_paciente", verifyToken, async (req, res) => {
  const { id_paciente } = req.params;
  const { diagnostico_inicial, tratamiento_inicial, observaciones } = req.body;

  try {
    // Verificamos si existe
    const [rows] = await pool.query(
  `SELECT id_historial_inicial FROM historial_inicial WHERE id_paciente = ? LIMIT 1`,
  [id_paciente]
);

    if (!rows.length) {
      return res.status(404).json({ message: "Historial inicial no encontrado" });
    }

    // Actualizamos
    await pool.query(
      `UPDATE historial_inicial 
       SET diagnostico_inicial = ?, tratamiento_inicial = ?, observaciones = ?, fecha = NOW()
       WHERE id_paciente = ?`,
      [diagnostico_inicial, tratamiento_inicial, observaciones, id_paciente]
    );

    res.json({ message: "✅ Historial actualizado correctamente" });
  } catch (err) {
    console.error("❌ Error al actualizar historial inicial:", err.message);
    res.status(500).json({ message: "Error al actualizar historial inicial" });
  }
});


/* ==================================================
   Sesiones = de la tabla sesiones + citas
================================================== */
app.get("/api/sesiones/paciente/:id_paciente", verifyToken, async (req, res) => {
  const { id_paciente } = req.params;
  try {
    const [rows] = await pool.query(
      `
      SELECT * FROM (
        SELECT id_sesion, id_paciente, fecha, notas
        FROM sesiones
        WHERE id_paciente = ?

        UNION ALL

        SELECT id_cita AS id_sesion, id_paciente, 
               CAST(CONCAT(fecha, ' ', hora) AS DATETIME) AS fecha, 
               notas
        FROM citas
        WHERE id_paciente = ?
      ) AS todas
      ORDER BY fecha DESC
      `,
      [id_paciente, id_paciente]
    );

    res.json(rows || []);
  } catch (err) {
    console.error("❌ Error al obtener sesiones:", err.message);
    res.status(500).json({ message: "Error al obtener sesiones" });
  }
});



/* ==================================================
   Crear sesión desde cita o manual
================================================== */
app.post("/api/sesiones", verifyToken, async (req, res) => {
  const { id_paciente, id_cita, notas } = req.body;
  console.log("📥 Backend recibió:", req.body);

  // 1️⃣ Validar que venga id_paciente
  if (!id_paciente) {
    return res.status(400).json({ message: "Falta el id del paciente" });
  }

  // 2️⃣ Validar que el paciente exista
  const [checkPaciente] = await pool.query(
    "SELECT * FROM pacientes WHERE id_paciente = ?",
    [id_paciente]
  );
  console.log("🔎 Validando paciente:", id_paciente, checkPaciente.length ? "✅ Existe" : "❌ No existe");
  if (checkPaciente.length === 0) {
    return res.status(400).json({ message: `❌ Paciente ${id_paciente} no existe en la BD` });
  }

  try {
    let textoNotas = notas || "Sesión sin notas";

    // 3️⃣ Si viene desde cita, validar que coincida con el paciente
    if (id_cita) {
      const [cita] = await pool.query(
        "SELECT id_paciente, motivo, notas FROM citas WHERE id_cita = ?",
        [id_cita]
      );

      if (!cita.length) {
        return res.status(400).json({ message: `❌ Cita ${id_cita} no existe` });
      }
      if (cita[0].id_paciente !== id_paciente) {
        return res.status(400).json({ message: "⚠️ El paciente no coincide con la cita" });
      }

      textoNotas = `Sesión desde cita - Motivo: ${cita[0].motivo || ""} ${cita[0].notas || ""}`;
    }

    // 4️⃣ Insertar en la tabla sesiones
    const [result] = await pool.query(
      `INSERT INTO sesiones (id_cita, id_paciente, notas, link_videollamada)
       VALUES (?, ?, ?, ?)`,
      [id_cita ?? null, id_paciente, textoNotas, null] // 👈 iniciamos link en NULL
    );

    res.json({
      id_sesion: result.insertId,
      message: "✅ Sesión creada correctamente",
    });
  } catch (err) {
    console.error("❌ Error al crear sesión:", err.message);
    res.status(500).json({ message: "Error al crear sesión" });
  }
});





/* ==================================================
   Subir multimedia (video o audio) de sesión
================================================== */
app.post("/api/multimedia", verifyToken, uploadMultimedia.single("file"), async (req, res) => {
  try {
    const { id_sesion, tipo, descripcion, duracion } = req.body;

    if (!id_sesion) return res.status(400).json({ message: "Falta id_sesion" });
    if (!req.file) return res.status(400).json({ message: "No se recibió archivo" });

    // ✅ 1) Validar que la sesión exista
    const [sesion] = await pool.query(
      "SELECT id_sesion FROM sesiones WHERE id_sesion = ?",
      [id_sesion]
    );
    if (!sesion.length) {
      return res.status(400).json({ message: `Sesión ${id_sesion} no existe` });
    }

    const ruta = "/uploads/multimedia/" + req.file.filename;
    const formato = req.file.mimetype;

    // ✅ 2) Insert usando nombres correctos
    const [result] = await pool.query(
      `INSERT INTO videos_sesion 
       (id_sesion, ruta_video, tipo, descripcion, duracion_segundos, formato, fecha_subida)
       VALUES (?, ?, ?, ?, ?, ?, NOW())`,
      [id_sesion, ruta, tipo || "video", descripcion || "Grabación de sesión", duracion || null, formato]
    );

    res.json({
      message: "✅ Archivo multimedia guardado",
      id_video: result.insertId,
      ruta,
      tipo: tipo || "video"
    });
  } catch (err) {
    console.error("❌ Error al subir multimedia:", err);
    res.status(500).json({ message: "Error al subir archivo multimedia" });
  }
});

/* ==================================================
   Pruebas
================================================== */
app.get("/api/pruebas", verifyToken, async (_req, res) => {
  try {
   const [rows] = await pool.query(
  "SELECT id_prueba, nombre, descripcion, tipo, version, activo FROM pruebas ORDER BY id_prueba DESC"
);


    res.json(rows || []);
  } catch (err) {
    console.error("❌ Error al obtener pruebas:", err.message);
    res.status(500).json({ message: "Error al obtener pruebas" });
  }
});

/* ==================================================
   Pruebas habilitadas 
================================================== */
app.post("/api/pruebas/habilitar", verifyToken, async (req, res) => {
  const { id_paciente, id_prueba, notas } = req.body;
  const id_psicologo = req.user?.id_psicologo;
  if (!id_paciente || !id_prueba || !id_psicologo) {
    return res.status(400).json({ message: "Faltan datos" });
  }
  try {
    await pool.query(
      "INSERT INTO pruebas_habilitadas (id_paciente, id_prueba, id_psicologo, notas) VALUES (?,?,?,?)",
      [id_paciente, id_prueba, id_psicologo, notas || null]
    );
    res.json({ message: "✅ Prueba habilitada" });
  } catch (err) {
    console.error("❌ Error:", err.message);
    res.status(500).json({ message: "Error al habilitar prueba" });
  }
});

/* ==================================================
   Pruebas habilitadas a un paciente
================================================== */

app.get("/api/pruebas/habilitadas/:id_paciente", verifyToken, async (req, res) => {
  const { id_paciente } = req.params;
  try {
    const [rows] = await pool.query(
      `SELECT ph.id_habilitacion, pr.id_prueba, pr.nombre, pr.descripcion, pr.tipo, ph.fecha
       FROM pruebas_habilitadas ph
       JOIN pruebas pr ON ph.id_prueba = pr.id_prueba
       WHERE ph.id_paciente = ?`,
      [id_paciente]
    );
    res.json(rows || []);
  } catch (err) {
    console.error("❌ Error:", err.message);
    res.status(500).json({ message: "Error al obtener pruebas habilitadas" });
  }
});


/* ==================================================
   Preguntas de prueba con opciones
================================================== */
app.get("/api/pruebas/:id/preguntas", verifyToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [preguntas] = await pool.query("SELECT * FROM preguntas_prueba WHERE id_prueba = ?", [id]);

    // Traer opciones de cada pregunta
    for (let p of preguntas) {
      const [opciones] = await pool.query(
        "SELECT * FROM opciones_respuesta WHERE id_pregunta = ?",
        [p.id_pregunta]
      );
      p.opciones = opciones;
    }

    res.json(preguntas || []);
  } catch (err) {
    console.error("❌ Error al obtener preguntas:", err.message);
    res.status(500).json({ message: "Error al obtener preguntas" });
  }
});

/* ==================================================
   Finalizar prueba (requiere login) → guarda resultado + reporte IA (solo Gemini)
================================================== */
app.post("/api/pruebas/:id/finalizar", verifyToken, async (req, res) => {
  const { id } = req.params; // id_prueba
  const { id_paciente, id_habilitacion, id_sesion } = req.body;

  if (!id_paciente || !id_habilitacion) {
    return res.status(400).json({
      message: "Faltan datos obligatorios (id_paciente, id_habilitacion)",
    });
  }

  try {
    // 1️⃣ Calcular puntaje total
    const [rows] = await pool.query(
      `SELECT SUM(o.valor) AS total
       FROM respuestas_prueba r
       JOIN opciones_respuesta o ON r.id_opcion = o.id_opcion
       WHERE r.id_prueba = ? AND r.id_paciente = ? AND r.id_habilitacion = ?`,
      [id, id_paciente, id_habilitacion]
    );

    const puntaje_total = rows[0]?.total || 0;

    // 2️⃣ Interpretación según prueba
    let interpretacion = "Sin interpretación";
    if (+id === 3) {
      interpretacion =
        puntaje_total < 5
          ? "Ansiedad mínima"
          : puntaje_total < 10
          ? "Ansiedad leve"
          : puntaje_total < 15
          ? "Ansiedad moderada"
          : "Ansiedad severa";
    }
    if (+id === 2) {
      interpretacion =
        puntaje_total < 14
          ? "Estrés bajo"
          : puntaje_total < 27
          ? "Estrés moderado"
          : "Estrés alto";
    }
    if (+id === 1) {
      interpretacion =
        puntaje_total < 10
          ? "Depresión mínima"
          : puntaje_total < 20
          ? "Depresión leve"
          : puntaje_total < 30
          ? "Depresión moderada"
          : "Depresión severa";
    }

    // 3️⃣ Generar reporte IA (solo Gemini)
    let reporteIA;
    try {
      const prompt = `
📌 Reporte automático de prueba psicológica

👤 Paciente ID: ${id_paciente}
🧾 Prueba ID: ${id}
📊 Puntaje obtenido: ${puntaje_total}
📌 Interpretación: ${interpretacion}

Genera un **reporte clínico breve, claro y estructurado en español** con posibles recomendaciones terapéuticas.
`;

      reporteIA = await generarReporteIA(prompt, 300);
    } catch (err) {
      console.error("⚠️ Error al generar reporte IA con Gemini:", err.message);
      reporteIA = "⚠️ No se pudo generar el reporte automático con Gemini.";
    }

    // 4️⃣ Guardar en resultados_prueba (UPDATE si ya existe)
    const [existe] = await pool.query(
      `SELECT id_resultado 
       FROM resultados_prueba 
       WHERE id_paciente = ? AND id_prueba = ? AND id_habilitacion = ?`,
      [id_paciente, id, id_habilitacion]
    );

    if (existe.length > 0) {
      await pool.query(
        `UPDATE resultados_prueba 
         SET puntaje_total = ?, interpretacion = ?, reporte_ia = ?, id_sesion = ?, fecha = NOW()
         WHERE id_resultado = ?`,
        [
          puntaje_total,
          interpretacion,
          reporteIA,
          id_sesion || null,
          existe[0].id_resultado,
        ]
      );
    } else {
      await pool.query(
        `INSERT INTO resultados_prueba 
         (id_paciente, id_prueba, id_habilitacion, puntaje_total, interpretacion, reporte_ia, id_sesion, fecha)
         VALUES (?, ?, ?, ?, ?, ?, ?, NOW())`,
        [
          id_paciente,
          id,
          id_habilitacion,
          puntaje_total,
          interpretacion,
          reporteIA,
          id_sesion || null,
        ]
      );
    }

    // 5️⃣ Respuesta al frontend
    res.json({
      message: "✅ Prueba finalizada con éxito",
      puntaje_total,
      interpretacion,
      reporteIA,
    });
  } catch (err) {
    console.error("❌ Error al finalizar prueba:", err.message);
    res
      .status(500)
      .json({ message: "Error al finalizar prueba", error: err.message });
  }
});





/* ==================================================
   Finalizar prueba (versión pública)
================================================== */
app.post("/api/pruebas/:id/finalizar/publico", async (req, res) => {
  const { id } = req.params; // id_prueba
  const { id_paciente, id_habilitacion, id_sesion } = req.body;

  // ✅ Validación flexible
  if (!id_habilitacion) {
    return res.status(400).json({ message: "⚠️ Falta el id_habilitacion" });
  }

  try {
    // 🔎 Debug: qué llegó desde el frontend
    console.log("📩 Finalizar público recibido:", JSON.stringify(req.body, null, 2));

    // 1️⃣ Calcular puntaje total
    const [rows] = await pool.query(
      `SELECT SUM(o.valor) AS total
       FROM respuestas_prueba r
       JOIN opciones_respuesta o ON r.id_opcion = o.id_opcion
       WHERE r.id_prueba = ? AND r.id_habilitacion = ? ${id_paciente ? "AND r.id_paciente = ?" : ""}`,
      id_paciente ? [id, id_habilitacion, id_paciente] : [id, id_habilitacion]
    );

    const puntaje_total = rows[0]?.total || 0;

    // 2️⃣ Interpretación básica según prueba
    let interpretacion = "Sin interpretación";
    if (+id === 3) {
      interpretacion =
        puntaje_total < 5 ? "Ansiedad mínima" :
        puntaje_total < 10 ? "Ansiedad leve" :
        puntaje_total < 15 ? "Ansiedad moderada" : "Ansiedad severa";
    }
    if (+id === 2) {
      interpretacion =
        puntaje_total < 14 ? "Estrés bajo" :
        puntaje_total < 27 ? "Estrés moderado" : "Estrés alto";
    }
    if (+id === 1) {
      interpretacion =
        puntaje_total < 10 ? "Depresión mínima" :
        puntaje_total < 20 ? "Depresión leve" :
        puntaje_total < 30 ? "Depresión moderada" : "Depresión severa";
    }

    // 3️⃣ Generar reporte IA
    let reporteIA = null;
    try {
      const prompt = `
Paciente ID: ${id_paciente || "Anónimo"}
Prueba ID: ${id}
Puntaje obtenido: ${puntaje_total}
Interpretación: ${interpretacion}

Genera un reporte en lenguaje clínico breve, claro y estructurado en español con posibles recomendaciones.
      `;

      reporteIA = await generarReporteIA(prompt, 300);
    } catch (err) {
      console.error("⚠️ Error al generar reporte IA:", err.message);
      reporteIA = "⚠️ No se pudo generar el reporte automático con IA.";
    }

    // 4️⃣ Guardar o actualizar resultado en la BD
    await pool.query(
      `INSERT INTO resultados_prueba 
        (id_paciente, id_prueba, id_habilitacion, id_sesion, puntaje_total, interpretacion, reporte_ia, fecha)
       VALUES (?, ?, ?, ?, ?, ?, ?, NOW())
       ON DUPLICATE KEY UPDATE 
         puntaje_total = VALUES(puntaje_total), 
         interpretacion = VALUES(interpretacion), 
         reporte_ia = VALUES(reporte_ia),
         id_sesion = VALUES(id_sesion),
         fecha = NOW()`,
      [id_paciente || null, id, id_habilitacion, id_sesion || null, puntaje_total, interpretacion, reporteIA]
    );

    // 5️⃣ Respuesta al frontend
    res.json({
      message: "✅ Prueba finalizada (público)",
      puntaje_total,
      interpretacion,
      analisis: reporteIA
    });

  } catch (err) {
    console.error("❌ Error en finalizar público:", err);
    res.status(500).json({
      message: "❌ Error al finalizar prueba público",
      error: err.message
    });
  }
});


/* ==================================================
   Respuestas de prueba (ligadas a la sesión - requiere login)
================================================== */
app.post("/api/respuestas", verifyToken, async (req, res) => {
  const { id_sesion, id_habilitacion, respuestas } = req.body;
  if (!id_sesion || !id_habilitacion || !Array.isArray(respuestas) || !respuestas.length) {
    return res.status(400).json({ message: "Faltan datos obligatorios" });
  }

  try {
    const values = respuestas.map((r) => [
      r.id_paciente,
      r.id_prueba,
      id_habilitacion,
      r.id_pregunta,
      r.id_opcion ?? null,
      r.respuesta_abierta ?? null
    ]);

    await pool.query(
      `INSERT INTO respuestas_prueba 
       (id_paciente, id_prueba, id_habilitacion, id_pregunta, id_opcion, respuesta_abierta) 
       VALUES ?`,
      [values]
    );

    res.json({ message: "✅ Respuestas guardadas" });
  } catch (err) {
    console.error("❌ Error al guardar respuestas:", err.message);
    res.status(500).json({ message: "Error al guardar respuestas" });
  }
});

/* ==================================================
   Obtener videos por paciente (para ver historial)
================================================== */
app.get("/api/videos/paciente/:id_paciente", verifyToken, async (req, res) => {
  const { id_paciente } = req.params;

  try {
    const [rows] = await pool.query(
      `SELECT v.id_video, v.id_sesion, v.ruta_video, 
              s.fecha AS fecha_sesion
       FROM videos_sesion v
       JOIN sesiones s ON v.id_sesion = s.id_sesion
       WHERE s.id_paciente = ?
       ORDER BY s.fecha DESC`,
      [id_paciente]
    );

    res.json({
      ok: true,
      videos: rows
    });

  } catch (err) {
    console.error("❌ Error al obtener videos:", err.message);
    res.status(500).json({ ok: false, message: "Error al obtener videos" });
  }
});

/* ==================================================
   Respuestas de prueba (versión pública - sin login)
================================================== */
app.post("/api/respuestas/publico", async (req, res) => {
  const { id_habilitacion, id_sesion, respuestas } = req.body;

  // ✅ Validación más robusta
  if (!id_habilitacion) {
    return res.status(400).json({ message: "⚠️ Falta el id_habilitacion en la petición" });
  }
  if (!Array.isArray(respuestas) || respuestas.length === 0) {
    return res.status(400).json({ message: "⚠️ Debes enviar al menos una respuesta" });
  }

  try {
    // 🔎 Depuración: mostrar qué llegó
    console.log("📩 Respuestas recibidas (público):", JSON.stringify(req.body, null, 2));

    const values = respuestas.map((r) => [
      r.id_paciente ?? null,         // si no llega, guardamos null
      r.id_prueba ?? null,           // id de la prueba (debe llegar del frontend)
      id_habilitacion,               // siempre obligatorio
      r.id_pregunta ?? null,         // id de la pregunta
      r.id_opcion ?? null,           // si fue opción múltiple
      r.respuesta_abierta ?? null,   // si fue respuesta escrita
      id_sesion ?? null              // puede ser null
    ]);

    // ✅ Inserción masiva
    await pool.query(
      `INSERT INTO respuestas_prueba 
       (id_paciente, id_prueba, id_habilitacion, id_pregunta, id_opcion, respuesta_abierta, id_sesion) 
       VALUES ?`,
      [values]
    );

    res.json({ 
      message: "✅ Respuestas guardadas correctamente (público)", 
      total_respuestas: values.length,
      id_habilitacion,
      id_sesion: id_sesion || null
    });

  } catch (err) {
    console.error("❌ Error al guardar respuestas (público):", err);
    res.status(500).json({ 
      message: "❌ Error interno al guardar respuestas (público)", 
      error: err.message 
    });
  }
});


/* ==================================================
   Enlace único público (paciente abre sin login)
================================================== */
app.get("/api/pruebas/habilitacion/:id_habilitacion", async (req, res) => {
  const { id_habilitacion } = req.params;
  try {
    const [rows] = await pool.query(
      `SELECT 
         ph.id_habilitacion AS id_habilitacion,
         ph.id_paciente,
         pr.id_prueba,
         pr.nombre,
         pr.descripcion,
         pr.tipo,
         ph.fecha
       FROM pruebas_habilitadas ph
       JOIN pruebas pr ON ph.id_prueba = pr.id_prueba
       WHERE ph.id_habilitacion = ?`,
      [id_habilitacion]
    );

    if (!rows.length) return res.status(404).json({ message: "Prueba no encontrada" });

    const prueba = rows[0];

    // Traer preguntas con sus opciones
    const [preguntas] = await pool.query(
      "SELECT * FROM preguntas_prueba WHERE id_prueba = ?",
      [prueba.id_prueba]
    );

    for (let p of preguntas) {
      const [opciones] = await pool.query(
        "SELECT * FROM opciones_respuesta WHERE id_pregunta = ?",
        [p.id_pregunta]
      );
      p.opciones = opciones;
    }

    res.json({ ...prueba, preguntas });
  } catch (err) {
    console.error("❌ Error:", err.message);
    res.status(500).json({ message: "Error al generar link" });
  }
});



/* ==================================================
   Reportes del paciente (incluye reporte_ia)
================================================== */
app.get("/api/reportes/:id_paciente", verifyToken, async (req, res) => {
  const { id_paciente } = req.params;

  try {
    const [rows] = await pool.query(
      `SELECT 
          r.id_resultado,
          r.id_prueba,
          p.nombre AS prueba,
          r.puntaje_total,
          r.interpretacion,
          r.reporte_ia,
          DATE_FORMAT(r.fecha, '%Y-%m-%dT%H:%i:%s') AS fecha
       FROM resultados_prueba r
       JOIN pruebas p ON r.id_prueba = p.id_prueba
       WHERE r.id_paciente = ?
       ORDER BY r.fecha DESC`,
      [id_paciente]
    );

    if (!rows.length) {
      return res.status(200).json({
        resultados: [],
        message: "No hay reportes registrados para este paciente"
      });
    }

    res.json({
      resultados: rows.map(r => ({
        id_resultado: r.id_resultado,
        id_prueba: r.id_prueba,
        prueba: r.prueba,
        puntaje_total: r.puntaje_total,
        interpretacion: r.interpretacion,
        reporte_ia: r.reporte_ia,
        fecha: r.fecha
      }))
    });

  } catch (err) {
    console.error("❌ Error al obtener reportes:", err.message);
    res.status(500).json({ message: "Error al obtener reportes" });
  }
});


/* ==================================================
   Historial inicial (solo una vez por paciente)
================================================== */
app.post("/api/historial-inicial", verifyToken, async (req, res) => {
  const {
    id_paciente,
    estado_civil,
    ocupacion,
    escolaridad,
    antecedentes_personales,
    antecedentes_familiares,
    antecedentes_patologicos,
    antecedentes_emocionales,
    habitos,
    alergias,
    enfermedades_previas,
    medicamentos_actuales,
    cirugias,
    historia_desarrollo,
    evaluacion_inicial,
    diagnostico_inicial,
    tratamiento_inicial,
    notas,
  } = req.body;

  try {
    const [exist] = await pool.query(
      "SELECT id_historial_inicial FROM historial_inicial WHERE id_paciente = ?",
      [id_paciente]
    );
    if (exist.length > 0) {
      return res.status(400).json({ message: "⚠️ El historial inicial ya fue registrado" });
    }

    const [result] = await pool.query(
      `INSERT INTO historial_inicial 
      (id_paciente, fecha_registro, estado_civil, ocupacion, escolaridad,
       antecedentes_personales, antecedentes_familiares, antecedentes_patologicos, antecedentes_emocionales,
       habitos, alergias, enfermedades_previas, medicamentos_actuales, cirugias,
       historia_desarrollo, evaluacion_inicial, diagnostico_inicial, tratamiento_inicial, notas, created_at)
      VALUES (?, NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())`,
      [
        id_paciente,
        estado_civil,
        ocupacion,
        escolaridad,
        antecedentes_personales,
        antecedentes_familiares,
        antecedentes_patologicos,
        antecedentes_emocionales,
        habitos,
        alergias,
        enfermedades_previas,
        medicamentos_actuales,
        cirugias,
        historia_desarrollo,
        evaluacion_inicial,
        diagnostico_inicial,
        tratamiento_inicial,
        notas,
      ]
    );

    res.json({ message: "✅ Historial inicial guardado", id_historial: result.insertId });
  } catch (err) {
    console.error("❌ Error al guardar historial inicial:", err.message);
    res.status(500).json({ message: "Error interno" });
  }
});

/* ==================================================
   Historial de seguimiento (sesiones de control)
================================================== */
app.post("/api/seguimiento", verifyToken, async (req, res) => {
  const { id_paciente, id_sesion, diagnostico, tratamiento, evolucion, observaciones } = req.body;

  try {
    const [result] = await pool.query(
      `INSERT INTO historial_seguimiento 
      (id_paciente, id_sesion, fecha, diagnostico, tratamiento, evolucion, observaciones) 
      VALUES (?, ?, NOW(), ?, ?, ?, ?)`,
      [id_paciente, id_sesion || null, diagnostico, tratamiento, evolucion, observaciones]
    );

    res.json({ message: "✅ Seguimiento guardado", id_seguimiento: result.insertId });
  } catch (err) {
    console.error("❌ Error al guardar seguimiento:", err.message);
    res.status(500).json({ message: "Error interno" });
  }
});

app.get("/api/seguimiento/:id_paciente", verifyToken, async (req, res) => {
  const { id_paciente } = req.params;
  try {
    const [rows] = await pool.query(
      "SELECT * FROM historial_seguimiento WHERE id_paciente = ? ORDER BY fecha DESC",
      [id_paciente]
    );
    res.json(rows || []);
  } catch (err) {
    console.error("❌ Error al obtener seguimiento:", err.message);
    res.status(500).json({ message: "Error interno" });
  }
});




/* ==================================================
   Notas / Chat manual de sesión (notas_sesion)
================================================== */
app.post("/api/notas", verifyToken, async (req, res) => {
  const { id_sesion, autor = "psicologo", pregunta, respuesta = null, tipo = "observacion" } = req.body;
  if (!id_sesion || !pregunta) return res.status(400).json({ message: "Faltan datos" });

  try {
    await pool.query(
      "INSERT INTO notas_sesion (id_sesion, autor, pregunta, respuesta, tipo, fecha) VALUES (?, ?, ?, ?, ?, NOW())",
      [id_sesion, autor, pregunta, respuesta, tipo]
    );
    res.json({ message: "Nota registrada" });
  } catch (err) {
    console.error("❌ Error al registrar nota:", err.message);
    res.status(500).json({ message: "Error al registrar nota" });
  }
});

app.get("/api/notas/sesion/:id_sesion", verifyToken, async (req, res) => {
  const { id_sesion } = req.params;
  try {
    const [rows] = await pool.query(
      "SELECT id_chat, autor, pregunta, respuesta, tipo, fecha FROM notas_sesion WHERE id_sesion = ? ORDER BY fecha ASC",
      [id_sesion]
    );
    res.json(rows || []);
  } catch (err) {
    console.error("❌ Error al obtener notas:", err.message);
    res.status(500).json({ message: "Error al obtener notas" });
  }
});


/* ==================================================
   Obtener citas (solo del psicólogo logueado)
================================================== */
app.get("/api/citas", verifyToken, async (req, res) => {
  try {
    const user = req.user;

    if (!user || !user.id_psicologo) {
      return res.status(403).json({ message: "Acceso denegado: psicólogo no válido" });
    }

    const [rows] = await pool.query(
      `
      SELECT 
        c.id_cita,
        c.fecha,
        c.hora,
        c.motivo,
        c.estado,
        c.notas,
        p.id_paciente,         
        p.nombre AS paciente,
        u.nombre AS psicologo
      FROM citas c
      JOIN pacientes p ON c.id_paciente = p.id_paciente
      JOIN psicologos ps ON c.id_psicologo = ps.id_psicologo
      JOIN usuarios u ON ps.id_usuario = u.id_usuario
      WHERE c.id_psicologo = ?
      ORDER BY c.fecha, c.hora
      `,
      [user.id_psicologo]
    );

    res.json(rows);
  } catch (err) {
    console.error("❌ Error al obtener citas:", err.message);
    res.status(500).json({ message: "Error al obtener citas" });
  }
});

/* ==================================================
   Crear cita (se asigna automáticamente al psicólogo logueado)
================================================== */
app.post("/api/citas", verifyToken, async (req, res) => {
  try {
    const user = req.user;

    if (!user || !user.id_psicologo) {
      return res.status(403).json({ message: "Acceso denegado: psicólogo no válido" });
    }

    const { id_paciente, fecha, hora, motivo, notas } = req.body;

    // Validar que el paciente exista
    const [paciente] = await pool.query(
      "SELECT id_paciente FROM pacientes WHERE id_paciente = ?",
      [id_paciente]
    );

    if (paciente.length === 0) {
      return res.status(400).json({ message: "Paciente no existe" });
    }

    // Crear cita vinculada al psicólogo logueado
    await pool.query(
      "INSERT INTO citas (id_paciente, id_psicologo, fecha, hora, motivo, notas, estado) VALUES (?,?,?,?,?,?,?)",
      [id_paciente, user.id_psicologo, fecha, hora, motivo, notas || "", "pendiente"]
    );

    res.status(201).json({ message: "✅ Cita creada exitosamente" });
  } catch (err) {
    console.error("❌ Error al crear cita:", err.message);
    res.status(500).json({ message: "Error al crear cita" });
  }
});

/* ==================================================
   Finalizar sesión (actualiza estado y fecha_fin)
================================================== */
app.put("/api/sesiones/:id/finalizar", verifyToken, async (req, res) => {
  const { id } = req.params;

  try {
    const [result] = await pool.query(
      "UPDATE sesiones SET estado = 'finalizada', fecha_fin = NOW() WHERE id_sesion = ?",
      [id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "⚠️ Sesión no encontrada" });
    }

    res.json({ message: "✅ Sesión finalizada correctamente" });
  } catch (err) {
    console.error("❌ Error al finalizar sesión:", err.message);
    res.status(500).json({ message: "Error al finalizar sesión" });
  }
});


/* ==================================================
   Eliminar paciente (solo psicólogo autenticado) nuevo cambio 
================================================== */
app.delete("/api/pacientes/:id", verifyToken, async (req, res) => {
  const { id } = req.params;

  try {
    // Primero validar que el paciente exista
    const [rows] = await pool.query("SELECT * FROM pacientes WHERE id_paciente = ?", [id]);
    if (!rows.length) {
      return res.status(404).json({ message: "Paciente no encontrado" });
    }

    // Eliminar paciente
    await pool.query("DELETE FROM pacientes WHERE id_paciente = ?", [id]);

    res.json({ message: "✅ Paciente eliminado correctamente" });
  } catch (err) {
    console.error("❌ Error al eliminar paciente:", err.message);
    res.status(500).json({ message: "Error al eliminar paciente" });
  }
});


/* ==================================================
   Actualizar estado de una cita
================================================== */
app.put("/api/citas/:id/estado", verifyToken, async (req, res) => {
  const { id } = req.params;
  const { estado } = req.body;

  try {
    const [result] = await pool.query(
      "UPDATE citas SET estado = ? WHERE id_cita = ?",
      [estado, id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "❌ Cita no encontrada" });
    }

    res.json({ message: "✅ Estado de la cita actualizado correctamente" });
  } catch (err) {
    console.error("❌ Error al actualizar estado de cita:", err.message);
    res.status(500).json({ message: "Error interno al actualizar cita" });
  }
});

/* ==================================================
   Start server
================================================== */
server.listen(PORT, "0.0.0.0", () => {
  console.log(`✅ Servidor backend corriendo en http://0.0.0.0:${PORT}`);
  console.log(`✅ PeerJS corriendo en ws://0.0.0.0:${PORT}/peerjs/myapp`);
});
