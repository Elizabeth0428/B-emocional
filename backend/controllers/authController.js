import pool from "../config/database.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

/* ==================================================
   Registro de psicólogo por Admin
================================================== */
export async function registerPsicologo(req, res) {
  try {
    // Solo admin
    if (req.user.role !== 1) {
      return res.status(403).json({
        message: "Acceso denegado: solo administradores",
      });
    }

    const {
      cedula_profesional,
      nombre,
      correo,
      password,
      especialidad,
    } = req.body;

    // Validaciones
    if (
      !cedula_profesional ||
      !nombre ||
      !correo ||
      !password
    ) {
      return res.status(400).json({
        message: "Faltan datos obligatorios",
      });
    }

    if (cedula_profesional.length < 5) {
      return res.status(400).json({
        message: "La cédula profesional no es válida",
      });
    }

    if (nombre.trim().length < 2) {
      return res.status(400).json({
        message: "El nombre no es válido",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        message: "La contraseña debe tener al menos 6 caracteres",
      });
    }

    // ¿Correo ya existe?
    const [uExist] = await pool.query(
      "SELECT id_usuario FROM usuarios WHERE correo = ?",
      [correo]
    );

    if (uExist.length) {
      return res.status(400).json({
        message: "El correo ya está registrado",
      });
    }

    // ¿Cédula ya existe?
    const [cExist] = await pool.query(
      "SELECT id_psicologo FROM psicologos WHERE cedula_profesional = ?",
      [cedula_profesional]
    );

    if (cExist.length) {
      return res.status(400).json({
        message: "La cédula ya está registrada",
      });
    }

    // Encriptar contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear usuario
    const [uIns] = await pool.query(
      `INSERT INTO usuarios
       (nombre, correo, password, rol)
       VALUES (?, ?, ?, ?)`,
      [
        nombre,
        correo,
        hashedPassword,
        "psicologo",
      ]
    );

    // Crear psicólogo
    const [pIns] = await pool.query(
      `INSERT INTO psicologos
       (id_usuario, cedula_profesional, especialidad)
       VALUES (?, ?, ?)`,
      [
        uIns.insertId,
        cedula_profesional,
        especialidad || null,
      ]
    );

    res.json({
      message: "Registro de psicólogo exitoso",
      psicologo: {
        id_psicologo: pIns.insertId,
        id_usuario: uIns.insertId,
        nombre,
        correo,
        cedula_profesional,
      },
    });
  } catch (err) {
    console.error(
      "❌ Error en registro:",
      err.message
    );

    res.status(500).json({
      message: "Error interno en registro",
    });
  }
}


/* ==================================================
   Login
================================================== */
export async function login(req, res) {
  try {
    const { correo, password } = req.body;

    if (!correo || !password) {
      return res.status(400).json({
        message: "Faltan correo y contraseña",
      });
    }

    // Buscar usuario
    const [rows] = await pool.query(
      `SELECT
        id_usuario,
        nombre,
        correo,
        password,
        rol
       FROM usuarios
       WHERE correo = ?
       LIMIT 1`,
      [correo]
    );

    if (!rows.length) {
      return res.status(401).json({
        message: "Credenciales inválidas",
      });
    }

    const user = rows[0];

    // Comparar contraseña
    const ok = await bcrypt.compare(
      password,
      user.password
    );

    if (!ok) {
      return res.status(401).json({
        message: "Credenciales inválidas",
      });
    }

    // Buscar psicólogo
    let id_psicologo = null;

    if (user.rol === "psicologo") {
      const [p] = await pool.query(
        `SELECT id_psicologo
         FROM psicologos
         WHERE id_usuario = ?`,
        [user.id_usuario]
      );

      id_psicologo =
        p[0]?.id_psicologo || null;
    }

    // Mantener compatibilidad con frontend
    // admin = 1
    // psicologo = 2
    const roleNumber =
      user.rol === "admin" ? 1 : 2;

    // Crear token
    const token = jwt.sign(
      {
        id_usuario: user.id_usuario,
        role: roleNumber,
        id_psicologo,
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "2h",
      }
    );

    res.json({
      message: "Login exitoso",

      user: {
        id_usuario: user.id_usuario,
        nombre: user.nombre,
        role: roleNumber,
        id_psicologo,
      },

      token,
    });
  } catch (err) {
    console.error(
      "❌ Error en login:",
      err
    );

    res.status(500).json({
      message: "Error en login",
    });
  }
}


/* ==================================================
   Cambiar contraseña
================================================== */
export async function changePassword(req, res) {
  try {
    const {
      oldPassword,
      newPassword,
    } = req.body;

    const { id_usuario } = req.user;

    if (!oldPassword || !newPassword) {
      return res.status(400).json({
        message: "Faltan datos",
      });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({
        message:
          "La nueva contraseña debe tener al menos 6 caracteres",
      });
    }

    // Buscar usuario
    const [rows] = await pool.query(
      `SELECT password
       FROM usuarios
       WHERE id_usuario = ?`,
      [id_usuario]
    );

    if (!rows.length) {
      return res.status(404).json({
        message: "Usuario no encontrado",
      });
    }

    // Verificar contraseña actual
    const ok = await bcrypt.compare(
      oldPassword,
      rows[0].password
    );

    if (!ok) {
      return res.status(401).json({
        message:
          "La contraseña actual es incorrecta",
      });
    }

    // Encriptar nueva contraseña
    const hashed = await bcrypt.hash(
      newPassword,
      10
    );

    await pool.query(
      `UPDATE usuarios
       SET password = ?
       WHERE id_usuario = ?`,
      [hashed, id_usuario]
    );

    res.json({
      message: "Contraseña actualizada",
    });
  } catch (err) {
    console.error(
      "❌ Error al cambiar contraseña:",
      err
    );

    res.status(500).json({
      message:
        "Error interno al cambiar contraseña",
    });
  }
}