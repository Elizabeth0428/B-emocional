// backend/controllers/notasController.js
import pool from "../config/database.js";

/* ==================================================
   CREAR NOTA / CHAT MANUAL
================================================== */
export async function crearNota(req, res) {
  const {
    id_sesion,
    autor = "psicologo",
    pregunta,
    respuesta = null,
    tipo = "observacion"
  } = req.body;

  if (!id_sesion || !pregunta?.trim())
    return res.status(400).json({ message: "Faltan datos" });

  try {
    const [result] = await pool.query(
      `INSERT INTO notas_sesion
       (id_sesion, autor, pregunta, respuesta, tipo, fecha)
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [id_sesion, autor, pregunta.trim(), respuesta, tipo]
    );

    res.json({
      message: "Nota registrada",
      id_chat: result.insertId
    });
  } catch (err) {
    console.error("❌ Error al registrar nota:", err.message);
    res.status(500).json({ message: "Error al registrar nota" });
  }
}

/* ==================================================
   GUARDAR / ACTUALIZAR NOTA PARA IA
   UNA NOTA IA POR SESIÓN
================================================== */
export async function guardarNotaIA(req, res) {
  const { id_sesion, nota } = req.body;

  if (!id_sesion)
    return res.status(400).json({ message: "Falta id_sesion" });

  if (!nota?.trim())
    return res.status(400).json({ message: "La nota está vacía" });

  try {
    const [existente] = await pool.query(
      `SELECT id_chat
       FROM notas_sesion
       WHERE id_sesion = ? AND tipo = 'nota_ia'
       ORDER BY fecha DESC
       LIMIT 1`,
      [id_sesion]
    );

    if (existente.length) {
      await pool.query(
        `UPDATE notas_sesion
         SET pregunta = ?, autor = 'psicologo', fecha = NOW()
         WHERE id_chat = ?`,
        [nota.trim(), existente[0].id_chat]
      );

      return res.json({
        message: "✅ Nota para IA actualizada",
        id_chat: existente[0].id_chat
      });
    }

    const [result] = await pool.query(
      `INSERT INTO notas_sesion
       (id_sesion, autor, pregunta, respuesta, tipo, fecha)
       VALUES (?, 'psicologo', ?, NULL, 'nota_ia', NOW())`,
      [id_sesion, nota.trim()]
    );

    res.json({
      message: "✅ Nota para IA guardada",
      id_chat: result.insertId
    });
  } catch (err) {
    console.error("❌ Error guardando nota IA:", err.message);
    res.status(500).json({ message: "Error al guardar nota para IA" });
  }
}

/* ==================================================
   OBTENER NOTA PARA IA
================================================== */
export async function obtenerNotaIA(req, res) {
  const { id_sesion } = req.params;

  try {
    const [rows] = await pool.query(
      `SELECT id_chat, id_sesion, autor, pregunta AS nota, fecha
       FROM notas_sesion
       WHERE id_sesion = ? AND tipo = 'nota_ia'
       ORDER BY fecha DESC
       LIMIT 1`,
      [id_sesion]
    );

    res.json(rows[0] || null);
  } catch (err) {
    console.error("❌ Error obteniendo nota IA:", err.message);
    res.status(500).json({ message: "Error al obtener nota para IA" });
  }
}

/* ==================================================
   OBTENER TODAS LAS NOTAS DE UNA SESIÓN
================================================== */
export async function obtenerNotasSesion(req, res) {
  const { id_sesion } = req.params;

  try {
    const [rows] = await pool.query(
      `SELECT id_chat, autor, pregunta, respuesta, tipo, fecha
       FROM notas_sesion
       WHERE id_sesion = ?
       ORDER BY fecha ASC`,
      [id_sesion]
    );

    res.json(rows || []);
  } catch (err) {
    console.error("❌ Error al obtener notas:", err.message);
    res.status(500).json({ message: "Error al obtener notas" });
  }
}