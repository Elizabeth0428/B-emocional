// backend/controllers/notasController.js

import pool from "../config/database.js";


/* ==================================================
   CREAR NOTA / CHAT MANUAL DE SESIÓN
================================================== */

export async function crearNota(req, res) {

  const {
    id_sesion,
    autor = "psicologo",
    pregunta,
    respuesta = null,
    tipo = "observacion"
  } = req.body;

  if (!id_sesion || !pregunta) {
    return res.status(400).json({
      message: "Faltan datos"
    });
  }

  try {

    await pool.query(
      `INSERT INTO notas_sesion
       (
         id_sesion,
         autor,
         pregunta,
         respuesta,
         tipo,
         fecha
       )
       VALUES (?, ?, ?, ?, ?, NOW())`,
      [
        id_sesion,
        autor,
        pregunta,
        respuesta,
        tipo
      ]
    );

    res.json({
      message: "Nota registrada"
    });

  } catch (err) {

    console.error(
      "❌ Error al registrar nota:",
      err.message
    );

    res.status(500).json({
      message: "Error al registrar nota"
    });
  }
}


/* ==================================================
   OBTENER NOTAS DE UNA SESIÓN
================================================== */

export async function obtenerNotasSesion(req, res) {

  const { id_sesion } = req.params;

  try {

    const [rows] = await pool.query(
      `SELECT
        id_chat,
        autor,
        pregunta,
        respuesta,
        tipo,
        fecha
       FROM notas_sesion
       WHERE id_sesion = ?
       ORDER BY fecha ASC`,
      [id_sesion]
    );

    res.json(rows || []);

  } catch (err) {

    console.error(
      "❌ Error al obtener notas:",
      err.message
    );

    res.status(500).json({
      message: "Error al obtener notas"
    });
  }
}