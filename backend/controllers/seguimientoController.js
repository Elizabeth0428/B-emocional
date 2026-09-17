// backend/controllers/seguimientoController.js

import pool from "../config/database.js";

/* ==================================================
   CREAR SEGUIMIENTO
================================================== */
export async function crearSeguimiento(req, res) {

  const {
    id_paciente,
    id_sesion,
    diagnostico,
    tratamiento,
    evolucion,
    observaciones,
    tareas_acuerdos
  } = req.body;

  try {

    const [result] = await pool.query(
      `INSERT INTO historial_seguimiento
       (
         id_paciente,
         id_sesion,
         fecha,
         diagnostico,
         tratamiento,
         evolucion,
         observaciones,
         tareas_acuerdos
       )
       VALUES (?, ?, NOW(), ?, ?, ?, ?, ?)`,
      [
        id_paciente,
        id_sesion || null,
        diagnostico,
        tratamiento,
        evolucion,
        observaciones,
        tareas_acuerdos || null
      ]
    );

    res.json({
      message: "✅ Seguimiento guardado",
      id_seguimiento: result.insertId
    });

  } catch (err) {

    console.error(
      "❌ Error al guardar seguimiento:",
      err.message
    );

    res.status(500).json({
      message: "Error interno"
    });
  }
}

/* ==================================================
   OBTENER SEGUIMIENTO DE UN PACIENTE
================================================== */
export async function obtenerSeguimiento(req, res) {

  const { id_paciente } = req.params;

  try {

    const [rows] = await pool.query(
      `SELECT *
       FROM historial_seguimiento
       WHERE id_paciente = ?
       ORDER BY fecha DESC`,
      [id_paciente]
    );

    res.json(rows || []);

  } catch (err) {

    console.error(
      "❌ Error al obtener seguimiento:",
      err.message
    );

    res.status(500).json({
      message: "Error interno"
    });
  }
}