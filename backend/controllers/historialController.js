// backend/controllers/historialController.js

import pool from "../config/database.js";


/* ==================================================
   OBTENER HISTORIAL INICIAL DE UN PACIENTE
================================================== */

export async function obtenerHistorialInicial(req, res) {

  const { id_paciente } = req.params;

  try {

    const [rows] = await pool.query(
      `SELECT *
       FROM historial_inicial
       WHERE id_paciente = ?
       LIMIT 1`,
      [id_paciente]
    );

    if (!rows.length) {
      return res.status(404).json({
        message: "Historial inicial no encontrado"
      });
    }

    res.json(rows[0]);

  } catch (err) {

    console.error(
      "❌ Error al obtener historial inicial:",
      err.message
    );

    res.status(500).json({
      message: "Error al obtener historial inicial"
    });

  }
}


/* ==================================================
   CREAR HISTORIAL INICIAL
   Solo si no existe
================================================== */

export async function crearHistorialInicial(req, res) {

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
    notas
  } = req.body;

  try {

    /* ================================================
       Verificar si ya existe
    ================================================= */

    const [exist] = await pool.query(
      `SELECT id_historial_inicial
       FROM historial_inicial
       WHERE id_paciente = ?`,
      [id_paciente]
    );

    if (exist.length > 0) {
      return res.status(400).json({
        message: "⚠️ El historial inicial ya fue registrado"
      });
    }


    /* ================================================
       Crear historial
    ================================================= */

    const [result] = await pool.query(
      `INSERT INTO historial_inicial
      (
        id_paciente,
        fecha_registro,
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
        created_at
      )
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
        notas
      ]
    );


    res.json({
      message: "✅ Historial inicial guardado",
      id_historial: result.insertId
    });

  } catch (err) {

    console.error(
      "❌ Error al guardar historial inicial:",
      err.message
    );

    res.status(500).json({
      message: "Error interno"
    });

  }
}


/* ==================================================
   ACTUALIZAR HISTORIAL INICIAL
================================================== */

export async function actualizarHistorialInicial(req, res) {

  const { id_paciente } = req.params;

  const {
    diagnostico_inicial,
    tratamiento_inicial,
    observaciones
  } = req.body;

  try {

    /* ================================================
       Verificar que exista
    ================================================= */

    const [rows] = await pool.query(
      `SELECT id_historial_inicial
       FROM historial_inicial
       WHERE id_paciente = ?
       LIMIT 1`,
      [id_paciente]
    );

    if (!rows.length) {
      return res.status(404).json({
        message: "Historial inicial no encontrado"
      });
    }


    /* ================================================
       Actualizar
    ================================================= */

    await pool.query(
      `UPDATE historial_inicial
       SET
         diagnostico_inicial = ?,
         tratamiento_inicial = ?,
         observaciones = ?,
         fecha_registro = NOW()
       WHERE id_paciente = ?`,
      [
        diagnostico_inicial,
        tratamiento_inicial,
        observaciones,
        id_paciente
      ]
    );


    res.json({
      message: "✅ Historial actualizado correctamente"
    });

  } catch (err) {

    console.error(
      "❌ Error al actualizar historial inicial:",
      err.message
    );

    res.status(500).json({
      message: "Error al actualizar historial inicial"
    });

  }
}