// backend/controllers/historialController.js

import pool from "../config/database.js";


// ============================================================
// OBTENER HISTORIAL INICIAL DE UN PACIENTE
// ============================================================

export async function obtenerHistorialInicial(
  req,
  res
) {

  const {
    id_paciente
  } = req.params;


  try {

    const idPaciente =
      Number(id_paciente);


    if (
      !Number.isInteger(idPaciente) ||
      idPaciente <= 0
    ) {

      return res.status(400).json({
        success: false,
        message:
          "ID de paciente inválido"
      });

    }


    const [
      rows
    ] =
      await pool.query(
        `
          SELECT *

          FROM historial_inicial

          WHERE id_paciente = ?

          LIMIT 1
        `,
        [
          idPaciente
        ]
      );


    if (
      !rows.length
    ) {

      return res.status(404).json({
        success: false,
        message:
          "Historial inicial no encontrado"
      });

    }


    return res.json(
      rows[0]
    );


  } catch (
    err
  ) {

    console.error(
      "❌ Error al obtener historial inicial:",
      err
    );


    return res.status(500).json({
      success: false,
      message:
        "Error al obtener historial inicial",

      error:
        process.env.NODE_ENV ===
        "development"
          ? err.message
          : undefined
    });

  }

}


// ============================================================
// CREAR HISTORIAL INICIAL
// Solo si no existe
// ============================================================

export async function crearHistorialInicial(
  req,
  res
) {

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

    const idPaciente =
      Number(
        id_paciente
      );


    if (
      !Number.isInteger(
        idPaciente
      ) ||
      idPaciente <= 0
    ) {

      return res.status(400).json({
        success: false,
        message:
          "ID de paciente inválido"
      });

    }


    // ========================================================
    // VERIFICAR PACIENTE
    // ========================================================

    const [
      pacientes
    ] =
      await pool.query(
        `
          SELECT
            id_paciente

          FROM pacientes

          WHERE id_paciente = ?

          LIMIT 1
        `,
        [
          idPaciente
        ]
      );


    if (
      !pacientes.length
    ) {

      return res.status(404).json({
        success: false,
        message:
          "Paciente no encontrado"
      });

    }


    // ========================================================
    // VERIFICAR SI YA EXISTE
    // ========================================================

    const [
      exist
    ] =
      await pool.query(
        `
          SELECT
            id_historial_inicial

          FROM historial_inicial

          WHERE id_paciente = ?

          LIMIT 1
        `,
        [
          idPaciente
        ]
      );


    if (
      exist.length > 0
    ) {

      return res.status(409).json({
        success: false,
        message:
          "⚠️ El historial inicial ya fue registrado"
      });

    }


    // ========================================================
    // CREAR HISTORIAL
    // ========================================================

    const [
      result
    ] =
      await pool.query(
        `
          INSERT INTO historial_inicial
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

          VALUES
          (
            ?,
            NOW(),
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            ?,
            NOW()
          )
        `,
        [
          idPaciente,

          estado_civil ||
            null,

          ocupacion ||
            null,

          escolaridad ||
            null,

          antecedentes_personales ||
            null,

          antecedentes_familiares ||
            null,

          antecedentes_patologicos ||
            null,

          antecedentes_emocionales ||
            null,

          habitos ||
            null,

          alergias ||
            null,

          enfermedades_previas ||
            null,

          medicamentos_actuales ||
            null,

          cirugias ||
            null,

          historia_desarrollo ||
            null,

          evaluacion_inicial ||
            null,

          diagnostico_inicial ||
            null,

          tratamiento_inicial ||
            null,

          notas ||
            null
        ]
      );


    return res
      .status(201)
      .json({

        success:
          true,

        message:
          "✅ Historial inicial guardado",

        id_historial:
          result.insertId

      });


  } catch (
    err
  ) {

    console.error(
      "❌ Error al guardar historial inicial:",
      err
    );


    return res.status(500).json({
      success: false,
      message:
        "Error interno al guardar historial inicial",

      error:
        process.env.NODE_ENV ===
        "development"
          ? err.message
          : undefined
    });

  }

}


// ============================================================
// ACTUALIZAR HISTORIAL INICIAL
//
// IMPORTANTE:
// Se actualizan los mismos campos que se utilizan al crear.
// ============================================================

export async function actualizarHistorialInicial(
  req,
  res
) {

  const {
    id_paciente
  } = req.params;


  const {

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

    const idPaciente =
      Number(
        id_paciente
      );


    if (
      !Number.isInteger(
        idPaciente
      ) ||
      idPaciente <= 0
    ) {

      return res.status(400).json({
        success: false,
        message:
          "ID de paciente inválido"
      });

    }


    // ========================================================
    // VERIFICAR HISTORIAL
    // ========================================================

    const [
      rows
    ] =
      await pool.query(
        `
          SELECT
            id_historial_inicial

          FROM historial_inicial

          WHERE id_paciente = ?

          LIMIT 1
        `,
        [
          idPaciente
        ]
      );


    if (
      !rows.length
    ) {

      return res.status(404).json({
        success: false,
        message:
          "Historial inicial no encontrado"
      });

    }


    // ========================================================
    // ACTUALIZAR TODO EL HISTORIAL
    // ========================================================

    const [
      result
    ] =
      await pool.query(
        `
          UPDATE historial_inicial

          SET

            estado_civil = ?,

            ocupacion = ?,

            escolaridad = ?,

            antecedentes_personales = ?,

            antecedentes_familiares = ?,

            antecedentes_patologicos = ?,

            antecedentes_emocionales = ?,

            habitos = ?,

            alergias = ?,

            enfermedades_previas = ?,

            medicamentos_actuales = ?,

            cirugias = ?,

            historia_desarrollo = ?,

            evaluacion_inicial = ?,

            diagnostico_inicial = ?,

            tratamiento_inicial = ?,

            notas = ?,

            fecha_registro = NOW()

          WHERE
            id_paciente = ?
        `,
        [

          estado_civil ||
            null,

          ocupacion ||
            null,

          escolaridad ||
            null,

          antecedentes_personales ||
            null,

          antecedentes_familiares ||
            null,

          antecedentes_patologicos ||
            null,

          antecedentes_emocionales ||
            null,

          habitos ||
            null,

          alergias ||
            null,

          enfermedades_previas ||
            null,

          medicamentos_actuales ||
            null,

          cirugias ||
            null,

          historia_desarrollo ||
            null,

          evaluacion_inicial ||
            null,

          diagnostico_inicial ||
            null,

          tratamiento_inicial ||
            null,

          notas ||
            null,

          idPaciente

        ]
      );


    if (
      result.affectedRows === 0
    ) {

      return res.status(404).json({
        success: false,
        message:
          "No se encontró el historial para actualizar"
      });

    }


    // ========================================================
    // DEVOLVER HISTORIAL ACTUALIZADO
    // ========================================================

    const [
      historialActualizado
    ] =
      await pool.query(
        `
          SELECT *

          FROM historial_inicial

          WHERE id_paciente = ?

          LIMIT 1
        `,
        [
          idPaciente
        ]
      );


    return res.json({

      success:
        true,

      message:
        "✅ Historial actualizado correctamente",

      historial:
        historialActualizado[0] ||
        null

    });


  } catch (
    err
  ) {

    console.error(
      "❌ Error al actualizar historial inicial:",
      err
    );


    return res.status(500).json({

      success:
        false,

      message:
        "Error al actualizar historial inicial",

      error:
        process.env.NODE_ENV ===
        "development"
          ? err.message
          : undefined

    });

  }

}