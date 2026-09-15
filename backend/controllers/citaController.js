// backend/controllers/citaController.js

import pool from "../config/database.js";


/* ============================================================
   OBTENER CITAS
   Solo del psicólogo logueado
============================================================ */

export async function listarCitas(req, res) {

  try {

    const user = req.user;

    if (!user || !user.id_psicologo) {

      return res.status(403).json({
        message: "Acceso denegado: psicólogo no válido"
      });

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

      INNER JOIN pacientes p
        ON c.id_paciente = p.id_paciente

      INNER JOIN psicologos ps
        ON c.id_psicologo = ps.id_psicologo

      INNER JOIN usuarios u
        ON ps.id_usuario = u.id_usuario

      WHERE c.id_psicologo = ?

      ORDER BY
        c.fecha ASC,
        c.hora ASC
      `,
      [
        user.id_psicologo
      ]
    );


    res.json(rows || []);

  } catch (err) {

    console.error(
      "❌ Error al obtener citas:",
      err
    );

    res.status(500).json({
      message: "Error al obtener citas"
    });

  }

}


/* ============================================================
   CREAR CITA

   IMPORTANTE:
   Aquí SOLO se crea la cita.

   NO se crea sesión.
   NO se genera videollamada.
   NO se genera sala.
============================================================ */

export async function crearCita(req, res) {

  try {

    const user = req.user;

    if (!user || !user.id_psicologo) {

      return res.status(403).json({
        message: "Acceso denegado: psicólogo no válido"
      });

    }


    const {
      id_paciente,
      fecha,
      hora,
      motivo,
      notas
    } = req.body;


    /* ========================================================
       VALIDAR DATOS
    ======================================================== */

    if (
      !id_paciente ||
      !fecha ||
      !hora
    ) {

      return res.status(400).json({
        message:
          "Faltan datos obligatorios: paciente, fecha u hora."
      });

    }


    /* ========================================================
       VALIDAR PACIENTE
    ======================================================== */

    const [paciente] = await pool.query(
      `
      SELECT
        id_paciente,
        nombre
      FROM pacientes
      WHERE id_paciente = ?
      `,
      [
        id_paciente
      ]
    );


    if (!paciente.length) {

      return res.status(400).json({
        message: "El paciente no existe."
      });

    }


    /* ========================================================
       VALIDAR HORARIO

       No permitir dos citas activas del mismo psicólogo
       en la misma fecha y hora.

       Una cita cancelada NO bloquea el horario.
    ======================================================== */

    const [citaExistente] = await pool.query(
      `
      SELECT
        id_cita
      FROM citas
      WHERE id_psicologo = ?
      AND fecha = ?
      AND hora = ?
      AND estado <> 'cancelada'
      LIMIT 1
      `,
      [
        user.id_psicologo,
        fecha,
        hora
      ]
    );


    if (citaExistente.length) {

      return res.status(409).json({
        message:
          "Ese horario ya está ocupado por otra cita."
      });

    }


    /* ========================================================
       CREAR CITA

       La cita nueva queda APARTADA.

       Verde = horario ocupado/apartado.
    ======================================================== */

    const [result] = await pool.query(
      `
      INSERT INTO citas
      (
        id_paciente,
        id_psicologo,
        fecha,
        hora,
        motivo,
        notas,
        estado
      )
      VALUES (?, ?, ?, ?, ?, ?, ?)
      `,
      [
        id_paciente,
        user.id_psicologo,
        fecha,
        hora,
        motivo || null,
        notas || "",
        "apartada"
      ]
    );


    console.log(
      "📅 Cita creada:",
      {
        id_cita: result.insertId,
        id_paciente,
        id_psicologo: user.id_psicologo,
        fecha,
        hora
      }
    );


    res.status(201).json({

      message:
        "✅ Cita agendada correctamente.",

      id_cita:
        result.insertId,

      estado:
        "apartada"

    });

  } catch (err) {

    console.error(
      "❌ Error al crear cita:",
      err
    );

    res.status(500).json({
      message: "Error al crear cita"
    });

  }

}


/* ============================================================
   OBTENER UNA CITA
============================================================ */

export async function obtenerCita(req, res) {

  const {
    id
  } = req.params;


  try {

    const user = req.user;

    if (!user || !user.id_psicologo) {

      return res.status(403).json({
        message: "Acceso denegado: psicólogo no válido"
      });

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

      INNER JOIN pacientes p
        ON c.id_paciente = p.id_paciente

      INNER JOIN psicologos ps
        ON c.id_psicologo = ps.id_psicologo

      INNER JOIN usuarios u
        ON ps.id_usuario = u.id_usuario

      WHERE c.id_cita = ?
      AND c.id_psicologo = ?
      `,
      [
        id,
        user.id_psicologo
      ]
    );


    if (!rows.length) {

      return res.status(404).json({
        message: "Cita no encontrada."
      });

    }


    res.json(
      rows[0]
    );

  } catch (err) {

    console.error(
      "❌ Error al obtener cita:",
      err
    );

    res.status(500).json({
      message: "Error al obtener cita"
    });

  }

}


/* ============================================================
   ACTUALIZAR CITA COMPLETA
============================================================ */

export async function actualizarCita(req, res) {

  const {
    id
  } = req.params;


  try {

    const user = req.user;

    if (!user || !user.id_psicologo) {

      return res.status(403).json({
        message: "Acceso denegado: psicólogo no válido"
      });

    }


    const {
      fecha,
      hora,
      motivo,
      estado,
      notas
    } = req.body;


    /* ========================================================
       VALIDAR FECHA Y HORA SI VIENEN
    ======================================================== */

    if (!fecha || !hora) {

      return res.status(400).json({
        message:
          "La fecha y hora son obligatorias."
      });

    }


    /* ========================================================
       COMPROBAR QUE NO SE DUPLIQUE HORARIO
    ======================================================== */

    const [duplicada] = await pool.query(
      `
      SELECT
        id_cita
      FROM citas
      WHERE id_psicologo = ?
      AND fecha = ?
      AND hora = ?
      AND id_cita <> ?
      AND estado <> 'cancelada'
      LIMIT 1
      `,
      [
        user.id_psicologo,
        fecha,
        hora,
        id
      ]
    );


    if (duplicada.length) {

      return res.status(409).json({
        message:
          "Ese horario ya está ocupado por otra cita."
      });

    }


    const estadosPermitidos = [
      "apartada",
      "pendiente",
      "completada",
      "cancelada"
    ];


    const estadoFinal =
      estadosPermitidos.includes(estado)
        ? estado
        : "apartada";


    const [result] = await pool.query(
      `
      UPDATE citas

      SET
        fecha = ?,
        hora = ?,
        motivo = ?,
        estado = ?,
        notas = ?

      WHERE id_cita = ?
      AND id_psicologo = ?
      `,
      [
        fecha,
        hora,
        motivo || null,
        estadoFinal,
        notas || "",
        id,
        user.id_psicologo
      ]
    );


    if (
      result.affectedRows === 0
    ) {

      return res.status(404).json({
        message:
          "Cita no encontrada."
      });

    }


    res.json({

      message:
        "✅ Cita actualizada correctamente.",

      estado:
        estadoFinal

    });

  } catch (err) {

    console.error(
      "❌ Error al actualizar cita:",
      err
    );

    res.status(500).json({
      message:
        "Error al actualizar cita"
    });

  }

}


/* ============================================================
   CAMBIAR SOLO EL ESTADO

   Endpoint:
   PUT /api/citas/:id/estado

   Se utiliza para:
   - apartada
   - pendiente
   - completada
   - cancelada
============================================================ */

export async function actualizarEstadoCita(req, res) {

  const {
    id
  } = req.params;


  try {

    const user = req.user;

    if (!user || !user.id_psicologo) {

      return res.status(403).json({
        message:
          "Acceso denegado: psicólogo no válido"
      });

    }


    const {
      estado
    } = req.body;


    const estadosPermitidos = [
      "apartada",
      "pendiente",
      "completada",
      "cancelada"
    ];


    if (
      !estadosPermitidos.includes(estado)
    ) {

      return res.status(400).json({
        message:
          "Estado de cita no válido."
      });

    }


    const [result] = await pool.query(
      `
      UPDATE citas

      SET estado = ?

      WHERE id_cita = ?
      AND id_psicologo = ?
      `,
      [
        estado,
        id,
        user.id_psicologo
      ]
    );


    if (
      result.affectedRows === 0
    ) {

      return res.status(404).json({
        message:
          "Cita no encontrada."
      });

    }


    console.log(
      "📅 Estado de cita actualizado:",
      {
        id_cita: id,
        estado
      }
    );


    res.json({

      message:
        "✅ Estado de la cita actualizado.",

      estado

    });

  } catch (err) {

    console.error(
      "❌ Error al actualizar estado:",
      err
    );

    res.status(500).json({
      message:
        "Error al actualizar estado de la cita"
    });

  }

}


/* ============================================================
   ELIMINAR CITA

   Esto elimina completamente la cita.

   Para el uso normal recomendamos CANCELAR,
   porque así queda historial.
============================================================ */

export async function eliminarCita(req, res) {

  const {
    id
  } = req.params;


  try {

    const user = req.user;

    if (!user || !user.id_psicologo) {

      return res.status(403).json({
        message:
          "Acceso denegado: psicólogo no válido"
      });

    }


    const [result] = await pool.query(
      `
      DELETE FROM citas

      WHERE id_cita = ?
      AND id_psicologo = ?
      `,
      [
        id,
        user.id_psicologo
      ]
    );


    if (
      result.affectedRows === 0
    ) {

      return res.status(404).json({
        message:
          "Cita no encontrada."
      });

    }


    res.json({
      message:
        "✅ Cita eliminada correctamente."
    });

  } catch (err) {

    console.error(
      "❌ Error al eliminar cita:",
      err
    );

    res.status(500).json({
      message:
        "Error al eliminar cita"
    });

  }

}