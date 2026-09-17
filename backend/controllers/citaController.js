// backend/controllers/citaController.js

import pool from "../config/database.js";

/* ==================================================
   TIPOS Y ESTADOS PERMITIDOS
================================================== */

const TIPOS_EVENTO = [
  "consulta",
  "reunion",
  "supervision",
  "capacitacion",
  "administrativo",
  "personal",
  "otro"
];

const MODALIDADES = [
  "presencial",
  "videollamada",
  "otro"
];

const ESTADOS = [
  "apartada",
  "pendiente",
  "completada",
  "cancelada"
];

/* ==================================================
   LISTAR EVENTOS / CITAS DEL PSICÓLOGO

   GET /api/citas
================================================== */

export async function listarCitas(req, res) {
  try {
    const idPsicologo = req.user?.id_psicologo;

    if (!idPsicologo) {
      return res.status(401).json({
        success: false,
        message: "Usuario no autenticado"
      });
    }

    const [rows] = await pool.query(
      `
      SELECT
        c.id_cita,
        c.id_psicologo,
        c.id_paciente,
        c.tipo_evento,
        c.titulo,
        c.fecha,
        c.hora,
        c.modalidad,
        c.motivo,
        c.notas,
        c.estado,

        p.nombre AS paciente_nombre,
        p.correo AS paciente_correo,
        p.telefono AS paciente_telefono

      FROM citas c

      LEFT JOIN pacientes p
        ON p.id_paciente = c.id_paciente

      WHERE c.id_psicologo = ?

      ORDER BY
        c.fecha ASC,
        c.hora ASC
      `,
      [idPsicologo]
    );

    return res.json(rows || []);

  } catch (error) {
    console.error(
      "❌ Error al listar citas/eventos:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Error al obtener la agenda"
    });
  }
}

/* ==================================================
   CREAR EVENTO / CITA

   POST /api/citas
================================================== */

export async function crearCita(req, res) {
  try {
    const idPsicologo = req.user?.id_psicologo;

    if (!idPsicologo) {
      return res.status(401).json({
        success: false,
        message: "Usuario no autenticado"
      });
    }

    let {
      id_paciente,
      tipo_evento,
      titulo,
      fecha,
      hora,
      modalidad,
      motivo,
      notas
    } = req.body;

    /* ==================================================
       NORMALIZAR DATOS
    ================================================== */

    tipo_evento =
      tipo_evento?.trim()?.toLowerCase() ||
      "consulta";

    titulo =
      titulo?.trim() ||
      null;

    modalidad =
      modalidad?.trim()?.toLowerCase() ||
      null;

    motivo =
      motivo?.trim() ||
      null;

    notas =
      notas?.trim() ||
      null;

    id_paciente =
      id_paciente !== undefined &&
      id_paciente !== null &&
      id_paciente !== ""
        ? Number(id_paciente)
        : null;

    /* ==================================================
       VALIDACIONES GENERALES
    ================================================== */

    if (!TIPOS_EVENTO.includes(tipo_evento)) {
      return res.status(400).json({
        success: false,
        message: "Tipo de evento no válido"
      });
    }

    if (!fecha) {
      return res.status(400).json({
        success: false,
        message: "La fecha es obligatoria"
      });
    }

    if (!hora) {
      return res.status(400).json({
        success: false,
        message: "La hora es obligatoria"
      });
    }

    if (
      modalidad &&
      !MODALIDADES.includes(modalidad)
    ) {
      return res.status(400).json({
        success: false,
        message: "Modalidad no válida"
      });
    }

    /* ==================================================
       CONSULTA CON PACIENTE

       Una consulta SÍ requiere paciente.
    ================================================== */

    if (tipo_evento === "consulta") {
      if (!id_paciente) {
        return res.status(400).json({
          success: false,
          message:
            "Debes seleccionar un paciente para una consulta"
        });
      }

      const [pacientes] = await pool.query(
        `
        SELECT id_paciente
        FROM pacientes
        WHERE id_paciente = ?
        LIMIT 1
        `,
        [id_paciente]
      );

      if (!pacientes.length) {
        return res.status(404).json({
          success: false,
          message: "Paciente no encontrado"
        });
      }

      /* ================================================
         VERIFICAR QUE EL PACIENTE PERTENEZCA
         AL PSICÓLOGO

         Si tu tabla pacientes tiene id_psicologo,
         se valida aquí.
      ================================================= */

      try {
        const [columnas] = await pool.query(
          `
          SHOW COLUMNS
          FROM pacientes
          LIKE 'id_psicologo'
          `
        );

        if (columnas.length) {
          const [pacientePropio] = await pool.query(
            `
            SELECT id_paciente
            FROM pacientes
            WHERE id_paciente = ?
              AND id_psicologo = ?
            LIMIT 1
            `,
            [
              id_paciente,
              idPsicologo
            ]
          );

          if (!pacientePropio.length) {
            return res.status(403).json({
              success: false,
              message:
                "No tienes permiso para agendar citas para este paciente"
            });
          }
        }
      } catch (errorValidacion) {
        console.warn(
          "⚠️ No se pudo validar propietario del paciente:",
          errorValidacion.message
        );
      }
    }

    /* ==================================================
       EVENTOS SIN PACIENTE

       Reunión, supervisión, capacitación, etc.
    ================================================== */

    if (tipo_evento !== "consulta") {
      id_paciente = null;

      if (!titulo) {
        return res.status(400).json({
          success: false,
          message:
            "El título es obligatorio para este tipo de evento"
        });
      }
    }

    /* ==================================================
       VERIFICAR HORARIO OCUPADO

       Un psicólogo no puede tener dos eventos
       activos exactamente a la misma fecha y hora.

       Los cancelados NO bloquean el horario.
    ================================================== */

    const [ocupadas] = await pool.query(
      `
      SELECT
        id_cita,
        tipo_evento,
        titulo,
        id_paciente,
        estado

      FROM citas

      WHERE id_psicologo = ?
        AND fecha = ?
        AND hora = ?
        AND estado <> 'cancelada'

      LIMIT 1
      `,
      [
        idPsicologo,
        fecha,
        hora
      ]
    );

    if (ocupadas.length) {
      return res.status(409).json({
        success: false,
        message:
          "Ya tienes una cita o evento programado en esa fecha y hora"
      });
    }

    /* ==================================================
       CREAR EVENTO
    ================================================== */

    const [result] = await pool.query(
      `
      INSERT INTO citas
      (
        id_psicologo,
        id_paciente,
        tipo_evento,
        titulo,
        fecha,
        hora,
        modalidad,
        motivo,
        notas,
        estado
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'apartada')
      `,
      [
        idPsicologo,
        id_paciente,
        tipo_evento,
        titulo,
        fecha,
        hora,
        modalidad,
        motivo,
        notas
      ]
    );

    /* ==================================================
       RESPUESTA
    ================================================== */

    return res.status(201).json({
      success: true,

      message:
        tipo_evento === "consulta"
          ? "✅ Cita agendada correctamente"
          : "✅ Evento agendado correctamente",

      id_cita: result.insertId,

      evento: {
        id_cita: result.insertId,
        id_psicologo: idPsicologo,
        id_paciente,
        tipo_evento,
        titulo,
        fecha,
        hora,
        modalidad,
        motivo,
        notas,
        estado: "apartada"
      }
    });

  } catch (error) {
    console.error(
      "❌ Error al crear cita/evento:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Error al guardar el evento"
    });
  }
}

/* ==================================================
   ACTUALIZAR CITA / EVENTO

   PUT /api/citas/:id
================================================== */

export async function actualizarCita(req, res) {
  try {
    const idPsicologo = req.user?.id_psicologo;
    const { id } = req.params;

    if (!idPsicologo) {
      return res.status(401).json({
        success: false,
        message: "Usuario no autenticado"
      });
    }

    /* ==================================================
       BUSCAR EVENTO ACTUAL
    ================================================== */

    const [actuales] = await pool.query(
      `
      SELECT *
      FROM citas
      WHERE id_cita = ?
        AND id_psicologo = ?
      LIMIT 1
      `,
      [
        id,
        idPsicologo
      ]
    );

    if (!actuales.length) {
      return res.status(404).json({
        success: false,
        message: "Cita o evento no encontrado"
      });
    }

    const actual = actuales[0];

    /* ==================================================
       COMBINAR DATOS ACTUALES + NUEVOS
    ================================================== */

    let tipo_evento =
      req.body.tipo_evento !== undefined
        ? String(req.body.tipo_evento)
            .trim()
            .toLowerCase()
        : actual.tipo_evento;

    let id_paciente =
      req.body.id_paciente !== undefined
        ? (
            req.body.id_paciente === "" ||
            req.body.id_paciente === null
              ? null
              : Number(req.body.id_paciente)
          )
        : actual.id_paciente;

    let titulo =
      req.body.titulo !== undefined
        ? (
            String(req.body.titulo || "")
              .trim() || null
          )
        : actual.titulo;

    const fecha =
      req.body.fecha !== undefined
        ? req.body.fecha
        : actual.fecha;

    const hora =
      req.body.hora !== undefined
        ? req.body.hora
        : actual.hora;

    let modalidad =
      req.body.modalidad !== undefined
        ? (
            String(req.body.modalidad || "")
              .trim()
              .toLowerCase() || null
          )
        : actual.modalidad;

    const motivo =
      req.body.motivo !== undefined
        ? (
            String(req.body.motivo || "")
              .trim() || null
          )
        : actual.motivo;

    const notas =
      req.body.notas !== undefined
        ? (
            String(req.body.notas || "")
              .trim() || null
          )
        : actual.notas;

    const estado =
      req.body.estado !== undefined
        ? String(req.body.estado)
            .trim()
            .toLowerCase()
        : actual.estado;

    /* ==================================================
       VALIDACIONES
    ================================================== */

    if (!TIPOS_EVENTO.includes(tipo_evento)) {
      return res.status(400).json({
        success: false,
        message: "Tipo de evento no válido"
      });
    }

    if (!fecha || !hora) {
      return res.status(400).json({
        success: false,
        message:
          "La fecha y la hora son obligatorias"
      });
    }

    if (
      modalidad &&
      !MODALIDADES.includes(modalidad)
    ) {
      return res.status(400).json({
        success: false,
        message: "Modalidad no válida"
      });
    }

    if (!ESTADOS.includes(estado)) {
      return res.status(400).json({
        success: false,
        message: "Estado no válido"
      });
    }

    /* ==================================================
       VALIDAR CONSULTA
    ================================================== */

    if (tipo_evento === "consulta") {
      if (!id_paciente) {
        return res.status(400).json({
          success: false,
          message:
            "Debes seleccionar un paciente para una consulta"
        });
      }

      const [pacientes] = await pool.query(
        `
        SELECT id_paciente
        FROM pacientes
        WHERE id_paciente = ?
        LIMIT 1
        `,
        [id_paciente]
      );

      if (!pacientes.length) {
        return res.status(404).json({
          success: false,
          message: "Paciente no encontrado"
        });
      }
    } else {
      id_paciente = null;

      if (!titulo) {
        return res.status(400).json({
          success: false,
          message:
            "El título es obligatorio para este tipo de evento"
        });
      }
    }

    /* ==================================================
       VALIDAR HORARIO

       Ignorar el propio evento que estamos editando.
    ================================================== */

    if (estado !== "cancelada") {
      const [ocupadas] = await pool.query(
        `
        SELECT id_cita

        FROM citas

        WHERE id_psicologo = ?
          AND fecha = ?
          AND hora = ?
          AND estado <> 'cancelada'
          AND id_cita <> ?

        LIMIT 1
        `,
        [
          idPsicologo,
          fecha,
          hora,
          id
        ]
      );

      if (ocupadas.length) {
        return res.status(409).json({
          success: false,
          message:
            "Ya tienes otra cita o evento programado en esa fecha y hora"
        });
      }
    }

    /* ==================================================
       ACTUALIZAR
    ================================================== */

    await pool.query(
      `
      UPDATE citas

      SET
        id_paciente = ?,
        tipo_evento = ?,
        titulo = ?,
        fecha = ?,
        hora = ?,
        modalidad = ?,
        motivo = ?,
        notas = ?,
        estado = ?

      WHERE id_cita = ?
        AND id_psicologo = ?
      `,
      [
        id_paciente,
        tipo_evento,
        titulo,
        fecha,
        hora,
        modalidad,
        motivo,
        notas,
        estado,
        id,
        idPsicologo
      ]
    );

    return res.json({
      success: true,
      message:
        "✅ Cita o evento actualizado correctamente"
    });

  } catch (error) {
    console.error(
      "❌ Error al actualizar cita/evento:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Error al actualizar la cita o evento"
    });
  }
}

/* ==================================================
   CAMBIAR ESTADO

   PATCH /api/citas/:id/estado
================================================== */

export async function cambiarEstadoCita(req, res) {
  try {
    const idPsicologo = req.user?.id_psicologo;
    const { id } = req.params;

    const estado =
      String(req.body.estado || "")
        .trim()
        .toLowerCase();

    if (!idPsicologo) {
      return res.status(401).json({
        success: false,
        message: "Usuario no autenticado"
      });
    }

    if (!ESTADOS.includes(estado)) {
      return res.status(400).json({
        success: false,
        message: "Estado no válido"
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
        idPsicologo
      ]
    );

    if (!result.affectedRows) {
      return res.status(404).json({
        success: false,
        message: "Cita o evento no encontrado"
      });
    }

    return res.json({
      success: true,
      message: "✅ Estado actualizado correctamente",
      estado
    });

  } catch (error) {
    console.error(
      "❌ Error al cambiar estado:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Error al cambiar el estado"
    });
  }
}

/* ==================================================
   ELIMINAR CITA / EVENTO

   DELETE /api/citas/:id
================================================== */

export async function eliminarCita(req, res) {
  try {
    const idPsicologo = req.user?.id_psicologo;
    const { id } = req.params;

    if (!idPsicologo) {
      return res.status(401).json({
        success: false,
        message: "Usuario no autenticado"
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
        idPsicologo
      ]
    );

    if (!result.affectedRows) {
      return res.status(404).json({
        success: false,
        message: "Cita o evento no encontrado"
      });
    }

    return res.json({
      success: true,
      message:
        "✅ Cita o evento eliminado correctamente"
    });

  } catch (error) {
    console.error(
      "❌ Error al eliminar cita/evento:",
      error
    );

    /*
      Si una cita ya está relacionada con una sesión,
      una FK podría impedir eliminarla.

      En ese caso es preferible cancelarla.
    */

    if (
      error.code === "ER_ROW_IS_REFERENCED_2" ||
      error.errno === 1451
    ) {
      return res.status(409).json({
        success: false,
        message:
          "Este registro ya está relacionado con información clínica. Cancélalo en lugar de eliminarlo."
      });
    }

    return res.status(500).json({
      success: false,
      message:
        "Error al eliminar la cita o evento"
    });
  }
}

/* ==================================================
   OBTENER UNA CITA / EVENTO

   GET /api/citas/:id
================================================== */

export async function obtenerCita(req, res) {
  try {
    const idPsicologo = req.user?.id_psicologo;
    const { id } = req.params;

    if (!idPsicologo) {
      return res.status(401).json({
        success: false,
        message: "Usuario no autenticado"
      });
    }

    const [rows] = await pool.query(
      `
      SELECT
        c.id_cita,
        c.id_psicologo,
        c.id_paciente,
        c.tipo_evento,
        c.titulo,
        c.fecha,
        c.hora,
        c.modalidad,
        c.motivo,
        c.notas,
        c.estado,

        p.nombre AS paciente_nombre,
        p.correo AS paciente_correo,
        p.telefono AS paciente_telefono

      FROM citas c

      LEFT JOIN pacientes p
        ON p.id_paciente = c.id_paciente

      WHERE c.id_cita = ?
        AND c.id_psicologo = ?

      LIMIT 1
      `,
      [
        id,
        idPsicologo
      ]
    );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message: "Cita o evento no encontrado"
      });
    }

    return res.json(rows[0]);

  } catch (error) {
    console.error(
      "❌ Error al obtener cita/evento:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Error al obtener la cita o evento"
    });
  }
}