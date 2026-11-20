import pool
from "../config/database.js";


// ==================================================
// AUXILIARES
// ==================================================

const normalizar =
  valor =>
    valor
      ? String(valor)
          .trim()
          .toLowerCase()
      : "";


const enteroPositivo =
  valor => {

    const numero =
      Number(valor);

    return (
      Number.isInteger(numero) &&
      numero > 0
    )
      ? numero
      : null;
  };


// ==================================================
// VALIDAR USUARIO RH
// ==================================================

const validarUsuarioRH =
  async user => {

    const idUsuario =
      enteroPositivo(
        user?.id_usuario
      );

    if (!idUsuario) {

      return {
        ok: false,
        status: 401,
        message:
          "No se pudo identificar al usuario"
      };
    }


    const [rows] =
      await pool.query(
        `
          SELECT
            id_usuario,
            rol,
            area,
            tipo_admin

          FROM usuarios

          WHERE
            id_usuario = ?

          LIMIT 1
        `,
        [
          idUsuario
        ]
      );


    if (!rows.length) {

      return {
        ok: false,
        status: 401,
        message:
          "Usuario no encontrado"
      };
    }


    const usuario =
      rows[0];


    const rol =
      normalizar(
        usuario.rol
      );


    const area =
      normalizar(
        usuario.area
      );


    const tipoAdmin =
      normalizar(
        usuario.tipo_admin
      );


    const esRH =
      rol === "rh" &&
      area === "rh";


    const esAdminRH =
      tipoAdmin === "normal" &&
      area === "rh";


    const esMaster =
      tipoAdmin === "master";


    if (
      !esRH &&
      !esAdminRH &&
      !esMaster
    ) {

      return {
        ok: false,
        status: 403,
        message:
          "No tienes permiso para utilizar la Agenda RH"
      };
    }


    return {
      ok: true,
      usuario
    };

  };


// ==================================================
// LISTAR ACTIVIDADES
//
// GET /api/agenda-rh
// ==================================================

export const listarAgendaRH =
async (req, res) => {

  try {

    const acceso =
      await validarUsuarioRH(
        req.user
      );


    if (!acceso.ok) {

      return res
        .status(
          acceso.status
        )
        .json({

          success: false,

          message:
            acceso.message

        });

    }


    const idUsuario =
      acceso.usuario
        .id_usuario;


    const [actividades] =
      await pool.query(
        `
          SELECT

            id_agenda,

            id_usuario_rh,

            titulo,

            tipo_actividad,

            fecha,

            hora_inicio,

            hora_fin,

            descripcion,

            ubicacion,

            enlace,

            persona_relacionada,

            recordatorio_activo,

            minutos_recordatorio,

            estado,

            fecha_creacion,

            fecha_actualizacion


          FROM agenda_rh


          WHERE
            id_usuario_rh = ?


          ORDER BY

            fecha ASC,

            CASE
              WHEN hora_inicio IS NULL
              THEN '23:59:59'
              ELSE hora_inicio
            END ASC,

            id_agenda ASC
        `,
        [
          idUsuario
        ]
      );


    return res.json({

      success: true,

      total:
        actividades.length,

      actividades

    });


  } catch (error) {

    console.error(
      "❌ Error listando Agenda RH:",
      error
    );


    return res
      .status(500)
      .json({

        success: false,

        message:
          "Error interno al obtener la agenda"

      });

  }

};


// ==================================================
// CREAR ACTIVIDAD
//
// POST /api/agenda-rh
// ==================================================

export const crearActividadRH =
async (req, res) => {

  try {

    const acceso =
      await validarUsuarioRH(
        req.user
      );


    if (!acceso.ok) {

      return res
        .status(
          acceso.status
        )
        .json({

          success: false,

          message:
            acceso.message

        });

    }


    const idUsuario =
      acceso.usuario
        .id_usuario;


    const titulo =
      String(
        req.body?.titulo ||
        ""
      ).trim();


    const tipoActividad =
      normalizar(
        req.body
          ?.tipo_actividad
      ) || "actividad";


    const fecha =
      String(
        req.body?.fecha ||
        ""
      ).trim();


    const horaInicio =
      req.body?.hora_inicio ||
      null;


    const horaFin =
      req.body?.hora_fin ||
      null;


    const descripcion =
      String(
        req.body?.descripcion ||
        ""
      ).trim() ||
      null;


    const ubicacion =
      String(
        req.body?.ubicacion ||
        ""
      ).trim() ||
      null;


    const enlace =
      String(
        req.body?.enlace ||
        ""
      ).trim() ||
      null;


    const personaRelacionada =
      String(
        req.body
          ?.persona_relacionada ||
        ""
      ).trim() ||
      null;


    const recordatorioActivo =
      Number(
        req.body
          ?.recordatorio_activo
      ) === 1
        ? 1
        : 0;


    const minutosRecordatorio =
      recordatorioActivo
        ? enteroPositivo(
            req.body
              ?.minutos_recordatorio
          )
        : null;


    if (!titulo) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "Debes indicar un título"

        });

    }


    if (!fecha) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "Debes indicar la fecha"

        });

    }


    const tiposPermitidos = [

      "entrevista",

      "reunion",

      "llamada",

      "seguimiento",

      "evaluacion",

      "recordatorio",

      "actividad",

      "otro"

    ];


    if (
      !tiposPermitidos.includes(
        tipoActividad
      )
    ) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "Tipo de actividad inválido"

        });

    }


    const [resultado] =
      await pool.query(
        `
          INSERT INTO agenda_rh
          (
            id_usuario_rh,

            titulo,

            tipo_actividad,

            fecha,

            hora_inicio,

            hora_fin,

            descripcion,

            ubicacion,

            enlace,

            persona_relacionada,

            recordatorio_activo,

            minutos_recordatorio,

            estado
          )

          VALUES
          (
            ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?,
            'pendiente'
          )
        `,
        [

          idUsuario,

          titulo,

          tipoActividad,

          fecha,

          horaInicio,

          horaFin,

          descripcion,

          ubicacion,

          enlace,

          personaRelacionada,

          recordatorioActivo,

          minutosRecordatorio

        ]
      );


    return res
      .status(201)
      .json({

        success: true,

        message:
          "Actividad registrada correctamente",

        actividad: {

          id_agenda:
            resultado.insertId,

          titulo,

          tipo_actividad:
            tipoActividad,

          fecha,

          hora_inicio:
            horaInicio,

          hora_fin:
            horaFin,

          descripcion,

          ubicacion,

          enlace,

          persona_relacionada:
            personaRelacionada,

          recordatorio_activo:
            recordatorioActivo,

          minutos_recordatorio:
            minutosRecordatorio,

          estado:
            "pendiente"

        }

      });


  } catch (error) {

    console.error(
      "❌ Error creando actividad RH:",
      error
    );


    return res
      .status(500)
      .json({

        success: false,

        message:
          "Error interno al registrar la actividad"

      });

  }

};


// ==================================================
// ACTUALIZAR ACTIVIDAD
//
// PUT /api/agenda-rh/:id
// ==================================================

export const actualizarActividadRH =
async (req, res) => {

  try {

    const acceso =
      await validarUsuarioRH(
        req.user
      );


    if (!acceso.ok) {

      return res
        .status(
          acceso.status
        )
        .json({

          success: false,

          message:
            acceso.message

        });

    }


    const idAgenda =
      enteroPositivo(
        req.params.id
      );


    if (!idAgenda) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "Actividad inválida"

        });

    }


    const idUsuario =
      acceso.usuario
        .id_usuario;


    const titulo =
      String(
        req.body?.titulo ||
        ""
      ).trim();


    const tipoActividad =
      normalizar(
        req.body
          ?.tipo_actividad
      );


    const fecha =
      String(
        req.body?.fecha ||
        ""
      ).trim();


    const horaInicio =
      req.body?.hora_inicio ||
      null;


    const horaFin =
      req.body?.hora_fin ||
      null;


    const descripcion =
      String(
        req.body?.descripcion ||
        ""
      ).trim() ||
      null;


    const ubicacion =
      String(
        req.body?.ubicacion ||
        ""
      ).trim() ||
      null;


    const enlace =
      String(
        req.body?.enlace ||
        ""
      ).trim() ||
      null;


    const personaRelacionada =
      String(
        req.body
          ?.persona_relacionada ||
        ""
      ).trim() ||
      null;


    const recordatorioActivo =
      Number(
        req.body
          ?.recordatorio_activo
      ) === 1
        ? 1
        : 0;


    const minutosRecordatorio =
      recordatorioActivo
        ? enteroPositivo(
            req.body
              ?.minutos_recordatorio
          )
        : null;


    const estado =
      normalizar(
        req.body?.estado
      ) ||
      "pendiente";


    if (
      !titulo ||
      !fecha
    ) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "Título y fecha son obligatorios"

        });

    }


    if (
      ![
        "pendiente",
        "realizado",
        "cancelado"
      ].includes(
        estado
      )
    ) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "Estado inválido"

        });

    }


    const [resultado] =
      await pool.query(
        `
          UPDATE agenda_rh

          SET
            titulo = ?,

            tipo_actividad = ?,

            fecha = ?,

            hora_inicio = ?,

            hora_fin = ?,

            descripcion = ?,

            ubicacion = ?,

            enlace = ?,

            persona_relacionada = ?,

            recordatorio_activo = ?,

            minutos_recordatorio = ?,

            estado = ?


          WHERE

            id_agenda = ?

            AND id_usuario_rh = ?
        `,
        [

          titulo,

          tipoActividad,

          fecha,

          horaInicio,

          horaFin,

          descripcion,

          ubicacion,

          enlace,

          personaRelacionada,

          recordatorioActivo,

          minutosRecordatorio,

          estado,

          idAgenda,

          idUsuario

        ]
      );


    if (
      resultado.affectedRows ===
      0
    ) {

      return res
        .status(404)
        .json({

          success: false,

          message:
            "Actividad no encontrada"

        });

    }


    return res.json({

      success: true,

      message:
        "Actividad actualizada correctamente"

    });


  } catch (error) {

    console.error(
      "❌ Error actualizando Agenda RH:",
      error
    );


    return res
      .status(500)
      .json({

        success: false,

        message:
          "Error interno al actualizar la actividad"

      });

  }

};


// ==================================================
// ELIMINAR ACTIVIDAD
//
// DELETE /api/agenda-rh/:id
// ==================================================

export const eliminarActividadRH =
async (req, res) => {

  try {

    const acceso =
      await validarUsuarioRH(
        req.user
      );


    if (!acceso.ok) {

      return res
        .status(
          acceso.status
        )
        .json({

          success: false,

          message:
            acceso.message

        });

    }


    const idAgenda =
      enteroPositivo(
        req.params.id
      );


    if (!idAgenda) {

      return res
        .status(400)
        .json({

          success: false,

          message:
            "Actividad inválida"

        });

    }


    const [resultado] =
      await pool.query(
        `
          DELETE FROM agenda_rh

          WHERE
            id_agenda = ?

            AND id_usuario_rh = ?
        `,
        [

          idAgenda,

          acceso.usuario
            .id_usuario

        ]
      );


    if (
      resultado.affectedRows ===
      0
    ) {

      return res
        .status(404)
        .json({

          success: false,

          message:
            "Actividad no encontrada"

        });

    }


    return res.json({

      success: true,

      message:
        "Actividad eliminada correctamente"

    });


  } catch (error) {

    console.error(
      "❌ Error eliminando actividad RH:",
      error
    );


    return res
      .status(500)
      .json({

        success: false,

        message:
          "Error interno al eliminar la actividad"

      });

  }

};