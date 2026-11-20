// ==================================================
// backend/controllers/seguimientoProspectoController.js
// ==================================================

import pool from "../config/database.js";


// ==================================================
// AUXILIAR: VALIDAR ACCESO RH AL PROSPECTO
// ==================================================

const validarAccesoProspecto = async (
  idProspecto,
  user
) => {

  const idUsuario =
    Number(user?.id_usuario) || null;

  if (!idUsuario) {
    return {
      ok: false,
      status: 401,
      message:
        "No se pudo identificar al usuario",
    };
  }

  // ==================================================
  // CONTEXTO REAL DEL USUARIO RH
  //
  // Permite:
  // - Master
  // - Admin RH
  // - Usuario RH
  // - Independiente con perfil RH
  // ==================================================

  const [usuarios] =
    await pool.query(
      `
        SELECT
          u.id_usuario,
          u.tipo_admin,
          u.area,
          u.rol,
          u.id_admin_padre,
          u.id_organizacion,
          o.tipo AS tipo_organizacion,
          o.perfil_independiente,
          o.estado AS estado_organizacion
        FROM usuarios u
        LEFT JOIN organizaciones o
          ON o.id_organizacion =
             u.id_organizacion
        WHERE u.id_usuario = ?
        LIMIT 1
      `,
      [idUsuario]
    );

  if (!usuarios.length) {
    return {
      ok: false,
      status: 401,
      message:
        "No se pudo identificar al usuario",
    };
  }

  const usuario =
    usuarios[0];

  const tipoAdmin =
    String(
      usuario.tipo_admin || ""
    )
      .trim()
      .toLowerCase();

  const area =
    String(
      usuario.area || ""
    )
      .trim()
      .toLowerCase();

  const rol =
    String(
      usuario.rol || ""
    )
      .trim()
      .toLowerCase();

  const perfilIndependiente =
    String(
      usuario.perfil_independiente || ""
    )
      .trim()
      .toLowerCase();

  const estadoOrganizacion =
    String(
      usuario.estado_organizacion || ""
    )
      .trim()
      .toLowerCase();

  const esMaster =
    tipoAdmin === "master";

  const esAdminRH =
    tipoAdmin === "normal" &&
    area === "rh";

  const esUsuarioRH =
    rol === "rh" &&
    area === "rh";

  const esIndependienteRH =
    rol === "independiente" &&
    area === "independiente" &&
    perfilIndependiente === "rh" &&
    estadoOrganizacion === "activa";

  const tienePermiso =
    esMaster ||
    esAdminRH ||
    esUsuarioRH ||
    esIndependienteRH;

  if (!tienePermiso) {
    return {
      ok: false,
      status: 403,
      message:
        "No tienes permiso para acceder al seguimiento de prospectos",
    };
  }

  let query = `
    SELECT
      *
    FROM prospectos
    WHERE id_prospecto = ?
  `;

  const params = [
    idProspecto
  ];

  // Todo usuario RH no-master,
  // incluido Independiente RH,
  // solo puede acceder a sus propios prospectos.
  if (!esMaster) {
    query += `
      AND id_admin_padre = ?
    `;

    params.push(
      idUsuario
    );
  }

  query += `
    LIMIT 1
  `;

  const [rows] =
    await pool.query(
      query,
      params
    );

  if (!rows.length) {
    return {
      ok: false,
      status: 404,
      message:
        "Prospecto no encontrado o no tienes permiso para acceder a él",
    };
  }

  return {
    ok: true,
    prospecto:
      rows[0],
    contexto: {
      idUsuario,
      tipoAdmin,
      area,
      rol,
      idOrganizacion:
        Number(
          usuario.id_organizacion
        ) || null,
      perfilIndependiente,
      esMaster,
      esAdminRH,
      esUsuarioRH,
      esIndependienteRH,
    },
  };
};




// ==================================================
// REGISTRAR SEGUIMIENTO
// POST /api/prospectos/:id/seguimiento
// ==================================================

export const registrarSeguimientoProspecto =
  async (
    req,
    res
  ) => {

    try {

      const idProspecto =
        Number(
          req.params.id
        );


      // ==================================================
      // VALIDAR ID
      // ==================================================

      if (
        !Number.isInteger(
          idProspecto
        ) ||
        idProspecto <= 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "ID de prospecto inválido",
        });

      }


      // ==================================================
      // VALIDAR ACCESO
      // ==================================================

      const acceso =
        await validarAccesoProspecto(
          idProspecto,
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
              acceso.message,
          });

      }


      // ==================================================
      // DATOS
      // ==================================================

      const {
        etapa,
        actividad,
        observacion,
        resultado,
        proxima_accion,
        fecha_proxima_accion,
      } = req.body;


      // ==================================================
      // VALIDAR ACTIVIDAD
      // ==================================================

      if (
        !actividad ||
        !String(
          actividad
        ).trim()
      ) {

        return res.status(400).json({
          success: false,
          message:
            "La actividad del seguimiento es obligatoria",
        });

      }


      // ==================================================
      // VALIDAR RESULTADO
      // ==================================================

      const resultadosPermitidos = [
        "pendiente",
        "continua",
        "detenido",
        "aprobado",
        "no_aprobado",
      ];


      const resultadoNormalizado =
        resultado
          ? String(
              resultado
            )
              .trim()
              .toLowerCase()
          : "pendiente";


      if (
        !resultadosPermitidos.includes(
          resultadoNormalizado
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Resultado de seguimiento inválido",
        });

      }


      // ==================================================
      // NORMALIZAR ETAPA
      // ==================================================

      const etapaNormalizada =
        etapa &&
        String(
          etapa
        ).trim()
          ? String(
              etapa
            ).trim()
          : "seguimiento";


      // ==================================================
      // INSERTAR
      // ==================================================

      const [resultadoInsert] =
        await pool.query(
          `
            INSERT INTO seguimiento_prospectos
            (
              id_prospecto,
              id_usuario_registro,
              fecha,
              etapa,
              actividad,
              observacion,
              resultado,
              proxima_accion,
              fecha_proxima_accion,
              creado_en
            )
            VALUES
            (
              ?,
              ?,
              NOW(),
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
            idProspecto,

            req.user?.id_usuario ||
              null,

            etapaNormalizada,

            String(
              actividad
            ).trim(),

            observacion
              ? String(
                  observacion
                ).trim()
              : null,

            resultadoNormalizado,

            proxima_accion
              ? String(
                  proxima_accion
                ).trim()
              : null,

            fecha_proxima_accion ||
              null,
          ]
        );


      // ==================================================
      // SI HAY MOVIMIENTO, ACTUALIZAR ESTATUS
      // ==================================================

      let nuevoEstatus =
        null;


      if (
        resultadoNormalizado ===
        "continua"
      ) {

        nuevoEstatus =
          "en_proceso";

      }


      if (
        etapaNormalizada
          .toLowerCase()
          .includes(
            "evalu"
          )
      ) {

        nuevoEstatus =
          "evaluacion";

      }


      if (
        resultadoNormalizado ===
        "aprobado"
      ) {

        nuevoEstatus =
          "aprobado";

      }


      if (
        resultadoNormalizado ===
        "no_aprobado"
      ) {

        nuevoEstatus =
          "no_contratado";

      }


      if (
        nuevoEstatus
      ) {

        await pool.query(
          `
            UPDATE prospectos
            SET estatus = ?
            WHERE id_prospecto = ?
          `,
          [
            nuevoEstatus,
            idProspecto,
          ]
        );

      }


      // ==================================================
      // RESPUESTA
      // ==================================================

      return res.status(201).json({
        success: true,

        message:
          "Seguimiento registrado correctamente",

        id_seguimiento:
          resultadoInsert.insertId,

        nuevo_estatus:
          nuevoEstatus,

      });


    } catch (error) {

      console.error(
        "❌ Error al registrar seguimiento del prospecto:",
        error
      );


      return res.status(500).json({
        success: false,

        message:
          "Error interno al registrar el seguimiento",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined,
      });

    }

  };


// ==================================================
// LISTAR SEGUIMIENTO
// GET /api/prospectos/:id/seguimiento
// ==================================================

export const listarSeguimientoProspecto =
  async (
    req,
    res
  ) => {

    try {

      const idProspecto =
        Number(
          req.params.id
        );


      // ==================================================
      // VALIDAR ID
      // ==================================================

      if (
        !Number.isInteger(
          idProspecto
        ) ||
        idProspecto <= 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "ID de prospecto inválido",
        });

      }


      // ==================================================
      // VALIDAR ACCESO
      // ==================================================

      const acceso =
        await validarAccesoProspecto(
          idProspecto,
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
              acceso.message,
          });

      }


      // ==================================================
      // CONSULTAR HISTORIAL
      // ==================================================

      const [seguimientos] =
        await pool.query(
          `
            SELECT
              sp.id_seguimiento,
              sp.id_prospecto,
              sp.id_usuario_registro,
              sp.fecha,
              sp.etapa,
              sp.actividad,
              sp.observacion,
              sp.resultado,
              sp.proxima_accion,
              sp.fecha_proxima_accion,
              sp.creado_en,
              sp.actualizado_en,

              u.nombre AS usuario_registro

            FROM seguimiento_prospectos sp

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 sp.id_usuario_registro

            WHERE sp.id_prospecto = ?

            ORDER BY
              sp.fecha DESC,
              sp.id_seguimiento DESC
          `,
          [
            idProspecto
          ]
        );


      // ==================================================
      // RESPUESTA
      // ==================================================

      return res.json({
        success: true,

        prospecto:
          acceso.prospecto,

        seguimientos,
      });


    } catch (error) {

      console.error(
        "❌ Error al obtener seguimiento del prospecto:",
        error
      );


      return res.status(500).json({
        success: false,

        message:
          "Error interno al obtener el seguimiento",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined,
      });

    }

  };