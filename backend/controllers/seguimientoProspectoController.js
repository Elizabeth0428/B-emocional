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
    user?.id_usuario;

  const tipoAdmin =
    user?.tipo_admin
      ? String(user.tipo_admin)
          .trim()
          .toLowerCase()
      : null;

  const area =
    user?.area
      ? String(user.area)
          .trim()
          .toLowerCase()
      : null;


  if (!idUsuario) {

    return {
      ok: false,
      status: 401,
      message:
        "No se pudo identificar al usuario",
    };

  }


  if (
    tipoAdmin !== "master" &&
    area !== "rh"
  ) {

    return {
      ok: false,
      status: 403,
      message:
        "No tienes permiso para acceder al seguimiento de prospectos",
    };

  }


  let query = `
    SELECT
      id_prospecto,
      id_mirror,
      nombre,
      estatus,
      id_admin_padre
    FROM prospectos
    WHERE id_prospecto = ?
  `;

  const params = [
    idProspecto
  ];


  if (
    tipoAdmin !== "master"
  ) {

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


  const [resultados] =
    await pool.query(
      query,
      params
    );


  if (
    resultados.length === 0
  ) {

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
      resultados[0],
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