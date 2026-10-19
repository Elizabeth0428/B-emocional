import pool from "../config/database.js";


// ==================================================
// AUXILIAR: VALIDAR ACCESO RH AL EMPLEADO
// ==================================================

const validarAccesoEmpleado = async (
  idEmpleado,
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
        "No se pudo identificar al usuario"
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
        "No tienes permiso para acceder al seguimiento laboral"
    };

  }


  let query = `
    SELECT
      id_empleado,
      id_admin_padre,
      id_mirror,
      nombre,
      puesto,
      departamento,
      estatus
    FROM empleados
    WHERE id_empleado = ?
  `;

  const params = [
    idEmpleado
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
        "Empleado no encontrado o no tienes permiso para acceder a él"
    };

  }


  return {
    ok: true,
    empleado:
      rows[0]
  };

};


// ==================================================
// REGISTRAR SEGUIMIENTO LABORAL
//
// POST /api/empleados/:id/seguimiento
// ==================================================

export const registrarSeguimientoEmpleado =
  async (
    req,
    res
  ) => {

    try {

      const idEmpleado =
        Number(
          req.params.id
        );


      if (
        !Number.isInteger(
          idEmpleado
        ) ||
        idEmpleado <= 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "ID de empleado inválido"
        });

      }


      const acceso =
        await validarAccesoEmpleado(
          idEmpleado,
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


      const tiposPermitidos = [
        "general",
        "desempeno",
        "bienestar",
        "incidencia",
        "adaptacion",
        "seguimiento",
        "prevencion"
      ];


      const resultadosPermitidos = [
        "pendiente",
        "continua",
        "resuelto",
        "requiere_atencion",
        "canalizacion_sugerida"
      ];


      const tipo =
        String(
          req.body?.tipo ||
          "seguimiento"
        )
          .trim()
          .toLowerCase();


      const resultado =
        String(
          req.body?.resultado ||
          "pendiente"
        )
          .trim()
          .toLowerCase();


      const motivo =
        req.body?.motivo
          ? String(
              req.body.motivo
            ).trim()
          : null;


      const observacion =
        req.body?.observacion
          ? String(
              req.body.observacion
            ).trim()
          : "";


      const accionRealizada =
        req.body?.accion_realizada
          ? String(
              req.body.accion_realizada
            ).trim()
          : null;


      const proximaAccion =
        req.body?.proxima_accion
          ? String(
              req.body.proxima_accion
            ).trim()
          : null;


      const fecha =
        req.body?.fecha ||
        null;


      const fechaProximaAccion =
        req.body?.fecha_proxima_accion ||
        null;


      if (
        !tiposPermitidos.includes(
          tipo
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Tipo de seguimiento inválido"
        });

      }


      if (
        !resultadosPermitidos.includes(
          resultado
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Resultado de seguimiento inválido"
        });

      }


      if (!observacion) {

        return res.status(400).json({
          success: false,
          message:
            "La observación es obligatoria"
        });

      }


      const [result] =
        await pool.query(
          `
            INSERT INTO seguimiento_empleados
            (
              id_empleado,
              id_usuario_registro,
              fecha,
              tipo,
              motivo,
              observacion,
              accion_realizada,
              resultado,
              proxima_accion,
              fecha_proxima_accion
            )
            VALUES
            (
              ?,
              ?,
              COALESCE(?, NOW()),
              ?,
              ?,
              ?,
              ?,
              ?,
              ?,
              ?
            )
          `,
          [
            idEmpleado,
            req.user?.id_usuario ||
              null,
            fecha,
            tipo,
            motivo,
            observacion,
            accionRealizada,
            resultado,
            proximaAccion,
            fechaProximaAccion
          ]
        );


      const [rows] =
        await pool.query(
          `
            SELECT
              s.id_seguimiento,
              s.id_empleado,
              s.id_usuario_registro,
              s.fecha,
              s.tipo,
              s.motivo,
              s.observacion,
              s.accion_realizada,
              s.resultado,
              s.proxima_accion,
              s.fecha_proxima_accion,
              s.creado_en,
              s.actualizado_en,

              u.nombre AS usuario_registro

            FROM seguimiento_empleados s

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 s.id_usuario_registro

            WHERE s.id_seguimiento = ?

            LIMIT 1
          `,
          [
            result.insertId
          ]
        );


      return res.status(201).json({
        success: true,
        message:
          "Seguimiento laboral registrado correctamente",
        seguimiento:
          rows[0] || null
      });


    } catch (error) {

      console.error(
        "❌ Error registrando seguimiento laboral:",
        error
      );


      return res.status(500).json({
        success: false,
        message:
          "Error interno al registrar el seguimiento laboral",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined
      });

    }

  };


// ==================================================
// LISTAR SEGUIMIENTO DEL EMPLEADO
//
// GET /api/empleados/:id/seguimiento
// ==================================================

export const listarSeguimientoEmpleado =
  async (
    req,
    res
  ) => {

    try {

      const idEmpleado =
        Number(
          req.params.id
        );


      if (
        !Number.isInteger(
          idEmpleado
        ) ||
        idEmpleado <= 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "ID de empleado inválido"
        });

      }


      const acceso =
        await validarAccesoEmpleado(
          idEmpleado,
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


      const [seguimientos] =
        await pool.query(
          `
            SELECT
              s.id_seguimiento,
              s.id_empleado,
              s.id_usuario_registro,
              s.fecha,
              s.tipo,
              s.motivo,
              s.observacion,
              s.accion_realizada,
              s.resultado,
              s.proxima_accion,
              s.fecha_proxima_accion,
              s.creado_en,
              s.actualizado_en,

              u.nombre AS usuario_registro

            FROM seguimiento_empleados s

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 s.id_usuario_registro

            WHERE s.id_empleado = ?

            ORDER BY
              s.fecha DESC,
              s.id_seguimiento DESC
          `,
          [
            idEmpleado
          ]
        );


      return res.json({
        success: true,
        empleado:
          acceso.empleado,
        total:
          seguimientos.length,
        seguimientos
      });


    } catch (error) {

      console.error(
        "❌ Error listando seguimiento laboral:",
        error
      );


      return res.status(500).json({
        success: false,
        message:
          "Error interno al obtener el seguimiento laboral"
      });

    }

  };


// ==================================================
// ACTUALIZAR SEGUIMIENTO
//
// PUT /api/empleados/:id/seguimiento/:idSeguimiento
// ==================================================

export const actualizarSeguimientoEmpleado =
  async (
    req,
    res
  ) => {

    try {

      const idEmpleado =
        Number(
          req.params.id
        );

      const idSeguimiento =
        Number(
          req.params.idSeguimiento
        );


      if (
        !Number.isInteger(
          idEmpleado
        ) ||
        idEmpleado <= 0 ||
        !Number.isInteger(
          idSeguimiento
        ) ||
        idSeguimiento <= 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Datos de seguimiento inválidos"
        });

      }


      const acceso =
        await validarAccesoEmpleado(
          idEmpleado,
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


      const [existentes] =
        await pool.query(
          `
            SELECT
              id_seguimiento
            FROM seguimiento_empleados
            WHERE id_seguimiento = ?
              AND id_empleado = ?
            LIMIT 1
          `,
          [
            idSeguimiento,
            idEmpleado
          ]
        );


      if (!existentes.length) {

        return res.status(404).json({
          success: false,
          message:
            "Seguimiento no encontrado"
        });

      }


      const tiposPermitidos = [
        "general",
        "desempeno",
        "bienestar",
        "incidencia",
        "adaptacion",
        "seguimiento",
        "prevencion"
      ];


      const resultadosPermitidos = [
        "pendiente",
        "continua",
        "resuelto",
        "requiere_atencion",
        "canalizacion_sugerida"
      ];


      const campos = [];
      const valores = [];


      if (
        req.body?.fecha !==
        undefined
      ) {

        campos.push(
          "fecha = ?"
        );

        valores.push(
          req.body.fecha ||
          null
        );

      }


      if (
        req.body?.tipo !==
        undefined
      ) {

        const tipo =
          String(
            req.body.tipo || ""
          )
            .trim()
            .toLowerCase();


        if (
          !tiposPermitidos.includes(
            tipo
          )
        ) {

          return res.status(400).json({
            success: false,
            message:
              "Tipo de seguimiento inválido"
          });

        }


        campos.push(
          "tipo = ?"
        );

        valores.push(
          tipo
        );

      }


      if (
        req.body?.motivo !==
        undefined
      ) {

        campos.push(
          "motivo = ?"
        );

        valores.push(
          String(
            req.body.motivo || ""
          ).trim() || null
        );

      }


      if (
        req.body?.observacion !==
        undefined
      ) {

        const observacion =
          String(
            req.body.observacion || ""
          ).trim();


        if (!observacion) {

          return res.status(400).json({
            success: false,
            message:
              "La observación es obligatoria"
          });

        }


        campos.push(
          "observacion = ?"
        );

        valores.push(
          observacion
        );

      }


      if (
        req.body?.accion_realizada !==
        undefined
      ) {

        campos.push(
          "accion_realizada = ?"
        );

        valores.push(
          String(
            req.body.accion_realizada || ""
          ).trim() || null
        );

      }


      if (
        req.body?.resultado !==
        undefined
      ) {

        const resultado =
          String(
            req.body.resultado || ""
          )
            .trim()
            .toLowerCase();


        if (
          !resultadosPermitidos.includes(
            resultado
          )
        ) {

          return res.status(400).json({
            success: false,
            message:
              "Resultado de seguimiento inválido"
          });

        }


        campos.push(
          "resultado = ?"
        );

        valores.push(
          resultado
        );

      }


      if (
        req.body?.proxima_accion !==
        undefined
      ) {

        campos.push(
          "proxima_accion = ?"
        );

        valores.push(
          String(
            req.body.proxima_accion || ""
          ).trim() || null
        );

      }


      if (
        req.body?.fecha_proxima_accion !==
        undefined
      ) {

        campos.push(
          "fecha_proxima_accion = ?"
        );

        valores.push(
          req.body.fecha_proxima_accion ||
          null
        );

      }


      if (!campos.length) {

        return res.status(400).json({
          success: false,
          message:
            "No se enviaron datos para actualizar"
        });

      }


      valores.push(
        idSeguimiento,
        idEmpleado
      );


      await pool.query(
        `
          UPDATE seguimiento_empleados

          SET
            ${campos.join(", ")}

          WHERE id_seguimiento = ?
            AND id_empleado = ?
        `,
        valores
      );


      const [rows] =
        await pool.query(
          `
            SELECT
              s.id_seguimiento,
              s.id_empleado,
              s.id_usuario_registro,
              s.fecha,
              s.tipo,
              s.motivo,
              s.observacion,
              s.accion_realizada,
              s.resultado,
              s.proxima_accion,
              s.fecha_proxima_accion,
              s.creado_en,
              s.actualizado_en,

              u.nombre AS usuario_registro

            FROM seguimiento_empleados s

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 s.id_usuario_registro

            WHERE s.id_seguimiento = ?

            LIMIT 1
          `,
          [
            idSeguimiento
          ]
        );


      return res.json({
        success: true,
        message:
          "Seguimiento laboral actualizado correctamente",
        seguimiento:
          rows[0] || null
      });


    } catch (error) {

      console.error(
        "❌ Error actualizando seguimiento laboral:",
        error
      );


      return res.status(500).json({
        success: false,
        message:
          "Error interno al actualizar el seguimiento laboral"
      });

    }

  };


// ==================================================
// ELIMINAR SEGUIMIENTO
//
// DELETE /api/empleados/:id/seguimiento/:idSeguimiento
// ==================================================

export const eliminarSeguimientoEmpleado =
  async (
    req,
    res
  ) => {

    try {

      const idEmpleado =
        Number(
          req.params.id
        );

      const idSeguimiento =
        Number(
          req.params.idSeguimiento
        );


      if (
        !Number.isInteger(
          idEmpleado
        ) ||
        idEmpleado <= 0 ||
        !Number.isInteger(
          idSeguimiento
        ) ||
        idSeguimiento <= 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Datos de seguimiento inválidos"
        });

      }


      const acceso =
        await validarAccesoEmpleado(
          idEmpleado,
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


      const [result] =
        await pool.query(
          `
            DELETE FROM seguimiento_empleados

            WHERE id_seguimiento = ?
              AND id_empleado = ?
          `,
          [
            idSeguimiento,
            idEmpleado
          ]
        );


      if (
        result.affectedRows === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Seguimiento no encontrado"
        });

      }


      return res.json({
        success: true,
        message:
          "Seguimiento laboral eliminado correctamente"
      });


    } catch (error) {

      console.error(
        "❌ Error eliminando seguimiento laboral:",
        error
      );


      return res.status(500).json({
        success: false,
        message:
          "Error interno al eliminar el seguimiento laboral"
      });

    }

  };