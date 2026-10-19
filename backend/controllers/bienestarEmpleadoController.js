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
        "No tienes permiso para acceder al módulo de bienestar"
    };

  }


  let query = `
    SELECT
      id_empleado,
      id_prospecto,
      id_admin_padre,
      id_mirror,
      nombre,
      edad,
      sexo,
      correo,
      telefono,
      puesto,
      departamento,
      fecha_contratacion,
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
// AUXILIAR: VALIDAR TIPO
// ==================================================

const tiposPermitidos = [
  "seguimiento",
  "carga_trabajo",
  "adaptacion",
  "clima_laboral",
  "conflicto",
  "bienestar",
  "prevencion",
  "orientacion",
  "otro"
];


// ==================================================
// AUXILIAR: VALIDAR ORIGEN
// ==================================================

const origenesPermitidos = [
  "seguimiento",
  "evaluacion",
  "observacion_rh",
  "solicitud_empleado",
  "iniciativa_rh",
  "otro"
];


// ==================================================
// AUXILIAR: VALIDAR RESULTADO
// ==================================================

const resultadosPermitidos = [
  "pendiente",
  "en_seguimiento",
  "completada",
  "sin_cambio",
  "mejora_observada",
  "requiere_nueva_revision"
];


// ==================================================
// OBTENER PANEL DE BIENESTAR
//
// GET /api/empleados/:id/bienestar
// ==================================================

export const obtenerPanelBienestarEmpleado =
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


      // ==================================================
      // SEGUIMIENTOS RECIENTES
      // ==================================================

      const [seguimientos] =
        await pool.query(
          `
            SELECT
              s.id_seguimiento,
              s.fecha,
              s.tipo,
              s.motivo,
              s.observacion,
              s.accion_realizada,
              s.resultado,
              s.proxima_accion,
              s.fecha_proxima_accion,
              s.creado_en,

              u.nombre AS usuario_registro

            FROM seguimiento_empleados s

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 s.id_usuario_registro

            WHERE s.id_empleado = ?

            ORDER BY
              s.fecha DESC,
              s.id_seguimiento DESC

            LIMIT 10
          `,
          [
            idEmpleado
          ]
        );


      // ==================================================
      // EVALUACIONES RECIENTES
      // ==================================================

      const [evaluaciones] =
        await pool.query(
          `
            SELECT
              h.id_habilitacion,
              h.id_prueba_rh,
              h.motivo,
              h.tipo_evaluacion,
              h.estatus,
              h.fecha_habilitacion,
              h.fecha_inicio,
              h.fecha_completada,

              p.nombre AS prueba_nombre,
              p.categoria,
              p.version,

              r.id_resultado,
              r.puntaje_total,
              r.resultado_texto,
              r.interpretacion_laboral,
              r.fortalezas,
              r.areas_atencion,
              r.indicadores_prevencion,
              r.recomendaciones,
              r.fecha_resultado

            FROM pruebas_empleados_habilitadas h

            INNER JOIN pruebas_rh p
              ON p.id_prueba_rh =
                 h.id_prueba_rh

            LEFT JOIN resultados_prueba_empleado r
              ON r.id_habilitacion =
                 h.id_habilitacion

            WHERE h.id_empleado = ?

            ORDER BY
              h.fecha_habilitacion DESC,
              h.id_habilitacion DESC

            LIMIT 10
          `,
          [
            idEmpleado
          ]
        );


      // ==================================================
      // ACCIONES PREVENTIVAS RECIENTES
      // ==================================================

      const [acciones] =
        await pool.query(
          `
            SELECT
              a.id_accion,
              a.id_empleado,
              a.id_usuario_registro,
              a.fecha,
              a.tipo,
              a.origen,
              a.descripcion,
              a.accion_realizada,
              a.responsable,
              a.resultado,
              a.proxima_accion,
              a.fecha_proxima_revision,
              a.observaciones,
              a.creado_en,
              a.actualizado_en,

              u.nombre AS usuario_registro

            FROM acciones_preventivas_empleados a

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 a.id_usuario_registro

            WHERE a.id_empleado = ?

            ORDER BY
              a.fecha DESC,
              a.id_accion DESC

            LIMIT 10
          `,
          [
            idEmpleado
          ]
        );


      // ==================================================
      // PRÓXIMAS REVISIONES
      // ==================================================

      const [proximasRevisiones] =
        await pool.query(
          `
            SELECT
              'seguimiento' AS origen,
              id_seguimiento AS id_registro,
              proxima_accion AS descripcion,
              fecha_proxima_accion AS fecha

            FROM seguimiento_empleados

            WHERE id_empleado = ?
              AND fecha_proxima_accion IS NOT NULL

            UNION ALL

            SELECT
              'accion_preventiva' AS origen,
              id_accion AS id_registro,
              proxima_accion AS descripcion,
              fecha_proxima_revision AS fecha

            FROM acciones_preventivas_empleados

            WHERE id_empleado = ?
              AND fecha_proxima_revision IS NOT NULL

            ORDER BY fecha ASC

            LIMIT 20
          `,
          [
            idEmpleado,
            idEmpleado
          ]
        );


      // ==================================================
      // RESUMEN
      // ==================================================

      const [
        resumenSeguimientoRows
      ] =
        await pool.query(
          `
            SELECT
              COUNT(*) AS total,

              SUM(
                CASE
                  WHEN resultado =
                    'requiere_atencion'
                  THEN 1
                  ELSE 0
                END
              ) AS requiere_atencion,

              SUM(
                CASE
                  WHEN resultado =
                    'canalizacion_sugerida'
                  THEN 1
                  ELSE 0
                END
              ) AS canalizaciones_sugeridas

            FROM seguimiento_empleados

            WHERE id_empleado = ?
          `,
          [
            idEmpleado
          ]
        );


      const [
        resumenAccionesRows
      ] =
        await pool.query(
          `
            SELECT
              COUNT(*) AS total,

              SUM(
                CASE
                  WHEN resultado =
                    'pendiente'
                  THEN 1
                  ELSE 0
                END
              ) AS pendientes,

              SUM(
                CASE
                  WHEN resultado =
                    'en_seguimiento'
                  THEN 1
                  ELSE 0
                END
              ) AS en_seguimiento,

              SUM(
                CASE
                  WHEN resultado =
                    'requiere_nueva_revision'
                  THEN 1
                  ELSE 0
                END
              ) AS requieren_revision

            FROM acciones_preventivas_empleados

            WHERE id_empleado = ?
          `,
          [
            idEmpleado
          ]
        );


      const [
        resumenEvaluacionesRows
      ] =
        await pool.query(
          `
            SELECT
              COUNT(*) AS total,

              SUM(
                CASE
                  WHEN estatus =
                    'completada'
                  THEN 1
                  ELSE 0
                END
              ) AS completadas,

              SUM(
                CASE
                  WHEN estatus IN (
                    'habilitada',
                    'iniciada'
                  )
                  THEN 1
                  ELSE 0
                END
              ) AS pendientes

            FROM pruebas_empleados_habilitadas

            WHERE id_empleado = ?
          `,
          [
            idEmpleado
          ]
        );


      return res.json({
        success: true,

        empleado:
          acceso.empleado,

        resumen: {

          seguimientos: {
            total:
              Number(
                resumenSeguimientoRows[0]?.total ||
                0
              ),

            requiere_atencion:
              Number(
                resumenSeguimientoRows[0]?.requiere_atencion ||
                0
              ),

            canalizaciones_sugeridas:
              Number(
                resumenSeguimientoRows[0]?.canalizaciones_sugeridas ||
                0
              )
          },

          evaluaciones: {
            total:
              Number(
                resumenEvaluacionesRows[0]?.total ||
                0
              ),

            completadas:
              Number(
                resumenEvaluacionesRows[0]?.completadas ||
                0
              ),

            pendientes:
              Number(
                resumenEvaluacionesRows[0]?.pendientes ||
                0
              )
          },

          acciones_preventivas: {
            total:
              Number(
                resumenAccionesRows[0]?.total ||
                0
              ),

            pendientes:
              Number(
                resumenAccionesRows[0]?.pendientes ||
                0
              ),

            en_seguimiento:
              Number(
                resumenAccionesRows[0]?.en_seguimiento ||
                0
              ),

            requieren_revision:
              Number(
                resumenAccionesRows[0]?.requieren_revision ||
                0
              )
          }

        },

        seguimientos,
        evaluaciones,
        acciones_preventivas:
          acciones,
        proximas_revisiones:
          proximasRevisiones
      });


    } catch (error) {

      console.error(
        "❌ Error obteniendo panel de bienestar:",
        error
      );


      return res.status(500).json({
        success: false,
        message:
          "Error interno al obtener el panel de bienestar",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined
      });

    }

  };


// ==================================================
// LISTAR ACCIONES PREVENTIVAS
//
// GET /api/empleados/:id/bienestar/acciones
// ==================================================

export const listarAccionesPreventivasEmpleado =
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


      const [acciones] =
        await pool.query(
          `
            SELECT
              a.id_accion,
              a.id_empleado,
              a.id_usuario_registro,
              a.fecha,
              a.tipo,
              a.origen,
              a.descripcion,
              a.accion_realizada,
              a.responsable,
              a.resultado,
              a.proxima_accion,
              a.fecha_proxima_revision,
              a.observaciones,
              a.creado_en,
              a.actualizado_en,

              u.nombre AS usuario_registro

            FROM acciones_preventivas_empleados a

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 a.id_usuario_registro

            WHERE a.id_empleado = ?

            ORDER BY
              a.fecha DESC,
              a.id_accion DESC
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
          acciones.length,
        acciones
      });


    } catch (error) {

      console.error(
        "❌ Error listando acciones preventivas:",
        error
      );


      return res.status(500).json({
        success: false,
        message:
          "Error interno al obtener las acciones preventivas"
      });

    }

  };


// ==================================================
// REGISTRAR ACCIÓN PREVENTIVA
//
// POST /api/empleados/:id/bienestar/acciones
// ==================================================

export const registrarAccionPreventivaEmpleado =
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


      const tipo =
        String(
          req.body?.tipo ||
          "prevencion"
        )
          .trim()
          .toLowerCase();


      const origen =
        String(
          req.body?.origen ||
          "iniciativa_rh"
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


      const descripcion =
        String(
          req.body?.descripcion ||
          ""
        ).trim();


      const accionRealizada =
        String(
          req.body?.accion_realizada ||
          ""
        ).trim();


      const responsable =
        req.body?.responsable
          ? String(
              req.body.responsable
            ).trim()
          : null;


      const proximaAccion =
        req.body?.proxima_accion
          ? String(
              req.body.proxima_accion
            ).trim()
          : null;


      const observaciones =
        req.body?.observaciones
          ? String(
              req.body.observaciones
            ).trim()
          : null;


      const fecha =
        req.body?.fecha ||
        null;


      const fechaProximaRevision =
        req.body?.fecha_proxima_revision ||
        null;


      if (
        !tiposPermitidos.includes(
          tipo
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Tipo de acción preventiva inválido"
        });

      }


      if (
        !origenesPermitidos.includes(
          origen
        )
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Origen de la acción inválido"
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
            "Resultado de la acción inválido"
        });

      }


      if (!descripcion) {

        return res.status(400).json({
          success: false,
          message:
            "La descripción es obligatoria"
        });

      }


      if (!accionRealizada) {

        return res.status(400).json({
          success: false,
          message:
            "La acción realizada es obligatoria"
        });

      }


      const [result] =
        await pool.query(
          `
            INSERT INTO acciones_preventivas_empleados
            (
              id_empleado,
              id_usuario_registro,
              fecha,
              tipo,
              origen,
              descripcion,
              accion_realizada,
              responsable,
              resultado,
              proxima_accion,
              fecha_proxima_revision,
              observaciones
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
            origen,
            descripcion,
            accionRealizada,
            responsable,
            resultado,
            proximaAccion,
            fechaProximaRevision,
            observaciones
          ]
        );


      const [rows] =
        await pool.query(
          `
            SELECT
              a.*,
              u.nombre AS usuario_registro

            FROM acciones_preventivas_empleados a

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 a.id_usuario_registro

            WHERE a.id_accion = ?

            LIMIT 1
          `,
          [
            result.insertId
          ]
        );


      return res.status(201).json({
        success: true,
        message:
          "Acción preventiva registrada correctamente",
        accion:
          rows[0] || null
      });


    } catch (error) {

      console.error(
        "❌ Error registrando acción preventiva:",
        error
      );


      return res.status(500).json({
        success: false,
        message:
          "Error interno al registrar la acción preventiva",

        error:
          process.env.NODE_ENV ===
          "development"
            ? error.message
            : undefined
      });

    }

  };


// ==================================================
// ACTUALIZAR ACCIÓN PREVENTIVA
//
// PUT
// /api/empleados/:id/bienestar/acciones/:idAccion
// ==================================================

export const actualizarAccionPreventivaEmpleado =
  async (
    req,
    res
  ) => {

    try {

      const idEmpleado =
        Number(
          req.params.id
        );

      const idAccion =
        Number(
          req.params.idAccion
        );


      if (
        !Number.isInteger(
          idEmpleado
        ) ||
        idEmpleado <= 0 ||
        !Number.isInteger(
          idAccion
        ) ||
        idAccion <= 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Datos de acción inválidos"
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
            SELECT id_accion

            FROM acciones_preventivas_empleados

            WHERE id_accion = ?
              AND id_empleado = ?

            LIMIT 1
          `,
          [
            idAccion,
            idEmpleado
          ]
        );


      if (!existentes.length) {

        return res.status(404).json({
          success: false,
          message:
            "Acción preventiva no encontrada"
        });

      }


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
            req.body.tipo ||
            ""
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
              "Tipo de acción inválido"
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
        req.body?.origen !==
        undefined
      ) {

        const origen =
          String(
            req.body.origen ||
            ""
          )
            .trim()
            .toLowerCase();


        if (
          !origenesPermitidos.includes(
            origen
          )
        ) {

          return res.status(400).json({
            success: false,
            message:
              "Origen de acción inválido"
          });

        }


        campos.push(
          "origen = ?"
        );

        valores.push(
          origen
        );

      }


      if (
        req.body?.descripcion !==
        undefined
      ) {

        const descripcion =
          String(
            req.body.descripcion ||
            ""
          ).trim();


        if (!descripcion) {

          return res.status(400).json({
            success: false,
            message:
              "La descripción es obligatoria"
          });

        }


        campos.push(
          "descripcion = ?"
        );

        valores.push(
          descripcion
        );

      }


      if (
        req.body?.accion_realizada !==
        undefined
      ) {

        const accionRealizada =
          String(
            req.body.accion_realizada ||
            ""
          ).trim();


        if (!accionRealizada) {

          return res.status(400).json({
            success: false,
            message:
              "La acción realizada es obligatoria"
          });

        }


        campos.push(
          "accion_realizada = ?"
        );

        valores.push(
          accionRealizada
        );

      }


      if (
        req.body?.responsable !==
        undefined
      ) {

        campos.push(
          "responsable = ?"
        );

        valores.push(
          String(
            req.body.responsable ||
            ""
          ).trim() ||
          null
        );

      }


      if (
        req.body?.resultado !==
        undefined
      ) {

        const resultado =
          String(
            req.body.resultado ||
            ""
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
              "Resultado de acción inválido"
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
            req.body.proxima_accion ||
            ""
          ).trim() ||
          null
        );

      }


      if (
        req.body?.fecha_proxima_revision !==
        undefined
      ) {

        campos.push(
          "fecha_proxima_revision = ?"
        );

        valores.push(
          req.body.fecha_proxima_revision ||
          null
        );

      }


      if (
        req.body?.observaciones !==
        undefined
      ) {

        campos.push(
          "observaciones = ?"
        );

        valores.push(
          String(
            req.body.observaciones ||
            ""
          ).trim() ||
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
        idAccion,
        idEmpleado
      );


      await pool.query(
        `
          UPDATE acciones_preventivas_empleados

          SET
            ${campos.join(", ")}

          WHERE id_accion = ?
            AND id_empleado = ?
        `,
        valores
      );


      const [rows] =
        await pool.query(
          `
            SELECT
              a.*,
              u.nombre AS usuario_registro

            FROM acciones_preventivas_empleados a

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 a.id_usuario_registro

            WHERE a.id_accion = ?

            LIMIT 1
          `,
          [
            idAccion
          ]
        );


      return res.json({
        success: true,
        message:
          "Acción preventiva actualizada correctamente",
        accion:
          rows[0] || null
      });


    } catch (error) {

      console.error(
        "❌ Error actualizando acción preventiva:",
        error
      );


      return res.status(500).json({
        success: false,
        message:
          "Error interno al actualizar la acción preventiva"
      });

    }

  };


// ==================================================
// ELIMINAR ACCIÓN PREVENTIVA
//
// DELETE
// /api/empleados/:id/bienestar/acciones/:idAccion
// ==================================================

export const eliminarAccionPreventivaEmpleado =
  async (
    req,
    res
  ) => {

    try {

      const idEmpleado =
        Number(
          req.params.id
        );

      const idAccion =
        Number(
          req.params.idAccion
        );


      if (
        !Number.isInteger(
          idEmpleado
        ) ||
        idEmpleado <= 0 ||
        !Number.isInteger(
          idAccion
        ) ||
        idAccion <= 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Datos de acción inválidos"
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
            DELETE FROM acciones_preventivas_empleados

            WHERE id_accion = ?
              AND id_empleado = ?
          `,
          [
            idAccion,
            idEmpleado
          ]
        );


      if (
        result.affectedRows === 0
      ) {

        return res.status(404).json({
          success: false,
          message:
            "Acción preventiva no encontrada"
        });

      }


      return res.json({
        success: true,
        message:
          "Acción preventiva eliminada correctamente"
      });


    } catch (error) {

      console.error(
        "❌ Error eliminando acción preventiva:",
        error
      );


      return res.status(500).json({
        success: false,
        message:
          "Error interno al eliminar la acción preventiva"
      });

    }

  };