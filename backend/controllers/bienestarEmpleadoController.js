import pool from "../config/database.js";


// ==================================================
// AUXILIARES
// ==================================================

const normalizar = valor =>
  valor
    ? String(valor)
        .trim()
        .toLowerCase()
    : "";

const texto = valor => {

  if (
    valor === undefined ||
    valor === null
  ) {
    return null;
  }

  const resultado =
    String(valor).trim();

  return resultado || null;
};


// ==================================================
// CONTEXTO REAL DEL USUARIO
// ==================================================

const obtenerContextoUsuario =
  async (
    user,
    connection = pool
  ) => {

    const idUsuario =
      Number(
        user?.id_usuario
      ) || null;

    if (!idUsuario) {

      return {
        idUsuario: null,
        tipoAdmin: "",
        area: "",
        rol: "",
        idAdminPadre: null,
        idOrganizacion: null,
        perfilIndependiente: "",
        estadoOrganizacion: ""
      };

    }

    const [rows] =
      await connection.query(
        `
          SELECT
            u.id_usuario,
            u.tipo_admin,
            u.area,
            u.rol,
            u.id_admin_padre,
            u.id_organizacion,

            o.perfil_independiente,
            o.estado AS estado_organizacion

          FROM usuarios u

          LEFT JOIN organizaciones o
            ON o.id_organizacion =
               u.id_organizacion

          WHERE
            u.id_usuario = ?

          LIMIT 1
        `,
        [
          idUsuario
        ]
      );

    if (!rows.length) {

      return {

        idUsuario,

        tipoAdmin:
          normalizar(
            user?.tipo_admin
          ),

        area:
          normalizar(
            user?.area
          ),

        rol:
          normalizar(
            user?.rol
          ),

        idAdminPadre:
          Number(
            user?.id_admin_padre
          ) || null,

        idOrganizacion:
          Number(
            user?.id_organizacion
          ) || null,

        perfilIndependiente:
          normalizar(
            user?.perfil_independiente
          ),

        estadoOrganizacion:
          normalizar(
            user?.estado_organizacion
          )
      };

    }

    const usuario =
      rows[0];

    return {

      idUsuario:
        Number(
          usuario.id_usuario
        ) || null,

      tipoAdmin:
        normalizar(
          usuario.tipo_admin
        ),

      area:
        normalizar(
          usuario.area
        ),

      rol:
        normalizar(
          usuario.rol
        ),

      idAdminPadre:
        Number(
          usuario.id_admin_padre
        ) || null,

      idOrganizacion:
        Number(
          usuario.id_organizacion
        ) || null,

      perfilIndependiente:
        normalizar(
          usuario.perfil_independiente
        ),

      estadoOrganizacion:
        normalizar(
          usuario.estado_organizacion
        )
    };

  };


// ==================================================
// VALIDAR ACCESO
// ==================================================

const validarAccesoEmpleado =
  async (
    idEmpleado,
    user,
    connection = pool
  ) => {

    const contexto =
      await obtenerContextoUsuario(
        user,
        connection
      );

    if (!contexto.idUsuario) {

      return {
        ok: false,
        status: 401,
        message:
          "No se pudo identificar al usuario"
      };

    }

    const esMaster =
      contexto.tipoAdmin ===
      "master";

    const esAdminRH =
      contexto.tipoAdmin ===
        "normal" &&
      contexto.area ===
        "rh";

    const esUsuarioRH =
      contexto.rol ===
        "rh" &&
      contexto.area ===
        "rh";

    const esIndependienteRH =
      contexto.rol ===
        "independiente" &&
      contexto.area ===
        "independiente" &&
      contexto.perfilIndependiente ===
        "rh" &&
      contexto.estadoOrganizacion ===
        "activa";

    if (
      !esMaster &&
      !esAdminRH &&
      !esUsuarioRH &&
      !esIndependienteRH
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
        e.id_empleado,
        e.id_prospecto,
        e.id_admin_padre,
        e.id_usuario_responsable,
        e.id_mirror,
        e.nombre,
        e.edad,
        e.sexo,
        e.correo,
        e.telefono,
        e.puesto,
        e.departamento,
        e.fecha_contratacion,
        e.estatus,

        ur.nombre
          AS responsable_actual

      FROM empleados e

      LEFT JOIN usuarios ur
        ON ur.id_usuario =
           e.id_usuario_responsable

      WHERE
        e.id_empleado = ?
    `;

    const params = [
      idEmpleado
    ];

    // ==================================================
    // ADMIN RH
    // ==================================================

    if (esAdminRH) {

      query += `
        AND
        (
          e.id_admin_padre = ?

          OR

          (
            e.id_usuario_responsable IS NULL

            AND e.id_admin_padre IN
            (
              SELECT
                u.id_usuario

              FROM usuarios u

              WHERE
                u.id_admin_padre = ?

                AND u.rol = 'rh'

                AND LOWER(
                  TRIM(
                    COALESCE(
                      u.area,
                      ''
                    )
                  )
                ) = 'rh'
            )
          )
        )
      `;

      params.push(
        contexto.idUsuario,
        contexto.idUsuario
      );

    }

    // ==================================================
    // RH / INDEPENDIENTE RH
    // ==================================================

    else if (
      esUsuarioRH ||
      esIndependienteRH
    ) {

      query += `
        AND
        (
          e.id_usuario_responsable = ?

          OR

          (
            e.id_usuario_responsable IS NULL
            AND e.id_admin_padre = ?
          )
        )
      `;

      params.push(
        contexto.idUsuario,
        contexto.idUsuario
      );

    }

    query += `
      LIMIT 1
    `;

    const [rows] =
      await connection.query(
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

      contexto: {
        ...contexto,
        esMaster,
        esAdminRH,
        esUsuarioRH,
        esIndependienteRH
      },

      empleado:
        rows[0]
    };

  };


// ==================================================
// VALORES PERMITIDOS
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

const origenesPermitidos = [
  "seguimiento",
  "evaluacion",
  "observacion_rh",
  "observacion",
  "solicitud_empleado",
  "solicitud_supervisor",
  "iniciativa_rh",
  "otro"
];

const resultadosPermitidos = [
  "pendiente",
  "en_revision",
  "en_seguimiento",
  "sin_cambio",
  "mejora",
  "mejora_observada",
  "requiere_atencion",
  "canalizacion_sugerida",
  "completado",
  "completada",
  "requiere_nueva_revision"
];

const estadosPermitidos = [
  "abierto",
  "en_seguimiento",
  "cerrado"
];


// ==================================================
// PANEL BIENESTAR
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

        return res
          .status(400)
          .json({
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
      // SEGUIMIENTOS
      // ==================================================

      const [seguimientos] =
        await pool.query(
          `
            SELECT
              s.id_seguimiento,
              s.fecha,
              s.tipo,
              s.prioridad,
              s.motivo,
              s.observacion,
              s.accion_realizada,
              s.resultado,
              s.estado,
              s.proxima_accion,
              s.fecha_proxima_accion,
              s.creado_en,

              u.nombre
                AS usuario_registro

            FROM seguimiento_empleados s

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 s.id_usuario_registro

            WHERE
              s.id_empleado = ?

              AND s.estado <>
                  'anulado'

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
      // EVALUACIONES
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

              p.nombre
                AS prueba_nombre,

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

            WHERE
              h.id_empleado = ?

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
      // ACCIONES PREVENTIVAS
      // ==================================================

      const [acciones] =
        await pool.query(
          `
            SELECT
              a.*,

              ur.nombre
                AS usuario_registro,

              ua.nombre
                AS usuario_anulacion,

              uc.nombre
                AS usuario_cierre

            FROM acciones_preventivas_empleados a

            LEFT JOIN usuarios ur
              ON ur.id_usuario =
                 a.id_usuario_registro

            LEFT JOIN usuarios ua
              ON ua.id_usuario =
                 a.id_usuario_anulacion

            LEFT JOIN usuarios uc
              ON uc.id_usuario =
                 a.id_usuario_cierre

            WHERE
              a.id_empleado = ?

              AND a.estado <>
                  'anulada'

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
              'seguimiento'
                AS origen,

              id_seguimiento
                AS id_registro,

              proxima_accion
                AS descripcion,

              fecha_proxima_accion
                AS fecha

            FROM seguimiento_empleados

            WHERE
              id_empleado = ?

              AND estado <>
                  'anulado'

              AND fecha_proxima_accion
                  IS NOT NULL

              AND fecha_proxima_accion >=
                  NOW()

            UNION ALL

            SELECT
              'accion_preventiva'
                AS origen,

              id_accion
                AS id_registro,

              proxima_accion
                AS descripcion,

              fecha_proxima_revision
                AS fecha

            FROM acciones_preventivas_empleados

            WHERE
              id_empleado = ?

              AND estado IN (
                'abierto',
                'en_seguimiento',
                'activa'
              )

              AND fecha_proxima_revision
                  IS NOT NULL

              AND fecha_proxima_revision >=
                  NOW()

            ORDER BY
              fecha ASC

            LIMIT 20
          `,
          [
            idEmpleado,
            idEmpleado
          ]
        );

      // ==================================================
      // RESUMEN SEGUIMIENTO
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

            WHERE
              id_empleado = ?

              AND estado <>
                  'anulado'
          `,
          [
            idEmpleado
          ]
        );

      // ==================================================
      // RESUMEN ACCIONES
      // ==================================================

      const [
        resumenAccionesRows
      ] =
        await pool.query(
          `
            SELECT
              COUNT(*) AS total,

              SUM(
                CASE
                  WHEN estado IN (
                    'abierto',
                    'activa'
                  )
                  THEN 1
                  ELSE 0
                END
              ) AS abiertas,

              SUM(
                CASE
                  WHEN estado =
                    'en_seguimiento'
                  THEN 1
                  ELSE 0
                END
              ) AS en_seguimiento,

              SUM(
                CASE
                  WHEN estado =
                    'cerrado'
                  THEN 1
                  ELSE 0
                END
              ) AS cerradas,

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

            FROM acciones_preventivas_empleados

            WHERE
              id_empleado = ?

              AND estado <>
                  'anulada'
          `,
          [
            idEmpleado
          ]
        );

      // ==================================================
      // RESUMEN EVALUACIONES
      // ==================================================

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

            WHERE
              id_empleado = ?
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
                resumenSeguimientoRows[0]
                  ?.total || 0
              ),

            requiere_atencion:
              Number(
                resumenSeguimientoRows[0]
                  ?.requiere_atencion || 0
              ),

            canalizaciones_sugeridas:
              Number(
                resumenSeguimientoRows[0]
                  ?.canalizaciones_sugeridas || 0
              )
          },

          evaluaciones: {

            total:
              Number(
                resumenEvaluacionesRows[0]
                  ?.total || 0
              ),

            completadas:
              Number(
                resumenEvaluacionesRows[0]
                  ?.completadas || 0
              ),

            pendientes:
              Number(
                resumenEvaluacionesRows[0]
                  ?.pendientes || 0
              ),

            requiere_atencion:
              Number(
                resumenAccionesRows[0]
                  ?.requiere_atencion || 0
              ),

            canalizaciones_sugeridas:
              Number(
                resumenAccionesRows[0]
                  ?.canalizaciones_sugeridas || 0
              )
          },

          acciones_preventivas: {

            total:
              Number(
                resumenAccionesRows[0]
                  ?.total || 0
              ),

            abiertas:
              Number(
                resumenAccionesRows[0]
                  ?.abiertas || 0
              ),

            en_seguimiento:
              Number(
                resumenAccionesRows[0]
                  ?.en_seguimiento || 0
              ),

            cerradas:
              Number(
                resumenAccionesRows[0]
                  ?.cerradas || 0
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

      return res
        .status(500)
        .json({

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
// LISTAR ACCIONES
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

        return res
          .status(400)
          .json({
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
              a.*,

              ur.nombre
                AS usuario_registro,

              ua.nombre
                AS usuario_anulacion,

              uc.nombre
                AS usuario_cierre

            FROM acciones_preventivas_empleados a

            LEFT JOIN usuarios ur
              ON ur.id_usuario =
                 a.id_usuario_registro

            LEFT JOIN usuarios ua
              ON ua.id_usuario =
                 a.id_usuario_anulacion

            LEFT JOIN usuarios uc
              ON uc.id_usuario =
                 a.id_usuario_cierre

            WHERE
              a.id_empleado = ?

            ORDER BY
              a.fecha DESC,
              a.id_accion DESC
          `,
          [
            idEmpleado
          ]
        );

      const activas =
        acciones.filter(
          item =>
            item.estado !==
            "anulada"
        );

      const anuladas =
        acciones.filter(
          item =>
            item.estado ===
            "anulada"
        );

      return res.json({

        success: true,

        empleado:
          acceso.empleado,

        total:
          acciones.length,

        activas:
          activas.length,

        anuladas:
          anuladas.length,

        acciones
      });

    } catch (error) {

      console.error(
        "❌ Error listando acciones preventivas:",
        error
      );

      return res
        .status(500)
        .json({

          success: false,

          message:
            "Error interno al obtener las acciones preventivas"
        });
    }
  };


// ==================================================
// REGISTRAR ACCIÓN
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

        return res
          .status(400)
          .json({
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
        normalizar(
          req.body?.tipo ||
          "prevencion"
        );

      const origen =
        normalizar(
          req.body?.origen ||
          "iniciativa_rh"
        );

      const resultado =
        normalizar(
          req.body?.resultado ||
          "pendiente"
        );

      const estado =
        normalizar(
          req.body?.estado ||
          "abierto"
        );

      const descripcion =
        texto(
          req.body?.descripcion
        );

      const accionRealizada =
        texto(
          req.body?.accion_realizada
        );

      const responsable =
        texto(
          req.body?.responsable
        );

      const proximaAccion =
        texto(
          req.body?.proxima_accion
        );

      const observaciones =
        texto(
          req.body?.observaciones
        );

      const fecha =
        req.body?.fecha ||
        null;

      const fechaProximaRevision =
        req.body
          ?.fecha_proxima_revision ||
        null;

      if (
        !tiposPermitidos.includes(
          tipo
        )
      ) {

        return res
          .status(400)
          .json({
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

        return res
          .status(400)
          .json({
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

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Resultado de la acción inválido"
          });
      }

      if (
        !estadosPermitidos.includes(
          estado
        )
      ) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Estado de la acción inválido"
          });
      }

      if (!descripcion) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "La descripción es obligatoria"
          });
      }

      if (!accionRealizada) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "La acción realizada es obligatoria"
          });
      }

      const cerrar =
        estado ===
        "cerrado";

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
              estado,
              proxima_accion,
              fecha_proxima_revision,
              fecha_cierre,
              id_usuario_cierre,
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
              ?,
              ?,
              ?,
              ?
            )
          `,
          [
            idEmpleado,

            acceso.contexto
              .idUsuario,

            fecha,
            tipo,
            origen,
            descripcion,
            accionRealizada,
            responsable,
            resultado,
            estado,
            proximaAccion,
            fechaProximaRevision,

            cerrar
              ? new Date()
              : null,

            cerrar
              ? acceso.contexto
                  .idUsuario
              : null,

            observaciones
          ]
        );

      const [rows] =
        await pool.query(
          `
            SELECT
              a.*,

              u.nombre
                AS usuario_registro

            FROM acciones_preventivas_empleados a

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 a.id_usuario_registro

            WHERE
              a.id_accion = ?

            LIMIT 1
          `,
          [
            result.insertId
          ]
        );

      return res
        .status(201)
        .json({

          success: true,

          message:
            cerrar
              ? "Acción preventiva registrada y cerrada correctamente"
              : "Acción preventiva registrada correctamente",

          accion:
            rows[0] || null
        });

    } catch (error) {

      console.error(
        "❌ Error registrando acción preventiva:",
        error
      );

      return res
        .status(500)
        .json({

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
// ACTUALIZAR ACCIÓN
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

        return res
          .status(400)
          .json({
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
            SELECT
              *

            FROM acciones_preventivas_empleados

            WHERE
              id_accion = ?
              AND id_empleado = ?

            LIMIT 1
          `,
          [
            idAccion,
            idEmpleado
          ]
        );

      if (!existentes.length) {

        return res
          .status(404)
          .json({
            success: false,
            message:
              "Acción preventiva no encontrada"
          });
      }

      const actual =
        existentes[0];

      if (
        actual.estado ===
        "anulada"
      ) {

        return res
          .status(409)
          .json({
            success: false,
            message:
              "Una acción preventiva anulada ya no puede modificarse"
          });
      }

      if (
        actual.estado ===
        "cerrado"
      ) {

        return res
          .status(409)
          .json({
            success: false,
            message:
              "Una acción preventiva cerrada ya no puede modificarse"
          });
      }

      const campos = [];
      const valores = [];

      const agregar =
        (
          campo,
          valor
        ) => {

          campos.push(
            `${campo} = ?`
          );

          valores.push(
            valor
          );
        };

      if (
        req.body?.fecha !==
        undefined
      ) {

        agregar(
          "fecha",
          req.body.fecha ||
          null
        );
      }

      if (
        req.body?.tipo !==
        undefined
      ) {

        const valor =
          normalizar(
            req.body.tipo
          );

        if (
          !tiposPermitidos.includes(
            valor
          )
        ) {

          return res
            .status(400)
            .json({
              success: false,
              message:
                "Tipo de acción inválido"
            });
        }

        agregar(
          "tipo",
          valor
        );
      }

      if (
        req.body?.origen !==
        undefined
      ) {

        const valor =
          normalizar(
            req.body.origen
          );

        if (
          !origenesPermitidos.includes(
            valor
          )
        ) {

          return res
            .status(400)
            .json({
              success: false,
              message:
                "Origen de acción inválido"
            });
        }

        agregar(
          "origen",
          valor
        );
      }

      if (
        req.body?.descripcion !==
        undefined
      ) {

        const valor =
          texto(
            req.body.descripcion
          );

        if (!valor) {

          return res
            .status(400)
            .json({
              success: false,
              message:
                "La descripción es obligatoria"
            });
        }

        agregar(
          "descripcion",
          valor
        );
      }

      if (
        req.body?.accion_realizada !==
        undefined
      ) {

        const valor =
          texto(
            req.body
              .accion_realizada
          );

        if (!valor) {

          return res
            .status(400)
            .json({
              success: false,
              message:
                "La acción realizada es obligatoria"
            });
        }

        agregar(
          "accion_realizada",
          valor
        );
      }

      if (
        req.body?.responsable !==
        undefined
      ) {

        agregar(
          "responsable",
          texto(
            req.body.responsable
          )
        );
      }

      if (
        req.body?.resultado !==
        undefined
      ) {

        const valor =
          normalizar(
            req.body.resultado
          );

        if (
          !resultadosPermitidos.includes(
            valor
          )
        ) {

          return res
            .status(400)
            .json({
              success: false,
              message:
                "Resultado de acción inválido"
            });
        }

        agregar(
          "resultado",
          valor
        );
      }

      if (
        req.body?.estado !==
        undefined
      ) {

        const valor =
          normalizar(
            req.body.estado
          );

        if (
          !estadosPermitidos.includes(
            valor
          )
        ) {

          return res
            .status(400)
            .json({
              success: false,
              message:
                "Estado de acción inválido"
            });
        }

        agregar(
          "estado",
          valor
        );

        if (
          valor ===
          "cerrado"
        ) {

          agregar(
            "fecha_cierre",
            new Date()
          );

          agregar(
            "id_usuario_cierre",
            acceso.contexto
              .idUsuario
          );
        }
      }

      if (
        req.body?.proxima_accion !==
        undefined
      ) {

        agregar(
          "proxima_accion",
          texto(
            req.body
              .proxima_accion
          )
        );
      }

      if (
        req.body
          ?.fecha_proxima_revision !==
        undefined
      ) {

        agregar(
          "fecha_proxima_revision",
          req.body
            .fecha_proxima_revision ||
          null
        );
      }

      if (
        req.body?.observaciones !==
        undefined
      ) {

        agregar(
          "observaciones",
          texto(
            req.body
              .observaciones
          )
        );
      }

      if (!campos.length) {

        return res
          .status(400)
          .json({
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

          WHERE
            id_accion = ?
            AND id_empleado = ?
        `,
        valores
      );

      const [rows] =
        await pool.query(
          `
            SELECT
              a.*,

              ur.nombre
                AS usuario_registro,

              uc.nombre
                AS usuario_cierre

            FROM acciones_preventivas_empleados a

            LEFT JOIN usuarios ur
              ON ur.id_usuario =
                 a.id_usuario_registro

            LEFT JOIN usuarios uc
              ON uc.id_usuario =
                 a.id_usuario_cierre

            WHERE
              a.id_accion = ?

            LIMIT 1
          `,
          [
            idAccion
          ]
        );

      return res.json({

        success: true,

        message:
          req.body?.estado ===
          "cerrado"
            ? "Acción preventiva cerrada correctamente"
            : "Acción preventiva actualizada correctamente",

        accion:
          rows[0] || null
      });

    } catch (error) {

      console.error(
        "❌ Error actualizando acción preventiva:",
        error
      );

      return res
        .status(500)
        .json({

          success: false,

          message:
            "Error interno al actualizar la acción preventiva",

          error:
            process.env.NODE_ENV ===
            "development"
              ? error.message
              : undefined
        });
    }
  };


// ==================================================
// ANULAR ACCIÓN
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

        return res
          .status(400)
          .json({
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

      const motivoAnulacion =
        texto(
          req.body
            ?.motivo_anulacion
        );

      if (!motivoAnulacion) {

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Debes indicar el motivo de la anulación"
          });
      }

      const [acciones] =
        await pool.query(
          `
            SELECT
              id_accion,
              estado

            FROM acciones_preventivas_empleados

            WHERE
              id_accion = ?
              AND id_empleado = ?

            LIMIT 1
          `,
          [
            idAccion,
            idEmpleado
          ]
        );

      if (!acciones.length) {

        return res
          .status(404)
          .json({
            success: false,
            message:
              "Acción preventiva no encontrada"
          });
      }

      if (
        acciones[0].estado ===
        "anulada"
      ) {

        return res
          .status(409)
          .json({
            success: false,
            message:
              "La acción preventiva ya se encuentra anulada"
          });
      }

      await pool.query(
        `
          UPDATE acciones_preventivas_empleados

          SET
            estado =
              'anulada',

            motivo_anulacion = ?,

            fecha_anulacion =
              NOW(),

            id_usuario_anulacion = ?

          WHERE
            id_accion = ?
            AND id_empleado = ?
        `,
        [
          motivoAnulacion,

          acceso.contexto
            .idUsuario,

          idAccion,
          idEmpleado
        ]
      );

      return res.json({

        success: true,

        message:
          "Acción preventiva anulada correctamente. El registro se conserva en el expediente."
      });

    } catch (error) {

      console.error(
        "❌ Error anulando acción preventiva:",
        error
      );

      return res
        .status(500)
        .json({

          success: false,

          message:
            "Error interno al anular la acción preventiva"
        });
    }
  };