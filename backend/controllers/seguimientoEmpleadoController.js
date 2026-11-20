import pool from "../config/database.js";

// ==================================================
// AUXILIARES
// ==================================================

const normalizar = valor =>
  valor
    ? String(valor).trim().toLowerCase()
    : "";

const texto = valor => {
  if (
    valor === undefined ||
    valor === null
  ) {
    return null;
  }

  const limpio =
    String(valor).trim();

  return limpio || null;
};

const serializar = valor => {
  try {
    return JSON.stringify(
      valor ?? null
    );
  } catch {
    return null;
  }
};

// ==================================================
// CONTEXTO REAL DEL USUARIO
// ==================================================

const obtenerContextoUsuario = async (
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
      [idUsuario]
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

  const u =
    rows[0];

  return {
    idUsuario:
      Number(
        u.id_usuario
      ) || null,

    tipoAdmin:
      normalizar(
        u.tipo_admin
      ),

    area:
      normalizar(
        u.area
      ),

    rol:
      normalizar(
        u.rol
      ),

    idAdminPadre:
      Number(
        u.id_admin_padre
      ) || null,

    idOrganizacion:
      Number(
        u.id_organizacion
      ) || null,

    perfilIndependiente:
      normalizar(
        u.perfil_independiente
      ),

    estadoOrganizacion:
      normalizar(
        u.estado_organizacion
      )
  };
};

// ==================================================
// VALIDAR ACCESO AL EMPLEADO
//
// MASTER:
// todos.
//
// ADMIN RH:
// toda su organización.
//
// USUARIO RH:
// asignados actuales +
// registros antiguos.
//
// INDEPENDIENTE RH:
// únicamente sus propios empleados.
// ==================================================

const validarAccesoEmpleado = async (
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
        "No tienes permiso para acceder al seguimiento laboral"
    };
  }

  let query = `
    SELECT
      e.id_empleado,
      e.id_admin_padre,
      e.id_usuario_responsable,
      e.id_mirror,
      e.nombre,
      e.puesto,
      e.departamento,
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

  // ADMIN RH

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

  // USUARIO RH / INDEPENDIENTE RH

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
    contexto,
    esMaster,
    esAdminRH,
    esUsuarioRH,
    esIndependienteRH,
    empleado:
      rows[0]
  };
};

// ==================================================
// VALORES PERMITIDOS
// ==================================================

const tiposPermitidos = [
  "general",
  "desempeno",
  "bienestar",
  "incidencia",
  "adaptacion",
  "seguimiento",
  "prevencion"
];

const prioridadesPermitidas = [
  "baja",
  "media",
  "alta"
];

const resultadosPermitidos = [
  "pendiente",
  "continua",
  "resuelto",
  "requiere_atencion",
  "canalizacion_sugerida"
];

const estadosPermitidos = [
  "abierto",
  "en_seguimiento",
  "cerrado"
];

// ==================================================
// OBTENER SEGUIMIENTO
// ==================================================

const obtenerSeguimientoPorId = async (
  idSeguimiento,
  idEmpleado,
  connection = pool
) => {
  const [rows] =
    await connection.query(
      `
        SELECT
          *
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

  return rows[0] || null;
};

// ==================================================
// AUDITORÍA
// ==================================================

const registrarAuditoria = async (
  {
    idSeguimiento,
    idEmpleado,
    idUsuario,
    accion,
    anterior = null,
    nuevo = null,
    motivo = null
  },
  connection = pool
) => {
  await connection.query(
    `
      INSERT INTO auditoria_seguimiento_empleados
      (
        id_seguimiento,
        id_empleado,
        id_usuario,
        accion,
        datos_anteriores,
        datos_nuevos,
        motivo,
        fecha
      )

      VALUES
      (
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
      idSeguimiento,
      idEmpleado,
      idUsuario || null,
      accion,
      serializar(anterior),
      serializar(nuevo),
      motivo
    ]
  );
};

// ==================================================
// SELECT COMPLETO
// ==================================================

const consultarSeguimientoCompleto = async (
  idSeguimiento,
  connection = pool
) => {
  const [rows] =
    await connection.query(
      `
        SELECT
          s.*,

          u.nombre
            AS usuario_registro,

          uc.nombre
            AS usuario_cierre,

          ua.nombre
            AS usuario_anulacion

        FROM seguimiento_empleados s

        LEFT JOIN usuarios u
          ON u.id_usuario =
             s.id_usuario_registro

        LEFT JOIN usuarios uc
          ON uc.id_usuario =
             s.id_usuario_cierre

        LEFT JOIN usuarios ua
          ON ua.id_usuario =
             s.id_usuario_anulacion

        WHERE
          s.id_seguimiento = ?

        LIMIT 1
      `,
      [
        idSeguimiento
      ]
    );

  return rows[0] || null;
};

// ==================================================
// REGISTRAR SEGUIMIENTO
//
// POST /api/empleados/:id/seguimiento
// ==================================================

export const registrarSeguimientoEmpleado =
  async (
    req,
    res
  ) => {
    let connection;

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

      connection =
        await pool.getConnection();

      await connection
        .beginTransaction();

      const acceso =
        await validarAccesoEmpleado(
          idEmpleado,
          req.user,
          connection
        );

      if (!acceso.ok) {
        await connection.rollback();

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
          "seguimiento"
        );

      const prioridad =
        normalizar(
          req.body?.prioridad ||
          "media"
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

      const observacion =
        texto(
          req.body?.observacion
        );

      if (
        !tiposPermitidos.includes(
          tipo
        )
      ) {
        await connection.rollback();

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Tipo de seguimiento inválido"
          });
      }

      if (
        !prioridadesPermitidas.includes(
          prioridad
        )
      ) {
        await connection.rollback();

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Prioridad inválida"
          });
      }

      if (
        !resultadosPermitidos.includes(
          resultado
        )
      ) {
        await connection.rollback();

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Resultado de seguimiento inválido"
          });
      }

      if (
        !estadosPermitidos.includes(
          estado
        )
      ) {
        await connection.rollback();

        return res
          .status(400)
          .json({
            success: false,
            message:
              "Estado de seguimiento inválido"
          });
      }

      if (!observacion) {
        await connection.rollback();

        return res
          .status(400)
          .json({
            success: false,
            message:
              "La descripción de la situación es obligatoria"
          });
      }

      const participantes =
        Array.isArray(
          req.body?.participantes
        )
          ? JSON.stringify(
              req.body.participantes
            )
          : texto(
              req.body?.participantes
            );

      const cerrar =
        estado === "cerrado";

      const [result] =
        await connection.query(
          `
            INSERT INTO seguimiento_empleados
            (
              id_empleado,
              id_usuario_registro,
              fecha,
              tipo,
              prioridad,
              motivo,
              participantes,
              version_empleado,
              version_supervisor,
              observacion,
              accion_realizada,
              acuerdo,
              compromiso_empresa,
              compromiso_empleado,
              resultado,
              estado,
              proxima_accion,
              fecha_proxima_accion,
              fecha_cierre,
              id_usuario_cierre
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

            req.body?.fecha ||
              null,

            tipo,
            prioridad,

            texto(
              req.body?.motivo
            ),

            participantes,

            texto(
              req.body
                ?.version_empleado
            ),

            texto(
              req.body
                ?.version_supervisor
            ),

            observacion,

            texto(
              req.body
                ?.accion_realizada
            ),

            texto(
              req.body?.acuerdo
            ),

            texto(
              req.body
                ?.compromiso_empresa
            ),

            texto(
              req.body
                ?.compromiso_empleado
            ),

            resultado,
            estado,

            texto(
              req.body
                ?.proxima_accion
            ),

            req.body
              ?.fecha_proxima_accion ||
              null,

            cerrar
              ? new Date()
              : null,

            cerrar
              ? acceso.contexto
                  .idUsuario
              : null
          ]
        );

      const seguimiento =
        await consultarSeguimientoCompleto(
          result.insertId,
          connection
        );

      await registrarAuditoria(
        {
          idSeguimiento:
            result.insertId,

          idEmpleado,

          idUsuario:
            acceso.contexto
              .idUsuario,

          accion:
            cerrar
              ? "cerrar"
              : "crear",

          nuevo:
            seguimiento
        },
        connection
      );

      await connection.commit();

      return res
        .status(201)
        .json({
          success: true,

          message:
            cerrar
              ? "Seguimiento registrado y cerrado correctamente"
              : "Seguimiento laboral registrado correctamente",

          seguimiento
        });

    } catch (error) {
      if (connection) {
        try {
          await connection.rollback();
        } catch {}
      }

      console.error(
        "❌ Error registrando seguimiento laboral:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,

          message:
            "Error interno al registrar el seguimiento laboral",

          error:
            process.env.NODE_ENV ===
            "development"
              ? error.message
              : undefined
        });

    } finally {
      if (connection) {
        connection.release();
      }
    }
  };

// ==================================================
// LISTAR SEGUIMIENTOS
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

      const [seguimientos] =
        await pool.query(
          `
            SELECT
              s.*,

              u.nombre
                AS usuario_registro,

              uc.nombre
                AS usuario_cierre,

              ua.nombre
                AS usuario_anulacion

            FROM seguimiento_empleados s

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 s.id_usuario_registro

            LEFT JOIN usuarios uc
              ON uc.id_usuario =
                 s.id_usuario_cierre

            LEFT JOIN usuarios ua
              ON ua.id_usuario =
                 s.id_usuario_anulacion

            WHERE
              s.id_empleado = ?

            ORDER BY
              s.fecha DESC,
              s.id_seguimiento DESC
          `,
          [
            idEmpleado
          ]
        );

      const lista =
        seguimientos.map(
          seguimiento => {
            let participantes =
              seguimiento.participantes;

            if (
              typeof participantes ===
              "string"
            ) {
              try {
                participantes =
                  JSON.parse(
                    participantes
                  );
              } catch {
                // Conservamos texto antiguo.
              }
            }

            return {
              ...seguimiento,
              participantes
            };
          }
        );

      return res.json({
        success: true,

        empleado:
          acceso.empleado,

        total:
          lista.length,

        abiertos:
          lista.filter(
            s =>
              s.estado ===
                "abierto" ||
              s.estado ===
                "en_seguimiento"
          ).length,

        cerrados:
          lista.filter(
            s =>
              s.estado ===
              "cerrado"
          ).length,

        seguimientos:
          lista
      });

    } catch (error) {
      console.error(
        "❌ Error listando seguimiento laboral:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,
          message:
            "Error interno al obtener el seguimiento laboral"
        });
    }
  };

// ==================================================
// ACTUALIZAR SEGUIMIENTO
//
// PUT
// /api/empleados/:id/seguimiento/:idSeguimiento
// ==================================================

export const actualizarSeguimientoEmpleado =
  async (
    req,
    res
  ) => {
    let connection;

    try {
      const idEmpleado =
        Number(
          req.params.id
        );

      const idSeguimiento =
        Number(
          req.params
            .idSeguimiento
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
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Datos de seguimiento inválidos"
          });
      }

      connection =
        await pool.getConnection();

      await connection
        .beginTransaction();

      const acceso =
        await validarAccesoEmpleado(
          idEmpleado,
          req.user,
          connection
        );

      if (!acceso.ok) {
        await connection.rollback();

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

      const anterior =
        await obtenerSeguimientoPorId(
          idSeguimiento,
          idEmpleado,
          connection
        );

      if (!anterior) {
        await connection.rollback();

        return res
          .status(404)
          .json({
            success: false,
            message:
              "Seguimiento no encontrado"
          });
      }

      if (
        anterior.estado ===
        "anulado"
      ) {
        await connection.rollback();

        return res
          .status(409)
          .json({
            success: false,
            message:
              "Un seguimiento anulado no puede modificarse"
          });
      }

      if (
        anterior.estado ===
        "cerrado"
      ) {
        await connection.rollback();

        return res
          .status(409)
          .json({
            success: false,
            message:
              "Un seguimiento cerrado ya no puede modificarse. Registra un nuevo seguimiento para agregar información."
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
          await connection.rollback();

          return res
            .status(400)
            .json({
              success: false,
              message:
                "Tipo de seguimiento inválido"
            });
        }

        agregar(
          "tipo",
          valor
        );
      }

      if (
        req.body?.prioridad !==
        undefined
      ) {
        const valor =
          normalizar(
            req.body.prioridad
          );

        if (
          !prioridadesPermitidas
            .includes(
              valor
            )
        ) {
          await connection.rollback();

          return res
            .status(400)
            .json({
              success: false,
              message:
                "Prioridad inválida"
            });
        }

        agregar(
          "prioridad",
          valor
        );
      }

      const camposTexto = [
        "motivo",
        "version_empleado",
        "version_supervisor",
        "accion_realizada",
        "acuerdo",
        "compromiso_empresa",
        "compromiso_empleado",
        "proxima_accion"
      ];

      camposTexto.forEach(
        campo => {
          if (
            req.body?.[campo] !==
            undefined
          ) {
            agregar(
              campo,
              texto(
                req.body[campo]
              )
            );
          }
        }
      );

      if (
        req.body
          ?.participantes !==
        undefined
      ) {
        const participantes =
          Array.isArray(
            req.body.participantes
          )
            ? JSON.stringify(
                req.body
                  .participantes
              )
            : texto(
                req.body
                  .participantes
              );

        agregar(
          "participantes",
          participantes
        );
      }

      if (
        req.body
          ?.observacion !==
        undefined
      ) {
        const observacion =
          texto(
            req.body
              .observacion
          );

        if (!observacion) {
          await connection.rollback();

          return res
            .status(400)
            .json({
              success: false,
              message:
                "La descripción de la situación es obligatoria"
            });
        }

        agregar(
          "observacion",
          observacion
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
          !resultadosPermitidos
            .includes(
              valor
            )
        ) {
          await connection.rollback();

          return res
            .status(400)
            .json({
              success: false,
              message:
                "Resultado inválido"
            });
        }

        agregar(
          "resultado",
          valor
        );
      }

      let cerrar = false;

      if (
        req.body?.estado !==
        undefined
      ) {
        const valor =
          normalizar(
            req.body.estado
          );

        if (
          !estadosPermitidos
            .includes(
              valor
            )
        ) {
          await connection.rollback();

          return res
            .status(400)
            .json({
              success: false,
              message:
                "Estado inválido"
            });
        }

        agregar(
          "estado",
          valor
        );

        if (
          valor === "cerrado"
        ) {
          cerrar = true;

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
        req.body
          ?.fecha_proxima_accion !==
        undefined
      ) {
        agregar(
          "fecha_proxima_accion",
          req.body
            .fecha_proxima_accion ||
          null
        );
      }

      if (!campos.length) {
        await connection.rollback();

        return res
          .status(400)
          .json({
            success: false,
            message:
              "No se enviaron datos para actualizar"
          });
      }

      valores.push(
        idSeguimiento,
        idEmpleado
      );

      await connection.query(
        `
          UPDATE seguimiento_empleados

          SET
            ${campos.join(", ")}

          WHERE
            id_seguimiento = ?

            AND id_empleado = ?
        `,
        valores
      );

      const nuevo =
        await consultarSeguimientoCompleto(
          idSeguimiento,
          connection
        );

      await registrarAuditoria(
        {
          idSeguimiento,
          idEmpleado,

          idUsuario:
            acceso.contexto
              .idUsuario,

          accion:
            cerrar
              ? "cerrar"
              : "actualizar",

          anterior,
          nuevo
        },
        connection
      );

      await connection.commit();

      return res.json({
        success: true,

        message:
          cerrar
            ? "Seguimiento cerrado correctamente"
            : "Seguimiento laboral actualizado correctamente",

        seguimiento:
          nuevo
      });

    } catch (error) {
      if (connection) {
        try {
          await connection.rollback();
        } catch {}
      }

      console.error(
        "❌ Error actualizando seguimiento laboral:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,
          message:
            "Error interno al actualizar el seguimiento laboral"
        });

    } finally {
      if (connection) {
        connection.release();
      }
    }
  };

// ==================================================
// ANULAR SEGUIMIENTO
//
// Conservamos la ruta DELETE para no romper frontend:
//
// DELETE
// /api/empleados/:id/seguimiento/:idSeguimiento
//
// IMPORTANTE:
// YA NO BORRA EL REGISTRO.
// ==================================================

export const eliminarSeguimientoEmpleado =
  async (
    req,
    res
  ) => {
    let connection;

    try {
      const idEmpleado =
        Number(
          req.params.id
        );

      const idSeguimiento =
        Number(
          req.params
            .idSeguimiento
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
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Datos de seguimiento inválidos"
          });
      }

      const motivo =
        texto(
          req.body
            ?.motivo_anulacion
        );

      if (!motivo) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Debes indicar el motivo de la anulación"
          });
      }

      connection =
        await pool.getConnection();

      await connection
        .beginTransaction();

      const acceso =
        await validarAccesoEmpleado(
          idEmpleado,
          req.user,
          connection
        );

      if (!acceso.ok) {
        await connection.rollback();

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

      const anterior =
        await obtenerSeguimientoPorId(
          idSeguimiento,
          idEmpleado,
          connection
        );

      if (!anterior) {
        await connection.rollback();

        return res
          .status(404)
          .json({
            success: false,
            message:
              "Seguimiento no encontrado"
          });
      }

      if (
        anterior.estado ===
        "anulado"
      ) {
        await connection.rollback();

        return res
          .status(409)
          .json({
            success: false,
            message:
              "Este seguimiento ya se encuentra anulado"
          });
      }

      await connection.query(
        `
          UPDATE seguimiento_empleados

          SET
            estado = 'anulado',
            motivo_anulacion = ?,
            fecha_anulacion = NOW(),
            id_usuario_anulacion = ?

          WHERE
            id_seguimiento = ?

            AND id_empleado = ?
        `,
        [
          motivo,

          acceso.contexto
            .idUsuario,

          idSeguimiento,
          idEmpleado
        ]
      );

      const nuevo =
        await consultarSeguimientoCompleto(
          idSeguimiento,
          connection
        );

      await registrarAuditoria(
        {
          idSeguimiento,
          idEmpleado,

          idUsuario:
            acceso.contexto
              .idUsuario,

          accion:
            "anular",

          anterior,
          nuevo,
          motivo
        },
        connection
      );

      await connection.commit();

      return res.json({
        success: true,

        message:
          "Seguimiento anulado correctamente. El registro se conserva en el historial.",

        seguimiento:
          nuevo
      });

    } catch (error) {
      if (connection) {
        try {
          await connection.rollback();
        } catch {}
      }

      console.error(
        "❌ Error anulando seguimiento laboral:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,

          message:
            "Error interno al anular el seguimiento laboral"
        });

    } finally {
      if (connection) {
        connection.release();
      }
    }
  };