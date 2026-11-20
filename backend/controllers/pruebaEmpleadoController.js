import crypto from "crypto";
import pool from "../config/database.js";
import { generarReporteIAConMeta } from "../svc/aiService.js";
import { buscarEvaluacion } from "../evaluaciones/index.js";

const normalizar = valor =>
  valor
    ? String(valor).trim().toLowerCase()
    : "";

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
      perfilIndependiente: ""
    };
  }

  const [rows] =
    await connection.query(
      `
        SELECT
          id_usuario,
          tipo_admin,
          area,
          rol,
          id_admin_padre,
          id_organizacion,
          (
            SELECT
              o.perfil_independiente
            FROM organizaciones o
            WHERE o.id_organizacion = usuarios.id_organizacion
            LIMIT 1
          ) AS perfil_independiente
        FROM usuarios
        WHERE id_usuario = ?
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
      )
  };
};

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
      "rh";

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
        "No tienes permiso para acceder a las evaluaciones del empleado"
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
      e.puesto,
      e.departamento,
      e.estatus,
      ur.nombre AS responsable_actual
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
  } else if (esUsuarioRH || esIndependienteRH) {
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
    empleado:
      rows[0]
  };
};

const obtenerHabilitacionPorToken =
  async token => {
    const [rows] =
      await pool.query(
        `
          SELECT
            h.id_habilitacion,
            h.id_empleado,
            h.id_prueba_rh,
            h.id_usuario_registro,
            h.token_publico,
            h.motivo,
            h.tipo_evaluacion,
            h.estatus,
            h.fecha_habilitacion,
            h.fecha_inicio,
            h.fecha_completada,

            e.id_mirror,
            e.nombre AS empleado_nombre,
            e.puesto,
            e.departamento,
            e.estatus AS empleado_estatus,

            p.nombre AS prueba_nombre,
            p.descripcion AS prueba_descripcion,
            p.categoria,
            p.version,
            p.activo AS prueba_activa

          FROM pruebas_empleados_habilitadas h

          INNER JOIN empleados e
            ON e.id_empleado =
               h.id_empleado

          INNER JOIN pruebas_rh p
            ON p.id_prueba_rh =
               h.id_prueba_rh

          WHERE h.token_publico = ?

          LIMIT 1
        `,
        [
          token
        ]
      );

    return rows.length
      ? rows[0]
      : null;
  };

export const listarPruebasDisponiblesEmpleado =
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

      const [pruebas] =
        await pool.query(
          `
            SELECT
              id_prueba_rh,
              nombre,
              descripcion,
              categoria,
              contexto,
              version,
              activo
            FROM pruebas_rh
            WHERE
              activo = 1
              AND contexto IN (
                'empleado',
                'ambos'
              )
            ORDER BY
              nombre ASC
          `
        );

      return res.json({
        success: true,
        empleado:
          acceso.empleado,
        pruebas
      });

    } catch (error) {
      console.error(
        "❌ Error listando pruebas RH para empleado:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,
          message:
            "Error interno al obtener las evaluaciones disponibles"
        });
    }
  };

export const habilitarPruebaEmpleado =
  async (
    req,
    res
  ) => {
    try {
      const idEmpleado =
        Number(
          req.params.id
        );

      const idPruebaRH =
        Number(
          req.body
            ?.id_prueba_rh
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

      if (
        !Number.isInteger(
          idPruebaRH
        ) ||
        idPruebaRH <= 0
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Selecciona una evaluación válida"
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
        "periodica",
        "seguimiento",
        "bienestar",
        "prevencion",
        "riesgo_psicosocial",
        "otro"
      ];

      const tipoEvaluacion =
        String(
          req.body
            ?.tipo_evaluacion ||
          "periodica"
        )
          .trim()
          .toLowerCase();

      if (
        !tiposPermitidos.includes(
          tipoEvaluacion
        )
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Tipo de evaluación inválido"
          });
      }

      const motivo =
        req.body?.motivo
          ? String(
              req.body.motivo
            ).trim()
          : null;

      const [pruebas] =
        await pool.query(
          `
            SELECT
              id_prueba_rh,
              nombre,
              descripcion,
              categoria,
              contexto,
              version
            FROM pruebas_rh
            WHERE
              id_prueba_rh = ?
              AND activo = 1
              AND contexto IN (
                'empleado',
                'ambos'
              )
            LIMIT 1
          `,
          [
            idPruebaRH
          ]
        );

      if (!pruebas.length) {
        return res
          .status(404)
          .json({
            success: false,
            message:
              "La evaluación seleccionada no existe, está inactiva o no está habilitada para empleados"
          });
      }

      const [activas] =
        await pool.query(
          `
            SELECT
              id_habilitacion,
              estatus,
              fecha_habilitacion
            FROM pruebas_empleados_habilitadas
            WHERE
              id_empleado = ?
              AND id_prueba_rh = ?
              AND estatus IN (
                'habilitada',
                'iniciada'
              )
            LIMIT 1
          `,
          [
            idEmpleado,
            idPruebaRH
          ]
        );

      if (
        activas.length
      ) {
        return res
          .status(409)
          .json({
            success: false,
            message:
              "Este empleado ya tiene esta evaluación pendiente o iniciada",
            habilitacion:
              activas[0]
          });
      }

      const tokenPublico =
        crypto
          .randomBytes(32)
          .toString("hex");

      const [result] =
        await pool.query(
          `
            INSERT INTO pruebas_empleados_habilitadas
            (
              id_empleado,
              id_prueba_rh,
              id_usuario_registro,
              token_publico,
              motivo,
              tipo_evaluacion,
              estatus,
              fecha_habilitacion
            )
            VALUES
            (
              ?,
              ?,
              ?,
              ?,
              ?,
              ?,
              'habilitada',
              NOW()
            )
          `,
          [
            idEmpleado,
            idPruebaRH,
            acceso.contexto
              ?.idUsuario ||
            req.user
              ?.id_usuario ||
            null,
            tokenPublico,
            motivo,
            tipoEvaluacion
          ]
        );

      return res
        .status(201)
        .json({
          success: true,
          message:
            "Evaluación habilitada correctamente",
          habilitacion: {
            id_habilitacion:
              result.insertId,
            id_empleado:
              idEmpleado,
            id_prueba_rh:
              idPruebaRH,
            prueba_nombre:
              pruebas[0]
                .nombre,
            motivo,
            tipo_evaluacion:
              tipoEvaluacion,
            token_publico:
              tokenPublico,
            estatus:
              "habilitada"
          }
        });

    } catch (error) {
      console.error(
        "❌ Error habilitando evaluación del empleado:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,
          message:
            "Error interno al habilitar la evaluación",
          error:
            process.env.NODE_ENV ===
            "development"
              ? error.message
              : undefined
        });
    }
  };

export const listarPruebasEmpleado =
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

      const [evaluaciones] =
        await pool.query(
          `
            SELECT
              h.id_habilitacion,
              h.id_empleado,
              h.id_prueba_rh,
              h.id_usuario_registro,
              h.token_publico,
              h.motivo,
              h.tipo_evaluacion,
              h.estatus,
              h.fecha_habilitacion,
              h.fecha_inicio,
              h.fecha_completada,

              u.nombre AS usuario_registro,

              p.nombre AS prueba_nombre,
              p.descripcion AS prueba_descripcion,
              p.categoria,
              p.contexto,
              p.version,

              r.id_resultado,
              r.puntaje_total,
              r.resultado_texto,
              r.interpretacion,
              r.interpretacion_laboral,
              r.fortalezas,
              r.areas_atencion,
              r.indicadores_prevencion,
              r.recomendaciones,
              r.generado_por_ia,
              r.preevaluacion_ia,
              r.ia_proveedor,
              r.ia_modelo,
              r.fecha_preevaluacion_ia,
              r.fecha_resultado

            FROM pruebas_empleados_habilitadas h

            INNER JOIN pruebas_rh p
              ON p.id_prueba_rh =
                 h.id_prueba_rh

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 h.id_usuario_registro

            LEFT JOIN resultados_prueba_empleado r
              ON r.id_habilitacion =
                 h.id_habilitacion

            WHERE
              h.id_empleado = ?

            ORDER BY
              h.fecha_habilitacion DESC,
              h.id_habilitacion DESC
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
          evaluaciones.length,
        evaluaciones
      });

    } catch (error) {
      console.error(
        "❌ Error listando evaluaciones del empleado:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,
          message:
            "Error interno al obtener las evaluaciones"
        });
    }
  };

export const obtenerResultadosPruebasEmpleado =
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

      const [resultados] =
        await pool.query(
          `
            SELECT
              r.id_resultado,
              r.id_habilitacion,
              r.id_empleado,
              r.id_prueba_rh,
              r.puntaje_total,
              r.resultado_texto,
              r.interpretacion,
              r.interpretacion_laboral,
              r.fortalezas,
              r.areas_atencion,
              r.indicadores_prevencion,
              r.recomendaciones,
              r.generado_por_ia,
              r.preevaluacion_ia,
              r.ia_proveedor,
              r.ia_modelo,
              r.fecha_preevaluacion_ia,
              r.fecha_resultado,

              p.nombre AS prueba_nombre,
              p.descripcion AS prueba_descripcion,
              p.categoria,
              p.contexto,
              p.version,

              h.tipo_evaluacion,
              h.motivo,
              h.fecha_habilitacion,
              h.fecha_completada,

              u.nombre AS usuario_registro

            FROM resultados_prueba_empleado r

            INNER JOIN pruebas_rh p
              ON p.id_prueba_rh =
                 r.id_prueba_rh

            INNER JOIN pruebas_empleados_habilitadas h
              ON h.id_habilitacion =
                 r.id_habilitacion

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 h.id_usuario_registro

            WHERE
              r.id_empleado = ?

            ORDER BY
              r.fecha_resultado DESC,
              r.id_resultado DESC
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
          resultados.length,
        resultados
      });

    } catch (error) {
      console.error(
        "❌ Error obteniendo resultados del empleado:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,
          message:
            "Error interno al obtener los resultados"
        });
    }
  };

export const obtenerPruebaPublicaEmpleado =
  async (
    req,
    res
  ) => {
    try {
      const token =
        String(
          req.params.token ||
          ""
        ).trim();

      if (!token) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Token de evaluación inválido"
          });
      }

      const habilitacion =
        await obtenerHabilitacionPorToken(
          token
        );

      if (!habilitacion) {
        return res
          .status(404)
          .json({
            success: false,
            message:
              "Evaluación no encontrada"
          });
      }

      if (
        habilitacion.estatus ===
        "cancelada"
      ) {
        return res
          .status(410)
          .json({
            success: false,
            message:
              "Esta evaluación fue cancelada"
          });
      }

      if (
        habilitacion.estatus ===
        "completada"
      ) {
        return res
          .status(409)
          .json({
            success: false,
            message:
              "Esta evaluación ya fue completada"
          });
      }

      if (
        Number(
          habilitacion.prueba_activa
        ) !== 1
      ) {
        return res
          .status(410)
          .json({
            success: false,
            message:
              "Esta evaluación ya no se encuentra disponible"
          });
      }

      if (
        habilitacion.estatus ===
        "habilitada"
      ) {
        await pool.query(
          `
            UPDATE pruebas_empleados_habilitadas
            SET
              estatus = 'iniciada',
              fecha_inicio =
                COALESCE(
                  fecha_inicio,
                  NOW()
                )
            WHERE
              id_habilitacion = ?
          `,
          [
            habilitacion
              .id_habilitacion
          ]
        );
      }

      const [preguntas] =
        await pool.query(
          `
            SELECT
              id_pregunta_rh,
              texto_pregunta,
              tipo_respuesta,
              orden
            FROM preguntas_prueba_rh
            WHERE
              id_prueba_rh = ?
              AND activo = 1
            ORDER BY
              orden ASC,
              id_pregunta_rh ASC
          `,
          [
            habilitacion
              .id_prueba_rh
          ]
        );

      let opciones = [];

      if (
        preguntas.length
      ) {
        const idsPreguntas =
          preguntas.map(
            pregunta =>
              pregunta
                .id_pregunta_rh
          );

        const placeholders =
          idsPreguntas
            .map(
              () => "?"
            )
            .join(",");

        const [rowsOpciones] =
          await pool.query(
            `
              SELECT
                id_opcion_rh,
                id_pregunta_rh,
                texto_opcion,
                valor,
                orden
              FROM opciones_respuesta_rh
              WHERE
                id_pregunta_rh
                  IN (${placeholders})
                AND activo = 1
              ORDER BY
                id_pregunta_rh ASC,
                orden ASC,
                id_opcion_rh ASC
            `,
            idsPreguntas
          );

        opciones =
          rowsOpciones;
      }

      const preguntasConOpciones =
        preguntas.map(
          pregunta => ({
            ...pregunta,
            opciones:
              opciones.filter(
                opcion =>
                  Number(
                    opcion
                      .id_pregunta_rh
                  ) ===
                  Number(
                    pregunta
                      .id_pregunta_rh
                  )
              )
          })
        );

      return res.json({
        success: true,
        evaluacion: {
          id_habilitacion:
            habilitacion
              .id_habilitacion,

          tipo_evaluacion:
            habilitacion
              .tipo_evaluacion,

          motivo:
            habilitacion.motivo,

          prueba: {
            id_prueba_rh:
              habilitacion
                .id_prueba_rh,

            nombre:
              habilitacion
                .prueba_nombre,

            descripcion:
              habilitacion
                .prueba_descripcion,

            categoria:
              habilitacion
                .categoria,

            version:
              habilitacion
                .version
          },

          empleado: {
            nombre:
              habilitacion
                .empleado_nombre,

            id_mirror:
              habilitacion
                .id_mirror,

            puesto:
              habilitacion
                .puesto,

            departamento:
              habilitacion
                .departamento
          },

          preguntas:
            preguntasConOpciones
        }
      });

    } catch (error) {
      console.error(
        "❌ Error obteniendo evaluación pública del empleado:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,
          message:
            "Error interno al cargar la evaluación"
        });
    }
  };

export const guardarRespuestasPruebaEmpleado =
  async (
    req,
    res
  ) => {
    let connection;

    try {
      const token =
        String(
          req.params.token ||
          ""
        ).trim();

      const respuestas =
        Array.isArray(
          req.body
            ?.respuestas
        )
          ? req.body.respuestas
          : [];

      if (!token) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Token inválido"
          });
      }

      if (
        !respuestas.length
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "No se recibieron respuestas"
          });
      }

      const habilitacion =
        await obtenerHabilitacionPorToken(
          token
        );

      if (!habilitacion) {
        return res
          .status(404)
          .json({
            success: false,
            message:
              "Evaluación no encontrada"
          });
      }

      if (
        habilitacion.estatus ===
        "cancelada"
      ) {
        return res
          .status(410)
          .json({
            success: false,
            message:
              "Esta evaluación fue cancelada"
          });
      }

      if (
        habilitacion.estatus ===
        "completada"
      ) {
        return res
          .status(409)
          .json({
            success: false,
            message:
              "Esta evaluación ya fue completada"
          });
      }

      connection =
        await pool
          .getConnection();

      await connection
        .beginTransaction();

      await connection.query(
        `
          DELETE FROM respuestas_prueba_empleado
          WHERE
            id_habilitacion = ?
        `,
        [
          habilitacion
            .id_habilitacion
        ]
      );

      const preguntasProcesadas =
        new Set();

      for (
        const item
        of respuestas
      ) {
        const idPregunta =
          Number(
            item
              ?.id_pregunta_rh
          );

        const idOpcion =
          item?.id_opcion_rh
            ? Number(
                item.id_opcion_rh
              )
            : null;

        if (
          !Number.isInteger(
            idPregunta
          ) ||
          idPregunta <= 0
        ) {
          await connection
            .rollback();

          return res
            .status(400)
            .json({
              success: false,
              message:
                "Se recibió una pregunta inválida"
            });
        }

        if (
          preguntasProcesadas.has(
            idPregunta
          )
        ) {
          await connection
            .rollback();

          return res
            .status(400)
            .json({
              success: false,
              message:
                "Una misma pregunta fue enviada más de una vez"
            });
        }

        preguntasProcesadas.add(
          idPregunta
        );

        const [preguntas] =
          await connection.query(
            `
              SELECT
                id_pregunta_rh,
                tipo_respuesta
              FROM preguntas_prueba_rh
              WHERE
                id_pregunta_rh = ?
                AND id_prueba_rh = ?
                AND activo = 1
              LIMIT 1
            `,
            [
              idPregunta,
              habilitacion
                .id_prueba_rh
            ]
          );

        if (!preguntas.length) {
          await connection
            .rollback();

          return res
            .status(400)
            .json({
              success: false,
              message:
                "Una de las preguntas no pertenece a esta evaluación"
            });
        }

        const pregunta =
          preguntas[0];

        let respuestaTexto =
          item?.respuesta !==
            undefined &&
          item?.respuesta !==
            null
            ? String(
                item.respuesta
              ).trim()
            : null;

        let valorRespuesta =
          null;

        if (
          pregunta.tipo_respuesta ===
            "opcion" ||
          pregunta.tipo_respuesta ===
            "escala"
        ) {
          if (
            !Number.isInteger(
              idOpcion
            ) ||
            idOpcion <= 0
          ) {
            await connection
              .rollback();

            return res
              .status(400)
              .json({
                success: false,
                message:
                  "Falta seleccionar una respuesta"
              });
          }

          const [opciones] =
            await connection.query(
              `
                SELECT
                  id_opcion_rh,
                  texto_opcion,
                  valor
                FROM opciones_respuesta_rh
                WHERE
                  id_opcion_rh = ?
                  AND id_pregunta_rh = ?
                  AND activo = 1
                LIMIT 1
              `,
              [
                idOpcion,
                idPregunta
              ]
            );

          if (!opciones.length) {
            await connection
              .rollback();

            return res
              .status(400)
              .json({
                success: false,
                message:
                  "Se recibió una opción de respuesta inválida"
              });
          }

          respuestaTexto =
            opciones[0]
              .texto_opcion;

          valorRespuesta =
            opciones[0]
              .valor;
        }

        if (
          pregunta.tipo_respuesta ===
          "abierta"
        ) {
          if (
            !respuestaTexto
          ) {
            await connection
              .rollback();

            return res
              .status(400)
              .json({
                success: false,
                message:
                  "Falta responder una pregunta abierta"
              });
          }
        }

        await connection.query(
          `
            INSERT INTO respuestas_prueba_empleado
            (
              id_habilitacion,
              id_empleado,
              id_prueba_rh,
              id_pregunta_rh,
              respuesta,
              valor_respuesta
            )
            VALUES
            (
              ?,
              ?,
              ?,
              ?,
              ?,
              ?
            )
          `,
          [
            habilitacion
              .id_habilitacion,

            habilitacion
              .id_empleado,

            habilitacion
              .id_prueba_rh,

            idPregunta,
            respuestaTexto,
            valorRespuesta
          ]
        );
      }

      await connection.query(
        `
          UPDATE pruebas_empleados_habilitadas
          SET
            estatus =
              'iniciada',
            fecha_inicio =
              COALESCE(
                fecha_inicio,
                NOW()
              )
          WHERE
            id_habilitacion = ?
        `,
        [
          habilitacion
            .id_habilitacion
        ]
      );

      await connection
        .commit();

      return res.json({
        success: true,
        message:
          "Respuestas guardadas correctamente"
      });

    } catch (error) {
      if (connection) {
        try {
          await connection
            .rollback();
        } catch {}
      }

      console.error(
        "❌ Error guardando respuestas del empleado:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,
          message:
            "Error interno al guardar las respuestas"
        });

    } finally {
      if (connection) {
        connection.release();
      }
    }
  };

const esIPIP50 =
  habilitacion => {
    const nombre =
      String(
        habilitacion
          ?.prueba_nombre ||
        ""
      )
        .trim()
        .toLowerCase();

    const version =
      String(
        habilitacion
          ?.version ||
        ""
      )
        .trim()
        .toLowerCase();

    return (
      nombre ===
        "ipip-50 big five" ||
      version ===
        "ipip-bffm-50 es-mx"
    );
  };

const calcularIPIP50Empleado =
  async (
    idHabilitacion,
    connection
  ) => {
    const [filas] =
      await connection.query(
        `
          SELECT
            p.id_pregunta_rh,
            p.codigo,
            p.dimension,
            p.invertida,
            p.orden,
            r.valor_respuesta

          FROM respuestas_prueba_empleado r

          INNER JOIN preguntas_prueba_rh p
            ON p.id_pregunta_rh =
               r.id_pregunta_rh

          WHERE
            r.id_habilitacion = ?
            AND p.activo = 1

          ORDER BY
            p.orden ASC,
            p.id_pregunta_rh ASC
        `,
        [
          idHabilitacion
        ]
      );

    if (
      filas.length !== 50
    ) {
      throw new Error(
        `El IPIP-50 requiere exactamente 50 respuestas válidas. Se encontraron ${filas.length}.`
      );
    }

    const dimensionesEsperadas = {
      "extraversión": {
        etiqueta:
          "Extraversión",
        puntaje: 0,
        reactivos: 0
      },

      "amabilidad": {
        etiqueta:
          "Amabilidad",
        puntaje: 0,
        reactivos: 0
      },

      "responsabilidad": {
        etiqueta:
          "Responsabilidad",
        puntaje: 0,
        reactivos: 0
      },

      "estabilidad_emocional": {
        etiqueta:
          "Estabilidad emocional",
        puntaje: 0,
        reactivos: 0
      },

      "intelecto": {
        etiqueta:
          "Intelecto / Apertura",
        puntaje: 0,
        reactivos: 0
      }
    };

    for (
      const fila
      of filas
    ) {
      const dimension =
        String(
          fila.dimension ||
          ""
        )
          .trim()
          .toLowerCase();

      if (
        !Object.prototype
          .hasOwnProperty
          .call(
            dimensionesEsperadas,
            dimension
          )
      ) {
        throw new Error(
          `La pregunta ${fila.codigo || fila.id_pregunta_rh} tiene una dimensión IPIP-50 inválida: ${fila.dimension || "sin dimensión"}.`
        );
      }

      const valorOriginal =
        Number(
          fila.valor_respuesta
        );

      if (
        !Number.isFinite(
          valorOriginal
        ) ||
        valorOriginal < 1 ||
        valorOriginal > 5
      ) {
        throw new Error(
          `La respuesta de ${fila.codigo || fila.id_pregunta_rh} no tiene un valor válido entre 1 y 5.`
        );
      }

      const valorCorregido =
        Number(
          fila.invertida
        ) === 1
          ? 6 -
            valorOriginal
          : valorOriginal;

      dimensionesEsperadas[
        dimension
      ].puntaje +=
        valorCorregido;

      dimensionesEsperadas[
        dimension
      ].reactivos += 1;
    }

    for (
      const [
        codigo,
        datos
      ]
      of Object.entries(
        dimensionesEsperadas
      )
    ) {
      if (
        datos.reactivos !==
        10
      ) {
        throw new Error(
          `La dimensión ${codigo} debe contener 10 reactivos y se encontraron ${datos.reactivos}.`
        );
      }
    }

    const dimensiones =
      Object.fromEntries(
        Object.entries(
          dimensionesEsperadas
        ).map(
          (
            [
              codigo,
              datos
            ]
          ) => [
            codigo,
            {
              etiqueta:
                datos.etiqueta,

              puntaje:
                datos.puntaje,

              minimo:
                10,

              maximo:
                50,

              reactivos:
                datos.reactivos
            }
          ]
        )
      );

    const puntajeTecnicoAcumulado =
      Object
        .values(
          dimensiones
        )
        .reduce(
          (
            suma,
            item
          ) =>
            suma +
            Number(
              item.puntaje ||
              0
            ),
          0
        );

    const resultadoTexto = [
      "IPIP-50 Big Five — puntuación por dimensiones",
      "",
      ...Object
        .values(
          dimensiones
        )
        .map(
          item =>
            `${item.etiqueta}: ${item.puntaje}/50`
        ),
      "",
      "Los reactivos invertidos fueron recodificados antes de calcular cada dimensión.",
      "El IPIP-50 se interpreta por dimensiones. El puntaje acumulado no debe utilizarse como una medida global de personalidad, aptitud ni decisión laboral.",
      "No se aplicaron categorías bajo/medio/alto sin una referencia normativa definida para la población evaluada."
    ].join("\n");

    const interpretacion =
      "Resultados calculados conforme a la clave de puntuación del IPIP-50: reactivos directos 1–5, reactivos invertidos 5–1 y suma independiente de los 10 reactivos de cada dimensión.";

    const interpretacionLaboral =
      "Uso descriptivo como apoyo para Recursos Humanos. Estos resultados no determinan por sí solos idoneidad, contratación, rechazo ni diagnóstico psicológico.";

    return {
      puntajeTecnicoAcumulado,
      resultadoTexto,
      interpretacion,
      interpretacionLaboral,
      dimensiones
    };
  };

const esORVIS92 =
  habilitacion => {
    const nombre =
      String(
        habilitacion
          ?.prueba_nombre ||
        ""
      )
        .trim()
        .toLowerCase();

    const version =
      String(
        habilitacion
          ?.version ||
        ""
      )
        .trim()
        .toLowerCase();

    return (
      nombre ===
        "orvis - oregon vocational interest scales" ||
      version ===
        "orvis-92 es-mx"
    );
  };

const calcularORVIS92Empleado =
  async (
    idHabilitacion,
    connection
  ) => {
    const [filas] =
      await connection.query(
        `
          SELECT
            p.id_pregunta_rh,
            p.codigo,
            p.dimension,
            p.invertida,
            p.orden,
            r.valor_respuesta

          FROM respuestas_prueba_empleado r

          INNER JOIN preguntas_prueba_rh p
            ON p.id_pregunta_rh =
               r.id_pregunta_rh

          WHERE
            r.id_habilitacion = ?
            AND p.activo = 1

          ORDER BY
            p.orden ASC,
            p.id_pregunta_rh ASC
        `,
        [
          idHabilitacion
        ]
      );

    if (
      filas.length !== 92
    ) {
      throw new Error(
        `ORVIS-92 requiere exactamente 92 respuestas válidas. Se encontraron ${filas.length}.`
      );
    }

    const dimensionesEsperadas = {
      leadership: {
        etiqueta:
          "Liderazgo",
        esperados: 12,
        suma: 0,
        reactivos: 0
      },

      organization: {
        etiqueta:
          "Organización",
        esperados: 13,
        suma: 0,
        reactivos: 0
      },

      altruism: {
        etiqueta:
          "Altruismo",
        esperados: 13,
        suma: 0,
        reactivos: 0
      },

      creativity: {
        etiqueta:
          "Creatividad",
        esperados: 14,
        suma: 0,
        reactivos: 0
      },

      analysis: {
        etiqueta:
          "Análisis",
        esperados: 10,
        suma: 0,
        reactivos: 0
      },

      production: {
        etiqueta:
          "Producción / actividades prácticas",
        esperados: 10,
        suma: 0,
        reactivos: 0
      },

      adventure: {
        etiqueta:
          "Aventura",
        esperados: 10,
        suma: 0,
        reactivos: 0
      },

      erudition: {
        etiqueta:
          "Erudición",
        esperados: 10,
        suma: 0,
        reactivos: 0
      }
    };

    for (
      const fila
      of filas
    ) {
      const dimension =
        String(
          fila.dimension ||
          ""
        )
          .trim()
          .toLowerCase();

      if (
        !Object.prototype
          .hasOwnProperty
          .call(
            dimensionesEsperadas,
            dimension
          )
      ) {
        throw new Error(
          `La pregunta ${fila.codigo || fila.id_pregunta_rh} tiene una dimensión ORVIS-92 inválida: ${fila.dimension || "sin dimensión"}.`
        );
      }

      if (
        Number(
          fila.invertida
        ) === 1
      ) {
        throw new Error(
          `La pregunta ${fila.codigo || fila.id_pregunta_rh} está marcada como invertida, pero la configuración ORVIS-92 usa reactivos directos.`
        );
      }

      const valor =
        Number(
          fila.valor_respuesta
        );

      if (
        !Number.isFinite(
          valor
        ) ||
        valor < 1 ||
        valor > 5
      ) {
        throw new Error(
          `La respuesta de ${fila.codigo || fila.id_pregunta_rh} no tiene un valor válido entre 1 y 5.`
        );
      }

      dimensionesEsperadas[
        dimension
      ].suma +=
        valor;

      dimensionesEsperadas[
        dimension
      ].reactivos += 1;
    }

    for (
      const [
        codigo,
        datos
      ]
      of Object.entries(
        dimensionesEsperadas
      )
    ) {
      if (
        datos.reactivos !==
        datos.esperados
      ) {
        throw new Error(
          `La dimensión ${codigo} debe contener ${datos.esperados} reactivos y se encontraron ${datos.reactivos}.`
        );
      }
    }

    const dimensiones =
      Object.fromEntries(
        Object.entries(
          dimensionesEsperadas
        ).map(
          (
            [
              codigo,
              datos
            ]
          ) => [
            codigo,
            {
              etiqueta:
                datos.etiqueta,

              suma:
                datos.suma,

              promedio:
                Number(
                  (
                    datos.suma /
                    datos.reactivos
                  ).toFixed(2)
                ),

              minimo_suma:
                datos.reactivos,

              maximo_suma:
                datos.reactivos *
                5,

              minimo_promedio:
                1,

              maximo_promedio:
                5,

              reactivos:
                datos.reactivos
            }
          ]
        )
      );

    const puntajeTecnicoAcumulado =
      Object
        .values(
          dimensiones
        )
        .reduce(
          (
            suma,
            item
          ) =>
            suma +
            Number(
              item.suma ||
              0
            ),
          0
        );

    const resultadoTexto = [
      "ORVIS-92 — perfil de intereses vocacionales",
      "",
      ...Object
        .values(
          dimensiones
        )
        .map(
          item =>
            `${item.etiqueta}: suma ${item.suma}/${item.maximo_suma} | promedio ${item.promedio}/5 | ${item.reactivos} reactivos`
        ),
      "",
      "Las ocho escalas tienen diferente número de reactivos; por eso se conserva tanto la suma bruta como el promedio 1–5 de cada dimensión.",
      "No se aplicaron puntos de corte ni categorías alto/medio/bajo.",
      "El perfil describe intereses expresados y no determina por sí solo aptitud, contratación, rechazo ni diagnóstico psicológico."
    ].join("\n");

    const interpretacion =
      "Resultados calculados por las ocho escalas configuradas para ORVIS-92. Cada respuesta conserva su valor directo de 1 a 5; se reportan suma bruta y promedio por dimensión.";

    const interpretacionLaboral =
      "Uso descriptivo como apoyo para Recursos Humanos. El perfil puede ayudar a explorar áreas de interés laboral y vocacional, pero no constituye por sí solo una decisión laboral ni una medida diagnóstica.";

    return {
      puntajeTecnicoAcumulado,
      resultadoTexto,
      interpretacion,
      interpretacionLaboral,
      dimensiones
    };
  };

const generarYGuardarPreevaluacionEvaluacionRH =
  async ({
    idResultado,
    habilitacion,
    puntajeTotal,
    resultadoTexto,
    interpretacion,
    interpretacionLaboral,
    dimensiones
  }) => {
    try {
      const systemPrompt = `
Eres un asistente de apoyo para Recursos Humanos.

Debes generar una PRE-EVALUACIÓN ORIENTATIVA y breve a partir exclusivamente del resultado YA CALCULADO de una evaluación laboral.

REGLAS OBLIGATORIAS:
- No realices diagnósticos médicos ni psicológicos.
- No afirmes que la persona tiene un trastorno.
- No inventes síntomas, antecedentes, rasgos ni conclusiones.
- No modifiques ni recalcules puntajes.
- No uses información clínica.
- No recomiendes medicamentos ni tratamientos.
- No determines contratación, rechazo, aptitud o no aptitud.
- No conviertas un puntaje bruto en una interpretación si el instrumento no tiene reglas configuradas.
- Si el resultado sólo contiene un puntaje bruto, indícalo y evita inferencias.
- La decisión administrativa final corresponde a Recursos Humanos.
`;

      const prompt = `
Genera una pre-evaluación RH de máximo 120 palabras.

Evaluación:
${habilitacion.prueba_nombre || "Evaluación RH"}

Categoría:
${habilitacion.categoria || "No especificada"}

Tipo de evaluación:
${habilitacion.tipo_evaluacion || "No especificado"}

Puntaje técnico:
${puntajeTotal}

Resultado calculado:
${resultadoTexto || "Sin resultado textual específico"}

Interpretación técnica:
${interpretacion || "No configurada para este instrumento"}

Interpretación laboral:
${interpretacionLaboral || "No configurada para este instrumento"}

Dimensiones calculadas:
${JSON.stringify(dimensiones || null, null, 2)}

FORMATO OBLIGATORIO:
PRE-EVALUACIÓN IA

Interpretación:
Máximo 2 oraciones. Resume únicamente lo que realmente permite concluir el instrumento.

Atención sugerida:
Máximo 2 oraciones. Indica qué conviene que RH revise o considere, sin tomar la decisión por RH.

Nota:
Una sola oración indicando que es orientativa, no constituye diagnóstico médico o psicológico y la decisión final corresponde a Recursos Humanos.

REGLAS DE EXTENSIÓN:
- Máximo 120 palabras en total.
- No repitas todos los puntajes.
- No enumeres todas las dimensiones salvo que sea indispensable.
- Menciona únicamente los aspectos más relevantes.
- Si no existe interpretación configurada, dilo claramente y no inventes significado.
`;

      const resultadoIA =
        await generarReporteIAConMeta(
          prompt,
          220,
          systemPrompt
        );

      const texto =
        resultadoIA?.texto
          ? String(
              resultadoIA.texto
            ).trim()
          : "";

      if (!texto) {
        throw new Error(
          "La IA no devolvió contenido para la pre-evaluación RH."
        );
      }

      await pool.query(
        `
          UPDATE resultados_prueba_empleado
          SET
            preevaluacion_ia = ?,
            ia_proveedor = ?,
            ia_modelo = ?,
            fecha_preevaluacion_ia = NOW()
          WHERE id_resultado = ?
        `,
        [
          texto,
          resultadoIA
            ?.proveedor ||
          null,
          resultadoIA
            ?.modelo ||
          null,
          idResultado
        ]
      );

      return {
        texto,
        proveedor:
          resultadoIA
            ?.proveedor ||
          null,
        modelo:
          resultadoIA
            ?.modelo ||
          null
      };

    } catch (error) {
      console.error(
        "⚠️ No fue posible generar la pre-evaluación IA de la evaluación RH:",
        error
      );

      return null;
    }
  };

export const finalizarPruebaEmpleado =
  async (
    req,
    res
  ) => {
    let connection;

    try {
      const token =
        String(
          req.params.token ||
          ""
        ).trim();

      if (!token) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Token inválido"
          });
      }

      const habilitacion =
        await obtenerHabilitacionPorToken(
          token
        );

      if (!habilitacion) {
        return res
          .status(404)
          .json({
            success: false,
            message:
              "Evaluación no encontrada"
          });
      }

      if (
        habilitacion.estatus ===
        "cancelada"
      ) {
        return res
          .status(410)
          .json({
            success: false,
            message:
              "Esta evaluación fue cancelada"
          });
      }

      if (
        habilitacion.estatus ===
        "completada"
      ) {
        return res
          .status(409)
          .json({
            success: false,
            message:
              "Esta evaluación ya fue completada"
          });
      }

      connection =
        await pool
          .getConnection();

      await connection
        .beginTransaction();

      const [totalPreguntasRows] =
        await connection.query(
          `
            SELECT
              COUNT(*) AS total
            FROM preguntas_prueba_rh
            WHERE
              id_prueba_rh = ?
              AND activo = 1
          `,
          [
            habilitacion
              .id_prueba_rh
          ]
        );

      const totalPreguntas =
        Number(
          totalPreguntasRows[0]
            ?.total ||
          0
        );

      if (
        totalPreguntas === 0
      ) {
        await connection
          .rollback();

        return res
          .status(400)
          .json({
            success: false,
            message:
              "La evaluación no tiene preguntas activas"
          });
      }

      const [totalRespuestasRows] =
        await connection.query(
          `
            SELECT
              COUNT(
                DISTINCT id_pregunta_rh
              ) AS total
            FROM respuestas_prueba_empleado
            WHERE
              id_habilitacion = ?
          `,
          [
            habilitacion
              .id_habilitacion
          ]
        );

      const totalRespuestas =
        Number(
          totalRespuestasRows[0]
            ?.total ||
          0
        );

      if (
        totalRespuestas <
        totalPreguntas
      ) {
        await connection
          .rollback();

        return res
          .status(400)
          .json({
            success: false,
            message:
              `Faltan respuestas. Se respondieron ${totalRespuestas} de ${totalPreguntas} preguntas.`
          });
      }

      let puntajeTotal =
        0;

      let resultadoTexto =
        "";

      let interpretacion =
        null;

      let interpretacionLaboral =
        null;

      let dimensiones =
        null;

      let metadataEvaluacion =
        null;

      const motorEvaluacion =
        buscarEvaluacion(
          habilitacion
        );

      if (
        motorEvaluacion
      ) {
        const resultadoMotor =
          await motorEvaluacion
            .calcular({
              idHabilitacion:
                habilitacion
                  .id_habilitacion,
              connection
            });

        puntajeTotal =
          Number(
            resultadoMotor
              ?.puntajeTotal ||
            0
          );

        resultadoTexto =
          resultadoMotor
            ?.resultadoTexto ||
          `Puntaje obtenido: ${puntajeTotal}`;

        interpretacion =
          resultadoMotor
            ?.interpretacion ||
          null;

        interpretacionLaboral =
          resultadoMotor
            ?.interpretacionLaboral ||
          null;

        dimensiones =
          resultadoMotor
            ?.dimensiones ||
          null;

        metadataEvaluacion =
          resultadoMotor
            ?.metadata ||
          null;

      } else if (
        esIPIP50(
          habilitacion
        )
      ) {
        if (
          totalPreguntas !==
          50
        ) {
          throw new Error(
            `El IPIP-50 debe tener 50 reactivos activos. Actualmente tiene ${totalPreguntas}.`
          );
        }

        const resultadoIPIP =
          await calcularIPIP50Empleado(
            habilitacion
              .id_habilitacion,
            connection
          );

        puntajeTotal =
          resultadoIPIP
            .puntajeTecnicoAcumulado;

        resultadoTexto =
          resultadoIPIP
            .resultadoTexto;

        interpretacion =
          resultadoIPIP
            .interpretacion;

        interpretacionLaboral =
          resultadoIPIP
            .interpretacionLaboral;

        dimensiones =
          resultadoIPIP
            .dimensiones;

      } else if (
        esORVIS92(
          habilitacion
        )
      ) {
        if (
          totalPreguntas !==
          92
        ) {
          throw new Error(
            `ORVIS-92 debe tener 92 reactivos activos. Actualmente tiene ${totalPreguntas}.`
          );
        }

        const resultadoORVIS =
          await calcularORVIS92Empleado(
            habilitacion
              .id_habilitacion,
            connection
          );

        puntajeTotal =
          resultadoORVIS
            .puntajeTecnicoAcumulado;

        resultadoTexto =
          resultadoORVIS
            .resultadoTexto;

        interpretacion =
          resultadoORVIS
            .interpretacion;

        interpretacionLaboral =
          resultadoORVIS
            .interpretacionLaboral;

        dimensiones =
          resultadoORVIS
            .dimensiones;

      } else {
        const [puntajeRows] =
          await connection.query(
            `
              SELECT
                COALESCE(
                  SUM(
                    valor_respuesta
                  ),
                  0
                ) AS puntaje_total
              FROM respuestas_prueba_empleado
              WHERE
                id_habilitacion = ?
            `,
            [
              habilitacion
                .id_habilitacion
            ]
          );

        puntajeTotal =
          Number(
            puntajeRows[0]
              ?.puntaje_total ||
            0
          );

        resultadoTexto =
          `Puntaje bruto obtenido: ${puntajeTotal}`;

        interpretacion =
          null;

        interpretacionLaboral =
          null;

        dimensiones =
          null;

        metadataEvaluacion =
          null;
      }

      const [resultadoExistente] =
        await connection.query(
          `
            SELECT
              id_resultado
            FROM resultados_prueba_empleado
            WHERE
              id_habilitacion = ?
            LIMIT 1
          `,
          [
            habilitacion
              .id_habilitacion
          ]
        );

      let idResultado;

      if (
        resultadoExistente
          .length
      ) {
        idResultado =
          resultadoExistente[0]
            .id_resultado;

        await connection.query(
          `
            UPDATE resultados_prueba_empleado
            SET
              puntaje_total = ?,
              resultado_texto = ?,
              interpretacion = ?,
              interpretacion_laboral = ?,
              fortalezas = NULL,
              areas_atencion = NULL,
              indicadores_prevencion = NULL,
              recomendaciones = NULL,
              generado_por_ia = 0,
              preevaluacion_ia = NULL,
              ia_proveedor = NULL,
              ia_modelo = NULL,
              fecha_preevaluacion_ia = NULL,
              fecha_resultado = NOW()
            WHERE
              id_resultado = ?
          `,
          [
            puntajeTotal,
            resultadoTexto,
            interpretacion,
            interpretacionLaboral,
            idResultado
          ]
        );

      } else {
        const [insertResultado] =
          await connection.query(
            `
              INSERT INTO resultados_prueba_empleado
              (
                id_habilitacion,
                id_empleado,
                id_prueba_rh,
                puntaje_total,
                resultado_texto,
                interpretacion,
                interpretacion_laboral,
                fortalezas,
                areas_atencion,
                indicadores_prevencion,
                recomendaciones,
                generado_por_ia,
                preevaluacion_ia,
                ia_proveedor,
                ia_modelo,
                fecha_preevaluacion_ia,
                fecha_resultado
              )
              VALUES
              (
                ?, ?, ?, ?, ?, ?, ?,
                NULL, NULL, NULL, NULL,
                0,
                NULL, NULL, NULL, NULL,
                NOW()
              )
            `,
            [
              habilitacion
                .id_habilitacion,

              habilitacion
                .id_empleado,

              habilitacion
                .id_prueba_rh,

              puntajeTotal,
              resultadoTexto,
              interpretacion,
              interpretacionLaboral
            ]
          );

        idResultado =
          insertResultado
            .insertId;
      }

      await connection.query(
        `
          UPDATE pruebas_empleados_habilitadas
          SET
            estatus =
              'completada',
            fecha_completada =
              NOW()
          WHERE
            id_habilitacion = ?
        `,
        [
          habilitacion
            .id_habilitacion
        ]
      );

      await connection
        .commit();

      const preevaluacionIA =
        await generarYGuardarPreevaluacionEvaluacionRH({
          idResultado,
          habilitacion,
          puntajeTotal,
          resultadoTexto,
          interpretacion,
          interpretacionLaboral,
          dimensiones
        });

      return res.json({
        success: true,

        message:
          "Evaluación completada correctamente",

        resultado: {
          id_resultado:
            idResultado,

          id_habilitacion:
            habilitacion
              .id_habilitacion,

          id_empleado:
            habilitacion
              .id_empleado,

          id_prueba_rh:
            habilitacion
              .id_prueba_rh,

          prueba_nombre:
            habilitacion
              .prueba_nombre,

          puntaje_total:
            puntajeTotal,

          resultado_texto:
            resultadoTexto,

          interpretacion,

          interpretacion_laboral:
            interpretacionLaboral,

          dimensiones,

          metadata_evaluacion:
            metadataEvaluacion,

          interpretacion_pendiente:
            !motorEvaluacion &&
            !esIPIP50(
              habilitacion
            ) &&
            !esORVIS92(
              habilitacion
            ),

          preevaluacion_ia:
            preevaluacionIA
              ?.texto ||
            null,

          ia_proveedor:
            preevaluacionIA
              ?.proveedor ||
            null,

          ia_modelo:
            preevaluacionIA
              ?.modelo ||
            null
        }
      });

    } catch (error) {
      if (connection) {
        try {
          await connection
            .rollback();
        } catch {}
      }

      console.error(
        "❌ Error finalizando evaluación del empleado:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,

          message:
            "Error interno al finalizar la evaluación",

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

export const cancelarPruebaEmpleado =
  async (
    req,
    res
  ) => {
    try {
      const idEmpleado =
        Number(
          req.params.id
        );

      const idHabilitacion =
        Number(
          req.params
            .idHabilitacion
        );

      if (
        !Number.isInteger(
          idEmpleado
        ) ||
        idEmpleado <= 0 ||
        !Number.isInteger(
          idHabilitacion
        ) ||
        idHabilitacion <= 0
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Datos de evaluación inválidos"
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

      const [rows] =
        await pool.query(
          `
            SELECT
              id_habilitacion,
              estatus
            FROM pruebas_empleados_habilitadas
            WHERE
              id_habilitacion = ?
              AND id_empleado = ?
            LIMIT 1
          `,
          [
            idHabilitacion,
            idEmpleado
          ]
        );

      if (!rows.length) {
        return res
          .status(404)
          .json({
            success: false,
            message:
              "Evaluación no encontrada"
          });
      }

      if (
        rows[0].estatus ===
        "completada"
      ) {
        return res
          .status(409)
          .json({
            success: false,
            message:
              "Una evaluación completada no puede cancelarse"
          });
      }

      if (
        rows[0].estatus ===
        "cancelada"
      ) {
        return res
          .status(409)
          .json({
            success: false,
            message:
              "La evaluación ya se encuentra cancelada"
          });
      }

      await pool.query(
        `
          UPDATE pruebas_empleados_habilitadas
          SET
            estatus =
              'cancelada'
          WHERE
            id_habilitacion = ?
            AND id_empleado = ?
        `,
        [
          idHabilitacion,
          idEmpleado
        ]
      );

      return res.json({
        success: true,
        message:
          "Evaluación cancelada correctamente"
      });

    } catch (error) {
      console.error(
        "❌ Error cancelando evaluación:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,
          message:
            "Error interno al cancelar la evaluación"
        });
    }
  };

export const eliminarPruebaCanceladaEmpleado =
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

      const idHabilitacion =
        Number(
          req.params
            .idHabilitacion
        );

      if (
        !Number.isInteger(
          idEmpleado
        ) ||
        idEmpleado <= 0 ||
        !Number.isInteger(
          idHabilitacion
        ) ||
        idHabilitacion <= 0
      ) {
        return res
          .status(400)
          .json({
            success: false,
            message:
              "Datos de evaluación inválidos"
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

      connection =
        await pool
          .getConnection();

      await connection
        .beginTransaction();

      const [rows] =
        await connection.query(
          `
            SELECT
              id_habilitacion,
              id_empleado,
              estatus
            FROM pruebas_empleados_habilitadas
            WHERE
              id_habilitacion = ?
              AND id_empleado = ?
            LIMIT 1
          `,
          [
            idHabilitacion,
            idEmpleado
          ]
        );

      if (!rows.length) {
        await connection
          .rollback();

        return res
          .status(404)
          .json({
            success: false,
            message:
              "Evaluación no encontrada"
          });
      }

      if (
        rows[0].estatus !==
        "cancelada"
      ) {
        await connection
          .rollback();

        return res
          .status(409)
          .json({
            success: false,
            message:
              "Solo se pueden eliminar evaluaciones canceladas"
          });
      }

      await connection.query(
        `
          DELETE FROM respuestas_prueba_empleado
          WHERE
            id_habilitacion = ?
            AND id_empleado = ?
        `,
        [
          idHabilitacion,
          idEmpleado
        ]
      );

      await connection.query(
        `
          DELETE FROM resultados_prueba_empleado
          WHERE
            id_habilitacion = ?
            AND id_empleado = ?
        `,
        [
          idHabilitacion,
          idEmpleado
        ]
      );

      await connection.query(
        `
          DELETE FROM pruebas_empleados_habilitadas
          WHERE
            id_habilitacion = ?
            AND id_empleado = ?
            AND estatus = 'cancelada'
        `,
        [
          idHabilitacion,
          idEmpleado
        ]
      );

      await connection
        .commit();

      return res.json({
        success: true,
        message:
          "Evaluación cancelada eliminada correctamente"
      });

    } catch (error) {
      if (connection) {
        try {
          await connection
            .rollback();
        } catch {}
      }

      console.error(
        "❌ Error eliminando evaluación cancelada:",
        error
      );

      return res
        .status(500)
        .json({
          success: false,

          message:
            "Error interno al eliminar la evaluación",

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