import crypto from "crypto";
import pool from "../config/database.js";


// ==================================================
// AUXILIAR: VALIDAR ACCESO AL EMPLEADO
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
        "No tienes permiso para acceder a las evaluaciones del empleado"
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
// AUXILIAR: OBTENER HABILITACIÓN POR TOKEN
// RUTA PÚBLICA
// ==================================================

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


// ==================================================
// LISTAR PRUEBAS RH DISPONIBLES
//
// GET
// /api/empleados/:id/evaluaciones/disponibles
// ==================================================

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


      const [pruebas] =
        await pool.query(
          `
            SELECT
              id_prueba_rh,
              nombre,
              descripcion,
              categoria,
              version,
              activo

            FROM pruebas_rh

            WHERE activo = 1

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


      return res.status(500).json({
        success: false,
        message:
          "Error interno al obtener las evaluaciones disponibles"
      });

    }

  };


// ==================================================
// HABILITAR PRUEBA PARA EMPLEADO
//
// POST
// /api/empleados/:id/evaluaciones/habilitar
//
// BODY:
// {
//   id_prueba_rh,
//   motivo,
//   tipo_evaluacion
// }
// ==================================================

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
          req.body?.id_prueba_rh
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


      if (
        !Number.isInteger(
          idPruebaRH
        ) ||
        idPruebaRH <= 0
      ) {

        return res.status(400).json({
          success: false,
          message:
            "Selecciona una prueba válida"
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
          req.body?.tipo_evaluacion ||
          "periodica"
        )
          .trim()
          .toLowerCase();


      if (
        !tiposPermitidos.includes(
          tipoEvaluacion
        )
      ) {

        return res.status(400).json({
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


      // ==================================================
      // VALIDAR PRUEBA RH
      // ==================================================

      const [pruebas] =
        await pool.query(
          `
            SELECT
              id_prueba_rh,
              nombre,
              descripcion,
              categoria,
              version
            FROM pruebas_rh
            WHERE id_prueba_rh = ?
              AND activo = 1
            LIMIT 1
          `,
          [
            idPruebaRH
          ]
        );


      if (!pruebas.length) {

        return res.status(404).json({
          success: false,
          message:
            "La prueba RH seleccionada no existe o está inactiva"
        });

      }


      // ==================================================
      // IMPEDIR DOS HABILITACIONES ACTIVAS DE LA MISMA
      // PRUEBA AL MISMO TIEMPO
      //
      // SÍ PERMITIMOS REPETIRLA CUANDO LA ANTERIOR
      // YA ESTÁ COMPLETADA O CANCELADA.
      // ==================================================

      const [activas] =
        await pool.query(
          `
            SELECT
              id_habilitacion,
              estatus,
              fecha_habilitacion
            FROM pruebas_empleados_habilitadas
            WHERE id_empleado = ?
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


      if (activas.length) {

        return res.status(409).json({
          success: false,
          message:
            "Este empleado ya tiene esta evaluación pendiente o iniciada",
          habilitacion:
            activas[0]
        });

      }


      // ==================================================
      // TOKEN PÚBLICO
      // ==================================================

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
            req.user?.id_usuario ||
              null,
            tokenPublico,
            motivo,
            tipoEvaluacion
          ]
        );


      return res.status(201).json({
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
            pruebas[0].nombre,

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


      return res.status(500).json({
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


// ==================================================
// LISTAR EVALUACIONES DEL EMPLEADO
//
// GET
// /api/empleados/:id/evaluaciones
// ==================================================

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


      const [evaluaciones] =
        await pool.query(
          `
            SELECT
              h.id_habilitacion,
              h.id_empleado,
              h.id_prueba_rh,
              h.token_publico,
              h.motivo,
              h.tipo_evaluacion,
              h.estatus,
              h.fecha_habilitacion,
              h.fecha_inicio,
              h.fecha_completada,

              p.nombre AS prueba_nombre,
              p.descripcion AS prueba_descripcion,
              p.categoria,
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


      return res.status(500).json({
        success: false,
        message:
          "Error interno al obtener las evaluaciones"
      });

    }

  };


// ==================================================
// OBTENER RESULTADOS DEL EMPLEADO
//
// GET
// /api/empleados/:id/evaluaciones/resultados
// ==================================================

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
              r.fecha_resultado,

              p.nombre AS prueba_nombre,
              p.descripcion AS prueba_descripcion,
              p.categoria,
              p.version,

              h.tipo_evaluacion,
              h.motivo,
              h.fecha_habilitacion,
              h.fecha_completada

            FROM resultados_prueba_empleado r

            INNER JOIN pruebas_rh p
              ON p.id_prueba_rh =
                 r.id_prueba_rh

            INNER JOIN pruebas_empleados_habilitadas h
              ON h.id_habilitacion =
                 r.id_habilitacion

            WHERE r.id_empleado = ?

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


      return res.status(500).json({
        success: false,
        message:
          "Error interno al obtener los resultados"
      });

    }

  };


// ==================================================
// OBTENER PRUEBA PÚBLICA POR TOKEN
//
// GET
// /api/empleados/evaluacion-publica/:token
//
// SIN LOGIN
// ==================================================

export const obtenerPruebaPublicaEmpleado =
  async (
    req,
    res
  ) => {

    try {

      const token =
        String(
          req.params.token || ""
        ).trim();


      if (!token) {

        return res.status(400).json({
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

        return res.status(404).json({
          success: false,
          message:
            "Evaluación no encontrada"
        });

      }


      if (
        habilitacion.estatus ===
        "cancelada"
      ) {

        return res.status(410).json({
          success: false,
          message:
            "Esta evaluación fue cancelada"
        });

      }


      if (
        habilitacion.estatus ===
        "completada"
      ) {

        return res.status(409).json({
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

        return res.status(410).json({
          success: false,
          message:
            "Esta evaluación ya no se encuentra disponible"
        });

      }


      // ==================================================
      // MARCAR COMO INICIADA
      // ==================================================

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

            WHERE id_habilitacion = ?
          `,
          [
            habilitacion.id_habilitacion
          ]
        );

      }


      // ==================================================
      // PREGUNTAS
      // ==================================================

      const [preguntas] =
        await pool.query(
          `
            SELECT
              id_pregunta_rh,
              texto_pregunta,
              tipo_respuesta,
              orden

            FROM preguntas_prueba_rh

            WHERE id_prueba_rh = ?
              AND activo = 1

            ORDER BY
              orden ASC,
              id_pregunta_rh ASC
          `,
          [
            habilitacion.id_prueba_rh
          ]
        );


      // ==================================================
      // OPCIONES
      // ==================================================

      let opciones = [];


      if (
        preguntas.length
      ) {

        const idsPreguntas =
          preguntas.map(
            pregunta =>
              pregunta.id_pregunta_rh
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

              WHERE id_pregunta_rh
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


      // ==================================================
      // AGRUPAR OPCIONES
      // ==================================================

      const preguntasConOpciones =
        preguntas.map(
          pregunta => ({
            ...pregunta,

            opciones:
              opciones.filter(
                opcion =>
                  Number(
                    opcion.id_pregunta_rh
                  ) ===
                  Number(
                    pregunta.id_pregunta_rh
                  )
              )
          })
        );


      return res.json({
        success: true,

        evaluacion: {
          id_habilitacion:
            habilitacion.id_habilitacion,

          tipo_evaluacion:
            habilitacion.tipo_evaluacion,

          motivo:
            habilitacion.motivo,

          prueba: {
            id_prueba_rh:
              habilitacion.id_prueba_rh,

            nombre:
              habilitacion.prueba_nombre,

            descripcion:
              habilitacion.prueba_descripcion,

            categoria:
              habilitacion.categoria,

            version:
              habilitacion.version
          },

          empleado: {
            nombre:
              habilitacion.empleado_nombre,

            id_mirror:
              habilitacion.id_mirror,

            puesto:
              habilitacion.puesto,

            departamento:
              habilitacion.departamento
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


      return res.status(500).json({
        success: false,
        message:
          "Error interno al cargar la evaluación"
      });

    }

  };


// ==================================================
// GUARDAR RESPUESTAS PÚBLICAS
//
// POST
// /api/empleados/evaluacion-publica/:token/respuestas
//
// BODY:
// {
//   respuestas: [
//      {
//        id_pregunta_rh,
//        id_opcion_rh,
//        respuesta
//      }
//   ]
// }
// ==================================================

export const guardarRespuestasPruebaEmpleado =
  async (
    req,
    res
  ) => {

    let connection;

    try {

      const token =
        String(
          req.params.token || ""
        ).trim();


      const respuestas =
        Array.isArray(
          req.body?.respuestas
        )
          ? req.body.respuestas
          : [];


      if (!token) {

        return res.status(400).json({
          success: false,
          message:
            "Token inválido"
        });

      }


      if (
        !respuestas.length
      ) {

        return res.status(400).json({
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

        return res.status(404).json({
          success: false,
          message:
            "Evaluación no encontrada"
        });

      }


      if (
        habilitacion.estatus ===
        "cancelada"
      ) {

        return res.status(410).json({
          success: false,
          message:
            "Esta evaluación fue cancelada"
        });

      }


      if (
        habilitacion.estatus ===
        "completada"
      ) {

        return res.status(409).json({
          success: false,
          message:
            "Esta evaluación ya fue completada"
        });

      }


      connection =
        await pool.getConnection();

      await connection.beginTransaction();


      // ==================================================
      // REEMPLAZAR RESPUESTAS DE ESTA HABILITACIÓN
      // ==================================================

      await connection.query(
        `
          DELETE FROM respuestas_prueba_empleado

          WHERE id_habilitacion = ?
        `,
        [
          habilitacion.id_habilitacion
        ]
      );


      // ==================================================
      // EVITAR PREGUNTAS REPETIDAS
      // ==================================================

      const preguntasProcesadas =
        new Set();


      for (
        const item of respuestas
      ) {

        const idPregunta =
          Number(
            item?.id_pregunta_rh
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

          await connection.rollback();

          return res.status(400).json({
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

          await connection.rollback();

          return res.status(400).json({
            success: false,
            message:
              "Una misma pregunta fue enviada más de una vez"
          });

        }


        preguntasProcesadas.add(
          idPregunta
        );


        // ==================================================
        // VALIDAR QUE LA PREGUNTA PERTENEZCA A LA PRUEBA
        // ==================================================

        const [preguntas] =
          await connection.query(
            `
              SELECT
                id_pregunta_rh,
                tipo_respuesta
              FROM preguntas_prueba_rh
              WHERE id_pregunta_rh = ?
                AND id_prueba_rh = ?
                AND activo = 1
              LIMIT 1
            `,
            [
              idPregunta,
              habilitacion.id_prueba_rh
            ]
          );


        if (!preguntas.length) {

          await connection.rollback();

          return res.status(400).json({
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
          item?.respuesta !== null
            ? String(
                item.respuesta
              ).trim()
            : null;


        let valorRespuesta =
          null;


        // ==================================================
        // RESPUESTA DE OPCIÓN / ESCALA
        // ==================================================

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

            await connection.rollback();

            return res.status(400).json({
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

                WHERE id_opcion_rh = ?
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

            await connection.rollback();

            return res.status(400).json({
              success: false,
              message:
                "Se recibió una opción de respuesta inválida"
            });

          }


          respuestaTexto =
            opciones[0].texto_opcion;

          valorRespuesta =
            opciones[0].valor;

        }


        // ==================================================
        // RESPUESTA ABIERTA
        // ==================================================

        if (
          pregunta.tipo_respuesta ===
          "abierta"
        ) {

          if (
            !respuestaTexto
          ) {

            await connection.rollback();

            return res.status(400).json({
              success: false,
              message:
                "Falta responder una pregunta abierta"
            });

          }

        }


        // ==================================================
        // GUARDAR
        // ==================================================

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
            habilitacion.id_habilitacion,
            habilitacion.id_empleado,
            habilitacion.id_prueba_rh,
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
            estatus = 'iniciada',
            fecha_inicio =
              COALESCE(
                fecha_inicio,
                NOW()
              )

          WHERE id_habilitacion = ?
        `,
        [
          habilitacion.id_habilitacion
        ]
      );


      await connection.commit();


      return res.json({
        success: true,
        message:
          "Respuestas guardadas correctamente"
      });


    } catch (error) {

      if (connection) {
        try {
          await connection.rollback();
        } catch {}
      }


      console.error(
        "❌ Error guardando respuestas del empleado:",
        error
      );


      return res.status(500).json({
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


// ==================================================
// FINALIZAR PRUEBA
//
// POST
// /api/empleados/evaluacion-publica/:token/finalizar
//
// IMPORTANTE:
// NO INVENTAMOS INTERPRETACIONES UNIVERSALES.
// GUARDAMOS PUNTAJE BRUTO.
// CADA INSTRUMENTO TENDRÁ SU PROPIO SISTEMA.
// ==================================================

export const finalizarPruebaEmpleado =
  async (
    req,
    res
  ) => {

    let connection;

    try {

      const token =
        String(
          req.params.token || ""
        ).trim();


      if (!token) {

        return res.status(400).json({
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

        return res.status(404).json({
          success: false,
          message:
            "Evaluación no encontrada"
        });

      }


      if (
        habilitacion.estatus ===
        "cancelada"
      ) {

        return res.status(410).json({
          success: false,
          message:
            "Esta evaluación fue cancelada"
        });

      }


      if (
        habilitacion.estatus ===
        "completada"
      ) {

        return res.status(409).json({
          success: false,
          message:
            "Esta evaluación ya fue completada"
        });

      }


      connection =
        await pool.getConnection();

      await connection.beginTransaction();


      // ==================================================
      // TOTAL DE PREGUNTAS ACTIVAS
      // ==================================================

      const [totalPreguntasRows] =
        await connection.query(
          `
            SELECT
              COUNT(*) AS total

            FROM preguntas_prueba_rh

            WHERE id_prueba_rh = ?
              AND activo = 1
          `,
          [
            habilitacion.id_prueba_rh
          ]
        );


      const totalPreguntas =
        Number(
          totalPreguntasRows[0]?.total ||
          0
        );


      if (
        totalPreguntas === 0
      ) {

        await connection.rollback();

        return res.status(400).json({
          success: false,
          message:
            "La evaluación no tiene preguntas activas"
        });

      }


      // ==================================================
      // TOTAL RESPUESTAS ÚNICAS
      // ==================================================

      const [totalRespuestasRows] =
        await connection.query(
          `
            SELECT
              COUNT(
                DISTINCT id_pregunta_rh
              ) AS total

            FROM respuestas_prueba_empleado

            WHERE id_habilitacion = ?
          `,
          [
            habilitacion.id_habilitacion
          ]
        );


      const totalRespuestas =
        Number(
          totalRespuestasRows[0]?.total ||
          0
        );


      if (
        totalRespuestas <
        totalPreguntas
      ) {

        await connection.rollback();

        return res.status(400).json({
          success: false,

          message:
            `Faltan respuestas. Se respondieron ${totalRespuestas} de ${totalPreguntas} preguntas.`
        });

      }


      // ==================================================
      // PUNTAJE BRUTO
      //
      // SOLO SUMAMOS LOS VALORES DEFINIDOS POR EL
      // INSTRUMENTO EN opciones_respuesta_rh.
      // ==================================================

      const [puntajeRows] =
        await connection.query(
          `
            SELECT
              COALESCE(
                SUM(valor_respuesta),
                0
              ) AS puntaje_total

            FROM respuestas_prueba_empleado

            WHERE id_habilitacion = ?
          `,
          [
            habilitacion.id_habilitacion
          ]
        );


      const puntajeTotal =
        Number(
          puntajeRows[0]?.puntaje_total ||
          0
        );


      // ==================================================
      // GUARDAR RESULTADO
      // ==================================================

      const [resultadoExistente] =
        await connection.query(
          `
            SELECT
              id_resultado

            FROM resultados_prueba_empleado

            WHERE id_habilitacion = ?

            LIMIT 1
          `,
          [
            habilitacion.id_habilitacion
          ]
        );


      let idResultado;


      if (
        resultadoExistente.length
      ) {

        idResultado =
          resultadoExistente[0]
            .id_resultado;


        await connection.query(
          `
            UPDATE resultados_prueba_empleado

            SET
              puntaje_total = ?,
              fecha_resultado = NOW()

            WHERE id_resultado = ?
          `,
          [
            puntajeTotal,
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
                fecha_resultado
              )
              VALUES
              (
                ?,
                ?,
                ?,
                ?,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                NULL,
                0,
                NOW()
              )
            `,
            [
              habilitacion.id_habilitacion,
              habilitacion.id_empleado,
              habilitacion.id_prueba_rh,
              puntajeTotal
            ]
          );


        idResultado =
          insertResultado.insertId;

      }


      // ==================================================
      // MARCAR COMPLETADA
      // ==================================================

      await connection.query(
        `
          UPDATE pruebas_empleados_habilitadas

          SET
            estatus = 'completada',
            fecha_completada = NOW()

          WHERE id_habilitacion = ?
        `,
        [
          habilitacion.id_habilitacion
        ]
      );


      await connection.commit();


      return res.json({
        success: true,

        message:
          "Evaluación completada correctamente",

        resultado: {
          id_resultado:
            idResultado,

          id_habilitacion:
            habilitacion.id_habilitacion,

          id_empleado:
            habilitacion.id_empleado,

          id_prueba_rh:
            habilitacion.id_prueba_rh,

          prueba_nombre:
            habilitacion.prueba_nombre,

          puntaje_total:
            puntajeTotal,

          interpretacion:
            null,

          interpretacion_laboral:
            null
        }
      });


    } catch (error) {

      if (connection) {
        try {
          await connection.rollback();
        } catch {}
      }


      console.error(
        "❌ Error finalizando evaluación del empleado:",
        error
      );


      return res.status(500).json({
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


// ==================================================
// CANCELAR EVALUACIÓN
//
// PUT
// /api/empleados/:id/evaluaciones/:idHabilitacion/cancelar
// ==================================================

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
          req.params.idHabilitacion
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

        return res.status(400).json({
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

            WHERE id_habilitacion = ?
              AND id_empleado = ?

            LIMIT 1
          `,
          [
            idHabilitacion,
            idEmpleado
          ]
        );


      if (!rows.length) {

        return res.status(404).json({
          success: false,
          message:
            "Evaluación no encontrada"
        });

      }


      if (
        rows[0].estatus ===
        "completada"
      ) {

        return res.status(409).json({
          success: false,
          message:
            "Una evaluación completada no puede cancelarse"
        });

      }


      await pool.query(
        `
          UPDATE pruebas_empleados_habilitadas

          SET estatus = 'cancelada'

          WHERE id_habilitacion = ?
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


      return res.status(500).json({
        success: false,
        message:
          "Error interno al cancelar la evaluación"
      });

    }

  };