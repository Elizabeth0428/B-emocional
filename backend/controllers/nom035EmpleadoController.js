import crypto from "crypto";
import pool from "../config/database.js";

// ==================================================
// AUXILIAR: VALIDAR ACCESO RH AL EMPLEADO
// ==================================================
const validarAccesoEmpleado = async (idEmpleado, user) => {
  const idUsuario = user?.id_usuario;
  const tipoAdmin = user?.tipo_admin
    ? String(user.tipo_admin).trim().toLowerCase()
    : null;
  const area = user?.area
    ? String(user.area).trim().toLowerCase()
    : null;

  if (!idUsuario) {
    return {
      ok: false,
      status: 401,
      message: "No se pudo identificar al usuario"
    };
  }

  if (tipoAdmin !== "master" && area !== "rh") {
    return {
      ok: false,
      status: 403,
      message: "No tienes permiso para acceder al módulo NOM-035"
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

  const params = [idEmpleado];

  if (tipoAdmin !== "master") {
    query += ` AND id_admin_padre = ? `;
    params.push(idUsuario);
  }

  query += ` LIMIT 1 `;

  const [rows] = await pool.query(query, params);

  if (!rows.length) {
    return {
      ok: false,
      status: 404,
      message: "Empleado no encontrado o no tienes permiso para acceder a él"
    };
  }

  return {
    ok: true,
    empleado: rows[0]
  };
};


// ==================================================
// AUXILIAR: OBTENER APLICACIÓN POR TOKEN
// ==================================================
const obtenerAplicacionPorToken = async token => {
  const [rows] = await pool.query(
    `
      SELECT
        a.id_aplicacion,
        a.id_empleado,
        a.id_cuestionario,
        a.id_usuario_registro,
        a.token_publico,
        a.tipo_aplicacion,
        a.motivo,
        a.estatus,
        a.fecha_habilitacion,
        a.fecha_inicio,
        a.fecha_completada,

        e.id_mirror,
        e.nombre AS empleado_nombre,
        e.puesto,
        e.departamento,
        e.estatus AS empleado_estatus,

        c.clave,
        c.nombre AS cuestionario_nombre,
        c.descripcion AS cuestionario_descripcion,
        c.guia,
        c.tipo,
        c.version,
        c.activo AS cuestionario_activo

      FROM nom035_aplicaciones a

      INNER JOIN empleados e
        ON e.id_empleado = a.id_empleado

      INNER JOIN nom035_cuestionarios c
        ON c.id_cuestionario = a.id_cuestionario

      WHERE a.token_publico = ?
      LIMIT 1
    `,
    [token]
  );

  return rows.length ? rows[0] : null;
};


// ==================================================
// LISTAR CUESTIONARIOS NOM-035 DISPONIBLES
//
// GET /api/empleados/:id/nom035/cuestionarios
// ==================================================
export const listarCuestionariosNom035 = async (req, res) => {
  try {
    const idEmpleado = Number(req.params.id);

    if (!Number.isInteger(idEmpleado) || idEmpleado <= 0) {
      return res.status(400).json({
        success: false,
        message: "ID de empleado inválido"
      });
    }

    const acceso = await validarAccesoEmpleado(
      idEmpleado,
      req.user
    );

    if (!acceso.ok) {
      return res.status(acceso.status).json({
        success: false,
        message: acceso.message
      });
    }

    const [cuestionarios] = await pool.query(
      `
        SELECT
          id_cuestionario,
          clave,
          nombre,
          descripcion,
          guia,
          tipo,
          version,
          activo
        FROM nom035_cuestionarios
        WHERE activo = 1
        ORDER BY guia ASC, nombre ASC
      `
    );

    return res.json({
      success: true,
      empleado: acceso.empleado,
      cuestionarios
    });

  } catch (error) {
    console.error(
      "❌ Error listando cuestionarios NOM-035:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Error interno al obtener los cuestionarios NOM-035"
    });
  }
};


// ==================================================
// HABILITAR CUESTIONARIO
//
// POST /api/empleados/:id/nom035/habilitar
// ==================================================
export const habilitarNom035Empleado = async (req, res) => {
  try {
    const idEmpleado = Number(req.params.id);
    const idCuestionario = Number(
      req.body?.id_cuestionario
    );

    if (!Number.isInteger(idEmpleado) || idEmpleado <= 0) {
      return res.status(400).json({
        success: false,
        message: "ID de empleado inválido"
      });
    }

    if (
      !Number.isInteger(idCuestionario) ||
      idCuestionario <= 0
    ) {
      return res.status(400).json({
        success: false,
        message: "Selecciona un cuestionario válido"
      });
    }

    const acceso = await validarAccesoEmpleado(
      idEmpleado,
      req.user
    );

    if (!acceso.ok) {
      return res.status(acceso.status).json({
        success: false,
        message: acceso.message
      });
    }

    const tiposPermitidos = [
      "inicial",
      "periodica",
      "seguimiento",
      "extraordinaria"
    ];

    const tipoAplicacion = String(
      req.body?.tipo_aplicacion || "periodica"
    )
      .trim()
      .toLowerCase();

    if (!tiposPermitidos.includes(tipoAplicacion)) {
      return res.status(400).json({
        success: false,
        message: "Tipo de aplicación inválido"
      });
    }

    const motivo = req.body?.motivo
      ? String(req.body.motivo).trim()
      : null;

    const [cuestionarios] = await pool.query(
      `
        SELECT
          id_cuestionario,
          clave,
          nombre,
          descripcion,
          guia,
          tipo,
          version
        FROM nom035_cuestionarios
        WHERE id_cuestionario = ?
          AND activo = 1
        LIMIT 1
      `,
      [idCuestionario]
    );

    if (!cuestionarios.length) {
      return res.status(404).json({
        success: false,
        message:
          "El cuestionario NOM-035 no existe o está inactivo"
      });
    }

    const [activas] = await pool.query(
      `
        SELECT
          id_aplicacion,
          estatus,
          fecha_habilitacion
        FROM nom035_aplicaciones
        WHERE id_empleado = ?
          AND id_cuestionario = ?
          AND estatus IN ('habilitada', 'iniciada')
        LIMIT 1
      `,
      [
        idEmpleado,
        idCuestionario
      ]
    );

    if (activas.length) {
      return res.status(409).json({
        success: false,
        message:
          "El empleado ya tiene este cuestionario pendiente o iniciado",
        aplicacion: activas[0]
      });
    }

    const tokenPublico = crypto
      .randomBytes(32)
      .toString("hex");

    const [result] = await pool.query(
      `
        INSERT INTO nom035_aplicaciones
        (
          id_empleado,
          id_cuestionario,
          id_usuario_registro,
          token_publico,
          tipo_aplicacion,
          motivo,
          estatus,
          fecha_habilitacion
        )
        VALUES
        (
          ?, ?, ?, ?, ?, ?,
          'habilitada',
          NOW()
        )
      `,
      [
        idEmpleado,
        idCuestionario,
        req.user?.id_usuario || null,
        tokenPublico,
        tipoAplicacion,
        motivo
      ]
    );

    return res.status(201).json({
      success: true,
      message:
        "Cuestionario NOM-035 habilitado correctamente",

      aplicacion: {
        id_aplicacion: result.insertId,
        id_empleado: idEmpleado,
        id_cuestionario: idCuestionario,
        cuestionario: cuestionarios[0].nombre,
        guia: cuestionarios[0].guia,
        tipo_aplicacion: tipoAplicacion,
        motivo,
        token_publico: tokenPublico,
        estatus: "habilitada"
      }
    });

  } catch (error) {
    console.error(
      "❌ Error habilitando NOM-035:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Error interno al habilitar el cuestionario NOM-035",
      error:
        process.env.NODE_ENV === "development"
          ? error.message
          : undefined
    });
  }
};


// ==================================================
// LISTAR APLICACIONES DEL EMPLEADO
//
// GET /api/empleados/:id/nom035
// ==================================================
export const listarAplicacionesNom035Empleado =
  async (req, res) => {

    try {
      const idEmpleado = Number(req.params.id);

      if (
        !Number.isInteger(idEmpleado) ||
        idEmpleado <= 0
      ) {
        return res.status(400).json({
          success: false,
          message: "ID de empleado inválido"
        });
      }

      const acceso = await validarAccesoEmpleado(
        idEmpleado,
        req.user
      );

      if (!acceso.ok) {
        return res.status(acceso.status).json({
          success: false,
          message: acceso.message
        });
      }

      const [aplicaciones] = await pool.query(
        `
          SELECT
            a.id_aplicacion,
            a.id_cuestionario,
            a.token_publico,
            a.tipo_aplicacion,
            a.motivo,
            a.estatus,
            a.fecha_habilitacion,
            a.fecha_inicio,
            a.fecha_completada,

            c.clave,
            c.nombre AS cuestionario_nombre,
            c.descripcion AS cuestionario_descripcion,
            c.guia,
            c.tipo AS cuestionario_tipo,
            c.version,

            r.id_resultado,
            r.puntaje_total,
            r.nivel_riesgo,
            r.resultado_general,
            r.categorias,
            r.dominios,
            r.dimensiones,
            r.requiere_accion,
            r.recomendaciones,
            r.fecha_resultado

          FROM nom035_aplicaciones a

          INNER JOIN nom035_cuestionarios c
            ON c.id_cuestionario =
               a.id_cuestionario

          LEFT JOIN nom035_resultados r
            ON r.id_aplicacion =
               a.id_aplicacion

          WHERE a.id_empleado = ?

          ORDER BY
            a.fecha_habilitacion DESC,
            a.id_aplicacion DESC
        `,
        [idEmpleado]
      );

      return res.json({
        success: true,
        empleado: acceso.empleado,
        total: aplicaciones.length,
        aplicaciones
      });

    } catch (error) {
      console.error(
        "❌ Error listando aplicaciones NOM-035:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Error interno al obtener el historial NOM-035"
      });
    }
  };


// ==================================================
// OBTENER CUESTIONARIO PÚBLICO
//
// GET /api/empleados/nom035-publica/:token
//
// SIN LOGIN
// ==================================================
export const obtenerNom035Publica = async (req, res) => {
  try {
    const token = String(
      req.params.token || ""
    ).trim();

    if (!token) {
      return res.status(400).json({
        success: false,
        message: "Token inválido"
      });
    }

    const aplicacion =
      await obtenerAplicacionPorToken(token);

    if (!aplicacion) {
      return res.status(404).json({
        success: false,
        message: "Aplicación NOM-035 no encontrada"
      });
    }

    if (aplicacion.estatus === "cancelada") {
      return res.status(410).json({
        success: false,
        message: "Esta aplicación fue cancelada"
      });
    }

    if (aplicacion.estatus === "completada") {
      return res.status(409).json({
        success: false,
        message: "Este cuestionario ya fue completado"
      });
    }

    if (Number(aplicacion.cuestionario_activo) !== 1) {
      return res.status(410).json({
        success: false,
        message: "Este cuestionario ya no está disponible"
      });
    }

    if (aplicacion.estatus === "habilitada") {
      await pool.query(
        `
          UPDATE nom035_aplicaciones
          SET
            estatus = 'iniciada',
            fecha_inicio = COALESCE(fecha_inicio, NOW())
          WHERE id_aplicacion = ?
        `,
        [aplicacion.id_aplicacion]
      );
    }

    const [preguntas] = await pool.query(
      `
        SELECT
          id_pregunta,
          numero,
          seccion,
          categoria,
          dominio,
          dimension,
          texto_pregunta,
          tipo_respuesta,
          orden
        FROM nom035_preguntas
        WHERE id_cuestionario = ?
          AND activo = 1
        ORDER BY
          orden ASC,
          id_pregunta ASC
      `,
      [aplicacion.id_cuestionario]
    );

    let opciones = [];

    if (preguntas.length) {
      const ids = preguntas.map(
        item => item.id_pregunta
      );

      const placeholders = ids
        .map(() => "?")
        .join(",");

      const [rowsOpciones] = await pool.query(
        `
          SELECT
            id_opcion,
            id_pregunta,
            texto_opcion,
            valor,
            orden
          FROM nom035_opciones
          WHERE id_pregunta IN (${placeholders})
            AND activo = 1
          ORDER BY
            id_pregunta ASC,
            orden ASC,
            id_opcion ASC
        `,
        ids
      );

      opciones = rowsOpciones;
    }


    // ==================================================
    // RECUPERAR RESPUESTAS GUARDADAS
    // ==================================================

    const [respuestasGuardadas] = await pool.query(
      `
        SELECT
          id_pregunta,
          id_opcion,
          respuesta,
          valor
        FROM nom035_respuestas
        WHERE id_aplicacion = ?
      `,
      [aplicacion.id_aplicacion]
    );


    const preguntasConOpciones = preguntas.map(
      pregunta => {

        const respuestaActual =
          respuestasGuardadas.find(
            respuesta =>
              Number(respuesta.id_pregunta) ===
              Number(pregunta.id_pregunta)
          );

        return {
          ...pregunta,

          opciones: opciones.filter(
            opcion =>
              Number(opcion.id_pregunta) ===
              Number(pregunta.id_pregunta)
          ),

          respuesta_actual:
            respuestaActual
              ? {
                  id_opcion:
                    respuestaActual.id_opcion,
                  respuesta:
                    respuestaActual.respuesta,
                  valor:
                    respuestaActual.valor
                }
              : null
        };
      }
    );


    return res.json({
      success: true,

      aplicacion: {
        id_aplicacion:
          aplicacion.id_aplicacion,

        tipo_aplicacion:
          aplicacion.tipo_aplicacion,

        motivo:
          aplicacion.motivo,

        cuestionario: {
          id_cuestionario:
            aplicacion.id_cuestionario,

          clave:
            aplicacion.clave,

          nombre:
            aplicacion.cuestionario_nombre,

          descripcion:
            aplicacion.cuestionario_descripcion,

          guia:
            aplicacion.guia,

          tipo:
            aplicacion.tipo,

          version:
            aplicacion.version
        },

        empleado: {
          nombre:
            aplicacion.empleado_nombre,

          id_mirror:
            aplicacion.id_mirror,

          puesto:
            aplicacion.puesto,

          departamento:
            aplicacion.departamento
        },

        preguntas:
          preguntasConOpciones
      }
    });

  } catch (error) {
    console.error(
      "❌ Error obteniendo NOM-035 pública:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Error interno al cargar el cuestionario NOM-035"
    });
  }
};


// ==================================================
// GUARDAR RESPUESTAS
//
// POST
// /api/empleados/nom035-publica/:token/respuestas
// ==================================================
export const guardarRespuestasNom035 =
  async (req, res) => {

    let connection;

    try {
      const token = String(
        req.params.token || ""
      ).trim();

      const respuestas = Array.isArray(
        req.body?.respuestas
      )
        ? req.body.respuestas
        : [];

      if (!token) {
        return res.status(400).json({
          success: false,
          message: "Token inválido"
        });
      }

      if (!respuestas.length) {
        return res.status(400).json({
          success: false,
          message: "No se recibieron respuestas"
        });
      }

      const aplicacion =
        await obtenerAplicacionPorToken(token);

      if (!aplicacion) {
        return res.status(404).json({
          success: false,
          message:
            "Aplicación NOM-035 no encontrada"
        });
      }

      if (aplicacion.estatus === "cancelada") {
        return res.status(410).json({
          success: false,
          message:
            "Esta aplicación fue cancelada"
        });
      }

      if (aplicacion.estatus === "completada") {
        return res.status(409).json({
          success: false,
          message:
            "Este cuestionario ya fue completado"
        });
      }

      connection =
        await pool.getConnection();

      await connection.beginTransaction();

      await connection.query(
        `
          DELETE FROM nom035_respuestas
          WHERE id_aplicacion = ?
        `,
        [aplicacion.id_aplicacion]
      );

      const preguntasProcesadas = new Set();

      for (const item of respuestas) {
        const idPregunta =
          Number(item?.id_pregunta);

        const idOpcion =
          Number(item?.id_opcion);

        if (
          !Number.isInteger(idPregunta) ||
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

        preguntasProcesadas.add(idPregunta);

        const [preguntas] =
          await connection.query(
            `
              SELECT
                id_pregunta,
                tipo_respuesta
              FROM nom035_preguntas
              WHERE id_pregunta = ?
                AND id_cuestionario = ?
                AND activo = 1
              LIMIT 1
            `,
            [
              idPregunta,
              aplicacion.id_cuestionario
            ]
          );

        if (!preguntas.length) {
          await connection.rollback();

          return res.status(400).json({
            success: false,
            message:
              "Una de las preguntas no pertenece a este cuestionario"
          });
        }

        if (
          !Number.isInteger(idOpcion) ||
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
                id_opcion,
                texto_opcion,
                valor
              FROM nom035_opciones
              WHERE id_opcion = ?
                AND id_pregunta = ?
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

        await connection.query(
          `
            INSERT INTO nom035_respuestas
            (
              id_aplicacion,
              id_empleado,
              id_pregunta,
              id_opcion,
              respuesta,
              valor
            )
            VALUES (?, ?, ?, ?, ?, ?)
          `,
          [
            aplicacion.id_aplicacion,
            aplicacion.id_empleado,
            idPregunta,
            idOpcion,
            opciones[0].texto_opcion,
            opciones[0].valor
          ]
        );
      }

      await connection.query(
        `
          UPDATE nom035_aplicaciones
          SET
            estatus = 'iniciada',
            fecha_inicio =
              COALESCE(fecha_inicio, NOW())
          WHERE id_aplicacion = ?
        `,
        [aplicacion.id_aplicacion]
      );

      await connection.commit();

      return res.json({
        success: true,
        message:
          "Respuestas NOM-035 guardadas correctamente"
      });

    } catch (error) {
      if (connection) {
        try {
          await connection.rollback();
        } catch {}
      }

      console.error(
        "❌ Error guardando respuestas NOM-035:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Error interno al guardar las respuestas NOM-035"
      });

    } finally {
      if (connection) {
        connection.release();
      }
    }
  };


// ==================================================
// FINALIZAR CUESTIONARIO NOM-035
//
// GUÍA I:
// - 6 NO → termina.
// - algún SÍ → exige II, III y IV.
// - valoración clínica si:
//      II  >= 1 SÍ
//      III >= 3 SÍ
//      IV  >= 2 SÍ
//
// GUÍA II / III:
// todavía sin clasificación hasta cargar sus reglas.
// ==================================================
export const finalizarNom035 = async (req, res) => {
  let connection;

  try {
    const token = String(
      req.params.token || ""
    ).trim();

    if (!token) {
      return res.status(400).json({
        success: false,
        message: "Token inválido"
      });
    }

    const aplicacion =
      await obtenerAplicacionPorToken(token);

    if (!aplicacion) {
      return res.status(404).json({
        success: false,
        message:
          "Aplicación NOM-035 no encontrada"
      });
    }

    if (aplicacion.estatus === "cancelada") {
      return res.status(410).json({
        success: false,
        message:
          "Esta aplicación fue cancelada"
      });
    }

    if (aplicacion.estatus === "completada") {
      return res.status(409).json({
        success: false,
        message:
          "Este cuestionario ya fue completado"
      });
    }

    connection =
      await pool.getConnection();

    await connection.beginTransaction();

    const [preguntasRows] =
      await connection.query(
        `
          SELECT COUNT(*) AS total
          FROM nom035_preguntas
          WHERE id_cuestionario = ?
            AND activo = 1
        `,
        [aplicacion.id_cuestionario]
      );

    const totalPreguntas =
      Number(
        preguntasRows[0]?.total || 0
      );

    if (totalPreguntas === 0) {
      await connection.rollback();

      return res.status(400).json({
        success: false,
        message:
          "Este cuestionario no tiene preguntas activas"
      });
    }


    // ==================================================
    // GUÍA I
    // ==================================================

    if (
      String(aplicacion.guia) === "I"
    ) {

      const [seccionIRows] =
        await connection.query(
          `
            SELECT
              COUNT(
                DISTINCT r.id_pregunta
              ) AS total,

              COALESCE(
                SUM(
                  CASE
                    WHEN r.valor = 1
                    THEN 1
                    ELSE 0
                  END
                ),
                0
              ) AS respuestas_si

            FROM nom035_respuestas r

            INNER JOIN nom035_preguntas p
              ON p.id_pregunta =
                 r.id_pregunta

            WHERE r.id_aplicacion = ?
              AND p.orden BETWEEN 1 AND 6
          `,
          [aplicacion.id_aplicacion]
        );

      const totalSeccionI =
        Number(
          seccionIRows[0]?.total || 0
        );

      const siSeccionI =
        Number(
          seccionIRows[0]?.respuestas_si || 0
        );


      if (totalSeccionI < 6) {
        await connection.rollback();

        return res.status(400).json({
          success: false,
          message:
            "Debes responder las seis preguntas de la Sección I."
        });
      }


      // ==================================================
      // GUÍA I: TODAS LAS RESPUESTAS DE I SON NO
      // ==================================================

      if (siSeccionI === 0) {
        const resultadoGeneral =
          "No se identificó exposición al acontecimiento traumático severo en la Sección I, por lo que no se requiere continuar con las demás secciones de la Guía de Referencia I.";

        const recomendaciones =
          "No se requiere continuar con las secciones II, III y IV conforme a la lógica de la Guía de Referencia I.";

        const categorias = [
          {
            nombre:
              "Acontecimiento traumático severo",
            respuestas_si: 0
          }
        ];

        const [existentes] =
          await connection.query(
            `
              SELECT id_resultado
              FROM nom035_resultados
              WHERE id_aplicacion = ?
              LIMIT 1
            `,
            [aplicacion.id_aplicacion]
          );

        let idResultado;

        if (existentes.length) {
          idResultado =
            existentes[0].id_resultado;

          await connection.query(
            `
              UPDATE nom035_resultados
              SET
                puntaje_total = 0,
                nivel_riesgo = 'no_aplica',
                resultado_general = ?,
                categorias = ?,
                dominios = ?,
                dimensiones = ?,
                requiere_accion = 0,
                recomendaciones = ?,
                fecha_resultado = NOW()
              WHERE id_resultado = ?
            `,
            [
              resultadoGeneral,
              JSON.stringify(categorias),
              JSON.stringify([]),
              JSON.stringify([]),
              recomendaciones,
              idResultado
            ]
          );

        } else {
          const [result] =
            await connection.query(
              `
                INSERT INTO nom035_resultados
                (
                  id_aplicacion,
                  id_empleado,
                  id_cuestionario,
                  puntaje_total,
                  nivel_riesgo,
                  resultado_general,
                  categorias,
                  dominios,
                  dimensiones,
                  requiere_accion,
                  recomendaciones,
                  fecha_resultado
                )
                VALUES
                (
                  ?, ?, ?, 0,
                  'no_aplica',
                  ?, ?, ?, ?,
                  0,
                  ?,
                  NOW()
                )
              `,
              [
                aplicacion.id_aplicacion,
                aplicacion.id_empleado,
                aplicacion.id_cuestionario,
                resultadoGeneral,
                JSON.stringify(categorias),
                JSON.stringify([]),
                JSON.stringify([]),
                recomendaciones
              ]
            );

          idResultado =
            result.insertId;
        }

        await connection.query(
          `
            UPDATE nom035_aplicaciones
            SET
              estatus = 'completada',
              fecha_completada = NOW()
            WHERE id_aplicacion = ?
          `,
          [aplicacion.id_aplicacion]
        );

        await connection.commit();

        return res.json({
          success: true,
          message:
            "Guía I completada correctamente",

          resultado: {
            id_resultado:
              idResultado,

            guia: "I",

            respuestas_si: {
              seccion_i: 0,
              seccion_ii: 0,
              seccion_iii: 0,
              seccion_iv: 0
            },

            continuar_secciones:
              false,

            requiere_atencion_clinica:
              false,

            requiere_accion:
              false,

            resultado_general:
              resultadoGeneral,

            recomendaciones
          }
        });
      }


      // ==================================================
      // ALGÚN SÍ EN SECCIÓN I:
      // DEBE CONTESTAR TODO
      // ==================================================

      const [totalRespondidasRows] =
        await connection.query(
          `
            SELECT
              COUNT(
                DISTINCT id_pregunta
              ) AS total
            FROM nom035_respuestas
            WHERE id_aplicacion = ?
          `,
          [aplicacion.id_aplicacion]
        );

      const totalRespondidas =
        Number(
          totalRespondidasRows[0]?.total || 0
        );

      if (
        totalRespondidas <
        totalPreguntas
      ) {
        await connection.rollback();

        return res.status(400).json({
          success: false,
          message:
            `Al existir al menos una respuesta "Sí" en la Sección I, debes responder las secciones II, III y IV. Se respondieron ${totalRespondidas} de ${totalPreguntas} preguntas.`
        });
      }


      const [criteriosRows] =
        await connection.query(
          `
            SELECT

              COALESCE(
                SUM(
                  CASE
                    WHEN p.orden BETWEEN 7 AND 8
                     AND r.valor = 1
                    THEN 1
                    ELSE 0
                  END
                ),
                0
              ) AS seccion_ii,

              COALESCE(
                SUM(
                  CASE
                    WHEN p.orden BETWEEN 9 AND 15
                     AND r.valor = 1
                    THEN 1
                    ELSE 0
                  END
                ),
                0
              ) AS seccion_iii,

              COALESCE(
                SUM(
                  CASE
                    WHEN p.orden BETWEEN 16 AND 20
                     AND r.valor = 1
                    THEN 1
                    ELSE 0
                  END
                ),
                0
              ) AS seccion_iv,

              COALESCE(
                SUM(
                  CASE
                    WHEN r.valor = 1
                    THEN 1
                    ELSE 0
                  END
                ),
                0
              ) AS total_si

            FROM nom035_respuestas r

            INNER JOIN nom035_preguntas p
              ON p.id_pregunta =
                 r.id_pregunta

            WHERE r.id_aplicacion = ?
          `,
          [aplicacion.id_aplicacion]
        );


      const siSeccionII =
        Number(
          criteriosRows[0]?.seccion_ii || 0
        );

      const siSeccionIII =
        Number(
          criteriosRows[0]?.seccion_iii || 0
        );

      const siSeccionIV =
        Number(
          criteriosRows[0]?.seccion_iv || 0
        );

      const totalSi =
        Number(
          criteriosRows[0]?.total_si || 0
        );


      const requiereAtencionClinica =
        (
          siSeccionII >= 1 ||
          siSeccionIII >= 3 ||
          siSeccionIV >= 2
        );


      const resultadoGeneral =
        requiereAtencionClinica
          ? "La aplicación cumple al menos uno de los criterios de la Guía de Referencia I para requerir atención clínica."
          : "La aplicación no alcanza los criterios de la Guía de Referencia I para requerir atención clínica.";


      const recomendaciones =
        requiereAtencionClinica
          ? "Corresponde realizar la canalización para valoración clínica conforme a la Guía de Referencia I."
          : "No se identifica criterio de atención clínica derivado de esta guía. Mantener las medidas preventivas y de seguimiento laboral que correspondan.";


      const categorias = [
        {
          nombre:
            "Acontecimiento traumático severo",
          respuestas_si:
            siSeccionI
        },
        {
          nombre:
            "Recuerdos persistentes",
          respuestas_si:
            siSeccionII
        },
        {
          nombre:
            "Evitación",
          respuestas_si:
            siSeccionIII
        },
        {
          nombre:
            "Afectación",
          respuestas_si:
            siSeccionIV
        }
      ];


      const [existentes] =
        await connection.query(
          `
            SELECT id_resultado
            FROM nom035_resultados
            WHERE id_aplicacion = ?
            LIMIT 1
          `,
          [aplicacion.id_aplicacion]
        );


      let idResultado;


      if (existentes.length) {
        idResultado =
          existentes[0].id_resultado;

        await connection.query(
          `
            UPDATE nom035_resultados
            SET
              puntaje_total = ?,
              nivel_riesgo = 'no_aplica',
              resultado_general = ?,
              categorias = ?,
              dominios = ?,
              dimensiones = ?,
              requiere_accion = ?,
              recomendaciones = ?,
              fecha_resultado = NOW()
            WHERE id_resultado = ?
          `,
          [
            totalSi,
            resultadoGeneral,
            JSON.stringify(categorias),
            JSON.stringify([]),
            JSON.stringify([]),
            requiereAtencionClinica ? 1 : 0,
            recomendaciones,
            idResultado
          ]
        );

      } else {
        const [result] =
          await connection.query(
            `
              INSERT INTO nom035_resultados
              (
                id_aplicacion,
                id_empleado,
                id_cuestionario,
                puntaje_total,
                nivel_riesgo,
                resultado_general,
                categorias,
                dominios,
                dimensiones,
                requiere_accion,
                recomendaciones,
                fecha_resultado
              )
              VALUES
              (
                ?, ?, ?, ?,
                'no_aplica',
                ?, ?, ?, ?,
                ?, ?,
                NOW()
              )
            `,
            [
              aplicacion.id_aplicacion,
              aplicacion.id_empleado,
              aplicacion.id_cuestionario,
              totalSi,
              resultadoGeneral,
              JSON.stringify(categorias),
              JSON.stringify([]),
              JSON.stringify([]),
              requiereAtencionClinica ? 1 : 0,
              recomendaciones
            ]
          );

        idResultado =
          result.insertId;
      }


      await connection.query(
        `
          UPDATE nom035_aplicaciones
          SET
            estatus = 'completada',
            fecha_completada = NOW()
          WHERE id_aplicacion = ?
        `,
        [aplicacion.id_aplicacion]
      );


      await connection.commit();


      return res.json({
        success: true,
        message:
          "Guía I completada correctamente",

        resultado: {
          id_resultado:
            idResultado,

          guia: "I",

          respuestas_si: {
            seccion_i:
              siSeccionI,

            seccion_ii:
              siSeccionII,

            seccion_iii:
              siSeccionIII,

            seccion_iv:
              siSeccionIV
          },

          continuar_secciones:
            true,

          requiere_atencion_clinica:
            requiereAtencionClinica,

          requiere_accion:
            requiereAtencionClinica,

          resultado_general:
            resultadoGeneral,

          recomendaciones
        }
      });
    }


    // ==================================================
    // GUÍAS II Y III
    // ==================================================

    const [respuestasRows] =
      await connection.query(
        `
          SELECT
            COUNT(
              DISTINCT id_pregunta
            ) AS total
          FROM nom035_respuestas
          WHERE id_aplicacion = ?
        `,
        [aplicacion.id_aplicacion]
      );

    const totalRespuestas =
      Number(
        respuestasRows[0]?.total || 0
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


    const [puntajeRows] =
      await connection.query(
        `
          SELECT
            COALESCE(
              SUM(valor),
              0
            ) AS puntaje_total
          FROM nom035_respuestas
          WHERE id_aplicacion = ?
        `,
        [aplicacion.id_aplicacion]
      );


    const puntajeTotal =
      Number(
        puntajeRows[0]?.puntaje_total || 0
      );


    const [categoriasRows] =
      await connection.query(
        `
          SELECT
            p.categoria,
            COALESCE(
              SUM(r.valor),
              0
            ) AS puntaje
          FROM nom035_respuestas r
          INNER JOIN nom035_preguntas p
            ON p.id_pregunta =
               r.id_pregunta
          WHERE r.id_aplicacion = ?
            AND p.categoria IS NOT NULL
          GROUP BY p.categoria
        `,
        [aplicacion.id_aplicacion]
      );


    const [dominiosRows] =
      await connection.query(
        `
          SELECT
            p.dominio,
            COALESCE(
              SUM(r.valor),
              0
            ) AS puntaje
          FROM nom035_respuestas r
          INNER JOIN nom035_preguntas p
            ON p.id_pregunta =
               r.id_pregunta
          WHERE r.id_aplicacion = ?
            AND p.dominio IS NOT NULL
          GROUP BY p.dominio
        `,
        [aplicacion.id_aplicacion]
      );


    const [dimensionesRows] =
      await connection.query(
        `
          SELECT
            p.dimension,
            COALESCE(
              SUM(r.valor),
              0
            ) AS puntaje
          FROM nom035_respuestas r
          INNER JOIN nom035_preguntas p
            ON p.id_pregunta =
               r.id_pregunta
          WHERE r.id_aplicacion = ?
            AND p.dimension IS NOT NULL
          GROUP BY p.dimension
        `,
        [aplicacion.id_aplicacion]
      );


    const categorias =
      categoriasRows.map(
        item => ({
          nombre:
            item.categoria,

          puntaje:
            Number(
              item.puntaje || 0
            )
        })
      );


    const dominios =
      dominiosRows.map(
        item => ({
          nombre:
            item.dominio,

          puntaje:
            Number(
              item.puntaje || 0
            )
        })
      );


    const dimensiones =
      dimensionesRows.map(
        item => ({
          nombre:
            item.dimension,

          puntaje:
            Number(
              item.puntaje || 0
            )
        })
      );


    const [existentes] =
      await connection.query(
        `
          SELECT id_resultado
          FROM nom035_resultados
          WHERE id_aplicacion = ?
          LIMIT 1
        `,
        [aplicacion.id_aplicacion]
      );


    let idResultado;


    if (existentes.length) {
      idResultado =
        existentes[0].id_resultado;

      await connection.query(
        `
          UPDATE nom035_resultados
          SET
            puntaje_total = ?,
            nivel_riesgo = NULL,
            resultado_general = NULL,
            categorias = ?,
            dominios = ?,
            dimensiones = ?,
            requiere_accion = 0,
            recomendaciones = NULL,
            fecha_resultado = NOW()
          WHERE id_resultado = ?
        `,
        [
          puntajeTotal,
          JSON.stringify(categorias),
          JSON.stringify(dominios),
          JSON.stringify(dimensiones),
          idResultado
        ]
      );

    } else {
      const [result] =
        await connection.query(
          `
            INSERT INTO nom035_resultados
            (
              id_aplicacion,
              id_empleado,
              id_cuestionario,
              puntaje_total,
              nivel_riesgo,
              resultado_general,
              categorias,
              dominios,
              dimensiones,
              requiere_accion,
              recomendaciones,
              fecha_resultado
            )
            VALUES
            (
              ?, ?, ?, ?,
              NULL,
              NULL,
              ?, ?, ?,
              0,
              NULL,
              NOW()
            )
          `,
          [
            aplicacion.id_aplicacion,
            aplicacion.id_empleado,
            aplicacion.id_cuestionario,
            puntajeTotal,
            JSON.stringify(categorias),
            JSON.stringify(dominios),
            JSON.stringify(dimensiones)
          ]
        );

      idResultado =
        result.insertId;
    }


    await connection.query(
      `
        UPDATE nom035_aplicaciones
        SET
          estatus = 'completada',
          fecha_completada = NOW()
        WHERE id_aplicacion = ?
      `,
      [aplicacion.id_aplicacion]
    );


    await connection.commit();


    return res.json({
      success: true,
      message:
        "Cuestionario NOM-035 completado correctamente",

      resultado: {
        id_resultado:
          idResultado,

        id_aplicacion:
          aplicacion.id_aplicacion,

        id_empleado:
          aplicacion.id_empleado,

        id_cuestionario:
          aplicacion.id_cuestionario,

        guia:
          aplicacion.guia,

        puntaje_total:
          puntajeTotal,

        categorias,
        dominios,
        dimensiones,

        nivel_riesgo:
          null,

        requiere_accion:
          false
      }
    });


  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch {}
    }

    console.error(
      "❌ Error finalizando NOM-035:",
      error
    );

    return res.status(500).json({
      success: false,
      message:
        "Error interno al finalizar el cuestionario NOM-035",
      error:
        process.env.NODE_ENV === "development"
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
// CANCELAR APLICACIÓN
//
// PUT /api/empleados/:id/nom035/:idAplicacion/cancelar
// ==================================================
export const cancelarNom035Empleado =
  async (req, res) => {

    try {
      const idEmpleado =
        Number(req.params.id);

      const idAplicacion =
        Number(req.params.idAplicacion);

      if (
        !Number.isInteger(idEmpleado) ||
        idEmpleado <= 0 ||
        !Number.isInteger(idAplicacion) ||
        idAplicacion <= 0
      ) {
        return res.status(400).json({
          success: false,
          message:
            "Datos de aplicación inválidos"
        });
      }

      const acceso =
        await validarAccesoEmpleado(
          idEmpleado,
          req.user
        );

      if (!acceso.ok) {
        return res
          .status(acceso.status)
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
              id_aplicacion,
              estatus
            FROM nom035_aplicaciones
            WHERE id_aplicacion = ?
              AND id_empleado = ?
            LIMIT 1
          `,
          [
            idAplicacion,
            idEmpleado
          ]
        );

      if (!rows.length) {
        return res.status(404).json({
          success: false,
          message:
            "Aplicación NOM-035 no encontrada"
        });
      }

      if (
        rows[0].estatus ===
        "completada"
      ) {
        return res.status(409).json({
          success: false,
          message:
            "Una aplicación completada no puede cancelarse"
        });
      }

      await pool.query(
        `
          UPDATE nom035_aplicaciones
          SET estatus = 'cancelada'
          WHERE id_aplicacion = ?
            AND id_empleado = ?
        `,
        [
          idAplicacion,
          idEmpleado
        ]
      );

      return res.json({
        success: true,
        message:
          "Aplicación NOM-035 cancelada correctamente"
      });

    } catch (error) {
      console.error(
        "❌ Error cancelando NOM-035:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Error interno al cancelar la aplicación NOM-035"
      });
    }
  };


// ==================================================
// OBTENER RESULTADOS NOM-035 DEL EMPLEADO
//
// GET /api/empleados/:id/nom035/resultados
// ==================================================
export const obtenerResultadosNom035Empleado =
  async (req, res) => {

    try {
      const idEmpleado =
        Number(req.params.id);

      if (
        !Number.isInteger(idEmpleado) ||
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
          .status(acceso.status)
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
              r.id_aplicacion,
              r.id_empleado,
              r.id_cuestionario,
              r.puntaje_total,
              r.nivel_riesgo,
              r.resultado_general,
              r.categorias,
              r.dominios,
              r.dimensiones,
              r.requiere_accion,
              r.recomendaciones,
              r.fecha_resultado,

              c.clave,
              c.nombre AS cuestionario_nombre,
              c.guia,
              c.tipo AS cuestionario_tipo,
              c.version,

              a.tipo_aplicacion,
              a.motivo,
              a.fecha_habilitacion,
              a.fecha_completada

            FROM nom035_resultados r

            INNER JOIN nom035_cuestionarios c
              ON c.id_cuestionario =
                 r.id_cuestionario

            INNER JOIN nom035_aplicaciones a
              ON a.id_aplicacion =
                 r.id_aplicacion

            WHERE r.id_empleado = ?

            ORDER BY
              r.fecha_resultado DESC,
              r.id_resultado DESC
          `,
          [idEmpleado]
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
        "❌ Error obteniendo resultados NOM-035:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          "Error interno al obtener los resultados NOM-035"
      });
    }
  };