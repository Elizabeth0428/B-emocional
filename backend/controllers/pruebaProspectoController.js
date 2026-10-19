// ==================================================
// backend/controllers/pruebaProspectoController.js
// ==================================================
import crypto from "crypto";
import pool from "../config/database.js";

// ==================================================
// AUXILIAR: VALIDAR ACCESO RH AL PROSPECTO
// ==================================================
const validarAccesoProspecto = async (idProspecto, user) => {
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
      message: "No se pudo identificar al usuario",
    };
  }

  if (tipoAdmin !== "master" && area !== "rh") {
    return {
      ok: false,
      status: 403,
      message: "No tienes permiso para acceder a pruebas psicométricas de RH",
    };
  }

  let query = `
    SELECT
      id_prospecto,
      id_mirror,
      nombre,
      correo,
      puesto,
      estatus,
      id_admin_padre
    FROM prospectos
    WHERE id_prospecto = ?
  `;

  const params = [idProspecto];

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
      message: "Prospecto no encontrado o no tienes permiso para acceder a él",
    };
  }

  return {
    ok: true,
    prospecto: rows[0],
  };
};

// ==================================================
// AUXILIAR: OBTENER HABILITACIÓN POR TOKEN
// ==================================================
const obtenerHabilitacionPorToken = async (
  token,
  connection = pool
) => {
  const [rows] = await connection.query(
    `
      SELECT
        h.id_habilitacion,
        h.id_prospecto,
        h.id_prueba_rh,
        h.token_publico,
        h.estatus,
        h.fecha_habilitacion,
        h.fecha_inicio,
        h.fecha_completada,

        p.nombre AS prospecto_nombre,
        p.id_mirror,
        p.puesto,
        p.correo,

        pr.nombre AS prueba_nombre,
        pr.descripcion AS prueba_descripcion,
        pr.categoria,
        pr.version

      FROM pruebas_prospectos_habilitadas h

      INNER JOIN prospectos p
        ON p.id_prospecto = h.id_prospecto

      INNER JOIN pruebas_rh pr
        ON pr.id_prueba_rh = h.id_prueba_rh

      WHERE h.token_publico = ?

      LIMIT 1
    `,
    [token]
  );

  return rows[0] || null;
};

// ==================================================
// LISTAR PRUEBAS PSICOMÉTRICAS DISPONIBLES
// GET /api/prospectos/:id/pruebas/disponibles
// ==================================================
export const listarPruebasDisponiblesProspecto =
  async (req, res) => {
    try {
      const idProspecto = Number(req.params.id);

      if (!Number.isInteger(idProspecto) || idProspecto <= 0) {
        return res.status(400).json({
          success: false,
          message: "ID de prospecto inválido",
        });
      }

      const acceso = await validarAccesoProspecto(
        idProspecto,
        req.user
      );

      if (!acceso.ok) {
        return res.status(acceso.status).json({
          success: false,
          message: acceso.message,
        });
      }

      const [pruebas] = await pool.query(
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
          ORDER BY nombre ASC
        `
      );

      return res.json({
        success: true,
        prospecto: acceso.prospecto,
        pruebas,
      });

    } catch (error) {
      console.error(
        "❌ Error al obtener pruebas RH:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Error interno al obtener las pruebas psicométricas",
        error:
          process.env.NODE_ENV === "development"
            ? error.message
            : undefined,
      });
    }
  };

// ==================================================
// HABILITAR PRUEBA PSICOMÉTRICA
// POST /api/prospectos/:id/pruebas/habilitar
// BODY: { id_prueba_rh }
// ==================================================
export const habilitarPruebaProspecto =
  async (req, res) => {
    let connection;

    try {
      const idProspecto = Number(req.params.id);

      const idPruebaRH = Number(
        req.body?.id_prueba_rh
      );

      if (!Number.isInteger(idProspecto) || idProspecto <= 0) {
        return res.status(400).json({
          success: false,
          message: "ID de prospecto inválido",
        });
      }

      if (!Number.isInteger(idPruebaRH) || idPruebaRH <= 0) {
        return res.status(400).json({
          success: false,
          message: "La prueba psicométrica seleccionada es inválida",
        });
      }

      const acceso = await validarAccesoProspecto(
        idProspecto,
        req.user
      );

      if (!acceso.ok) {
        return res.status(acceso.status).json({
          success: false,
          message: acceso.message,
        });
      }

      connection = await pool.getConnection();
      await connection.beginTransaction();

      // ================================================
      // VALIDAR PRUEBA RH
      // ================================================
      const [pruebas] = await connection.query(
        `
          SELECT
            id_prueba_rh,
            nombre,
            activo
          FROM pruebas_rh
          WHERE id_prueba_rh = ?
          LIMIT 1
        `,
        [idPruebaRH]
      );

      if (!pruebas.length) {
        await connection.rollback();

        return res.status(404).json({
          success: false,
          message: "La prueba psicométrica no existe",
        });
      }

      if (!Number(pruebas[0].activo)) {
        await connection.rollback();

        return res.status(400).json({
          success: false,
          message: "La prueba psicométrica se encuentra inactiva",
        });
      }

      // ================================================
      // EVITAR HABILITACIÓN DUPLICADA ACTIVA
      // ================================================
      const [existentes] = await connection.query(
        `
          SELECT
            id_habilitacion,
            estatus,
            token_publico
          FROM pruebas_prospectos_habilitadas
          WHERE id_prospecto = ?
            AND id_prueba_rh = ?
            AND estatus IN ('habilitada','iniciada')
          ORDER BY id_habilitacion DESC
          LIMIT 1
        `,
        [
          idProspecto,
          idPruebaRH,
        ]
      );

      if (existentes.length) {
        await connection.rollback();

        return res.status(409).json({
          success: false,
          message: "Esta prueba ya está habilitada para el prospecto",
          habilitacion: existentes[0],
        });
      }

      // ================================================
      // TOKEN PÚBLICO
      // ================================================
      const tokenPublico =
        crypto.randomBytes(32).toString("hex");

      const [insert] = await connection.query(
        `
          INSERT INTO pruebas_prospectos_habilitadas
          (
            id_prospecto,
            id_prueba_rh,
            id_usuario_registro,
            token_publico,
            estatus,
            fecha_habilitacion,
            creado_en
          )
          VALUES (?, ?, ?, ?, 'habilitada', NOW(), NOW())
        `,
        [
          idProspecto,
          idPruebaRH,
          req.user?.id_usuario || null,
          tokenPublico,
        ]
      );

      await connection.commit();

      return res.status(201).json({
        success: true,
        message: "Prueba psicométrica habilitada correctamente",

        habilitacion: {
          id_habilitacion: insert.insertId,
          id_prospecto: idProspecto,
          id_prueba_rh: idPruebaRH,
          prueba_nombre: pruebas[0].nombre,
          token_publico: tokenPublico,
          estatus: "habilitada",
        },
      });

    } catch (error) {
      if (connection) {
        try {
          await connection.rollback();
        } catch {}
      }

      console.error(
        "❌ Error al habilitar prueba RH:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Error interno al habilitar la prueba psicométrica",
        error:
          process.env.NODE_ENV === "development"
            ? error.message
            : undefined,
      });

    } finally {
      if (connection) {
        connection.release();
      }
    }
  };

// ==================================================
// LISTAR PRUEBAS HABILITADAS DEL PROSPECTO
// GET /api/prospectos/:id/pruebas
// ==================================================
export const listarPruebasProspecto =
  async (req, res) => {
    try {
      const idProspecto = Number(req.params.id);

      if (!Number.isInteger(idProspecto) || idProspecto <= 0) {
        return res.status(400).json({
          success: false,
          message: "ID de prospecto inválido",
        });
      }

      const acceso = await validarAccesoProspecto(
        idProspecto,
        req.user
      );

      if (!acceso.ok) {
        return res.status(acceso.status).json({
          success: false,
          message: acceso.message,
        });
      }

      const [pruebas] = await pool.query(
        `
          SELECT
            h.id_habilitacion,
            h.id_prospecto,
            h.id_prueba_rh,
            h.id_usuario_registro,
            h.token_publico,
            h.estatus,
            h.fecha_habilitacion,
            h.fecha_inicio,
            h.fecha_completada,

            pr.nombre,
            pr.descripcion,
            pr.categoria,
            pr.version,

            r.id_resultado,
            r.puntaje_total,
            r.resultado_texto,
            r.interpretacion,
            r.interpretacion_laboral,
            r.fortalezas,
            r.areas_atencion,
            r.compatibilidad_puesto,
            r.recomendaciones,
            r.generado_por_ia,
            r.fecha_resultado,

            u.nombre AS usuario_registro

          FROM pruebas_prospectos_habilitadas h

          INNER JOIN pruebas_rh pr
            ON pr.id_prueba_rh = h.id_prueba_rh

          LEFT JOIN resultados_prueba_prospecto r
            ON r.id_habilitacion = h.id_habilitacion

          LEFT JOIN usuarios u
            ON u.id_usuario = h.id_usuario_registro

          WHERE h.id_prospecto = ?

          ORDER BY
            h.fecha_habilitacion DESC,
            h.id_habilitacion DESC
        `,
        [idProspecto]
      );

      return res.json({
        success: true,
        prospecto: acceso.prospecto,
        pruebas,
      });

    } catch (error) {
      console.error(
        "❌ Error al listar pruebas del prospecto:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Error interno al obtener las pruebas del prospecto",
        error:
          process.env.NODE_ENV === "development"
            ? error.message
            : undefined,
      });
    }
  };

// ==================================================
// RESULTADOS DE PRUEBAS DEL PROSPECTO
// GET /api/prospectos/:id/pruebas/resultados
// ==================================================
export const obtenerResultadosPruebasProspecto =
  async (req, res) => {
    try {
      const idProspecto = Number(req.params.id);

      if (!Number.isInteger(idProspecto) || idProspecto <= 0) {
        return res.status(400).json({
          success: false,
          message: "ID de prospecto inválido",
        });
      }

      const acceso = await validarAccesoProspecto(
        idProspecto,
        req.user
      );

      if (!acceso.ok) {
        return res.status(acceso.status).json({
          success: false,
          message: acceso.message,
        });
      }

      const [resultados] = await pool.query(
        `
          SELECT
            r.id_resultado,
            r.id_habilitacion,
            r.id_prospecto,
            r.id_prueba_rh,
            r.puntaje_total,
            r.resultado_texto,
            r.interpretacion,
            r.interpretacion_laboral,
            r.fortalezas,
            r.areas_atencion,
            r.compatibilidad_puesto,
            r.recomendaciones,
            r.generado_por_ia,
            r.fecha_resultado,

            pr.nombre,
            pr.descripcion,
            pr.categoria,
            pr.version

          FROM resultados_prueba_prospecto r

          INNER JOIN pruebas_rh pr
            ON pr.id_prueba_rh = r.id_prueba_rh

          WHERE r.id_prospecto = ?

          ORDER BY
            r.fecha_resultado DESC,
            r.id_resultado DESC
        `,
        [idProspecto]
      );

      return res.json({
        success: true,
        prospecto: acceso.prospecto,
        resultados,
      });

    } catch (error) {
      console.error(
        "❌ Error al obtener resultados RH:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Error interno al obtener los resultados psicométricos",
        error:
          process.env.NODE_ENV === "development"
            ? error.message
            : undefined,
      });
    }
  };

// ==================================================
// OBTENER PRUEBA PÚBLICA COMPLETA
// GET /api/prospectos/prueba-publica/:token
// SIN LOGIN
// ==================================================
export const obtenerPruebaPublicaProspecto =
  async (req, res) => {
    try {
      const token =
        String(req.params.token || "").trim();

      if (!token) {
        return res.status(400).json({
          success: false,
          message: "Token de prueba inválido",
        });
      }

      const habilitacion =
        await obtenerHabilitacionPorToken(token);

      if (!habilitacion) {
        return res.status(404).json({
          success: false,
          message: "Prueba psicométrica no encontrada",
        });
      }

      if (habilitacion.estatus === "cancelada") {
        return res.status(410).json({
          success: false,
          message: "Esta prueba fue cancelada",
        });
      }

      if (habilitacion.estatus === "completada") {
        return res.status(409).json({
          success: false,
          message: "Esta prueba ya fue completada",
        });
      }

      if (habilitacion.estatus === "habilitada") {
        await pool.query(
          `
            UPDATE pruebas_prospectos_habilitadas
            SET
              estatus = 'iniciada',
              fecha_inicio = COALESCE(fecha_inicio, NOW())
            WHERE id_habilitacion = ?
          `,
          [habilitacion.id_habilitacion]
        );

        habilitacion.estatus = "iniciada";
      }

      const [preguntas] = await pool.query(
        `
          SELECT
            id_pregunta_rh,
            id_prueba_rh,
            texto_pregunta,
            tipo_respuesta,
            orden
          FROM preguntas_prueba_rh
          WHERE id_prueba_rh = ?
            AND activo = 1
          ORDER BY orden ASC, id_pregunta_rh ASC
        `,
        [habilitacion.id_prueba_rh]
      );

      for (const pregunta of preguntas) {
        const [opciones] = await pool.query(
          `
            SELECT
              id_opcion_rh,
              id_pregunta_rh,
              texto_opcion,
              valor,
              orden
            FROM opciones_respuesta_rh
            WHERE id_pregunta_rh = ?
              AND activo = 1
            ORDER BY orden ASC, id_opcion_rh ASC
          `,
          [pregunta.id_pregunta_rh]
        );

        pregunta.opciones = opciones;
      }

      return res.json({
        success: true,

        prueba: {
          id_habilitacion:
            habilitacion.id_habilitacion,

          id_prospecto:
            habilitacion.id_prospecto,

          id_prueba_rh:
            habilitacion.id_prueba_rh,

          nombre:
            habilitacion.prueba_nombre,

          descripcion:
            habilitacion.prueba_descripcion,

          categoria:
            habilitacion.categoria,

          version:
            habilitacion.version,

          prospecto_nombre:
            habilitacion.prospecto_nombre,

          id_mirror:
            habilitacion.id_mirror,

          puesto:
            habilitacion.puesto,

          estatus:
            habilitacion.estatus,

          preguntas,
        },
      });

    } catch (error) {
      console.error(
        "❌ Error al cargar prueba pública RH:",
        error
      );

      return res.status(500).json({
        success: false,
        message: "Error interno al cargar la prueba psicométrica",
      });
    }
  };

  // ==================================================
// GUARDAR RESPUESTAS PÚBLICAS
// POST /api/prospectos/prueba-publica/:token/respuestas
// ==================================================
export const guardarRespuestasPruebaProspecto =
  async (req, res) => {
    let connection;

    try {
      const token =
        String(req.params.token || "").trim();

      const respuestas =
        req.body?.respuestas;

      if (!token) {
        return res.status(400).json({
          success: false,
          message: "Token inválido",
        });
      }

      if (!Array.isArray(respuestas) || !respuestas.length) {
        return res.status(400).json({
          success: false,
          message: "No se recibieron respuestas",
        });
      }

      connection =
        await pool.getConnection();

      await connection.beginTransaction();

      const habilitacion =
        await obtenerHabilitacionPorToken(
          token,
          connection
        );

      if (!habilitacion) {
        await connection.rollback();

        return res.status(404).json({
          success: false,
          message: "Prueba no encontrada",
        });
      }

      if (habilitacion.estatus === "cancelada") {
        await connection.rollback();

        return res.status(410).json({
          success: false,
          message: "Esta prueba fue cancelada",
        });
      }

      if (habilitacion.estatus === "completada") {
        await connection.rollback();

        return res.status(409).json({
          success: false,
          message: "Esta prueba ya fue completada",
        });
      }

      await connection.query(
        `
          DELETE FROM respuestas_prueba_prospecto
          WHERE id_habilitacion = ?
        `,
        [habilitacion.id_habilitacion]
      );

      for (const item of respuestas) {
        const idPreguntaRH =
          Number(item.id_pregunta_rh);

        if (
          !Number.isInteger(idPreguntaRH) ||
          idPreguntaRH <= 0
        ) {
          throw new Error(
            "Se recibió una pregunta inválida"
          );
        }

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
              idPreguntaRH,
              habilitacion.id_prueba_rh,
            ]
          );

        if (!preguntas.length) {
          throw new Error(
            "Una de las preguntas no pertenece a esta prueba"
          );
        }

        const pregunta =
          preguntas[0];

        let respuestaTexto = null;
        let valorRespuesta = null;

        if (
          pregunta.tipo_respuesta === "opcion" ||
          pregunta.tipo_respuesta === "escala"
        ) {
          const idOpcionRH =
            Number(item.id_opcion_rh);

          if (
            !Number.isInteger(idOpcionRH) ||
            idOpcionRH <= 0
          ) {
            throw new Error(
              "Falta seleccionar una respuesta"
            );
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
                idOpcionRH,
                idPreguntaRH,
              ]
            );

          if (!opciones.length) {
            throw new Error(
              "La opción seleccionada no corresponde a la pregunta"
            );
          }

          respuestaTexto =
            opciones[0].texto_opcion;

          valorRespuesta =
            opciones[0].valor !== null
              ? Number(opciones[0].valor)
              : null;
        }

        if (
          pregunta.tipo_respuesta === "abierta"
        ) {
          respuestaTexto =
            item.respuesta !== undefined &&
            item.respuesta !== null
              ? String(item.respuesta).trim()
              : null;

          valorRespuesta = null;
        }

        await connection.query(
          `
            INSERT INTO respuestas_prueba_prospecto
            (
              id_habilitacion,
              id_prospecto,
              id_prueba_rh,
              id_pregunta_rh,
              respuesta,
              valor_respuesta,
              creado_en
            )
            VALUES (?, ?, ?, ?, ?, ?, NOW())
          `,
          [
            habilitacion.id_habilitacion,
            habilitacion.id_prospecto,
            habilitacion.id_prueba_rh,
            idPreguntaRH,
            respuestaTexto,
            valorRespuesta,
          ]
        );
      }

      await connection.query(
        `
          UPDATE pruebas_prospectos_habilitadas
          SET
            estatus = 'iniciada',
            fecha_inicio = COALESCE(fecha_inicio, NOW())
          WHERE id_habilitacion = ?
        `,
        [habilitacion.id_habilitacion]
      );

      await connection.commit();

      return res.json({
        success: true,
        message: "Respuestas guardadas correctamente",
      });

    } catch (error) {
      if (connection) {
        try {
          await connection.rollback();
        } catch {}
      }

      console.error(
        "❌ Error guardando respuestas RH:",
        error
      );

      return res.status(500).json({
        success: false,
        message:
          error.message ||
          "Error interno al guardar las respuestas",
      });

    } finally {
      if (connection) {
        connection.release();
      }
    }
  };

// ==================================================
// AUXILIAR: IDENTIFICAR IPIP-50 BIG FIVE
// ==================================================
const esIPIP50 = (habilitacion) => {
  const nombre =
    String(
      habilitacion?.prueba_nombre || ""
    )
      .trim()
      .toLowerCase();

  const version =
    String(
      habilitacion?.version || ""
    )
      .trim()
      .toLowerCase();

  return (
    nombre === "ipip-50 big five" ||
    version === "ipip-bffm-50 es-mx"
  );
};

// ==================================================
// AUXILIAR: CALCULAR IPIP-50
// ==================================================
const calcularIPIP50 = async (
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

        FROM respuestas_prueba_prospecto r

        INNER JOIN preguntas_prueba_rh p
          ON p.id_pregunta_rh =
             r.id_pregunta_rh

        WHERE r.id_habilitacion = ?
          AND p.activo = 1

        ORDER BY
          p.orden ASC,
          p.id_pregunta_rh ASC
      `,
      [
        idHabilitacion
      ]
    );

  if (filas.length !== 50) {
    throw new Error(
      `El IPIP-50 requiere exactamente 50 respuestas válidas. Se encontraron ${filas.length}.`
    );
  }

  const dimensionesEsperadas = {
    "extraversión": {
      etiqueta: "Extraversión",
      puntaje: 0,
      reactivos: 0
    },

    "amabilidad": {
      etiqueta: "Amabilidad",
      puntaje: 0,
      reactivos: 0
    },

    "responsabilidad": {
      etiqueta: "Responsabilidad",
      puntaje: 0,
      reactivos: 0
    },

    "estabilidad_emocional": {
      etiqueta: "Estabilidad emocional",
      puntaje: 0,
      reactivos: 0
    },

    "intelecto": {
      etiqueta: "Intelecto / Apertura",
      puntaje: 0,
      reactivos: 0
    }
  };

  for (const fila of filas) {
    const dimension =
      String(
        fila.dimension || ""
      )
        .trim()
        .toLowerCase();

    if (
      !Object.prototype.hasOwnProperty.call(
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

    const esInvertida =
      Number(
        fila.invertida
      ) === 1;

    const valorCorregido =
      esInvertida
        ? 6 - valorOriginal
        : valorOriginal;

    dimensionesEsperadas[
      dimension
    ].puntaje +=
      valorCorregido;

    dimensionesEsperadas[
      dimension
    ].reactivos +=
      1;
  }

  for (
    const [
      codigoDimension,
      datos
    ] of Object.entries(
      dimensionesEsperadas
    )
  ) {
    if (
      datos.reactivos !== 10
    ) {
      throw new Error(
        `La dimensión ${codigoDimension} debe contener 10 reactivos y se encontraron ${datos.reactivos}.`
      );
    }
  }

  const dimensiones =
    Object.fromEntries(
      Object.entries(
        dimensionesEsperadas
      ).map(
        ([
          codigo,
          datos
        ]) => [
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
    Object.values(
      dimensiones
    ).reduce(
      (
        suma,
        item
      ) =>
        suma +
        Number(
          item.puntaje || 0
        ),
      0
    );

  const resultadoTexto = [
    "IPIP-50 Big Five — puntuación por dimensiones",
    "",
    ...Object.values(
      dimensiones
    ).map(
      item =>
        `${item.etiqueta}: ${item.puntaje}/50`
    ),
    "",
    "Los reactivos invertidos fueron recodificados antes de calcular cada dimensión.",
    "El IPIP-50 se interpreta por dimensiones. El puntaje acumulado no debe utilizarse como una medida global de personalidad, aptitud ni decisión de contratación.",
    "No se aplicaron puntos de corte ni categorías bajo/medio/alto sin una referencia normativa definida para la población evaluada."
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

// ==================================================
// AUXILIAR: IDENTIFICAR ORVIS-92
// ==================================================
const esORVIS92 = (habilitacion) => {
  const nombre =
    String(
      habilitacion?.prueba_nombre || ""
    )
      .trim()
      .toLowerCase();

  const version =
    String(
      habilitacion?.version || ""
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

// ==================================================
// AUXILIAR: CALCULAR ORVIS-92
// ==================================================
const calcularORVIS92 = async (
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

        FROM respuestas_prueba_prospecto r

        INNER JOIN preguntas_prueba_rh p
          ON p.id_pregunta_rh =
             r.id_pregunta_rh

        WHERE r.id_habilitacion = ?
          AND p.activo = 1

        ORDER BY
          p.orden ASC,
          p.id_pregunta_rh ASC
      `,
      [
        idHabilitacion
      ]
    );

  if (filas.length !== 92) {
    throw new Error(
      `ORVIS-92 requiere exactamente 92 respuestas válidas. Se encontraron ${filas.length}.`
    );
  }

  const dimensionesEsperadas = {
    leadership: {
      etiqueta: "Liderazgo",
      esperados: 12,
      suma: 0,
      reactivos: 0
    },

    organization: {
      etiqueta: "Organización",
      esperados: 13,
      suma: 0,
      reactivos: 0
    },

    altruism: {
      etiqueta: "Altruismo",
      esperados: 13,
      suma: 0,
      reactivos: 0
    },

    creativity: {
      etiqueta: "Creatividad",
      esperados: 14,
      suma: 0,
      reactivos: 0
    },

    analysis: {
      etiqueta: "Análisis",
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
      etiqueta: "Aventura",
      esperados: 10,
      suma: 0,
      reactivos: 0
    },

    erudition: {
      etiqueta: "Erudición",
      esperados: 10,
      suma: 0,
      reactivos: 0
    }
  };

  for (const fila of filas) {
    const dimension =
      String(
        fila.dimension || ""
      )
        .trim()
        .toLowerCase();

    if (
      !Object.prototype.hasOwnProperty.call(
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
        `La pregunta ${fila.codigo || fila.id_pregunta_rh} está marcada como invertida, pero la configuración ORVIS-92 cargada en MirrorSoul usa reactivos directos.`
      );
    }

    const valor =
      Number(
        fila.valor_respuesta
      );

    if (
      !Number.isFinite(valor) ||
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
    ].reactivos +=
      1;
  }

  for (
    const [
      codigoDimension,
      datos
    ] of Object.entries(
      dimensionesEsperadas
    )
  ) {
    if (
      datos.reactivos !==
      datos.esperados
    ) {
      throw new Error(
        `La dimensión ${codigoDimension} debe contener ${datos.esperados} reactivos y se encontraron ${datos.reactivos}.`
      );
    }
  }

  const dimensiones =
    Object.fromEntries(
      Object.entries(
        dimensionesEsperadas
      ).map(
        ([
          codigo,
          datos
        ]) => [
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
              datos.reactivos * 5,

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
    Object.values(
      dimensiones
    ).reduce(
      (
        suma,
        item
      ) =>
        suma +
        Number(
          item.suma || 0
        ),
      0
    );

  const resultadoTexto = [
    "ORVIS-92 — perfil de intereses vocacionales",
    "",
    ...Object.values(
      dimensiones
    ).map(
      item =>
        `${item.etiqueta}: suma ${item.suma}/${item.maximo_suma} | promedio ${item.promedio}/5 | ${item.reactivos} reactivos`
    ),
    "",
    "Las ocho escalas tienen diferente número de reactivos; por eso MirrorSoul conserva tanto la suma bruta como el promedio 1–5 de cada dimensión.",
    "No se aplicaron puntos de corte ni categorías alto/medio/bajo.",
    "El perfil describe intereses expresados y no determina por sí solo aptitud, contratación, rechazo ni diagnóstico psicológico."
  ].join("\n");

  const interpretacion =
    "Resultados calculados por las ocho escalas configuradas para ORVIS-92. Cada respuesta conserva su valor directo de 1 a 5; se reportan suma bruta y promedio por dimensión.";

  const interpretacionLaboral =
    "Uso descriptivo como apoyo para Recursos Humanos. El perfil puede ayudar a explorar áreas de interés laboral y vocacional, pero no constituye por sí solo una decisión de contratación ni una medida diagnóstica.";

  return {
    puntajeTecnicoAcumulado,
    resultadoTexto,
    interpretacion,
    interpretacionLaboral,
    dimensiones
  };
};

// ==================================================
// FINALIZAR PRUEBA PSICOMÉTRICA
// POST /api/prospectos/prueba-publica/:token/finalizar
// ==================================================
export const finalizarPruebaProspecto =
  async (req, res) => {
    let connection;

    try {
      const token =
        String(
          req.params.token || ""
        ).trim();

      if (!token) {
        return res.status(400).json({
          success: false,
          message: "Token inválido",
        });
      }

      connection =
        await pool.getConnection();

      await connection.beginTransaction();

      const habilitacion =
        await obtenerHabilitacionPorToken(
          token,
          connection
        );

      if (!habilitacion) {
        await connection.rollback();

        return res.status(404).json({
          success: false,
          message: "Prueba no encontrada",
        });
      }

      if (
        habilitacion.estatus ===
        "cancelada"
      ) {
        await connection.rollback();

        return res.status(410).json({
          success: false,
          message:
            "Esta prueba fue cancelada",
        });
      }

      if (
        habilitacion.estatus ===
        "completada"
      ) {
        await connection.rollback();

        return res.status(409).json({
          success: false,
          message:
            "Esta prueba ya fue completada",
        });
      }

      // ================================================
      // CONTAR PREGUNTAS
      // ================================================
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

      // ================================================
      // CONTAR RESPUESTAS
      // ================================================
      const [totalRespuestasRows] =
        await connection.query(
          `
            SELECT
              COUNT(*) AS total
            FROM respuestas_prueba_prospecto
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
        totalPreguntas > 0 &&
        totalRespuestas <
          totalPreguntas
      ) {
        await connection.rollback();

        return res.status(400).json({
          success: false,

          message:
            "La prueba todavía tiene preguntas sin responder",

          total_preguntas:
            totalPreguntas,

          total_respuestas:
            totalRespuestas,
        });
      }

      // ================================================
      // VARIABLES DE RESULTADO
      // ================================================
      let puntajeTotal = 0;

      let resultadoTexto = "";

      let interpretacion = null;

      let interpretacionLaboral = null;

      let dimensiones = null;

      // ================================================
      // IPIP-50 BIG FIVE
      // ================================================
      if (
        esIPIP50(
          habilitacion
        )
      ) {
        if (
          totalPreguntas !== 50
        ) {
          throw new Error(
            `El IPIP-50 debe tener 50 reactivos activos. Actualmente tiene ${totalPreguntas}.`
          );
        }

        const resultadoIPIP =
          await calcularIPIP50(
            habilitacion.id_habilitacion,
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
        // ==============================================
        // ORVIS-92
        // ==============================================
        if (
          totalPreguntas !== 92
        ) {
          throw new Error(
            `ORVIS-92 debe tener 92 reactivos activos. Actualmente tiene ${totalPreguntas}.`
          );
        }

        const resultadoORVIS =
          await calcularORVIS92(
            habilitacion.id_habilitacion,
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
        // ==============================================
        // PRUEBAS GENÉRICAS
        // ==============================================
        const [puntajeRows] =
          await connection.query(
            `
              SELECT
                COALESCE(
                  SUM(valor_respuesta),
                  0
                ) AS total
              FROM respuestas_prueba_prospecto
              WHERE id_habilitacion = ?
            `,
            [
              habilitacion.id_habilitacion
            ]
          );

        puntajeTotal =
          Number(
            puntajeRows[0]?.total ||
            0
          );

        resultadoTexto =
          `Puntaje bruto obtenido: ${puntajeTotal}`;
      }

      // ================================================
      // GUARDAR RESULTADO
      // ================================================
      const [existente] =
        await connection.query(
          `
            SELECT
              id_resultado
            FROM resultados_prueba_prospecto
            WHERE id_habilitacion = ?
            LIMIT 1
          `,
          [
            habilitacion.id_habilitacion
          ]
        );

      let idResultado;

      if (
        existente.length
      ) {
        idResultado =
          existente[0]
            .id_resultado;

        await connection.query(
          `
            UPDATE resultados_prueba_prospecto
            SET
              puntaje_total = ?,
              resultado_texto = ?,
              interpretacion = ?,
              interpretacion_laboral = ?,
              fortalezas = NULL,
              areas_atencion = NULL,
              compatibilidad_puesto = NULL,
              recomendaciones = NULL,
              generado_por_ia = 0,
              fecha_resultado = NOW()
            WHERE id_resultado = ?
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
        const [insert] =
          await connection.query(
            `
              INSERT INTO resultados_prueba_prospecto
              (
                id_habilitacion,
                id_prospecto,
                id_prueba_rh,
                puntaje_total,
                resultado_texto,
                interpretacion,
                interpretacion_laboral,
                fortalezas,
                areas_atencion,
                compatibilidad_puesto,
                recomendaciones,
                generado_por_ia,
                fecha_resultado,
                creado_en
              )
              VALUES
              (
                ?, ?, ?, ?, ?, ?, ?,
                NULL, NULL, NULL,
                NULL, 0,
                NOW(), NOW()
              )
            `,
            [
              habilitacion.id_habilitacion,
              habilitacion.id_prospecto,
              habilitacion.id_prueba_rh,
              puntajeTotal,
              resultadoTexto,
              interpretacion,
              interpretacionLaboral
            ]
          );

        idResultado =
          insert.insertId;
      }

      // ================================================
      // MARCAR COMO COMPLETADA
      // ================================================
      await connection.query(
        `
          UPDATE pruebas_prospectos_habilitadas
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

      // ================================================
      // RESPUESTA PÚBLICA
      // ================================================
      return res.json({
        success: true,

        message:
          "Prueba psicométrica completada correctamente",

        resultado: {
          id_resultado:
            idResultado,

          id_habilitacion:
            habilitacion.id_habilitacion,

          id_prueba_rh:
            habilitacion.id_prueba_rh,

          puntaje_total:
            puntajeTotal,

          resultado_texto:
            resultadoTexto,

          dimensiones,

          interpretacion_pendiente:
            !esIPIP50(
              habilitacion
            ) &&
            !esORVIS92(
              habilitacion
            )
        },
      });

    } catch (error) {
      if (connection) {
        try {
          await connection.rollback();
        } catch {}
      }

      console.error(
        "❌ Error finalizando prueba RH:",
        error
      );

      return res.status(500).json({
        success: false,

        message:
          error.message ||
          "Error interno al finalizar la prueba",
      });

    } finally {
      if (connection) {
        connection.release();
      }
    }
  };