// backend/controllers/ravenController.js

import pool from "../config/database.js";

const ID_PRUEBA_RAVEN_RH = 3;

// =========================================================
// IDENTIFICAR RAVEN RH
// =========================================================

const esRaven = (habilitacion) => {
  const nombre = String(
    habilitacion?.prueba_nombre || ""
  )
    .trim()
    .toLowerCase();

  const version = String(
    habilitacion?.version || ""
  )
    .trim()
    .toLowerCase();

  return (
    Number(habilitacion?.id_prueba_rh) ===
      ID_PRUEBA_RAVEN_RH ||
    version === "raven-spm" ||
    nombre.includes(
      "matrices progresivas de raven"
    )
  );
};

// =========================================================
// OBTENER HABILITACIÓN RH POR ID
// =========================================================

async function obtenerHabilitacionRH(
  id_habilitacion,
  connection = pool
) {
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
      p.edad,
      p.sexo,
      p.id_mirror,
      p.puesto,
      p.correo,

      pr.nombre AS prueba_nombre,
      pr.descripcion AS prueba_descripcion,
      pr.categoria,
      pr.version,
      pr.activo

    FROM pruebas_prospectos_habilitadas h

    INNER JOIN prospectos p
      ON p.id_prospecto = h.id_prospecto

    INNER JOIN pruebas_rh pr
      ON pr.id_prueba_rh = h.id_prueba_rh

    WHERE h.id_habilitacion = ?
    LIMIT 1
    `,
    [id_habilitacion]
  );

  if (!rows.length) {
    return null;
  }

  const habilitacion = rows[0];

  if (!esRaven(habilitacion)) {
    return null;
  }

  return habilitacion;
}

// =========================================================
// OBTENER HABILITACIÓN RH POR TOKEN
// =========================================================

async function obtenerHabilitacionPorToken(
  token,
  connection = pool
) {
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
      p.edad,
      p.sexo,
      p.id_mirror,
      p.puesto,
      p.correo,

      pr.nombre AS prueba_nombre,
      pr.descripcion AS prueba_descripcion,
      pr.categoria,
      pr.version,
      pr.activo

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

  if (!rows.length) {
    return null;
  }

  const habilitacion = rows[0];

  if (!esRaven(habilitacion)) {
    return null;
  }

  return habilitacion;
}

// =========================================================
// VALIDAR ESTADO
// =========================================================

const validarEstado = (habilitacion) => {
  if (!habilitacion) {
    return {
      ok: false,
      status: 404,
      message: "Prueba Raven no encontrada"
    };
  }

  if (habilitacion.estatus === "cancelada") {
    return {
      ok: false,
      status: 410,
      message: "Esta prueba fue cancelada"
    };
  }

  if (habilitacion.estatus === "completada") {
    return {
      ok: false,
      status: 409,
      message: "Esta prueba ya fue completada"
    };
  }

  if (!Number(habilitacion.activo)) {
    return {
      ok: false,
      status: 400,
      message: "La prueba Raven está inactiva"
    };
  }

  return {
    ok: true
  };
};

// =========================================================
// MARCAR COMO INICIADA
// =========================================================

async function marcarComoIniciada(
  habilitacion,
  connection = pool
) {
  if (
    habilitacion.estatus !==
    "habilitada"
  ) {
    return;
  }

  await connection.query(
    `
    UPDATE pruebas_prospectos_habilitadas
    SET
      estatus = 'iniciada',
      fecha_inicio = COALESCE(
        fecha_inicio,
        NOW()
      )
    WHERE id_habilitacion = ?
    `,
    [
      habilitacion.id_habilitacion
    ]
  );

  habilitacion.estatus =
    "iniciada";
}

// =========================================================
// VALIDAR 60 RESPUESTAS
// =========================================================

async function validarRespuestas(
  respuestas,
  connection = pool
) {
  if (!Array.isArray(respuestas)) {
    return {
      ok: false,
      message:
        "Las respuestas deben enviarse como arreglo"
    };
  }

  if (respuestas.length !== 60) {
    return {
      ok: false,
      message:
        "Raven debe contener exactamente 60 reactivos respondidos"
    };
  }

  const ids = new Set();

  for (const respuesta of respuestas) {
    const idReactivo =
      Number(
        respuesta.id_reactivo
      );

    const opcion =
      Number(
        respuesta.respuesta
      );

    if (
      !Number.isInteger(
        idReactivo
      ) ||
      idReactivo <= 0 ||
      !Number.isInteger(
        opcion
      ) ||
      opcion <= 0
    ) {
      return {
        ok: false,
        message:
          "Cada respuesta debe incluir id_reactivo y una opción válida"
      };
    }

    if (
      ids.has(
        idReactivo
      )
    ) {
      return {
        ok: false,
        message:
          `El reactivo ${idReactivo} está repetido`
      };
    }

    ids.add(
      idReactivo
    );
  }

  const idsReactivos =
    [...ids];

  const [reactivos] =
    await connection.query(
      `
      SELECT
        id_reactivo,
        total_opciones

      FROM reactivos_raven

      WHERE id_prueba_rh = ?
        AND id_reactivo IN (?)
        AND activo = 1
      `,
      [
        ID_PRUEBA_RAVEN_RH,
        idsReactivos
      ]
    );

  if (reactivos.length !== 60) {
    return {
      ok: false,
      message:
        "Uno o más reactivos no pertenecen a Raven"
    };
  }

  const mapa =
    new Map(
      reactivos.map(
        (r) => [
          Number(
            r.id_reactivo
          ),
          Number(
            r.total_opciones
          )
        ]
      )
    );

  for (const respuesta of respuestas) {
    const idReactivo =
      Number(
        respuesta.id_reactivo
      );

    const opcion =
      Number(
        respuesta.respuesta
      );

    const totalOpciones =
      mapa.get(
        idReactivo
      );

    if (
      !totalOpciones ||
      opcion < 1 ||
      opcion > totalOpciones
    ) {
      return {
        ok: false,
        message:
          `Respuesta inválida para el reactivo ${idReactivo}`
      };
    }
  }

  return {
    ok: true
  };
}

// =========================================================
// OBTENER REACTIVOS PÚBLICOS
// NO ENVÍA respuesta_correcta
// =========================================================

export async function obtenerReactivosRavenPublico(
  req,
  res
) {
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

    const validacion =
      validarEstado(
        habilitacion
      );

    if (!validacion.ok) {
      return res
        .status(
          validacion.status
        )
        .json({
          success: false,
          message:
            validacion.message
        });
    }

    await marcarComoIniciada(
      habilitacion
    );

    const [reactivos] =
      await pool.query(
        `
        SELECT
          id_reactivo,
          serie,
          numero,
          imagen,
          total_opciones

        FROM reactivos_raven

        WHERE id_prueba_rh = ?
          AND activo = 1

        ORDER BY
          FIELD(
            serie,
            'A',
            'B',
            'C',
            'D',
            'E'
          ),
          numero
        `,
        [
          ID_PRUEBA_RAVEN_RH
        ]
      );

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
          "iniciada"
      },

      total:
        reactivos.length,

      reactivos
    });

  } catch (error) {
    console.error(
      "❌ Error cargando Raven RH:",
      error
    );

    return res
      .status(500)
      .json({
        success: false,
        message:
          "Error interno al cargar Raven"
      });
  }
}

// =========================================================
// CATÁLOGO TÉCNICO DE REACTIVOS
// =========================================================

export async function obtenerReactivosRaven(
  req,
  res
) {
  try {
    const [rows] =
      await pool.query(
        `
        SELECT
          id_reactivo,
          serie,
          numero,
          imagen,
          total_opciones

        FROM reactivos_raven

        WHERE id_prueba_rh = ?
          AND activo = 1

        ORDER BY
          FIELD(
            serie,
            'A',
            'B',
            'C',
            'D',
            'E'
          ),
          numero
        `,
        [
          ID_PRUEBA_RAVEN_RH
        ]
      );

    return res.json({
      success: true,
      total:
        rows.length,
      reactivos:
        rows
    });

  } catch (error) {
    console.error(
      "❌ Error obteniendo reactivos Raven:",
      error
    );

    return res
      .status(500)
      .json({
        success: false,
        message:
          "Error al obtener reactivos Raven"
      });
  }
}

// =========================================================
// GUARDAR RESPUESTAS RAVEN
// =========================================================

export async function guardarRespuestasRaven(
  req,
  res
) {
  let connection;

  try {
    const token =
      String(
        req.params.token ||
        ""
      ).trim();

    const {
      respuestas
    } = req.body;

    if (!token) {
      return res
        .status(400)
        .json({
          success: false,
          message:
            "Token inválido"
        });
    }

    connection =
      await pool.getConnection();

    const habilitacion =
      await obtenerHabilitacionPorToken(
        token,
        connection
      );

    const estado =
      validarEstado(
        habilitacion
      );

    if (!estado.ok) {
      return res
        .status(
          estado.status
        )
        .json({
          success: false,
          message:
            estado.message
        });
    }

    const validacion =
      await validarRespuestas(
        respuestas,
        connection
      );

    if (!validacion.ok) {
      return res
        .status(400)
        .json({
          success: false,
          message:
            validacion.message
        });
    }

    const idsReactivos =
      respuestas.map(
        (r) =>
          Number(
            r.id_reactivo
          )
      );

    const [reactivos] =
      await connection.query(
        `
        SELECT
          id_reactivo,
          respuesta_correcta

        FROM reactivos_raven

        WHERE id_prueba_rh = ?
          AND id_reactivo IN (?)
          AND activo = 1
        `,
        [
          ID_PRUEBA_RAVEN_RH,
          idsReactivos
        ]
      );

    const mapaCorrectas =
      new Map(
        reactivos.map(
          (r) => [
            Number(
              r.id_reactivo
            ),
            Number(
              r.respuesta_correcta
            )
          ]
        )
      );

    await connection
      .beginTransaction();

    await connection.query(
      `
      DELETE FROM respuestas_raven
      WHERE id_habilitacion = ?
      `,
      [
        habilitacion.id_habilitacion
      ]
    );

    const valores =
      respuestas.map(
        (respuesta) => {
          const idReactivo =
            Number(
              respuesta.id_reactivo
            );

          const opcion =
            Number(
              respuesta.respuesta
            );

          const correcta =
            mapaCorrectas.get(
              idReactivo
            ) === opcion
              ? 1
              : 0;

          return [
            habilitacion.id_habilitacion,
            habilitacion.id_prospecto,
            habilitacion.id_prueba_rh,
            idReactivo,
            opcion,
            correcta
          ];
        }
      );

    await connection.query(
      `
      INSERT INTO respuestas_raven
      (
        id_habilitacion,
        id_prospecto,
        id_prueba_rh,
        id_reactivo,
        respuesta,
        correcta
      )
      VALUES ?
      `,
      [
        valores
      ]
    );

    await marcarComoIniciada(
      habilitacion,
      connection
    );

    await connection
      .commit();

    return res.json({
      success: true,
      total_respuestas:
        valores.length,
      message:
        "✅ Respuestas Raven guardadas correctamente"
    });

  } catch (error) {
    if (connection) {
      try {
        await connection
          .rollback();
      } catch {}
    }

    console.error(
      "❌ Error guardando respuestas Raven RH:",
      error
    );

    return res
      .status(500)
      .json({
        success: false,
        message:
          "Error al guardar respuestas Raven",
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
}

// =========================================================
// CALCULAR PUNTAJE BRUTO POR SERIE
// =========================================================

async function calcularResultado(
  id_habilitacion,
  connection = pool
) {
  const [rows] =
    await connection.query(
      `
      SELECT
        rr.serie,

        SUM(
          CASE
            WHEN r.correcta = 1
              THEN 1
            ELSE 0
          END
        ) AS aciertos

      FROM respuestas_raven r

      INNER JOIN reactivos_raven rr
        ON rr.id_reactivo =
           r.id_reactivo

      WHERE r.id_habilitacion = ?
        AND r.id_prueba_rh = ?

      GROUP BY rr.serie

      ORDER BY
        FIELD(
          rr.serie,
          'A',
          'B',
          'C',
          'D',
          'E'
        )
      `,
      [
        id_habilitacion,
        ID_PRUEBA_RAVEN_RH
      ]
    );

  const resultado = {
    A: 0,
    B: 0,
    C: 0,
    D: 0,
    E: 0
  };

  for (const fila of rows) {
    if (
      Object.prototype
        .hasOwnProperty.call(
          resultado,
          fila.serie
        )
    ) {
      resultado[
        fila.serie
      ] =
        Number(
          fila.aciertos ||
          0
        );
    }
  }

  return {
    ...resultado,

    total:
      resultado.A +
      resultado.B +
      resultado.C +
      resultado.D +
      resultado.E
  };
}

// =========================================================
// OBTENER BAREMO RAVEN
// =========================================================

async function obtenerBaremoRaven(
  edad,
  puntaje,
  connection = pool
) {
  const edadNum =
    Number(edad);

  const puntajeNum =
    Number(puntaje);

  if (
    !Number.isInteger(
      edadNum
    ) ||
    edadNum <= 0
  ) {
    return null;
  }

  const [baremos] =
    await connection.query(
      `
      SELECT
        percentil,
        puntaje_min,
        poblacion,
        edad_min,
        edad_max,
        fuente

      FROM baremos_raven

      WHERE id_prueba_rh = ?
        AND ? BETWEEN edad_min AND edad_max
        AND activo = 1

      ORDER BY percentil DESC
      `,
      [
        ID_PRUEBA_RAVEN_RH,
        edadNum
      ]
    );

  if (!baremos.length) {
    return null;
  }

  const alcanzado =
    baremos.find(
      (b) =>
        puntajeNum >=
        Number(
          b.puntaje_min
        )
    );

  if (!alcanzado) {
    return {
      percentil: 5,
      banda: "< P5",
      rango: "V",
      clasificacion:
        "Inferior al percentil 5",
      poblacion:
        baremos[0].poblacion,
      fuente:
        baremos[0].fuente
    };
  }

  const p =
    Number(
      alcanzado.percentil
    );

  let banda = "";
  let rango = "";
  let clasificacion = "";

  if (p >= 95) {
    banda =
      "P95 o superior";

    rango =
      "I";

    clasificacion =
      "Superior";

  } else if (p >= 90) {
    banda =
      "P90 – <P95";

    rango =
      "II";

    clasificacion =
      "Superior al término medio";

  } else if (p >= 75) {
    banda =
      "P75 – <P90";

    rango =
      "II";

    clasificacion =
      "Superior al término medio";

  } else if (p >= 50) {
    banda =
      "P50 – <P75";

    rango =
      "III";

    clasificacion =
      "Término medio";

  } else if (p >= 25) {
    banda =
      "P25 – <P50";

    rango =
      "III";

    clasificacion =
      "Término medio";

  } else if (p >= 10) {
    banda =
      "P10 – <P25";

    rango =
      "IV";

    clasificacion =
      "Inferior al término medio";

  } else if (p >= 5) {
    banda =
      "P5 – <P10";

    rango =
      "IV";

    clasificacion =
      "Inferior al término medio";

  } else {
    banda =
      "< P5";

    rango =
      "V";

    clasificacion =
      "Muy inferior";
  }

  return {
    percentil: p,
    banda,
    rango,
    clasificacion,
    poblacion:
      alcanzado.poblacion,
    fuente:
      alcanzado.fuente
  };
}

// =========================================================
// GUARDAR RESULTADO GENERAL DE RH
// =========================================================

async function guardarResultadoGeneralRH(
  connection,
  habilitacion,
  resultado,
  baremo,
  interpretacionRaven
) {
  const resultadoTexto = [
    "Matrices Progresivas de Raven - Escala General",
    "",
    `Serie A: ${resultado.A}/12`,
    `Serie B: ${resultado.B}/12`,
    `Serie C: ${resultado.C}/12`,
    `Serie D: ${resultado.D}/12`,
    `Serie E: ${resultado.E}/12`,
    "",
    `Puntaje bruto total: ${resultado.total}/60`,
    "",
    baremo
      ? `Banda percentilar: ${baremo.banda}`
      : "Banda percentilar: No disponible",

    baremo
      ? `Rango: ${baremo.rango}`
      : "Rango: No disponible",

    baremo
      ? `Clasificación: ${baremo.clasificacion}`
      : "Clasificación: No disponible"
  ].join("\n");

  const interpretacionLaboral =
    "Resultado psicométrico de apoyo para Recursos Humanos. Debe interpretarse junto con la entrevista, experiencia, competencias y demás información del proceso de selección. No determina por sí solo contratación, rechazo o idoneidad laboral.";

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

  if (existente.length) {
    const idResultado =
      existente[0].id_resultado;

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
        resultado.total,
        resultadoTexto,
        interpretacionRaven,
        interpretacionLaboral,
        idResultado
      ]
    );

    return idResultado;
  }

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
        NULL,
        NULL,
        NULL,
        NULL,
        0,
        NOW(),
        NOW()
      )
      `,
      [
        habilitacion.id_habilitacion,
        habilitacion.id_prospecto,
        habilitacion.id_prueba_rh,
        resultado.total,
        resultadoTexto,
        interpretacionRaven,
        interpretacionLaboral
      ]
    );

  return insert.insertId;
}

// =========================================================
// FINALIZAR RAVEN RH
// =========================================================

export async function finalizarRaven(
  req,
  res
) {
  let connection;

  try {
    const token =
      String(
        req.params.token ||
        ""
      ).trim();

    const {
      tiempo_segundos
    } = req.body;

    if (!token) {
      return res
        .status(400)
        .json({
          success: false,
          message:
            "Token inválido"
        });
    }

    connection =
      await pool.getConnection();

    const habilitacion =
      await obtenerHabilitacionPorToken(
        token,
        connection
      );

    const estado =
      validarEstado(
        habilitacion
      );

    if (!estado.ok) {
      return res
        .status(
          estado.status
        )
        .json({
          success: false,
          message:
            estado.message
        });
    }

    const [cantidad] =
      await connection.query(
        `
        SELECT
          COUNT(*) AS total

        FROM respuestas_raven

        WHERE id_habilitacion = ?
          AND id_prueba_rh = ?
        `,
        [
          habilitacion.id_habilitacion,
          ID_PRUEBA_RAVEN_RH
        ]
      );

    if (
      Number(
        cantidad[0]?.total ||
        0
      ) !== 60
    ) {
      return res
        .status(400)
        .json({
          success: false,
          message:
            "Debes responder los 60 reactivos antes de finalizar Raven"
        });
    }

    // -------------------------------------------------
    // CALCULAR A-E Y TOTAL
    // -------------------------------------------------

    const resultado =
      await calcularResultado(
        habilitacion.id_habilitacion,
        connection
      );

    // -------------------------------------------------
    // CALCULAR BAREMO
    // -------------------------------------------------

    const baremo =
      await obtenerBaremoRaven(
        habilitacion.edad,
        resultado.total,
        connection
      );

    // -------------------------------------------------
    // INTERPRETACIÓN
    // -------------------------------------------------

    const interpretacionRaven =
      baremo
        ? [
            `Puntaje bruto: ${resultado.total}/60.`,
            `Edad de aplicación: ${habilitacion.edad} años.`,
            `Banda percentilar: ${baremo.banda}.`,
            `Rango: ${baremo.rango}.`,
            `Clasificación: ${baremo.clasificacion}.`,
            `Baremo: ${baremo.poblacion}.`,
            `Fuente normativa: ${baremo.fuente}.`
          ].join(" ")
        : [
            `Puntaje bruto: ${resultado.total}/60.`,
            `Edad de aplicación: ${habilitacion.edad || "no disponible"}.`,
            "No existe un baremo cargado para esta edad, por lo que no se asignó percentil ni rango."
          ].join(" ");

    await connection
      .beginTransaction();

    // -------------------------------------------------
    // RESULTADO GENERAL RH
    // -------------------------------------------------

    const idResultado =
      await guardarResultadoGeneralRH(
        connection,
        habilitacion,
        resultado,
        baremo,
        interpretacionRaven
      );

    // -------------------------------------------------
    // RESULTADO ESPECÍFICO RAVEN
    // -------------------------------------------------

    await connection.query(
      `
      INSERT INTO resultados_raven
      (
        id_resultado,
        id_habilitacion,
        id_prospecto,
        id_prueba_rh,

        serie_a,
        serie_b,
        serie_c,
        serie_d,
        serie_e,

        puntaje_total,

        edad_aplicacion,
        percentil,
        rango,
        clasificacion,
        interpretacion,

        tiempo_segundos,
        fecha
      )

      VALUES
      (
        ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?,
        ?, ?, ?, ?, ?,
        ?,
        NOW()
      )

      ON DUPLICATE KEY UPDATE

        id_resultado =
          VALUES(id_resultado),

        serie_a =
          VALUES(serie_a),

        serie_b =
          VALUES(serie_b),

        serie_c =
          VALUES(serie_c),

        serie_d =
          VALUES(serie_d),

        serie_e =
          VALUES(serie_e),

        puntaje_total =
          VALUES(puntaje_total),

        edad_aplicacion =
          VALUES(edad_aplicacion),

        percentil =
          VALUES(percentil),

        rango =
          VALUES(rango),

        clasificacion =
          VALUES(clasificacion),

        interpretacion =
          VALUES(interpretacion),

        tiempo_segundos =
          VALUES(tiempo_segundos),

        fecha = NOW()
      `,
      [
        idResultado,

        habilitacion.id_habilitacion,
        habilitacion.id_prospecto,
        habilitacion.id_prueba_rh,

        resultado.A,
        resultado.B,
        resultado.C,
        resultado.D,
        resultado.E,

        resultado.total,

        habilitacion.edad
          ? Number(
              habilitacion.edad
            )
          : null,

        baremo
          ? baremo.percentil
          : null,

        baremo
          ? baremo.rango
          : null,

        baremo
          ? `${baremo.clasificacion} (${baremo.banda})`
          : null,

        interpretacionRaven,

        tiempo_segundos
          ? Number(
              tiempo_segundos
            )
          : null
      ]
    );

    // -------------------------------------------------
    // MARCAR HABILITACIÓN COMPLETADA
    // -------------------------------------------------

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

    await connection
      .commit();

    // El prospecto no recibe el resultado psicométrico.
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

        procesada:
          true
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
      "❌ Error finalizando Raven RH:",
      error
    );

    return res
      .status(500)
      .json({
        success: false,

        message:
          "Error interno al finalizar Raven",

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
}

// =========================================================
// OBTENER RESULTADO RAVEN
// USO INTERNO DE RH
// =========================================================

export async function obtenerResultadoRaven(
  req,
  res
) {
  try {
    const idHabilitacion =
      Number(
        req.params.id_habilitacion
      );

    if (
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
            "Habilitación inválida"
        });
    }

    const [rows] =
      await pool.query(
        `
        SELECT
          r.*,

          pr.nombre
            AS nombre_prueba,

          pr.version,

          p.nombre
            AS prospecto_nombre,

          p.id_mirror,
          p.puesto

        FROM resultados_raven r

        INNER JOIN pruebas_rh pr
          ON pr.id_prueba_rh =
             r.id_prueba_rh

        INNER JOIN prospectos p
          ON p.id_prospecto =
             r.id_prospecto

        WHERE r.id_habilitacion = ?

        LIMIT 1
        `,
        [
          idHabilitacion
        ]
      );

    if (!rows.length) {
      return res
        .status(404)
        .json({
          success: false,
          message:
            "No existe resultado Raven para esta habilitación"
        });
    }

    const r =
      rows[0];

    return res.json({
      success: true,

      id_resultado_raven:
        r.id_resultado_raven,

      id_resultado:
        r.id_resultado,

      id_habilitacion:
        r.id_habilitacion,

      id_prospecto:
        r.id_prospecto,

      id_prueba_rh:
        r.id_prueba_rh,

      prospecto: {
        nombre:
          r.prospecto_nombre,

        id_mirror:
          r.id_mirror,

        puesto:
          r.puesto
      },

      prueba: {
        nombre:
          r.nombre_prueba,

        version:
          r.version
      },

      series: {
        A:
          r.serie_a,

        B:
          r.serie_b,

        C:
          r.serie_c,

        D:
          r.serie_d,

        E:
          r.serie_e
      },

      puntaje_total:
        r.puntaje_total,

      edad_aplicacion:
        r.edad_aplicacion,

      percentil:
        r.percentil,

      rango:
        r.rango,

      clasificacion:
        r.clasificacion,

      interpretacion:
        r.interpretacion,

      tiempo_segundos:
        r.tiempo_segundos,

      fecha:
        r.fecha
    });

  } catch (error) {
    console.error(
      "❌ Error obteniendo resultado Raven:",
      error
    );

    return res
      .status(500)
      .json({
        success: false,
        message:
          "Error al obtener resultado Raven"
      });
  }
}

// =========================================================
// OBTENER RESPUESTAS RAVEN
// USO INTERNO
// =========================================================

export async function obtenerRespuestasRaven(
  req,
  res
) {
  try {
    const idHabilitacion =
      Number(
        req.params.id_habilitacion
      );

    if (
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
            "Habilitación inválida"
        });
    }

    const [rows] =
      await pool.query(
        `
        SELECT
          r.id_respuesta_raven,
          r.id_reactivo,

          rr.serie,
          rr.numero,

          r.respuesta,
          r.correcta,

          r.fecha_respuesta

        FROM respuestas_raven r

        INNER JOIN reactivos_raven rr
          ON rr.id_reactivo =
             r.id_reactivo

        WHERE r.id_habilitacion = ?
          AND r.id_prueba_rh = ?

        ORDER BY
          FIELD(
            rr.serie,
            'A',
            'B',
            'C',
            'D',
            'E'
          ),
          rr.numero
        `,
        [
          idHabilitacion,
          ID_PRUEBA_RAVEN_RH
        ]
      );

    return res.json({
      success: true,

      total:
        rows.length,

      respuestas:
        rows
    });

  } catch (error) {
    console.error(
      "❌ Error obteniendo respuestas Raven:",
      error
    );

    return res
      .status(500)
      .json({
        success: false,
        message:
          "Error al obtener respuestas Raven"
      });
  }
}