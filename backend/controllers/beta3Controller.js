import pool from "../config/database.js";

const ID_PRUEBA_BETA3_RH = 4;
const TOLERANCIA_FIGURAS = 5;

/* =========================================================
   HELPERS
========================================================= */

const textoSeguro = (valor) => String(valor ?? "").trim();

const numeroSeguro = (valor) => {
  const numero = Number(valor);
  return Number.isFinite(numero) ? numero : null;
};

function parsearCoordenadaFigura(valor) {
  const partes = textoSeguro(valor)
    .split(",")
    .map((v) => v.trim());

  if (partes.length !== 3) return null;

  const pagina = Number(partes[0]);
  const x = Number(partes[1]);
  const y = Number(partes[2]);

  if (
    !Number.isFinite(pagina) ||
    !Number.isFinite(x) ||
    !Number.isFinite(y)
  ) {
    return null;
  }

  return { pagina, x, y };
}

function evaluarRespuestaBeta3(
  respuesta,
  respuestaCorrecta,
  idSubprueba
) {
  const respuestaTexto = textoSeguro(respuesta);
  const correctaTexto = textoSeguro(respuestaCorrecta);

  if (!respuestaTexto || !correctaTexto) {
    return null;
  }

  /* =======================================================
     FIGURAS INCOMPLETAS
     Formato: pagina,x,y
     ======================================================= */

  if (Number(idSubprueba) === 2) {
    const marcada = parsearCoordenadaFigura(respuestaTexto);
    const clave = parsearCoordenadaFigura(correctaTexto);

    if (!marcada || !clave) return 0;

    if (marcada.pagina !== clave.pagina) {
      return 0;
    }

    const diferenciaX = Math.abs(
      marcada.x - clave.x
    );

    const diferenciaY = Math.abs(
      marcada.y - clave.y
    );

    return (
      diferenciaX <= TOLERANCIA_FIGURAS &&
      diferenciaY <= TOLERANCIA_FIGURAS
    )
      ? 1
      : 0;
  }

  /* =======================================================
     CLAVES / PARES / OBJETOS / MATRICES
     ======================================================= */

  return (
    respuestaTexto.toLowerCase() ===
    correctaTexto.toLowerCase()
  )
    ? 1
    : 0;
}

/* =========================================================
   OBTENER HABILITACIÓN POR TOKEN
========================================================= */

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
      AND h.id_prueba_rh = ?

    LIMIT 1
    `,
    [
      token,
      ID_PRUEBA_BETA3_RH
    ]
  );

  return rows.length
    ? rows[0]
    : null;
}

/* =========================================================
   OBTENER HABILITACIÓN POR ID
========================================================= */

async function obtenerHabilitacionPorId(
  idHabilitacion,
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

      p.nombre AS prospecto_nombre,
      p.edad,
      p.sexo,
      p.id_mirror,
      p.puesto,

      pr.nombre AS prueba_nombre,
      pr.categoria,
      pr.version

    FROM pruebas_prospectos_habilitadas h

    INNER JOIN prospectos p
      ON p.id_prospecto = h.id_prospecto

    INNER JOIN pruebas_rh pr
      ON pr.id_prueba_rh = h.id_prueba_rh

    WHERE h.id_habilitacion = ?
      AND h.id_prueba_rh = ?

    LIMIT 1
    `,
    [
      idHabilitacion,
      ID_PRUEBA_BETA3_RH
    ]
  );

  return rows.length
    ? rows[0]
    : null;
}

/* =========================================================
   VALIDAR ESTADO
========================================================= */

function validarEstado(
  habilitacion,
  permitirCompletada = false
) {
  if (!habilitacion) {
    return {
      ok: false,
      status: 404,
      message:
        "La aplicación Beta III no fue encontrada."
    };
  }

  if (
    habilitacion.estatus ===
    "cancelada"
  ) {
    return {
      ok: false,
      status: 410,
      message:
        "Esta evaluación fue cancelada."
    };
  }

  if (
    !permitirCompletada &&
    habilitacion.estatus ===
    "completada"
  ) {
    return {
      ok: false,
      status: 409,
      message:
        "Esta evaluación ya fue completada."
    };
  }

  return {
    ok: true
  };
}

/* =========================================================
   MARCAR COMO INICIADA
========================================================= */

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

  habilitacion.estatus =
    "iniciada";
}

/* =========================================================
   VERIFICAR CLAVES PENDIENTES
========================================================= */

async function obtenerEstadoClaves(
  connection = pool
) {
  const [rows] = await connection.query(
    `
    SELECT
      s.id_subprueba,
      s.nombre,

      COUNT(r.id_reactivo_beta3)
        AS total,

      SUM(
        CASE
          WHEN r.respuesta_correcta IS NULL
          THEN 1
          ELSE 0
        END
      ) AS sin_clave,

      SUM(
        CASE
          WHEN r.respuesta_correcta IS NOT NULL
          THEN 1
          ELSE 0
        END
      ) AS con_clave

    FROM subpruebas_beta3 s

    LEFT JOIN reactivos_beta3 r
      ON r.id_subprueba = s.id_subprueba
     AND r.id_prueba_rh = ?
     AND r.activo = 1

    WHERE s.id_prueba_rh = ?
      AND s.activo = 1

    GROUP BY
      s.id_subprueba,
      s.nombre,
      s.orden

    ORDER BY s.orden
    `,
    [
      ID_PRUEBA_BETA3_RH,
      ID_PRUEBA_BETA3_RH
    ]
  );

  const totalPendientes =
    rows.reduce(
      (suma, fila) =>
        suma +
        Number(
          fila.sin_clave || 0
        ),
      0
    );

  return {
    completo:
      totalPendientes === 0,

    total_pendientes:
      totalPendientes,

    subpruebas:
      rows
  };
}

/* =========================================================
   GET /api/beta3/estado-claves
========================================================= */

export async function verificarClavesBeta3(
  req,
  res
) {
  try {
    const estado =
      await obtenerEstadoClaves();

    return res.json({
      success: true,
      ...estado
    });

  } catch (error) {
    console.error(
      "❌ Error verificando claves Beta III:",
      error
    );

    return res
      .status(500)
      .json({
        success: false,
        message:
          "Error al verificar las claves de Beta III."
      });
  }
}

/* =========================================================
   CARGAR BETA III PÚBLICA
========================================================= */

export async function obtenerBeta3Publica(
  req,
  res
) {
  try {
    const token =
      textoSeguro(
        req.params.token
      );

    if (!token) {
      return res
        .status(400)
        .json({
          success: false,
          message:
            "Token inválido."
        });
    }

    const habilitacion =
      await obtenerHabilitacionPorToken(
        token
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

    await marcarComoIniciada(
      habilitacion
    );

    const [subpruebas] =
      await pool.query(
        `
        SELECT
          id_subprueba,
          codigo,
          nombre,
          orden,
          tiempo_segundos,
          descripcion

        FROM subpruebas_beta3

        WHERE id_prueba_rh = ?
          AND activo = 1

        ORDER BY orden
        `,
        [
          ID_PRUEBA_BETA3_RH
        ]
      );

    for (
      const subprueba
      of subpruebas
    ) {
      const [reactivos] =
        await pool.query(
          `
          SELECT
            id_reactivo_beta3,
            id_subprueba,
            id_lamina_beta3,
            numero,
            fila,
            posicion_fila,
            tipo_respuesta,
            imagen,
            enunciado,
            total_opciones,
            es_ejemplo

          FROM reactivos_beta3

          WHERE id_prueba_rh = ?
            AND id_subprueba = ?
            AND activo = 1

          ORDER BY numero
          `,
          [
            ID_PRUEBA_BETA3_RH,
            subprueba.id_subprueba
          ]
        );

      subprueba.reactivos =
        reactivos;
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

        participante:
          habilitacion.prospecto_nombre,

        id_mirror:
          habilitacion.id_mirror,

        puesto:
          habilitacion.puesto,

        edad:
          habilitacion.edad,

        estatus:
          "iniciada"
      },

      subpruebas
    });

  } catch (error) {
    console.error(
      "❌ Error cargando Beta III:",
      error
    );

    return res
      .status(500)
      .json({
        success: false,
        message:
          "Error al cargar Beta III."
      });
  }
}

/* =========================================================
   GUARDAR RESPUESTAS
========================================================= */

export async function guardarRespuestasBeta3(
  req,
  res
) {
  let connection;

  try {
    const token =
      textoSeguro(
        req.params.token
      );

    const {
      id_subprueba,
      respuestas
    } = req.body;

    const idSubprueba =
      Number(id_subprueba);

    if (!token) {
      return res
        .status(400)
        .json({
          success: false,
          message:
            "Token inválido."
        });
    }

    if (
      !Number.isInteger(
        idSubprueba
      ) ||
      idSubprueba <= 0
    ) {
      return res
        .status(400)
        .json({
          success: false,
          message:
            "Subprueba inválida."
        });
    }

    if (
      !Array.isArray(
        respuestas
      )
    ) {
      return res
        .status(400)
        .json({
          success: false,
          message:
            "Las respuestas deben enviarse como arreglo."
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

    const [subpruebaRows] =
      await connection.query(
        `
        SELECT
          id_subprueba,
          codigo,
          nombre

        FROM subpruebas_beta3

        WHERE id_subprueba = ?
          AND id_prueba_rh = ?
          AND activo = 1

        LIMIT 1
        `,
        [
          idSubprueba,
          ID_PRUEBA_BETA3_RH
        ]
      );

    if (!subpruebaRows.length) {
      return res
        .status(404)
        .json({
          success: false,
          message:
            "La subprueba no existe."
        });
    }

    await connection
      .beginTransaction();

    for (
      const item
      of respuestas
    ) {
      const idReactivo =
        Number(
          item.id_reactivo_beta3
        );

      if (
        !Number.isInteger(
          idReactivo
        ) ||
        idReactivo <= 0
      ) {
        throw new Error(
          "Se recibió un reactivo inválido."
        );
      }

      const [reactivoRows] =
        await connection.query(
          `
          SELECT
            id_reactivo_beta3,
            id_subprueba,
            tipo_respuesta,
            respuesta_correcta,
            es_ejemplo

          FROM reactivos_beta3

          WHERE id_reactivo_beta3 = ?
            AND id_prueba_rh = ?
            AND id_subprueba = ?
            AND activo = 1

          LIMIT 1
          `,
          [
            idReactivo,
            ID_PRUEBA_BETA3_RH,
            idSubprueba
          ]
        );

      if (!reactivoRows.length) {
        throw new Error(
          `El reactivo ${idReactivo} no pertenece a esta subprueba.`
        );
      }

      const reactivo =
        reactivoRows[0];

      if (
        Number(
          reactivo.es_ejemplo
        ) === 1
      ) {
        continue;
      }

      const respuesta =
        textoSeguro(
          item.respuesta
        );

      if (!respuesta) {
        continue;
      }

      let correcta = null;

      if (
        reactivo.respuesta_correcta !== null &&
        reactivo.respuesta_correcta !== undefined
      ) {
        correcta =
          evaluarRespuestaBeta3(
            respuesta,
            reactivo.respuesta_correcta,
            idSubprueba
          );
      }

      const tiempo =
        numeroSeguro(
          item.tiempo_respuesta_ms
        );

      await connection.query(
        `
        INSERT INTO respuestas_beta3
        (
          id_habilitacion,
          id_prospecto,
          id_prueba_rh,
          id_subprueba,
          id_reactivo_beta3,
          respuesta,
          correcta,
          tiempo_respuesta_ms,
          fecha_respuesta
        )

        VALUES
        (
          ?, ?, ?, ?, ?, ?, ?, ?, NOW()
        )

        ON DUPLICATE KEY UPDATE

          respuesta =
            VALUES(respuesta),

          correcta =
            VALUES(correcta),

          tiempo_respuesta_ms =
            VALUES(tiempo_respuesta_ms),

          fecha_respuesta =
            NOW()
        `,
        [
          habilitacion.id_habilitacion,
          habilitacion.id_prospecto,
          ID_PRUEBA_BETA3_RH,
          idSubprueba,
          idReactivo,
          respuesta,
          correcta,
          tiempo
        ]
      );
    }

    await marcarComoIniciada(
      habilitacion,
      connection
    );

    await connection
      .commit();

    return res.json({
      success: true,
      message:
        "✅ Respuestas Beta III guardadas correctamente."
    });

  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch {}
    }

    console.error(
      "❌ Error guardando respuestas Beta III:",
      error
    );

    return res
      .status(500)
      .json({
        success: false,

        message:
          "Error al guardar respuestas Beta III.",

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

/* =========================================================
   RECALIFICAR RESPUESTAS YA GUARDADAS
========================================================= */

async function recalificarRespuestasBeta3(
  idHabilitacion,
  connection
) {
  const [respuestas] =
    await connection.query(
      `
      SELECT
        rb.id_respuesta_beta3,
        rb.id_subprueba,
        rb.respuesta,
        r.respuesta_correcta

      FROM respuestas_beta3 rb

      INNER JOIN reactivos_beta3 r
        ON r.id_reactivo_beta3 =
           rb.id_reactivo_beta3

      WHERE rb.id_habilitacion = ?
        AND r.id_prueba_rh = ?
        AND r.activo = 1
        AND r.es_ejemplo = 0
      `,
      [
        idHabilitacion,
        ID_PRUEBA_BETA3_RH
      ]
    );

  for (
    const item
    of respuestas
  ) {
    let correcta = null;

    if (
      item.respuesta_correcta !== null &&
      item.respuesta_correcta !== undefined
    ) {
      correcta =
        evaluarRespuestaBeta3(
          item.respuesta,
          item.respuesta_correcta,
          item.id_subprueba
        );
    }

    await connection.query(
      `
      UPDATE respuestas_beta3
      SET correcta = ?
      WHERE id_respuesta_beta3 = ?
      `,
      [
        correcta,
        item.id_respuesta_beta3
      ]
    );
  }
}

/* =========================================================
   CALCULAR PUNTAJES BRUTOS
========================================================= */

async function calcularPuntajesBrutos(
  idHabilitacion,
  connection
) {
  /* =======================================================
     CLAVES
     Los 3 ejemplos cuentan.
     ======================================================= */

  const [ejemplosClaves] =
    await connection.query(
      `
      SELECT COUNT(*) AS total

      FROM reactivos_beta3

      WHERE id_prueba_rh = ?
        AND id_subprueba = 1
        AND es_ejemplo = 1
        AND activo = 1
      `,
      [
        ID_PRUEBA_BETA3_RH
      ]
    );

  const ejemplos =
    Number(
      ejemplosClaves[0]?.total ||
      0
    );

  const [clavesRows] =
    await connection.query(
      `
      SELECT
        COALESCE(
          SUM(
            CASE
              WHEN correcta = 1
              THEN 1
              ELSE 0
            END
          ),
          0
        ) AS aciertos

      FROM respuestas_beta3

      WHERE id_habilitacion = ?
        AND id_subprueba = 1
      `,
      [
        idHabilitacion
      ]
    );

  const claves =
    ejemplos +
    Number(
      clavesRows[0]?.aciertos ||
      0
    );

  /* =======================================================
     FIGURAS
     ======================================================= */

  const [figurasRows] =
    await connection.query(
      `
      SELECT
        COALESCE(
          SUM(
            CASE
              WHEN correcta = 1
              THEN 1
              ELSE 0
            END
          ),
          0
        ) AS aciertos

      FROM respuestas_beta3

      WHERE id_habilitacion = ?
        AND id_subprueba = 2
      `,
      [
        idHabilitacion
      ]
    );

  const figuras =
    Number(
      figurasRows[0]?.aciertos ||
      0
    );

  /* =======================================================
     PARES
     correctas - errores
     ======================================================= */

  const [paresRows] =
    await connection.query(
      `
      SELECT

        COALESCE(
          SUM(
            CASE
              WHEN correcta = 1
              THEN 1
              ELSE 0
            END
          ),
          0
        ) AS correctas,

        COALESCE(
          SUM(
            CASE
              WHEN correcta = 0
              THEN 1
              ELSE 0
            END
          ),
          0
        ) AS errores

      FROM respuestas_beta3

      WHERE id_habilitacion = ?
        AND id_subprueba = 3
      `,
      [
        idHabilitacion
      ]
    );

  const paresCorrectas =
    Number(
      paresRows[0]?.correctas ||
      0
    );

  const paresErrores =
    Number(
      paresRows[0]?.errores ||
      0
    );

  const pares =
    paresCorrectas -
    paresErrores;

  /* =======================================================
     OBJETOS
     ======================================================= */

  const [objetosRows] =
    await connection.query(
      `
      SELECT
        COALESCE(
          SUM(
            CASE
              WHEN correcta = 1
              THEN 1
              ELSE 0
            END
          ),
          0
        ) AS aciertos

      FROM respuestas_beta3

      WHERE id_habilitacion = ?
        AND id_subprueba = 4
      `,
      [
        idHabilitacion
      ]
    );

  const objetos =
    Number(
      objetosRows[0]?.aciertos ||
      0
    );

  /* =======================================================
     MATRICES
     ======================================================= */

  const [matricesRows] =
    await connection.query(
      `
      SELECT
        COALESCE(
          SUM(
            CASE
              WHEN correcta = 1
              THEN 1
              ELSE 0
            END
          ),
          0
        ) AS aciertos

      FROM respuestas_beta3

      WHERE id_habilitacion = ?
        AND id_subprueba = 5
      `,
      [
        idHabilitacion
      ]
    );

  const matrices =
    Number(
      matricesRows[0]?.aciertos ||
      0
    );

  return {
    claves,
    figuras,
    pares,
    objetos,
    matrices
  };
}

/* =========================================================
   CONVERTIR BRUTO A ESCALAR POR EDAD
========================================================= */

async function convertirAEscalar(
  edad,
  subprueba,
  puntaje,
  connection
) {
  const columnas = {
    claves: [
      "claves_min",
      "claves_max"
    ],

    figuras: [
      "figuras_min",
      "figuras_max"
    ],

    pares: [
      "pares_min",
      "pares_max"
    ],

    objetos: [
      "objetos_min",
      "objetos_max"
    ],

    matrices: [
      "matrices_min",
      "matrices_max"
    ]
  };

  const columnasSubprueba =
    columnas[subprueba];

  if (!columnasSubprueba) {
    throw new Error(
      "Subprueba Beta III inválida."
    );
  }

  const [
    columnaMin,
    columnaMax
  ] =
    columnasSubprueba;

  const [rows] =
    await connection.query(
      `
      SELECT
        puntuacion_escalar

      FROM baremos_beta3

      WHERE id_prueba_rh = ?

        AND ? BETWEEN
              edad_min
              AND edad_max

        AND ${columnaMin}
            IS NOT NULL

        AND ${columnaMax}
            IS NOT NULL

        AND ? BETWEEN
              ${columnaMin}
              AND ${columnaMax}

      LIMIT 1
      `,
      [
        ID_PRUEBA_BETA3_RH,
        edad,
        puntaje
      ]
    );

  if (!rows.length) {
    return null;
  }

  return Number(
    rows[0]
      .puntuacion_escalar
  );
}

/* =========================================================
   OBTENER CONVERSIÓN FINAL CI
========================================================= */

async function obtenerConversionCI(
  sumaEscalares,
  connection
) {
  const [rows] =
    await connection.query(
      `
      SELECT
        suma_escalares,
        ci,
        percentil,
        rango_percentil,
        intervalo_90,
        intervalo_95,
        clasificacion

      FROM conversion_ci_beta3

      WHERE id_prueba_rh = ?
        AND suma_escalares = ?

      LIMIT 1
      `,
      [
        ID_PRUEBA_BETA3_RH,
        sumaEscalares
      ]
    );

  return rows.length
    ? rows[0]
    : null;
}

/* =========================================================
   GUARDAR RESULTADO GENERAL RH
========================================================= */

async function guardarResultadoGeneralRH(
  connection,
  habilitacion,
  brutos,
  escalares,
  sumaEscalares,
  conversion,
  interpretacion
) {
  const resultadoTexto =
    [
      "Beta III",
      "",

      "Puntuaciones naturales:",
      `Claves: ${brutos.claves}`,
      `Figuras incompletas: ${brutos.figuras}`,
      `Pares iguales/desiguales: ${brutos.pares}`,
      `Objetos equivocados: ${brutos.objetos}`,
      `Matrices: ${brutos.matrices}`,
      "",

      "Puntuaciones escalares:",
      `Claves: ${escalares.claves}`,
      `Figuras incompletas: ${escalares.figuras}`,
      `Pares: ${escalares.pares}`,
      `Objetos: ${escalares.objetos}`,
      `Matrices: ${escalares.matrices}`,
      "",

      `Suma escalar: ${sumaEscalares}`,
      `CI: ${conversion.ci}`,
      `Percentil: ${conversion.percentil}`,
      `Clasificación: ${conversion.clasificacion}`,
      `IC 90%: ${conversion.intervalo_90}`,
      `IC 95%: ${conversion.intervalo_95}`
    ].join("\n");

  const interpretacionLaboral =
    "Resultado psicométrico de apoyo para Recursos Humanos. El resultado Beta III debe interpretarse junto con la entrevista, experiencia, competencias y demás información del proceso de selección. No debe utilizarse de manera aislada para decidir contratación, rechazo o idoneidad laboral.";

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
        conversion.ci,
        resultadoTexto,
        interpretacion,
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
        ?, ?, ?,
        ?, ?, ?, ?,

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
        ID_PRUEBA_BETA3_RH,

        conversion.ci,
        resultadoTexto,
        interpretacion,
        interpretacionLaboral
      ]
    );

  return insert.insertId;
}

/* =========================================================
   FINALIZAR BETA III
========================================================= */

export async function finalizarBeta3(
  req,
  res
) {
  let connection;

  try {
    const token =
      textoSeguro(
        req.params.token
      );

    const {
      tiempo_total_segundos
    } = req.body || {};

    if (!token) {
      return res
        .status(400)
        .json({
          success: false,
          message:
            "Token inválido."
        });
    }

    connection =
      await pool.getConnection();

    const habilitacion =
      await obtenerHabilitacionPorToken(
        token,
        connection
      );

    /*
      Permitimos una evaluación completada
      para poder recalcularla después.
    */

    const estado =
      validarEstado(
        habilitacion,
        true
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

    /* =====================================================
       MARCAR APLICACIÓN COMO COMPLETADA
       ===================================================== */

    await connection.query(
      `
      UPDATE pruebas_prospectos_habilitadas

      SET
        estatus = 'completada',

        fecha_completada =
          COALESCE(
            fecha_completada,
            NOW()
          )

      WHERE id_habilitacion = ?
      `,
      [
        habilitacion.id_habilitacion
      ]
    );

    habilitacion.estatus =
      "completada";

    /* =====================================================
       VERIFICAR CLAVES
       ===================================================== */

    const estadoClaves =
      await obtenerEstadoClaves(
        connection
      );

    if (
      !estadoClaves.completo
    ) {
      return res
        .status(200)
        .json({
          success: true,

          completada: true,

          resultado_disponible:
            false,

          codigo:
            "BETA3_CLAVES_INCOMPLETAS",

          message:
            "Beta III fue completada y guardada correctamente. El resultado final quedará disponible cuando se carguen las claves oficiales de corrección.",

          total_pendientes:
            estadoClaves
              .total_pendientes,

          subpruebas:
            estadoClaves
              .subpruebas
        });
    }

    /* =====================================================
       RECALIFICAR RESPUESTAS EXISTENTES
       ===================================================== */

    await recalificarRespuestasBeta3(
      habilitacion.id_habilitacion,
      connection
    );

    /* =====================================================
       VALIDAR EDAD
       ===================================================== */

    const edad =
      Number(
        habilitacion.edad
      );

    if (
      !Number.isInteger(
        edad
      ) ||
      edad < 16 ||
      edad > 89
    ) {
      return res
        .status(422)
        .json({
          success: false,

          completada: true,

          resultado_disponible:
            false,

          message:
            "La aplicación quedó completada, pero el baremo Beta III cargado permite edades de 16 a 89 años."
        });
    }

    /* =====================================================
       PUNTAJES BRUTOS
       ===================================================== */

    const brutos =
      await calcularPuntajesBrutos(
        habilitacion.id_habilitacion,
        connection
      );

    /* =====================================================
       PUNTUACIONES ESCALARES
       ===================================================== */

    const escalares = {
      claves:
        await convertirAEscalar(
          edad,
          "claves",
          brutos.claves,
          connection
        ),

      figuras:
        await convertirAEscalar(
          edad,
          "figuras",
          brutos.figuras,
          connection
        ),

      pares:
        await convertirAEscalar(
          edad,
          "pares",
          brutos.pares,
          connection
        ),

      objetos:
        await convertirAEscalar(
          edad,
          "objetos",
          brutos.objetos,
          connection
        ),

      matrices:
        await convertirAEscalar(
          edad,
          "matrices",
          brutos.matrices,
          connection
        )
    };

    const escalaresFaltantes =
      Object.entries(
        escalares
      )
        .filter(
          ([, valor]) =>
            valor === null
        )
        .map(
          ([clave]) =>
            clave
        );

    if (
      escalaresFaltantes.length
    ) {
      return res
        .status(422)
        .json({
          success: false,

          completada: true,

          resultado_disponible:
            false,

          message:
            "La aplicación quedó completada, pero no fue posible convertir una o más puntuaciones naturales al baremo correspondiente.",

          brutos,

          escalares,

          faltantes:
            escalaresFaltantes
        });
    }

    /* =====================================================
       SUMA ESCALAR
       ===================================================== */

    const sumaEscalares =
      escalares.claves +
      escalares.figuras +
      escalares.pares +
      escalares.objetos +
      escalares.matrices;

    /* =====================================================
       CONVERSIÓN CI
       ===================================================== */

    const conversion =
      await obtenerConversionCI(
        sumaEscalares,
        connection
      );

    if (!conversion) {
      return res
        .status(422)
        .json({
          success: false,

          completada: true,

          resultado_disponible:
            false,

          message:
            "La aplicación quedó completada, pero no existe conversión CI para la suma de puntuaciones escalares obtenida.",

          suma_escalares:
            sumaEscalares
        });
    }

    /* =====================================================
       INTERPRETACIÓN
       ===================================================== */

    const interpretacion =
      [
        `Beta III obtuvo una puntuación de CI de ${conversion.ci}.`,
        `El resultado corresponde al percentil ${conversion.percentil}.`,
        `Clasificación: ${conversion.clasificacion}.`,
        `Intervalo de confianza al 90%: ${conversion.intervalo_90}.`,
        `Intervalo de confianza al 95%: ${conversion.intervalo_95}.`
      ].join(" ");

    /* =====================================================
       TRANSACCIÓN RESULTADOS
       ===================================================== */

    await connection
      .beginTransaction();

    const idResultado =
      await guardarResultadoGeneralRH(
        connection,
        habilitacion,
        brutos,
        escalares,
        sumaEscalares,
        conversion,
        interpretacion
      );

    /* =====================================================
       GUARDAR RESULTADO BETA III
       ===================================================== */

    await connection.query(
      `
      INSERT INTO resultados_beta3
      (
        id_resultado,
        id_habilitacion,
        id_prospecto,
        id_prueba_rh,

        claves_bruto,
        figuras_bruto,
        pares_bruto,
        objetos_bruto,
        matrices_bruto,

        claves_escalar,
        figuras_escalar,
        pares_escalar,
        objetos_escalar,
        matrices_escalar,

        suma_escalar,
        edad_aplicacion,

        ci,
        percentil,
        clasificacion,
        interpretacion,

        tiempo_total_segundos,
        fecha
      )

      VALUES
      (
        ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?,
        ?, ?, ?, ?,
        ?,
        NOW()
      )

      ON DUPLICATE KEY UPDATE

        id_resultado =
          VALUES(id_resultado),

        claves_bruto =
          VALUES(claves_bruto),

        figuras_bruto =
          VALUES(figuras_bruto),

        pares_bruto =
          VALUES(pares_bruto),

        objetos_bruto =
          VALUES(objetos_bruto),

        matrices_bruto =
          VALUES(matrices_bruto),

        claves_escalar =
          VALUES(claves_escalar),

        figuras_escalar =
          VALUES(figuras_escalar),

        pares_escalar =
          VALUES(pares_escalar),

        objetos_escalar =
          VALUES(objetos_escalar),

        matrices_escalar =
          VALUES(matrices_escalar),

        suma_escalar =
          VALUES(suma_escalar),

        edad_aplicacion =
          VALUES(edad_aplicacion),

        ci =
          VALUES(ci),

        percentil =
          VALUES(percentil),

        clasificacion =
          VALUES(clasificacion),

        interpretacion =
          VALUES(interpretacion),

        tiempo_total_segundos =
          VALUES(tiempo_total_segundos),

        fecha =
          NOW()
      `,
      [
        idResultado,

        habilitacion.id_habilitacion,
        habilitacion.id_prospecto,
        ID_PRUEBA_BETA3_RH,

        brutos.claves,
        brutos.figuras,
        brutos.pares,
        brutos.objetos,
        brutos.matrices,

        escalares.claves,
        escalares.figuras,
        escalares.pares,
        escalares.objetos,
        escalares.matrices,

        sumaEscalares,
        edad,

        conversion.ci,
        conversion.percentil,
        conversion.clasificacion,
        interpretacion,

        numeroSeguro(
          tiempo_total_segundos
        )
      ]
    );

    /* =====================================================
       ASEGURAR COMPLETADA
       ===================================================== */

    await connection.query(
      `
      UPDATE pruebas_prospectos_habilitadas

      SET
        estatus = 'completada',

        fecha_completada =
          COALESCE(
            fecha_completada,
            NOW()
          )

      WHERE id_habilitacion = ?
      `,
      [
        habilitacion.id_habilitacion
      ]
    );

    await connection
      .commit();

    return res.json({
      success: true,

      completada: true,

      resultado_disponible:
        true,

      message:
        "✅ Beta III completada y calculada correctamente.",

      resultado: {
        id_resultado:
          idResultado,

        edad,

        brutos,

        escalares,

        suma_escalares:
          sumaEscalares,

        ci:
          conversion.ci,

        percentil:
          conversion.percentil,

        clasificacion:
          conversion.clasificacion,

        intervalo_90:
          conversion.intervalo_90,

        intervalo_95:
          conversion.intervalo_95
      }
    });

  } catch (error) {
    if (connection) {
      try {
        await connection.rollback();
      } catch {}
    }

    console.error(
      "❌ Error finalizando Beta III:",
      error
    );

    return res
      .status(500)
      .json({
        success: false,

        message:
          "Error interno al finalizar Beta III.",

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

/* =========================================================
   OBTENER RESULTADO BETA III
========================================================= */

export async function obtenerResultadoBeta3(
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
            "Habilitación inválida."
        });
    }

    const [rows] =
      await pool.query(
        `
        SELECT
          rb.*,

          p.nombre
            AS prospecto_nombre,

          p.id_mirror,
          p.puesto,

          pr.nombre
            AS nombre_prueba,

          pr.version,

          c.rango_percentil,
          c.intervalo_90,
          c.intervalo_95

        FROM resultados_beta3 rb

        INNER JOIN prospectos p
          ON p.id_prospecto =
             rb.id_prospecto

        INNER JOIN pruebas_rh pr
          ON pr.id_prueba_rh =
             rb.id_prueba_rh

        LEFT JOIN conversion_ci_beta3 c
          ON c.id_prueba_rh =
             rb.id_prueba_rh

         AND c.suma_escalares =
             rb.suma_escalar

        WHERE rb.id_habilitacion = ?

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
            "Todavía no existe resultado Beta III para esta aplicación."
        });
    }

    const r =
      rows[0];

    return res.json({
      success: true,

      id_resultado_beta3:
        r.id_resultado_beta3,

      id_resultado:
        r.id_resultado,

      id_habilitacion:
        r.id_habilitacion,

      id_prospecto:
        r.id_prospecto,

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

      edad_aplicacion:
        r.edad_aplicacion,

      brutos: {
        claves:
          r.claves_bruto,

        figuras:
          r.figuras_bruto,

        pares:
          r.pares_bruto,

        objetos:
          r.objetos_bruto,

        matrices:
          r.matrices_bruto
      },

      escalares: {
        claves:
          r.claves_escalar,

        figuras:
          r.figuras_escalar,

        pares:
          r.pares_escalar,

        objetos:
          r.objetos_escalar,

        matrices:
          r.matrices_escalar
      },

      suma_escalar:
        r.suma_escalar,

      ci:
        r.ci,

      percentil:
        r.percentil,

      rango_percentil:
        r.rango_percentil,

      clasificacion:
        r.clasificacion,

      intervalo_90:
        r.intervalo_90,

      intervalo_95:
        r.intervalo_95,

      interpretacion:
        r.interpretacion,

      tiempo_total_segundos:
        r.tiempo_total_segundos,

      fecha:
        r.fecha
    });

  } catch (error) {
    console.error(
      "❌ Error obteniendo resultado Beta III:",
      error
    );

    return res
      .status(500)
      .json({
        success: false,
        message:
          "Error al obtener resultado Beta III."
      });
  }
}

/* =========================================================
   OBTENER RESPUESTAS
========================================================= */

export async function obtenerRespuestasBeta3(
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
            "Habilitación inválida."
        });
    }

    const [rows] =
      await pool.query(
        `
        SELECT
          rb.id_respuesta_beta3,
          rb.id_subprueba,

          s.nombre
            AS subprueba,

          rb.id_reactivo_beta3,

          r.numero,

          rb.respuesta,
          rb.correcta,
          rb.tiempo_respuesta_ms,
          rb.fecha_respuesta

        FROM respuestas_beta3 rb

        INNER JOIN reactivos_beta3 r
          ON r.id_reactivo_beta3 =
             rb.id_reactivo_beta3

        INNER JOIN subpruebas_beta3 s
          ON s.id_subprueba =
             rb.id_subprueba

        WHERE rb.id_habilitacion = ?

        ORDER BY
          s.orden,
          r.numero
        `,
        [
          idHabilitacion
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
      "❌ Error obteniendo respuestas Beta III:",
      error
    );

    return res
      .status(500)
      .json({
        success: false,
        message:
          "Error al obtener respuestas Beta III."
      });
  }
}