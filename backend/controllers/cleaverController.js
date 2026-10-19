// backend/controllers/cleaverController.js

import pool from "../config/database.js";

const ID_PRUEBA_CLEAVER = 4;

/* =========================================================
   PERFILES CLEAVER
   Se determina con el patrón T:
   factor más alto / factor más bajo
========================================================= */

const PERFILES_CLEAVER = {
  "D/I": {
    nombre: "Creatividad",
    interpretacion:
      "Tiende a ser lógico, crítico e incisivo en sus enfoques hacia la obtención de metas. Puede sentirse retado por problemas que requieren análisis y originalidad, mostrando franqueza y una actitud crítica ante las situaciones."
  },

  "D/S": {
    nombre: "Empuje",
    interpretacion:
      "Tiende a responder rápidamente a los retos y a mostrar movilidad y flexibilidad en sus enfoques. Puede actuar como iniciador y responder con rapidez ante situaciones competitivas."
  },

  "D/C": {
    nombre: "Individualidad",
    interpretacion:
      "Tiende a actuar de manera directa y positiva ante la oposición. Puede tomar posiciones firmes, asumir riesgos y defender sus decisiones con independencia."
  },

  "I/D": {
    nombre: "Buena Voluntad",
    interpretacion:
      "Tiende a mostrarse cordial y equilibrado en sus relaciones. Busca establecer un ambiente favorable y relaciones armoniosas desde el contacto inicial."
  },

  "I/S": {
    nombre: "Habilidad de Contactos",
    interpretacion:
      "Tiende a buscar el contacto con otras personas con entusiasmo. Puede mostrarse abierto, optimista y persuasivo, utilizando el trato interpersonal como una de sus principales herramientas."
  },

  "I/C": {
    nombre: "Confianza en sí mismo",
    interpretacion:
      "Tiende a mostrar confianza en sí mismo en sus relaciones con otras personas. Busca influir y ganar aceptación, aunque puede mantenerse firme en sus propios puntos de vista."
  },

  "S/D": {
    nombre: "Paciencia",
    interpretacion:
      "Tiende a ser constante y consistente. Suele preferir trabajar con continuidad, atender un proyecto o tarea a la vez y desenvolverse en ambientes relativamente estables."
  },

  "S/I": {
    nombre: "Reflexión (Concentración)",
    interpretacion:
      "Tiende a ser controlado y paciente. Puede actuar con moderación, cuidado y premeditación, concentrándose en las situaciones antes de responder."
  },

  "S/C": {
    nombre: "Persistencia",
    interpretacion:
      "Tiende a ser perseverante y, una vez tomada una decisión, procura mantener el objetivo establecido. Suele adoptar un ritmo de trabajo y apegarse a él, pudiendo mostrar resistencia cuando se le presiona para cambiar."
  },

  "C/D": {
    nombre: "Adaptabilidad",
    interpretacion:
      "Tiende a actuar de manera cuidadosa y conservadora. Puede modificar su posición cuando considera que esto facilita el logro de sus objetivos y suele preferir ambientes con poco antagonismo."
  },

  "C/I": {
    nombre: "Perfeccionismo",
    interpretacion:
      "Tiende a apegarse al orden, los sistemas y los procedimientos establecidos. Suele basar sus decisiones en hechos conocidos y procurar cumplir cuidadosamente con los estándares."
  },

  "C/S": {
    nombre: "Sensibilidad",
    interpretacion:
      "Tiende a estar atento a posibles riesgos o problemas y puede analizar cuidadosamente las situaciones antes de decidir. Bajo presión puede buscar mayor confirmación o seguridad antes de actuar."
  }
};

/* =========================================================
   OBTENER Y VALIDAR HABILITACIÓN CLEAVER
========================================================= */

async function obtenerHabilitacion(id_habilitacion) {
  const [rows] = await pool.query(
    `
    SELECT
      ph.id_habilitacion,
      ph.id_paciente,
      ph.id_sesion,
      ph.id_prueba,
      ph.id_psicologo,
      p.nombre,
      p.tipo,
      p.version
    FROM pruebas_habilitadas ph
    INNER JOIN pruebas p
      ON p.id_prueba = ph.id_prueba
    WHERE ph.id_habilitacion = ?
    LIMIT 1
    `,
    [id_habilitacion]
  );

  if (!rows.length) return null;

  const habilitacion = rows[0];

  if (
    Number(habilitacion.id_prueba) !== ID_PRUEBA_CLEAVER ||
    String(habilitacion.tipo || "").toLowerCase() !== "cleaver"
  ) {
    return null;
  }

  return habilitacion;
}

/* =========================================================
   VALIDAR RESPUESTAS
========================================================= */

async function validarRespuestas(respuestas) {
  if (!Array.isArray(respuestas)) {
    return {
      ok: false,
      message: "Las respuestas deben enviarse como arreglo"
    };
  }

  if (respuestas.length !== 24) {
    return {
      ok: false,
      message: "Cleaver debe contener exactamente 24 grupos respondidos"
    };
  }

  const preguntasRecibidas = new Set();

  for (const respuesta of respuestas) {
    const idPregunta = Number(respuesta.id_pregunta);
    const idMas = Number(respuesta.id_opcion_mas);
    const idMenos = Number(respuesta.id_opcion_menos);

    if (!idPregunta || !idMas || !idMenos) {
      return {
        ok: false,
        message:
          "Cada grupo debe incluir pregunta, opción MÁS y opción MENOS"
      };
    }

    if (idMas === idMenos) {
      return {
        ok: false,
        message:
          `La opción MÁS y MENOS deben ser diferentes en la pregunta ${idPregunta}`
      };
    }

    if (preguntasRecibidas.has(idPregunta)) {
      return {
        ok: false,
        message: `La pregunta ${idPregunta} está repetida`
      };
    }

    preguntasRecibidas.add(idPregunta);
  }

  const idsPreguntas = [...preguntasRecibidas];

  const [preguntasValidas] = await pool.query(
    `
    SELECT id_pregunta
    FROM preguntas_prueba
    WHERE id_prueba = ?
      AND id_pregunta IN (?)
    `,
    [ID_PRUEBA_CLEAVER, idsPreguntas]
  );

  if (preguntasValidas.length !== 24) {
    return {
      ok: false,
      message:
        "Una o más preguntas no pertenecen a la prueba Cleaver"
    };
  }

  for (const respuesta of respuestas) {
    const idPregunta = Number(respuesta.id_pregunta);
    const idMas = Number(respuesta.id_opcion_mas);
    const idMenos = Number(respuesta.id_opcion_menos);

    const [opciones] = await pool.query(
      `
      SELECT id_opcion
      FROM opciones_respuesta
      WHERE id_pregunta = ?
        AND id_opcion IN (?, ?)
      `,
      [idPregunta, idMas, idMenos]
    );

    if (opciones.length !== 2) {
      return {
        ok: false,
        message:
          `Las opciones seleccionadas no corresponden al grupo ${idPregunta}`
      };
    }
  }

  return { ok: true };
}

/* =========================================================
   CALCULAR M Y L
========================================================= */

async function calcularML(id_habilitacion) {
  const resultado = {
    M: { D: 0, I: 0, S: 0, C: 0 },
    L: { D: 0, I: 0, S: 0, C: 0 }
  };

  const [mas] = await pool.query(
    `
    SELECT
      cc.factor,
      COUNT(*) AS total
    FROM respuestas_cleaver rc
    INNER JOIN claves_cleaver cc
      ON cc.id_prueba = rc.id_prueba
     AND cc.id_pregunta = rc.id_pregunta
     AND cc.id_opcion = rc.id_opcion_mas
     AND cc.seleccion = 'M'
    WHERE rc.id_habilitacion = ?
      AND rc.id_prueba = ?
    GROUP BY cc.factor
    `,
    [id_habilitacion, ID_PRUEBA_CLEAVER]
  );

  for (const fila of mas) {
    if (resultado.M[fila.factor] !== undefined) {
      resultado.M[fila.factor] = Number(fila.total);
    }
  }

  const [menos] = await pool.query(
    `
    SELECT
      cc.factor,
      COUNT(*) AS total
    FROM respuestas_cleaver rc
    INNER JOIN claves_cleaver cc
      ON cc.id_prueba = rc.id_prueba
     AND cc.id_pregunta = rc.id_pregunta
     AND cc.id_opcion = rc.id_opcion_menos
     AND cc.seleccion = 'L'
    WHERE rc.id_habilitacion = ?
      AND rc.id_prueba = ?
    GROUP BY cc.factor
    `,
    [id_habilitacion, ID_PRUEBA_CLEAVER]
  );

  for (const fila of menos) {
    if (resultado.L[fila.factor] !== undefined) {
      resultado.L[fila.factor] = Number(fila.total);
    }
  }

  return resultado;
}

/* =========================================================
   CALCULAR T

   T = M - L
========================================================= */

function calcularT(resultado) {
  return {
    D: Number(resultado.M.D) - Number(resultado.L.D),
    I: Number(resultado.M.I) - Number(resultado.L.I),
    S: Number(resultado.M.S) - Number(resultado.L.S),
    C: Number(resultado.M.C) - Number(resultado.L.C)
  };
}

/* =========================================================
   CONVERSIONES / POSICIONES GRÁFICAS
========================================================= */

async function obtenerConversiones(resultado) {
  const [rows] = await pool.query(
    `
    SELECT
      patron,
      factor,
      puntaje_bruto,
      percentil,
      posicion_grafica
    FROM conversion_cleaver
    WHERE id_prueba = ?
    `,
    [ID_PRUEBA_CLEAVER]
  );

  const mapa = new Map();

  for (const fila of rows) {
    const clave =
      `${fila.patron}-${fila.factor}-${fila.puntaje_bruto}`;

    mapa.set(clave, {
      percentil:
        fila.percentil !== null
          ? Number(fila.percentil)
          : null,

      posicion:
        fila.posicion_grafica !== null
          ? Number(fila.posicion_grafica)
          : null
    });
  }

  const obtener = (patron, factor, bruto) => {
    const clave = `${patron}-${factor}-${bruto}`;

    return (
      mapa.get(clave) || {
        percentil: null,
        posicion: null
      }
    );
  };

  return {
    M: {
      D: obtener("M", "D", resultado.M.D),
      I: obtener("M", "I", resultado.M.I),
      S: obtener("M", "S", resultado.M.S),
      C: obtener("M", "C", resultado.M.C)
    },

    L: {
      D: obtener("L", "D", resultado.L.D),
      I: obtener("L", "I", resultado.L.I),
      S: obtener("L", "S", resultado.L.S),
      C: obtener("L", "C", resultado.L.C)
    },

    T: {
      D: obtener("T", "D", resultado.T.D),
      I: obtener("T", "I", resultado.T.I),
      S: obtener("T", "S", resultado.T.S),
      C: obtener("T", "C", resultado.T.C)
    }
  };
}

/* =========================================================
   DETERMINAR PERFIL CLEAVER

   Se usa el patrón T.

   Ejemplo actual:
   D = 47
   I = 61
   S = 75  -> más alto
   C = 40  -> más bajo

   Resultado:
   S/C = Persistencia
========================================================= */

function determinarPerfilCleaver(conversiones) {
  const posicionesT = {
    D: conversiones?.T?.D?.posicion,
    I: conversiones?.T?.I?.posicion,
    S: conversiones?.T?.S?.posicion,
    C: conversiones?.T?.C?.posicion
  };

  const disponibles = Object.entries(posicionesT)
    .filter(
      ([, valor]) =>
        valor !== null &&
        valor !== undefined &&
        !Number.isNaN(Number(valor))
    )
    .map(([factor, valor]) => ({
      factor,
      valor: Number(valor)
    }));

  if (disponibles.length !== 4) {
    return {
      codigo: null,
      nombre: null,
      interpretacion:
        "No fue posible determinar el perfil Cleaver porque faltan posiciones gráficas del patrón T."
    };
  }

  const valores = disponibles.map(item => item.valor);

  /* =====================================================
     PERFIL APLANADO

     Cuando todos los factores T se encuentran en
     una zona media 40-60 no se fuerza una combinación.
  ===================================================== */

  const aplanado = valores.every(
    valor =>
      valor >= 40 &&
      valor <= 60
  );

  if (aplanado) {
    return {
      codigo: "APLANADO",
      nombre: "Perfil aplanado",
      interpretacion:
        "Las cuatro dimensiones del patrón T se encuentran concentradas en una zona media. No se observa una diferenciación suficiente para asignar una combinación conductual predominante únicamente con el patrón T. Se recomienda revisar conjuntamente los patrones M y L."
    };
  }

  const ordenados = [...disponibles].sort(
    (a, b) => b.valor - a.valor
  );

  const mayor = ordenados[0];
  const menor = ordenados[ordenados.length - 1];

  const codigo =
    `${mayor.factor}/${menor.factor}`;

  const perfil =
    PERFILES_CLEAVER[codigo];

  if (!perfil) {
    return {
      codigo,
      nombre: codigo,
      interpretacion:
        "Se calculó la combinación conductual Cleaver, pero no existe una interpretación configurada para este perfil."
    };
  }

  return {
    codigo,
    nombre: perfil.nombre,
    interpretacion: perfil.interpretacion
  };
}

/* =========================================================
   CREAR / ACTUALIZAR RESULTADO GENERAL
========================================================= */

async function guardarResultadoGeneral(
  connection,
  id_paciente,
  id_habilitacion,
  id_sesion
) {
  const interpretacion =
    "Resultado multidimensional Cleaver. Consulte el detalle D/I/S/C.";

  const [existente] = await connection.query(
    `
    SELECT id_resultado
    FROM resultados_prueba
    WHERE id_paciente = ?
      AND id_prueba = ?
      AND id_habilitacion = ?
    LIMIT 1
    `,
    [
      id_paciente,
      ID_PRUEBA_CLEAVER,
      id_habilitacion
    ]
  );

  if (existente.length) {
    const idResultado =
      existente[0].id_resultado;

    await connection.query(
      `
      UPDATE resultados_prueba
      SET
        puntaje_total = 0,
        interpretacion = ?,
        id_sesion = ?,
        fecha = NOW()
      WHERE id_resultado = ?
      `,
      [
        interpretacion,
        id_sesion,
        idResultado
      ]
    );

    return idResultado;
  }

  const [insert] = await connection.query(
    `
    INSERT INTO resultados_prueba
    (
      id_paciente,
      id_prueba,
      id_habilitacion,
      id_sesion,
      puntaje_total,
      interpretacion,
      fecha
    )
    VALUES (?, ?, ?, ?, 0, ?, NOW())
    `,
    [
      id_paciente,
      ID_PRUEBA_CLEAVER,
      id_habilitacion,
      id_sesion,
      interpretacion
    ]
  );

  return insert.insertId;
}

/* =========================================================
   GUARDAR RESPUESTAS CLEAVER
========================================================= */

export async function guardarRespuestasCleaver(req, res) {
  const {
    id_habilitacion,
    respuestas
  } = req.body;

  if (!id_habilitacion) {
    return res.status(400).json({
      success: false,
      message: "Falta id_habilitacion"
    });
  }

  const connection =
    await pool.getConnection();

  try {
    const habilitacion =
      await obtenerHabilitacion(
        id_habilitacion
      );

    if (!habilitacion) {
      return res.status(404).json({
        success: false,
        message:
          "Habilitación Cleaver no encontrada"
      });
    }

    const validacion =
      await validarRespuestas(
        respuestas
      );

    if (!validacion.ok) {
      return res.status(400).json({
        success: false,
        message:
          validacion.message
      });
    }

    await connection.beginTransaction();

    await connection.query(
      `
      DELETE FROM respuestas_cleaver
      WHERE id_habilitacion = ?
      `,
      [id_habilitacion]
    );

    const valores =
      respuestas.map(
        respuesta => [
          habilitacion.id_paciente,
          ID_PRUEBA_CLEAVER,
          id_habilitacion,
          habilitacion.id_sesion || null,
          Number(
            respuesta.id_pregunta
          ),
          Number(
            respuesta.id_opcion_mas
          ),
          Number(
            respuesta.id_opcion_menos
          )
        ]
      );

    await connection.query(
      `
      INSERT INTO respuestas_cleaver
      (
        id_paciente,
        id_prueba,
        id_habilitacion,
        id_sesion,
        id_pregunta,
        id_opcion_mas,
        id_opcion_menos
      )
      VALUES ?
      `,
      [valores]
    );

    await connection.commit();

    return res.json({
      success: true,
      total_respuestas:
        valores.length,
      id_habilitacion:
        Number(id_habilitacion),
      message:
        "✅ Respuestas Cleaver guardadas correctamente"
    });

  } catch (err) {
    try {
      await connection.rollback();
    } catch {}

    console.error(
      "❌ Error al guardar Cleaver:",
      err
    );

    return res.status(500).json({
      success: false,
      message:
        "Error al guardar las respuestas Cleaver",
      error: err.message
    });

  } finally {
    connection.release();
  }
}

/* =========================================================
   FINALIZAR CLEAVER

   1. Calcula M
   2. Calcula L
   3. Calcula T = M - L
   4. Obtiene posiciones gráficas
   5. Determina perfil
   6. Guarda resultado
========================================================= */

export async function finalizarCleaver(req, res) {
  const {
    id_habilitacion
  } = req.body;

  if (!id_habilitacion) {
    return res.status(400).json({
      success: false,
      message: "Falta id_habilitacion"
    });
  }

  const connection =
    await pool.getConnection();

  try {
    const habilitacion =
      await obtenerHabilitacion(
        id_habilitacion
      );

    if (!habilitacion) {
      return res.status(404).json({
        success: false,
        message:
          "Habilitación Cleaver no encontrada"
      });
    }

    /* =====================================================
       VALIDAR 24 RESPUESTAS
    ===================================================== */

    const [cantidad] =
      await connection.query(
        `
        SELECT COUNT(*) AS total
        FROM respuestas_cleaver
        WHERE id_habilitacion = ?
          AND id_prueba = ?
        `,
        [
          id_habilitacion,
          ID_PRUEBA_CLEAVER
        ]
      );

    if (
      Number(
        cantidad[0]?.total || 0
      ) !== 24
    ) {
      return res.status(400).json({
        success: false,
        message:
          "La prueba debe tener los 24 grupos contestados antes de finalizar"
      });
    }

    /* =====================================================
       M Y L
    ===================================================== */

    const ml =
      await calcularML(
        id_habilitacion
      );

    /* =====================================================
       T
    ===================================================== */

    const T =
      calcularT(ml);

    const resultado = {
      M: ml.M,
      L: ml.L,
      T
    };

    /* =====================================================
       CONVERSIONES
    ===================================================== */

    const conversiones =
      await obtenerConversiones(
        resultado
      );

    /* =====================================================
       PERFIL
    ===================================================== */

    const perfil =
      determinarPerfilCleaver(
        conversiones
      );

    console.log(
      "📊 CLEAVER CALCULADO:",
      {
        bruto: resultado,
        conversiones,
        perfil
      }
    );

    await connection.beginTransaction();

    /* =====================================================
       RESULTADO GENERAL
    ===================================================== */

    const idResultado =
      await guardarResultadoGeneral(
        connection,
        habilitacion.id_paciente,
        id_habilitacion,
        habilitacion.id_sesion || null
      );

    /* =====================================================
       RESULTADO CLEAVER
    ===================================================== */

    await connection.query(
      `
      INSERT INTO resultados_cleaver
      (
        id_resultado,
        id_paciente,
        id_prueba,
        id_habilitacion,
        id_sesion,

        m_d_bruto,
        m_i_bruto,
        m_s_bruto,
        m_c_bruto,

        l_d_bruto,
        l_i_bruto,
        l_s_bruto,
        l_c_bruto,

        t_d_bruto,
        t_i_bruto,
        t_s_bruto,
        t_c_bruto,

        m_d_percentil,
        m_d_posicion,

        m_i_percentil,
        m_i_posicion,

        m_s_percentil,
        m_s_posicion,

        m_c_percentil,
        m_c_posicion,

        l_d_percentil,
        l_d_posicion,

        l_i_percentil,
        l_i_posicion,

        l_s_percentil,
        l_s_posicion,

        l_c_percentil,
        l_c_posicion,

        t_d_percentil,
        t_d_posicion,

        t_i_percentil,
        t_i_posicion,

        t_s_percentil,
        t_s_posicion,

        t_c_percentil,
        t_c_posicion,

        perfil_principal,
        interpretacion,
        fecha
      )

      VALUES
      (
        ?, ?, ?, ?, ?,

        ?, ?, ?, ?,

        ?, ?, ?, ?,

        ?, ?, ?, ?,

        ?, ?,
        ?, ?,
        ?, ?,
        ?, ?,

        ?, ?,
        ?, ?,
        ?, ?,
        ?, ?,

        ?, ?,
        ?, ?,
        ?, ?,
        ?, ?,

        ?, ?,

        NOW()
      )

      ON DUPLICATE KEY UPDATE

        id_resultado =
          VALUES(id_resultado),

        id_sesion =
          VALUES(id_sesion),

        m_d_bruto =
          VALUES(m_d_bruto),

        m_i_bruto =
          VALUES(m_i_bruto),

        m_s_bruto =
          VALUES(m_s_bruto),

        m_c_bruto =
          VALUES(m_c_bruto),

        l_d_bruto =
          VALUES(l_d_bruto),

        l_i_bruto =
          VALUES(l_i_bruto),

        l_s_bruto =
          VALUES(l_s_bruto),

        l_c_bruto =
          VALUES(l_c_bruto),

        t_d_bruto =
          VALUES(t_d_bruto),

        t_i_bruto =
          VALUES(t_i_bruto),

        t_s_bruto =
          VALUES(t_s_bruto),

        t_c_bruto =
          VALUES(t_c_bruto),

        m_d_percentil =
          VALUES(m_d_percentil),

        m_d_posicion =
          VALUES(m_d_posicion),

        m_i_percentil =
          VALUES(m_i_percentil),

        m_i_posicion =
          VALUES(m_i_posicion),

        m_s_percentil =
          VALUES(m_s_percentil),

        m_s_posicion =
          VALUES(m_s_posicion),

        m_c_percentil =
          VALUES(m_c_percentil),

        m_c_posicion =
          VALUES(m_c_posicion),

        l_d_percentil =
          VALUES(l_d_percentil),

        l_d_posicion =
          VALUES(l_d_posicion),

        l_i_percentil =
          VALUES(l_i_percentil),

        l_i_posicion =
          VALUES(l_i_posicion),

        l_s_percentil =
          VALUES(l_s_percentil),

        l_s_posicion =
          VALUES(l_s_posicion),

        l_c_percentil =
          VALUES(l_c_percentil),

        l_c_posicion =
          VALUES(l_c_posicion),

        t_d_percentil =
          VALUES(t_d_percentil),

        t_d_posicion =
          VALUES(t_d_posicion),

        t_i_percentil =
          VALUES(t_i_percentil),

        t_i_posicion =
          VALUES(t_i_posicion),

        t_s_percentil =
          VALUES(t_s_percentil),

        t_s_posicion =
          VALUES(t_s_posicion),

        t_c_percentil =
          VALUES(t_c_percentil),

        t_c_posicion =
          VALUES(t_c_posicion),

        perfil_principal =
          VALUES(perfil_principal),

        interpretacion =
          VALUES(interpretacion),

        fecha =
          NOW()
      `,
      [
        /* GENERAL */
        idResultado,
        habilitacion.id_paciente,
        ID_PRUEBA_CLEAVER,
        id_habilitacion,
        habilitacion.id_sesion || null,

        /* M BRUTO */
        resultado.M.D,
        resultado.M.I,
        resultado.M.S,
        resultado.M.C,

        /* L BRUTO */
        resultado.L.D,
        resultado.L.I,
        resultado.L.S,
        resultado.L.C,

        /* T BRUTO */
        resultado.T.D,
        resultado.T.I,
        resultado.T.S,
        resultado.T.C,

        /* M D */
        conversiones.M.D.percentil,
        conversiones.M.D.posicion,

        /* M I */
        conversiones.M.I.percentil,
        conversiones.M.I.posicion,

        /* M S */
        conversiones.M.S.percentil,
        conversiones.M.S.posicion,

        /* M C */
        conversiones.M.C.percentil,
        conversiones.M.C.posicion,

        /* L D */
        conversiones.L.D.percentil,
        conversiones.L.D.posicion,

        /* L I */
        conversiones.L.I.percentil,
        conversiones.L.I.posicion,

        /* L S */
        conversiones.L.S.percentil,
        conversiones.L.S.posicion,

        /* L C */
        conversiones.L.C.percentil,
        conversiones.L.C.posicion,

        /* T D */
        conversiones.T.D.percentil,
        conversiones.T.D.posicion,

        /* T I */
        conversiones.T.I.percentil,
        conversiones.T.I.posicion,

        /* T S */
        conversiones.T.S.percentil,
        conversiones.T.S.posicion,

        /* T C */
        conversiones.T.C.percentil,
        conversiones.T.C.posicion,

        /* PERFIL */
        perfil.nombre
          ? `${perfil.codigo} - ${perfil.nombre}`
          : null,

        perfil.interpretacion || null
      ]
    );

    await connection.commit();

    return res.json({
      success: true,

      id_resultado:
        idResultado,

      id_habilitacion:
        Number(
          id_habilitacion
        ),

      id_paciente:
        Number(
          habilitacion.id_paciente
        ),

      id_sesion:
        habilitacion.id_sesion ||
        null,

      resultado: {
        M: resultado.M,
        L: resultado.L,
        T: resultado.T
      },

      posiciones: {
        M: {
          D:
            conversiones.M.D.posicion,
          I:
            conversiones.M.I.posicion,
          S:
            conversiones.M.S.posicion,
          C:
            conversiones.M.C.posicion
        },

        L: {
          D:
            conversiones.L.D.posicion,
          I:
            conversiones.L.I.posicion,
          S:
            conversiones.L.S.posicion,
          C:
            conversiones.L.C.posicion
        },

        T: {
          D:
            conversiones.T.D.posicion,
          I:
            conversiones.T.I.posicion,
          S:
            conversiones.T.S.posicion,
          C:
            conversiones.T.C.posicion
        }
      },

      perfil: {
        codigo:
          perfil.codigo,
        nombre:
          perfil.nombre,
        interpretacion:
          perfil.interpretacion
      },

      message:
        "✅ Cleaver calculado. M, L, T, posiciones y perfil disponibles."
    });

  } catch (err) {
    try {
      await connection.rollback();
    } catch {}

    console.error(
      "❌ Error al finalizar Cleaver:",
      err
    );

    return res.status(500).json({
      success: false,
      message:
        "Error al finalizar la prueba Cleaver",
      error: err.message
    });

  } finally {
    connection.release();
  }
}

/* =========================================================
   OBTENER RESULTADO CLEAVER
========================================================= */

export async function obtenerResultadoCleaver(req, res) {
  const {
    id_habilitacion
  } = req.params;

  if (!id_habilitacion) {
    return res.status(400).json({
      success: false,
      message: "Falta id_habilitacion"
    });
  }

  try {
    const [rows] =
      await pool.query(
        `
        SELECT
          rc.id_resultado_cleaver,
          rc.id_resultado,
          rc.id_paciente,
          rc.id_prueba,
          rc.id_habilitacion,
          rc.id_sesion,

          rc.m_d_bruto,
          rc.m_i_bruto,
          rc.m_s_bruto,
          rc.m_c_bruto,

          rc.l_d_bruto,
          rc.l_i_bruto,
          rc.l_s_bruto,
          rc.l_c_bruto,

          rc.t_d_bruto,
          rc.t_i_bruto,
          rc.t_s_bruto,
          rc.t_c_bruto,

          rc.m_d_percentil,
          rc.m_d_posicion,

          rc.m_i_percentil,
          rc.m_i_posicion,

          rc.m_s_percentil,
          rc.m_s_posicion,

          rc.m_c_percentil,
          rc.m_c_posicion,

          rc.l_d_percentil,
          rc.l_d_posicion,

          rc.l_i_percentil,
          rc.l_i_posicion,

          rc.l_s_percentil,
          rc.l_s_posicion,

          rc.l_c_percentil,
          rc.l_c_posicion,

          rc.t_d_percentil,
          rc.t_d_posicion,

          rc.t_i_percentil,
          rc.t_i_posicion,

          rc.t_s_percentil,
          rc.t_s_posicion,

          rc.t_c_percentil,
          rc.t_c_posicion,

          rc.perfil_principal,
          rc.interpretacion,
          rc.fecha,

          p.nombre AS nombre_prueba,
          p.version

        FROM resultados_cleaver rc

        INNER JOIN pruebas p
          ON p.id_prueba =
             rc.id_prueba

        WHERE rc.id_habilitacion = ?

        LIMIT 1
        `,
        [id_habilitacion]
      );

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        message:
          "Todavía no existe resultado Cleaver para esta habilitación"
      });
    }

    const r = rows[0];

    return res.json({
      success: true,

      id_resultado_cleaver:
        r.id_resultado_cleaver,

      id_resultado:
        r.id_resultado,

      id_paciente:
        r.id_paciente,

      id_habilitacion:
        r.id_habilitacion,

      id_sesion:
        r.id_sesion,

      prueba: {
        nombre:
          r.nombre_prueba,
        version:
          r.version
      },

      bruto: {
        M: {
          D: r.m_d_bruto,
          I: r.m_i_bruto,
          S: r.m_s_bruto,
          C: r.m_c_bruto
        },

        L: {
          D: r.l_d_bruto,
          I: r.l_i_bruto,
          S: r.l_s_bruto,
          C: r.l_c_bruto
        },

        T: {
          D: r.t_d_bruto,
          I: r.t_i_bruto,
          S: r.t_s_bruto,
          C: r.t_c_bruto
        }
      },

      percentiles: {
        M: {
          D: r.m_d_percentil,
          I: r.m_i_percentil,
          S: r.m_s_percentil,
          C: r.m_c_percentil
        },

        L: {
          D: r.l_d_percentil,
          I: r.l_i_percentil,
          S: r.l_s_percentil,
          C: r.l_c_percentil
        },

        T: {
          D: r.t_d_percentil,
          I: r.t_i_percentil,
          S: r.t_s_percentil,
          C: r.t_c_percentil
        }
      },

      posiciones: {
        M: {
          D: r.m_d_posicion,
          I: r.m_i_posicion,
          S: r.m_s_posicion,
          C: r.m_c_posicion
        },

        L: {
          D: r.l_d_posicion,
          I: r.l_i_posicion,
          S: r.l_s_posicion,
          C: r.l_c_posicion
        },

        T: {
          D: r.t_d_posicion,
          I: r.t_i_posicion,
          S: r.t_s_posicion,
          C: r.t_c_posicion
        }
      },

      perfil_principal:
        r.perfil_principal,

      interpretacion:
        r.interpretacion,

      fecha:
        r.fecha
    });

  } catch (err) {
    console.error(
      "❌ Error al obtener resultado Cleaver:",
      err
    );

    return res.status(500).json({
      success: false,
      message:
        "Error al obtener resultado Cleaver",
      error:
        err.message
    });
  }
}

/* =========================================================
   OBTENER RESPUESTAS CLEAVER
========================================================= */

export async function obtenerRespuestasCleaver(req, res) {
  const {
    id_habilitacion
  } = req.params;

  try {
    const [rows] =
      await pool.query(
        `
        SELECT
          rc.id_respuesta_cleaver,
          rc.id_pregunta,

          p.texto AS grupo,

          rc.id_opcion_mas,

          om.texto AS opcion_mas,

          rc.id_opcion_menos,

          ome.texto AS opcion_menos,

          rc.fecha_respuesta

        FROM respuestas_cleaver rc

        INNER JOIN preguntas_prueba p
          ON p.id_pregunta =
             rc.id_pregunta

        INNER JOIN opciones_respuesta om
          ON om.id_opcion =
             rc.id_opcion_mas

        INNER JOIN opciones_respuesta ome
          ON ome.id_opcion =
             rc.id_opcion_menos

        WHERE rc.id_habilitacion = ?
          AND rc.id_prueba = ?

        ORDER BY
          rc.id_pregunta ASC
        `,
        [
          id_habilitacion,
          ID_PRUEBA_CLEAVER
        ]
      );

    return res.json({
      success: true,
      total:
        rows.length,
      respuestas:
        rows
    });

  } catch (err) {
    console.error(
      "❌ Error al obtener respuestas Cleaver:",
      err
    );

    return res.status(500).json({
      success: false,
      message:
        "Error al obtener respuestas Cleaver",
      error:
        err.message
    });
  }
}