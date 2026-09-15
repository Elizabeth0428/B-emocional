// backend/controllers/evaluationController.js

import pool from "../config/database.js";


/* ==================================================
   OBTENER TODAS LAS PRUEBAS
================================================== */

export async function obtenerPruebas(req, res) {

  try {

    const [rows] = await pool.query(
      `SELECT
        id_prueba,
        nombre,
        descripcion,
        tipo,
        version,
        activo
       FROM pruebas
       ORDER BY id_prueba DESC`
    );

    res.json(rows || []);

  } catch (err) {

    console.error(
      "❌ Error al obtener pruebas:",
      err.message
    );

    res.status(500).json({
      message: "Error al obtener pruebas"
    });

  }

}


/* ==================================================
   HABILITAR PRUEBA PARA PACIENTE
================================================== */

export async function habilitarPrueba(req, res) {

  const {
    id_paciente,
    id_prueba,
    notas
  } = req.body;

  const id_psicologo =
    req.user?.id_psicologo;


  if (
    !id_paciente ||
    !id_prueba ||
    !id_psicologo
  ) {

    return res.status(400).json({
      message: "Faltan datos"
    });

  }


  try {

    await pool.query(
      `INSERT INTO pruebas_habilitadas
       (
         id_paciente,
         id_prueba,
         id_psicologo,
         notas
       )
       VALUES (?, ?, ?, ?)`,
      [
        id_paciente,
        id_prueba,
        id_psicologo,
        notas || null
      ]
    );


    res.json({
      message: "✅ Prueba habilitada"
    });


  } catch (err) {

    console.error(
      "❌ Error al habilitar prueba:",
      err.message
    );

    res.status(500).json({
      message: "Error al habilitar prueba"
    });

  }

}


/* ==================================================
   OBTENER PRUEBAS HABILITADAS DE UN PACIENTE
================================================== */

export async function obtenerPruebasHabilitadas(
  req,
  res
) {

  const { id_paciente } =
    req.params;


  try {

    const [rows] = await pool.query(
      `SELECT
        ph.id_habilitacion,
        pr.id_prueba,
        pr.nombre,
        pr.descripcion,
        pr.tipo,
        ph.fecha
       FROM pruebas_habilitadas ph
       JOIN pruebas pr
         ON ph.id_prueba = pr.id_prueba
       WHERE ph.id_paciente = ?
       ORDER BY ph.fecha DESC`,
      [id_paciente]
    );


    res.json(rows || []);


  } catch (err) {

    console.error(
      "❌ Error al obtener pruebas habilitadas:",
      err.message
    );

    res.status(500).json({
      message:
        "Error al obtener pruebas habilitadas"
    });

  }

}


/* ==================================================
   OBTENER PREGUNTAS DE UNA PRUEBA
   INCLUYE OPCIONES DE RESPUESTA
================================================== */

export async function obtenerPreguntasPrueba(
  req,
  res
) {

  const { id } = req.params;


  try {

    const [preguntas] =
      await pool.query(
        `SELECT *
         FROM preguntas_prueba
         WHERE id_prueba = ?`,
        [id]
      );


    /* ================================================
       OBTENER OPCIONES DE CADA PREGUNTA
    ================================================ */

    for (const pregunta of preguntas) {

      const [opciones] =
        await pool.query(
          `SELECT *
           FROM opciones_respuesta
           WHERE id_pregunta = ?`,
          [pregunta.id_pregunta]
        );

      pregunta.opciones =
        opciones;

    }


    res.json(
      preguntas || []
    );


  } catch (err) {

    console.error(
      "❌ Error al obtener preguntas:",
      err.message
    );

    res.status(500).json({
      message:
        "Error al obtener preguntas"
    });

  }

}


/* ==================================================
   FUNCIÓN PARA INTERPRETAR RESULTADO
================================================== */

function obtenerInterpretacion(
  id_prueba,
  puntaje_total
) {

  let interpretacion =
    "Sin interpretación";


  /* ================================================
     PRUEBA 3 — ANSIEDAD
  ================================================ */

  if (+id_prueba === 3) {

    interpretacion =
      puntaje_total < 5
        ? "Ansiedad mínima"
        : puntaje_total < 10
        ? "Ansiedad leve"
        : puntaje_total < 15
        ? "Ansiedad moderada"
        : "Ansiedad severa";

  }


  /* ================================================
     PRUEBA 2 — ESTRÉS
  ================================================ */

  if (+id_prueba === 2) {

    interpretacion =
      puntaje_total < 14
        ? "Estrés bajo"
        : puntaje_total < 27
        ? "Estrés moderado"
        : "Estrés alto";

  }


  /* ================================================
     PRUEBA 1 — DEPRESIÓN
  ================================================ */

  if (+id_prueba === 1) {

    interpretacion =
      puntaje_total < 10
        ? "Depresión mínima"
        : puntaje_total < 20
        ? "Depresión leve"
        : puntaje_total < 30
        ? "Depresión moderada"
        : "Depresión severa";

  }


  return interpretacion;

}


/* ==================================================
   FINALIZAR PRUEBA
   REQUIERE LOGIN
================================================== */

export async function finalizarPrueba(
  req,
  res
) {

  const { id } =
    req.params;

  const {
    id_paciente,
    id_habilitacion,
    id_sesion
  } = req.body;


  if (
    !id_paciente ||
    !id_habilitacion
  ) {

    return res.status(400).json({
      message:
        "Faltan datos obligatorios (id_paciente, id_habilitacion)"
    });

  }


  try {

    /* ================================================
       1. CALCULAR PUNTAJE
    ================================================ */

    const [rows] =
      await pool.query(
        `SELECT
          SUM(o.valor) AS total
         FROM respuestas_prueba r
         JOIN opciones_respuesta o
           ON r.id_opcion = o.id_opcion
         WHERE r.id_prueba = ?
         AND r.id_paciente = ?
         AND r.id_habilitacion = ?`,
        [
          id,
          id_paciente,
          id_habilitacion
        ]
      );


    const puntaje_total =
      rows[0]?.total || 0;


    /* ================================================
       2. INTERPRETACIÓN
    ================================================ */

    const interpretacion =
      obtenerInterpretacion(
        id,
        puntaje_total
      );


    /* ================================================
       3. BUSCAR RESULTADO EXISTENTE
    ================================================ */

    const [existe] =
      await pool.query(
        `SELECT
          id_resultado
         FROM resultados_prueba
         WHERE id_paciente = ?
         AND id_prueba = ?
         AND id_habilitacion = ?`,
        [
          id_paciente,
          id,
          id_habilitacion
        ]
      );


    /* ================================================
       4. ACTUALIZAR O INSERTAR
    ================================================ */

    if (existe.length > 0) {

      await pool.query(
        `UPDATE resultados_prueba
         SET
           puntaje_total = ?,
           interpretacion = ?,
           id_sesion = ?,
           fecha = NOW()
         WHERE id_resultado = ?`,
        [
          puntaje_total,
          interpretacion,
          id_sesion || null,
          existe[0].id_resultado
        ]
      );

    } else {

      await pool.query(
        `INSERT INTO resultados_prueba
         (
           id_paciente,
           id_prueba,
           id_habilitacion,
           puntaje_total,
           interpretacion,
           id_sesion,
           fecha
         )
         VALUES (?, ?, ?, ?, ?, ?, NOW())`,
        [
          id_paciente,
          id,
          id_habilitacion,
          puntaje_total,
          interpretacion,
          id_sesion || null
        ]
      );

    }


    /* ================================================
       5. RESPUESTA
    ================================================ */

    res.json({
      puntaje_total,
      interpretacion
    });


  } catch (err) {

    console.error(
      "❌ Error al finalizar prueba:",
      err.message
    );

    res.status(500).json({
      message:
        "Error al finalizar prueba"
    });

  }

}


/* ==================================================
   FINALIZAR PRUEBA PÚBLICA
   SIN LOGIN
================================================== */

export async function finalizarPruebaPublica(
  req,
  res
) {

  const { id } =
    req.params;

  const {
    id_paciente,
    id_habilitacion,
    id_sesion
  } = req.body;


  if (
    !id_paciente ||
    !id_habilitacion
  ) {

    return res.status(400).json({
      message:
        "Faltan datos obligatorios (id_paciente, id_habilitacion)"
    });

  }


  try {

    /* ================================================
       1. CALCULAR PUNTAJE
    ================================================ */

    const [rows] =
      await pool.query(
        `SELECT
          SUM(o.valor) AS total
         FROM respuestas_prueba r
         JOIN opciones_respuesta o
           ON r.id_opcion = o.id_opcion
         WHERE r.id_prueba = ?
         AND r.id_paciente = ?
         AND r.id_habilitacion = ?`,
        [
          id,
          id_paciente,
          id_habilitacion
        ]
      );


    const puntaje_total =
      rows[0]?.total || 0;


    /* ================================================
       2. INTERPRETACIÓN
    ================================================ */

    const interpretacion =
      obtenerInterpretacion(
        id,
        puntaje_total
      );


    /* ================================================
       3. GUARDAR RESULTADO
    ================================================ */

    await pool.query(
      `INSERT INTO resultados_prueba
       (
         id_paciente,
         id_prueba,
         id_habilitacion,
         id_sesion,
         puntaje_total,
         interpretacion,
         fecha
       )
       VALUES (?, ?, ?, ?, ?, ?, NOW())
       ON DUPLICATE KEY UPDATE
         puntaje_total =
           VALUES(puntaje_total),
         interpretacion =
           VALUES(interpretacion),
         id_sesion =
           VALUES(id_sesion),
         fecha = NOW()`,
      [
        id_paciente,
        id,
        id_habilitacion,
        id_sesion || null,
        puntaje_total,
        interpretacion
      ]
    );


    /* ================================================
       4. RESPUESTA
    ================================================ */

    res.json({
      puntaje_total,
      interpretacion
    });


  } catch (err) {

    console.error(
      "❌ Error en finalizar público:",
      err.message
    );

    res.status(500).json({
      message:
        "Error al finalizar prueba público",
      error:
        err.message
    });

  }

}


/* ==================================================
   GUARDAR RESPUESTAS
   REQUIERE LOGIN
================================================== */

export async function guardarRespuestas(
  req,
  res
) {

  const {
    id_sesion,
    id_habilitacion,
    respuestas
  } = req.body;


  if (
    !id_sesion ||
    !id_habilitacion ||
    !Array.isArray(respuestas) ||
    !respuestas.length
  ) {

    return res.status(400).json({
      message:
        "Faltan datos obligatorios"
    });

  }


  try {

    const values =
      respuestas.map((r) => [

        r.id_paciente,

        r.id_prueba,

        id_habilitacion,

        r.id_pregunta,

        r.id_opcion ?? null,

        r.respuesta_abierta ?? null

      ]);


    await pool.query(
      `INSERT INTO respuestas_prueba
       (
         id_paciente,
         id_prueba,
         id_habilitacion,
         id_pregunta,
         id_opcion,
         respuesta_abierta
       )
       VALUES ?`,
      [values]
    );


    res.json({
      message:
        "✅ Respuestas guardadas"
    });


  } catch (err) {

    console.error(
      "❌ Error al guardar respuestas:",
      err.message
    );

    res.status(500).json({
      message:
        "Error al guardar respuestas"
    });

  }

}


/* ==================================================
   GUARDAR RESPUESTAS PÚBLICAS
================================================== */

export async function guardarRespuestasPublicas(
  req,
  res
) {

  const {
    id_habilitacion,
    id_sesion,
    respuestas
  } = req.body;


  if (
    !id_habilitacion ||
    !Array.isArray(respuestas) ||
    !respuestas.length
  ) {

    return res.status(400).json({
      message:
        "Faltan datos obligatorios"
    });

  }


  try {

    const values =
      respuestas.map((r) => [

        r.id_paciente,

        r.id_prueba,

        id_habilitacion,

        r.id_pregunta,

        r.id_opcion ?? null,

        r.respuesta_abierta ?? null,

        id_sesion || null

      ]);


    await pool.query(
      `INSERT INTO respuestas_prueba
       (
         id_paciente,
         id_prueba,
         id_habilitacion,
         id_pregunta,
         id_opcion,
         respuesta_abierta,
         id_sesion
       )
       VALUES ?`,
      [values]
    );


    res.json({
      message:
        "✅ Respuestas guardadas (público)"
    });


  } catch (err) {

    console.error(
      "❌ Error al guardar respuestas públicas:",
      err.message
    );

    res.status(500).json({
      message:
        "Error al guardar respuestas públicas"
    });

  }

}


/* ==================================================
   OBTENER PRUEBA MEDIANTE HABILITACIÓN
   RUTA PÚBLICA
================================================== */

export async function obtenerPruebaPorHabilitacion(
  req,
  res
) {

  const {
    id_habilitacion
  } = req.params;


  try {

    /* ================================================
       1. OBTENER INFORMACIÓN DE LA PRUEBA
    ================================================ */

    const [rows] =
      await pool.query(
        `SELECT
          ph.id_habilitacion AS id_habilitacion,
          ph.id_paciente,
          pr.id_prueba,
          pr.nombre,
          pr.descripcion,
          pr.tipo,
          ph.fecha
         FROM pruebas_habilitadas ph
         JOIN pruebas pr
           ON ph.id_prueba = pr.id_prueba
         WHERE ph.id_habilitacion = ?`,
        [id_habilitacion]
      );


    if (!rows.length) {

      return res.status(404).json({
        message:
          "Prueba no encontrada"
      });

    }


    const prueba =
      rows[0];


    /* ================================================
       2. OBTENER PREGUNTAS
    ================================================ */

    const [preguntas] =
      await pool.query(
        `SELECT *
         FROM preguntas_prueba
         WHERE id_prueba = ?`,
        [prueba.id_prueba]
      );


    /* ================================================
       3. OBTENER OPCIONES
    ================================================ */

    for (const pregunta of preguntas) {

      const [opciones] =
        await pool.query(
          `SELECT *
           FROM opciones_respuesta
           WHERE id_pregunta = ?`,
          [pregunta.id_pregunta]
        );


      pregunta.opciones =
        opciones;

    }


    /* ================================================
       4. RESPUESTA
    ================================================ */

    res.json({
      ...prueba,
      preguntas
    });


  } catch (err) {

    console.error(
      "❌ Error al obtener prueba:",
      err.message
    );

    res.status(500).json({
      message:
        "Error al generar link"
    });

  }

}

/* ==================================================
   OBTENER RESULTADOS DE PRUEBAS DE UN PACIENTE
================================================== */

export async function obtenerResultadosPaciente(req, res) {

  const { id_paciente } = req.params;

  if (!id_paciente) {
    return res.status(400).json({
      message: "Falta el id del paciente"
    });
  }

  try {

    const [rows] = await pool.query(
      `SELECT
        rp.id_resultado,
        rp.id_paciente,
        rp.id_prueba,
        rp.id_habilitacion,
        rp.id_sesion,
        rp.puntaje_total,
        rp.interpretacion,
        rp.fecha,

        p.nombre AS nombre_prueba,
        p.descripcion,
        p.tipo

       FROM resultados_prueba rp

       INNER JOIN pruebas p
         ON rp.id_prueba = p.id_prueba

       WHERE rp.id_paciente = ?

       ORDER BY rp.fecha DESC`,
      [id_paciente]
    );

    res.json(rows || []);

  } catch (err) {

    console.error(
      "❌ Error al obtener resultados del paciente:",
      err.message
    );

    res.status(500).json({
      message: "Error al obtener resultados del paciente"
    });

  }

}

/* ==================================================
   EVALUAR PRUEBAS
   Ruta antigua /evaluateTests
================================================== */

export function evaluateTests(req, res) {

  const {
    paciente,
    pruebas = {},
    emociones = []
  } = req.body;


  /* ================================================
     BECK COMO ARRAY
  ================================================ */

  const beckResponses =
    Array.isArray(pruebas.Beck)
      ? pruebas.Beck
      : [];


  /* ================================================
     CALCULAR SCORE BECK
  ================================================ */

  let scoreBeck = 0;


  if (beckResponses.length > 0) {

    scoreBeck =
      beckResponses.reduce(
        (acc, r) => {

          if (
            typeof r === "number"
          ) {

            return acc + r;

          }


          if (
            typeof r === "object" &&
            r &&
            r.score
          ) {

            return acc + r.score;

          }


          return acc + 1;

        },
        0
      );

  }


  /* ================================================
     CREAR REPORTE
  ================================================ */

  const reporte = `
📄 Reporte de ${paciente?.nombre || "Paciente"}
-----------------------------------
Emociones detectadas: ${emociones.join(", ") || "Ninguna"}

Resultados de pruebas:
- Beck: ${scoreBeck} puntos (${scoreBeck < 10 ? "Leve" : "Moderado/Alto"})

⚠️ Este reporte es preliminar, el psicólogo tiene la última decisión.
`;


  res.json({
    reporte
  });

}