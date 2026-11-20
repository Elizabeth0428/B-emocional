// backend/controllers/evaluationController.js

import pool from "../config/database.js";


// ============================================================
// AUXILIAR: NORMALIZAR TEXTO
// ============================================================

function normalizar(valor) {

  return valor
    ? String(valor)
        .trim()
        .toLowerCase()
    : "";

}


// ============================================================
// OBTENER ID_PSICOLOGO DE LA SESIÓN
//
// PERMITE:
//
// 1. Psicólogo normal.
//
// 2. Independiente Clínica:
//
//    rol = independiente
//    perfil_independiente = clinica
//
// El Independiente conserva:
// rol = independiente
// area = independiente
//
// Si el token no trae id_psicologo,
// se busca en psicologos mediante id_usuario.
// ============================================================

async function obtenerIdPsicologoSesion(
  req
) {

  if (
    !req.user
  ) {

    return null;

  }


  const rol =
    normalizar(
      req.user?.rol
    );


  const perfilIndependiente =
    normalizar(
      req.user
        ?.perfil_independiente
    );


  const esPsicologo =
    rol ===
    "psicologo";


  const esIndependienteClinica =
    rol ===
      "independiente" &&

    perfilIndependiente ===
      "clinica";


  if (
    !esPsicologo &&
    !esIndependienteClinica
  ) {

    return null;

  }


  // ========================================================
  // SI EL TOKEN YA TRAE id_psicologo
  // ========================================================

  const idPsicologoToken =
    Number(
      req.user
        ?.id_psicologo
    );


  if (
    Number.isInteger(
      idPsicologoToken
    ) &&
    idPsicologoToken > 0
  ) {

    return idPsicologoToken;

  }


  // ========================================================
  // BUSCAR POR id_usuario
  // ========================================================

  const idUsuario =
    Number(
      req.user
        ?.id_usuario
    );


  if (
    !Number.isInteger(
      idUsuario
    ) ||
    idUsuario <= 0
  ) {

    return null;

  }


  const [
    rows
  ] =
    await pool.query(
      `
        SELECT
          id_psicologo

        FROM psicologos

        WHERE
          id_usuario = ?

        LIMIT 1
      `,
      [
        idUsuario
      ]
    );


  if (
    !rows.length
  ) {

    return null;

  }


  return Number(
    rows[0]
      .id_psicologo
  ) || null;

}


// ==================================================
// OBTENER TODAS LAS PRUEBAS
// ==================================================

export async function obtenerPruebas(
  req,
  res
) {

  try {

    const [
      rows
    ] =
      await pool.query(
        `
          SELECT
            id_prueba,
            nombre,
            descripcion,
            tipo,
            version,
            activo

          FROM pruebas

          ORDER BY
            id_prueba DESC
        `
      );


    return res.json(
      rows || []
    );


  } catch (
    err
  ) {

    console.error(
      "❌ Error al obtener pruebas:",
      err.message
    );


    return res
      .status(500)
      .json({

        message:
          "Error al obtener pruebas"

      });

  }

}


// ==================================================
// HABILITAR PRUEBA PARA PACIENTE
//
// Puede pertenecer a una sesión clínica
// o ser una prueba independiente.
//
// id_sesion = número -> prueba de sesión
// id_sesion = NULL   -> prueba independiente
// ==================================================

export async function habilitarPrueba(
  req,
  res
) {

  const {

    id_paciente,

    id_prueba,

    id_sesion = null,

    notas

  } = req.body;


  try {

    // ========================================================
    // RESOLVER PERFIL CLÍNICO
    // ========================================================

    const id_psicologo =
      await obtenerIdPsicologoSesion(
        req
      );


    // ========================================================
    // DATOS OBLIGATORIOS
    // ========================================================

    if (
      !id_paciente ||
      !id_prueba
    ) {

      return res
        .status(400)
        .json({

          success:
            false,

          message:
            "Faltan datos: id_paciente e id_prueba son obligatorios"

        });

    }


    // ========================================================
    // PERFIL CLÍNICO
    // ========================================================

    if (
      !id_psicologo
    ) {

      return res
        .status(403)
        .json({

          success:
            false,

          message:
            "Tu cuenta no tiene configurado un perfil clínico válido. Completa primero Mi perfil profesional."

        });

    }


    const idPaciente =
      Number(
        id_paciente
      );


    const idPrueba =
      Number(
        id_prueba
      );


    const idSesion =
      id_sesion
        ? Number(
            id_sesion
          )
        : null;


    // ========================================================
    // VALIDAR ID PACIENTE
    // ========================================================

    if (
      !Number.isInteger(
        idPaciente
      ) ||
      idPaciente <= 0
    ) {

      return res
        .status(400)
        .json({

          success:
            false,

          message:
            "ID de paciente inválido"

        });

    }


    // ========================================================
    // VALIDAR ID PRUEBA
    // ========================================================

    if (
      !Number.isInteger(
        idPrueba
      ) ||
      idPrueba <= 0
    ) {

      return res
        .status(400)
        .json({

          success:
            false,

          message:
            "ID de prueba inválido"

        });

    }


    // ========================================================
    // VALIDAR ID SESIÓN
    // ========================================================

    if (
      idSesion !== null &&
      (
        !Number.isInteger(
          idSesion
        ) ||
        idSesion <= 0
      )
    ) {

      return res
        .status(400)
        .json({

          success:
            false,

          message:
            "ID de sesión inválido"

        });

    }


    // ========================================================
    // VALIDAR PACIENTE
    //
    // También verificamos que pertenezca al profesional.
    // ========================================================

    const [
      paciente
    ] =
      await pool.query(
        `
          SELECT
            id_paciente,
            id_psicologo

          FROM pacientes

          WHERE
            id_paciente = ?

          LIMIT 1
        `,
        [
          idPaciente
        ]
      );


    if (
      !paciente.length
    ) {

      return res
        .status(404)
        .json({

          success:
            false,

          message:
            "Paciente no encontrado"

        });

    }


    // ========================================================
    // SEGURIDAD
    //
    // Solo puede habilitar pruebas a sus pacientes.
    // ========================================================

    if (
      Number(
        paciente[0]
          .id_psicologo
      ) !==
      Number(
        id_psicologo
      )
    ) {

      return res
        .status(403)
        .json({

          success:
            false,

          message:
            "No tienes permiso para habilitar pruebas a este paciente"

        });

    }


    // ========================================================
    // VALIDAR PRUEBA
    // ========================================================

    const [
      prueba
    ] =
      await pool.query(
        `
          SELECT
            id_prueba,
            nombre,
            activo

          FROM pruebas

          WHERE
            id_prueba = ?

          LIMIT 1
        `,
        [
          idPrueba
        ]
      );


    if (
      !prueba.length
    ) {

      return res
        .status(404)
        .json({

          success:
            false,

          message:
            "Prueba no encontrada"

        });

    }


    if (
      Number(
        prueba[0]
          .activo
      ) !== 1
    ) {

      return res
        .status(400)
        .json({

          success:
            false,

          message:
            "La prueba seleccionada no está activa"

        });

    }


    // ========================================================
    // VALIDAR SESIÓN SI FUE ENVIADA
    // ========================================================

    if (
      idSesion
    ) {

      const [
        sesion
      ] =
        await pool.query(
          `
            SELECT
              id_sesion,
              id_paciente,
              estado

            FROM sesiones

            WHERE
              id_sesion = ?

            LIMIT 1
          `,
          [
            idSesion
          ]
        );


      if (
        !sesion.length
      ) {

        return res
          .status(404)
          .json({

            success:
              false,

            message:
              "Sesión no encontrada"

          });

      }


      if (
        Number(
          sesion[0]
            .id_paciente
        ) !==
        idPaciente
      ) {

        return res
          .status(400)
          .json({

            success:
              false,

            message:
              "La sesión no pertenece a este paciente"

          });

      }


      // ======================================================
      // LA PRUEBA DE SESIÓN SOLO SE HABILITA
      // SI LA SESIÓN ESTÁ ACTIVA
      // ======================================================

      if (
        String(
          sesion[0]
            .estado ||
          ""
        )
          .trim()
          .toLowerCase() !==
        "activa"
      ) {

        return res
          .status(409)
          .json({

            success:
              false,

            message:
              "La prueba solo puede habilitarse dentro de una sesión activa"

          });

      }


      // ======================================================
      // EVITAR DUPLICADO EN LA MISMA SESIÓN
      // ======================================================

      const [
        duplicada
      ] =
        await pool.query(
          `
            SELECT
              id_habilitacion

            FROM pruebas_habilitadas

            WHERE
              id_paciente = ?

              AND id_prueba = ?

              AND id_sesion = ?

            LIMIT 1
          `,
          [
            idPaciente,
            idPrueba,
            idSesion
          ]
        );


      if (
        duplicada.length
      ) {

        return res
          .status(409)
          .json({

            success:
              false,

            id_habilitacion:
              duplicada[0]
                .id_habilitacion,

            message:
              "Esta prueba ya está habilitada en esta sesión"

          });

      }

    }


    // ========================================================
    // GUARDAR HABILITACIÓN
    // ========================================================

    const [
      result
    ] =
      await pool.query(
        `
          INSERT INTO pruebas_habilitadas
          (
            id_paciente,
            id_sesion,
            id_prueba,
            id_psicologo,
            notas
          )

          VALUES
          (
            ?,
            ?,
            ?,
            ?,
            ?
          )
        `,
        [
          idPaciente,
          idSesion,
          idPrueba,
          id_psicologo,
          notas || null
        ]
      );


    return res.json({

      success:
        true,

      id_habilitacion:
        result.insertId,

      id_paciente:
        idPaciente,

      id_prueba:
        idPrueba,

      id_psicologo:
        id_psicologo,

      id_sesion:
        idSesion,

      message:
        idSesion
          ? "✅ Prueba habilitada para la sesión"
          : "✅ Prueba habilitada de forma independiente"

    });


  } catch (
    err
  ) {

    console.error(
      "❌ Error al habilitar prueba:",
      err
    );


    return res
      .status(500)
      .json({

        success:
          false,

        message:
          "Error al habilitar prueba",

        error:
          process.env.NODE_ENV ===
          "development"
            ? err.message
            : undefined

      });

  }

}


// ==================================================
// OBTENER PRUEBAS HABILITADAS DE UN PACIENTE
// ==================================================

export async function obtenerPruebasHabilitadas(
  req,
  res
) {

  const {
    id_paciente
  } =
    req.params;


  try {

    const [
      rows
    ] =
      await pool.query(
        `
          SELECT
            ph.id_habilitacion,
            ph.id_paciente,
            ph.id_sesion,

            pr.id_prueba,
            pr.nombre,
            pr.descripcion,
            pr.tipo,

            ph.fecha,

            rp.id_resultado,
            rp.puntaje_total,
            rp.interpretacion,
            rp.fecha AS fecha_resultado,

            CASE
              WHEN rp.id_resultado IS NOT NULL
                THEN 1
              ELSE 0
            END AS completada

          FROM pruebas_habilitadas ph

          JOIN pruebas pr
            ON ph.id_prueba =
               pr.id_prueba

          LEFT JOIN resultados_prueba rp
            ON rp.id_habilitacion =
               ph.id_habilitacion

          WHERE
            ph.id_paciente = ?

          ORDER BY
            ph.fecha DESC
        `,
        [
          id_paciente
        ]
      );


    return res.json(
      rows || []
    );


  } catch (
    err
  ) {

    console.error(
      "❌ Error al obtener pruebas habilitadas:",
      err.message
    );


    return res
      .status(500)
      .json({

        message:
          "Error al obtener pruebas habilitadas"

      });

  }

}


// ==================================================
// OBTENER PREGUNTAS DE UNA PRUEBA
// INCLUYE OPCIONES DE RESPUESTA
// ==================================================

export async function obtenerPreguntasPrueba(
  req,
  res
) {

  const {
    id
  } =
    req.params;


  try {

    const [
      preguntas
    ] =
      await pool.query(
        `
          SELECT *

          FROM preguntas_prueba

          WHERE
            id_prueba = ?
        `,
        [
          id
        ]
      );


    // ========================================================
    // OBTENER OPCIONES DE CADA PREGUNTA
    // ========================================================

    for (
      const pregunta
      of preguntas
    ) {

      const [
        opciones
      ] =
        await pool.query(
          `
            SELECT *

            FROM opciones_respuesta

            WHERE
              id_pregunta = ?
          `,
          [
            pregunta
              .id_pregunta
          ]
        );


      pregunta.opciones =
        opciones;

    }


    return res.json(
      preguntas || []
    );


  } catch (
    err
  ) {

    console.error(
      "❌ Error al obtener preguntas:",
      err.message
    );


    return res
      .status(500)
      .json({

        message:
          "Error al obtener preguntas"

      });

  }

}


// ==================================================
// FUNCIÓN PARA INTERPRETAR RESULTADO
// ==================================================

function obtenerInterpretacion(
  id_prueba,
  puntaje_total
) {

  let interpretacion =
    "Sin interpretación";


  // ========================================================
  // PRUEBA 3 — ANSIEDAD
  // ========================================================

  if (
    +id_prueba === 3
  ) {

    interpretacion =
      puntaje_total < 5
        ? "Ansiedad mínima"
        : puntaje_total < 10
        ? "Ansiedad leve"
        : puntaje_total < 15
        ? "Ansiedad moderada"
        : "Ansiedad severa";

  }


  // ========================================================
  // PRUEBA 2 — ESTRÉS
  // ========================================================

  if (
    +id_prueba === 2
  ) {

    interpretacion =
      puntaje_total < 14
        ? "Estrés bajo"
        : puntaje_total < 27
        ? "Estrés moderado"
        : "Estrés alto";

  }


  // ========================================================
  // PRUEBA 1 — DEPRESIÓN
  // ========================================================

  if (
    +id_prueba === 1
  ) {

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


// ==================================================
// OBTENER ID_SESION DESDE LA HABILITACIÓN
//
// La habilitación es la fuente de verdad.
// ==================================================

async function obtenerSesionHabilitacion(
  id_habilitacion
) {

  const [
    rows
  ] =
    await pool.query(
      `
        SELECT
          id_habilitacion,
          id_paciente,
          id_prueba,
          id_sesion

        FROM pruebas_habilitadas

        WHERE
          id_habilitacion = ?
      `,
      [
        id_habilitacion
      ]
    );


  if (
    !rows.length
  ) {

    return null;

  }


  return rows[0];

}


// ==================================================
// FINALIZAR PRUEBA
// REQUIERE LOGIN
// ==================================================

export async function finalizarPrueba(
  req,
  res
) {

  const {
    id
  } =
    req.params;


  const {

    id_paciente,

    id_habilitacion

  } = req.body;


  if (
    !id_paciente ||
    !id_habilitacion
  ) {

    return res
      .status(400)
      .json({

        message:
          "Faltan datos obligatorios (id_paciente, id_habilitacion)"

      });

  }


  try {

    // ========================================================
    // 1. OBTENER HABILITACIÓN
    // ========================================================

    const habilitacion =
      await obtenerSesionHabilitacion(
        id_habilitacion
      );


    if (
      !habilitacion
    ) {

      return res
        .status(404)
        .json({

          message:
            "Habilitación de prueba no encontrada"

        });

    }


    if (
      Number(
        habilitacion
          .id_paciente
      ) !==
      Number(
        id_paciente
      )
    ) {

      return res
        .status(400)
        .json({

          message:
            "La habilitación no pertenece al paciente"

        });

    }


    if (
      Number(
        habilitacion
          .id_prueba
      ) !==
      Number(
        id
      )
    ) {

      return res
        .status(400)
        .json({

          message:
            "La habilitación no corresponde a esta prueba"

        });

    }


    const idSesion =
      habilitacion
        .id_sesion
        ? Number(
            habilitacion
              .id_sesion
          )
        : null;


    // ========================================================
    // 2. CALCULAR PUNTAJE
    // ========================================================

    const [
      rows
    ] =
      await pool.query(
        `
          SELECT
            SUM(
              o.valor
            )
              AS total

          FROM respuestas_prueba r

          JOIN opciones_respuesta o
            ON r.id_opcion =
               o.id_opcion

          WHERE
            r.id_prueba = ?

            AND r.id_paciente = ?

            AND r.id_habilitacion = ?
        `,
        [
          id,
          id_paciente,
          id_habilitacion
        ]
      );


    const puntaje_total =
      Number(
        rows[0]
          ?.total ||
        0
      );


    // ========================================================
    // 3. INTERPRETACIÓN
    // ========================================================

    const interpretacion =
      obtenerInterpretacion(
        id,
        puntaje_total
      );


    // ========================================================
    // 4. BUSCAR RESULTADO EXISTENTE
    // ========================================================

    const [
      existe
    ] =
      await pool.query(
        `
          SELECT
            id_resultado

          FROM resultados_prueba

          WHERE
            id_paciente = ?

            AND id_prueba = ?

            AND id_habilitacion = ?
        `,
        [
          id_paciente,
          id,
          id_habilitacion
        ]
      );


    // ========================================================
    // 5. ACTUALIZAR O INSERTAR
    // ========================================================

    if (
      existe.length > 0
    ) {

      await pool.query(
        `
          UPDATE resultados_prueba

          SET
            puntaje_total = ?,
            interpretacion = ?,
            id_sesion = ?,
            fecha = NOW()

          WHERE
            id_resultado = ?
        `,
        [
          puntaje_total,
          interpretacion,
          idSesion,
          existe[0]
            .id_resultado
        ]
      );

    } else {

      await pool.query(
        `
          INSERT INTO resultados_prueba
          (
            id_paciente,
            id_prueba,
            id_habilitacion,
            puntaje_total,
            interpretacion,
            id_sesion,
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
            NOW()
          )
        `,
        [
          id_paciente,
          id,
          id_habilitacion,
          puntaje_total,
          interpretacion,
          idSesion
        ]
      );

    }


    // ========================================================
    // 6. RESPUESTA
    // ========================================================

    return res.json({

      success:
        true,

      id_sesion:
        idSesion,

      puntaje_total,

      interpretacion

    });


  } catch (
    err
  ) {

    console.error(
      "❌ Error al finalizar prueba:",
      err.message
    );


    return res
      .status(500)
      .json({

        message:
          "Error al finalizar prueba"

      });

  }

}


// ==================================================
// FINALIZAR PRUEBA PÚBLICA
// SIN LOGIN
// ==================================================

export async function finalizarPruebaPublica(
  req,
  res
) {

  const {
    id
  } =
    req.params;


  const {

    id_paciente,

    id_habilitacion

  } = req.body;


  if (
    !id_paciente ||
    !id_habilitacion
  ) {

    return res
      .status(400)
      .json({

        message:
          "Faltan datos obligatorios (id_paciente, id_habilitacion)"

      });

  }


  try {

    // ========================================================
    // 1. OBTENER HABILITACIÓN
    // ========================================================

    const habilitacion =
      await obtenerSesionHabilitacion(
        id_habilitacion
      );


    if (
      !habilitacion
    ) {

      return res
        .status(404)
        .json({

          message:
            "Habilitación de prueba no encontrada"

        });

    }


    if (
      Number(
        habilitacion
          .id_paciente
      ) !==
      Number(
        id_paciente
      )
    ) {

      return res
        .status(400)
        .json({

          message:
            "La habilitación no pertenece al paciente"

        });

    }


    if (
      Number(
        habilitacion
          .id_prueba
      ) !==
      Number(
        id
      )
    ) {

      return res
        .status(400)
        .json({

          message:
            "La habilitación no corresponde a esta prueba"

        });

    }


    const idSesion =
      habilitacion
        .id_sesion
        ? Number(
            habilitacion
              .id_sesion
          )
        : null;


    // ========================================================
    // 2. CALCULAR PUNTAJE
    // ========================================================

    const [
      rows
    ] =
      await pool.query(
        `
          SELECT
            SUM(
              o.valor
            )
              AS total

          FROM respuestas_prueba r

          JOIN opciones_respuesta o
            ON r.id_opcion =
               o.id_opcion

          WHERE
            r.id_prueba = ?

            AND r.id_paciente = ?

            AND r.id_habilitacion = ?
        `,
        [
          id,
          id_paciente,
          id_habilitacion
        ]
      );


    const puntaje_total =
      Number(
        rows[0]
          ?.total ||
        0
      );


    // ========================================================
    // 3. INTERPRETACIÓN
    // ========================================================

    const interpretacion =
      obtenerInterpretacion(
        id,
        puntaje_total
      );


    // ========================================================
    // 4. GUARDAR RESULTADO
    // ========================================================

    await pool.query(
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

        VALUES
        (
          ?,
          ?,
          ?,
          ?,
          ?,
          ?,
          NOW()
        )

        ON DUPLICATE KEY UPDATE

          puntaje_total =
            VALUES(
              puntaje_total
            ),

          interpretacion =
            VALUES(
              interpretacion
            ),

          id_sesion =
            VALUES(
              id_sesion
            ),

          fecha =
            NOW()
      `,
      [
        id_paciente,
        id,
        id_habilitacion,
        idSesion,
        puntaje_total,
        interpretacion
      ]
    );


    // ========================================================
    // 5. RESPUESTA
    // ========================================================

    return res.json({

      success:
        true,

      id_sesion:
        idSesion,

      puntaje_total,

      interpretacion

    });


  } catch (
    err
  ) {

    console.error(
      "❌ Error en finalizar público:",
      err.message
    );


    return res
      .status(500)
      .json({

        message:
          "Error al finalizar prueba público",

        error:
          err.message

      });

  }

}


// ==================================================
// GUARDAR RESPUESTAS
// REQUIERE LOGIN
//
// id_sesion se obtiene desde pruebas_habilitadas.
// ==================================================

export async function guardarRespuestas(
  req,
  res
) {

  const {

    id_habilitacion,

    respuestas

  } = req.body;


  if (
    !id_habilitacion ||
    !Array.isArray(
      respuestas
    ) ||
    !respuestas.length
  ) {

    return res
      .status(400)
      .json({

        message:
          "Faltan datos obligatorios"

      });

  }


  try {

    // ========================================================
    // OBTENER HABILITACIÓN
    // ========================================================

    const habilitacion =
      await obtenerSesionHabilitacion(
        id_habilitacion
      );


    if (
      !habilitacion
    ) {

      return res
        .status(404)
        .json({

          message:
            "Habilitación de prueba no encontrada"

        });

    }


    const idSesion =
      habilitacion
        .id_sesion
        ? Number(
            habilitacion
              .id_sesion
          )
        : null;


    // ========================================================
    // PREPARAR RESPUESTAS
    // ========================================================

    const values =
      respuestas.map(
        r => [

          r.id_paciente,

          r.id_prueba,

          id_habilitacion,

          r.id_pregunta,

          r.id_opcion ??
            null,

          r.respuesta_abierta ??
            null,

          idSesion

        ]
      );


    // ========================================================
    // GUARDAR RESPUESTAS
    // ========================================================

    await pool.query(
      `
        INSERT INTO respuestas_prueba
        (
          id_paciente,
          id_prueba,
          id_habilitacion,
          id_pregunta,
          id_opcion,
          respuesta_abierta,
          id_sesion
        )

        VALUES ?
      `,
      [
        values
      ]
    );


    return res.json({

      success:
        true,

      id_sesion:
        idSesion,

      message:
        "✅ Respuestas guardadas"

    });


  } catch (
    err
  ) {

    console.error(
      "❌ Error al guardar respuestas:",
      err.message
    );


    return res
      .status(500)
      .json({

        message:
          "Error al guardar respuestas"

      });

  }

}


// ==================================================
// GUARDAR RESPUESTAS PÚBLICAS
//
// No confiamos en un id_sesion enviado desde
// el navegador.
// ==================================================

export async function guardarRespuestasPublicas(
  req,
  res
) {

  const {

    id_habilitacion,

    respuestas

  } = req.body;


  if (
    !id_habilitacion ||
    !Array.isArray(
      respuestas
    ) ||
    !respuestas.length
  ) {

    return res
      .status(400)
      .json({

        message:
          "Faltan datos obligatorios"

      });

  }


  try {

    // ========================================================
    // OBTENER HABILITACIÓN
    // ========================================================

    const habilitacion =
      await obtenerSesionHabilitacion(
        id_habilitacion
      );


    if (
      !habilitacion
    ) {

      return res
        .status(404)
        .json({

          message:
            "Habilitación de prueba no encontrada"

        });

    }


    const idSesion =
      habilitacion
        .id_sesion
        ? Number(
            habilitacion
              .id_sesion
          )
        : null;


    // ========================================================
    // PREPARAR RESPUESTAS
    // ========================================================

    const values =
      respuestas.map(
        r => [

          r.id_paciente,

          r.id_prueba,

          id_habilitacion,

          r.id_pregunta,

          r.id_opcion ??
            null,

          r.respuesta_abierta ??
            null,

          idSesion

        ]
      );


    // ========================================================
    // GUARDAR
    // ========================================================

    await pool.query(
      `
        INSERT INTO respuestas_prueba
        (
          id_paciente,
          id_prueba,
          id_habilitacion,
          id_pregunta,
          id_opcion,
          respuesta_abierta,
          id_sesion
        )

        VALUES ?
      `,
      [
        values
      ]
    );


    return res.json({

      success:
        true,

      id_sesion:
        idSesion,

      message:
        "✅ Respuestas guardadas (público)"

    });


  } catch (
    err
  ) {

    console.error(
      "❌ Error al guardar respuestas públicas:",
      err.message
    );


    return res
      .status(500)
      .json({

        message:
          "Error al guardar respuestas públicas"

      });

  }

}


// ==================================================
// OBTENER PRUEBA MEDIANTE HABILITACIÓN
// RUTA PÚBLICA
//
// Ahora también devuelve id_sesion.
// ==================================================

export async function obtenerPruebaPorHabilitacion(
  req,
  res
) {

  const {
    id_habilitacion
  } =
    req.params;


  try {

    // ========================================================
    // 1. OBTENER INFORMACIÓN DE LA PRUEBA
    // ========================================================

    const [
      rows
    ] =
      await pool.query(
        `
          SELECT
            ph.id_habilitacion
              AS id_habilitacion,

            ph.id_paciente,

            ph.id_sesion,

            pr.id_prueba,

            pr.nombre,

            pr.descripcion,

            pr.tipo,

            ph.fecha

          FROM pruebas_habilitadas ph

          JOIN pruebas pr
            ON ph.id_prueba =
               pr.id_prueba

          WHERE
            ph.id_habilitacion = ?
        `,
        [
          id_habilitacion
        ]
      );


    if (
      !rows.length
    ) {

      return res
        .status(404)
        .json({

          message:
            "Prueba no encontrada"

        });

    }


    const prueba =
      rows[0];


    // ========================================================
    // 2. OBTENER PREGUNTAS
    // ========================================================

    const [
      preguntas
    ] =
      await pool.query(
        `
          SELECT *

          FROM preguntas_prueba

          WHERE
            id_prueba = ?
        `,
        [
          prueba
            .id_prueba
        ]
      );


    // ========================================================
    // 3. OBTENER OPCIONES
    // ========================================================

    for (
      const pregunta
      of preguntas
    ) {

      const [
        opciones
      ] =
        await pool.query(
          `
            SELECT *

            FROM opciones_respuesta

            WHERE
              id_pregunta = ?
          `,
          [
            pregunta
              .id_pregunta
          ]
        );


      pregunta.opciones =
        opciones;

    }


    // ========================================================
    // 4. RESPUESTA
    // ========================================================

    return res.json({

      ...prueba,

      preguntas

    });


  } catch (
    err
  ) {

    console.error(
      "❌ Error al obtener prueba:",
      err.message
    );


    return res
      .status(500)
      .json({

        message:
          "Error al generar link"

      });

  }

}


// ==================================================
// OBTENER RESULTADOS DE PRUEBAS DE UN PACIENTE
// ==================================================

export async function obtenerResultadosPaciente(
  req,
  res
) {

  const {
    id_paciente
  } =
    req.params;


  if (
    !id_paciente
  ) {

    return res
      .status(400)
      .json({

        message:
          "Falta el id del paciente"

      });

  }


  try {

    const [
      rows
    ] =
      await pool.query(
        `
          SELECT
            rp.id_resultado,
            rp.id_paciente,
            rp.id_prueba,
            rp.id_habilitacion,
            rp.id_sesion,
            rp.puntaje_total,
            rp.interpretacion,
            rp.fecha,

            p.nombre
              AS nombre_prueba,

            p.descripcion,

            p.tipo

          FROM resultados_prueba rp

          INNER JOIN pruebas p
            ON rp.id_prueba =
               p.id_prueba

          WHERE
            rp.id_paciente = ?

          ORDER BY
            rp.fecha DESC
        `,
        [
          id_paciente
        ]
      );


    return res.json(
      rows || []
    );


  } catch (
    err
  ) {

    console.error(
      "❌ Error al obtener resultados del paciente:",
      err.message
    );


    return res
      .status(500)
      .json({

        message:
          "Error al obtener resultados del paciente"

      });

  }

}


// ==================================================
// EVALUAR PRUEBAS
// Ruta antigua /evaluateTests
// ==================================================

export function evaluateTests(
  req,
  res
) {

  const {

    paciente,

    pruebas = {},

    emociones = []

  } = req.body;


  // ========================================================
  // BECK COMO ARRAY
  // ========================================================

  const beckResponses =
    Array.isArray(
      pruebas.Beck
    )
      ? pruebas.Beck
      : [];


  // ========================================================
  // CALCULAR SCORE BECK
  // ========================================================

  let scoreBeck =
    0;


  if (
    beckResponses.length > 0
  ) {

    scoreBeck =
      beckResponses.reduce(
        (
          acc,
          r
        ) => {

          if (
            typeof r ===
            "number"
          ) {

            return acc + r;

          }


          if (
            typeof r ===
              "object" &&
            r &&
            r.score
          ) {

            return acc +
              r.score;

          }


          return acc + 1;

        },
        0
      );

  }


  // ========================================================
  // CREAR REPORTE
  // ========================================================

  const reporte = `
📄 Reporte de ${paciente?.nombre || "Paciente"}
-----------------------------------
Emociones detectadas: ${emociones.join(", ") || "Ninguna"}

Resultados de pruebas:
- Beck: ${scoreBeck} puntos (${scoreBeck < 10 ? "Leve" : "Moderado/Alto"})

⚠️ Este reporte es preliminar, el psicólogo tiene la última decisión.
`;


  return res.json({

    reporte

  });

}