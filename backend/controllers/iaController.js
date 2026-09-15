import pool from "../config/database.js";
import {
  analyzeWithIA,
  generarReporteIA
} from "../svc/aiService.js";


/* ==================================================
   ANALIZAR DATOS RECIBIDOS
   POST /api/ia/analizar
================================================== */

export async function generarAnalisisIA(req, res) {

  try {

    const {
      paciente,
      pruebas,
      emociones,
      reporte
    } = req.body;


    const resultado = await analyzeWithIA(
      paciente,
      pruebas,
      emociones,
      reporte
    );


    res.json({
      success: true,
      analisis: resultado
    });


  } catch (error) {

    console.error(
      "❌ Error IA:",
      error
    );


    res.status(500).json({

      success: false,

      message: "Error generando análisis IA",

      error: error.message

    });

  }

}


/* ==================================================
   ANALIZAR SESIÓN
   POST /api/ia/analisis-sesion
================================================== */

export async function generarAnalisisSesion(req, res) {

  const { id_sesion } = req.body;


  if (!id_sesion) {

    return res.status(400).json({

      message: "Falta el ID de la sesión"

    });

  }


  try {

    console.log(
      "📥 Generando reporte IA para sesión:",
      id_sesion
    );


    /* ==========================================
       1. DATOS DEL PACIENTE
    ========================================== */

    const [paciente] = await pool.query(

      `SELECT
        p.id_paciente,
        p.nombre,
        p.edad,
        p.sexo,
        p.antecedentes

       FROM pacientes p

       JOIN sesiones s
       ON s.id_paciente = p.id_paciente

       WHERE s.id_sesion = ?

       LIMIT 1`,

      [id_sesion]

    );


    if (!paciente.length) {

      return res.status(404).json({

        message:
          "Paciente no encontrado para la sesión"

      });

    }


    /* ==========================================
       2. HISTORIAL INICIAL
    ========================================== */

    const [historial] = await pool.query(

      `SELECT *
       FROM historial_inicial

       WHERE id_paciente = ?

       LIMIT 1`,

      [paciente[0].id_paciente]

    );


    /* ==========================================
       3. RESULTADOS DE PRUEBAS
    ========================================== */

    let resultados = [];

    try {

      [resultados] = await pool.query(

        `SELECT
          pr.nombre AS prueba,
          SUM(o.valor) AS puntaje_total

         FROM respuestas_prueba r

         JOIN preguntas_prueba q
         ON r.id_pregunta = q.id_pregunta

         JOIN pruebas pr
         ON q.id_prueba = pr.id_prueba

         LEFT JOIN opciones_respuesta o
         ON r.id_opcion = o.id_opcion

         WHERE r.id_sesion = ?

         GROUP BY
           pr.id_prueba,
           pr.nombre`,

        [id_sesion]

      );

    } catch (error) {

      console.warn(
        "⚠️ No hay pruebas ligadas a la sesión:",
        error.message
      );

    }


    /* ==========================================
       4. SEGUIMIENTO CLÍNICO
    ========================================== */

    const [seguimiento] = await pool.query(

      `SELECT
        diagnostico,
        tratamiento,
        evolucion,
        observaciones

       FROM historial_seguimiento

       WHERE id_sesion = ?

       LIMIT 1`,

      [id_sesion]

    );


    /* ==========================================
       5. MULTIMEDIA
    ========================================== */

    const [multimedia] = await pool.query(

      `SELECT
        tipo,
        ruta_video,
        descripcion,
        duracion_segundos,
        formato

       FROM videos_sesion

       WHERE id_sesion = ?`,

      [id_sesion]

    );


    /* ==========================================
       6. CONSTRUIR CONTEXTO
    ========================================== */

    let contexto = `
REPORTE CLÍNICO PRELIMINAR

PACIENTE
Nombre: ${paciente[0].nombre}
Edad: ${paciente[0].edad || "N/A"}
Sexo: ${paciente[0].sexo || "N/A"}
Antecedentes: ${paciente[0].antecedentes || "No registrados"}
`;


    /* ==========================================
       HISTORIAL INICIAL
    ========================================== */

    if (historial.length) {

      contexto += `

HISTORIAL INICIAL
${Object.entries(historial[0])
  .filter(([key, value]) =>
    value !== null &&
    value !== undefined &&
    value !== ""
  )
  .map(([key, value]) =>
    `${key}: ${value}`
  )
  .join("\n")}
`;

    }


    /* ==========================================
       PRUEBAS
    ========================================== */

    contexto += `

RESULTADOS DE PRUEBAS
`;

    if (resultados.length) {

      resultados.forEach((r) => {

        contexto +=
          `- ${r.prueba}: puntaje ${r.puntaje_total}\n`;

      });

    } else {

      contexto +=
        "- No se registraron pruebas en esta sesión.\n";

    }


    /* ==========================================
       SEGUIMIENTO
    ========================================== */

    if (seguimiento.length) {

      contexto += `

SEGUIMIENTO DEL PROFESIONAL
Diagnóstico registrado: ${seguimiento[0].diagnostico || "No registrado"}
Tratamiento registrado: ${seguimiento[0].tratamiento || "No registrado"}
Evolución: ${seguimiento[0].evolucion || "No registrada"}
Observaciones: ${seguimiento[0].observaciones || "No registradas"}
`;

    }


    /* ==========================================
       MULTIMEDIA
    ========================================== */

    contexto += `

MULTIMEDIA
`;

    if (multimedia.length) {

      multimedia.forEach((m) => {

        contexto +=
          `- ${m.tipo || "Archivo"}: ` +
          `${m.descripcion || "Sin descripción"}\n`;

      });

    } else {

      contexto +=
        "- No se registró multimedia relevante.\n";

    }


    /* ==========================================
       7. PROMPT CLÍNICO CONTROLADO
    ========================================== */

    const prompt = `
Eres un asistente de apoyo para psicólogos.

Genera un PREANÁLISIS CLÍNICO BREVE utilizando
EXCLUSIVAMENTE la información proporcionada.

REGLAS:

- No realices diagnósticos.
- No inventes síntomas, resultados, antecedentes,
  interpretaciones ni información faltante.
- Una sospecha, motivo de consulta o área de evaluación
  NO constituye un diagnóstico.
- Si una condición aparece como hipótesis o área pendiente,
  descríbela como "área pendiente de evaluación".
- Si no existen pruebas, indícalo claramente.
- Conserva los puntajes registrados sin modificarlos.
- No atribuyas causas psicológicas o médicas a conductas
  si no están explícitamente registradas.
- No hagas recomendaciones médicas.
- Las recomendaciones deben limitarse a seguimiento,
  evaluación y revisión profesional.
- Si la información es insuficiente, indica:
  "Se requiere evaluación adicional."
- El diagnóstico registrado por un profesional debe
  presentarse únicamente como "diagnóstico registrado",
  no como diagnóstico realizado por la IA.

FORMATO OBLIGATORIO:

PREANÁLISIS CLÍNICO

Paciente
Nombre, edad y sexo.

Información relevante
Máximo 3 puntos.

Evaluación y pruebas
Pruebas realizadas, puntajes y datos disponibles.
Si no existen:
"No se registraron pruebas en esta sesión."

Aspectos para revisar
Máximo 3 puntos.
Solo aspectos que requieran seguimiento o evaluación.

Recomendaciones de seguimiento
Máximo 3 puntos.
Enfocadas en evaluación y seguimiento profesional.

Multimedia
Indica si existe material multimedia relevante.
Si no existe:
"No se registró multimedia relevante."

Conclusión preliminar
2 o 3 frases que indiquen qué información se conoce,
qué información falta y qué conviene revisar.

NOTA:
Este preanálisis es generado mediante inteligencia
artificial. No constituye un diagnóstico y debe ser
revisado por el psicólogo responsable.

EXTENSIÓN:
Máximo 350 palabras.

DATOS DE LA SESIÓN:

${contexto}
`;


    /* ==========================================
       8. GENERAR REPORTE
    ========================================== */

    console.log(
      "🤖 Generando reporte IA breve..."
    );


    const analisis =
      await generarReporteIA(
        prompt,
        600
      );


    console.log(
      "✅ IA respondió."
    );


    if (!analisis) {

      throw new Error(
        "La IA no devolvió ningún contenido."
      );

    }


    console.log(
      "Longitud del reporte:",
      analisis.length
    );


    /* ==========================================
       9. GUARDAR REPORTE
    ========================================== */

    const id_paciente =
      paciente[0].id_paciente;


    const [resultado] =
      await pool.query(

        `INSERT INTO reportes_ia
        (
          id_paciente,
          id_sesion,
          fecha,
          contenido
        )

        VALUES
        (
          ?, ?, NOW(), ?
        )`,

        [
          id_paciente,
          id_sesion,
          analisis
        ]

      );


    console.log(
      "✅ Reporte IA guardado:",
      resultado.insertId
    );


    /* ==========================================
       10. RESPUESTA
    ========================================== */

    return res.json({

      success: true,

      message:
        "✅ Reporte generado y guardado",

      id_reporte:
        resultado.insertId,

      analisis

    });


  } catch (err) {

    console.error(
      "❌ Error al generar análisis:",
      err
    );


    return res.status(500).json({

      success: false,

      message:
        "Error al generar el análisis",

      error:
        err.message

    });

  }

}