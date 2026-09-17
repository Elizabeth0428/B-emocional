import pool from "../config/database.js";
import { analyzeWithIA, generarReporteIA } from "../svc/aiService.js";

/* ==================================================
   ANALIZAR DATOS RECIBIDOS
   POST /api/ia/analizar
================================================== */
export async function generarAnalisisIA(req, res) {
  try {
    const { paciente, pruebas, emociones, reporte } = req.body;

    const resultado = await analyzeWithIA(
      paciente,
      pruebas,
      emociones,
      reporte
    );

    res.json({
      success: true,
      analisis: resultado,
    });
  } catch (error) {
    console.error("❌ Error IA:", error);

    res.status(500).json({
      success: false,
      message: "Error generando análisis IA",
      error: error.message,
    });
  }
}

/* ==================================================
   ANALIZAR SESIÓN
   POST /api/ia/analisis-sesion

   IMPORTANTE:
   - Trabaja con el id_sesion real.
   - Obtiene el paciente desde la sesión.
   - Usa resultados_prueba vinculados a esa sesión.
   - Lee notas específicas para IA.
   - Compara con la última sesión finalizada.
   - Usa la nota IA anterior si el cierre no aporta.
   - Lee transcripciones completadas.
   - NO realiza diagnóstico definitivo.
   - Guarda el Preanálisis IA ligado a la sesión.
================================================== */
export async function generarAnalisisSesion(req, res) {
  const { id_sesion } = req.body;

  if (!id_sesion) {
    return res.status(400).json({
      success: false,
      message: "Falta el ID de la sesión",
    });
  }

  try {
    console.log(
      "📥 Generando Preanálisis IA para sesión:",
      id_sesion
    );

    /* ==========================================
       1. DATOS DEL PACIENTE + SESIÓN
    ========================================== */
    const [paciente] = await pool.query(
      `SELECT
        p.id_paciente,
        p.nombre,
        p.edad,
        p.sexo,
        p.antecedentes,
        s.id_sesion,
        s.modalidad,
        s.notas,
        s.fecha,
        s.fecha_fin,
        s.estado
       FROM pacientes p
       JOIN sesiones s
         ON s.id_paciente = p.id_paciente
       WHERE s.id_sesion = ?
       LIMIT 1`,
      [id_sesion]
    );

    if (!paciente.length) {
      return res.status(404).json({
        success: false,
        message: "Paciente no encontrado para la sesión",
      });
    }

    const pacienteActual = paciente[0];

    /* ==========================================
       2. HISTORIAL INICIAL
    ========================================== */
    const [historial] = await pool.query(
      `SELECT *
       FROM historial_inicial
       WHERE id_paciente = ?
       LIMIT 1`,
      [pacienteActual.id_paciente]
    );

    /* ==========================================
       3. SESIÓN ANTERIOR FINALIZADA + CIERRE
    ========================================== */
    let sesionAnterior = null;
    let cierreAnterior = null;
    let notaIAAnterior = null;

    try {
      const [anteriores] = await pool.query(
        `SELECT
          id_sesion,
          fecha,
          modalidad,
          estado
         FROM sesiones
         WHERE id_paciente = ?
           AND id_sesion <> ?
           AND estado = 'finalizada'
           AND fecha < ?
         ORDER BY fecha DESC, id_sesion DESC
         LIMIT 1`,
        [
          pacienteActual.id_paciente,
          id_sesion,
          pacienteActual.fecha,
        ]
      );

      sesionAnterior = anteriores[0] || null;

      if (sesionAnterior) {
        const [cierres] = await pool.query(
          `SELECT
            diagnostico,
            tratamiento,
            evolucion,
            observaciones,
            tareas_acuerdos,
            fecha
           FROM historial_seguimiento
           WHERE id_sesion = ?
           ORDER BY fecha DESC, id_seguimiento DESC
           LIMIT 1`,
          [sesionAnterior.id_sesion]
        );

        cierreAnterior = cierres[0] || null;

        const [notasAnterior] = await pool.query(
          `SELECT
            id_chat,
            pregunta,
            fecha
           FROM notas_sesion
           WHERE id_sesion = ?
             AND tipo = 'nota_ia'
           ORDER BY fecha DESC
           LIMIT 1`,
          [sesionAnterior.id_sesion]
        );

        notaIAAnterior = notasAnterior[0] || null;
      }

      console.log(
        `🔄 Sesión anterior para #${id_sesion}:`,
        sesionAnterior?.id_sesion || "ninguna"
      );

      console.log(
        `📝 Nota IA anterior:`,
        notaIAAnterior ? "encontrada" : "no registrada"
      );

    } catch (error) {
      console.warn(
        "⚠️ No fue posible obtener la sesión anterior:",
        error.message
      );

      sesionAnterior = null;
      cierreAnterior = null;
      notaIAAnterior = null;
    }

    /* ==========================================
       4. NOTA PARA IA DE ESTA SESIÓN
    ========================================== */
    let notaIA = null;

    try {
      const [notasIA] = await pool.query(
        `SELECT
          id_chat,
          pregunta,
          fecha
         FROM notas_sesion
         WHERE id_sesion = ?
           AND tipo = 'nota_ia'
         ORDER BY fecha DESC
         LIMIT 1`,
        [id_sesion]
      );

      notaIA = notasIA.length
        ? notasIA[0]
        : null;

      console.log(
        `📝 Nota IA sesión #${id_sesion}:`,
        notaIA ? "encontrada" : "no registrada"
      );
    } catch (error) {
      console.warn(
        "⚠️ No fue posible obtener la nota IA:",
        error.message
      );

      notaIA = null;
    }

    /* ==========================================
       5. RESULTADOS REALES DE PRUEBAS
    ========================================== */
    let resultados = [];

    try {
      [resultados] = await pool.query(
        `SELECT
          rp.id_resultado,
          rp.id_prueba,
          rp.id_habilitacion,
          rp.id_sesion,
          rp.puntaje_total,
          rp.interpretacion,
          rp.fecha,
          pr.nombre AS prueba
         FROM resultados_prueba rp
         JOIN pruebas pr
           ON pr.id_prueba = rp.id_prueba
         WHERE rp.id_sesion = ?
         ORDER BY rp.fecha ASC, rp.id_resultado ASC`,
        [id_sesion]
      );

      console.log(
        `🧪 Resultados encontrados para sesión #${id_sesion}:`,
        resultados.length
      );
    } catch (error) {
      console.warn(
        "⚠️ No fue posible obtener los resultados de pruebas:",
        error.message
      );

      resultados = [];
    }

    /* ==========================================
       6. SEGUIMIENTO CLÍNICO EXISTENTE
    ========================================== */
    let seguimiento = [];

    try {
      [seguimiento] = await pool.query(
        `SELECT
          diagnostico,
          tratamiento,
          evolucion,
          observaciones
         FROM historial_seguimiento
         WHERE id_sesion = ?
         ORDER BY fecha DESC, id_seguimiento DESC
         LIMIT 1`,
        [id_sesion]
      );
    } catch (error) {
      console.warn(
        "⚠️ No fue posible obtener seguimiento:",
        error.message
      );

      seguimiento = [];
    }

    /* ==========================================
       7. MULTIMEDIA + TRANSCRIPCIÓN
    ========================================== */
    let multimedia = [];

    try {
      [multimedia] = await pool.query(
        `SELECT
          tipo,
          ruta_video,
          descripcion,
          duracion_segundos,
          formato,
          transcripcion,
          transcripcion_estado,
          transcripcion_fecha,
          transcripcion_modelo
         FROM videos_sesion
         WHERE id_sesion = ?
         ORDER BY fecha_subida ASC`,
        [id_sesion]
      );
    } catch (error) {
      console.warn(
        "⚠️ No fue posible obtener multimedia:",
        error.message
      );

      multimedia = [];
    }

    /* ==========================================
       8. NORMALIZAR INFORMACIÓN CLÍNICA
    ========================================== */
    const valorClinicoUtil = (valor) => {
      if (valor === null || valor === undefined) return null;

      const texto = String(valor).trim();

      if (!texto) return null;

      const sinInformacion = [
        "no",
        "ninguno",
        "ninguna",
        "n/a",
        "na",
        "no aplica",
        "no registrado",
        "no registrada",
        "-",
        "--"
      ];

      return sinInformacion.includes(texto.toLowerCase())
        ? null
        : texto;
    };

    const diagnosticoAnterior = valorClinicoUtil(
      cierreAnterior?.diagnostico
    );

    const tratamientoAnterior = valorClinicoUtil(
      cierreAnterior?.tratamiento
    );

    const evolucionAnterior = valorClinicoUtil(
      cierreAnterior?.evolucion
    );

    const observacionesAnteriores = valorClinicoUtil(
      cierreAnterior?.observaciones
    );

    const tareasAnteriores = valorClinicoUtil(
      cierreAnterior?.tareas_acuerdos
    );

    const notaAnteriorUtil = valorClinicoUtil(
      notaIAAnterior?.pregunta
    );

    /* ==========================================
       9. CONSTRUIR CONTEXTO
    ========================================== */
    let contexto = `
PREANÁLISIS CLÍNICO DE SESIÓN

DATOS DEL PACIENTE
Nombre: ${pacienteActual.nombre}
Edad: ${pacienteActual.edad || "N/A"}
Sexo: ${pacienteActual.sexo || "N/A"}

DATOS DE LA SESIÓN
ID de sesión: ${pacienteActual.id_sesion}
Fecha: ${pacienteActual.fecha || "No registrada"}
Modalidad: ${pacienteActual.modalidad || "No registrada"}
Estado: ${pacienteActual.estado || "No registrado"}
`;

    /* ==========================================
       NOTAS GENERALES DE LA SESIÓN
    ========================================== */
    contexto += `
NOTAS GENERALES DE LA SESIÓN
${pacienteActual.notas || "No registradas"}
`;

    /* ==========================================
       NOTA DEL PSICÓLOGO PARA IA
    ========================================== */
    contexto += `
NOTA DEL PSICÓLOGO PARA PREANÁLISIS IA
${
  notaIA?.pregunta
    ? notaIA.pregunta
    : "No se registró nota adicional para IA en esta sesión."
}
`;

    /* ==========================================
       HISTORIAL INICIAL RESUMIDO
    ========================================== */
    contexto += `
ANTECEDENTES RELEVANTES
`;

    if (historial.length) {
      const datosHistorial = Object.entries(historial[0])
        .filter(
          ([key, value]) =>
            key !== "id_historial" &&
            key !== "id_paciente" &&
            value !== null &&
            value !== undefined &&
            value !== ""
        )
        .slice(0, 15)
        .map(([key, value]) => `${key}: ${value}`)
        .join("\n");

      contexto +=
        datosHistorial ||
        "No hay antecedentes relevantes disponibles.\n";
    } else {
      contexto +=
        "No se encontró historial inicial registrado.\n";
    }

    /* ==========================================
       CONTINUIDAD CON SESIÓN ANTERIOR
    ========================================== */
    contexto += `
SESIÓN ANTERIOR PARA COMPARACIÓN
`;

    if (sesionAnterior) {
      contexto += `
Sesión anterior: #${sesionAnterior.id_sesion}
Fecha: ${sesionAnterior.fecha || "No registrada"}
Modalidad: ${sesionAnterior.modalidad || "No registrada"}

Diagnóstico / impresión profesional anterior:
${diagnosticoAnterior || "Sin información clínica útil"}

Intervención / tratamiento anterior:
${tratamientoAnterior || "Sin información clínica útil"}

Evolución registrada anteriormente:
${evolucionAnterior || "Sin información clínica útil"}

Observaciones anteriores:
${observacionesAnteriores || "Sin información clínica útil"}

Tareas / acuerdos de la sesión anterior:
${tareasAnteriores || "Sin información clínica útil"}

Nota clínica para IA de la sesión anterior:
${notaAnteriorUtil || "No registrada"}
`;
    } else {
      contexto +=
        "No existe una sesión anterior finalizada disponible para comparación.\n";
    }

    /* ==========================================
       PRUEBAS
    ========================================== */
    contexto += `
RESULTADOS DE PRUEBAS DE ESTA SESIÓN
`;

    if (resultados.length) {
      resultados.forEach((r) => {
        contexto += `- Prueba: ${
          r.prueba || "Sin nombre"
        }\n`;

        contexto += `  Puntaje: ${
          r.puntaje_total !== null &&
          r.puntaje_total !== undefined
            ? r.puntaje_total
            : "No registrado"
        }\n`;

        contexto += `  Interpretación registrada: ${
          r.interpretacion || "No registrada"
        }\n`;
      });
    } else {
      contexto +=
        "No se registraron pruebas en esta sesión.\n";
    }

    /* ==========================================
       SEGUIMIENTO EXISTENTE
    ========================================== */
    contexto += `
CIERRE O SEGUIMIENTO REGISTRADO EN ESTA SESIÓN
`;

    if (seguimiento.length) {
      contexto += `
Diagnóstico registrado por el profesional: ${
        seguimiento[0].diagnostico ||
        "No registrado"
      }
Tratamiento registrado: ${
        seguimiento[0].tratamiento ||
        "No registrado"
      }
Evolución registrada: ${
        seguimiento[0].evolucion ||
        "No registrada"
      }
Observaciones registradas: ${
        seguimiento[0].observaciones ||
        "No registradas"
      }
`;
    } else {
      contexto +=
        "Todavía no existe cierre o seguimiento clínico registrado para esta sesión.\n";
    }

    /* ==========================================
       MULTIMEDIA + TRANSCRIPCIÓN
    ========================================== */
    contexto += `
MULTIMEDIA DE ESTA SESIÓN
`;

    if (multimedia.length) {
      multimedia.forEach((m, index) => {
        const tieneTranscripcion =
          m.transcripcion_estado === "completada" &&
          typeof m.transcripcion === "string" &&
          m.transcripcion.trim();

        contexto += `- Archivo ${index + 1}
Tipo: ${m.tipo || "Archivo"}
Descripción: ${m.descripcion || "Sin descripción"}
Formato: ${m.formato || "No registrado"}
Duración: ${
          m.duracion_segundos
            ? `${m.duracion_segundos} segundos`
            : "No registrada"
        }
Estado de transcripción: ${
          m.transcripcion_estado || "No registrada"
        }
`;

        if (tieneTranscripcion) {
          contexto += `Transcripción del audio:
${m.transcripcion.trim()}
`;
        } else {
          contexto +=
            "Transcripción del audio: No disponible.\n";
        }
      });
    } else {
      contexto +=
        "No se registró multimedia relevante.\n";
    }

    /* ==========================================
       10. PROMPT CLÍNICO CORTO
    ========================================== */
    const prompt = `
Eres un asistente de apoyo para profesionales de psicología.

Tu función es generar un PREANÁLISIS IA BREVE antes de que
el psicólogo realice el cierre clínico de la sesión.

Utiliza EXCLUSIVAMENTE la información proporcionada.

REGLAS OBLIGATORIAS:

- No inventes información.
- No inventes síntomas.
- No inventes antecedentes.
- No inventes resultados de pruebas.
- No modifiques puntajes.
- No afirmes haber escuchado audio o visto video directamente.
- Si existe una TRANSCRIPCIÓN completada, puedes utilizar su contenido
  como fuente textual de esta sesión.
- La transcripción puede contener intervenciones del psicólogo,
  del paciente o de otras personas.
- NO atribuyas automáticamente cada frase al paciente si el hablante
  no está claramente identificado.
- No conviertas frases del psicólogo en síntomas del paciente.
- Si existe multimedia pero no existe transcripción,
  solo menciona que hay material registrado.
- Da prioridad a la información ACTUAL de esta sesión.
- La nota del psicólogo para IA representa información
  relevante de la consulta actual y debe considerarse.
- Para describir lo ocurrido HOY, integra de forma prudente:
  nota del psicólogo + transcripción disponible + pruebas de esta sesión.
- Si la nota del psicólogo y la transcripción parecen contradecirse,
  no elijas una como verdadera: señala que existe información
  que requiere revisión profesional.

- Para identificar CAMBIOS, compara prioritariamente con
  la SESIÓN ANTERIOR FINALIZADA.
- Usa primero el cierre profesional anterior cuando contenga
  información clínica útil.
- Si el cierre anterior está vacío o contiene respuestas sin
  valor clínico como "no", "ninguno", "N/A" o similares,
  utiliza la NOTA CLÍNICA PARA IA DE LA SESIÓN ANTERIOR
  como fuente de continuidad.
- La nota anterior NO sustituye un diagnóstico profesional;
  úsala únicamente para reconocer temas, cambios y continuidad.
- El historial inicial funciona como antecedente general,
  no como comparación principal cuando existe sesión anterior.
- No afirmes mejoría, empeoramiento, continuidad o recaída
  si la información disponible no permite compararlo.
- Si un tema actual no aparece en la sesión anterior,
  puedes describirlo como "nuevo elemento registrado".
- Si existen tareas o acuerdos de la sesión anterior,
  utilízalos solo para señalar qué conviene revisar antes del cierre.

- Si existen pruebas de esta sesión, considéralas.
- Si no existen pruebas, indícalo brevemente.
- No presentes una hipótesis como diagnóstico confirmado.
- No realices recomendaciones médicas.
- No uses lenguaje alarmista.
- El psicólogo conserva siempre la decisión clínica final.

FORMATO OBLIGATORIO:

PREANÁLISIS IA

Hoy: una sola frase sobre lo más importante ocurrido en esta sesión.

Cambio: compara prioritariamente la información ACTUAL contra
la SESIÓN ANTERIOR FINALIZADA. Indica en una sola frase si algo
mejoró, empeoró, continúa, reapareció, desapareció o es un elemento nuevo.
No inventes cambios.

Si no hay información suficiente de la sesión anterior para comparar,
escribe:
"No hay información suficiente de la sesión anterior para establecer cambios."

Pruebas: una sola frase con las pruebas realizadas en ESTA SESIÓN,
puntaje e interpretación relevante. Si no hubo pruebas escribe:
"No se registraron pruebas en esta sesión."

Atención: una sola frase indicando el aspecto más importante que
merece atención profesional.

Antes del cierre: una sola frase con lo más importante que conviene
aclarar, confirmar o revisar antes de cerrar la sesión.

Orientación prediagnóstica IA: una sola frase de orientación clínica
preliminar basada únicamente en la información disponible.

Describe indicadores, áreas de exploración o patrones observados.

NO nombres trastornos, síndromes ni diagnósticos específicos
a menos que exista un diagnóstico previamente registrado por
el profesional y, en ese caso, identifícalo como tal.

Prefiere expresiones como:
"se observan indicadores de malestar emocional asociados a..."
"la información sugiere revisar..."
"los datos disponibles orientan a explorar..."

Nunca presentes esta orientación como diagnóstico definitivo.

IMPORTANTE:

- Máximo 6 líneas principales después del título.
- Cada apartado debe ocupar solo una línea o frase breve.
- Evita repetir nombre, edad, sexo o antecedentes completos.
- Evita explicaciones largas.
- Evita listas adicionales.
- No agregues recomendaciones extensas.
- No agregues una sección aparte de multimedia.
- No agregues una conclusión adicional.
- No superes aproximadamente 130 palabras.

Al final agrega únicamente:

"Apoyo generado por IA. La interpretación y decisión clínica final corresponden al psicólogo."

DATOS DISPONIBLES:

${contexto}
`;

    /* ==========================================
       11. GENERAR PREANÁLISIS
    ========================================== */
    console.log(
      `🤖 Generando Preanálisis IA corto de sesión #${id_sesion}...`
    );

    const analisis =
      await generarReporteIA(
        prompt,
        300
      );

    if (!analisis) {
      throw new Error(
        "La IA no devolvió ningún contenido."
      );
    }

    console.log(
      "✅ Preanálisis IA generado. Longitud:",
      analisis.length
    );

    /* ==========================================
       12. GUARDAR REPORTE
    ========================================== */
    const [resultado] = await pool.query(
      `INSERT INTO reportes_ia
       (
         id_paciente,
         id_sesion,
         fecha,
         contenido
       )
       VALUES (?, ?, NOW(), ?)`,
      [
        pacienteActual.id_paciente,
        id_sesion,
        analisis,
      ]
    );

    console.log(
      "✅ Preanálisis IA guardado:",
      resultado.insertId
    );

    /* ==========================================
       13. RESPUESTA
    ========================================== */
    return res.json({
      success: true,
      message:
        "✅ Preanálisis IA generado y guardado",
      id_reporte:
        resultado.insertId,
      id_paciente:
        pacienteActual.id_paciente,
      id_sesion:
        Number(id_sesion),
      analisis,
    });

  } catch (err) {
    console.error(
      "❌ Error al generar Preanálisis IA:",
      err
    );

    return res.status(500).json({
      success: false,
      message:
        "Error al generar el Preanálisis IA",
      error:
        err.message,
    });
  }
}