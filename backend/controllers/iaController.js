import pool from "../config/database.js";
import { analyzeWithIA, generarReporteIA } from "../svc/aiService.js";

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

    const resultado =
      await analyzeWithIA(
        paciente,
        pruebas,
        emociones,
        reporte
      );

    return res.json({
      success: true,
      analisis: resultado
    });

  } catch (error) {
    console.error(
      "❌ Error IA:",
      error
    );

    return res
      .status(500)
      .json({
        success: false,
        message:
          "Error generando análisis IA",
        error:
          error.message
      });
  }
}


/* ==================================================
   ANALIZAR SESIÓN
   POST /api/ia/analisis-sesion

   IMPORTANTE:
   - Trabaja con el id_sesion real.
   - Usa numero_sesion como consecutivo clínico visible.
   - Obtiene el paciente desde la sesión.
   - Usa resultados_prueba vinculados a esa sesión.
   - Complementa Cleaver con resultados_cleaver.
   - Lee notas específicas para IA.
   - Compara con la última sesión finalizada.
   - Usa la nota IA anterior si el cierre no aporta.
   - Lee transcripciones completadas.
   - NO realiza diagnóstico definitivo.
   - Guarda el Preanálisis IA ligado a la sesión.
   - Solo permite 1 Preanálisis IA por sesión.
================================================== */
export async function generarAnalisisSesion(req, res) {

  const {
    id_sesion
  } = req.body;

  if (!id_sesion) {
    return res
      .status(400)
      .json({
        success: false,
        message:
          "Falta el ID de la sesión"
      });
  }

  try {

    const idSesion =
      Number(
        id_sesion
      );

    if (
      !Number.isInteger(
        idSesion
      ) ||
      idSesion <= 0
    ) {
      return res
        .status(400)
        .json({
          success: false,
          message:
            "ID de sesión inválido"
        });
    }

    console.log(
      "📥 Generando Preanálisis IA para sesión:",
      idSesion
    );


    /* ==========================================
       1. DATOS DEL PACIENTE + SESIÓN
    ========================================== */

    const [paciente] =
      await pool.query(
        `
          SELECT
            p.id_paciente,
            p.nombre,
            p.edad,
            p.sexo,
            p.antecedentes,

            s.id_sesion,
            s.numero_sesion,
            s.modalidad,
            s.notas,
            s.fecha,
            s.fecha_fin,
            s.estado

          FROM pacientes p

          JOIN sesiones s
            ON s.id_paciente =
               p.id_paciente

          WHERE s.id_sesion = ?

          LIMIT 1
        `,
        [
          idSesion
        ]
      );

    if (
      !paciente.length
    ) {
      return res
        .status(404)
        .json({
          success: false,
          message:
            "Paciente no encontrado para la sesión"
        });
    }

    const pacienteActual =
      paciente[0];

    const numeroSesionActual =
      Number(
        pacienteActual
          .numero_sesion ||
        1
      );


    /* ==========================================
       2. EVITAR PREANÁLISIS DUPLICADO

       REGLA:
       1 sesión clínica = 1 Preanálisis IA

       Si ya existe un reporte ligado a esta sesión,
       se devuelve el existente y NO se genera otro.
    ========================================== */

    const [reportesExistentes] =
      await pool.query(
        `
          SELECT
            id_reporte,
            id_paciente,
            id_sesion,
            fecha,
            contenido,
            ruta_pdf

          FROM reportes_ia

          WHERE id_sesion = ?

          ORDER BY
            fecha DESC,
            id_reporte DESC

          LIMIT 1
        `,
        [
          idSesion
        ]
      );

    if (
      reportesExistentes.length > 0
    ) {

      const reporteExistente =
        reportesExistentes[0];

      console.log(
        `♻️ Preanálisis IA ya existente para sesión clínica #${numeroSesionActual} (id interno ${idSesion}). Se reutiliza reporte #${reporteExistente.id_reporte}.`
      );

      return res.json({
        success: true,

        existente:
          true,

        message:
          `✅ Ya existe un Preanálisis IA para la sesión #${numeroSesionActual}`,

        id_reporte:
          reporteExistente
            .id_reporte,

        id_paciente:
          pacienteActual
            .id_paciente,

        id_sesion:
          idSesion,

        numero_sesion:
          numeroSesionActual,

        fecha:
          reporteExistente
            .fecha,

        ruta_pdf:
          reporteExistente
            .ruta_pdf ||
          null,

        analisis:
          reporteExistente
            .contenido
      });
    }


    /* ==========================================
       3. HISTORIAL INICIAL
    ========================================== */

    const [historial] =
      await pool.query(
        `
          SELECT *

          FROM historial_inicial

          WHERE id_paciente = ?

          LIMIT 1
        `,
        [
          pacienteActual
            .id_paciente
        ]
      );


    /* ==========================================
       4. SESIÓN ANTERIOR FINALIZADA + CIERRE
    ========================================== */

    let sesionAnterior =
      null;

    let cierreAnterior =
      null;

    let notaIAAnterior =
      null;

    try {

      const [anteriores] =
        await pool.query(
          `
            SELECT
              id_sesion,
              numero_sesion,
              fecha,
              modalidad,
              estado

            FROM sesiones

            WHERE id_paciente = ?

              AND id_sesion <> ?

              AND estado = 'finalizada'

              AND fecha < ?

            ORDER BY
              fecha DESC,
              id_sesion DESC

            LIMIT 1
          `,
          [
            pacienteActual
              .id_paciente,

            idSesion,

            pacienteActual
              .fecha
          ]
        );

      sesionAnterior =
        anteriores[0] ||
        null;

      if (
        sesionAnterior
      ) {

        const [cierres] =
          await pool.query(
            `
              SELECT
                diagnostico,
                tratamiento,
                evolucion,
                observaciones,
                tareas_acuerdos,
                fecha

              FROM historial_seguimiento

              WHERE id_sesion = ?

              ORDER BY
                fecha DESC,
                id_seguimiento DESC

              LIMIT 1
            `,
            [
              sesionAnterior
                .id_sesion
            ]
          );

        cierreAnterior =
          cierres[0] ||
          null;

        const [notasAnterior] =
          await pool.query(
            `
              SELECT
                id_chat,
                pregunta,
                fecha

              FROM notas_sesion

              WHERE id_sesion = ?

                AND tipo = 'nota_ia'

              ORDER BY
                fecha DESC

              LIMIT 1
            `,
            [
              sesionAnterior
                .id_sesion
            ]
          );

        notaIAAnterior =
          notasAnterior[0] ||
          null;
      }

      console.log(
        `🔄 Sesión anterior para sesión clínica #${numeroSesionActual}:`,
        sesionAnterior
          ? `#${sesionAnterior.numero_sesion || sesionAnterior.id_sesion}`
          : "ninguna"
      );

      console.log(
        "📝 Nota IA anterior:",
        notaIAAnterior
          ? "encontrada"
          : "no registrada"
      );

    } catch (error) {

      console.warn(
        "⚠️ No fue posible obtener la sesión anterior:",
        error.message
      );

      sesionAnterior =
        null;

      cierreAnterior =
        null;

      notaIAAnterior =
        null;
    }


    /* ==========================================
       5. NOTA PARA IA DE ESTA SESIÓN
    ========================================== */

    let notaIA =
      null;

    try {

      const [notasIA] =
        await pool.query(
          `
            SELECT
              id_chat,
              pregunta,
              fecha

            FROM notas_sesion

            WHERE id_sesion = ?

              AND tipo = 'nota_ia'

            ORDER BY
              fecha DESC

            LIMIT 1
          `,
          [
            idSesion
          ]
        );

      notaIA =
        notasIA.length
          ? notasIA[0]
          : null;

      console.log(
        `📝 Nota IA sesión clínica #${numeroSesionActual}:`,
        notaIA
          ? "encontrada"
          : "no registrada"
      );

    } catch (error) {

      console.warn(
        "⚠️ No fue posible obtener la nota IA:",
        error.message
      );

      notaIA =
        null;
    }


    /* ==========================================
       6. RESULTADOS REALES DE PRUEBAS
       + DETALLE ESPECIAL CLEAVER
    ========================================== */

    let resultados =
      [];

    try {

      [resultados] =
        await pool.query(
          `
            SELECT

              rp.id_resultado,
              rp.id_prueba,
              rp.id_habilitacion,
              rp.id_sesion,
              rp.puntaje_total,
              rp.interpretacion,
              rp.fecha,

              pr.nombre AS prueba,

              rc.id_resultado_cleaver,

              rc.perfil_principal
                AS cleaver_perfil_principal,

              rc.interpretacion
                AS cleaver_interpretacion,

              rc.m_d_bruto
                AS cleaver_m_d,

              rc.m_i_bruto
                AS cleaver_m_i,

              rc.m_s_bruto
                AS cleaver_m_s,

              rc.m_c_bruto
                AS cleaver_m_c,

              rc.l_d_bruto
                AS cleaver_l_d,

              rc.l_i_bruto
                AS cleaver_l_i,

              rc.l_s_bruto
                AS cleaver_l_s,

              rc.l_c_bruto
                AS cleaver_l_c,

              rc.t_d_bruto
                AS cleaver_t_d,

              rc.t_i_bruto
                AS cleaver_t_i,

              rc.t_s_bruto
                AS cleaver_t_s,

              rc.t_c_bruto
                AS cleaver_t_c

            FROM resultados_prueba rp

            JOIN pruebas pr
              ON pr.id_prueba =
                 rp.id_prueba

            LEFT JOIN resultados_cleaver rc
              ON rc.id_resultado =
                 rp.id_resultado

            WHERE rp.id_sesion = ?

            ORDER BY
              rp.fecha ASC,
              rp.id_resultado ASC
          `,
          [
            idSesion
          ]
        );

      console.log(
        `🧪 Resultados encontrados para sesión clínica #${numeroSesionActual}:`,
        resultados.length
      );

    } catch (error) {

      console.warn(
        "⚠️ No fue posible obtener los resultados de pruebas:",
        error.message
      );

      resultados =
        [];
    }


    /* ==========================================
       7. SEGUIMIENTO CLÍNICO EXISTENTE
    ========================================== */

    let seguimiento =
      [];

    try {

      [seguimiento] =
        await pool.query(
          `
            SELECT
              diagnostico,
              tratamiento,
              evolucion,
              observaciones

            FROM historial_seguimiento

            WHERE id_sesion = ?

            ORDER BY
              fecha DESC,
              id_seguimiento DESC

            LIMIT 1
          `,
          [
            idSesion
          ]
        );

    } catch (error) {

      console.warn(
        "⚠️ No fue posible obtener seguimiento:",
        error.message
      );

      seguimiento =
        [];
    }


    /* ==========================================
       8. MULTIMEDIA + TRANSCRIPCIÓN
    ========================================== */

    let multimedia =
      [];

    try {

      [multimedia] =
        await pool.query(
          `
            SELECT
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

            ORDER BY
              fecha_subida ASC
          `,
          [
            idSesion
          ]
        );

    } catch (error) {

      console.warn(
        "⚠️ No fue posible obtener multimedia:",
        error.message
      );

      multimedia =
        [];
    }


    /* ==========================================
       9. NORMALIZAR INFORMACIÓN CLÍNICA
    ========================================== */

    const valorClinicoUtil = (
      valor
    ) => {

      if (
        valor === null ||
        valor === undefined
      ) {
        return null;
      }

      const texto =
        String(
          valor
        ).trim();

      if (!texto) {
        return null;
      }

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

      return sinInformacion.includes(
        texto.toLowerCase()
      )
        ? null
        : texto;
    };

    const diagnosticoAnterior =
      valorClinicoUtil(
        cierreAnterior
          ?.diagnostico
      );

    const tratamientoAnterior =
      valorClinicoUtil(
        cierreAnterior
          ?.tratamiento
      );

    const evolucionAnterior =
      valorClinicoUtil(
        cierreAnterior
          ?.evolucion
      );

    const observacionesAnteriores =
      valorClinicoUtil(
        cierreAnterior
          ?.observaciones
      );

    const tareasAnteriores =
      valorClinicoUtil(
        cierreAnterior
          ?.tareas_acuerdos
      );

    const notaAnteriorUtil =
      valorClinicoUtil(
        notaIAAnterior
          ?.pregunta
      );


    /* ==========================================
       IDENTIFICAR CLEAVER
    ========================================== */

    const esCleaver = (
      resultado
    ) => {

      return (
        Number(
          resultado
            ?.id_prueba
        ) === 4 ||

        String(
          resultado
            ?.prueba ||
          ""
        )
          .trim()
          .toLowerCase()
          .includes(
            "cleaver"
          )
      );
    };


    /* ==========================================
       10. CATÁLOGO DE PRUEBAS DISPONIBLES

       Se usa para que la IA pueda recomendar
       únicamente pruebas reales de MirrorSoul.
    ========================================== */

    let pruebasDisponibles = [];

    try {

      [pruebasDisponibles] =
        await pool.query(
          `
            SELECT
              id_prueba,
              nombre

            FROM pruebas

            ORDER BY nombre ASC
          `
        );

      console.log(
        "🧪 Pruebas disponibles para recomendaciones IA:",
        pruebasDisponibles.length
      );

    } catch (error) {

      console.warn(
        "⚠️ No fue posible obtener el catálogo de pruebas:",
        error.message
      );

      pruebasDisponibles = [];
    }


    /* ==========================================
       11. CONSTRUIR CONTEXTO
    ========================================== */

    let contexto = `
PREANÁLISIS CLÍNICO DE SESIÓN

DATOS DEL PACIENTE
Nombre: ${pacienteActual.nombre}
Edad: ${pacienteActual.edad || "N/A"}
Sexo: ${pacienteActual.sexo || "N/A"}

DATOS DE LA SESIÓN
Número clínico de sesión: #${numeroSesionActual}
ID interno de sesión: ${pacienteActual.id_sesion}
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

    if (
      historial.length
    ) {

      const datosHistorial =
        Object.entries(
          historial[0]
        )
          .filter(
            ([key, value]) =>
              key !==
                "id_historial" &&

              key !==
                "id_historial_inicial" &&

              key !==
                "id_paciente" &&

              key !==
                "fecha_registro" &&

              key !==
                "created_at" &&

              key !==
                "updated_at" &&

              value !==
                null &&

              value !==
                undefined &&

              value !==
                ""
          )
          .slice(
            0,
            15
          )
          .map(
            (
              [
                key,
                value
              ]
            ) =>
              `${key}: ${value}`
          )
          .join(
            "\n"
          );

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

    if (
      sesionAnterior
    ) {

      const numeroSesionAnterior =
        Number(
          sesionAnterior
            .numero_sesion ||
          0
        ) ||
        sesionAnterior
          .id_sesion;

      contexto += `
Sesión anterior: #${numeroSesionAnterior}
ID interno anterior: ${sesionAnterior.id_sesion}
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
       PRUEBAS REALIZADAS
    ========================================== */

    contexto += `
RESULTADOS DE PRUEBAS DE ESTA SESIÓN
`;

    if (
      resultados.length
    ) {

      resultados.forEach(
        (
          r
        ) => {

          const nombrePrueba =
            r.prueba ||
            "Sin nombre";

          contexto +=
            `- Prueba: ${nombrePrueba}\n`;


          /* ======================================
             CLEAVER
          ====================================== */

          if (
            esCleaver(
              r
            )
          ) {

            contexto +=
              "  Tipo de resultado: Perfil conductual multidimensional Cleaver.\n";

            contexto +=
              `  Perfil principal: ${
                r.cleaver_perfil_principal ||
                "No registrado"
              }\n`;

            const tieneT =
              r.cleaver_t_d !==
                null &&
              r.cleaver_t_d !==
                undefined &&

              r.cleaver_t_i !==
                null &&
              r.cleaver_t_i !==
                undefined &&

              r.cleaver_t_s !==
                null &&
              r.cleaver_t_s !==
                undefined &&

              r.cleaver_t_c !==
                null &&
              r.cleaver_t_c !==
                undefined;

            if (
              tieneT
            ) {

              contexto +=
                `  Perfil D/I/S/C: D ${r.cleaver_t_d} · I ${r.cleaver_t_i} · S ${r.cleaver_t_s} · C ${r.cleaver_t_c}\n`;
            }

            contexto +=
              `  Interpretación Cleaver: ${
                r.cleaver_interpretacion ||
                r.interpretacion ||
                "No registrada"
              }\n`;

            contexto +=
              "  IMPORTANTE: Cleaver no debe interpretarse como un puntaje total. No utilizar puntaje_total = 0 como resultado clínico.\n";

            return;
          }


          /* ======================================
             PRUEBAS NORMALES
          ====================================== */

          contexto +=
            `  Puntaje: ${
              r.puntaje_total !==
                null &&
              r.puntaje_total !==
                undefined

                ? r.puntaje_total

                : "No registrado"
            }\n`;

          contexto +=
            `  Interpretación registrada: ${
              r.interpretacion ||
              "No registrada"
            }\n`;
        }
      );

    } else {

      contexto +=
        "No se registraron pruebas en esta sesión.\n";
    }


    /* ==========================================
       PRUEBAS DISPONIBLES EN MIRRORSOUL
    ========================================== */

    contexto += `
PRUEBAS DISPONIBLES EN MIRRORSOUL
`;

    if (
      pruebasDisponibles.length
    ) {

      pruebasDisponibles.forEach(
        (prueba) => {

          contexto +=
            `- ${prueba.nombre} (id ${prueba.id_prueba})\n`;
        }
      );

    } else {

      contexto +=
        "No fue posible obtener el catálogo de pruebas disponibles.\n";
    }


    /* ==========================================
       SEGUIMIENTO EXISTENTE
    ========================================== */

    contexto += `
CIERRE O SEGUIMIENTO REGISTRADO EN ESTA SESIÓN
`;

    if (
      seguimiento.length
    ) {

      contexto += `
Diagnóstico registrado por el profesional: ${
  seguimiento[0]
    .diagnostico ||
  "No registrado"
}

Tratamiento registrado: ${
  seguimiento[0]
    .tratamiento ||
  "No registrado"
}

Evolución registrada: ${
  seguimiento[0]
    .evolucion ||
  "No registrada"
}

Observaciones registradas: ${
  seguimiento[0]
    .observaciones ||
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

    if (
      multimedia.length
    ) {

      multimedia.forEach(
        (
          m,
          index
        ) => {

          const tieneTranscripcion =
            m.transcripcion_estado ===
              "completada" &&

            typeof m.transcripcion ===
              "string" &&

            m.transcripcion
              .trim();

          contexto +=
            `- Archivo ${index + 1}\n`;

          contexto +=
            `Tipo: ${m.tipo || "Archivo"}\n`;

          contexto +=
            `Descripción: ${m.descripcion || "Sin descripción"}\n`;

          contexto +=
            `Formato: ${m.formato || "No registrado"}\n`;

          contexto +=
            `Duración: ${
              m.duracion_segundos
                ? `${m.duracion_segundos} segundos`
                : "No registrada"
            }\n`;

          contexto +=
            `Estado de transcripción: ${
              m.transcripcion_estado ||
              "No registrada"
            }\n`;

          if (
            tieneTranscripcion
          ) {

            contexto +=
              `Transcripción del audio:\n${m.transcripcion.trim()}\n`;

          } else {

            contexto +=
              "Transcripción del audio: No disponible.\n";
          }
        }
      );

    } else {

      contexto +=
        "No se registró multimedia relevante.\n";
    }


    /* ==========================================
       12. PROMPT CLÍNICO CORTO
    ========================================== */

    const prompt = `
Eres un asistente de apoyo clínico para profesionales de psicología.

Tu función es generar un PREANÁLISIS IA BREVE antes de que
el psicólogo realice el cierre clínico de la sesión.

Utiliza EXCLUSIVAMENTE la información proporcionada.


REGLAS OBLIGATORIAS:

- No inventes información, síntomas, antecedentes ni resultados.

- No modifiques puntajes ni clasificaciones de las pruebas.

- No afirmes haber escuchado audio o visto video directamente.

- Si existe una transcripción completada,
  úsala únicamente como fuente textual.

- No atribuyas automáticamente una frase al paciente
  si el hablante no está claramente identificado.

- No conviertas frases del psicólogo
  en síntomas del paciente.

- Da prioridad a la información ACTUAL
  de esta sesión.

- La nota del psicólogo para IA representa
  información relevante de la consulta actual.

- Para describir lo ocurrido hoy,
  integra prudentemente:

  nota del psicólogo,
  transcripción disponible
  y pruebas de esta sesión.

- Si la nota del psicólogo y la transcripción
  parecen contradecirse,
  señala que existe información
  que requiere revisión profesional.

- Para identificar CAMBIOS,
  compara prioritariamente con
  la SESIÓN ANTERIOR FINALIZADA.

- Usa primero el cierre profesional anterior
  cuando contenga información clínica útil.

- Si el cierre anterior está vacío
  o carece de información clínica útil,
  puedes utilizar la nota clínica para IA
  de la sesión anterior como referencia.

- El historial inicial funciona
  como antecedente general.

- No afirmes mejoría,
  empeoramiento,
  continuidad
  o recaída
  si la información disponible
  no permite establecerlo.

- Si un tema actual
  no aparece en la sesión anterior,
  puedes describirlo como:

  "nuevo elemento registrado".

- Si existen tareas
  o acuerdos de la sesión anterior,
  utilízalos únicamente para señalar
  qué conviene revisar.

- Si existen pruebas de esta sesión,
  intégralas entre sí.

- Si no existen pruebas,
  indícalo brevemente.

- Si una prueba es Cleaver,
  NO la describas mediante "puntaje 0".

- Para Cleaver utiliza:

  perfil principal,
  valores D/I/S/C,
  e interpretación proporcionada.

- Cleaver es un resultado multidimensional.

- No lo conviertas
  en un puntaje total.

- No inventes una escala global.

- No realices recomendaciones médicas.

- No realices recomendaciones farmacológicas.

- No uses lenguaje alarmista.

- El psicólogo conserva siempre
  la decisión clínica final.


ORIENTACIÓN PREDIAGNÓSTICA:

- Puedes formular una
  HIPÓTESIS CLÍNICA PRELIMINAR
  cuando los datos disponibles
  la sostengan.

- Nunca presentes esta hipótesis
  como diagnóstico confirmado.

- Puedes utilizar expresiones como:

  "sintomatología depresiva"

  "sintomatología ansiosa"

  "estrés significativo"

  "malestar emocional significativo"

  "indicadores compatibles con un cuadro depresivo"

  "indicadores compatibles con un cuadro ansioso"

- Cuando existan varios resultados
  de pruebas,
  intégralos de manera breve.

- Si existen indicadores
  de ansiedad,
  depresión
  y estrés,
  puedes señalar que existe
  un patrón de malestar emocional
  que requiere valoración clínica conjunta.

- Solo menciona un trastorno específico
  como hipótesis a explorar
  cuando exista evidencia suficiente
  en pruebas,
  notas
  o antecedentes.

- Utiliza expresiones prudentes como:

  "conviene explorar..."

  "podría ser compatible con..."

  "requiere valoración clínica..."

  "hipótesis a descartar o confirmar..."

  "los resultados orientan a explorar..."

- Nunca escribas:

  "el paciente tiene..."

  "el diagnóstico es..."

  salvo que exista un diagnóstico
  previamente registrado
  por el profesional.

- Si existe un diagnóstico profesional previo,
  aclara que fue registrado
  por el profesional.


PRUEBAS COMPLEMENTARIAS:

- Revisa el apartado:

  PRUEBAS DISPONIBLES EN MIRRORSOUL.

- Sugiere únicamente pruebas
  cuyo nombre aparezca
  en ese catálogo.

- No inventes nombres de pruebas.

- No recomiendes pruebas
  que no existan en MirrorSoul.

- Revisa qué pruebas
  ya fueron aplicadas
  en esta sesión.

- Evita recomendar nuevamente
  una prueba ya realizada.

- Solo puede repetirse una prueba
  si existe una razón clínica clara
  para seguimiento longitudinal
  o comparación posterior.

- Recomienda máximo
  2 o 3 pruebas.

- Cada prueba sugerida
  debe incluir una razón
  breve y concreta.

Ejemplo:

"Prueba X: para profundizar en síntomas ansiosos."

- No hagas recomendaciones
  solo para llenar el apartado.

- Si las pruebas realizadas
  ya proporcionan información suficiente
  y no existe una evaluación
  complementaria clara,
  escribe:

  "No se identifica una prueba complementaria específica disponible en MirrorSoul."


ALERTA CLÍNICA:

- Si los resultados muestran
  intensidad severa,
  riesgo importante,
  deterioro marcado
  o información que amerite
  atención prioritaria,
  indícalo de forma breve
  y profesional.

- No exageres el nivel de riesgo.

- No inventes riesgo.

- Un resultado severo
  no significa automáticamente
  que exista riesgo suicida.

- Sin embargo,
  cuando clínicamente corresponda,
  puedes sugerir brevemente:

  "Conviene explorar factores de riesgo autolesivo o suicida."

- Esa recomendación debe presentarse
  como algo que el profesional
  debe valorar,
  nunca como una afirmación
  de que el riesgo existe.


FORMATO OBLIGATORIO:

PREANÁLISIS IA

Resumen actual:

Una o dos frases
con los hallazgos principales
de esta sesión.


Cambio:

Una sola frase
comparando la información actual
con la sesión anterior.

Si no hay información suficiente,
escribe exactamente:

"No hay información suficiente de la sesión anterior para establecer cambios."


Pruebas:

Una sola frase
con las pruebas realizadas,
puntajes
e interpretación relevante.

Para Cleaver:

resume perfil principal,
D/I/S/C
e interpretación relevante.

No menciones "puntaje 0".

Si no hubo pruebas escribe:

"No se registraron pruebas en esta sesión."


Orientación prediagnóstica IA:

Máximo dos frases.

Integra los resultados disponibles
y señala la principal hipótesis clínica
o las áreas que conviene explorar.

Nunca la presentes
como diagnóstico definitivo.


Pruebas complementarias sugeridas:

Recomienda máximo
2 o 3 pruebas
disponibles en MirrorSoul.

Incluye solamente
una razón breve
para cada una.

No repitas pruebas
ya realizadas
sin justificación.


Siguiente sesión / atención:

Máximo dos frases.

Indica qué aspecto
conviene revisar,
confirmar
o explorar.

Si existe un resultado severo
o un hallazgo
que amerite atención profesional prioritaria,
menciónalo aquí
de forma breve.


IMPORTANTE:

- Mantén el texto compacto.

- Debe ser claro.

- Debe ser clínicamente útil.

- No hagas listas largas.

- No repitas nombre,
  edad,
  sexo
  ni antecedentes completos.

- No agregues
  una conclusión adicional.

- No agregues
  una sección extra.

- Evita explicaciones extensas.

- No desarrolles
  tratamientos completos.

- No realices recomendaciones
  médicas
  o farmacológicas.

- No superes aproximadamente
  180 palabras.


Al final agrega únicamente:

"Apoyo generado por IA. La interpretación, diagnóstico y decisión clínica final corresponden al psicólogo."


DATOS DISPONIBLES:

${contexto}
`;


    /* ==========================================
       13. GENERAR PREANÁLISIS
    ========================================== */

    console.log(
      `🤖 Generando Preanálisis IA corto de sesión clínica #${numeroSesionActual} (id interno ${idSesion})...`
    );

    const analisis =
      await generarReporteIA(
        prompt,
        420
      );

    if (
      !analisis
    ) {
      throw new Error(
        "La IA no devolvió ningún contenido."
      );
    }

    console.log(
      "✅ Preanálisis IA generado. Longitud:",
      analisis.length
    );


    /* ==========================================
       14. GUARDAR REPORTE
    ========================================== */

    const [resultado] =
      await pool.query(
        `
          INSERT INTO reportes_ia
          (
            id_paciente,
            id_sesion,
            fecha,
            contenido
          )
          VALUES
          (
            ?,
            ?,
            NOW(),
            ?
          )
        `,
        [
          pacienteActual
            .id_paciente,

          idSesion,

          analisis
        ]
      );

    console.log(
      "✅ Preanálisis IA guardado:",
      resultado.insertId
    );


    /* ==========================================
       15. RESPUESTA
    ========================================== */

    return res.json({
      success: true,

      existente:
        false,

      message:
        "✅ Preanálisis IA generado y guardado",

      id_reporte:
        resultado.insertId,

      id_paciente:
        pacienteActual
          .id_paciente,

      id_sesion:
        idSesion,

      numero_sesion:
        numeroSesionActual,

      analisis
    });

  } catch (err) {

    console.error(
      "❌ Error al generar Preanálisis IA:",
      err
    );

    return res
      .status(500)
      .json({
        success: false,

        message:
          "Error al generar el Preanálisis IA",

        error:
          err.message
      });
  }
}