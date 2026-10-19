import {
  openaiClient,
  geminiModel,
  IA_PROVIDER
} from "../config/ia.js";

import fs from "fs";


/* ==================================================
   TRANSCRIBIR AUDIO O VIDEO CON GEMINI
================================================== */

export async function transcribirMultimedia(
  rutaArchivo,
  mimeType = "audio/webm"
) {

  if (!geminiModel) {

    throw new Error(
      "Gemini no está configurado para realizar transcripciones."
    );

  }


  if (!fs.existsSync(rutaArchivo)) {

    throw new Error(
      `No se encontró el archivo multimedia: ${rutaArchivo}`
    );

  }


  const archivoBuffer =
    fs.readFileSync(
      rutaArchivo
    );


  const archivoBase64 =
    archivoBuffer.toString(
      "base64"
    );


  const prompt = `
Transcribe fielmente el contenido hablado de esta grabación
de una sesión psicológica en español.

REGLAS:
- Transcribe únicamente lo que realmente se escucha.
- Puede haber más de una persona hablando.
- No inventes quién habla si no puede distinguirse.
- No resumas.
- No interpretes clínicamente.
- No agregues diagnósticos.
- No inventes palabras.
- Si una parte no puede entenderse, escribe [inaudible].
- Devuelve únicamente la transcripción.
`;


  const maxIntentos =
    3;


  for (
    let intento = 1;
    intento <= maxIntentos;
    intento++
  ) {

    try {

      console.log(
        `🎙️ Transcribiendo multimedia con Gemini. Intento ${intento}/${maxIntentos}`
      );


      console.log(
        "📦 MIME enviado a Gemini:",
        mimeType
      );


      const result =
        await geminiModel.generateContent([
          {
            text:
              prompt
          },
          {
            inlineData: {
              mimeType,
              data:
                archivoBase64
            }
          }
        ]);


      const texto =
        result.response
          .text()
          ?.trim() ||
        "";


      if (!texto) {

        throw new Error(
          "Gemini no devolvió texto de transcripción."
        );

      }


      console.log(
        "✅ Grabación transcrita con Gemini. Caracteres:",
        texto.length
      );


      return {
        texto,
        modelo:
          "gemini-2.5-flash"
      };


    } catch (error) {

      console.error(
        `❌ Intento ${intento} falló:`,
        error.message
      );


      const mensaje =
        String(
          error?.message ||
          ""
        ).toLowerCase();


      const errorTemporal =
        mensaje.includes("503") ||
        mensaje.includes("overloaded") ||
        mensaje.includes("temporary") ||
        mensaje.includes("try again later") ||
        mensaje.includes("unavailable");


      if (
        !errorTemporal ||
        intento === maxIntentos
      ) {

        throw error;

      }


      const espera =
        intento *
        3000;


      console.log(
        `⏳ Gemini temporalmente ocupado. Reintentando en ${espera / 1000}s...`
      );


      await new Promise(
        resolve =>
          setTimeout(
            resolve,
            espera
          )
      );

    }

  }

}


/* ==================================================
   COMPATIBILIDAD CON AUDIO EXISTENTE
================================================== */

export async function transcribirAudio(
  rutaArchivo
) {

  return transcribirMultimedia(
    rutaArchivo,
    "audio/webm"
  );

}


/* ==================================================
   GENERAR REPORTE IA CON METADATOS

   NUEVA FUNCIÓN:
   devuelve texto + proveedor + modelo.

   Esto permite saber qué IA generó realmente
   el reporte, incluyendo fallback.
================================================== */

export async function generarReporteIAConMeta(
  prompt,
  maxTokens = 1000,
  systemPrompt = null
) {

  const sistema =
    systemPrompt ||
    `Eres un asistente profesional que analiza
información proporcionada por especialistas.

Utiliza únicamente los datos disponibles.
No inventes información.
Distingue hechos registrados de inferencias.
No sustituyes el criterio del profesional.`;


  /* ==================================================
     GEMINI PRIMARIO
  ================================================== */

  if (
    IA_PROVIDER === "gemini" &&
    geminiModel
  ) {

    console.log(
      "🤖 Usando Gemini para generar reporte..."
    );


    try {

      const promptFinal = `
INSTRUCCIONES DEL SISTEMA:

${sistema}

SOLICITUD:

${prompt}
`;


      const result =
        await geminiModel.generateContent(
          promptFinal
        );


      const texto =
        result.response
          .text()
          ?.trim() ||
        "";


      if (!texto) {

        throw new Error(
          "Gemini no devolvió contenido."
        );

      }


      return {
        texto,
        proveedor:
          "gemini",
        modelo:
          "gemini"
      };


    } catch (err) {

      console.error(
        "❌ Error con Gemini:",
        err.message
      );


      if (!openaiClient) {

        throw err;

      }


      console.log(
        "🔄 Cambiando a OpenAI como respaldo..."
      );


      const response =
        await openaiClient
          .chat
          .completions
          .create({

            model:
              "gpt-4o-mini",

            messages: [
              {
                role:
                  "system",

                content:
                  sistema
              },
              {
                role:
                  "user",

                content:
                  prompt
              }
            ],

            max_tokens:
              maxTokens

          });


      const texto =
        response
          .choices?.[0]
          ?.message?.content
          ?.trim() ||
        "";


      if (!texto) {

        throw new Error(
          "OpenAI no devolvió contenido."
        );

      }


      return {
        texto,
        proveedor:
          "openai-fallback",
        modelo:
          "gpt-4o-mini"
      };

    }

  }


  /* ==================================================
     OPENAI PRIMARIO
  ================================================== */

  if (openaiClient) {

    console.log(
      "🤖 Usando OpenAI para generar reporte..."
    );


    const response =
      await openaiClient
        .chat
        .completions
        .create({

          model:
            "gpt-4o-mini",

          messages: [
            {
              role:
                "system",

              content:
                sistema
            },
            {
              role:
                "user",

              content:
                prompt
            }
          ],

          max_tokens:
            maxTokens

        });


    const texto =
      response
        .choices?.[0]
        ?.message?.content
        ?.trim() ||
      "";


    if (!texto) {

      throw new Error(
        "OpenAI no devolvió contenido."
      );

    }


    return {
      texto,
      proveedor:
        "openai",
      modelo:
        "gpt-4o-mini"
    };

  }


  /* ==================================================
     GEMINI COMO RESPALDO SI OPENAI NO EXISTE
  ================================================== */

  if (geminiModel) {

    console.log(
      "🔄 OpenAI no disponible. Usando Gemini..."
    );


    const promptFinal = `
INSTRUCCIONES DEL SISTEMA:

${sistema}

SOLICITUD:

${prompt}
`;


    const result =
      await geminiModel.generateContent(
        promptFinal
      );


    const texto =
      result.response
        .text()
        ?.trim() ||
      "";


    if (!texto) {

      throw new Error(
        "Gemini no devolvió contenido."
      );

    }


    return {
      texto,
      proveedor:
        "gemini-fallback",
      modelo:
        "gemini"
    };

  }


  throw new Error(
    "No existe proveedor IA disponible"
  );

}


/* ==================================================
   GENERAR REPORTE IA
   COMPATIBILIDAD CON CLÍNICA

   IMPORTANTE:
   sigue devolviendo STRING para no romper
   iaController.js ni el módulo clínico.
================================================== */

export async function generarReporteIA(
  prompt,
  maxTokens = 1000,
  systemPrompt = null
) {

  try {

    const resultado =
      await generarReporteIAConMeta(
        prompt,
        maxTokens,
        systemPrompt
      );


    return resultado.texto;


  } catch (error) {

    console.error(
      "❌ Error al generar reporte IA:",
      error
    );


    throw error;

  }

}


/* ==================================================
   ANALIZAR DATOS DE PACIENTE
================================================== */

export async function analyzeWithIA(
  paciente,
  pruebas,
  emociones,
  reporte
) {

  const prompt = `
Eres un asistente para psicólogos.

Analiza los siguientes datos clínicos.

Paciente:
${paciente?.nombre || "Desconocido"}

Emociones detectadas:
${
  Array.isArray(emociones)
    ? emociones.join(", ")
    : "No detectadas"
}

Pruebas:
${JSON.stringify(
  pruebas || [],
  null,
  2
)}

Reporte preliminar:
${reporte || "Sin reporte"}

Genera observaciones adicionales:

- claras
- humanas
- fáciles de entender
- no dar diagnóstico definitivo
`;


  return await generarReporteIA(
    prompt,
    1000,
    `Eres un asistente clínico profesional
que ayuda a psicólogos.

No realices diagnósticos definitivos.
No inventes información.
Utiliza únicamente los datos proporcionados.`
  );

}