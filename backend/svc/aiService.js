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
    fs.readFileSync(rutaArchivo);

  const archivoBase64 =
    archivoBuffer.toString("base64");

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

  const maxIntentos = 3;

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
            text: prompt
          },
          {
            inlineData: {
              mimeType,
              data: archivoBase64
            }
          }
        ]);

      const texto =
        result.response.text()?.trim() || "";

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
        modelo: "gemini-2.5-flash"
      };

    } catch (error) {
      console.error(
        `❌ Intento ${intento} falló:`,
        error.message
      );

      const mensaje =
        String(error?.message || "")
          .toLowerCase();

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
        intento * 3000;

      console.log(
        `⏳ Gemini temporalmente ocupado. Reintentando en ${espera / 1000}s...`
      );

      await new Promise(
        resolve =>
          setTimeout(resolve, espera)
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
   GENERAR REPORTE IA
================================================== */
export async function generarReporteIA(
  prompt,
  maxTokens = 1000
) {
  try {

    /* =============================
       GEMINI
    ============================= */
    if (
      IA_PROVIDER === "gemini" &&
      geminiModel
    ) {
      console.log(
        "🤖 Usando Gemini para generar reporte..."
      );

      try {
        const result =
          await geminiModel.generateContent(
            prompt
          );

        return result.response.text();

      } catch (err) {
        console.error(
          "❌ Error con Gemini:",
          err.message
        );

        if (openaiClient) {
          console.log(
            "🔄 Cambiando a OpenAI como respaldo..."
          );

          const response =
            await openaiClient.chat.completions.create({
              model: "gpt-4o-mini",
              messages: [
                {
                  role: "system",
                  content:
                    "Eres un asistente clínico profesional que ayuda a psicólogos."
                },
                {
                  role: "user",
                  content: prompt
                }
              ],
              max_tokens: maxTokens
            });

          return (
            response.choices?.[0]?.message?.content ||
            "⚠️ Sin respuesta IA."
          );
        }

        throw err;
      }
    }

    /* =============================
       OPENAI
    ============================= */
    if (openaiClient) {
      console.log(
        "🤖 Usando OpenAI para generar reporte..."
      );

      const response =
        await openaiClient.chat.completions.create({
          model: "gpt-4o-mini",
          messages: [
            {
              role: "system",
              content:
                "Eres un asistente clínico profesional que ayuda a psicólogos."
            },
            {
              role: "user",
              content: prompt
            }
          ],
          max_tokens: maxTokens
        });

      return (
        response.choices?.[0]?.message?.content ||
        "⚠️ Sin respuesta IA."
      );
    }

    throw new Error(
      "No existe proveedor IA disponible"
    );

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
    1000
  );
}