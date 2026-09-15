import {
  openaiClient,
  geminiModel,
  IA_PROVIDER
} from "../config/ia.js";

/**
 * Servicio central de IA
 * 
 * Mantiene la lógica actual:
 * - Gemini como proveedor principal cuando está configurado.
 * - OpenAI como respaldo.
 * - OpenAI directamente cuando IA_PROVIDER no es "gemini".
 */

/* ==================================================
   GENERAR REPORTE IA
================================================== */

export async function generarReporteIA(prompt, maxTokens = 1000) {
  try {

    // =============================
    // GEMINI
    // =============================

    if (IA_PROVIDER === "gemini" && geminiModel) {

      console.log("🤖 Usando Gemini para generar reporte...");

      try {

        const result = await geminiModel.generateContent(prompt);

        return result.response.text();

      } catch (err) {

        console.error("❌ Error con Gemini:", err.message);

        // Fallback automático a OpenAI
        if (openaiClient) {

          console.log("🔄 Cambiando a OpenAI como respaldo...");

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

    // =============================
    // OPENAI
    // =============================

    if (openaiClient) {

      console.log("🤖 Usando OpenAI para generar reporte...");

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

    throw new Error("No existe proveedor IA disponible");

  } catch (error) {

    console.error("❌ Error al generar reporte IA:", error);

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
${JSON.stringify(pruebas || [], null, 2)}

Reporte preliminar:
${reporte || "Sin reporte"}

Genera observaciones adicionales:

- claras
- humanas
- fáciles de entender
- no dar diagnóstico definitivo
`;

  return await generarReporteIA(prompt, 1000);
}