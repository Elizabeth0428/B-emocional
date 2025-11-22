import OpenAI from "openai";

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY
});

export async function analyzeWithIA(paciente, pruebas, emociones, reporte) {
  const prompt = `
Eres un asistente para psicólogos. Analiza los siguientes datos clínicos y da observaciones cualitativas, claras y breves.
Paciente: ${paciente?.nombre || "Desconocido"}
Emociones detectadas: ${emociones.join(", ")}
Pruebas: ${JSON.stringify(pruebas, null, 2)}
Reporte preliminar: ${reporte}

Genera observaciones adicionales en lenguaje humano, no técnico.
`;

  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini", // o "gpt-4o" si lo prefieres
    messages: [{ role: "user", content: prompt }]
  });

  return completion.choices[0].message.content;
}
