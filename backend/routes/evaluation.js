import express from "express";
import { analyzeWithIA } from "../services/aiService.js";

const router = express.Router();

// ===== Ruta /evaluateTests =====
router.post("/evaluateTests", (req, res) => {
  const { paciente, pruebas = {}, emociones = [] } = req.body;

  // 🔹 Aseguramos que Beck es un array
  const beckResponses = Array.isArray(pruebas.Beck) ? pruebas.Beck : [];

  // 🔹 Si vinieran respuestas como texto, asignamos puntajes simples
  let scoreBeck = 0;
  if (beckResponses.length > 0) {
    scoreBeck = beckResponses.reduce((acc, r) => {
      if (typeof r === "number") return acc + r; // caso: ya es número
      if (typeof r === "object" && r.score) return acc + r.score; // caso: objeto con score
      return acc + 1; // caso: texto, contamos 1 punto por respuesta
    }, 0);
  }

  const reporte = `
📄 Reporte de ${paciente?.nombre || "Paciente"}
-----------------------------------
Emociones detectadas: ${emociones.join(", ") || "Ninguna"}

Resultados de pruebas:
- Beck: ${scoreBeck} puntos (${scoreBeck < 10 ? "Leve" : "Moderado/Alto"})

⚠️ Este reporte es preliminar, el psicólogo tiene la última decisión.
`;

  res.json({ reporte });
});

// ===== Ruta /analyzeWithIA =====
router.post("/analyzeWithIA", async (req, res) => {
  const { paciente, pruebas, emociones, reporte } = req.body;

  try {
    const insights = await analyzeWithIA(paciente, pruebas, emociones, reporte);
    res.json({ insights });
  } catch (error) {
    console.error("❌ Error en IA:", error);
    res.status(500).json({ error: "Error generando análisis IA" });
  }
});

export default router;
