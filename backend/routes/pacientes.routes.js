import { Router } from "express";
import { db } from "../db.js";
import { verifyToken } from "../middlewares/authMiddleware.js";

const router = Router();

// ===============================
//   OBTENER TODOS LOS PACIENTES
// ===============================
router.get("/pacientes", verifyToken, async (req, res) => {
  try {
    const [rows] = await db.query(
      `SELECT * FROM pacientes`
    );

    res.json(rows);

  } catch (error) {
    console.error("❌ Error al obtener pacientes:", error);
    res.status(500).json({ message: "Error interno" });
  }
});

// ===============================
//  OBTENER DETALLE DE PACIENTE
// ===============================
router.get("/pacientes/:idPaciente", verifyToken, async (req, res) => {
  try {
    const { idPaciente } = req.params;

    const [rows] = await db.query(
      `SELECT * FROM pacientes WHERE id_paciente = ?`,
      [idPaciente]
    );

    if (rows.length === 0) {
      return res.status(404).json({ message: "Paciente no encontrado" });
    }

    res.json(rows[0]);

  } catch (error) {
    console.error("❌ Error al obtener paciente:", error);
    res.status(500).json({ message: "Error interno" });
  }
});

export default router;
