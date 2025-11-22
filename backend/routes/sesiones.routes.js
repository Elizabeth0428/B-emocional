// backend/routes/sesiones.routes.js
import { Router } from "express";
import { db } from "../db.js";  // ✅ CONECTA CON TU ARCHIVO db.js
import { verifyToken } from "../middlewares/authMiddleware.js";

const router = Router();

// ✅ Ruta para obtener todas las sesiones con sus videos por paciente
router.get("/pacientes/:idPaciente/sesiones", verifyToken, async (req, res) => {
  try {
    const { idPaciente } = req.params;

    // 1. Obtener sesiones
    const [sesiones] = await db.query(
      `SELECT id_sesion, fecha, notas 
       FROM sesiones 
       WHERE id_paciente = ? 
       ORDER BY fecha DESC`,
      [idPaciente]
    );

    // 2. Obtener videos por cada sesión
    for (const sesion of sesiones) {
      const [videos] = await db.query(
        "SELECT ruta_video FROM videos_sesion WHERE id_sesion = ?",
        [sesion.id_sesion]
      );
      // Agregar los videos a la sesión
      sesion.videos = videos.map(v => v.ruta_video);
    }

    res.json({ ok: true, sesiones });
  } catch (error) {
    console.error("❌ Error al obtener sesiones con videos:", error);
    res.status(500).json({ ok: false, message: "Error al obtener sesiones" });
  }
});

export default router;
