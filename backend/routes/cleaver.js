// backend/routes/cleaver.js

import express from "express";

import {
  guardarRespuestasCleaver,
  finalizarCleaver,
  obtenerResultadoCleaver,
  obtenerRespuestasCleaver
} from "../controllers/cleaverController.js";

const router = express.Router();

/* ==================================================
   PRUEBA DE CONEXIÓN
   GET /api/cleaver/test
================================================== */

router.get(
  "/test",
  (req, res) => {
    return res.json({
      success: true,
      message: "✅ Cleaver conectado"
    });
  }
);

/* ==================================================
   GUARDAR RESPUESTAS CLEAVER

   POST /api/cleaver/respuestas
================================================== */

router.post(
  "/respuestas",
  guardarRespuestasCleaver
);

/* ==================================================
   FINALIZAR CLEAVER

   POST /api/cleaver/finalizar
================================================== */

router.post(
  "/finalizar",
  finalizarCleaver
);

/* ==================================================
   OBTENER RESULTADO CLEAVER

   GET /api/cleaver/resultado/:id_habilitacion
================================================== */

router.get(
  "/resultado/:id_habilitacion",
  obtenerResultadoCleaver
);

/* ==================================================
   OBTENER RESPUESTAS CLEAVER

   GET /api/cleaver/respuestas/:id_habilitacion
================================================== */

router.get(
  "/respuestas/:id_habilitacion",
  obtenerRespuestasCleaver
);

/* ==================================================
   EXPORTAR ROUTER
================================================== */

export default router;