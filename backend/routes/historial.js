// backend/routes/historial.js

import express from "express";

import {
  obtenerHistorialInicial,
  crearHistorialInicial,
  actualizarHistorialInicial
} from "../controllers/historialController.js";

import { verifyToken } from "../middlewares/authMiddleware.js";

const router = express.Router();


/* ==================================================
   OBTENER HISTORIAL INICIAL
================================================== */

router.get(
  "/:id_paciente",
  verifyToken,
  obtenerHistorialInicial
);


/* ==================================================
   CREAR HISTORIAL INICIAL
================================================== */

router.post(
  "/",
  verifyToken,
  crearHistorialInicial
);


/* ==================================================
   ACTUALIZAR HISTORIAL INICIAL
================================================== */

router.put(
  "/:id_paciente",
  verifyToken,
  actualizarHistorialInicial
);


export default router;