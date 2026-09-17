// backend/routes/notas.js

import express from "express";

import {
  crearNota,
  guardarNotaIA,
  obtenerNotaIA,
  obtenerNotasSesion
} from "../controllers/notasController.js";

import { verifyToken } from "../middlewares/authMiddleware.js";

const router = express.Router();

/* ==================================================
   CREAR NOTA / CHAT MANUAL
================================================== */

router.post(
  "/",
  verifyToken,
  crearNota
);

/* ==================================================
   NOTA PARA PREANÁLISIS IA
================================================== */

router.post(
  "/ia",
  verifyToken,
  guardarNotaIA
);

router.get(
  "/ia/:id_sesion",
  verifyToken,
  obtenerNotaIA
);

/* ==================================================
   OBTENER TODAS LAS NOTAS DE UNA SESIÓN
================================================== */

router.get(
  "/sesion/:id_sesion",
  verifyToken,
  obtenerNotasSesion
);

export default router;