// backend/routes/notas.js

import express from "express";

import {
  crearNota,
  guardarNotaIA,
  obtenerNotaIA,
  obtenerNotasSesion
} from "../controllers/notasController.js";

import { verifyToken,
  verificarSuscripcionOrganizacion
} from "../middlewares/authMiddleware.js";

const router = express.Router();

/* ==================================================
   CREAR NOTA / CHAT MANUAL
================================================== */

router.post(
  "/",
  verifyToken,
  verificarSuscripcionOrganizacion,
  crearNota
);

/* ==================================================
   NOTA PARA PREANÁLISIS IA
================================================== */

router.post(
  "/ia",
  verifyToken,
  verificarSuscripcionOrganizacion,
  guardarNotaIA
);

router.get(
  "/ia/:id_sesion",
  verifyToken,
  verificarSuscripcionOrganizacion,
  obtenerNotaIA
);

/* ==================================================
   OBTENER TODAS LAS NOTAS DE UNA SESIÓN
================================================== */

router.get(
  "/sesion/:id_sesion",
  verifyToken,
  verificarSuscripcionOrganizacion,
  obtenerNotasSesion
);

export default router;
