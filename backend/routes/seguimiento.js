// backend/routes/seguimiento.js

import express from "express";

import {
  crearSeguimiento,
  obtenerSeguimiento
} from "../controllers/seguimientoController.js";

import { verifyToken,
  verificarSuscripcionOrganizacion
} from "../middlewares/authMiddleware.js";


const router = express.Router();


/* ==================================================
   CREAR SEGUIMIENTO
================================================== */

router.post(
  "/",
  verifyToken,
  verificarSuscripcionOrganizacion,
  crearSeguimiento
);


/* ==================================================
   OBTENER SEGUIMIENTO DE UN PACIENTE
================================================== */

router.get(
  "/:id_paciente",
  verifyToken,
  verificarSuscripcionOrganizacion,
  obtenerSeguimiento
);


export default router;
