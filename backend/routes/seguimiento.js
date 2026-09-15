// backend/routes/seguimiento.js

import express from "express";

import {
  crearSeguimiento,
  obtenerSeguimiento
} from "../controllers/seguimientoController.js";

import { verifyToken } from "../middlewares/authMiddleware.js";


const router = express.Router();


/* ==================================================
   CREAR SEGUIMIENTO
================================================== */

router.post(
  "/",
  verifyToken,
  crearSeguimiento
);


/* ==================================================
   OBTENER SEGUIMIENTO DE UN PACIENTE
================================================== */

router.get(
  "/:id_paciente",
  verifyToken,
  obtenerSeguimiento
);


export default router;