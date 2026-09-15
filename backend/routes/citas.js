// backend/routes/citas.js

import express from "express";

import {
  listarCitas,
  crearCita,
  obtenerCita,
  actualizarCita,
  eliminarCita
} from "../controllers/citaController.js";

import { verifyToken } from "../middlewares/authMiddleware.js";

const router = express.Router();


/* ==================================================
   LISTAR CITAS
================================================== */

router.get(
  "/",
  verifyToken,
  listarCitas
);


/* ==================================================
   CREAR CITA
================================================== */

router.post(
  "/",
  verifyToken,
  crearCita
);


/* ==================================================
   OBTENER UNA CITA
================================================== */

router.get(
  "/:id",
  verifyToken,
  obtenerCita
);


/* ==================================================
   ACTUALIZAR CITA
================================================== */

router.put(
  "/:id",
  verifyToken,
  actualizarCita
);


/* ==================================================
   ELIMINAR CITA
================================================== */

router.delete(
  "/:id",
  verifyToken,
  eliminarCita
);


export default router;