// backend/routes/citas.js

import express from "express";

import {
  listarCitas,
  crearCita,
  obtenerCita,
  actualizarCita,
  cambiarEstadoCita,
  eliminarCita
} from "../controllers/citaController.js";

import {
  verifyToken,
  verificarSuscripcionOrganizacion
} from "../middlewares/authMiddleware.js";

const router = express.Router();


/* ==================================================
   LISTAR CITAS Y EVENTOS

   GET /api/citas
================================================== */

router.get(
  "/",
  verifyToken,
  verificarSuscripcionOrganizacion,
  listarCitas
);


/* ==================================================
   CREAR CITA O EVENTO

   POST /api/citas
================================================== */

router.post(
  "/",
  verifyToken,
  verificarSuscripcionOrganizacion,
  crearCita
);


/* ==================================================
   CAMBIAR ESTADO DE CITA O EVENTO

   PATCH /api/citas/:id/estado

   IMPORTANTE:
   Esta ruta debe estar ANTES de /:id
================================================== */

router.patch(
  "/:id/estado",
  verifyToken,
  verificarSuscripcionOrganizacion,
  cambiarEstadoCita
);


/* ==================================================
   OBTENER UNA CITA O EVENTO

   GET /api/citas/:id
================================================== */

router.get(
  "/:id",
  verifyToken,
  verificarSuscripcionOrganizacion,
  obtenerCita
);


/* ==================================================
   ACTUALIZAR CITA O EVENTO

   PUT /api/citas/:id
================================================== */

router.put(
  "/:id",
  verifyToken,
  verificarSuscripcionOrganizacion,
  actualizarCita
);


/* ==================================================
   ELIMINAR CITA O EVENTO

   DELETE /api/citas/:id
================================================== */

router.delete(
  "/:id",
  verifyToken,
  verificarSuscripcionOrganizacion,
  eliminarCita
);


export default router;
