// ==================================================
// backend/routes/agendaRH.js
// ==================================================

import express
from "express";

import {
  verifyToken,
  verificarSuscripcionOrganizacion
} from "../middlewares/authMiddleware.js";

import {
  listarAgendaRH,
  crearActividadRH,
  actualizarActividadRH,
  eliminarActividadRH
} from "../controllers/agendaRHController.js";


const router =
  express.Router();


// ==================================================
// LISTAR AGENDA RH
//
// GET
// /api/agenda-rh
// ==================================================

router.get(
  "/",
  verifyToken,
  verificarSuscripcionOrganizacion,
  listarAgendaRH
);


// ==================================================
// CREAR ACTIVIDAD
//
// POST
// /api/agenda-rh
// ==================================================

router.post(
  "/",
  verifyToken,
  verificarSuscripcionOrganizacion,
  crearActividadRH
);


// ==================================================
// ACTUALIZAR ACTIVIDAD
//
// PUT
// /api/agenda-rh/:id
// ==================================================

router.put(
  "/:id",
  verifyToken,
  verificarSuscripcionOrganizacion,
  actualizarActividadRH
);


// ==================================================
// ELIMINAR ACTIVIDAD
//
// DELETE
// /api/agenda-rh/:id
// ==================================================

router.delete(
  "/:id",
  verifyToken,
  verificarSuscripcionOrganizacion,
  eliminarActividadRH
);


export default router;
