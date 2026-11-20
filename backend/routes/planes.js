// ==================================================
// backend/routes/planes.js
// ==================================================

import express from "express";

import {
  listarPlanes,
  obtenerPlan,
  crearPlan,
  actualizarPlan,
  cambiarEstadoPlan
} from "../controllers/planController.js";

import {
  verifyToken
} from "../middlewares/authMiddleware.js";


// ==================================================
// ROUTER
// ==================================================

const router =
  express.Router();


// ==================================================
// TODAS LAS RUTAS DE PLANES REQUIEREN TOKEN
// ==================================================

router.use(
  verifyToken
);


// ==================================================
// LISTAR PLANES
// GET /api/planes
// ==================================================

router.get(
  "/",
  listarPlanes
);


// ==================================================
// OBTENER PLAN
// GET /api/planes/:id
// ==================================================

router.get(
  "/:id",
  obtenerPlan
);


// ==================================================
// CREAR PLAN
// POST /api/planes
// ==================================================

router.post(
  "/",
  crearPlan
);


// ==================================================
// CAMBIAR ESTADO DEL PLAN
// PATCH /api/planes/:id/estado
//
// IMPORTANTE:
// esta ruta debe ir ANTES de /:id
// ==================================================

router.patch(
  "/:id/estado",
  cambiarEstadoPlan
);


// ==================================================
// ACTUALIZAR PLAN
// PATCH /api/planes/:id
// ==================================================

router.patch(
  "/:id",
  actualizarPlan
);


// ==================================================
// EXPORTAR
// ==================================================

export default router;