// ============================================================
// backend/routes/independienteManual.js
// ============================================================

import express from "express";

import {
  verifyToken
} from "../middlewares/authMiddleware.js";

import {
  crearIndependienteManual
} from "../controllers/independienteManualController.js";


const router =
  express.Router();


// ============================================================
// CREAR MEMBRESÍA INDEPENDIENTE MANUAL
//
// POST
// /api/independientes-manual
//
// SOLO MASTER
// ============================================================

router.post(
  "/",
  verifyToken,
  crearIndependienteManual
);


export default router;