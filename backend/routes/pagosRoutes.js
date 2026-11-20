// ============================================================
// backend/routes/pagosRoutes.js
// ============================================================

import express
  from "express";

import {
  crearSuscripcionMirrorSoul,
  obtenerEstadoSuscripcion,
  obtenerPrecioPlan,
  obtenerEstadoContratacion,
  webhookMercadoPago,
} from "../controllers/pagosController.js";


const router =
  express.Router();


// ============================================================
// PRECIO
// ============================================================

router.get(
  "/precio",
  obtenerPrecioPlan
);


// ============================================================
// CREAR SUSCRIPCIÓN
// ============================================================

router.post(
  "/crear-suscripcion",
  crearSuscripcionMirrorSoul
);


// ============================================================
// CONSULTAR SUSCRIPCIÓN MERCADO PAGO
// ============================================================

router.get(
  "/suscripcion/:id",
  obtenerEstadoSuscripcion
);


// ============================================================
// CONSULTAR CONTRATACIÓN INTERNA
// ============================================================

router.get(
  "/contratacion/:externalReference",
  obtenerEstadoContratacion
);


// ============================================================
// WEBHOOK MERCADO PAGO
// ============================================================

router.post(
  "/webhook",
  webhookMercadoPago
);


export default router;
