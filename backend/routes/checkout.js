// ============================================================
// backend/routes/checkout.js
// ============================================================

import express from "express";

import {
  crearCheckout,
  aprobarPago,
  obtenerPago
} from "../controllers/checkoutController.js";

import {
  verifyToken
} from "../middlewares/authMiddleware.js";


const router =
  express.Router();


// ============================================================
// CREAR CHECKOUT
//
// Público por ahora.
// Después se conectará con el flujo comercial.
// ============================================================

router.post(
  "/",
  crearCheckout
);


// ============================================================
// CONSULTAR PAGO
// ============================================================

router.get(
  "/:id",
  obtenerPago
);


// ============================================================
// APROBAR MANUALMENTE
//
// Solo Master.
// ============================================================

router.patch(
  "/:id/aprobar",
  verifyToken,
  aprobarPago
);


export default router;