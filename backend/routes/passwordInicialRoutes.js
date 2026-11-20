// ============================================================
// backend/routes/passwordInicialRoutes.js
// ============================================================

import express from "express";

import {
  validarTokenInicial,
  crearPasswordInicial,
} from "../controllers/passwordInicialController.js";


const router =
  express.Router();


// ============================================================
// VALIDAR TOKEN
// ============================================================

router.get(
  "/validar/:token",
  validarTokenInicial
);


// ============================================================
// CREAR PASSWORD INICIAL
// ============================================================

router.post(
  "/crear",
  crearPasswordInicial
);


export default router;