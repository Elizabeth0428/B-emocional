// ============================================================
// backend/routes/usuariosIndependiente.js
// ============================================================

import express from "express";

import {
  registrarUsuarioIndependiente,
  listarUsuariosIndependiente
} from "../controllers/usuarioIndependienteController.js";

import {
  verifyToken
} from "../middlewares/authMiddleware.js";


const router =
  express.Router();


// ============================================================
// CREAR CUENTA INDEPENDIENTE
//
// PÚBLICA
//
// El propio profesional crea su cuenta.
// NO necesita token.
// ============================================================

router.post(
  "/",
  registrarUsuarioIndependiente
);


// ============================================================
// LISTAR CUENTAS INDEPENDIENTES
//
// PRIVADA
// SOLO MASTER
// ============================================================

router.get(
  "/",
  verifyToken,
  listarUsuariosIndependiente
);


export default router;