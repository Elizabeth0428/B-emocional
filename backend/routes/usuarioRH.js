
// backend/routes/usuario-RH.js

import express from "express";

import {
  registrarUsuarioRH,
  listarUsuariosRH,
  obtenerUsuarioRH,
  actualizarUsuarioRH,
} from "../controllers/usuarioRHController.js";

import {
  verifyToken,
} from "../middlewares/authMiddleware.js";

const router = express.Router();


// ============================================================
// REGISTRAR USUARIO RH
//
// POST
// /api/usuario-rh
// ============================================================

router.post(
  "/",
  verifyToken,
  registrarUsuarioRH
);


// ============================================================
// LISTAR USUARIOS RH
//
// GET
// /api/usuario-rh
// ============================================================

router.get(
  "/",
  verifyToken,
  listarUsuariosRH
);


// ============================================================
// OBTENER FICHA COMPLETA
//
// GET
// /api/usuario-rh/:id
// ============================================================

router.get(
  "/:id",
  verifyToken,
  obtenerUsuarioRH
);


// ============================================================
// ACTUALIZAR FICHA
//
// PUT
// /api/usuario-rh/:id
// ============================================================

router.put(
  "/:id",
  verifyToken,
  actualizarUsuarioRH
);


export default router;
