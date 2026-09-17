// backend/routes/usuariosIndependiente.js

import express from "express";

import {
  registrarUsuarioIndependiente,
  listarUsuariosIndependiente
} from "../controllers/usuarioIndependienteController.js";

import {
  verifyToken
} from "../middlewares/authMiddleware.js";


const router = express.Router();


/* ============================================================
   REGISTRAR USUARIO INDEPENDIENTE

   POST
   /api/usuarios-independiente
============================================================ */

router.post(
  "/",
  verifyToken,
  registrarUsuarioIndependiente
);


/* ============================================================
   LISTAR USUARIOS INDEPENDIENTES

   GET
   /api/usuarios-independiente
============================================================ */

router.get(
  "/",
  verifyToken,
  listarUsuariosIndependiente
);


export default router;