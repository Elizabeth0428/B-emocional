// backend/routes/usuariosEducativo.js

import express from "express";

import {
  registrarUsuarioEducativo,
  listarUsuariosEducativo
} from "../controllers/usuarioEducativoController.js";

import {
  verifyToken
} from "../middlewares/authMiddleware.js";


const router = express.Router();


/* ============================================================
   REGISTRAR USUARIO EDUCATIVO

   POST
   /api/usuarios-educativo
============================================================ */

router.post(
  "/",
  verifyToken,
  registrarUsuarioEducativo
);


/* ============================================================
   LISTAR USUARIOS EDUCATIVOS

   GET
   /api/usuarios-educativo
============================================================ */

router.get(
  "/",
  verifyToken,
  listarUsuariosEducativo
);


export default router;