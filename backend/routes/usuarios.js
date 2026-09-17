// backend/routes/usuarios.js

import express from "express";

import {
  registrarUsuarioRH,
  listarUsuariosRH
} from "../controllers/usuarioController.js";

import {
  verifyToken
} from "../middlewares/authMiddleware.js";


const router = express.Router();


/* ==================================================
   REGISTRAR USUARIO RH
================================================== */

router.post(
  "/rh/register",
  verifyToken,
  registrarUsuarioRH
);


/* ==================================================
   LISTAR USUARIOS RH
================================================== */

router.get(
  "/rh",
  verifyToken,
  listarUsuariosRH
);


export default router;