// backend/routes/notas.js

import express from "express";

import {
  crearNota,
  obtenerNotasSesion
} from "../controllers/notasController.js";

import { verifyToken } from "../middlewares/authMiddleware.js";


const router = express.Router();


/* ==================================================
   CREAR NOTA / CHAT MANUAL DE SESIÓN
================================================== */

router.post(
  "/",
  verifyToken,
  crearNota
);


/* ==================================================
   OBTENER NOTAS DE UNA SESIÓN
================================================== */

router.get(
  "/sesion/:id_sesion",
  verifyToken,
  obtenerNotasSesion
);


export default router;