// backend/routes/psicologos.js

import express from "express";

import {
  listarPsicologos
} from "../controllers/psicologoController.js";

import { verifyToken } from "../middlewares/authMiddleware.js";


const router = express.Router();


/* ==================================================
   LISTAR PSICÓLOGOS
   Solo administradores
================================================== */

router.get(
  "/",
  verifyToken,
  listarPsicologos
);


export default router;