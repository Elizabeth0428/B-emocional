import express from "express";

import {
  registerPsicologo,
  login,
  changePassword,
} from "../controllers/authController.js";

import { verifyToken } from "../middlewares/authMiddleware.js";

const router = express.Router();


/* ==================================================
   Registro de psicólogo
================================================== */

router.post(
  "/psicologos/register",
  verifyToken,
  registerPsicologo
);


/* ==================================================
   Login
================================================== */

router.post(
  "/login",
  login
);


/* ==================================================
   Cambiar contraseña
================================================== */

router.put(
  "/change-password",
  verifyToken,
  changePassword
);


export default router;