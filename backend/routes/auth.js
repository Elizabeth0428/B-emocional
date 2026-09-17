import express from "express";

import {
  registerPsicologo,
  registerAdmin,
  login,
  changePassword,
} from "../controllers/authController.js";

import {
  verifyToken,
  isMasterAdmin
} from "../middlewares/authMiddleware.js";


const router = express.Router();


// ==================================================
// REGISTRO DE ADMINISTRADOR NORMAL
//
// SOLO ADMIN MASTER
// ==================================================

router.post(
  "/admin/register",
  verifyToken,
  isMasterAdmin,
  registerAdmin
);


// ==================================================
// REGISTRO DE PSICÓLOGO
// ==================================================

router.post(
  "/psicologos/register",
  verifyToken,
  registerPsicologo
);


// ==================================================
// LOGIN
// ==================================================

router.post(
  "/login",
  login
);


// ==================================================
// CAMBIAR CONTRASEÑA
// ==================================================

router.put(
  "/change-password",
  verifyToken,
  changePassword
);


export default router;