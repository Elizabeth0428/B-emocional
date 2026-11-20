// ==================================================
// backend/routes/psicologoEstadoRoutes.js
// ==================================================

import express
from "express";

import {
  verifyToken
} from "../middlewares/authMiddleware.js";

import {
  desactivarPsicologo,
  reactivarPsicologo
} from "../controllers/psicologoEstadoController.js";


const router =
  express.Router();


// ==================================================
// TODAS REQUIEREN LOGIN
// ==================================================

router.use(
  verifyToken
);


// ==================================================
// DESACTIVAR PSICÓLOGO
//
// PATCH
// /api/psicologos/:id/desactivar
// ==================================================

router.patch(
  "/:id/desactivar",
  desactivarPsicologo
);


// ==================================================
// REACTIVAR PSICÓLOGO
//
// PATCH
// /api/psicologos/:id/reactivar
// ==================================================

router.patch(
  "/:id/reactivar",
  reactivarPsicologo
);


export default router;