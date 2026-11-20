// ==================================================
// backend/routes/backups.js
// ==================================================

import express
from "express";

import {
  verifyToken
} from "../middlewares/authMiddleware.js";

import {
  obtenerBackups,
  crearBackupManual,
  descargarBackup,
  estadoBackups
} from "../controllers/backupController.js";


const router =
  express.Router();


// ==================================================
// TODAS REQUIEREN LOGIN
// ==================================================

router.use(
  verifyToken
);


// ==================================================
// ESTADO
// GET /api/backups/status
// ==================================================

router.get(
  "/status",
  estadoBackups
);


// ==================================================
// LISTAR
// GET /api/backups
// ==================================================

router.get(
  "/",
  obtenerBackups
);


// ==================================================
// CREAR MANUAL
// POST /api/backups
// ==================================================

router.post(
  "/",
  crearBackupManual
);


// ==================================================
// DESCARGAR
// GET /api/backups/:nombre/download
// ==================================================

router.get(
  "/:nombre/download",
  descargarBackup
);


export default router;