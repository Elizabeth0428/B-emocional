// ==================================================
// backend/routes/archivosEntrevistaRH.js
// ==================================================

import express from "express";

import {
  subirArchivoEntrevistaRH,
  obtenerArchivosEntrevistaRH,
  transcribirArchivoEntrevistaRH,
  eliminarArchivoEntrevistaRH
} from "../controllers/archivosEntrevistaRHController.js";

import {
  verifyToken
} from "../middlewares/authMiddleware.js";

import {
  uploadMultimedia
} from "../config/multer.js";


const router =
  express.Router();


// ==================================================
// SUBIR GRABACIÓN RH
// POST
// /api/archivos-rh/prospecto/:idProspecto/entrevista/:idEntrevista
// ==================================================

router.post(
  "/prospecto/:idProspecto/entrevista/:idEntrevista",
  verifyToken,
  uploadMultimedia.single("file"),
  subirArchivoEntrevistaRH
);


// ==================================================
// LISTAR GRABACIONES RH
// GET
// /api/archivos-rh/prospecto/:idProspecto/entrevista/:idEntrevista
// ==================================================

router.get(
  "/prospecto/:idProspecto/entrevista/:idEntrevista",
  verifyToken,
  obtenerArchivosEntrevistaRH
);


// ==================================================
// TRANSCRIBIR GRABACIÓN RH
// POST
// /api/archivos-rh/:id/transcribir
// ==================================================

router.post(
  "/:id/transcribir",
  verifyToken,
  transcribirArchivoEntrevistaRH
);


// ==================================================
// ELIMINAR GRABACIÓN RH
// DELETE
// /api/archivos-rh/:id
// ==================================================

router.delete(
  "/:id",
  verifyToken,
  eliminarArchivoEntrevistaRH
);


export default router;