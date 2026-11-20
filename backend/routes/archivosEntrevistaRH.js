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
  verifyToken,
  verificarSuscripcionOrganizacion
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
  verificarSuscripcionOrganizacion,
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
  verificarSuscripcionOrganizacion,
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
  verificarSuscripcionOrganizacion,
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
  verificarSuscripcionOrganizacion,
  eliminarArchivoEntrevistaRH
);


export default router;
