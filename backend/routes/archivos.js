// backend/routes/archivos.js

import express from "express";

import {
  subirArchivo,
  obtenerArchivosSesion,
  eliminarArchivo,
  transcribirArchivo
} from "../controllers/archivosController.js";

import { verifyToken,
  verificarSuscripcionOrganizacion
} from "../middlewares/authMiddleware.js";
import { uploadMultimedia } from "../config/multer.js";

const router = express.Router();

/* ==================================================
   SUBIR ARCHIVO MULTIMEDIA
================================================== */
router.post(
  "/",
  verifyToken,
  verificarSuscripcionOrganizacion,
  uploadMultimedia.single("file"),
  subirArchivo
);

/* ==================================================
   OBTENER ARCHIVOS DE UNA SESIÓN
================================================== */
router.get(
  "/sesion/:id_sesion",
  verifyToken,
  verificarSuscripcionOrganizacion,
  obtenerArchivosSesion
);

/* ==================================================
   TRANSCRIBIR AUDIO
================================================== */
router.post(
  "/:id/transcribir",
  verifyToken,
  verificarSuscripcionOrganizacion,
  transcribirArchivo
);

/* ==================================================
   ELIMINAR ARCHIVO
================================================== */
router.delete(
  "/:id",
  verifyToken,
  verificarSuscripcionOrganizacion,
  eliminarArchivo
);

export default router;
