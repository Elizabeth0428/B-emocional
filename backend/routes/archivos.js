// backend/routes/archivos.js

import express from "express";

import {
  subirArchivo,
  obtenerArchivosSesion,
  eliminarArchivo
} from "../controllers/archivosController.js";

import { verifyToken } from "../middlewares/authMiddleware.js";

import { uploadMultimedia } from "../config/multer.js";


const router = express.Router();


/* ==================================================
   SUBIR ARCHIVO MULTIMEDIA
================================================== */

router.post(
  "/",
  verifyToken,
  uploadMultimedia.single("file"),
  subirArchivo
);


/* ==================================================
   OBTENER ARCHIVOS DE UNA SESIÓN
================================================== */

router.get(
  "/sesion/:id_sesion",
  verifyToken,
  obtenerArchivosSesion
);


/* ==================================================
   ELIMINAR ARCHIVO
================================================== */

router.delete(
  "/:id",
  verifyToken,
  eliminarArchivo
);


export default router;