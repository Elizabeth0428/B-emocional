// ==================================================
// backend/routes/codigoPostalRoutes.js
// ==================================================

import express from "express";

import {
  consultarCodigoPostal
} from "../controllers/codigoPostalController.js";


const router =
  express.Router();


// ==================================================
// CONSULTAR CÓDIGO POSTAL
//
// GET /api/codigos-postales/:cp
//
// Ejemplo:
// GET /api/codigos-postales/56400
//
// Esta ruta no necesita autenticación porque únicamente
// consulta información pública de códigos postales.
// ==================================================

router.get(
  "/:cp",
  consultarCodigoPostal
);


export default router;