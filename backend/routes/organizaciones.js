// backend/routes/organizaciones.js

import express from "express";

import { verifyToken } from "../middlewares/authMiddleware.js";

import {
  crearOrganizacion,
  listarOrganizaciones,
  obtenerOrganizacion,
  obtenerEstadoLicencias,
  activarSuscripcion,
  renovarSuscripcion,
  ajustarLicenciasOrganizacion,
  otorgarBeneficioMaster,
  marcarSuscripcionesVencidas
} from "../controllers/organizacionController.js";


const router = express.Router();


// ==================================================
// TODAS LAS RUTAS SON PRIVADAS
// ==================================================

router.use(
  verifyToken
);


// ==================================================
// RUTAS GENERALES
// ==================================================


// GET
// /api/organizaciones
router.get(
  "/",
  listarOrganizaciones
);


// POST
// /api/organizaciones
router.post(
  "/",
  crearOrganizacion
);


// ==================================================
// VENCIMIENTOS
// DEBE IR ANTES DE /:id
// ==================================================


// POST
// /api/organizaciones/suscripciones/revisar-vencidas
router.post(
  "/suscripciones/revisar-vencidas",
  marcarSuscripcionesVencidas
);


// ==================================================
// ORGANIZACIÓN ESPECÍFICA
// ==================================================


// GET
// /api/organizaciones/:id
router.get(
  "/:id",
  obtenerOrganizacion
);


// ==================================================
// LICENCIAS
// ==================================================


// GET
// /api/organizaciones/:id/licencias
router.get(
  "/:id/licencias",
  obtenerEstadoLicencias
);

// PATCH
// /api/organizaciones/:id/licencias
router.patch(
  "/:id/licencias",
  ajustarLicenciasOrganizacion
);

// ==================================================
// SUSCRIPCIÓN
// ==================================================


// PATCH
// /api/organizaciones/:id/suscripcion/activar
router.patch(
  "/:id/suscripcion/activar",
  activarSuscripcion
);


// PATCH
// /api/organizaciones/:id/suscripcion/renovar
router.patch(
  "/:id/suscripcion/renovar",
  renovarSuscripcion
);

// ==================================================
// BENEFICIOS MASTER
// ==================================================

// POST
// /api/organizaciones/:id/beneficio
router.post(
  "/:id/beneficio",
  otorgarBeneficioMaster
);

export default router;