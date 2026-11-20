import express from "express";

import {
  registrarProspecto,
  listarProspectos,
  obtenerProspecto
} from "../controllers/prospectoController.js";

import {
  registrarSeguimientoProspecto,
  listarSeguimientoProspecto
} from "../controllers/seguimientoProspectoController.js";

import {
  registrarEntrevistaProspecto,
  listarEntrevistasProspecto,
  actualizarEntrevistaProspecto,
  crearVideollamadaEntrevistaProspecto
} from "../controllers/entrevistaProspectoController.js";

import {
  listarPruebasDisponiblesProspecto,
  habilitarPruebaProspecto,
  listarPruebasProspecto,
  obtenerResultadosPruebasProspecto,
  obtenerPruebaPublicaProspecto,
  guardarRespuestasPruebaProspecto,
  finalizarPruebaProspecto
} from "../controllers/pruebaProspectoController.js";

import {
  registrarObservacionProspecto,
  listarObservacionesProspecto,
  actualizarObservacionProspecto,
  eliminarObservacionProspecto
} from "../controllers/observacionProspectoController.js";

import {
  generarReporteIAProspecto,
  listarReportesIAProspecto,
  obtenerReporteIAProspecto
} from "../controllers/reporteIAProspectoController.js";

import {
  registrarDecisionProspecto,
  obtenerDecisionProspecto
} from "../controllers/decisionProspectoController.js";

import {
  verifyToken,
  verificarSuscripcionOrganizacion
} from "../middlewares/authMiddleware.js";

const router =
  express.Router();

// ==================================================
// PRUEBAS PÚBLICAS DEL PROSPECTO
// SIN LOGIN
// ==================================================

router.get(
  "/prueba-publica/:token",
  obtenerPruebaPublicaProspecto
);

router.post(
  "/prueba-publica/:token/respuestas",
  guardarRespuestasPruebaProspecto
);

router.post(
  "/prueba-publica/:token/finalizar",
  finalizarPruebaProspecto
);

// ==================================================
// REGISTRAR PROSPECTO
// POST /api/prospectos
// ==================================================

router.post(
  "/",
  verifyToken,
  verificarSuscripcionOrganizacion,
  registrarProspecto
);

// ==================================================
// LISTAR PROSPECTOS ACTIVOS
// GET /api/prospectos
// ==================================================

router.get(
  "/",
  verifyToken,
  verificarSuscripcionOrganizacion,
  listarProspectos
);

// ==================================================
// SEGUIMIENTO DEL PROSPECTO
// ==================================================

router.get(
  "/:id/seguimiento",
  verifyToken,
  verificarSuscripcionOrganizacion,
  listarSeguimientoProspecto
);

router.post(
  "/:id/seguimiento",
  verifyToken,
  verificarSuscripcionOrganizacion,
  registrarSeguimientoProspecto
);

// ==================================================
// ENTREVISTAS DEL PROSPECTO
// ==================================================

router.get(
  "/:id/entrevistas",
  verifyToken,
  verificarSuscripcionOrganizacion,
  listarEntrevistasProspecto
);

router.post(
  "/:id/entrevistas",
  verifyToken,
  verificarSuscripcionOrganizacion,
  registrarEntrevistaProspecto
);

router.put(
  "/:id/entrevistas/:idEntrevista",
  verifyToken,
  verificarSuscripcionOrganizacion,
  actualizarEntrevistaProspecto
);

// ==================================================
// VIDEOLLAMADA RH DE UNA ENTREVISTA
// ==================================================

router.post(
  "/:id/entrevistas/:idEntrevista/videollamada",
  verifyToken,
  verificarSuscripcionOrganizacion,
  crearVideollamadaEntrevistaProspecto
);

// ==================================================
// PRUEBAS PSICOMÉTRICAS DEL PROSPECTO
// ==================================================

router.get(
  "/:id/pruebas/disponibles",
  verifyToken,
  verificarSuscripcionOrganizacion,
  listarPruebasDisponiblesProspecto
);

router.post(
  "/:id/pruebas/habilitar",
  verifyToken,
  verificarSuscripcionOrganizacion,
  habilitarPruebaProspecto
);

router.get(
  "/:id/pruebas/resultados",
  verifyToken,
  verificarSuscripcionOrganizacion,
  obtenerResultadosPruebasProspecto
);

router.get(
  "/:id/pruebas",
  verifyToken,
  verificarSuscripcionOrganizacion,
  listarPruebasProspecto
);

// ==================================================
// OBSERVACIONES RH DEL PROSPECTO
// ==================================================

router.get(
  "/:id/observaciones",
  verifyToken,
  verificarSuscripcionOrganizacion,
  listarObservacionesProspecto
);

router.post(
  "/:id/observaciones",
  verifyToken,
  verificarSuscripcionOrganizacion,
  registrarObservacionProspecto
);

router.put(
  "/:id/observaciones/:idObservacion",
  verifyToken,
  verificarSuscripcionOrganizacion,
  actualizarObservacionProspecto
);

router.delete(
  "/:id/observaciones/:idObservacion",
  verifyToken,
  verificarSuscripcionOrganizacion,
  eliminarObservacionProspecto
);

// ==================================================
// REPORTES / PREANÁLISIS IA RH
// ==================================================

router.post(
  "/:id/reporte-ia",
  verifyToken,
  verificarSuscripcionOrganizacion,
  generarReporteIAProspecto
);

router.get(
  "/:id/reportes-ia",
  verifyToken,
  verificarSuscripcionOrganizacion,
  listarReportesIAProspecto
);

router.get(
  "/:id/reportes-ia/:idReporte",
  verifyToken,
  verificarSuscripcionOrganizacion,
  obtenerReporteIAProspecto
);

// ==================================================
// DECISIÓN RH
// ==================================================

router.get(
  "/:id/decision",
  verifyToken,
  verificarSuscripcionOrganizacion,
  obtenerDecisionProspecto
);

router.post(
  "/:id/decision",
  verifyToken,
  verificarSuscripcionOrganizacion,
  registrarDecisionProspecto
);

// ==================================================
// OBTENER UN PROSPECTO
// ESTA RUTA DEBE QUEDAR AL FINAL
// ==================================================

router.get(
  "/:id",
  verifyToken,
  verificarSuscripcionOrganizacion,
  obtenerProspecto
);

export default router;
