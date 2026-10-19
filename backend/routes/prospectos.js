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
  verifyToken
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
  registrarProspecto
);

// ==================================================
// LISTAR PROSPECTOS ACTIVOS
// GET /api/prospectos
// ==================================================

router.get(
  "/",
  verifyToken,
  listarProspectos
);

// ==================================================
// SEGUIMIENTO DEL PROSPECTO
// ==================================================

router.get(
  "/:id/seguimiento",
  verifyToken,
  listarSeguimientoProspecto
);

router.post(
  "/:id/seguimiento",
  verifyToken,
  registrarSeguimientoProspecto
);

// ==================================================
// ENTREVISTAS DEL PROSPECTO
// ==================================================

router.get(
  "/:id/entrevistas",
  verifyToken,
  listarEntrevistasProspecto
);

router.post(
  "/:id/entrevistas",
  verifyToken,
  registrarEntrevistaProspecto
);

router.put(
  "/:id/entrevistas/:idEntrevista",
  verifyToken,
  actualizarEntrevistaProspecto
);

// ==================================================
// VIDEOLLAMADA RH DE UNA ENTREVISTA
// ==================================================

router.post(
  "/:id/entrevistas/:idEntrevista/videollamada",
  verifyToken,
  crearVideollamadaEntrevistaProspecto
);

// ==================================================
// PRUEBAS PSICOMÉTRICAS DEL PROSPECTO
// ==================================================

router.get(
  "/:id/pruebas/disponibles",
  verifyToken,
  listarPruebasDisponiblesProspecto
);

router.post(
  "/:id/pruebas/habilitar",
  verifyToken,
  habilitarPruebaProspecto
);

router.get(
  "/:id/pruebas/resultados",
  verifyToken,
  obtenerResultadosPruebasProspecto
);

router.get(
  "/:id/pruebas",
  verifyToken,
  listarPruebasProspecto
);

// ==================================================
// OBSERVACIONES RH DEL PROSPECTO
// ==================================================

router.get(
  "/:id/observaciones",
  verifyToken,
  listarObservacionesProspecto
);

router.post(
  "/:id/observaciones",
  verifyToken,
  registrarObservacionProspecto
);

router.put(
  "/:id/observaciones/:idObservacion",
  verifyToken,
  actualizarObservacionProspecto
);

router.delete(
  "/:id/observaciones/:idObservacion",
  verifyToken,
  eliminarObservacionProspecto
);

// ==================================================
// REPORTES / PREANÁLISIS IA RH
// ==================================================

router.post(
  "/:id/reporte-ia",
  verifyToken,
  generarReporteIAProspecto
);

router.get(
  "/:id/reportes-ia",
  verifyToken,
  listarReportesIAProspecto
);

router.get(
  "/:id/reportes-ia/:idReporte",
  verifyToken,
  obtenerReporteIAProspecto
);

// ==================================================
// DECISIÓN RH
// ==================================================

router.get(
  "/:id/decision",
  verifyToken,
  obtenerDecisionProspecto
);

router.post(
  "/:id/decision",
  verifyToken,
  registrarDecisionProspecto
);

// ==================================================
// OBTENER UN PROSPECTO
// ESTA RUTA DEBE QUEDAR AL FINAL
// ==================================================

router.get(
  "/:id",
  verifyToken,
  obtenerProspecto
);

export default router;