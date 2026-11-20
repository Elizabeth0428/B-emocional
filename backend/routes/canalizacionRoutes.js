import express from "express";

import { verifyToken,
  verificarSuscripcionOrganizacion
} from "../middlewares/authMiddleware.js";

import {
  listarCanalizacionesEmpleado,
  obtenerCanalizacionEmpleado,
  crearCanalizacion,

  // RECOMENDACIONES DEL SISTEMA
  listarRecomendacionesCanalizacion,
  registrarRecomendacionSistema,
  decidirRecomendacionRH,

  // PROFESIONALES / RANKING
  listarPsicologosDisponibles,
  asignarOpcionesPsicologos,
  listarAreasAtencionCanalizacion,
  actualizarCriteriosRankingCanalizacion,

  // CANALIZACIÓN PÚBLICA DEL EMPLEADO
  obtenerCanalizacionPublica,
  seleccionarPsicologoEmpleado,

  // SEGUIMIENTO / CIERRE
  registrarSeguimientoCanalizacion,
  cerrarCanalizacion,
  cancelarCanalizacion

} from "../controllers/canalizacionController.js";


const router =
  express.Router();


// ==================================================
// EMPLEADO - CANALIZACIÓN PÚBLICA
// SIN LOGIN
//
// IMPORTANTE:
// Estas rutas deben ir antes de las rutas dinámicas.
// ==================================================


// ==================================================
// CONSULTAR OPCIONES ENVIADAS POR RH
//
// GET
// /api/empleados/canalizacion-publica/:token
// ==================================================

router.get(
  "/canalizacion-publica/:token",
  obtenerCanalizacionPublica
);


// ==================================================
// EMPLEADO SELECCIONA PROFESIONAL
//
// POST
// /api/empleados/canalizacion-publica/:token/seleccionar
// ==================================================

router.post(
  "/canalizacion-publica/:token/seleccionar",
  seleccionarPsicologoEmpleado
);


// ==================================================
// RH - RECOMENDACIONES DE CANALIZACIÓN
// ==================================================


// ==================================================
// LISTAR RECOMENDACIONES DEL SISTEMA
//
// GET
// /api/empleados/:id/canalizaciones/recomendaciones
// ==================================================

router.get(
  "/:id/canalizaciones/recomendaciones",
  verifyToken,
  verificarSuscripcionOrganizacion,
  listarRecomendacionesCanalizacion
);


// ==================================================
// REGISTRAR RECOMENDACIÓN DEL SISTEMA
//
// POST
// /api/empleados/:id/canalizaciones/recomendaciones
//
// Preparada para:
//
// - NOM-035
// - estrés laboral
// - otras evaluaciones
// ==================================================

router.post(
  "/:id/canalizaciones/recomendaciones",
  verifyToken,
  verificarSuscripcionOrganizacion,
  registrarRecomendacionSistema
);


// ==================================================
// RH TOMA DECISIÓN SOBRE RECOMENDACIÓN
//
// PUT
// /api/empleados/:id/canalizaciones/
// recomendaciones/:idRecomendacion/decision
//
// decision_rh:
//
// canalizar
// seguimiento
// no_canalizar
// ==================================================

router.put(
  "/:id/canalizaciones/recomendaciones/:idRecomendacion/decision",
  verifyToken,
  verificarSuscripcionOrganizacion,
  decidirRecomendacionRH
);


// ==================================================
// RH - CATÁLOGO DE ÁREAS DE ATENCIÓN
//
// GET
// /api/empleados/:id/canalizaciones/areas-atencion
//
// Se utiliza para seleccionar las áreas requeridas
// antes de calcular el ranking.
// ==================================================

router.get(
  "/:id/canalizaciones/areas-atencion",
  verifyToken,
  verificarSuscripcionOrganizacion,
  listarAreasAtencionCanalizacion
);


// ==================================================
// RH - GUARDAR CRITERIOS DEL RANKING
//
// PUT
// /api/empleados/:id/canalizaciones/
// :idCanalizacion/criterios-ranking
//
// Guarda:
//
// - modalidad_atencion_preferida
// - areas_atencion_requeridas
// ==================================================

router.put(
  "/:id/canalizaciones/:idCanalizacion/criterios-ranking",
  verifyToken,
  verificarSuscripcionOrganizacion,
  actualizarCriteriosRankingCanalizacion
);


// ==================================================
// RH - PROFESIONALES DISPONIBLES + RANKING
//
// GET
// /api/empleados/:id/canalizaciones/
// :idCanalizacion/psicologos-disponibles
//
// IMPORTANTE:
//
// El ranking se calcula sobre una canalización concreta.
//
// La canalización aporta:
//
// - modalidad_atencion_preferida
// - areas_atencion_requeridas
//
// El empleado aporta:
//
// - sueldo
// - periodicidad_sueldo
// - estado_residencia
// - municipio_residencia
// - colonia_residencia
// - codigo_postal_residencia
//
// El profesional aporta:
//
// - áreas de atención
// - precios
// - ubicación
// - modalidad de atención
//
// RANKING:
//
// Áreas ............... 45
// Economía ............ 25
// Ubicación ........... 20
// Modalidad ........... 10
//
// TOTAL .............. 100
//
// Esta ruta debe ir antes de:
//
// /:id/canalizaciones/:idCanalizacion
// ==================================================

router.get(
  "/:id/canalizaciones/:idCanalizacion/psicologos-disponibles",
  verifyToken,
  verificarSuscripcionOrganizacion,
  listarPsicologosDisponibles
);


// ==================================================
// RH - CANALIZACIONES DEL EMPLEADO
// ==================================================


// ==================================================
// LISTAR HISTORIAL DE CANALIZACIONES
//
// GET
// /api/empleados/:id/canalizaciones
// ==================================================

router.get(
  "/:id/canalizaciones",
  verifyToken,
  verificarSuscripcionOrganizacion,
  listarCanalizacionesEmpleado
);


// ==================================================
// CREAR CANALIZACIÓN MANUAL
//
// POST
// /api/empleados/:id/canalizaciones
// ==================================================

router.post(
  "/:id/canalizaciones",
  verifyToken,
  verificarSuscripcionOrganizacion,
  crearCanalizacion
);


// ==================================================
// OBTENER DETALLE DE UNA CANALIZACIÓN
//
// GET
// /api/empleados/:id/canalizaciones/:idCanalizacion
//
// IMPORTANTE:
// Debe ir después de:
// - recomendaciones
// - areas-atencion
// - criterios-ranking
// - psicologos-disponibles
// ==================================================

router.get(
  "/:id/canalizaciones/:idCanalizacion",
  verifyToken,
  verificarSuscripcionOrganizacion,
  obtenerCanalizacionEmpleado
);


// ==================================================
// ENVIAR / ACTUALIZAR OPCIONES
//
// POST
// /api/empleados/:id/canalizaciones/
// :idCanalizacion/opciones
//
// RH selecciona de 1 a 5 profesionales.
// ==================================================

router.post(
  "/:id/canalizaciones/:idCanalizacion/opciones",
  verifyToken,
  verificarSuscripcionOrganizacion,
  asignarOpcionesPsicologos
);


// ==================================================
// REGISTRAR SEGUIMIENTO
//
// POST
// /api/empleados/:id/canalizaciones/
// :idCanalizacion/seguimientos
// ==================================================

router.post(
  "/:id/canalizaciones/:idCanalizacion/seguimientos",
  verifyToken,
  verificarSuscripcionOrganizacion,
  registrarSeguimientoCanalizacion
);


// ==================================================
// CERRAR CANALIZACIÓN
//
// PUT
// /api/empleados/:id/canalizaciones/
// :idCanalizacion/cerrar
// ==================================================

router.put(
  "/:id/canalizaciones/:idCanalizacion/cerrar",
  verifyToken,
  verificarSuscripcionOrganizacion,
  cerrarCanalizacion
);


// ==================================================
// CANCELAR CANALIZACIÓN
//
// PUT
// /api/empleados/:id/canalizaciones/
// :idCanalizacion/cancelar
// ==================================================

router.put(
  "/:id/canalizaciones/:idCanalizacion/cancelar",
  verifyToken,
  verificarSuscripcionOrganizacion,
  cancelarCanalizacion
);


export default router;
