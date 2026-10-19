import express from "express";

import {
  listarEmpleados,
  obtenerEmpleado,
  actualizarEmpleado
} from "../controllers/empleadoController.js";

import {
  registrarSeguimientoEmpleado,
  listarSeguimientoEmpleado,
  actualizarSeguimientoEmpleado,
  eliminarSeguimientoEmpleado
} from "../controllers/seguimientoEmpleadoController.js";

import {
  listarPruebasDisponiblesEmpleado,
  habilitarPruebaEmpleado,
  listarPruebasEmpleado,
  obtenerResultadosPruebasEmpleado,
  obtenerPruebaPublicaEmpleado,
  guardarRespuestasPruebaEmpleado,
  finalizarPruebaEmpleado,
  cancelarPruebaEmpleado
} from "../controllers/pruebaEmpleadoController.js";

import {
  obtenerPanelBienestarEmpleado,
  listarAccionesPreventivasEmpleado,
  registrarAccionPreventivaEmpleado,
  actualizarAccionPreventivaEmpleado,
  eliminarAccionPreventivaEmpleado
} from "../controllers/bienestarEmpleadoController.js";

import {
  listarCuestionariosNom035,
  habilitarNom035Empleado,
  listarAplicacionesNom035Empleado,
  obtenerNom035Publica,
  guardarRespuestasNom035,
  finalizarNom035,
  cancelarNom035Empleado,
  obtenerResultadosNom035Empleado
} from "../controllers/nom035EmpleadoController.js";

import {
  verifyToken
} from "../middlewares/authMiddleware.js";


const router =
  express.Router();


// ==================================================
// EVALUACIONES RH PÚBLICAS DEL EMPLEADO
// SIN LOGIN
// ==================================================

// GET
// /api/empleados/evaluacion-publica/:token
router.get(
  "/evaluacion-publica/:token",
  obtenerPruebaPublicaEmpleado
);


// POST
// /api/empleados/evaluacion-publica/:token/respuestas
router.post(
  "/evaluacion-publica/:token/respuestas",
  guardarRespuestasPruebaEmpleado
);


// POST
// /api/empleados/evaluacion-publica/:token/finalizar
router.post(
  "/evaluacion-publica/:token/finalizar",
  finalizarPruebaEmpleado
);


// ==================================================
// NOM-035 PÚBLICA
// SIN LOGIN
// IMPORTANTE:
// ESTAS RUTAS VAN ANTES DE /:id
// ==================================================

// GET
// /api/empleados/nom035-publica/:token
router.get(
  "/nom035-publica/:token",
  obtenerNom035Publica
);


// POST
// /api/empleados/nom035-publica/:token/respuestas
router.post(
  "/nom035-publica/:token/respuestas",
  guardarRespuestasNom035
);


// POST
// /api/empleados/nom035-publica/:token/finalizar
router.post(
  "/nom035-publica/:token/finalizar",
  finalizarNom035
);


// ==================================================
// LISTAR EMPLEADOS
//
// GET /api/empleados
// ==================================================

router.get(
  "/",
  verifyToken,
  listarEmpleados
);


// ==================================================
// SEGUIMIENTO LABORAL
// ==================================================

// GET
// /api/empleados/:id/seguimiento
router.get(
  "/:id/seguimiento",
  verifyToken,
  listarSeguimientoEmpleado
);


// POST
// /api/empleados/:id/seguimiento
router.post(
  "/:id/seguimiento",
  verifyToken,
  registrarSeguimientoEmpleado
);


// PUT
// /api/empleados/:id/seguimiento/:idSeguimiento
router.put(
  "/:id/seguimiento/:idSeguimiento",
  verifyToken,
  actualizarSeguimientoEmpleado
);


// DELETE
// /api/empleados/:id/seguimiento/:idSeguimiento
router.delete(
  "/:id/seguimiento/:idSeguimiento",
  verifyToken,
  eliminarSeguimientoEmpleado
);


// ==================================================
// EVALUACIONES PERIÓDICAS DEL EMPLEADO
// ==================================================

// GET
// /api/empleados/:id/evaluaciones/disponibles
router.get(
  "/:id/evaluaciones/disponibles",
  verifyToken,
  listarPruebasDisponiblesEmpleado
);


// POST
// /api/empleados/:id/evaluaciones/habilitar
router.post(
  "/:id/evaluaciones/habilitar",
  verifyToken,
  habilitarPruebaEmpleado
);


// GET
// /api/empleados/:id/evaluaciones/resultados
router.get(
  "/:id/evaluaciones/resultados",
  verifyToken,
  obtenerResultadosPruebasEmpleado
);


// PUT
// /api/empleados/:id/evaluaciones/:idHabilitacion/cancelar
router.put(
  "/:id/evaluaciones/:idHabilitacion/cancelar",
  verifyToken,
  cancelarPruebaEmpleado
);


// GET
// /api/empleados/:id/evaluaciones
router.get(
  "/:id/evaluaciones",
  verifyToken,
  listarPruebasEmpleado
);


// ==================================================
// BIENESTAR Y PREVENCIÓN
// ==================================================

// GET
// /api/empleados/:id/bienestar
router.get(
  "/:id/bienestar",
  verifyToken,
  obtenerPanelBienestarEmpleado
);


// GET
// /api/empleados/:id/bienestar/acciones
router.get(
  "/:id/bienestar/acciones",
  verifyToken,
  listarAccionesPreventivasEmpleado
);


// POST
// /api/empleados/:id/bienestar/acciones
router.post(
  "/:id/bienestar/acciones",
  verifyToken,
  registrarAccionPreventivaEmpleado
);


// PUT
// /api/empleados/:id/bienestar/acciones/:idAccion
router.put(
  "/:id/bienestar/acciones/:idAccion",
  verifyToken,
  actualizarAccionPreventivaEmpleado
);


// DELETE
// /api/empleados/:id/bienestar/acciones/:idAccion
router.delete(
  "/:id/bienestar/acciones/:idAccion",
  verifyToken,
  eliminarAccionPreventivaEmpleado
);


// ==================================================
// NOM-035
// ==================================================

// GET
// /api/empleados/:id/nom035/cuestionarios
router.get(
  "/:id/nom035/cuestionarios",
  verifyToken,
  listarCuestionariosNom035
);


// POST
// /api/empleados/:id/nom035/habilitar
router.post(
  "/:id/nom035/habilitar",
  verifyToken,
  habilitarNom035Empleado
);


// GET
// /api/empleados/:id/nom035/resultados
router.get(
  "/:id/nom035/resultados",
  verifyToken,
  obtenerResultadosNom035Empleado
);


// PUT
// /api/empleados/:id/nom035/:idAplicacion/cancelar
router.put(
  "/:id/nom035/:idAplicacion/cancelar",
  verifyToken,
  cancelarNom035Empleado
);


// GET
// /api/empleados/:id/nom035
router.get(
  "/:id/nom035",
  verifyToken,
  listarAplicacionesNom035Empleado
);


// ==================================================
// OBTENER EMPLEADO
//
// GET /api/empleados/:id
// ==================================================

router.get(
  "/:id",
  verifyToken,
  obtenerEmpleado
);


// ==================================================
// ACTUALIZAR INFORMACIÓN LABORAL
//
// PUT /api/empleados/:id
// ==================================================

router.put(
  "/:id",
  verifyToken,
  actualizarEmpleado
);


export default router;