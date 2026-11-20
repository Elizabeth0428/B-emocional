import express from "express";

import {
  verifyToken,
  verificarSuscripcionOrganizacion
} from "../middlewares/authMiddleware.js";

import {
  listarCuestionariosNom035,
  habilitarNom035Empleado,
  listarAplicacionesNom035Empleado,
  obtenerNom035Publica,
  guardarRespuestasNom035,
  finalizarNom035,
  cancelarNom035Empleado,
  eliminarNom035Empleado,
  obtenerResultadosNom035Empleado
} from "../controllers/nom035EmpleadoController.js";

const router = express.Router();

// ==================================================
// NOM-035
// ==================================================
//
// Este archivo se monta en server.js como:
//
// app.use(
//   "/api/empleados",
//   nom035Routes
// );
//
// Por lo tanto las rutas finales quedan:
//
// GET
// /api/empleados/:id/nom035/cuestionarios
//
// GET
// /api/empleados/:id/nom035
//
// POST
// /api/empleados/:id/nom035/habilitar
//
// GET
// /api/empleados/:id/nom035/resultados
//
// PUT
// /api/empleados/:id/nom035/:idAplicacion/cancelar
//
// PÚBLICAS:
//
// GET
// /api/empleados/nom035-publica/:token
//
// POST
// /api/empleados/nom035-publica/:token/respuestas
//
// POST
// /api/empleados/nom035-publica/:token/finalizar
//
// ==================================================


// ==================================================
// RUTAS PRIVADAS RH
// REQUIEREN TOKEN
// ==================================================


// ==================================================
// LISTAR CUESTIONARIOS NOM-035 DISPONIBLES
//
// GET
// /api/empleados/:id/nom035/cuestionarios
// ==================================================

router.get(
  "/:id/nom035/cuestionarios",
  verifyToken,
  verificarSuscripcionOrganizacion,
  listarCuestionariosNom035
);


// ==================================================
// LISTAR APLICACIONES NOM-035 DEL EMPLEADO
//
// GET
// /api/empleados/:id/nom035
// ==================================================

router.get(
  "/:id/nom035",
  verifyToken,
  verificarSuscripcionOrganizacion,
  listarAplicacionesNom035Empleado
);


// ==================================================
// HABILITAR CUESTIONARIO NOM-035
//
// POST
// /api/empleados/:id/nom035/habilitar
// ==================================================

router.post(
  "/:id/nom035/habilitar",
  verifyToken,
  verificarSuscripcionOrganizacion,
  habilitarNom035Empleado
);


// ==================================================
// OBTENER RESULTADOS NOM-035 DEL EMPLEADO
//
// GET
// /api/empleados/:id/nom035/resultados
// ==================================================

router.get(
  "/:id/nom035/resultados",
  verifyToken,
  verificarSuscripcionOrganizacion,
  obtenerResultadosNom035Empleado
);


// ==================================================
// CANCELAR APLICACIÓN NOM-035
//
// PUT
// /api/empleados/:id/nom035/:idAplicacion/cancelar
// ==================================================

router.put(
  "/:id/nom035/:idAplicacion/cancelar",
  verifyToken,
  verificarSuscripcionOrganizacion,
  cancelarNom035Empleado
);

// SOLO CANCELADAS
router.delete(
  "/:id/nom035/:idAplicacion",
  verifyToken,
  verificarSuscripcionOrganizacion,
  eliminarNom035Empleado
);
// ==================================================
// RUTAS PÚBLICAS
//
// Estas rutas NO requieren inicio de sesión.
// El empleado accede mediante token_publico.
// ==================================================


// ==================================================
// OBTENER CUESTIONARIO PÚBLICO
//
// GET
// /api/empleados/nom035-publica/:token
// ==================================================

router.get(
  "/nom035-publica/:token",
  obtenerNom035Publica
);


// ==================================================
// GUARDAR RESPUESTAS / AVANCE
//
// POST
// /api/empleados/nom035-publica/:token/respuestas
// ==================================================

router.post(
  "/nom035-publica/:token/respuestas",
  guardarRespuestasNom035
);


// ==================================================
// FINALIZAR CUESTIONARIO
//
// POST
// /api/empleados/nom035-publica/:token/finalizar
// ==================================================

router.post(
  "/nom035-publica/:token/finalizar",
  finalizarNom035
);


// ==================================================
// EXPORT
// ==================================================

export default router;
