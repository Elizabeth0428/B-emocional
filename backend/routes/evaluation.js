// backend/routes/evaluation.js

import express from "express";

import {

  obtenerPruebas,

  habilitarPrueba,

  obtenerPruebasHabilitadas,

  obtenerPreguntasPrueba,

  finalizarPrueba,

  finalizarPruebaPublica,

  guardarRespuestas,

  guardarRespuestasPublicas,

  obtenerPruebaPorHabilitacion,

  obtenerResultadosPaciente,

  evaluateTests

} from "../controllers/evaluationController.js";

import {
  verifyToken
} from "../middlewares/authMiddleware.js";


const router = express.Router();


// ==================================================
// OBTENER TODAS LAS PRUEBAS
//
// GET /api/evaluation/pruebas
// ==================================================

router.get(

  "/pruebas",

  verifyToken,

  obtenerPruebas

);


// ==================================================
// HABILITAR PRUEBA
//
// POST /api/evaluation/pruebas/habilitar
// ==================================================

router.post(

  "/pruebas/habilitar",

  verifyToken,

  habilitarPrueba

);


// ==================================================
// PRUEBAS HABILITADAS DE UN PACIENTE
//
// GET /api/evaluation/pruebas/habilitadas/:id_paciente
// ==================================================

router.get(

  "/pruebas/habilitadas/:id_paciente",

  verifyToken,

  obtenerPruebasHabilitadas

);


// ==================================================
// OBTENER RESULTADOS DE UN PACIENTE
//
// GET /api/evaluation/resultados/:id_paciente
// ==================================================

router.get(

  "/resultados/:id_paciente",

  verifyToken,

  obtenerResultadosPaciente

);


// ==================================================
// PREGUNTAS DE UNA PRUEBA
//
// GET /api/evaluation/pruebas/:id/preguntas
// ==================================================

router.get(

  "/pruebas/:id/preguntas",

  verifyToken,

  obtenerPreguntasPrueba

);


// ==================================================
// FINALIZAR PRUEBA
//
// POST /api/evaluation/pruebas/:id/finalizar
// ==================================================

router.post(

  "/pruebas/:id/finalizar",

  verifyToken,

  finalizarPrueba

);


// ==================================================
// FINALIZAR PRUEBA PÚBLICA
//
// POST /api/evaluation/pruebas/:id/finalizar/publico
// ==================================================

router.post(

  "/pruebas/:id/finalizar/publico",

  finalizarPruebaPublica

);


// ==================================================
// GUARDAR RESPUESTAS
//
// POST /api/evaluation/respuestas
// ==================================================

router.post(

  "/respuestas",

  verifyToken,

  guardarRespuestas

);


// ==================================================
// GUARDAR RESPUESTAS PÚBLICAS
//
// POST /api/evaluation/respuestas/publico
// ==================================================

router.post(

  "/respuestas/publico",

  guardarRespuestasPublicas

);


// ==================================================
// OBTENER PRUEBA POR HABILITACIÓN
//
// GET /api/evaluation/pruebas/habilitacion/:id_habilitacion
//
// Ruta pública
// ==================================================

router.get(

  "/pruebas/habilitacion/:id_habilitacion",

  obtenerPruebaPorHabilitacion

);


// ==================================================
// EVALUAR TESTS
//
// POST /api/evaluation/evaluateTests
// ==================================================

router.post(

  "/evaluateTests",

  evaluateTests

);


export default router;