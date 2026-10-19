import express from "express";

import {
  guardarRespuestasRaven,
  finalizarRaven,
  obtenerReactivosRaven,
  obtenerReactivosRavenPublico,
  obtenerResultadoRaven,
  obtenerRespuestasRaven
} from "../controllers/ravenController.js";

const router =
  express.Router();

// ==================================================
// PRUEBA TÉCNICA DEL CATÁLOGO
// ==================================================

router.get(
  "/reactivos",
  obtenerReactivosRaven
);

// ==================================================
// RAVEN PÚBLICO RH
// ==================================================

router.get(
  "/publico/:token/reactivos",
  obtenerReactivosRavenPublico
);

router.post(
  "/publico/:token/respuestas",
  guardarRespuestasRaven
);

router.post(
  "/publico/:token/finalizar",
  finalizarRaven
);

// ==================================================
// CONSULTAS INTERNAS
// ==================================================

router.get(
  "/resultado/:id_habilitacion",
  obtenerResultadoRaven
);

router.get(
  "/respuestas/:id_habilitacion",
  obtenerRespuestasRaven
);

export default router;