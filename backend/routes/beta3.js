import express from "express";

import {
  verificarClavesBeta3,
  obtenerBeta3Publica,
  guardarRespuestasBeta3,
  finalizarBeta3,
  obtenerResultadoBeta3,
  obtenerRespuestasBeta3
} from "../controllers/beta3Controller.js";

const router =
  express.Router();

router.get(
  "/estado-claves",
  verificarClavesBeta3
);

router.get(
  "/publica/:token",
  obtenerBeta3Publica
);

router.post(
  "/publica/:token/respuestas",
  guardarRespuestasBeta3
);

router.post(
  "/publica/:token/finalizar",
  finalizarBeta3
);

router.get(
  "/resultado/:id_habilitacion",
  obtenerResultadoBeta3
);

router.get(
  "/respuestas/:id_habilitacion",
  obtenerRespuestasBeta3
);

export default router;