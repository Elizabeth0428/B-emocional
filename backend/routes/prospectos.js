import express from "express";
import {
  registrarProspecto,
  listarProspectos,
  obtenerProspecto
} from "../controllers/prospectoController.js";

import { verifyToken } from "../middlewares/authMiddleware.js";

const router = express.Router();

router.post(
  "/",
  verifyToken,
  registrarProspecto
);

router.get(
  "/",
  verifyToken,
  listarProspectos
);

router.get(
  "/:id",
  verifyToken,
  obtenerProspecto
);

export default router;