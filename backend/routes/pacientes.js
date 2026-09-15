import express from "express";

import {
  listarPacientes,
  obtenerPaciente,
  registrarPaciente,
  obtenerReportesCompletos
} from "../controllers/pacienteController.js";

import { verifyToken } from "../middlewares/authMiddleware.js";

const router = express.Router();

/* Reportes completos — ANTES de /:id */
router.get(
  "/:id/reportes-completos",
  verifyToken,
  obtenerReportesCompletos
);

/* Listar pacientes */
router.get(
  "/",
  verifyToken,
  listarPacientes
);

/* Obtener paciente */
router.get(
  "/:id",
  verifyToken,
  obtenerPaciente
);

/* Registrar paciente */
router.post(
  "/",
  verifyToken,
  registrarPaciente
);

export default router;