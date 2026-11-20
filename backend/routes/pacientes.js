import express from "express";

import {
  listarPacientes,
  obtenerPaciente,
  registrarPaciente,
  obtenerReportesCompletos
} from "../controllers/pacienteController.js";

import { verifyToken,
  verificarSuscripcionOrganizacion
} from "../middlewares/authMiddleware.js";

const router = express.Router();

/* Reportes completos — ANTES de /:id */
router.get(
  "/:id/reportes-completos",
  verifyToken,
  verificarSuscripcionOrganizacion,
  obtenerReportesCompletos
);

/* Listar pacientes */
router.get(
  "/",
  verifyToken,
  verificarSuscripcionOrganizacion,
  listarPacientes
);

/* Obtener paciente */
router.get(
  "/:id",
  verifyToken,
  verificarSuscripcionOrganizacion,
  obtenerPaciente
);

/* Registrar paciente */
router.post(
  "/",
  verifyToken,
  verificarSuscripcionOrganizacion,
  registrarPaciente
);

export default router;
