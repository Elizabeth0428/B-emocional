import express from "express";

import {
  verifyToken,
  verificarSuscripcionOrganizacion
} from "../middlewares/authMiddleware.js";

import {
  listarDestinosPaciente,
  transferirPaciente,
  obtenerHistorialPaciente,
  listarDestinosEmpleado,
  transferirEmpleado,
  obtenerHistorialEmpleado
} from "../controllers/transferenciaController.js";

const router =
  express.Router();

// ==================================================
// PACIENTES / CLÍNICA
// ==================================================

router.get(
  "/pacientes/:id/destinos",
  verifyToken,
  verificarSuscripcionOrganizacion,
  listarDestinosPaciente
);

router.post(
  "/pacientes/:id",
  verifyToken,
  verificarSuscripcionOrganizacion,
  transferirPaciente
);

router.get(
  "/pacientes/:id/historial",
  verifyToken,
  verificarSuscripcionOrganizacion,
  obtenerHistorialPaciente
);

// ==================================================
// EMPLEADOS / RH
// ==================================================

router.get(
  "/empleados/:id/destinos",
  verifyToken,
  verificarSuscripcionOrganizacion,
  listarDestinosEmpleado
);

router.post(
  "/empleados/:id",
  verifyToken,
  verificarSuscripcionOrganizacion,
  transferirEmpleado
);

router.get(
  "/empleados/:id/historial",
  verifyToken,
  verificarSuscripcionOrganizacion,
  obtenerHistorialEmpleado
);

export default router;
