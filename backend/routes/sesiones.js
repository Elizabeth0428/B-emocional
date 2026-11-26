// backend/routes/sesionRoutes.js

import express from "express";

import {
  obtenerSesionesPaciente,
  crearSesion,
  iniciarVideollamadaPaciente,
  finalizarSesion,
  generarLinkVideollamada,
  cancelarSesion
} from "../controllers/sesionController.js";

import { verifyToken,
  verificarSuscripcionOrganizacion
} from "../middlewares/authMiddleware.js";

const router = express.Router();


// ==================================================
// SESIONES DE UN PACIENTE
// ==================================================

router.get(
  "/paciente/:id_paciente",
  verifyToken,
  verificarSuscripcionOrganizacion,
  obtenerSesionesPaciente
);


// ==================================================
// CREAR SESIÓN MANUAL
// ==================================================

router.post(
  "/",
  verifyToken,
  verificarSuscripcionOrganizacion,
  crearSesion
);


// ==================================================
// INICIAR / RECUPERAR VIDEOLLAMADA
// ==================================================
//
// FLUJO PRINCIPAL:
//
// Expediente
//     ↓
// SalaVideollamada/nueva/:idPaciente
//     ↓
// POST /api/sesiones/iniciar/:idPaciente
//     ↓
// iniciarVideollamadaPaciente()
//
// El backend:
//
// 1. valida paciente
// 2. busca sesión activa
// 3. reutiliza la sesión si existe
// 4. crea sesión si no existe
// 5. reutiliza la sala si existe
// 6. crea sala si no existe
// 7. devuelve link del psicólogo
// 8. devuelve link del paciente
//
// ==================================================

router.post(
  "/iniciar/:id_paciente",
  verifyToken,
  verificarSuscripcionOrganizacion,
  iniciarVideollamadaPaciente
);


// ==================================================
// FINALIZAR SESIÓN
// ==================================================

router.put(
  "/:id/finalizar",
  verifyToken,
  verificarSuscripcionOrganizacion,
  finalizarSesion
);

// ==================================================
// CANCELAR SESIÓN
// ==================================================

router.put(
  "/:id/cancelar",
  verifyToken,
  cancelarSesion
);


// ==================================================
// GENERAR / RECUPERAR LINK DE VIDEOLLAMADA
// ==================================================
//
// Esta ruta se conserva para compatibilidad.
//
// Si la sesión ya tiene sala:
//      la reutiliza.
//
// Si no tiene sala:
//      crea una.
//
// ==================================================

router.post(
  "/:id/videollamada",
  verifyToken,
  verificarSuscripcionOrganizacion,
  generarLinkVideollamada
);


export default router;
