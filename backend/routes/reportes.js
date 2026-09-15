import express from "express";

import {
    generarPDF,
    obtenerReportesPaciente
} from "../controllers/reporteController.js";

const router = express.Router();


/* ==================================================
   OBTENER REPORTES DE UN PACIENTE
   GET /api/reportes/paciente/:id
================================================== */

router.get(
    "/paciente/:id",
    obtenerReportesPaciente
);


/* ==================================================
   GENERAR PDF
   GET /api/reportes/:id/pdf
================================================== */

router.get(
    "/:id/pdf",
    generarPDF
);


export default router;