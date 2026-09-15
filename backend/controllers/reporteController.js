import pool from "../config/database.js";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { crearPDF } from "../svc/pdfService.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


/* ==================================================
   OBTENER REPORTES IA DE UN PACIENTE

   GET /api/reportes/paciente/:id
================================================== */

export async function obtenerReportesPaciente(req, res) {

    try {

        const { id } = req.params;

        const [rows] = await pool.query(
            `
            SELECT
                id_reporte,
                id_paciente,
                id_sesion,
                fecha,
                contenido,
                ruta_pdf
            FROM reportes_ia
            WHERE id_paciente = ?
            ORDER BY fecha DESC
            `,
            [id]
        );

        return res.json(rows);

    } catch (error) {

        console.error(
            "❌ Error obteniendo reportes IA:",
            error
        );

        return res.status(500).json({
            message: "Error obteniendo reportes IA"
        });

    }

}


/* ==================================================
   GENERAR PDF DE REPORTE IA

   GET /api/reportes/:id/pdf
================================================== */

export async function generarPDF(req, res) {

    try {

        const { id } = req.params;

        const [rows] = await pool.query(
            "SELECT * FROM reportes_ia WHERE id_reporte = ?",
            [id]
        );

        if (!rows.length) {

            return res.status(404).json({
                message: "Reporte no encontrado"
            });

        }

        const reporte = rows[0];

        const carpetaPDF = path.join(
            __dirname,
            "../uploads/pdfs"
        );

        if (!fs.existsSync(carpetaPDF)) {

            fs.mkdirSync(
                carpetaPDF,
                {
                    recursive: true
                }
            );

        }

        const nombreArchivo =
            `reporte_${id}.pdf`;

        const rutaPDF =
            path.join(
                carpetaPDF,
                nombreArchivo
            );

        await crearPDF(
            reporte,
            rutaPDF
        );

        await pool.query(
            `
            UPDATE reportes_ia
            SET ruta_pdf = ?
            WHERE id_reporte = ?
            `,
            [
                `/uploads/pdfs/${nombreArchivo}`,
                id
            ]
        );

        return res.download(
            rutaPDF
        );

    } catch (error) {

        console.error(
            "❌ Error generando PDF:",
            error
        );

        return res.status(500).json({
            message: "Error generando PDF"
        });

    }

}