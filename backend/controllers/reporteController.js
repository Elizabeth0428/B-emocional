import pool from "../config/database.js";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { crearPDF } from "../svc/pdfService.js";

const __filename =
    fileURLToPath(
        import.meta.url
    );

const __dirname =
    path.dirname(
        __filename
    );


/* ==================================================
   OBTENER REPORTES IA DE UN PACIENTE

   GET /api/reportes/paciente/:id

   IMPORTANTE:
   - id_sesion = ID interno
   - numero_sesion = consecutivo clínico del paciente
================================================== */

export async function obtenerReportesPaciente(
    req,
    res
) {

    try {

        const {
            id
        } = req.params;


        const idPaciente =
            Number(
                id
            );


        if (
            !Number.isInteger(
                idPaciente
            ) ||
            idPaciente <= 0
        ) {

            return res
                .status(400)
                .json({
                    success: false,

                    message:
                        "ID de paciente inválido"
                });

        }


        const [rows] =
            await pool.query(
                `
                SELECT

                    r.id_reporte,

                    r.id_paciente,

                    r.id_sesion,

                    s.numero_sesion,

                    r.fecha,

                    r.contenido,

                    r.ruta_pdf

                FROM reportes_ia r

                LEFT JOIN sesiones s
                    ON s.id_sesion =
                       r.id_sesion

                WHERE
                    r.id_paciente = ?

                ORDER BY
                    r.fecha DESC,
                    r.id_reporte DESC
                `,
                [
                    idPaciente
                ]
            );


        return res.json(
            rows || []
        );


    } catch (error) {

        console.error(
            "❌ Error obteniendo reportes IA:",
            error
        );


        return res
            .status(500)
            .json({
                success: false,

                message:
                    "Error obteniendo reportes IA",

                error:
                    process.env.NODE_ENV ===
                    "development"
                        ? error.message
                        : undefined
            });

    }

}


/* ==================================================
   GENERAR PDF DE REPORTE IA

   GET /api/reportes/:id/pdf

   IMPORTANTE:
   El reporte también recibe numero_sesion
   para que el PDF pueda utilizar el número
   clínico en vez del ID interno.
================================================== */

export async function generarPDF(
    req,
    res
) {

    try {

        const {
            id
        } = req.params;


        const idReporte =
            Number(
                id
            );


        if (
            !Number.isInteger(
                idReporte
            ) ||
            idReporte <= 0
        ) {

            return res
                .status(400)
                .json({
                    success: false,

                    message:
                        "ID de reporte inválido"
                });

        }


        const [rows] =
            await pool.query(
                `
                SELECT

                    r.*,

                    s.numero_sesion

                FROM reportes_ia r

                LEFT JOIN sesiones s
                    ON s.id_sesion =
                       r.id_sesion

                WHERE
                    r.id_reporte = ?

                LIMIT 1
                `,
                [
                    idReporte
                ]
            );


        if (
            !rows.length
        ) {

            return res
                .status(404)
                .json({
                    success: false,

                    message:
                        "Reporte no encontrado"
                });

        }


        const reporte =
            rows[0];


        const carpetaPDF =
            path.join(
                __dirname,
                "../uploads/pdfs"
            );


        if (
            !fs.existsSync(
                carpetaPDF
            )
        ) {

            fs.mkdirSync(
                carpetaPDF,
                {
                    recursive: true
                }
            );

        }


        const nombreArchivo =
            `reporte_${idReporte}.pdf`;


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

                idReporte
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


        return res
            .status(500)
            .json({
                success: false,

                message:
                    "Error generando PDF",

                error:
                    process.env.NODE_ENV ===
                    "development"
                        ? error.message
                        : undefined
            });

    }

}