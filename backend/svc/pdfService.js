import PDFDocument from "pdfkit";
import fs from "fs";

/* ==================================================
   COLORES DEL DOCUMENTO
================================================== */

const COLORS = {
    navy: "#163A5F",
    blue: "#245B87",
    lightBlue: "#EAF2F8",
    gray: "#666666",
    lightGray: "#F4F6F8",
    dark: "#222222",
    white: "#FFFFFF",
    border: "#D9E1E8"
};


/* ==================================================
   CREAR PDF
================================================== */

export function crearPDF(reporte, rutaDestino) {

    return new Promise((resolve, reject) => {

        const doc = new PDFDocument({
            margin: 45,
            size: "A4",
            bufferPages: true
        });

        const stream = fs.createWriteStream(rutaDestino);

        doc.pipe(stream);


        /* ==================================================
           CONFIGURACIÓN
        ================================================== */

        const pageWidth =
            doc.page.width -
            doc.page.margins.left -
            doc.page.margins.right;


        /* ==================================================
           ENCABEZADO
        ================================================== */

        doc
            .font("Helvetica-Bold")
            .fontSize(25)
            .fillColor(COLORS.navy)
            .text("Mirror Soul", {
                continued: true
            });

       doc
    .font("Helvetica-Bold")
    .fontSize(10)
    .fillColor(COLORS.gray)
    .text("  |  Plataforma de evaluación y acompañamiento emocional");


        doc.moveDown(0.5);


        /* Línea superior */

        doc
            .moveTo(
                doc.page.margins.left,
                doc.y
            )
            .lineTo(
                doc.page.width - doc.page.margins.right,
                doc.y
            )
            .lineWidth(2)
            .strokeColor(COLORS.navy)
            .stroke();


        doc.moveDown(0.7);


        /* ==================================================
           TÍTULO
        ================================================== */

        doc
            .font("Helvetica-Bold")
            .fontSize(17)
            .fillColor(COLORS.dark)
            .text("REPORTE CLÍNICO", {
                align: "right"
            });


        doc.moveDown(1);


        /* ==================================================
           DATOS DEL REPORTE
        ================================================== */

        crearTituloSeccion(
            doc,
            "DATOS DEL REPORTE"
        );


        const fecha =
            formatearFecha(reporte.fecha);


        const yDatos =
            doc.y;


        /* Paciente */

        doc
            .font("Helvetica-Bold")
            .fontSize(10)
            .fillColor(COLORS.dark)
            .text(
                "Paciente",
                doc.page.margins.left,
                yDatos
            );


        doc
            .font("Helvetica")
            .text(
                String(
                    reporte.id_paciente ??
                    "No disponible"
                ),
                doc.page.margins.left + 65,
                yDatos
            );


        /* Sesión */

        doc
            .font("Helvetica-Bold")
            .text(
                "Sesión",
                doc.page.margins.left +
                    pageWidth / 2,
                yDatos
            );


        doc
            .font("Helvetica")
            .text(
                String(
                    reporte.id_sesion ??
                    "No disponible"
                ),
                doc.page.margins.left +
                    pageWidth / 2 +
                    45,
                yDatos
            );


        doc.moveDown(1.3);


        /* Fecha */

        const yFecha =
            doc.y;


        doc
            .font("Helvetica-Bold")
            .text(
                "Fecha",
                doc.page.margins.left,
                yFecha
            );


        doc
            .font("Helvetica")
            .text(
                fecha,
                doc.page.margins.left + 65,
                yFecha
            );


        doc.moveDown(1.5);


        /* ==================================================
           CONTENIDO DEL REPORTE
        ================================================== */

        crearTituloSeccion(
            doc,
            "ANÁLISIS CLÍNICO PRELIMINAR"
        );


        const contenido =
            reporte.contenido ||
            "Sin contenido disponible.";


        renderizarContenido(
            doc,
            contenido
        );


        /* ==================================================
           AVISO CLÍNICO
        ================================================== */

        if (
            doc.y >
            doc.page.height - 180
        ) {
            doc.addPage();
        }


        doc.moveDown(1);


        crearTituloSeccion(
            doc,
            "AVISO CLÍNICO"
        );


        doc
            .font("Helvetica")
            .fontSize(9)
            .fillColor(COLORS.gray)
            .text(
                "Este documento constituye un apoyo para la revisión clínica y no sustituye la valoración, diagnóstico o criterio profesional de un especialista.",
                {
                    width: pageWidth,
                    align: "justify",
                    lineGap: 3
                }
            );


        /* ==================================================
           PIE DE PÁGINA
        ================================================== */

        agregarPieDePagina(doc);


        doc.end();


        stream.on(
            "finish",
            resolve
        );


        stream.on(
            "error",
            reject
        );

    });

}


/* ==================================================
   TÍTULO DE SECCIÓN
================================================== */

function crearTituloSeccion(doc, titulo) {

    const x =
        doc.page.margins.left;


    const width =
        doc.page.width -
        doc.page.margins.left -
        doc.page.margins.right;


    doc
        .rect(
            x,
            doc.y,
            width,
            25
        )
        .fill(COLORS.navy);


    doc
        .font("Helvetica-Bold")
        .fontSize(10)
        .fillColor(COLORS.white)
        .text(
            titulo,
            x + 10,
            doc.y + 7,
            {
                width: width - 20
            }
        );


    doc.y += 35;

}


/* ==================================================
   RENDERIZAR CONTENIDO IA
================================================== */

function renderizarContenido(
    doc,
    contenido
) {

    const lineas =
        contenido
            .replace(/\r/g, "")
            .split("\n");


    for (
        let i = 0;
        i < lineas.length;
        i++
    ) {

        let linea =
            lineas[i].trim();


        /* Línea vacía */

        if (!linea) {

            doc.moveDown(0.5);

            continue;
        }


        /* ==================================================
           QUITAR EMOJIS ANTES DE PDFKIT
        ================================================== */

        const lineaSinEmoji =
            quitarEmojis(linea);


        linea =
            lineaSinEmoji.trim();


        if (!linea) {
            continue;
        }


        /* ==================================================
           TÍTULOS CON #
        ================================================== */

        if (
            linea.startsWith("#")
        ) {

            const titulo =
                linea.replace(
                    /^#+\s*/,
                    ""
                );


            crearSubtitulo(
                doc,
                limpiarMarkdown(titulo)
            );


            continue;
        }


        /* ==================================================
           TÍTULOS NUMERADOS
        ================================================== */

        if (
            /^\d+\.\s+/.test(linea)
        ) {

            crearSubtitulo(
                doc,
                limpiarMarkdown(linea)
            );


            continue;
        }


        /* ==================================================
           TÍTULOS CONOCIDOS
        ================================================== */

        const posiblesTitulos = [
            "Reporte clínico preliminar",
            "Resumen clínico breve",
            "Patrones observados",
            "Riesgos detectados",
            "Recomendaciones de seguimiento",
            "Observaciones sobre multimedia",
            "Nota aclaratoria"
        ];


        const esTitulo =
            posiblesTitulos.some(
                titulo =>
                    linea
                        .toLowerCase()
                        .includes(
                            titulo.toLowerCase()
                        )
            );


        if (esTitulo) {

            crearSubtitulo(
                doc,
                limpiarMarkdown(linea)
            );


            continue;
        }


        /* ==================================================
           LISTAS
        ================================================== */

        if (
            linea.startsWith("* ") ||
            linea.startsWith("- ")
        ) {

            const texto =
                linea.substring(2);


            crearLista(
                doc,
                limpiarMarkdown(texto)
            );


            continue;
        }


        /* ==================================================
           TEXTO NORMAL
        ================================================== */

        crearParrafo(
            doc,
            linea
        );

    }

}


/* ==================================================
   QUITAR EMOJIS
================================================== */

function quitarEmojis(texto) {

    return texto
        .replace(
            /[\u{1F300}-\u{1FAFF}]/gu,
            ""
        )
        .replace(
            /[\u{1F1E6}-\u{1F1FF}]/gu,
            ""
        )
        .replace(
            /[\u{2600}-\u{27BF}]/gu,
            ""
        )
        .replace(
            /[\u{FE0F}]/gu,
            ""
        )
        .trim();

}


/* ==================================================
   SUBTÍTULO
================================================== */

function crearSubtitulo(
    doc,
    texto
) {

    comprobarEspacio(
        doc,
        60
    );


    doc
        .font("Helvetica-Bold")
        .fontSize(12)
        .fillColor(COLORS.navy)
        .text(
            limpiarMarkdown(texto),
            {
                width:
                    doc.page.width -
                    doc.page.margins.left -
                    doc.page.margins.right
            }
        );


    doc.moveDown(0.3);


    doc
        .moveTo(
            doc.page.margins.left,
            doc.y
        )
        .lineTo(
            doc.page.width -
                doc.page.margins.right,
            doc.y
        )
        .lineWidth(0.7)
        .strokeColor(COLORS.border)
        .stroke();


    doc.moveDown(0.6);

}


/* ==================================================
   PÁRRAFO
================================================== */

function crearParrafo(
    doc,
    texto
) {

    comprobarEspacio(
        doc,
        45
    );


    doc
        .font("Helvetica")
        .fontSize(10)
        .fillColor(COLORS.dark)
        .text(
            limpiarMarkdown(texto),
            {
                width:
                    doc.page.width -
                    doc.page.margins.left -
                    doc.page.margins.right,

                align: "justify",

                lineGap: 3
            }
        );


    doc.moveDown(0.4);

}


/* ==================================================
   LISTA
================================================== */

function crearLista(
    doc,
    texto
) {

    comprobarEspacio(
        doc,
        40
    );


    const x =
        doc.page.margins.left;


    const bulletX =
        x + 4;


    const textX =
        x + 18;


    doc
        .circle(
            bulletX,
            doc.y + 5,
            2
        )
        .fill(COLORS.navy);


    doc
        .font("Helvetica")
        .fontSize(10)
        .fillColor(COLORS.dark)
        .text(
            limpiarMarkdown(texto),
            textX,
            doc.y,
            {
                width:
                    doc.page.width -
                    doc.page.margins.right -
                    textX,

                align: "left",

                lineGap: 3
            }
        );


    doc.moveDown(0.3);

}


/* ==================================================
   LIMPIAR MARKDOWN
================================================== */

function limpiarMarkdown(
    texto
) {

    return quitarEmojis(texto)
        .replace(
            /\*\*(.*?)\*\*/g,
            "$1"
        )
        .replace(
            /__(.*?)__/g,
            "$1"
        )
        .replace(
            /`(.*?)`/g,
            "$1"
        )
        .replace(
            /^#+\s*/,
            ""
        )
        .trim();

}


/* ==================================================
   COMPROBAR ESPACIO
================================================== */

function comprobarEspacio(
    doc,
    espacioNecesario
) {

    const limite =
        doc.page.height -
        doc.page.margins.bottom -
        espacioNecesario;


    if (
        doc.y > limite
    ) {

        doc.addPage();

    }

}


/* ==================================================
   PIE DE PÁGINA
================================================== */

function agregarPieDePagina(
    doc
) {

    const rango =
        doc.bufferedPageRange();


    for (
        let i = rango.start;
        i <
        rango.start + rango.count;
        i++
    ) {

        doc.switchToPage(i);


        const y =
            doc.page.height - 30;


        doc
            .font("Helvetica")
            .fontSize(8)
            .fillColor(COLORS.gray)
            .text(
                `Mirror Soul • Reporte clínico • Página ${i + 1}`,
                doc.page.margins.left,
                y,
                {
                    width:
                        doc.page.width -
                        doc.page.margins.left -
                        doc.page.margins.right,

                    align: "center"
                }
            );

    }

}


/* ==================================================
   FORMATEAR FECHA
================================================== */

function formatearFecha(
    fecha
) {

    if (!fecha) {

        return "No disponible";

    }


    const date =
        new Date(fecha);


    if (
        Number.isNaN(
            date.getTime()
        )
    ) {

        return String(fecha);

    }


    return date.toLocaleDateString(
        "es-MX",
        {
            day: "2-digit",
            month: "2-digit",
            year: "numeric"
        }
    );

}