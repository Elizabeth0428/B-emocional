// ==================================================
// backend/controllers/reporteIAProspectoController.js
// ==================================================

import pool from "../config/database.js";

import {
  generarReporteIAConMeta
} from "../svc/aiService.js";


// ==================================================
// AUXILIAR: VALIDAR ACCESO AL PROSPECTO
// ==================================================

const validarAccesoProspecto =
  async (
    idProspecto,
    user
  ) => {

    const idUsuario =
      user?.id_usuario;


    const tipoAdmin =
      user?.tipo_admin
        ? String(
            user.tipo_admin
          )
            .trim()
            .toLowerCase()
        : null;


    const area =
      user?.area
        ? String(
            user.area
          )
            .trim()
            .toLowerCase()
        : null;


    if (!idUsuario) {

      return {
        ok:
          false,
        status:
          401,
        message:
          "No se pudo identificar al usuario"
      };

    }


    if (
      tipoAdmin !== "master" &&
      area !== "rh"
    ) {

      return {
        ok:
          false,
        status:
          403,
        message:
          "No tienes permiso para generar reportes RH"
      };

    }


    let query = `
      SELECT
        id_prospecto,
        id_mirror,
        nombre,
        edad,
        sexo,
        correo,
        telefono,
        puesto,
        direccion,
        estatus,
        id_admin_padre
      FROM prospectos
      WHERE id_prospecto = ?
    `;


    const params = [
      idProspecto
    ];


    if (
      tipoAdmin !== "master"
    ) {

      query += `
        AND id_admin_padre = ?
      `;


      params.push(
        idUsuario
      );

    }


    query += `
      LIMIT 1
    `;


    const [rows] =
      await pool.query(
        query,
        params
      );


    if (!rows.length) {

      return {
        ok:
          false,
        status:
          404,
        message:
          "Prospecto no encontrado o no tienes permiso para acceder a él"
      };

    }


    return {
      ok:
        true,
      prospecto:
        rows[0]
    };

  };


// ==================================================
// AUXILIAR: LIMITAR TEXTO MUY GRANDE
// ==================================================

const limitarTexto = (
  texto,
  limite = 12000
) => {

  if (!texto) {

    return "";

  }


  const limpio =
    String(
      texto
    ).trim();


  if (
    limpio.length <= limite
  ) {

    return limpio;

  }


  return (
    limpio.slice(
      0,
      limite
    ) +
    "\n[Contenido recortado por longitud]"
  );

};


// ==================================================
// AUXILIAR: OBTENER CONTEXTO COMPLETO
// ==================================================

const obtenerContextoProspecto =
  async (
    idProspecto
  ) => {


    // ==================================================
    // SEGUIMIENTOS
    // ==================================================

    const [seguimientos] =
      await pool.query(
        `
          SELECT
            id_seguimiento,
            fecha,
            etapa,
            actividad,
            observacion,
            resultado,
            proxima_accion,
            fecha_proxima_accion
          FROM seguimiento_prospectos
          WHERE id_prospecto = ?
          ORDER BY
            fecha ASC,
            id_seguimiento ASC
        `,
        [
          idProspecto
        ]
      );


    // ==================================================
    // ENTREVISTAS
    // ==================================================

    const [entrevistas] =
      await pool.query(
        `
          SELECT
            id_entrevista,
            tipo_entrevista,
            modalidad,
            fecha_entrevista,
            motivo,
            observaciones,
            resultado,
            transcripcion,
            estatus
          FROM entrevistas_prospectos
          WHERE id_prospecto = ?
          ORDER BY
            fecha_entrevista ASC,
            id_entrevista ASC
        `,
        [
          idProspecto
        ]
      );


    // ==================================================
    // GRABACIONES Y TRANSCRIPCIONES RH
    // ==================================================

    const [grabaciones] =
      await pool.query(
        `
          SELECT
            id_video_rh,
            id_prospecto,
            id_entrevista,
            tipo,
            descripcion,
            duracion_segundos,
            formato,
            transcripcion,
            transcripcion_estado,
            transcripcion_fecha,
            transcripcion_modelo,
            fecha_subida
          FROM videos_entrevista_rh
          WHERE id_prospecto = ?
          ORDER BY
            fecha_subida ASC,
            id_video_rh ASC
        `,
        [
          idProspecto
        ]
      );


    // ==================================================
    // RESULTADOS PSICOMÉTRICOS
    // ==================================================

    const [pruebas] =
      await pool.query(
        `
          SELECT
            r.id_resultado,
            r.id_habilitacion,
            r.id_prueba_rh,
            r.puntaje_total,
            r.resultado_texto,
            r.interpretacion,
            r.interpretacion_laboral,
            r.fortalezas,
            r.areas_atencion,
            r.compatibilidad_puesto,
            r.recomendaciones,
            r.fecha_resultado,

            p.nombre AS prueba_nombre,
            p.descripcion AS prueba_descripcion,
            p.categoria,
            p.version

          FROM resultados_prueba_prospecto r

          INNER JOIN pruebas_rh p
            ON p.id_prueba_rh =
               r.id_prueba_rh

          WHERE r.id_prospecto = ?

          ORDER BY
            r.fecha_resultado ASC,
            r.id_resultado ASC
        `,
        [
          idProspecto
        ]
      );


    // ==================================================
    // OBSERVACIONES RH
    // ==================================================

    const [observaciones] =
      await pool.query(
        `
          SELECT
            id_observacion,
            tipo,
            titulo,
            observacion,
            relevancia,
            fecha
          FROM observaciones_prospectos
          WHERE id_prospecto = ?
          ORDER BY
            fecha ASC,
            id_observacion ASC
        `,
        [
          idProspecto
        ]
      );


    // ==================================================
    // DOCUMENTOS
    //
    // IMPORTANTE:
    // La IA conoce que existen, tipo y descripción.
    // NO afirmamos que haya leído el contenido.
    // ==================================================

    const [documentos] =
      await pool.query(
        `
          SELECT
            id_documento,
            tipo_documento,
            nombre_original,
            mime_type,
            descripcion,
            fecha_subida
          FROM documentos_prospectos
          WHERE id_prospecto = ?
          ORDER BY
            fecha_subida ASC,
            id_documento ASC
        `,
        [
          idProspecto
        ]
      );


    return {

      seguimientos:
        seguimientos ||
        [],

      entrevistas:
        entrevistas ||
        [],

      grabaciones:
        grabaciones ||
        [],

      pruebas:
        pruebas ||
        [],

      observaciones:
        observaciones ||
        [],

      documentos:
        documentos ||
        []

    };

  };


// ==================================================
// CONSTRUIR CONTEXTO PARA IA
// ==================================================

const construirContextoIA =
  (
    prospecto,
    contexto
  ) => {

    const {
      seguimientos,
      entrevistas,
      grabaciones,
      pruebas,
      observaciones,
      documentos
    } = contexto;


    let texto = `

DATOS DEL PROSPECTO

Nombre: ${prospecto.nombre || "No registrado"}
ID MirrorSoul: ${prospecto.id_mirror || "No asignado"}
Edad: ${prospecto.edad ?? "No registrada"}
Sexo: ${prospecto.sexo || "No registrado"}
Puesto solicitado: ${prospecto.puesto || "No especificado"}
Estatus del proceso: ${prospecto.estatus || "prospecto"}

`;


    // ==================================================
    // ENTREVISTAS
    // ==================================================

    texto += `
==================================================
ENTREVISTAS
==================================================
`;


    if (
      entrevistas.length
    ) {

      entrevistas.forEach(
        (
          entrevista,
          index
        ) => {

          const archivosEntrevista =
            grabaciones.filter(
              archivo =>
                Number(
                  archivo.id_entrevista
                ) ===
                Number(
                  entrevista.id_entrevista
                )
            );


          texto += `

Entrevista ${index + 1}
ID: ${entrevista.id_entrevista}
Tipo: ${entrevista.tipo_entrevista || "No especificado"}
Modalidad: ${entrevista.modalidad || "No especificada"}
Fecha: ${entrevista.fecha_entrevista || "No registrada"}
Motivo: ${entrevista.motivo || "No registrado"}
Estado: ${entrevista.estatus || "No especificado"}
Resultado registrado por RH: ${entrevista.resultado || "No registrado"}
Observaciones de la entrevista:
${entrevista.observaciones || "Sin observaciones"}
`;


          if (
            archivosEntrevista.length
          ) {

            texto += `
Grabaciones asociadas: ${archivosEntrevista.length}
`;


            archivosEntrevista.forEach(
              (
                archivo,
                indiceArchivo
              ) => {

                texto += `

Grabación ${indiceArchivo + 1}
Tipo: ${archivo.tipo || "No especificado"}
Descripción: ${archivo.descripcion || "Sin descripción"}
Formato: ${archivo.formato || "No registrado"}
Duración: ${
  archivo.duracion_segundos
    ? `${archivo.duracion_segundos} segundos`
    : "No registrada"
}
Estado de transcripción: ${archivo.transcripcion_estado || "No registrado"}
Modelo de transcripción: ${archivo.transcripcion_modelo || "No registrado"}
`;


                if (
                  archivo.transcripcion_estado ===
                    "completada" &&
                  archivo.transcripcion
                ) {

                  texto += `
TRANSCRIPCIÓN TEXTUAL:
${limitarTexto(
  archivo.transcripcion
)}
`;

                } else {

                  texto += `
Transcripción: No disponible.
`;

                }

              }
            );

          } else if (
            entrevista.transcripcion
          ) {

            texto += `
TRANSCRIPCIÓN REGISTRADA EN LA ENTREVISTA:
${limitarTexto(
  entrevista.transcripcion
)}
`;

          } else {

            texto += `
No existe transcripción disponible para esta entrevista.
`;

          }

        }
      );


    } else {

      texto += `
No se registran entrevistas.
`;

    }


    // ==================================================
    // PRUEBAS
    // ==================================================

    texto += `

==================================================
PRUEBAS PSICOMÉTRICAS
==================================================
`;


    if (
      pruebas.length
    ) {

      pruebas.forEach(
        (
          prueba,
          index
        ) => {

          texto += `

Prueba ${index + 1}
Nombre: ${prueba.prueba_nombre || "Prueba psicométrica"}
Categoría: ${prueba.categoria || "No especificada"}
Descripción: ${prueba.prueba_descripcion || "No disponible"}
Versión: ${prueba.version || "No registrada"}
Puntaje: ${prueba.puntaje_total ?? "No disponible"}
Resultado registrado: ${prueba.resultado_texto || "No registrado"}
Interpretación: ${prueba.interpretacion || "No registrada"}
Interpretación laboral: ${prueba.interpretacion_laboral || "No registrada"}
Fortalezas registradas: ${prueba.fortalezas || "No registradas"}
Áreas de atención registradas: ${prueba.areas_atencion || "No registradas"}
Compatibilidad registrada con el puesto: ${prueba.compatibilidad_puesto || "No registrada"}
Recomendaciones registradas: ${prueba.recomendaciones || "No registradas"}
`;

        }
      );


    } else {

      texto += `
No se registran pruebas psicométricas completadas.
`;

    }


    // ==================================================
    // SEGUIMIENTO
    // ==================================================

    texto += `

==================================================
SEGUIMIENTO DEL PROCESO
==================================================
`;


    if (
      seguimientos.length
    ) {

      seguimientos.forEach(
        (
          item,
          index
        ) => {

          texto += `

Seguimiento ${index + 1}
Fecha: ${item.fecha || "No registrada"}
Etapa: ${item.etapa || "No especificada"}
Actividad: ${item.actividad || "No especificada"}
Resultado: ${item.resultado || "No especificado"}
Observación:
${item.observacion || "Sin observación"}

Próxima acción:
${item.proxima_accion || "No registrada"}

Fecha próxima acción:
${item.fecha_proxima_accion || "No registrada"}
`;

        }
      );


    } else {

      texto += `
No se registran seguimientos.
`;

    }


    // ==================================================
    // DOCUMENTOS
    // ==================================================

    texto += `

==================================================
DOCUMENTOS DISPONIBLES
==================================================

IMPORTANTE:
Solamente se proporciona a la IA información
sobre la existencia y descripción de los archivos.
No se proporciona el contenido interno de los
documentos.
`;


    if (
      documentos.length
    ) {

      documentos.forEach(
        (
          documento,
          index
        ) => {

          texto += `

Documento ${index + 1}
Tipo: ${documento.tipo_documento || "otro"}
Nombre del archivo: ${documento.nombre_original || "Sin nombre"}
Formato: ${documento.mime_type || "No registrado"}
Descripción: ${documento.descripcion || "Sin descripción"}
Fecha de carga: ${documento.fecha_subida || "No registrada"}
`;

        }
      );


    } else {

      texto += `
No se registran documentos.
`;

    }


    // ==================================================
    // OBSERVACIONES
    // ==================================================

    texto += `

==================================================
OBSERVACIONES DE RECURSOS HUMANOS
==================================================
`;


    if (
      observaciones.length
    ) {

      observaciones.forEach(
        (
          item,
          index
        ) => {

          texto += `

Observación ${index + 1}
Fecha: ${item.fecha || "No registrada"}
Tipo: ${item.tipo || "General"}
Título: ${item.titulo || "Sin título"}
Relevancia: ${item.relevancia || "Informativa"}
Contenido:
${item.observacion || "Sin contenido"}
`;

        }
      );


    } else {

      texto += `
No se registran observaciones RH.
`;

    }


    return texto.trim();

  };


// ==================================================
// CONSTRUIR PROMPT LABORAL
// ==================================================

const construirPromptIA =
  (
    prospecto,
    contextoTexto
  ) => {

    return `

Genera un PREANÁLISIS LABORAL de apoyo para
Recursos Humanos utilizando EXCLUSIVAMENTE
la información incluida al final de este mensaje.

El prospecto participa en un proceso de selección
para el puesto:

${prospecto.puesto || "No especificado"}


REGLAS OBLIGATORIAS

1. No inventes datos.
2. No inventes experiencia laboral.
3. No inventes competencias.
4. No inventes resultados de pruebas.
5. No modifiques puntajes psicométricos.
6. No realices diagnósticos médicos ni psicológicos.
7. No utilices criterios relacionados con sexo,
   edad u otras características personales para
   recomendar contratar o rechazar.
8. No decidas si la persona debe ser contratada.
9. No clasifiques al prospecto como bueno o malo.
10. No afirmes haber escuchado audio o visto video.
11. Cuando exista una transcripción, trátala
    únicamente como información textual disponible.
12. No afirmes haber leído CV, identificaciones,
    certificados u otros archivos. Solamente conoces
    su nombre, tipo y descripción.
13. Si falta información para una conclusión,
    indícalo claramente.
14. Distingue datos registrados por RH de
    observaciones generadas por IA.
15. La decisión final siempre corresponde al
    responsable humano de Recursos Humanos.


OBJETIVO

Integra la información disponible y ayuda a RH
a comprender el proceso sin repetir mecánicamente
todos los datos.


FORMATO OBLIGATORIO

PREANÁLISIS LABORAL — MIRRORSOUL

1. RESUMEN DEL PROCESO DE SELECCIÓN
Resume el avance general y la información disponible.

2. PERFIL GENERAL OBSERVADO
Describe únicamente características laborales o
conductuales respaldadas por entrevistas,
observaciones, seguimiento o pruebas.

3. INFORMACIÓN RELEVANTE DE ENTREVISTAS
Integra los puntos importantes de entrevistas y
transcripciones disponibles.

4. RESULTADOS PSICOMÉTRICOS
Resume resultados registrados sin alterar puntajes
ni convertirlos en diagnósticos.

5. SEGUIMIENTO Y EVOLUCIÓN DEL PROCESO
Resume actividades, avances, pendientes y cambios
observables durante el proceso.

6. DOCUMENTACIÓN DISPONIBLE
Indica qué documentos están registrados.
No afirmes haber leído su contenido.

7. FORTALEZAS OBSERVADAS
Incluye únicamente fortalezas respaldadas por
evidencia disponible.

8. ASPECTOS QUE REQUIEREN VALORACIÓN
Menciona inconsistencias, faltantes, pendientes o
puntos que RH debería revisar.

9. CORRESPONDENCIA OBSERVADA CON EL PUESTO
Relaciona la información disponible con el puesto,
pero sin emitir una decisión de contratación.

10. PUNTOS QUE RH DEBE REVISAR
Incluye verificaciones concretas antes de cerrar
el proceso.

11. SÍNTESIS FINAL
Genera una síntesis profesional breve, equilibrada
y basada exclusivamente en los datos disponibles.

Finaliza exactamente con:

"Este preanálisis es una herramienta de apoyo para Recursos Humanos. La valoración y decisión final corresponden al responsable humano del proceso de selección."


==================================================
INFORMACIÓN DISPONIBLE
==================================================

${contextoTexto}

`;

  };


// ==================================================
// GENERAR PREANÁLISIS REAL CON IA
//
// POST
// /api/prospectos/:id/reporte-ia
// ==================================================

export const generarReporteIAProspecto =
  async (
    req,
    res
  ) => {

    try {

      const idProspecto =
        Number(
          req.params.id
        );


      if (
        !Number.isInteger(
          idProspecto
        ) ||
        idProspecto <= 0
      ) {

        return res
          .status(400)
          .json({

            success:
              false,

            message:
              "ID de prospecto inválido"

          });

      }


      // ==================================================
      // ACCESO
      // ==================================================

      const acceso =
        await validarAccesoProspecto(
          idProspecto,
          req.user
        );


      if (
        !acceso.ok
      ) {

        return res
          .status(
            acceso.status
          )
          .json({

            success:
              false,

            message:
              acceso.message

          });

      }


      // ==================================================
      // CONTEXTO
      // ==================================================

      const contexto =
        await obtenerContextoProspecto(
          idProspecto
        );


      const totalInformacion =
        contexto.seguimientos.length +
        contexto.entrevistas.length +
        contexto.pruebas.length +
        contexto.observaciones.length +
        contexto.documentos.length +
        contexto.grabaciones.length;


      if (
        totalInformacion === 0
      ) {

        return res
          .status(400)
          .json({

            success:
              false,

            message:
              "Aún no existe información suficiente del proceso para generar el preanálisis."

          });

      }


      // ==================================================
      // CONTEXTO TEXTUAL
      // ==================================================

      const contextoTexto =
        construirContextoIA(
          acceso.prospecto,
          contexto
        );


      // ==================================================
      // PROMPT
      // ==================================================

      const prompt =
        construirPromptIA(
          acceso.prospecto,
          contextoTexto
        );


      // ==================================================
      // SYSTEM PROMPT RH
      // ==================================================

      const systemPrompt = `
Eres un asistente especializado en apoyo a
procesos profesionales de Recursos Humanos.

Tu función es organizar, relacionar y resumir
evidencia disponible de un proceso de selección.

No realizas diagnóstico clínico.

No decides quién debe ser contratado.

No inventas información.

No debes utilizar características personales
como sexo o edad para recomendar contratar
o rechazar a una persona.

Tus respuestas deben ser profesionales,
prudentes, claras y basadas exclusivamente
en la información proporcionada por RH.
      `.trim();


      console.log(
        "🤖 Generando preanálisis laboral REAL con IA:",
        {
          idProspecto,
          seguimientos:
            contexto.seguimientos.length,
          entrevistas:
            contexto.entrevistas.length,
          grabaciones:
            contexto.grabaciones.length,
          pruebas:
            contexto.pruebas.length,
          documentos:
            contexto.documentos.length,
          observaciones:
            contexto.observaciones.length
        }
      );


      // ==================================================
      // GENERAR CON IA
      // ==================================================

      const resultadoIA =
        await generarReporteIAConMeta(
          prompt,
          2200,
          systemPrompt
        );


      const contenido =
        String(
          resultadoIA?.texto ||
          ""
        ).trim();


      if (
        !contenido
      ) {

        throw new Error(
          "La IA no devolvió contenido para el preanálisis."
        );

      }


      // ==================================================
      // TRAZABILIDAD
      // ==================================================

      const transcripciones =
        contexto.grabaciones.filter(
          archivo =>
            archivo.transcripcion_estado ===
              "completada" &&
            String(
              archivo.transcripcion ||
              ""
            ).trim()
        ).length;


      const generadoDesde = {

        seguimientos:
          contexto.seguimientos.length,

        entrevistas:
          contexto.entrevistas.length,

        grabaciones:
          contexto.grabaciones.length,

        transcripciones,

        pruebas:
          contexto.pruebas.length,

        documentos:
          contexto.documentos.length,

        observaciones:
          contexto.observaciones.length

      };


      // ==================================================
      // MODELO REAL
      // ==================================================

      const modeloIA =
        `${resultadoIA.proveedor}:${resultadoIA.modelo}`;


      // ==================================================
      // GUARDAR
      // ==================================================

      const [result] =
        await pool.query(
          `
            INSERT INTO reportes_ia_prospectos
            (
              id_prospecto,
              id_usuario_registro,
              tipo_reporte,
              contenido,
              modelo_ia,
              generado_desde
            )
            VALUES
            (
              ?,
              ?,
              'preanalisis',
              ?,
              ?,
              ?
            )
          `,
          [
            idProspecto,

            req.user?.id_usuario ||
              null,

            contenido,

            modeloIA,

            JSON.stringify(
              generadoDesde
            )
          ]
        );


      console.log(
        "✅ Preanálisis RH generado con IA:",
        {
          id_reporte:
            result.insertId,
          proveedor:
            resultadoIA.proveedor,
          modelo:
            resultadoIA.modelo
        }
      );


      // ==================================================
      // RESPUESTA
      // ==================================================

      return res
        .status(201)
        .json({

          success:
            true,

          message:
            "Preanálisis laboral generado correctamente con IA.",

          reporte: {

            id_reporte:
              result.insertId,

            id_prospecto:
              idProspecto,

            tipo_reporte:
              "preanalisis",

            contenido,

            modelo_ia:
              modeloIA,

            generado_desde:
              generadoDesde,

            creado_en:
              new Date()
                .toISOString()

          }

        });


    } catch (error) {

      console.error(
        "❌ Error generando reporte IA RH:",
        error
      );


      return res
        .status(500)
        .json({

          success:
            false,

          message:
            "No fue posible generar el preanálisis laboral con IA.",

          error:
            process.env.NODE_ENV ===
            "development"
              ? error.message
              : undefined

        });

    }

  };


// ==================================================
// LISTAR REPORTES
//
// GET /api/prospectos/:id/reportes-ia
// ==================================================

export const listarReportesIAProspecto =
  async (
    req,
    res
  ) => {

    try {

      const idProspecto =
        Number(
          req.params.id
        );


      if (
        !Number.isInteger(
          idProspecto
        ) ||
        idProspecto <= 0
      ) {

        return res
          .status(400)
          .json({

            success:
              false,

            message:
              "ID de prospecto inválido"

          });

      }


      const acceso =
        await validarAccesoProspecto(
          idProspecto,
          req.user
        );


      if (
        !acceso.ok
      ) {

        return res
          .status(
            acceso.status
          )
          .json({

            success:
              false,

            message:
              acceso.message

          });

      }


      const [reportes] =
        await pool.query(
          `
            SELECT
              r.id_reporte,
              r.id_prospecto,
              r.id_usuario_registro,
              r.tipo_reporte,
              r.contenido,
              r.modelo_ia,
              r.generado_desde,
              r.creado_en,
              r.actualizado_en,

              u.nombre AS usuario_registro

            FROM reportes_ia_prospectos r

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 r.id_usuario_registro

            WHERE r.id_prospecto = ?

            ORDER BY
              r.creado_en DESC,
              r.id_reporte DESC
          `,
          [
            idProspecto
          ]
        );


      return res.json({

        success:
          true,

        prospecto:
          acceso.prospecto,

        reportes:
          reportes ||
          []

      });


    } catch (error) {

      console.error(
        "❌ Error listando reportes IA RH:",
        error
      );


      return res
        .status(500)
        .json({

          success:
            false,

          message:
            "Error interno al obtener los reportes",

          error:
            process.env.NODE_ENV ===
            "development"
              ? error.message
              : undefined

        });

    }

  };


// ==================================================
// OBTENER UN REPORTE
//
// GET
// /api/prospectos/:id/reportes-ia/:idReporte
// ==================================================

export const obtenerReporteIAProspecto =
  async (
    req,
    res
  ) => {

    try {

      const idProspecto =
        Number(
          req.params.id
        );


      const idReporte =
        Number(
          req.params.idReporte
        );


      if (
        !Number.isInteger(
          idProspecto
        ) ||
        idProspecto <= 0 ||
        !Number.isInteger(
          idReporte
        ) ||
        idReporte <= 0
      ) {

        return res
          .status(400)
          .json({

            success:
              false,

            message:
              "Datos de reporte inválidos"

          });

      }


      const acceso =
        await validarAccesoProspecto(
          idProspecto,
          req.user
        );


      if (
        !acceso.ok
      ) {

        return res
          .status(
            acceso.status
          )
          .json({

            success:
              false,

            message:
              acceso.message

          });

      }


      const [rows] =
        await pool.query(
          `
            SELECT
              r.id_reporte,
              r.id_prospecto,
              r.id_usuario_registro,
              r.tipo_reporte,
              r.contenido,
              r.modelo_ia,
              r.generado_desde,
              r.creado_en,
              r.actualizado_en,

              u.nombre AS usuario_registro

            FROM reportes_ia_prospectos r

            LEFT JOIN usuarios u
              ON u.id_usuario =
                 r.id_usuario_registro

            WHERE r.id_reporte = ?
              AND r.id_prospecto = ?

            LIMIT 1
          `,
          [
            idReporte,
            idProspecto
          ]
        );


      if (
        !rows.length
      ) {

        return res
          .status(404)
          .json({

            success:
              false,

            message:
              "Reporte no encontrado"

          });

      }


      return res.json({

        success:
          true,

        prospecto:
          acceso.prospecto,

        reporte:
          rows[0]

      });


    } catch (error) {

      console.error(
        "❌ Error obteniendo reporte IA RH:",
        error
      );


      return res
        .status(500)
        .json({

          success:
            false,

          message:
            "Error interno al obtener el reporte",

          error:
            process.env.NODE_ENV ===
            "development"
              ? error.message
              : undefined

        });

    }

  };