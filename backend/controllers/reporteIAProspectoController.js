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

const validarAccesoProspecto = async (
  idProspecto,
  user
) => {

  const idUsuario =
    Number(user?.id_usuario) || null;

  if (!idUsuario) {
    return {
      ok: false,
      status: 401,
      message:
        "No se pudo identificar al usuario",
    };
  }


  // ==================================================
  // CONTEXTO REAL DEL USUARIO RH
  //
  // Permite:
  // - Master
  // - Admin RH
  // - Usuario RH
  // - Independiente con perfil RH
  // ==================================================

  const [usuarios] =
    await pool.query(
      `
        SELECT
          u.id_usuario,
          u.tipo_admin,
          u.area,
          u.rol,
          u.id_admin_padre,
          u.id_organizacion,
          o.tipo AS tipo_organizacion,
          o.perfil_independiente,
          o.estado AS estado_organizacion
        FROM usuarios u
        LEFT JOIN organizaciones o
          ON o.id_organizacion =
             u.id_organizacion
        WHERE u.id_usuario = ?
        LIMIT 1
      `,
      [idUsuario]
    );


  if (!usuarios.length) {
    return {
      ok: false,
      status: 401,
      message:
        "No se pudo identificar al usuario",
    };
  }


  const usuario =
    usuarios[0];


  const tipoAdmin =
    String(
      usuario.tipo_admin || ""
    )
      .trim()
      .toLowerCase();


  const area =
    String(
      usuario.area || ""
    )
      .trim()
      .toLowerCase();


  const rol =
    String(
      usuario.rol || ""
    )
      .trim()
      .toLowerCase();


  const perfilIndependiente =
    String(
      usuario.perfil_independiente || ""
    )
      .trim()
      .toLowerCase();


  const estadoOrganizacion =
    String(
      usuario.estado_organizacion || ""
    )
      .trim()
      .toLowerCase();


  const esMaster =
    tipoAdmin === "master";


  const esAdminRH =
    tipoAdmin === "normal" &&
    area === "rh";


  const esUsuarioRH =
    rol === "rh" &&
    area === "rh";


  const esIndependienteRH =
    rol === "independiente" &&
    area === "independiente" &&
    perfilIndependiente === "rh" &&
    estadoOrganizacion === "activa";


  const tienePermiso =
    esMaster ||
    esAdminRH ||
    esUsuarioRH ||
    esIndependienteRH;


  if (!tienePermiso) {
    return {
      ok: false,
      status: 403,
      message:
        "No tienes permiso para generar reportes RH",
    };
  }


  let query = `
    SELECT
      *
    FROM prospectos
    WHERE id_prospecto = ?
  `;


  const params = [
    idProspecto
  ];


  // Todo usuario RH no-master,
  // incluido Independiente RH,
  // solo puede acceder a sus propios prospectos.

  if (!esMaster) {

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
      ok: false,
      status: 404,
      message:
        "Prospecto no encontrado o no tienes permiso para acceder a él",
    };
  }


  return {
    ok: true,

    prospecto:
      rows[0],

    contexto: {
      idUsuario,
      tipoAdmin,
      area,
      rol,

      idOrganizacion:
        Number(
          usuario.id_organizacion
        ) || null,

      perfilIndependiente,

      esMaster,
      esAdminRH,
      esUsuarioRH,
      esIndependienteRH,
    },
  };
};


// ==================================================
// AUXILIAR: LIMITAR TEXTO MUY GRANDE
// ==================================================

const limitarTexto = (
  texto,
  limite = 12000
) => {

  if (
    texto === undefined ||
    texto === null
  ) {
    return "";
  }


  const limpio =
    String(
      texto
    ).trim();


  if (!limpio) {
    return "";
  }


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

Genera un PREANÁLISIS LABORAL EJECUTIVO para Recursos Humanos
utilizando EXCLUSIVAMENTE la información proporcionada.

Debe ser breve, claro, profesional y realmente útil
para que RH entienda qué significan los resultados.

Puesto solicitado:

${prospecto.puesto || "No especificado"}


REGLAS OBLIGATORIAS

1. No inventes datos.
2. No inventes experiencia laboral.
3. No inventes competencias.
4. No inventes resultados psicométricos.
5. No modifiques puntajes ni clasificaciones.
6. No realices diagnósticos médicos ni psicológicos.
7. No utilices sexo, edad u otras características personales
   para recomendar contratar o rechazar.
8. No afirmes que una persona miente, manipula, es irresponsable,
   no se toma nada en serio o tiene determinada personalidad,
   salvo que exista evidencia específica y válida en una prueba
   diseñada para evaluar ese aspecto.
9. Si una prueba cuenta con escalas de validez, consistencia,
   sinceridad o respuesta aleatoria, explica únicamente lo que
   esas escalas permitan concluir.
10. Si existen resultados contradictorios entre pruebas,
    explica claramente la diferencia.
11. Cuando existan resultados distintos, puedes señalar causas
    prudentes que convenga verificar, por ejemplo:
    atención, comprensión de instrucciones, velocidad de respuesta,
    cansancio o variabilidad del desempeño.
12. No presentes esas posibles causas como hechos confirmados.
13. No afirmes haber escuchado audios o visto videos.
14. Si existe transcripción, úsala únicamente como texto.
15. No afirmes haber leído documentos. Solo conoces
    nombre, tipo y descripción.
16. Distingue hechos registrados de interpretación de la IA.
17. La decisión definitiva de contratación corresponde a RH.
18. Sí puedes emitir una RECOMENDACIÓN DE CONTINUIDAD:
    - Continuar
    - Continuar con reservas
    - No recomendable continuar por ahora
    - Información insuficiente
19. La recomendación debe estar justificada exclusivamente
    con los datos disponibles.
20. No escribas únicamente "contrastar", "revisar" o "analizar".
    Realiza tú el contraste y explica brevemente qué significa.
21. Resume cada prueba en UNA sola línea:
    nombre + resultado + significado laboral breve.
22. No expliques ampliamente la teoría de las pruebas.
23. No repitas el mismo resultado en varias secciones.
24. Máximo 2 fortalezas.
25. Máximo 2 debilidades o aspectos de atención.
26. La recomendación RH debe ser concreta y accionable.
27. El reporte debe tener IDEALMENTE entre 8 y 10 líneas
    de contenido.
28. NUNCA debe superar 12 líneas de contenido.
29. NUNCA debe superar 160 palabras.
30. Usa frases cortas.
31. No escribas párrafos largos.
32. Cada línea debe aportar información nueva.
33. Si hay más pruebas de las que caben en 12 líneas,
    agrupa resultados similares sin omitir hallazgos importantes.


FORMATO OBLIGATORIO

PREANÁLISIS LABORAL — MIRRORSOUL
Prospecto: ${prospecto.nombre || "No registrado"} | Puesto: ${prospecto.puesto || "No especificado"}

PRUEBAS:
• [Nombre]: [resultado] — [qué significa laboralmente].
• [Nombre]: [resultado] — [qué significa laboralmente].

CONTRASTE:
• [Explica en una sola línea si los resultados son consistentes
  o si existe alguna diferencia importante y qué conviene verificar].

FORTALEZAS:
• [Máximo 2 fortalezas respaldadas].

ASPECTOS DE ATENCIÓN:
• [Máximo 2 debilidades, riesgos o puntos por confirmar].

CONTINUIDAD:
[Continuar / Continuar con reservas / No recomendable continuar por ahora / Información insuficiente] — [motivo breve].

RECOMENDACIÓN RH:
[Una sola acción concreta para el siguiente paso].

IMPORTANTE:
No agregues introducciones.
No agregues conclusión adicional.
No repitas el nombre del prospecto varias veces.
No excedas 12 líneas ni 160 palabras.


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

Tu función es resumir evidencia de procesos
de selección de manera EJECUTIVA.

Tus respuestas deben ser extremadamente breves,
claras, prácticas y fáciles de leer.

Prioriza resultados, significado laboral,
fortalezas, aspectos de atención y siguiente acción.

No repitas información.

No realizas diagnóstico clínico.

No decides definitivamente quién debe ser contratado.

Puedes recomendar si conviene continuar,
continuar con reservas, no continuar por ahora
o indicar información insuficiente.

No inventas información.

No debes utilizar características personales
como sexo o edad para recomendar contratar
o rechazar a una persona.

No atribuyas mentira, manipulación, desinterés,
irresponsabilidad o falta de seriedad sin evidencia
específica de una prueba válida para ese aspecto.

Respeta estrictamente el formato solicitado.

La respuesta debe tener idealmente 8 a 10 líneas,
nunca más de 12 líneas y nunca más de 160 palabras.
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
          700,
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