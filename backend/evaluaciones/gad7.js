// ==================================================
// GAD-7
// TAMIZAJE PREVENTIVO DE INDICADORES DE ANSIEDAD
//
// IMPORTANTE:
// - NO realiza diagnóstico.
// - NO sustituye valoración psicológica.
// - Solo calcula el resultado técnico del instrumento.
// - La pre-evaluación IA se genera después,
//   desde pruebaEmpleadoController.js.
// ==================================================

export const gad7 = {

  // ==================================================
  // IDENTIFICACIÓN DEL INSTRUMENTO
  // ==================================================

  codigo: "GAD-7",

  coincide(habilitacion) {

    const nombre =
      String(
        habilitacion?.prueba_nombre || ""
      )
        .trim()
        .toLowerCase();

    const version =
      String(
        habilitacion?.version || ""
      )
        .trim()
        .toLowerCase();


    return (
      version === "gad-7" ||
      nombre === "gad-7 ansiedad" ||
      nombre.startsWith("gad-7")
    );
  },


  // ==================================================
  // CALCULAR RESULTADO
  // ==================================================

  async calcular({
    idHabilitacion,
    connection
  }) {

    if (
      !Number.isInteger(
        Number(idHabilitacion)
      ) ||
      Number(idHabilitacion) <= 0
    ) {

      throw new Error(
        "ID de habilitación inválido para GAD-7."
      );
    }


    // ==================================================
    // OBTENER RESPUESTAS
    // ==================================================

    const [filas] =
      await connection.query(
        `
          SELECT
            p.id_pregunta_rh,
            p.orden,
            p.texto_pregunta,

            r.valor_respuesta

          FROM respuestas_prueba_empleado r

          INNER JOIN preguntas_prueba_rh p
            ON p.id_pregunta_rh =
               r.id_pregunta_rh

          WHERE
            r.id_habilitacion = ?

            AND p.activo = 1

          ORDER BY
            p.orden ASC,
            p.id_pregunta_rh ASC
        `,
        [
          idHabilitacion
        ]
      );


    // ==================================================
    // GAD-7 DEBE TENER EXACTAMENTE 7 RESPUESTAS
    // ==================================================

    if (filas.length !== 7) {

      throw new Error(
        `GAD-7 requiere exactamente 7 respuestas válidas. Se encontraron ${filas.length}.`
      );
    }


    // ==================================================
    // VALIDAR ORDEN DE REACTIVOS
    // ==================================================

    const ordenes =
      filas.map(
        fila =>
          Number(
            fila.orden
          )
      );


    const ordenesUnicos =
      new Set(
        ordenes
      );


    if (
      ordenesUnicos.size !== 7
    ) {

      throw new Error(
        "GAD-7 contiene reactivos duplicados o con un orden inválido."
      );
    }


    for (
      let orden = 1;
      orden <= 7;
      orden++
    ) {

      if (
        !ordenesUnicos.has(
          orden
        )
      ) {

        throw new Error(
          `GAD-7 no contiene correctamente el reactivo ${orden}.`
        );
      }
    }


    // ==================================================
    // CALCULAR PUNTAJE
    //
    // Cada respuesta:
    // 0 = Nunca
    // 1 = Varios días
    // 2 = Más de la mitad de los días
    // 3 = Casi todos los días
    //
    // Total:
    // 0 - 21
    // ==================================================

    let puntajeTotal = 0;


    for (
      const fila
      of filas
    ) {

      const valor =
        Number(
          fila.valor_respuesta
        );


      if (
        !Number.isInteger(valor) ||
        valor < 0 ||
        valor > 3
      ) {

        throw new Error(
          `GAD-7 contiene una respuesta inválida en el reactivo ${fila.orden}. El valor debe estar entre 0 y 3.`
        );
      }


      puntajeTotal +=
        valor;
    }


    // ==================================================
    // CLASIFICACIÓN PREVENTIVA
    //
    // IMPORTANTE:
    // No usamos esto como diagnóstico.
    // ==================================================

    let nivel =
      "";

    let codigoNivel =
      "";


    if (
      puntajeTotal <= 4
    ) {

      codigoNivel =
        "minimos";

      nivel =
        "Indicadores mínimos";

    } else if (
      puntajeTotal <= 9
    ) {

      codigoNivel =
        "leves";

      nivel =
        "Indicadores leves";

    } else if (
      puntajeTotal <= 14
    ) {

      codigoNivel =
        "moderados";

      nivel =
        "Indicadores moderados";

    } else {

      codigoNivel =
        "elevados";

      nivel =
        "Indicadores elevados";
    }


    // ==================================================
    // RECOMENDACIÓN PREVENTIVA DEL SISTEMA
    //
    // Esta recomendación NO decide por RH.
    // ==================================================

    let recomendacionSistema =
      "no_requiere";


    if (
      puntajeTotal >= 10
    ) {

      recomendacionSistema =
        "canalizacion";

    } else if (
      puntajeTotal >= 5
    ) {

      recomendacionSistema =
        "seguimiento";
    }


    // ==================================================
    // RESULTADO TÉCNICO
    // ==================================================

    const resultadoTexto = [
      "GAD-7 — Tamizaje preventivo",
      "",
      `Puntaje técnico: ${puntajeTotal}/21`,
      `Resultado preventivo: ${nivel}`,
      "",
      "El resultado corresponde a un instrumento de tamizaje.",
      "No constituye diagnóstico médico o psicológico."
    ].join("\n");


    // ==================================================
    // INTERPRETACIÓN TÉCNICA
    // ==================================================

    const interpretacion =
      `El resultado del GAD-7 corresponde a ${nivel.toLowerCase()} dentro de la escala de puntuación del instrumento. El resultado debe utilizarse únicamente como tamizaje preventivo y no como diagnóstico.`;


    // ==================================================
    // INTERPRETACIÓN PARA RH
    // ==================================================

    let interpretacionLaboral =
      "";


    if (
      codigoNivel ===
      "minimos"
    ) {

      interpretacionLaboral =
        "El tamizaje no muestra indicadores relevantes que por sí solos requieran canalización. Recursos Humanos puede mantener las acciones preventivas habituales.";

    } else if (
      codigoNivel ===
      "leves"
    ) {

      interpretacionLaboral =
        "El tamizaje muestra indicadores leves que pueden justificar seguimiento preventivo por Recursos Humanos. La decisión de seguimiento o canalización corresponde a RH.";

    } else if (
      codigoNivel ===
      "moderados"
    ) {

      interpretacionLaboral =
        "El tamizaje muestra indicadores moderados que ameritan revisión preventiva. Recursos Humanos puede valorar la canalización voluntaria con un profesional.";

    } else {

      interpretacionLaboral =
        "El tamizaje muestra indicadores elevados que ameritan atención preventiva. Se recomienda que Recursos Humanos valore oportunamente la canalización con un profesional.";
    }


    // ==================================================
    // DEVOLVER RESULTADO
    // ==================================================

    return {

      instrumento:
        "GAD-7",

      puntajeTotal,

      resultadoTexto,

      interpretacion,

      interpretacionLaboral,

      dimensiones:
        null,

      metadata: {

        codigo:
          "GAD-7",

        puntaje:
          puntajeTotal,

        minimo:
          0,

        maximo:
          21,

        nivel,

        codigo_nivel:
          codigoNivel,

        recomendacion_sistema:
          recomendacionSistema,

        requiere_revision_rh:
          puntajeTotal >= 5,

        sugerir_canalizacion:
          puntajeTotal >= 10
      }
    };
  }
};