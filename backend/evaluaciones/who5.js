// ==================================================
// WHO-5
// ÍNDICE DE BIENESTAR
//
// MOTOR DE EVALUACIÓN PARA EMPLEADOS
//
// IMPORTANTE:
// - NO diagnostica.
// - NO toma decisiones laborales.
// - Calcula únicamente el instrumento.
// - RH conserva la decisión administrativa.
// ==================================================


// ==================================================
// IDENTIFICAR WHO-5
// ==================================================

const coincideWHO5 =
  habilitacion => {

    const nombre =
      String(
        habilitacion?.prueba_nombre ||
        ""
      )
        .trim()
        .toLowerCase();


    const version =
      String(
        habilitacion?.version ||
        ""
      )
        .trim()
        .toLowerCase();


    return (
      version === "who-5" ||
      nombre ===
        "who-5 índice de bienestar" ||
      nombre.startsWith(
        "who-5"
      )
    );

  };


// ==================================================
// CALCULAR WHO-5
// ==================================================

const calcularWHO5 =
  async ({
    idHabilitacion,
    connection
  }) => {

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
    // VALIDAR CANTIDAD
    // ==================================================

    if (
      filas.length !== 5
    ) {

      throw new Error(
        `WHO-5 requiere exactamente 5 respuestas válidas. Se encontraron ${filas.length}.`
      );

    }


    // ==================================================
    // VALIDAR ÓRDENES
    // ==================================================

    const ordenes =
      filas.map(
        fila =>
          Number(
            fila.orden
          )
      );


    const ordenesEsperados = [
      1,
      2,
      3,
      4,
      5
    ];


    for (
      const orden
      of ordenesEsperados
    ) {

      const coincidencias =
        ordenes.filter(
          valor =>
            valor === orden
        ).length;


      if (
        coincidencias !== 1
      ) {

        throw new Error(
          `WHO-5 debe contener exactamente una pregunta con orden ${orden}.`
        );

      }

    }


    // ==================================================
    // CALCULAR PUNTAJE BRUTO
    //
    // Cada reactivo:
    // 0 a 5
    //
    // Total:
    // 0 a 25
    // ==================================================

    let puntajeBruto = 0;


    for (
      const fila
      of filas
    ) {

      const valor =
        Number(
          fila.valor_respuesta
        );


      if (
        !Number.isInteger(
          valor
        ) ||
        valor < 0 ||
        valor > 5
      ) {

        throw new Error(
          `La respuesta de la pregunta ${fila.orden} del WHO-5 debe tener un valor entero entre 0 y 5.`
        );

      }


      puntajeBruto +=
        valor;

    }


    // ==================================================
    // ESCALA PORCENTUAL
    //
    // WHO-5:
    // bruto x 4
    //
    // 0 - 100
    // ==================================================

    const puntajePorcentual =
      puntajeBruto * 4;


    // ==================================================
    // INTERPRETACIÓN PREVENTIVA
    //
    // < 13 bruto
    // < 50 porcentual
    //
    // Sugiere revisión adicional.
    //
    // NO equivale a diagnóstico.
    // ==================================================

    const requiereRevision =
      puntajeBruto < 13;


    let nivel;

    let codigoNivel;

    let recomendacionSistema;

    let resultadoTexto;

    let interpretacion;

    let interpretacionLaboral;


    // ==================================================
    // RESULTADO POR DEBAJO DEL PUNTO DE REFERENCIA
    // ==================================================

    if (
      requiereRevision
    ) {

      nivel =
        "Indicadores de bienestar reducido";

      codigoNivel =
        "bienestar_reducido";

      recomendacionSistema =
        "seguimiento";


      resultadoTexto =
        [
          "WHO-5 Índice de Bienestar",
          "",
          `Puntaje bruto: ${puntajeBruto}/25`,
          `Puntaje porcentual: ${puntajePorcentual}/100`,
          "",
          "El resultado se encuentra por debajo del punto de referencia utilizado para sugerir una revisión adicional del bienestar.",
          "",
          "En términos sencillos, esto significa que durante las últimas dos semanas la persona reportó una menor frecuencia de experiencias positivas relacionadas con su bienestar, como buen ánimo, tranquilidad, energía, descanso o interés en sus actividades cotidianas.",
          "",
          "Este resultado corresponde a un instrumento de tamizaje y no constituye diagnóstico médico o psicológico."
        ].join("\n");


      interpretacion =
        "El resultado del WHO-5 muestra indicadores de bienestar reducido dentro del instrumento de tamizaje. En términos sencillos, significa que la persona reportó con menor frecuencia experiencias positivas relacionadas con su bienestar reciente, como sentirse de buen ánimo, tranquila, con energía, descansada o interesada en sus actividades cotidianas. La puntuación sugiere realizar una valoración adicional del bienestar, sin que esto represente por sí mismo un diagnóstico.";


      interpretacionLaboral =
        "El tamizaje muestra indicadores que ameritan revisión preventiva. En términos prácticos, esto puede reflejar que durante las últimas dos semanas la persona ha experimentado menor bienestar general en aspectos como ánimo, energía, descanso, tranquilidad o interés cotidiano. Recursos Humanos puede valorar seguimiento y, cuando corresponda, ofrecer opciones voluntarias de apoyo conforme a las políticas internas.";

    }


    // ==================================================
    // RESULTADO SIN INDICADOR DE REVISIÓN
    // ==================================================

    else {

      nivel =
        "Bienestar sin indicador de revisión por punto de corte";

      codigoNivel =
        "sin_indicador_revision";

      recomendacionSistema =
        "no_requiere";


      resultadoTexto =
        [
          "WHO-5 Índice de Bienestar",
          "",
          `Puntaje bruto: ${puntajeBruto}/25`,
          `Puntaje porcentual: ${puntajePorcentual}/100`,
          "",
          "El resultado no se encuentra por debajo del punto de referencia utilizado para sugerir una revisión adicional.",
          "",
          "En términos sencillos, la persona reportó una frecuencia suficiente de experiencias positivas relacionadas con bienestar reciente, como buen ánimo, tranquilidad, energía, descanso o interés en sus actividades cotidianas.",
          "",
          "Esto no significa que no pueda existir alguna dificultad específica; únicamente indica que el puntaje global del WHO-5 no activa por sí mismo una señal de revisión adicional.",
          "",
          "Este resultado corresponde a un instrumento de tamizaje y no constituye diagnóstico médico o psicológico."
        ].join("\n");


      interpretacion =
        "El resultado del WHO-5 no se encuentra por debajo del punto de referencia utilizado para sugerir una valoración adicional. En términos sencillos, la persona reportó una frecuencia suficiente de experiencias positivas relacionadas con su bienestar reciente, como buen ánimo, tranquilidad, energía, descanso e interés en sus actividades cotidianas. Esto no descarta dificultades específicas y debe interpretarse únicamente como información de tamizaje, no como diagnóstico.";


      interpretacionLaboral =
        "El resultado no activa por sí mismo una recomendación preventiva adicional basada en el punto de referencia del instrumento. En términos prácticos, el nivel global de bienestar reportado no muestra una señal que requiera seguimiento adicional únicamente por WHO-5. Recursos Humanos puede integrarlo con otras fuentes de información laboral cuando sea necesario.";

    }


    // ==================================================
    // RESPUESTA DEL MOTOR
    // ==================================================

    return {

      // ==================================================
      // PUNTAJE PRINCIPAL
      //
      // Se conserva el puntaje bruto 0-25.
      // ==================================================

      puntajeTotal:
        puntajeBruto,


      // ==================================================
      // TEXTOS
      // ==================================================

      resultadoTexto,


      interpretacion,


      interpretacionLaboral,


      // ==================================================
      // DIMENSIONES
      // ==================================================

      dimensiones: {

        bienestar: {

          etiqueta:
            "Bienestar general",

          puntaje_bruto:
            puntajeBruto,

          minimo_bruto:
            0,

          maximo_bruto:
            25,

          puntaje_porcentual:
            puntajePorcentual,

          minimo_porcentual:
            0,

          maximo_porcentual:
            100,

          reactivos:
            5

        }

      },


      // ==================================================
      // METADATA PARA EL SISTEMA
      // ==================================================

      metadata: {

        codigo:
          "WHO-5",

        puntaje_bruto:
          puntajeBruto,

        minimo_bruto:
          0,

        maximo_bruto:
          25,

        puntaje_porcentual:
          puntajePorcentual,

        minimo_porcentual:
          0,

        maximo_porcentual:
          100,

        nivel,

        codigo_nivel:
          codigoNivel,

        punto_referencia_bruto:
          13,

        punto_referencia_porcentual:
          50,

        debajo_punto_referencia:
          requiereRevision,

        recomendacion_sistema:
          recomendacionSistema,

        requiere_revision_rh:
          requiereRevision,

        sugerir_canalizacion:
          false

      }

    };

  };


// ==================================================
// EXPORTAR MOTOR
// ==================================================

export const who5 = {

  codigo:
    "WHO-5",


  coincide:
    coincideWHO5,


  calcular:
    calcularWHO5

};