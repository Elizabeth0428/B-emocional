import React, {
  useEffect,
  useRef,
  useState
} from "react";

/*
=========================================================
BETA III - SUBPRUEBA 4
OBJETOS EQUIVOCADOS
=========================================================

10.jpg -> ejemplos
11.jpg -> reactivos 1 - 6
12.jpg -> reactivos 7 - 12
13.jpg -> reactivos 13 - 18
14.jpg -> reactivos 19 - 24

Cada reactivo contiene 4 dibujos:

1 = arriba izquierda
2 = arriba derecha
3 = abajo izquierda
4 = abajo derecha

El usuario hace clic directamente
sobre el dibujo que considera equivocado.

La respuesta guardada será:
"1", "2", "3" o "4"

Así puede compararse directamente contra:
reactivos_beta3.respuesta_correcta
=========================================================
*/

const ObjetosBeta3 = ({
  subprueba,
  guardando,
  onTerminar
}) => {
  const [iniciada, setIniciada] =
    useState(false);

  const [finalizada, setFinalizada] =
    useState(false);

  const [indice, setIndice] =
    useState(0);

  const [tiempo, setTiempo] =
    useState(
      Number(
        subprueba?.tiempo_segundos ||
          180
      )
    );

  const [respuestas, setRespuestas] =
    useState({});

  const finalizandoRef =
    useRef(false);

  const avanceRef =
    useRef(null);

  const reactivos =
    Array.isArray(
      subprueba?.reactivos
    )
      ? subprueba.reactivos
      : [];

  // ==================================================
  // EJEMPLOS / RESPONDIBLES
  // ==================================================

  const ejemplos =
    reactivos.filter(
      (reactivo) =>
        Number(
          reactivo.es_ejemplo
        ) === 1
    );

  const respondibles =
    reactivos
      .filter(
        (reactivo) =>
          Number(
            reactivo.es_ejemplo
          ) !== 1
      )
      .sort(
        (a, b) =>
          Number(a.numero) -
          Number(b.numero)
      );

  const reactivoActual =
    respondibles[indice] ||
    null;

  // ==================================================
  // LIMPIEZA
  // ==================================================

  useEffect(() => {
    return () => {
      if (avanceRef.current) {
        window.clearTimeout(
          avanceRef.current
        );
      }
    };
  }, []);

  // ==================================================
  // CRONÓMETRO
  // ==================================================

  useEffect(() => {
    if (
      !iniciada ||
      finalizada
    ) {
      return;
    }

    if (tiempo <= 0) {
      terminar();
      return;
    }

    const timer =
      window.setTimeout(
        () => {
          setTiempo(
            (prev) =>
              Math.max(
                0,
                prev - 1
              )
          );
        },
        1000
      );

    return () =>
      window.clearTimeout(
        timer
      );
  }, [
    iniciada,
    finalizada,
    tiempo
  ]);

  // ==================================================
  // FORMATO DE TIEMPO
  // ==================================================

  const formatearTiempo =
    (segundos) => {
      const minutos =
        Math.floor(
          segundos / 60
        );

      const resto =
        segundos % 60;

      return `${String(
        minutos
      ).padStart(
        2,
        "0"
      )}:${String(
        resto
      ).padStart(
        2,
        "0"
      )}`;
    };

  // ==================================================
  // MOVER ÍNDICE SEGURO
  // ==================================================

  const moverIndice =
    (nuevoIndice) => {
      const ultimo =
        Math.max(
          0,
          respondibles.length - 1
        );

      setIndice(
        Math.min(
          Math.max(
            nuevoIndice,
            0
          ),
          ultimo
        )
      );
    };

  // ==================================================
  // COMENZAR
  // ==================================================

  const comenzar = () => {
    moverIndice(0);
    setIniciada(true);
  };

  // ==================================================
  // RESPONDER
  // ==================================================

  const responderObjeto = (
    opcion
  ) => {
    if (
      !reactivoActual ||
      !iniciada ||
      finalizada ||
      tiempo <= 0
    ) {
      return;
    }

    const respuesta =
      String(opcion);

    setRespuestas(
      (prev) => ({
        ...prev,

        [
          reactivoActual
            .id_reactivo_beta3
        ]: {
          id_reactivo_beta3:
            Number(
              reactivoActual
                .id_reactivo_beta3
            ),

          respuesta
        }
      })
    );

    if (avanceRef.current) {
      window.clearTimeout(
        avanceRef.current
      );
    }

    if (
      indice <
      respondibles.length - 1
    ) {
      avanceRef.current =
        window.setTimeout(
          () => {
            setIndice(
              (prev) =>
                Math.min(
                  prev + 1,
                  respondibles.length - 1
                )
            );
          },
          250
        );
    }
  };

  // ==================================================
  // NAVEGACIÓN
  // ==================================================

  const siguiente = () => {
    if (avanceRef.current) {
      window.clearTimeout(
        avanceRef.current
      );

      avanceRef.current = null;
    }

    moverIndice(
      indice + 1
    );
  };

  const anterior = () => {
    if (avanceRef.current) {
      window.clearTimeout(
        avanceRef.current
      );

      avanceRef.current = null;
    }

    moverIndice(
      indice - 1
    );
  };

  // ==================================================
  // PREPARAR RESPUESTAS
  // ==================================================

  const prepararRespuestas =
    () => {
      return Object.values(
        respuestas
      );
    };

  // ==================================================
  // TERMINAR
  // ==================================================

  const terminar =
    async () => {
      if (
        finalizandoRef.current ||
        finalizada
      ) {
        return;
      }

      if (avanceRef.current) {
        window.clearTimeout(
          avanceRef.current
        );

        avanceRef.current = null;
      }

      finalizandoRef.current =
        true;

      setFinalizada(true);

      try {
        await onTerminar(
          prepararRespuestas()
        );

      } finally {
        finalizandoRef.current =
          false;
      }
    };

  // ==================================================
  // SIN REACTIVOS
  // ==================================================

  if (!reactivos.length) {
    return (
      <div style={styles.card}>
        <h2>
          Objetos equivocados
        </h2>

        <p>
          No hay reactivos disponibles.
        </p>
      </div>
    );
  }

  // ==================================================
  // INTRODUCCIÓN
  // ==================================================

  if (!iniciada) {
    return (
      <div style={styles.card}>

        <div style={styles.header}>

          <div>
            <div style={styles.code}>
              SUBPRUEBA 4
            </div>

            <h2 style={styles.title}>
              Objetos equivocados
            </h2>
          </div>

          <div style={styles.timer}>
            ⏱{" "}

            {formatearTiempo(
              Number(
                subprueba
                  ?.tiempo_segundos ||
                  180
              )
            )}
          </div>

        </div>

        <div
          style={
            styles.instructions
          }
        >

          <h3>
            Instrucciones
          </h3>

          <p>
            En cada ejercicio verás
            cuatro dibujos relacionados.
          </p>

          <p>
            Uno de ellos representa algo
            incorrecto, equivocado o que
            no corresponde con los demás.
          </p>

          <p>
            Haz clic directamente sobre
            el dibujo que consideras
            equivocado.
          </p>

          <div style={styles.demo}>

            <div style={styles.demoGrid}>
              <span>1</span>
              <span>2</span>
              <span>3</span>
              <span>4</span>
            </div>

            <strong>
              Selecciona el dibujo
              equivocado
            </strong>

          </div>

          <div
            style={
              styles.important
            }
          >
            Tendrás{" "}

            <strong>
              {formatearTiempo(
                Number(
                  subprueba
                    ?.tiempo_segundos ||
                    180
                )
              )}
            </strong>{" "}

            para responder tantos
            ejercicios como puedas.
          </div>

        </div>

        {ejemplos.length > 0 && (
          <div
            style={
              styles.exampleCard
            }
          >
            <strong>
              Ejemplo
            </strong>

            <p>
              Observa los cuatro dibujos
              e identifica cuál representa
              la acción u objeto
              equivocado.
            </p>
          </div>
        )}

        <button
          type="button"
          style={styles.startButton}
          onClick={comenzar}
        >
          ▶ Comenzar subprueba
        </button>

      </div>
    );
  }

  // ==================================================
  // FINALIZADA
  // ==================================================

  if (finalizada) {
    return (
      <div style={styles.card}>

        <div
          style={
            styles.finishedIcon
          }
        >
          ✅
        </div>

        <h2
          style={
            styles.finishedTitle
          }
        >
          Objetos equivocados terminada
        </h2>

        <p
          style={
            styles.finishedText
          }
        >
          Se registraron{" "}

          {
            Object.keys(
              respuestas
            ).length
          }{" "}

          respuestas.
        </p>

      </div>
    );
  }

  // ==================================================
  // DATOS ACTUALES
  // ==================================================

  const numero =
    Number(
      reactivoActual?.numero ||
        0
    );

  const respuestaActual =
    reactivoActual
      ? respuestas[
          reactivoActual
            .id_reactivo_beta3
        ]?.respuesta
      : null;

  const respondidas =
    Object.keys(
      respuestas
    ).length;

  const progreso =
    respondibles.length
      ? Math.round(
          (
            respondidas /
            respondibles.length
          ) * 100
        )
      : 0;

  const esUltimo =
    indice ===
    respondibles.length - 1;

  // ==================================================
  // VISTA
  // ==================================================

  return (
    <div style={styles.card}>

      <div style={styles.header}>

        <div>

          <div style={styles.code}>
            SUBPRUEBA 4
          </div>

          <h2 style={styles.title}>
            Objetos equivocados
          </h2>

          <div
            style={
              styles.progressText
            }
          >
            {respondidas} de{" "}
            {respondibles.length}{" "}
            respondidos
          </div>

        </div>

        <div
          style={{
            ...styles.timer,

            ...(tiempo <= 30
              ? styles.timerWarning
              : {})
          }}
        >
          ⏱{" "}
          {formatearTiempo(
            tiempo
          )}
        </div>

      </div>

      {/* PROGRESO */}

      <div
        style={
          styles.progressTrack
        }
      >
        <div
          style={{
            ...styles.progressFill,

            width:
              `${progreso}%`
          }}
        />
      </div>

      {/* REACTIVO */}

      <div
        style={
          styles.questionTop
        }
      >

        <div>

          <div
            style={
              styles.smallLabel
            }
          >
            OBJETOS
          </div>

          <h3
            style={
              styles.questionTitle
            }
          >
            Reactivo {numero}
          </h3>

        </div>

        <div
          style={
            styles.counter
          }
        >
          {Math.min(
            indice + 1,
            respondibles.length
          )}

          <span>
            /{respondibles.length}
          </span>
        </div>

      </div>

      <div
        style={
          styles.instruction
        }
      >
        Haz clic sobre el dibujo
        que consideras equivocado.
      </div>

      {/* REACTIVO RECORTADO */}

      <RecorteObjetoBeta3
        numero={numero}
        respuestaActual={
          respuestaActual
        }
        onResponder={
          responderObjeto
        }
      />

      {respuestaActual && (
        <div
          style={
            styles.selected
          }
        >
          ✓ Respuesta registrada:
          {" "}

          <strong>
            opción {respuestaActual}
          </strong>
        </div>
      )}

      {/* BOTONES */}

      <div style={styles.actions}>

        <button
          type="button"

          disabled={
            indice === 0 ||
            guardando
          }

          onClick={
            anterior
          }

          style={{
            ...styles.backButton,

            ...(indice === 0
              ? styles.disabled
              : {})
          }}
        >
          ← Anterior
        </button>

        {!esUltimo ? (

          <button
            type="button"

            disabled={
              guardando
            }

            onClick={
              siguiente
            }

            style={
              styles.nextButton
            }
          >
            Siguiente →
          </button>

        ) : (

          <button
            type="button"

            disabled={
              guardando
            }

            onClick={
              terminar
            }

            style={
              styles.finishButton
            }
          >
            {guardando
              ? "Guardando..."
              : "Terminar subprueba"}
          </button>

        )}

      </div>

      {/* NAVEGADOR */}

      <div
        style={
          styles.navigator
        }
      >

        {respondibles.map(
          (
            reactivo,
            i
          ) => {
            const contestado =
              Boolean(
                respuestas[
                  reactivo
                    .id_reactivo_beta3
                ]
              );

            const actual =
              i === indice;

            return (
              <button
                type="button"

                key={
                  reactivo
                    .id_reactivo_beta3
                }

                onClick={() => {

                  if (
                    avanceRef.current
                  ) {
                    window.clearTimeout(
                      avanceRef.current
                    );

                    avanceRef.current =
                      null;
                  }

                  moverIndice(i);
                }}

                style={{
                  ...styles.navigatorButton,

                  ...(contestado
                    ? styles.navigatorAnswered
                    : {}),

                  ...(actual
                    ? styles.navigatorCurrent
                    : {})
                }}
              >
                {reactivo.numero}
              </button>
            );
          }
        )}

      </div>

    </div>
  );
};

// ==================================================
// RECORTE DEL REACTIVO
// ==================================================

const RecorteObjetoBeta3 = ({
  numero,
  respuestaActual,
  onResponder
}) => {

  const obtenerRecorte = () => {
    /*
    =====================================================
    DISTRIBUCIÓN

    11.jpg
    izquierda -> 1,2,3
    derecha   -> 4,5,6

    12.jpg
    izquierda -> 7,8,9
    derecha   -> 10,11,12

    13.jpg
    izquierda -> 13,14,15
    derecha   -> 16,17,18

    14.jpg
    izquierda -> 19,20,21
    derecha   -> 22,23,24
    =====================================================
    */

    let pagina;
    let local;

    if (
      numero >= 1 &&
      numero <= 6
    ) {
      pagina = 11;
      local = numero;

    } else if (
      numero >= 7 &&
      numero <= 12
    ) {
      pagina = 12;
      local =
        numero - 6;

    } else if (
      numero >= 13 &&
      numero <= 18
    ) {
      pagina = 13;
      local =
        numero - 12;

    } else if (
      numero >= 19 &&
      numero <= 24
    ) {
      pagina = 14;
      local =
        numero - 18;

    } else {
      return null;
    }

    const derecha =
      local >= 4;

    const fila =
      derecha
        ? local - 4
        : local - 1;

    const configuraciones = {
      11: {
        xIzq: 150,
        xDer: 920,
        y: 125,
        pasoY: 675,
        width: 670,
        height: 650
      },

      12: {
        xIzq: 145,
        xDer: 915,
        y: 125,
        pasoY: 690,
        width: 680,
        height: 660
      },

      13: {
        xIzq: 145,
        xDer: 920,
        y: 120,
        pasoY: 675,
        width: 675,
        height: 650
      },

      14: {
        xIzq: 150,
        xDer: 930,
        y: 115,
        pasoY: 680,
        width: 680,
        height: 655
      }
    };

    const config =
      configuraciones[
        pagina
      ];

    return {
      pagina,

      imagen:
        `/beta3/${pagina}.jpg`,

      x:
        derecha
          ? config.xDer
          : config.xIzq,

      y:
        config.y +
        fila *
          config.pasoY,

      width:
        config.width,

      height:
        config.height
    };
  };

  const recorte =
    obtenerRecorte();

  if (!recorte) {
    return (
      <div style={styles.noImage}>
        No se encontró el reactivo.
      </div>
    );
  }

  // ==================================================
  // OPCIÓN SELECCIONADA
  // ==================================================

  const opcionSeleccionada =
    Number(
      respuestaActual
    );

  // ==================================================
  // COORDENADAS VISUALES DE CADA OPCIÓN
  // ==================================================

  const obtenerZonaOpcion =
    (opcion) => {

      const mitadX =
        recorte.x +
        recorte.width / 2;

      const mitadY =
        recorte.y +
        recorte.height / 2;

      const margenX =
        recorte.width * 0.035;

      const margenY =
        recorte.height * 0.035;

      switch (
        Number(opcion)
      ) {
        case 1:
          return {
            x:
              recorte.x +
              margenX,

            y:
              recorte.y +
              margenY,

            width:
              recorte.width / 2 -
              margenX * 2,

            height:
              recorte.height / 2 -
              margenY * 2
          };

        case 2:
          return {
            x:
              mitadX +
              margenX,

            y:
              recorte.y +
              margenY,

            width:
              recorte.width / 2 -
              margenX * 2,

            height:
              recorte.height / 2 -
              margenY * 2
          };

        case 3:
          return {
            x:
              recorte.x +
              margenX,

            y:
              mitadY +
              margenY,

            width:
              recorte.width / 2 -
              margenX * 2,

            height:
              recorte.height / 2 -
              margenY * 2
          };

        case 4:
          return {
            x:
              mitadX +
              margenX,

            y:
              mitadY +
              margenY,

            width:
              recorte.width / 2 -
              margenX * 2,

            height:
              recorte.height / 2 -
              margenY * 2
          };

        default:
          return null;
      }
    };

  const zonaSeleccionada =
    obtenerZonaOpcion(
      opcionSeleccionada
    );

  // ==================================================
  // CLIC
  // ==================================================

  const seleccionar =
    (event) => {

      const svg =
        event.currentTarget;

      const rect =
        svg
          .getBoundingClientRect();

      const localX =
        (
          event.clientX -
          rect.left
        ) /
        rect.width;

      const localY =
        (
          event.clientY -
          rect.top
        ) /
        rect.height;

      /*
      ==================================================
      CONVERTIR CLIC EN OPCIÓN

      superior izquierda = 1
      superior derecha   = 2
      inferior izquierda = 3
      inferior derecha   = 4
      ==================================================
      */

      let opcion;

      if (
        localY < 0.5
      ) {
        opcion =
          localX < 0.5
            ? 1
            : 2;
      } else {
        opcion =
          localX < 0.5
            ? 3
            : 4;
      }

      onResponder(
        opcion
      );
    };

  // ==================================================
  // VISTA
  // ==================================================

  return (
    <div
      style={
        styles.objectCard
      }
    >

      <svg
        viewBox={
          `${recorte.x} ${recorte.y} ${recorte.width} ${recorte.height}`
        }

        preserveAspectRatio=
          "xMidYMid meet"

        onClick={
          seleccionar
        }

        style={
          styles.objectSvg
        }
      >

        <image
          href={
            recorte.imagen
          }

          x="0"
          y="0"

          width="1824"
          height="2362"

          preserveAspectRatio=
            "none"
        />

        {/* MARCADOR DE LA OPCIÓN ELEGIDA */}

        {zonaSeleccionada && (

          <rect
            x={
              zonaSeleccionada.x
            }

            y={
              zonaSeleccionada.y
            }

            width={
              zonaSeleccionada.width
            }

            height={
              zonaSeleccionada.height
            }

            rx="25"

            fill=
              "rgba(49,87,166,.08)"

            stroke="#3157a6"

            strokeWidth="8"
          />

        )}

      </svg>

      <div
        style={
          styles.clickHelp
        }
      >
        👆 Haz clic sobre el
        dibujo equivocado.
      </div>

    </div>
  );
};

// ==================================================
// ESTILOS
// ==================================================

const styles = {
  card: {
    background:
      "#ffffff",

    borderRadius:
      "20px",

    padding:
      "28px",

    boxShadow:
      "0 4px 20px rgba(0,0,0,.06)"
  },

  header: {
    display:
      "flex",

    justifyContent:
      "space-between",

    alignItems:
      "center",

    gap:
      "20px",

    marginBottom:
      "20px"
  },

  code: {
    color:
      "#3157a6",

    fontSize:
      "12px",

    fontWeight:
      "900",

    letterSpacing:
      "1px"
  },

  title: {
    margin:
      "5px 0",

    color:
      "#101828"
  },

  progressText: {
    color:
      "#667085",

    fontSize:
      "13px"
  },

  timer: {
    fontSize:
      "28px",

    fontWeight:
      "900",

    color:
      "#3157a6",

    whiteSpace:
      "nowrap"
  },

  timerWarning: {
    color:
      "#b42318"
  },

  instructions: {
    background:
      "#f8fafc",

    border:
      "1px solid #e4e7ec",

    borderRadius:
      "14px",

    padding:
      "22px",

    lineHeight:
      "1.65",

    color:
      "#475467"
  },

  important: {
    marginTop:
      "18px",

    padding:
      "14px",

    background:
      "#eef4ff",

    border:
      "1px solid #b9ccff",

    borderRadius:
      "10px"
  },

  demo: {
    margin:
      "20px 0",

    display:
      "flex",

    flexDirection:
      "column",

    alignItems:
      "center",

    gap:
      "12px"
  },

  demoGrid: {
    width:
      "200px",

    display:
      "grid",

    gridTemplateColumns:
      "repeat(2,1fr)",

    gap:
      "8px",

    fontSize:
      "24px",

    fontWeight:
      "900",

    textAlign:
      "center",

    color:
      "#3157a6"
  },

  exampleCard: {
    marginTop:
      "20px",

    padding:
      "18px",

    border:
      "1px solid #e4e7ec",

    borderRadius:
      "14px",

    textAlign:
      "center"
  },

  startButton: {
    display:
      "block",

    margin:
      "22px auto 0",

    border:
      "none",

    borderRadius:
      "12px",

    background:
      "#3157a6",

    color:
      "#ffffff",

    padding:
      "14px 30px",

    fontSize:
      "16px",

    fontWeight:
      "900",

    cursor:
      "pointer"
  },

  progressTrack: {
    height:
      "9px",

    background:
      "#eaecf0",

    borderRadius:
      "999px",

    overflow:
      "hidden",

    marginBottom:
      "22px"
  },

  progressFill: {
    height:
      "100%",

    background:
      "#3157a6",

    borderRadius:
      "999px"
  },

  questionTop: {
    display:
      "flex",

    justifyContent:
      "space-between",

    alignItems:
      "center"
  },

  smallLabel: {
    color:
      "#3157a6",

    fontSize:
      "11px",

    fontWeight:
      "900"
  },

  questionTitle: {
    margin:
      "4px 0 0",

    fontSize:
      "23px"
  },

  counter: {
    color:
      "#3157a6",

    fontSize:
      "25px",

    fontWeight:
      "900"
  },

  instruction: {
    textAlign:
      "center",

    margin:
      "20px 0 15px",

    color:
      "#475467",

    fontWeight:
      "700"
  },

  objectCard: {
    width:
      "100%",

    maxWidth:
      "650px",

    margin:
      "0 auto",

    textAlign:
      "center"
  },

  objectSvg: {
    width:
      "100%",

    maxHeight:
      "510px",

    display:
      "block",

    margin:
      "0 auto",

    border:
      "1px solid #e4e7ec",

    borderRadius:
      "14px",

    background:
      "#ffffff",

    cursor:
      "pointer",

    boxSizing:
      "border-box"
  },

  clickHelp: {
    marginTop:
      "10px",

    color:
      "#667085",

    fontSize:
      "13px"
  },

  noImage: {
    minHeight:
      "280px",

    border:
      "1px dashed #d0d5dd",

    borderRadius:
      "14px",

    display:
      "flex",

    justifyContent:
      "center",

    alignItems:
      "center",

    color:
      "#667085"
  },

  selected: {
    marginTop:
      "12px",

    color:
      "#027a48",

    textAlign:
      "center",

    fontWeight:
      "700"
  },

  actions: {
    display:
      "flex",

    justifyContent:
      "space-between",

    gap:
      "12px",

    marginTop:
      "24px",

    paddingTop:
      "18px",

    borderTop:
      "1px solid #eaecf0"
  },

  backButton: {
    border:
      "1px solid #d0d5dd",

    background:
      "#ffffff",

    borderRadius:
      "10px",

    padding:
      "12px 20px",

    fontWeight:
      "800",

    cursor:
      "pointer"
  },

  nextButton: {
    border:
      "none",

    background:
      "#3157a6",

    color:
      "#ffffff",

    borderRadius:
      "10px",

    padding:
      "12px 22px",

    fontWeight:
      "800",

    cursor:
      "pointer"
  },

  finishButton: {
    border:
      "none",

    background:
      "#1570ef",

    color:
      "#ffffff",

    borderRadius:
      "10px",

    padding:
      "12px 22px",

    fontWeight:
      "800",

    cursor:
      "pointer"
  },

  disabled: {
    opacity:
      0.45,

    cursor:
      "not-allowed"
  },

  navigator: {
    display:
      "grid",

    gridTemplateColumns:
      "repeat(auto-fit,minmax(42px,1fr))",

    gap:
      "6px",

    marginTop:
      "22px"
  },

  navigatorButton: {
    minHeight:
      "38px",

    border:
      "1px solid #e4e7ec",

    borderRadius:
      "8px",

    background:
      "#ffffff",

    color:
      "#667085",

    fontWeight:
      "700",

    cursor:
      "pointer"
  },

  navigatorAnswered: {
    background:
      "#ecfdf3",

    border:
      "1px solid #abefc6",

    color:
      "#027a48"
  },

  navigatorCurrent: {
    border:
      "2px solid #3157a6",

    color:
      "#3157a6"
  },

  finishedIcon: {
    fontSize:
      "52px",

    textAlign:
      "center"
  },

  finishedTitle: {
    textAlign:
      "center"
  },

  finishedText: {
    textAlign:
      "center",

    color:
      "#667085"
  }
};

export default ObjetosBeta3;