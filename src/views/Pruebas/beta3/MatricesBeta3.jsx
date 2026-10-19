import React, {
  useEffect,
  useRef,
  useState
} from "react";

const ANCHO_LAMINA = 1824;
const ALTO_LAMINA = 2362;

const MatricesBeta3 = ({
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
        300
      )
    );

  const [respuestas, setRespuestas] =
    useState({});

  const [aviso, setAviso] =
    useState("");

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
  // LIMPIAR AVANCE
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
      terminar(true);
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
  // FORMATEAR TIEMPO
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
    setAviso("");
    moverIndice(0);
    setIniciada(true);
  };

  // ==================================================
  // RESPONDER
  // ==================================================

  const responder = (
    reactivo,
    opcion
  ) => {
    if (
      !reactivo ||
      !iniciada ||
      finalizada ||
      tiempo <= 0
    ) {
      return;
    }

    setAviso("");

    setRespuestas(
      (prev) => ({
        ...prev,

        [
          reactivo
            .id_reactivo_beta3
        ]: {
          id_reactivo_beta3:
            Number(
              reactivo
                .id_reactivo_beta3
            ),

          respuesta:
            String(opcion)
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
          220
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

    setAviso("");

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

    setAviso("");

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
  // porTiempo = true:
  // guarda lo que alcanzó a responder.
  //
  // porTiempo = false:
  // exige todos los reactivos contestados.
  // ==================================================

  const terminar =
    async (porTiempo = false) => {
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

      const respuestasPreparadas =
        prepararRespuestas();

      const respondidas =
        respuestasPreparadas.length;

      // ----------------------------------------------
      // TERMINACIÓN MANUAL
      // ----------------------------------------------

      if (!porTiempo) {
        if (
          respondidas <
          respondibles.length
        ) {
          const faltantes =
            respondibles.length -
            respondidas;

          setAviso(
            `Aún faltan ${faltantes} reactivo${faltantes === 1 ? "" : "s"} por responder.`
          );

          return;
        }
      }

      // ----------------------------------------------
      // TIEMPO AGOTADO SIN NINGUNA RESPUESTA
      // ----------------------------------------------

      if (
        porTiempo &&
        respondidas === 0
      ) {
        setAviso(
          "El tiempo terminó y no se registró ninguna respuesta."
        );

        return;
      }

      finalizandoRef.current =
        true;

      setAviso("");

      try {
        const guardado =
          await onTerminar(
            respuestasPreparadas
          );

        // Solo mostramos "Terminada"
        // si Beta3RH confirmó el guardado.
        if (guardado === true) {
          setFinalizada(true);
        } else {
          setAviso(
            "No fue posible guardar la subprueba. Revisa el mensaje mostrado arriba."
          );
        }

      } catch (error) {
        console.error(
          "❌ Error terminando Matrices:",
          error
        );

        setAviso(
          "No fue posible guardar la subprueba."
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
          Matrices
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
              SUBPRUEBA 5
            </div>

            <h2 style={styles.title}>
              Matrices
            </h2>
          </div>

          <div style={styles.timer}>
            ⏱{" "}

            {formatearTiempo(
              Number(
                subprueba
                  ?.tiempo_segundos ||
                300
              )
            )}
          </div>

        </div>

        <div style={styles.instructions}>

          <h3>
            Instrucciones
          </h3>

          <p>
            Observa cuidadosamente
            cada matriz.
          </p>

          <p>
            En cada ejercicio falta
            una figura.
          </p>

          <p>
            Selecciona entre las cinco
            opciones la figura que
            completa correctamente
            la matriz.
          </p>

          <div style={styles.demo}>

            <div style={styles.demoMatrix}>
              <span>◻</span>
              <span>◻</span>
              <span>?</span>
              <span>◻</span>
            </div>

            <div style={styles.demoArrow}>
              →
            </div>

            <div style={styles.demoOptions}>
              1 &nbsp; 2 &nbsp; 3 &nbsp; 4 &nbsp; 5
            </div>

          </div>

          <div style={styles.important}>
            Tendrás{" "}

            <strong>
              {formatearTiempo(
                Number(
                  subprueba
                    ?.tiempo_segundos ||
                  300
                )
              )}
            </strong>{" "}

            para responder tantos
            ejercicios como puedas.
          </div>

        </div>

        {ejemplos.length > 0 && (
          <div style={styles.exampleCard}>

            <strong>
              Ejemplo
            </strong>

            <p>
              Identifica el patrón
              de la matriz y selecciona
              la opción correcta.
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

        <div style={styles.finishedIcon}>
          ✅
        </div>

        <h2 style={styles.finishedTitle}>
          Matrices terminada
        </h2>

        <p style={styles.finishedText}>
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

  const faltantes =
    Math.max(
      0,
      respondibles.length -
      respondidas
    );

  // ==================================================
  // VISTA
  // ==================================================

  return (
    <div style={styles.card}>

      <div style={styles.header}>

        <div>

          <div style={styles.code}>
            SUBPRUEBA 5
          </div>

          <h2 style={styles.title}>
            Matrices
          </h2>

          <div style={styles.progressText}>
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

      <div style={styles.progressTrack}>

        <div
          style={{
            ...styles.progressFill,

            width:
              `${progreso}%`
          }}
        />

      </div>

      {/* REACTIVO */}

      <div style={styles.questionTop}>

        <div>

          <div style={styles.smallLabel}>
            MATRICES
          </div>

          <h3 style={styles.questionTitle}>
            Reactivo {numero}
          </h3>

        </div>

        <div style={styles.counter}>
          {Math.min(
            indice + 1,
            respondibles.length
          )}

          <span>
            /{respondibles.length}
          </span>
        </div>

      </div>

      <div style={styles.instruction}>
        Selecciona la opción que
        completa correctamente
        la matriz.
      </div>

      {/* MATRIZ */}

      <RecorteMatrizBeta3
        numero={numero}
      />

      {/* OPCIONES 1 - 5 */}

      <div style={styles.options}>

        {[1, 2, 3, 4, 5].map(
          (opcion) => (

            <button
              key={opcion}
              type="button"

              disabled={
                guardando ||
                tiempo <= 0
              }

              onClick={() =>
                responder(
                  reactivoActual,
                  opcion
                )
              }

              style={{
                ...styles.optionButton,

                ...(String(
                  respuestaActual
                ) ===
                String(opcion)
                  ? styles.optionSelected
                  : {})
              }}
            >
              {opcion}
            </button>

          )
        )}

      </div>

      {respuestaActual && (
        <div style={styles.selected}>
          ✓ Respuesta registrada:{" "}

          <strong>
            opción {respuestaActual}
          </strong>
        </div>
      )}

      {/* AVISO LOCAL */}

      {aviso && (
        <div style={styles.warning}>
          ⚠️ {aviso}
        </div>
      )}

      {/* NAVEGACIÓN */}

      <div style={styles.actions}>

        <button
          type="button"

          disabled={
            indice === 0 ||
            guardando
          }

          onClick={anterior}

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

            disabled={guardando}

            onClick={siguiente}

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
              guardando ||
              finalizandoRef.current
            }

            onClick={() =>
              terminar(false)
            }

            style={
              styles.finishButton
            }
          >
            {guardando
              ? "Guardando..."
              : faltantes > 0
                ? `Faltan ${faltantes}`
                : "Terminar subprueba"}
          </button>

        )}

      </div>

      {/* NAVEGADOR */}

      <div style={styles.navigator}>

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

                  setAviso("");
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
// RECORTE DE CADA MATRIZ
// ==================================================

const RecorteMatrizBeta3 = ({
  numero
}) => {
  /*
  =====================================================
  DISTRIBUCIÓN

  16.jpg -> 1 - 5
  17.jpg -> 6 - 10
  18.jpg -> 11 - 15
  19.jpg -> 16 - 20
  20.jpg -> 21 - 25
  =====================================================
  */

  let pagina;
  let fila;

  if (
    numero >= 1 &&
    numero <= 5
  ) {
    pagina = 16;
    fila = numero - 1;

  } else if (
    numero >= 6 &&
    numero <= 10
  ) {
    pagina = 17;
    fila = numero - 6;

  } else if (
    numero >= 11 &&
    numero <= 15
  ) {
    pagina = 18;
    fila = numero - 11;

  } else if (
    numero >= 16 &&
    numero <= 20
  ) {
    pagina = 19;
    fila = numero - 16;

  } else if (
    numero >= 21 &&
    numero <= 25
  ) {
    pagina = 20;
    fila = numero - 21;

  } else {
    return (
      <div style={styles.noImage}>
        No se encontró el reactivo.
      </div>
    );
  }

  const recorte = {
    x: 120,

    y:
      130 +
      fila * 410,

    width: 1550,

    height: 390
  };

  return (
    <div style={styles.matrixCard}>

      <svg
        viewBox={
          `${recorte.x} ${recorte.y} ${recorte.width} ${recorte.height}`
        }

        preserveAspectRatio=
          "xMidYMid meet"

        style={
          styles.matrixSvg
        }
      >

        <image
          href={
            `/beta3/${pagina}.jpg`
          }

          x="0"
          y="0"

          width={
            ANCHO_LAMINA
          }

          height={
            ALTO_LAMINA
          }

          preserveAspectRatio=
            "none"
        />

      </svg>

    </div>
  );
};

// ==================================================
// ESTILOS
// ==================================================

const styles = {
  card: {
    background: "#ffffff",
    borderRadius: "20px",
    padding: "28px",
    boxShadow:
      "0 4px 20px rgba(0,0,0,.06)"
  },

  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: "20px",
    marginBottom: "20px"
  },

  code: {
    color: "#3157a6",
    fontSize: "12px",
    fontWeight: "900",
    letterSpacing: "1px"
  },

  title: {
    margin: "5px 0",
    color: "#101828"
  },

  progressText: {
    color: "#667085",
    fontSize: "13px"
  },

  timer: {
    fontSize: "28px",
    fontWeight: "900",
    color: "#3157a6",
    whiteSpace: "nowrap"
  },

  timerWarning: {
    color: "#b42318"
  },

  instructions: {
    background: "#f8fafc",
    border:
      "1px solid #e4e7ec",
    borderRadius: "14px",
    padding: "22px",
    lineHeight: "1.65",
    color: "#475467"
  },

  important: {
    marginTop: "18px",
    padding: "14px",
    background: "#eef4ff",
    border:
      "1px solid #b9ccff",
    borderRadius: "10px"
  },

  demo: {
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    gap: "20px",
    margin: "20px 0",
    flexWrap: "wrap"
  },

  demoMatrix: {
    display: "grid",
    gridTemplateColumns:
      "repeat(2,45px)",
    gridTemplateRows:
      "repeat(2,45px)",
    gap: "4px",
    fontSize: "25px",
    textAlign: "center",
    alignItems: "center",
    justifyContent: "center"
  },

  demoArrow: {
    fontSize: "25px"
  },

  demoOptions: {
    fontWeight: "800",
    color: "#3157a6"
  },

  exampleCard: {
    marginTop: "20px",
    padding: "18px",
    border:
      "1px solid #e4e7ec",
    borderRadius: "14px",
    textAlign: "center"
  },

  startButton: {
    display: "block",
    margin: "22px auto 0",
    border: "none",
    borderRadius: "12px",
    background: "#3157a6",
    color: "#ffffff",
    padding: "14px 30px",
    fontSize: "16px",
    fontWeight: "900",
    cursor: "pointer"
  },

  progressTrack: {
    height: "9px",
    borderRadius: "999px",
    background: "#eaecf0",
    overflow: "hidden",
    marginBottom: "22px"
  },

  progressFill: {
    height: "100%",
    background: "#3157a6",
    borderRadius: "999px"
  },

  questionTop: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center"
  },

  smallLabel: {
    color: "#3157a6",
    fontSize: "11px",
    fontWeight: "900"
  },

  questionTitle: {
    margin: "4px 0 0",
    fontSize: "23px"
  },

  counter: {
    color: "#3157a6",
    fontSize: "25px",
    fontWeight: "900"
  },

  instruction: {
    textAlign: "center",
    color: "#475467",
    fontWeight: "700",
    margin: "20px 0 15px"
  },

  matrixCard: {
    width: "100%",
    maxWidth: "900px",
    margin: "0 auto",
    border:
      "1px solid #e4e7ec",
    borderRadius: "14px",
    background: "#ffffff",
    padding: "12px",
    boxSizing: "border-box",
    overflow: "hidden"
  },

  matrixSvg: {
    width: "100%",
    maxHeight: "360px",
    display: "block",
    userSelect: "none"
  },

  noImage: {
    minHeight: "250px",
    border:
      "1px dashed #d0d5dd",
    borderRadius: "14px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    color: "#667085"
  },

  options: {
    display: "grid",
    gridTemplateColumns:
      "repeat(5,minmax(0,1fr))",
    gap: "10px",
    marginTop: "20px"
  },

  optionButton: {
    minHeight: "58px",
    border:
      "2px solid #e4e7ec",
    borderRadius: "12px",
    background: "#ffffff",
    color: "#344054",
    fontSize: "20px",
    fontWeight: "900",
    cursor: "pointer"
  },

  optionSelected: {
    border:
      "2px solid #3157a6",
    background: "#eef4ff",
    color: "#3157a6"
  },

  selected: {
    marginTop: "14px",
    textAlign: "center",
    color: "#027a48",
    fontWeight: "700"
  },

  warning: {
    marginTop: "14px",
    padding: "12px 14px",
    borderRadius: "10px",
    background: "#fffaeb",
    border:
      "1px solid #fedf89",
    color: "#93370d",
    textAlign: "center",
    fontWeight: "700"
  },

  actions: {
    display: "flex",
    justifyContent: "space-between",
    gap: "12px",
    marginTop: "24px",
    paddingTop: "18px",
    borderTop:
      "1px solid #eaecf0"
  },

  backButton: {
    border:
      "1px solid #d0d5dd",
    background: "#ffffff",
    borderRadius: "10px",
    padding: "12px 20px",
    fontWeight: "800",
    cursor: "pointer"
  },

  nextButton: {
    border: "none",
    background: "#3157a6",
    color: "#ffffff",
    borderRadius: "10px",
    padding: "12px 22px",
    fontWeight: "800",
    cursor: "pointer"
  },

  finishButton: {
    border: "none",
    background: "#1570ef",
    color: "#ffffff",
    borderRadius: "10px",
    padding: "12px 22px",
    fontWeight: "800",
    cursor: "pointer"
  },

  disabled: {
    opacity: 0.45,
    cursor: "not-allowed"
  },

  navigator: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(42px,1fr))",
    gap: "6px",
    marginTop: "22px"
  },

  navigatorButton: {
    minHeight: "38px",
    border:
      "1px solid #e4e7ec",
    borderRadius: "8px",
    background: "#ffffff",
    color: "#667085",
    fontWeight: "700",
    cursor: "pointer"
  },

  navigatorAnswered: {
    background: "#ecfdf3",
    border:
      "1px solid #abefc6",
    color: "#027a48"
  },

  navigatorCurrent: {
    border:
      "2px solid #3157a6",
    color: "#3157a6"
  },

  finishedIcon: {
    fontSize: "52px",
    textAlign: "center"
  },

  finishedTitle: {
    textAlign: "center"
  },

  finishedText: {
    textAlign: "center",
    color: "#667085"
  }
};

export default MatricesBeta3;