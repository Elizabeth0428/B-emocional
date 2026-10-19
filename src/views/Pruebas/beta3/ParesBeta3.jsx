import React, { useEffect, useRef, useState } from "react";

const ANCHO_LAMINA = 1824;
const ALTO_LAMINA = 2362;

const ParesBeta3 = ({
  subprueba,
  guardando,
  onTerminar
}) => {
  const [iniciada, setIniciada] = useState(false);
  const [finalizada, setFinalizada] = useState(false);
  const [indice, setIndice] = useState(0);

  const [tiempo, setTiempo] = useState(
    Number(subprueba?.tiempo_segundos || 120)
  );

  const [respuestas, setRespuestas] = useState({});

  const finalizandoRef = useRef(false);
  const avanceRef = useRef(null);

  const reactivos = Array.isArray(subprueba?.reactivos)
    ? subprueba.reactivos
    : [];

  const ejemplos = reactivos.filter(
    (reactivo) => Number(reactivo.es_ejemplo) === 1
  );

  const respondibles = reactivos
    .filter(
      (reactivo) => Number(reactivo.es_ejemplo) !== 1
    )
    .sort(
      (a, b) => Number(a.numero) - Number(b.numero)
    );

  const reactivoActual =
    respondibles[indice] || null;

  // ==================================================
  // LIMPIAR AVANCE AUTOMÁTICO
  // ==================================================

  useEffect(() => {
    return () => {
      if (avanceRef.current) {
        window.clearTimeout(avanceRef.current);
      }
    };
  }, []);

  // ==================================================
  // CRONÓMETRO
  // ==================================================

  useEffect(() => {
    if (!iniciada || finalizada) return;

    if (tiempo <= 0) {
      terminar();
      return;
    }

    const timer = window.setTimeout(() => {
      setTiempo((prev) =>
        Math.max(0, prev - 1)
      );
    }, 1000);

    return () =>
      window.clearTimeout(timer);
  }, [iniciada, finalizada, tiempo]);

  // ==================================================
  // FORMATEAR TIEMPO
  // ==================================================

  const formatearTiempo = (segundos) => {
    const minutos =
      Math.floor(segundos / 60);

    const resto =
      segundos % 60;

    return `${String(minutos).padStart(
      2,
      "0"
    )}:${String(resto).padStart(
      2,
      "0"
    )}`;
  };

  // ==================================================
  // MOVER ÍNDICE SIN SALIR DEL RANGO
  // ==================================================

  const moverIndice = (nuevoIndice) => {
    const ultimo =
      Math.max(
        0,
        respondibles.length - 1
      );

    setIndice(
      Math.min(
        Math.max(nuevoIndice, 0),
        ultimo
      )
    );
  };

  // ==================================================
  // RESPONDER
  // ==================================================

  const responder = (
    reactivo,
    respuesta
  ) => {
    if (
      !reactivo ||
      !iniciada ||
      finalizada ||
      tiempo <= 0
    ) {
      return;
    }

    setRespuestas((prev) => ({
      ...prev,

      [reactivo.id_reactivo_beta3]: {
        id_reactivo_beta3:
          Number(
            reactivo.id_reactivo_beta3
          ),
        respuesta
      }
    }));

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
        window.setTimeout(() => {
          setIndice((prev) =>
            Math.min(
              prev + 1,
              respondibles.length - 1
            )
          );
        }, 180);
    }
  };

  // ==================================================
  // COMENZAR
  // ==================================================

  const comenzar = () => {
    moverIndice(0);
    setIniciada(true);
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

    moverIndice(indice + 1);
  };

  const anterior = () => {
    if (avanceRef.current) {
      window.clearTimeout(
        avanceRef.current
      );

      avanceRef.current = null;
    }

    moverIndice(indice - 1);
  };

  // ==================================================
  // RESPUESTAS
  // ==================================================

  const prepararRespuestas = () => {
    return Object.values(
      respuestas
    );
  };

  // ==================================================
  // TERMINAR
  // ==================================================

  const terminar = async () => {
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

    finalizandoRef.current = true;
    setFinalizada(true);

    try {
      await onTerminar(
        prepararRespuestas()
      );
    } finally {
      finalizandoRef.current = false;
    }
  };

  // ==================================================
  // SIN REACTIVOS
  // ==================================================

  if (!reactivos.length) {
    return (
      <div style={styles.card}>
        <h2>
          Pares iguales y pares desiguales
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
              SUBPRUEBA 3
            </div>

            <h2 style={styles.title}>
              Pares iguales y pares desiguales
            </h2>
          </div>

          <div style={styles.timer}>
            ⏱{" "}
            {formatearTiempo(
              Number(
                subprueba?.tiempo_segundos ||
                  120
              )
            )}
          </div>
        </div>

        <div style={styles.instructions}>
          <h3>
            Instrucciones
          </h3>

          <p>
            Observa cada par de figuras,
            objetos, símbolos o números.
          </p>

          <p>
            Indica si ambos elementos son{" "}
            <strong>iguales</strong> o{" "}
            <strong>diferentes</strong>.
          </p>

          <div style={styles.exampleOptions}>
            <div style={styles.equalExample}>
              <strong>=</strong>
              <span>Iguales</span>
            </div>

            <div style={styles.differentExample}>
              <strong>≠</strong>
              <span>Diferentes</span>
            </div>
          </div>

          <div style={styles.important}>
            Tendrás{" "}
            <strong>
              {formatearTiempo(
                Number(
                  subprueba?.tiempo_segundos ||
                    120
                )
              )}
            </strong>{" "}
            para responder tantos reactivos
            como puedas.
          </div>
        </div>

        {ejemplos.length > 0 && (
          <div style={styles.exampleCard}>
            <strong>
              Ejemplo
            </strong>

            <p>
              Observa cada par y decide
              si ambos elementos son
              exactamente iguales.
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
          Pares terminada
        </h2>

        <p style={styles.finishedText}>
          Se registraron{" "}
          {Object.keys(respuestas).length}{" "}
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
            SUBPRUEBA 3
          </div>

          <h2 style={styles.title}>
            Pares iguales y pares desiguales
          </h2>

          <div style={styles.progressText}>
            {respondidas} de{" "}
            {respondibles.length} respondidos
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

      <div style={styles.progressTrack}>
        <div
          style={{
            ...styles.progressFill,

            width:
              `${progreso}%`
          }}
        />
      </div>

      <div style={styles.questionTop}>
        <div>
          <div style={styles.smallLabel}>
            PARES
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
        ¿Los dos elementos son iguales
        o diferentes?
      </div>

      <RecorteParBeta3
        numero={numero}
      />

      <div style={styles.options}>

        <button
          type="button"
          disabled={
            guardando ||
            tiempo <= 0
          }
          onClick={() =>
            responder(
              reactivoActual,
              "="
            )
          }
          style={{
            ...styles.optionButton,

            ...(respuestaActual === "="
              ? styles.optionSelected
              : {})
          }}
        >
          <span style={styles.optionSymbol}>
            =
          </span>

          <span>
            Iguales
          </span>
        </button>

        <button
          type="button"
          disabled={
            guardando ||
            tiempo <= 0
          }
          onClick={() =>
            responder(
              reactivoActual,
              "!="
            )
          }
          style={{
            ...styles.optionButton,

            ...(respuestaActual === "!="
              ? styles.optionSelected
              : {})
          }}
        >
          <span style={styles.optionSymbol}>
            ≠
          </span>

          <span>
            Diferentes
          </span>
        </button>

      </div>

      {respuestaActual && (
        <div style={styles.selected}>
          ✓ Respuesta registrada:{" "}

          <strong>
            {respuestaActual === "="
              ? "Iguales"
              : "Diferentes"}
          </strong>
        </div>
      )}

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
            style={styles.nextButton}
          >
            Siguiente →
          </button>
        ) : (
          <button
            type="button"
            disabled={guardando}
            onClick={terminar}
            style={styles.finishButton}
          >
            {guardando
              ? "Guardando..."
              : "Terminar subprueba"}
          </button>
        )}

      </div>

      <div style={styles.navigator}>
        {respondibles.map(
          (reactivo, i) => {
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
                key={
                  reactivo
                    .id_reactivo_beta3
                }
                type="button"
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
// RECORTE INDIVIDUAL
// ==================================================

const RecorteParBeta3 = ({
  numero
}) => {
  const recortes8 = {
    1: {
      x: 285,
      y: 130,
      width: 360,
      height: 125
    },

    2: {
      x: 285,
      y: 305,
      width: 360,
      height: 110
    },

    3: {
      x: 235,
      y: 455,
      width: 430,
      height: 95
    },

    4: {
      x: 235,
      y: 600,
      width: 430,
      height: 125
    },

    5: {
      x: 270,
      y: 775,
      width: 380,
      height: 115
    },

    6: {
      x: 235,
      y: 945,
      width: 430,
      height: 95
    },

    7: {
      x: 255,
      y: 1100,
      width: 390,
      height: 75
    },

    8: {
      x: 230,
      y: 1225,
      width: 455,
      height: 170
    },

    9: {
      x: 235,
      y: 1445,
      width: 420,
      height: 140
    },

    10: {
      x: 235,
      y: 1625,
      width: 420,
      height: 90
    },

    11: {
      x: 230,
      y: 1750,
      width: 430,
      height: 165
    },

    12: {
      x: 235,
      y: 1935,
      width: 425,
      height: 135
    },

    13: {
      x: 1140,
      y: 125,
      width: 330,
      height: 105
    },

    14: {
      x: 1160,
      y: 305,
      width: 300,
      height: 120
    },

    15: {
      x: 1110,
      y: 500,
      width: 380,
      height: 100
    },

    16: {
      x: 1140,
      y: 675,
      width: 330,
      height: 120
    },

    17: {
      x: 1110,
      y: 865,
      width: 410,
      height: 105
    },

    18: {
      x: 1090,
      y: 1045,
      width: 450,
      height: 105
    },

    19: {
      x: 1090,
      y: 1225,
      width: 455,
      height: 100
    },

    20: {
      x: 1140,
      y: 1405,
      width: 340,
      height: 80
    },

    21: {
      x: 1120,
      y: 1585,
      width: 370,
      height: 80
    },

    22: {
      x: 1120,
      y: 1765,
      width: 370,
      height: 80
    },

    23: {
      x: 1095,
      y: 1945,
      width: 410,
      height: 80
    }
  };

  // ==================================================
  // 8.JPG
  // ==================================================

  if (
    numero >= 1 &&
    numero <= 23
  ) {
    const recorte =
      recortes8[numero];

    return (
      <RecorteSVG
        imagen="/beta3/8.jpg"
        recorte={recorte}
      />
    );
  }

  // ==================================================
  // 9.JPG
  // ==================================================

  if (
    numero >= 24 &&
    numero <= 55
  ) {
    const derecha =
      numero >= 40;

    const fila =
      derecha
        ? numero - 40
        : numero - 24;

    const recorte = {
      x:
        derecha
          ? 1010
          : 245,

      y:
        150 +
        fila * 120,

      width:
        derecha
          ? 570
          : 455,

      height: 65
    };

    return (
      <RecorteSVG
        imagen="/beta3/9.jpg"
        recorte={recorte}
      />
    );
  }

  return (
    <div style={styles.noImage}>
      No se encontró el reactivo.
    </div>
  );
};

// ==================================================
// SVG REUTILIZABLE
// ==================================================

const RecorteSVG = ({
  imagen,
  recorte
}) => {
  if (!recorte) {
    return (
      <div style={styles.noImage}>
        No se encontró el reactivo.
      </div>
    );
  }

  return (
    <div style={styles.cropCard}>
      <svg
        viewBox={
          `${recorte.x} ${recorte.y} ${recorte.width} ${recorte.height}`
        }
        preserveAspectRatio="xMidYMid meet"
        style={styles.cropSvg}
      >
        <image
          href={imagen}
          x="0"
          y="0"
          width={ANCHO_LAMINA}
          height={ALTO_LAMINA}
          preserveAspectRatio="none"
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
    justifyContent:
      "space-between",
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

  exampleOptions: {
    display: "grid",
    gridTemplateColumns:
      "repeat(2,minmax(0,1fr))",
    gap: "12px",
    marginTop: "18px"
  },

  equalExample: {
    minHeight: "70px",
    background: "#ecfdf3",
    border:
      "1px solid #abefc6",
    borderRadius: "12px",
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    gap: "12px",
    color: "#027a48",
    fontSize: "20px"
  },

  differentExample: {
    minHeight: "70px",
    background: "#eef4ff",
    border:
      "1px solid #b9ccff",
    borderRadius: "12px",
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    gap: "12px",
    color: "#3157a6",
    fontSize: "20px"
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
    justifyContent:
      "space-between",
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
    margin: "20px 0 15px",
    color: "#475467",
    fontWeight: "700"
  },

  cropCard: {
    width: "100%",
    maxWidth: "620px",
    minHeight: "150px",
    margin: "0 auto",
    border:
      "1px solid #e4e7ec",
    borderRadius: "14px",
    background: "#ffffff",
    padding: "18px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    boxSizing: "border-box",
    overflow: "hidden"
  },

  cropSvg: {
    width: "100%",
    height: "135px",
    display: "block",
    userSelect: "none"
  },

  noImage: {
    minHeight: "180px",
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
      "repeat(2,minmax(0,1fr))",
    gap: "14px",
    marginTop: "20px"
  },

  optionButton: {
    minHeight: "78px",
    border:
      "2px solid #e4e7ec",
    borderRadius: "14px",
    background: "#ffffff",
    color: "#344054",
    fontSize: "17px",
    fontWeight: "800",
    cursor: "pointer",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    gap: "14px"
  },

  optionSelected: {
    border:
      "2px solid #3157a6",
    background: "#eef4ff",
    color: "#3157a6"
  },

  optionSymbol: {
    fontSize: "32px",
    fontWeight: "900"
  },

  selected: {
    marginTop: "14px",
    textAlign: "center",
    color: "#027a48"
  },

  actions: {
    marginTop: "24px",
    paddingTop: "18px",
    borderTop:
      "1px solid #eaecf0",
    display: "flex",
    justifyContent:
      "space-between",
    gap: "12px"
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

export default ParesBeta3;