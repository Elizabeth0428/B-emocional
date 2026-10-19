import React, {
  useEffect,
  useRef,
  useState
} from "react";

const ANCHO_IMAGEN = 1824;
const ALTO_IMAGEN = 2362;

/*
=========================================================
BETA III - FIGURAS INCOMPLETAS
=========================================================

4.jpg -> reactivos 1 - 8
5.jpg -> reactivos 9 - 16
6.jpg -> reactivos 17 - 24

Cada hoja contiene:

IZQUIERDA
1
2
3
4

DERECHA
5
6
7
8

La segunda página continúa:
9-16

La tercera:
17-24

Los recortes están calculados sobre las imágenes reales
1824 x 2362.
=========================================================
*/

const FigurasBeta3 = ({
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
        150
      )
    );

  const [respuestas, setRespuestas] =
    useState({});

  const finalizandoRef =
    useRef(false);

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
  // FORMATO TIEMPO
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
  // COMENZAR
  // ==================================================

  const comenzar = () => {
    setIndice(0);
    setIniciada(true);
  };

  // ==================================================
  // RESPONDER
  // ==================================================

  const responder = (
    pagina,
    xOriginal,
    yOriginal
  ) => {
    if (
      !reactivoActual ||
      !iniciada ||
      finalizada ||
      tiempo <= 0
    ) {
      return;
    }

    /*
      Guardamos porcentaje respecto
      a la página original completa.

      Formato:
      pagina,x,y

      Ejemplo:
      4,31.42,18.75
    */

    const x =
      (
        xOriginal /
        ANCHO_IMAGEN
      ) * 100;

    const y =
      (
        yOriginal /
        ALTO_IMAGEN
      ) * 100;

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

          respuesta:
            `${pagina},${x.toFixed(
              2
            )},${y.toFixed(
              2
            )}`
        }
      })
    );

    /*
      Avance automático después
      de marcar una parte.
    */

    if (
      indice <
      respondibles.length - 1
    ) {
      window.setTimeout(
        () => {
          setIndice(
            (prev) =>
              prev + 1
          );
        },
        300
      );
    }
  };

  // ==================================================
  // NAVEGACIÓN
  // ==================================================

  const anterior = () => {
    if (indice > 0) {
      setIndice(
        (prev) =>
          prev - 1
      );
    }
  };

  const siguiente = () => {
    if (
      indice <
      respondibles.length - 1
    ) {
      setIndice(
        (prev) =>
          prev + 1
      );
    }
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
          Figuras incompletas
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
              SUBPRUEBA 2
            </div>

            <h2 style={styles.title}>
              Figuras incompletas
            </h2>

          </div>

          <div style={styles.timer}>
            ⏱{" "}
            {formatearTiempo(
              Number(
                subprueba
                  ?.tiempo_segundos ||
                150
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
            cada dibujo.
          </p>

          <p>
            En cada figura falta una
            parte importante.
          </p>

          <p>
            Haz clic directamente
            sobre el lugar donde
            consideras que falta
            esa parte.
          </p>

          <div style={styles.important}>
            Tendrás{" "}
            <strong>
              {formatearTiempo(
                Number(
                  subprueba
                    ?.tiempo_segundos ||
                  150
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
              Identifica visualmente
              cuál es la parte que
              falta antes de comenzar.
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
          Figuras incompletas terminada
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

  // ==================================================
  // VISTA
  // ==================================================

  return (
    <div style={styles.card}>

      {/* ENCABEZADO */}

      <div style={styles.header}>

        <div>

          <div style={styles.code}>
            SUBPRUEBA 2
          </div>

          <h2 style={styles.title}>
            Figuras incompletas
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
            FIGURA
          </div>

          <h3 style={styles.questionTitle}>
            Reactivo {numero}
          </h3>

        </div>

        <div style={styles.counter}>
          {indice + 1}

          <span>
            /{respondibles.length}
          </span>
        </div>

      </div>

      <div style={styles.instruction}>
        Haz clic directamente sobre
        la parte de la figura que
        consideras incompleta.
      </div>

      {/* FIGURA */}

      <FiguraIndividual
        numero={numero}
        respuestaActual={
          respuestaActual
        }
        onResponder={
          responder
        }
      />

      {respuestaActual && (
        <div style={styles.selected}>
          ✓ Respuesta registrada
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

                onClick={() =>
                  setIndice(i)
                }

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
// FIGURA INDIVIDUAL
// ==================================================

const FiguraIndividual = ({
  numero,
  respuestaActual,
  onResponder
}) => {
  /*
  =====================================================
  COORDENADAS REALES
  =====================================================

  Imágenes:
    1824 x 2362

  Página 4:
    1-4 izquierda
    5-8 derecha

  Página 5:
    9-12 izquierda
    13-16 derecha

  Página 6:
    17-20 izquierda
    21-24 derecha
  =====================================================
  */

  const obtenerRecorte = () => {
    // ================================================
    // PÁGINA 4
    // ================================================

    if (
      numero >= 1 &&
      numero <= 8
    ) {
      const derecha =
        numero >= 5;

      const fila =
        derecha
          ? numero - 5
          : numero - 1;

      return {
        pagina: 4,
        imagen: "/beta3/4.jpg",

        x:
          derecha
            ? 1175
            : 382,

        y:
          157 +
          fila * 482,

        width: 490,
        height: 482
      };
    }

    // ================================================
    // PÁGINA 5
    // ================================================

    if (
      numero >= 9 &&
      numero <= 16
    ) {
      const local =
        numero - 8;

      const derecha =
        local >= 5;

      const fila =
        derecha
          ? local - 5
          : local - 1;

      return {
        pagina: 5,
        imagen: "/beta3/5.jpg",

        x:
          derecha
            ? 1110
            : 303,

        y:
          164 +
          fila * 483,

        width: 490,
        height: 483
      };
    }

    // ================================================
    // PÁGINA 6
    // ================================================

    if (
      numero >= 17 &&
      numero <= 24
    ) {
      const local =
        numero - 16;

      const derecha =
        local >= 5;

      const fila =
        derecha
          ? local - 5
          : local - 1;

      return {
        pagina: 6,
        imagen: "/beta3/6.jpg",

        x:
          derecha
            ? 1110
            : 308,

        y:
          165 +
          fila * 483,

        width: 495,
        height: 483
      };
    }

    return null;
  };

  const recorte =
    obtenerRecorte();

  if (!recorte) {
    return (
      <div style={styles.noImage}>
        No se encontró la figura.
      </div>
    );
  }

  // ==================================================
  // RESPUESTA GUARDADA
  // ==================================================

  let punto = null;

  if (respuestaActual) {
    const partes =
      String(
        respuestaActual
      ).split(",");

    if (
      partes.length === 3
    ) {
      const pagina =
        Number(
          partes[0]
        );

      const porcentajeX =
        Number(
          partes[1]
        );

      const porcentajeY =
        Number(
          partes[2]
        );

      if (
        pagina ===
        recorte.pagina
      ) {
        punto = {
          x:
            (
              porcentajeX /
              100
            ) *
            ANCHO_IMAGEN,

          y:
            (
              porcentajeY /
              100
            ) *
            ALTO_IMAGEN
        };
      }
    }
  }

  // ==================================================
  // CLIC EN SVG
  // ==================================================

  const seleccionar =
    (event) => {
      const svg =
        event.currentTarget;

      const rect =
        svg.getBoundingClientRect();

      const porcentajeLocalX =
        (
          event.clientX -
          rect.left
        ) /
        rect.width;

      const porcentajeLocalY =
        (
          event.clientY -
          rect.top
        ) /
        rect.height;

      const xOriginal =
        recorte.x +
        porcentajeLocalX *
          recorte.width;

      const yOriginal =
        recorte.y +
        porcentajeLocalY *
          recorte.height;

      onResponder(
        recorte.pagina,
        xOriginal,
        yOriginal
      );
    };

  // ==================================================
  // MOSTRAR UNA SOLA FIGURA
  // ==================================================

  return (
    <div style={styles.figureContainer}>

      <svg
        viewBox={
          `${recorte.x} ${recorte.y} ${recorte.width} ${recorte.height}`
        }

        preserveAspectRatio="xMidYMid meet"

        onClick={
          seleccionar
        }

        style={
          styles.figureSvg
        }
      >

        <image
          href={
            recorte.imagen
          }

          x="0"
          y="0"

          width={
            ANCHO_IMAGEN
          }

          height={
            ALTO_IMAGEN
          }

          preserveAspectRatio="none"
        />

        {punto &&
          punto.x >=
            recorte.x &&
          punto.x <=
            recorte.x +
              recorte.width &&
          punto.y >=
            recorte.y &&
          punto.y <=
            recorte.y +
              recorte.height && (

          <circle
            cx={
              punto.x
            }

            cy={
              punto.y
            }

            r="18"

            fill="rgba(217,45,32,.18)"

            stroke="#d92d20"

            strokeWidth="7"
          />

        )}

      </svg>

      <div style={styles.clickHelp}>
        👆 Haz clic sobre la
        parte que falta.
      </div>

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
    background: "#eaecf0",
    borderRadius: "999px",
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
    margin: "20px 0 16px",
    color: "#475467",
    fontWeight: "700"
  },

  figureContainer: {
    width: "100%",
    maxWidth: "640px",
    margin: "0 auto",
    textAlign: "center"
  },

  figureSvg: {
    width: "100%",
    maxHeight: "520px",
    display: "block",
    margin: "0 auto",
    border:
      "1px solid #e4e7ec",
    borderRadius: "14px",
    background: "#ffffff",
    cursor: "crosshair",
    boxSizing: "border-box"
  },

  clickHelp: {
    marginTop: "10px",
    color: "#667085",
    fontSize: "13px"
  },

  noImage: {
    minHeight: "280px",
    border:
      "1px dashed #d0d5dd",
    borderRadius: "14px",
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    color: "#667085"
  },

  selected: {
    marginTop: "12px",
    color: "#027a48",
    textAlign: "center",
    fontWeight: "700"
  },

  actions: {
    display: "flex",
    justifyContent:
      "space-between",
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

export default FigurasBeta3;