import React, {
  useEffect,
  useRef,
  useState
} from "react";

const IMAGEN_CLAVES = "/beta3/2.jpg";

/*
=========================================================
DATOS DE LA LÁMINA ORIGINAL 2.JPG
=========================================================
Tamaño utilizado para digitalizar:
1792 x 2400

La tabla tiene:
7 filas
20 símbolos por fila
140 reactivos
=========================================================
*/

const ANCHO_ORIGINAL = 1792;
const ALTO_ORIGINAL = 2400;

const X_INICIAL = 185;
const ANCHO_CELDA = 72;

const Y_FILAS = [
  735,
  911,
  1085,
  1261,
  1435,
  1610,
  1785
];

// ==================================================
// SÍMBOLO INDIVIDUAL DESDE 2.JPG
// ==================================================

const SimboloClaveBeta3 = ({
  fila,
  posicion
}) => {
  /*
    Recortamos visualmente cada símbolo
    directamente de la lámina 2.jpg.

    No se crean 140 archivos.
  */

  const escala = 0.72;

  const x =
    X_INICIAL +
    (Number(posicion) - 1) *
      ANCHO_CELDA +
    5;

  const y =
    Y_FILAS[
      Number(fila) - 1
    ] + 5;

  const anchoImagen =
    ANCHO_ORIGINAL *
    escala;

  const altoImagen =
    ALTO_ORIGINAL *
    escala;

  return (
    <div
      style={{
        width: "44px",
        height: "44px",
        overflow: "hidden",
        position: "relative",
        margin: "0 auto 4px",
        background: "#fff"
      }}
    >
      <img
        src={IMAGEN_CLAVES}
        alt=""
        draggable={false}
        style={{
          position: "absolute",

          width:
            `${anchoImagen}px`,

          height:
            `${altoImagen}px`,

          maxWidth: "none",

          left:
            `${-(x * escala)}px`,

          top:
            `${-(y * escala)}px`,

          pointerEvents: "none",
          userSelect: "none"
        }}
      />
    </div>
  );
};

// ==================================================
// CLAVE SUPERIOR 1 - 9 DESDE 2.JPG
// ==================================================

const ClaveSuperiorBeta3 = () => {
  /*
    Zona aproximada de la clave superior
    dentro de la lámina original.

    x: 350
    y: 120
    ancho: 1230
    alto: 240
  */

  const escala = 0.58;

  const x = 350;
  const y = 120;

  return (
    <div style={styles.claveViewport}>
      <img
        src={IMAGEN_CLAVES}
        alt="Clave de símbolos Beta III"
        draggable={false}
        style={{
          position: "absolute",

          width:
            `${ANCHO_ORIGINAL * escala}px`,

          height:
            `${ALTO_ORIGINAL * escala}px`,

          maxWidth: "none",

          left:
            `${-(x * escala)}px`,

          top:
            `${-(y * escala)}px`,

          pointerEvents: "none",
          userSelect: "none"
        }}
      />
    </div>
  );
};

// ==================================================
// COMPONENTE PRINCIPAL
// ==================================================

const ClavesBeta3 = ({
  subprueba,
  guardando,
  onTerminar
}) => {
  const [iniciada, setIniciada] =
    useState(false);

  const [finalizada, setFinalizada] =
    useState(false);

  const [tiempo, setTiempo] =
    useState(
      Number(
        subprueba?.tiempo_segundos ||
        120
      )
    );

  /*
    Los primeros tres son ejemplos
    impresos en la hoja:
    1 = 5
    2 = 3
    3 = 1
  */

  const [respuestas, setRespuestas] =
    useState({
      1: "5",
      2: "3",
      3: "1"
    });

  const inputsRef =
    useRef({});

  const finalizandoRef =
    useRef(false);

  const reactivos =
    Array.isArray(
      subprueba?.reactivos
    )
      ? subprueba.reactivos
      : [];

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
    tiempo,
    finalizada
  ]);

  // ==================================================
  // TIEMPO MM:SS
  // ==================================================

  const formatearTiempo =
    (segundos) => {
      const min =
        Math.floor(
          segundos / 60
        );

      const sec =
        segundos % 60;

      return `${String(
        min
      ).padStart(
        2,
        "0"
      )}:${String(
        sec
      ).padStart(
        2,
        "0"
      )}`;
    };

  // ==================================================
  // RESPONDER
  // ==================================================

  const responder = (
    numero,
    valor
  ) => {
    if (
      !iniciada ||
      finalizada ||
      tiempo <= 0
    ) {
      return;
    }

    /*
      Solo números del 1 al 9.
    */

    const limpio =
      String(valor)
        .replace(
          /[^1-9]/g,
          ""
        )
        .slice(
          0,
          1
        );

    setRespuestas(
      (prev) => ({
        ...prev,

        [numero]:
          limpio
      })
    );

    /*
      Cuando escribe un número,
      pasa automáticamente al siguiente.
    */

    if (limpio) {
      const siguiente =
        Number(numero) + 1;

      if (
        siguiente <= 140
      ) {
        window.setTimeout(
          () => {
            inputsRef.current[
              siguiente
            ]?.focus();
          },
          10
        );
      }
    }
  };

  // ==================================================
  // COMENZAR
  // ==================================================

  const comenzar = () => {
    setIniciada(true);

    /*
      Comenzamos en el reactivo 4
      porque 1,2,3 son ejemplos.
    */

    window.setTimeout(
      () => {
        inputsRef.current[
          4
        ]?.focus();
      },
      150
    );
  };

  // ==================================================
  // PREPARAR RESPUESTAS PARA BACKEND
  // ==================================================

  const prepararRespuestas =
    () => {
      return reactivos
        .filter(
          (reactivo) => {
            const numero =
              Number(
                reactivo.numero
              );

            /*
              No enviamos los 3 ejemplos.
            */

            if (numero <= 3) {
              return false;
            }

            return Boolean(
              respuestas[numero]
            );
          }
        )
        .map(
          (reactivo) => ({
            id_reactivo_beta3:
              Number(
                reactivo
                  .id_reactivo_beta3
              ),

            respuesta:
              String(
                respuestas[
                  reactivo.numero
                ]
              )
          })
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
  // AGRUPAR 7 FILAS x 20
  // ==================================================

  const filas =
    Array.from(
      {
        length: 7
      },

      (_, indiceFila) =>
        reactivos

          .filter(
            (reactivo) =>
              Number(
                reactivo.fila
              ) ===
              indiceFila + 1
          )

          .sort(
            (a, b) =>
              Number(
                a.posicion_fila
              ) -
              Number(
                b.posicion_fila
              )
          )
    );

  /*
    No contamos los tres ejemplos
    como respuestas reales.
  */

  const respondidas =
    Object.keys(
      respuestas
    ).filter(
      (numero) =>
        Number(numero) > 3 &&
        Boolean(
          respuestas[numero]
        )
    ).length;

  // ==================================================
  // ANTES DE COMENZAR
  // ==================================================

  if (!iniciada) {
    return (
      <div style={styles.card}>

        <div style={styles.header}>

          <div>
            <div style={styles.code}>
              SUBPRUEBA 1
            </div>

            <h2 style={styles.title}>
              Claves
            </h2>
          </div>

          <div style={styles.timer}>
            ⏱{" "}
            {formatearTiempo(
              Number(
                subprueba
                  ?.tiempo_segundos ||
                120
              )
            )}
          </div>

        </div>

        <div style={styles.instructions}>

          <h3 style={styles.instructionsTitle}>
            Instrucciones
          </h3>

          <p>
            En la parte superior encontrarás
            nueve símbolos. Cada símbolo
            corresponde a un número del
            <strong> 1 al 9</strong>.
          </p>

          <p>
            Observa cada símbolo y escribe
            en la casilla de abajo el número
            correspondiente.
          </p>

          <p>
            Los primeros tres ejercicios
            aparecen contestados como ejemplo:
          </p>

          <div style={styles.examples}>
            <strong>1 → 5</strong>
            <strong>2 → 3</strong>
            <strong>3 → 1</strong>
          </div>

          <p>
            Cuando presiones
            <strong> Comenzar subprueba</strong>,
            tendrás
            <strong> 2 minutos</strong>
            para responder tantos ejercicios
            como puedas.
          </p>

          <div style={styles.important}>
            No es necesario terminar los
            140 reactivos. Cuando finalice
            el tiempo se guardarán
            automáticamente las respuestas
            que hayas alcanzado a contestar.
          </div>

        </div>

        <div style={styles.legendCard}>

          <div style={styles.legendTitle}>
            Clave de símbolos
          </div>

          <ClaveSuperiorBeta3 />

        </div>

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
  // VISTA DE TRABAJO
  // ==================================================

  return (
    <div style={styles.card}>

      {/* ENCABEZADO */}

      <div style={styles.header}>

        <div>

          <div style={styles.code}>
            SUBPRUEBA 1
          </div>

          <h2 style={styles.title}>
            Claves
          </h2>

          <div style={styles.progressText}>
            {respondidas} respondidos
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

      {/* CLAVE SIEMPRE VISIBLE */}

      <div style={styles.stickyLegend}>

        <div style={styles.stickyTitle}>
          Clave 1–9
        </div>

        <ClaveSuperiorBeta3 />

      </div>

      {/* CUADRÍCULA */}

      <div style={styles.board}>

        {filas.map(
          (
            fila,
            indiceFila
          ) => (
            <div
              key={
                indiceFila
              }
              style={styles.row}
            >

              <div style={styles.rowNumber}>
                {indiceFila + 1}
              </div>

              <div style={styles.cells}>

                {fila.map(
                  (reactivo) => {
                    const numero =
                      Number(
                        reactivo.numero
                      );

                    /*
                      Los primeros tres son
                      ejemplos bloqueados.
                    */

                    const ejemplo =
                      numero <= 3;

                    return (
                      <div
                        key={
                          reactivo
                            .id_reactivo_beta3
                        }
                        style={{
                          ...styles.cell,

                          ...(ejemplo
                            ? styles.exampleCell
                            : {})
                        }}
                      >

                        {/* NÚMERO DEL REACTIVO */}

                        <div style={styles.number}>
                          {numero}
                        </div>

                        {/* SÍMBOLO */}

                        <SimboloClaveBeta3
                          fila={
                            reactivo.fila
                          }
                          posicion={
                            reactivo
                              .posicion_fila
                          }
                        />

                        {/* RESPUESTA */}

                        <input
                          ref={(element) => {
                            inputsRef.current[
                              numero
                            ] =
                              element;
                          }}

                          type="text"

                          inputMode="numeric"

                          maxLength={1}

                          autoComplete="off"

                          disabled={
                            ejemplo ||
                            finalizada ||
                            guardando ||
                            tiempo <= 0
                          }

                          value={
                            respuestas[
                              numero
                            ] || ""
                          }

                          onChange={(e) =>
                            responder(
                              numero,
                              e.target.value
                            )
                          }

                          onFocus={(e) => {
                            e.target.select();
                          }}

                          style={{
                            ...styles.input,

                            ...(ejemplo
                              ? styles.exampleInput
                              : {})
                          }}
                        />

                      </div>
                    );
                  }
                )}

              </div>

            </div>
          )
        )}

      </div>

      {/* PIE */}

      <div style={styles.footer}>

        <div style={styles.footerText}>

          <strong>
            {respondidas}
          </strong>
          {" "}
          respuestas registradas.

          <br />

          La subprueba terminará
          automáticamente cuando el
          cronómetro llegue a 00:00.

        </div>

        <button
          type="button"
          style={{
            ...styles.finishButton,

            ...(finalizada ||
            guardando
              ? styles.buttonDisabled
              : {})
          }}
          disabled={
            finalizada ||
            guardando
          }
          onClick={terminar}
        >
          {guardando
            ? "Guardando..."
            : "Terminar subprueba"}
        </button>

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

  instructionsTitle: {
    marginTop: 0,
    color: "#101828"
  },

  examples: {
    display: "flex",
    flexWrap: "wrap",
    gap: "10px",
    margin:
      "14px 0",
    color: "#3157a6"
  },

  important: {
    marginTop: "15px",
    padding: "13px",
    borderRadius: "10px",
    background: "#eef4ff",
    border:
      "1px solid #b9ccff",
    color: "#344054",
    fontWeight: "700"
  },

  legendCard: {
    textAlign: "center",
    margin: "25px 0"
  },

  legendTitle: {
    fontWeight: "900",
    color: "#101828",
    marginBottom: "12px"
  },

  /*
    Vista recortada de la clave superior
    dentro de 2.jpg.
  */

  claveViewport: {
    width: "720px",
    maxWidth: "100%",
    height: "140px",
    margin: "0 auto",
    overflow: "hidden",
    position: "relative",
    background: "#ffffff",
    borderRadius: "10px"
  },

  stickyLegend: {
    position: "sticky",
    top: "8px",
    zIndex: 20,
    background: "#ffffff",
    border:
      "1px solid #e4e7ec",
    borderRadius: "14px",
    padding: "8px 12px 10px",
    textAlign: "center",
    boxShadow:
      "0 5px 18px rgba(0,0,0,.12)",
    marginBottom: "18px"
  },

  stickyTitle: {
    fontSize: "11px",
    color: "#667085",
    fontWeight: "800",
    marginBottom: "2px"
  },

  board: {
    display: "flex",
    flexDirection: "column",
    gap: "12px",
    overflowX: "auto",
    paddingBottom: "8px"
  },

  row: {
    display: "flex",
    alignItems: "stretch",
    minWidth: "1120px"
  },

  rowNumber: {
    width: "38px",
    minWidth: "38px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontWeight: "900",
    fontSize: "18px",
    color: "#475467"
  },

  cells: {
    flex: 1,
    display: "grid",
    gridTemplateColumns:
      "repeat(20, minmax(50px,1fr))",
    gap: "4px"
  },

  cell: {
    border:
      "1px solid #d0d5dd",
    borderRadius: "8px",
    padding: "4px",
    background: "#ffffff",
    textAlign: "center",
    minWidth: "48px"
  },

  exampleCell: {
    background: "#f2f4f7",
    border:
      "1px solid #b9ccff"
  },

  number: {
    fontSize: "9px",
    color: "#98a2b3",
    marginBottom: "2px"
  },

  input: {
    width: "100%",
    height: "34px",
    boxSizing: "border-box",
    border:
      "1px solid #98a2b3",
    borderRadius: "6px",
    textAlign: "center",
    fontWeight: "900",
    fontSize: "18px",
    color: "#101828",
    background: "#ffffff",
    outline: "none"
  },

  exampleInput: {
    background: "#eaecf0",
    color: "#344054",
    border:
      "1px solid #b9ccff"
  },

  footer: {
    marginTop: "24px",
    borderTop:
      "1px solid #eaecf0",
    paddingTop: "18px",
    display: "flex",
    justifyContent:
      "space-between",
    alignItems: "center",
    gap: "20px"
  },

  footerText: {
    color: "#667085",
    fontSize: "13px",
    lineHeight: "1.5"
  },

  startButton: {
    display: "block",
    margin: "20px auto 0",
    border: "none",
    borderRadius: "12px",
    background: "#3157a6",
    color: "#ffffff",
    padding: "14px 30px",
    fontSize: "16px",
    fontWeight: "900",
    cursor: "pointer"
  },

  finishButton: {
    border: "none",
    borderRadius: "10px",
    background: "#3157a6",
    color: "#ffffff",
    padding: "12px 22px",
    fontWeight: "800",
    cursor: "pointer",
    whiteSpace: "nowrap"
  },

  buttonDisabled: {
    opacity: 0.55,
    cursor: "not-allowed"
  }
};

export default ClavesBeta3;