import React, { useEffect, useState } from "react";
import axios from "axios";

const API_URL = import.meta.env.VITE_API_URL || (window.location.protocol === 'https:' ? 'https://reflejoyalma.com' : `http://${window.location.hostname}:5000`);

const RavenRH = ({
  token,
  pruebaBase
}) => {
  const [prueba, setPrueba] =
    useState(pruebaBase || null);

  const [reactivosRaven, setReactivosRaven] =
    useState([]);

  const [respuestasRaven, setRespuestasRaven] =
    useState({});

  const [indiceRaven, setIndiceRaven] =
    useState(0);

  const [inicioRaven, setInicioRaven] =
    useState(null);

  const [cargando, setCargando] =
    useState(true);

  const [finalizando, setFinalizando] =
    useState(false);

  const [completada, setCompletada] =
    useState(false);

  const [resultado, setResultado] =
    useState(null);

  const [mensaje, setMensaje] =
    useState("");

  const [error, setError] =
    useState("");

  // ==================================================
  // CARGAR RAVEN
  // ==================================================

  useEffect(() => {
    const cargar = async () => {
      try {
        setCargando(true);
        setError("");

        const respuesta =
          await axios.get(
            `${API_URL}/api/raven/publico/${token}/reactivos`
          );

        const pruebaRaven =
          respuesta.data?.prueba ||
          pruebaBase ||
          null;

        const reactivos =
          Array.isArray(
            respuesta.data?.reactivos
          )
            ? respuesta.data.reactivos
            : [];

        setPrueba(pruebaRaven);
        setReactivosRaven(reactivos);

        setIndiceRaven(0);
        setInicioRaven(Date.now());

      } catch (err) {
        console.error(
          "❌ Error cargando Raven:",
          err.response?.data ||
            err
        );

        setError(
          err.response?.data?.message ||
            "No fue posible cargar Raven."
        );

      } finally {
        setCargando(false);
      }
    };

    if (token) {
      cargar();
    }
  }, [token]);

  // ==================================================
  // SELECCIONAR RESPUESTA
  // ==================================================

  const seleccionarRaven = (
    idReactivo,
    opcion
  ) => {
    setRespuestasRaven(
      (prev) => ({
        ...prev,

        [idReactivo]:
          Number(opcion)
      })
    );

    setError("");
    setMensaje("");
  };

  // ==================================================
  // SIGUIENTE
  // ==================================================

  const siguienteRaven = () => {
    const reactivo =
      reactivosRaven[
        indiceRaven
      ];

    if (!reactivo) {
      return;
    }

    if (
      respuestasRaven[
        reactivo.id_reactivo
      ] === undefined
    ) {
      setError(
        "Selecciona una respuesta antes de continuar."
      );

      return;
    }

    setError("");

    if (
      indiceRaven <
      reactivosRaven.length - 1
    ) {
      setIndiceRaven(
        (prev) =>
          prev + 1
      );

      window.scrollTo({
        top: 0,
        behavior: "smooth"
      });
    }
  };

  // ==================================================
  // ANTERIOR
  // ==================================================

  const anteriorRaven = () => {
    if (indiceRaven > 0) {
      setIndiceRaven(
        (prev) =>
          prev - 1
      );

      setError("");

      window.scrollTo({
        top: 0,
        behavior: "smooth"
      });
    }
  };

  // ==================================================
  // IR A REACTIVO
  // ==================================================

  const irAReactivoRaven =
    (indice) => {
      if (
        indice < 0 ||
        indice >=
          reactivosRaven.length
      ) {
        return;
      }

      setIndiceRaven(indice);
      setError("");

      window.scrollTo({
        top: 0,
        behavior: "smooth"
      });
    };

  // ==================================================
  // VALIDAR COMPLETA
  // ==================================================

  const ravenCompleto = () => {
    if (
      reactivosRaven.length !==
      60
    ) {
      return false;
    }

    return reactivosRaven.every(
      (reactivo) =>
        respuestasRaven[
          reactivo.id_reactivo
        ] !== undefined
    );
  };

  // ==================================================
  // PREPARAR RESPUESTAS
  // ==================================================

  const prepararRespuestasRaven =
    () => {
      return reactivosRaven.map(
        (reactivo) => ({
          id_reactivo:
            Number(
              reactivo.id_reactivo
            ),

          respuesta:
            Number(
              respuestasRaven[
                reactivo.id_reactivo
              ]
            )
        })
      );
    };

  // ==================================================
  // FINALIZAR RAVEN
  // ==================================================

  const finalizarRaven =
    async () => {
      if (!ravenCompleto()) {
        const pendientes =
          reactivosRaven.filter(
            (reactivo) =>
              respuestasRaven[
                reactivo.id_reactivo
              ] === undefined
          );

        setError(
          `Debes responder los 60 reactivos. Faltan ${pendientes.length}.`
        );

        if (
          pendientes.length
        ) {
          const indice =
            reactivosRaven.findIndex(
              (r) =>
                Number(
                  r.id_reactivo
                ) ===
                Number(
                  pendientes[0]
                    .id_reactivo
                )
            );

          if (indice >= 0) {
            setIndiceRaven(
              indice
            );
          }
        }

        return;
      }

      try {
        setFinalizando(true);
        setError("");
        setMensaje("");

        await axios.post(
          `${API_URL}/api/raven/publico/${token}/respuestas`,
          {
            respuestas:
              prepararRespuestasRaven()
          }
        );

        const tiempoSegundos =
          inicioRaven
            ? Math.max(
                1,
                Math.round(
                  (
                    Date.now() -
                    inicioRaven
                  ) / 1000
                )
              )
            : null;

        const respuesta =
          await axios.post(
            `${API_URL}/api/raven/publico/${token}/finalizar`,
            {
              tiempo_segundos:
                tiempoSegundos
            }
          );

        setResultado(
          respuesta.data?.resultado ||
            null
        );

        setCompletada(true);

      } catch (err) {
        console.error(
          "❌ Error finalizando Raven:",
          err.response?.data ||
            err
        );

        setError(
          err.response?.data?.message ||
            "No fue posible finalizar Raven."
        );

      } finally {
        setFinalizando(false);
      }
    };

  // ==================================================
  // URL IMAGEN
  // ==================================================

  const obtenerUrlImagenRaven =
    (imagen) => {
      if (!imagen) {
        return "";
      }

      const ruta =
        String(imagen)
          .replace(
            /^\/+/,
            ""
          );

      return `/${ruta}`;
    };

  // ==================================================
  // CARGANDO
  // ==================================================

  if (cargando) {
    return (
      <div style={styles.page}>
        <div style={styles.mainCard}>
          <h2>
            🧠 MirrorSoul
          </h2>

          <p>
            Cargando Raven...
          </p>
        </div>
      </div>
    );
  }

  // ==================================================
  // ERROR
  // ==================================================

  if (
    error &&
    !reactivosRaven.length
  ) {
    return (
      <div style={styles.page}>
        <div style={styles.mainCard}>

          <div style={styles.bigIcon}>
            ⚠️
          </div>

          <h2>
            No fue posible abrir Raven
          </h2>

          <p style={styles.muted}>
            {error}
          </p>

        </div>
      </div>
    );
  }

  // ==================================================
  // COMPLETADA
  // ==================================================

  if (completada) {
    return (
      <div style={styles.page}>
        <div style={styles.mainCard}>

          <div style={styles.bigIcon}>
            ✅
          </div>

          <h1>
            Evaluación completada
          </h1>

          <p style={styles.muted}>
            Tus respuestas fueron
            registradas correctamente.
          </p>

          <div style={styles.completeBox}>
            <strong>
              {prueba?.nombre ||
                "Matrices Progresivas de Raven"}
            </strong>

            <p>
              El área de Recursos Humanos
              podrá consultar los resultados
              correspondientes a esta
              evaluación.
            </p>
          </div>

          {resultado && (
            <p style={styles.smallText}>
              La evaluación fue procesada
              correctamente.
            </p>
          )}

          <p style={styles.smallText}>
            Ya puedes cerrar esta ventana.
          </p>

        </div>
      </div>
    );
  }

  // ==================================================
  // SIN REACTIVOS
  // ==================================================

  if (
    !reactivosRaven.length
  ) {
    return (
      <div style={styles.page}>
        <div style={styles.mainCard}>
          <h3>
            Raven todavía no contiene
            reactivos.
          </h3>
        </div>
      </div>
    );
  }

  // ==================================================
  // DATOS ACTUALES
  // ==================================================

  const reactivo =
    reactivosRaven[
      indiceRaven
    ];

  const respuestaActual =
    respuestasRaven[
      reactivo?.id_reactivo
    ];

  const respondidas =
    Object.keys(
      respuestasRaven
    ).length;

  const progreso =
    reactivosRaven.length
      ? Math.round(
          (
            respondidas /
            reactivosRaven.length
          ) * 100
        )
      : 0;

  const totalOpciones =
    Number(
      reactivo?.total_opciones ||
        0
    );

  const opciones =
    Array.from(
      {
        length:
          totalOpciones
      },
      (_, index) =>
        index + 1
    );

  const esUltimo =
    indiceRaven ===
    reactivosRaven.length - 1;

  const serieAnterior =
    indiceRaven > 0
      ? reactivosRaven[
          indiceRaven - 1
        ]?.serie
      : null;

  const cambioSerie =
    indiceRaven === 0 ||
    serieAnterior !==
      reactivo?.serie;

  // ==================================================
  // VISTA RAVEN
  // ==================================================

  return (
    <div style={styles.page}>
      <div style={styles.specialContainer}>

        {/* ENCABEZADO */}

        <div style={styles.mainCard}>

          <div style={styles.brand}>
            🧠 MirrorSoul
          </div>

          <div style={styles.testBadge}>
            PRUEBA PSICOMÉTRICA
          </div>

          <h1 style={styles.title}>
            {prueba?.nombre}
          </h1>

          {prueba?.descripcion && (
            <p style={styles.description}>
              {prueba.descripcion}
            </p>
          )}

          <div style={styles.infoGrid}>

            <InfoBox
              label="Participante"
              value={
                prueba?.prospecto_nombre ||
                prueba?.participante ||
                "Prospecto"
              }
            />

            <InfoBox
              label="ID MirrorSoul"
              value={
                prueba?.id_mirror ||
                "No disponible"
              }
            />

            <InfoBox
              label="Puesto"
              value={
                prueba?.puesto ||
                "No especificado"
              }
            />

            <InfoBox
              label="Evaluación"
              value={
                prueba?.categoria ||
                "Aptitudes cognitivas"
              }
            />

          </div>

          <div style={styles.blueNotice}>
            Observa cuidadosamente cada
            matriz y selecciona la opción
            que completa correctamente la
            figura. Responde todos los
            reactivos antes de finalizar.
          </div>

        </div>

        {/* PROGRESO */}

        <div style={styles.progressCard}>

          <div style={styles.progressTop}>

            <div>
              <strong>
                Progreso de la evaluación
              </strong>

              <div style={styles.progressSmall}>
                {respondidas} de{" "}
                {reactivosRaven.length}{" "}
                respondidos
              </div>
            </div>

            <div style={styles.progressPercent}>
              {progreso}%
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

          <div style={styles.seriesRow}>

            {[
              "A",
              "B",
              "C",
              "D",
              "E"
            ].map(
              (serie) => {
                const reactivosSerie =
                  reactivosRaven.filter(
                    (r) =>
                      r.serie ===
                      serie
                  );

                const contestados =
                  reactivosSerie.filter(
                    (r) =>
                      respuestasRaven[
                        r.id_reactivo
                      ] !== undefined
                  ).length;

                return (
                  <div
                    key={serie}
                    style={{
                      ...styles.seriesBadge,

                      ...(reactivo?.serie ===
                      serie
                        ? styles.seriesBadgeActive
                        : {})
                    }}
                  >
                    Serie {serie}

                    <span style={styles.seriesCount}>
                      {contestados}/12
                    </span>
                  </div>
                );
              }
            )}

          </div>

        </div>

        {mensaje && (
          <div style={styles.success}>
            ✅ {mensaje}
          </div>
        )}

        {error && (
          <div style={styles.error}>
            ❌ {error}
          </div>
        )}

        {/* CAMBIO DE SERIE */}

        {cambioSerie && (
          <div style={styles.sectionHeader}>

            <div style={styles.sectionNumber}>
              {reactivo.serie}
            </div>

            <div>
              <strong style={styles.sectionTitle}>
                Serie {reactivo.serie}
              </strong>

              <div style={styles.sectionSubtitle}>
                12 matrices en esta serie
              </div>
            </div>

          </div>
        )}

        {/* REACTIVO */}

        <div style={styles.testCard}>

          <div style={styles.questionTop}>

            <div>
              <div style={styles.testCode}>
                SERIE {reactivo.serie}
              </div>

              <h2 style={styles.questionTitle}>
                Reactivo{" "}
                {reactivo.numero}
              </h2>
            </div>

            <div style={styles.counter}>
              {indiceRaven + 1}

              <span>
                /{reactivosRaven.length}
              </span>
            </div>

          </div>

          <div style={styles.imageContainer}>

            <img
              src={
                obtenerUrlImagenRaven(
                  reactivo.imagen
                )
              }
              alt={
                `Serie ${reactivo.serie} - Reactivo ${reactivo.numero}`
              }
              style={styles.testImage}
            />

          </div>

          <div style={styles.answerInstruction}>
            Selecciona la respuesta
            correcta:
          </div>

          <div
            style={{
              ...styles.numberOptions,

              gridTemplateColumns:
                `repeat(${Math.min(
                  totalOpciones,
                  8
                )}, minmax(50px, 1fr))`
            }}
          >
            {opciones.map(
              (opcion) => (
                <button
                  type="button"
                  key={opcion}

                  onClick={() =>
                    seleccionarRaven(
                      reactivo.id_reactivo,
                      opcion
                    )
                  }

                  style={{
                    ...styles.answerButton,

                    ...(Number(
                      respuestaActual
                    ) ===
                    Number(
                      opcion
                    )
                      ? styles.answerButtonSelected
                      : {})
                  }}
                >
                  {opcion}
                </button>
              )
            )}
          </div>

          {respuestaActual !==
            undefined && (

            <div style={styles.selectedAnswer}>
              ✓ Respuesta seleccionada:{" "}
              <strong>
                {respuestaActual}
              </strong>
            </div>

          )}

        </div>

        {/* NAVEGACIÓN */}

        <div style={styles.navigationCard}>

          <button
            type="button"

            style={{
              ...styles.backButton,

              ...(indiceRaven === 0
                ? styles.disabledButton
                : {})
            }}

            disabled={
              indiceRaven === 0 ||
              finalizando
            }

            onClick={
              anteriorRaven
            }
          >
            ← Anterior
          </button>

          {!esUltimo ? (

            <button
              type="button"
              style={styles.nextButton}
              disabled={finalizando}
              onClick={
                siguienteRaven
              }
            >
              Siguiente →
            </button>

          ) : (

            <button
              type="button"
              style={styles.finishButton}
              disabled={finalizando}
              onClick={
                finalizarRaven
              }
            >
              {finalizando
                ? "Procesando..."
                : "✅ Finalizar evaluación"}
            </button>

          )}

        </div>

        {/* NAVEGADOR */}

        <div style={styles.navigatorCard}>

          <div style={styles.navigatorTitle}>
            Reactivos
          </div>

          <div style={styles.navigatorText}>
            Puedes regresar a una
            respuesta antes de finalizar.
          </div>

          <div style={styles.navigatorGrid}>

            {reactivosRaven.map(
              (
                item,
                index
              ) => {
                const contestado =
                  respuestasRaven[
                    item.id_reactivo
                  ] !== undefined;

                const actual =
                  index ===
                  indiceRaven;

                return (
                  <button
                    type="button"

                    key={
                      item.id_reactivo
                    }

                    onClick={() =>
                      irAReactivoRaven(
                        index
                      )
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
                    {item.serie}
                    {item.numero}
                  </button>
                );
              }
            )}

          </div>

        </div>

      </div>
    </div>
  );
};

// ==================================================
// INFO BOX
// ==================================================

function InfoBox({
  label,
  value
}) {
  return (
    <div style={styles.infoBox}>

      <span style={styles.infoLabel}>
        {label}
      </span>

      <strong>
        {value}
      </strong>

    </div>
  );
}

// ==================================================
// ESTILOS
// ==================================================

const styles = {
  page: {
    minHeight: "100vh",
    background: "#f5f7fa",
    padding: "30px 18px",
    boxSizing: "border-box"
  },

  specialContainer: {
    maxWidth: "1040px",
    margin: "0 auto"
  },

  mainCard: {
    maxWidth: "920px",
    margin: "0 auto 20px",
    background: "#ffffff",
    borderRadius: "18px",
    padding: "28px",
    boxShadow:
      "0 4px 20px rgba(0,0,0,.06)",
    textAlign: "center",
    boxSizing: "border-box"
  },

  brand: {
    fontWeight: "800",
    fontSize: "20px",
    marginBottom: "12px"
  },

  testBadge: {
    display: "inline-block",
    padding: "6px 12px",
    borderRadius: "999px",
    background: "#eef4ff",
    color: "#3157a6",
    fontSize: "10px",
    fontWeight: "800",
    letterSpacing: "1px",
    marginBottom: "10px"
  },

  title: {
    margin: "0 0 10px",
    color: "#101828"
  },

  description: {
    color: "#667085",
    maxWidth: "700px",
    margin: "0 auto 22px",
    lineHeight: "1.6"
  },

  infoGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(160px, 1fr))",
    gap: "12px",
    marginTop: "22px"
  },

  infoBox: {
    padding: "14px",
    borderRadius: "11px",
    background: "#f8fafc",
    display: "flex",
    flexDirection: "column",
    gap: "5px"
  },

  infoLabel: {
    color: "#667085",
    fontSize: "12px"
  },

  blueNotice: {
    marginTop: "22px",
    padding: "15px 18px",
    borderRadius: "12px",
    background: "#eef4ff",
    border:
      "1px solid #dce5ff",
    color: "#344054",
    lineHeight: "1.6",
    fontSize: "14px"
  },

  success: {
    maxWidth: "920px",
    margin: "0 auto 16px",
    background: "#ecfdf3",
    border:
      "1px solid #abefc6",
    padding: "13px",
    borderRadius: "10px"
  },

  error: {
    maxWidth: "920px",
    margin: "0 auto 16px",
    background: "#fef3f2",
    border:
      "1px solid #fecdca",
    padding: "13px",
    borderRadius: "10px",
    color: "#b42318"
  },

  progressCard: {
    maxWidth: "920px",
    margin: "0 auto 16px",
    background: "#ffffff",
    borderRadius: "16px",
    padding: "18px",
    boxShadow:
      "0 3px 14px rgba(0,0,0,.05)"
  },

  progressTop: {
    display: "flex",
    justifyContent: "space-between",
    gap: "15px",
    marginBottom: "12px"
  },

  progressSmall: {
    color: "#667085",
    fontSize: "12px",
    marginTop: "3px"
  },

  progressPercent: {
    fontSize: "22px",
    fontWeight: "900",
    color: "#3157a6"
  },

  progressTrack: {
    height: "9px",
    borderRadius: "999px",
    background: "#eaecf0",
    overflow: "hidden"
  },

  progressFill: {
    height: "100%",
    borderRadius: "999px",
    background: "#3157a6"
  },

  seriesRow: {
    display: "grid",
    gridTemplateColumns:
      "repeat(5,1fr)",
    gap: "7px",
    marginTop: "14px"
  },

  seriesBadge: {
    padding: "9px 5px",
    borderRadius: "9px",
    background: "#f8fafc",
    border:
      "1px solid #eaecf0",
    textAlign: "center",
    fontSize: "11px",
    color: "#667085",
    fontWeight: "700"
  },

  seriesBadgeActive: {
    background: "#eef4ff",
    border:
      "1px solid #b9ccff",
    color: "#3157a6"
  },

  seriesCount: {
    display: "block",
    fontSize: "9px",
    marginTop: "2px"
  },

  sectionHeader: {
    maxWidth: "920px",
    margin: "0 auto 16px",
    background: "#ffffff",
    padding: "15px 18px",
    borderRadius: "14px",
    boxShadow:
      "0 3px 14px rgba(0,0,0,.05)",
    display: "flex",
    alignItems: "center",
    gap: "13px"
  },

  sectionNumber: {
    width: "46px",
    height: "46px",
    borderRadius: "12px",
    background: "#3157a6",
    color: "#ffffff",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontWeight: "900",
    fontSize: "20px"
  },

  sectionTitle: {
    color: "#101828",
    fontSize: "16px"
  },

  sectionSubtitle: {
    color: "#667085",
    fontSize: "12px",
    marginTop: "3px"
  },

  testCard: {
    maxWidth: "920px",
    margin: "0 auto 16px",
    background: "#ffffff",
    borderRadius: "18px",
    padding: "24px",
    boxShadow:
      "0 4px 20px rgba(0,0,0,.06)"
  },

  questionTop: {
    display: "flex",
    justifyContent:
      "space-between",
    alignItems: "center"
  },

  testCode: {
    color: "#3157a6",
    fontWeight: "800",
    fontSize: "11px"
  },

  questionTitle: {
    margin: "4px 0 0",
    fontSize: "22px"
  },

  counter: {
    fontSize: "24px",
    fontWeight: "900",
    color: "#3157a6"
  },

  imageContainer: {
    minHeight: "300px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    border:
      "1px solid #eaecf0",
    borderRadius: "14px",
    marginTop: "20px",
    padding: "15px"
  },

  testImage: {
    maxWidth: "100%",
    maxHeight: "650px",
    objectFit: "contain"
  },

  answerInstruction: {
    textAlign: "center",
    margin: "22px 0 13px",
    fontWeight: "700"
  },

  numberOptions: {
    display: "grid",
    gap: "10px"
  },

  answerButton: {
    minHeight: "55px",
    border:
      "2px solid #e4e7ec",
    borderRadius: "12px",
    background: "#ffffff",
    fontSize: "17px",
    fontWeight: "800",
    cursor: "pointer"
  },

  answerButtonSelected: {
    border:
      "2px solid #3157a6",
    background: "#eef4ff",
    color: "#3157a6"
  },

  selectedAnswer: {
    marginTop: "14px",
    textAlign: "center",
    color: "#027a48"
  },

  navigationCard: {
    maxWidth: "920px",
    margin: "0 auto 16px",
    display: "flex",
    justifyContent:
      "space-between",
    background: "#ffffff",
    borderRadius: "16px",
    padding: "18px",
    boxShadow:
      "0 3px 14px rgba(0,0,0,.05)"
  },

  backButton: {
    border:
      "1px solid #d0d5dd",
    background: "#ffffff",
    borderRadius: "10px",
    padding: "12px 20px",
    fontWeight: "700",
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

  disabledButton: {
    opacity: ".45",
    cursor: "not-allowed"
  },

  navigatorCard: {
    maxWidth: "920px",
    margin: "0 auto",
    background: "#ffffff",
    borderRadius: "16px",
    padding: "20px",
    boxShadow:
      "0 3px 14px rgba(0,0,0,.05)"
  },

  navigatorTitle: {
    fontWeight: "800"
  },

  navigatorText: {
    color: "#667085",
    fontSize: "12px",
    margin: "4px 0 14px"
  },

  navigatorGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(45px,1fr))",
    gap: "7px"
  },

  navigatorButton: {
    minHeight: "38px",
    border:
      "1px solid #e4e7ec",
    borderRadius: "8px",
    background: "#ffffff",
    cursor: "pointer",
    fontSize: "11px"
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
    color: "#3157a6",
    fontWeight: "900"
  },

  bigIcon: {
    fontSize: "50px"
  },

  muted: {
    color: "#667085"
  },

  completeBox: {
    marginTop: "24px",
    padding: "18px",
    borderRadius: "12px",
    background: "#f8fafc"
  },

  smallText: {
    color: "#667085",
    fontSize: "14px"
  }
};

export default RavenRH;