import React, { useState } from "react";
import axios from "axios";

const API_URL = import.meta.env.VITE_API_URL || (window.location.protocol === 'https:' ? 'https://reflejoyalma.com' : `http://${window.location.hostname}:5000`);

const PruebaGenericaRH = ({
  token,
  pruebaBase
}) => {
  const [prueba] = useState(
    pruebaBase || null
  );

  const [respuestas, setRespuestas] =
    useState({});

  const [guardando, setGuardando] =
    useState(false);

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
  // SELECCIONAR OPCIÓN
  // ==================================================

  const seleccionarOpcion = (
    idPregunta,
    idOpcion
  ) => {
    setRespuestas((prev) => ({
      ...prev,

      [idPregunta]: {
        id_pregunta_rh:
          idPregunta,

        id_opcion_rh:
          idOpcion
      }
    }));

    setMensaje("");
    setError("");
  };

  // ==================================================
  // RESPUESTA ABIERTA
  // ==================================================

  const escribirRespuesta = (
    idPregunta,
    texto
  ) => {
    setRespuestas((prev) => ({
      ...prev,

      [idPregunta]: {
        id_pregunta_rh:
          idPregunta,

        respuesta:
          texto
      }
    }));

    setMensaje("");
    setError("");
  };

  // ==================================================
  // VALIDAR
  // ==================================================

  const validarCompleta = () => {
    if (
      !prueba?.preguntas?.length
    ) {
      return false;
    }

    for (
      const pregunta
      of prueba.preguntas
    ) {
      const respuesta =
        respuestas[
          pregunta.id_pregunta_rh
        ];

      if (!respuesta) {
        return false;
      }

      if (
        pregunta.tipo_respuesta ===
          "abierta" &&
        !String(
          respuesta.respuesta || ""
        ).trim()
      ) {
        return false;
      }

      if (
        (
          pregunta.tipo_respuesta ===
            "opcion" ||
          pregunta.tipo_respuesta ===
            "escala"
        ) &&
        !respuesta.id_opcion_rh
      ) {
        return false;
      }
    }

    return true;
  };

  // ==================================================
  // GUARDAR RESPUESTAS
  // ==================================================

  const guardarRespuestas =
    async (
      mostrarMensaje = true
    ) => {
      try {
        const lista =
          Object.values(
            respuestas
          );

        if (!lista.length) {
          setError(
            "Debes responder al menos una pregunta."
          );

          return false;
        }

        setGuardando(true);
        setError("");

        await axios.post(
          `${API_URL}/api/prospectos/prueba-publica/${token}/respuestas`,
          {
            respuestas:
              lista
          }
        );

        if (mostrarMensaje) {
          setMensaje(
            "Tus respuestas fueron guardadas."
          );
        }

        return true;

      } catch (err) {
        console.error(
          "❌ Error guardando respuestas:",
          err.response?.data ||
            err
        );

        setError(
          err.response?.data?.message ||
            "No fue posible guardar las respuestas."
        );

        return false;

      } finally {
        setGuardando(false);
      }
    };

  // ==================================================
  // FINALIZAR PRUEBA
  // ==================================================

  const finalizarPrueba =
    async () => {
      if (!validarCompleta()) {
        setError(
          "Debes responder todas las preguntas antes de finalizar."
        );

        return;
      }

      try {
        setFinalizando(true);
        setError("");
        setMensaje("");

        const guardado =
          await guardarRespuestas(
            false
          );

        if (!guardado) {
          return;
        }

        const respuesta =
          await axios.post(
            `${API_URL}/api/prospectos/prueba-publica/${token}/finalizar`
          );

        setResultado(
          respuesta.data?.resultado ||
            null
        );

        setCompletada(true);

      } catch (err) {
        console.error(
          "❌ Error finalizando prueba:",
          err.response?.data ||
            err
        );

        setError(
          err.response?.data?.message ||
            "No fue posible finalizar la prueba."
        );

      } finally {
        setFinalizando(false);
      }
    };

  // ==================================================
  // PRUEBA COMPLETADA
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
                "Prueba psicométrica"}
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
  // VISTA PRINCIPAL
  // ==================================================

  return (
    <div style={styles.page}>
      <div style={styles.container}>

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
                "Psicométrica"
              }
            />

          </div>

          <div style={styles.notice}>
            Lee cuidadosamente cada
            pregunta y selecciona la
            respuesta que mejor represente
            tu respuesta.
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

        {!prueba?.preguntas?.length ? (

          <div style={styles.mainCard}>
            <h3>
              Esta evaluación todavía no
              contiene preguntas.
            </h3>
          </div>

        ) : (

          prueba.preguntas.map(
            (
              pregunta,
              indice
            ) => {
              const respuestaActual =
                respuestas[
                  pregunta
                    .id_pregunta_rh
                ];

              return (
                <div
                  key={
                    pregunta
                      .id_pregunta_rh
                  }
                  style={
                    styles.questionCard
                  }
                >

                  <div style={styles.number}>
                    Pregunta{" "}
                    {indice + 1}
                  </div>

                  <h3 style={styles.questionText}>
                    {
                      pregunta
                        .texto_pregunta
                    }
                  </h3>

                  {(
                    pregunta
                      .tipo_respuesta ===
                      "opcion" ||
                    pregunta
                      .tipo_respuesta ===
                      "escala"
                  ) && (

                    <div style={styles.options}>

                      {pregunta.opciones?.map(
                        (opcion) => {
                          const seleccionada =
                            Number(
                              respuestaActual
                                ?.id_opcion_rh
                            ) ===
                            Number(
                              opcion
                                .id_opcion_rh
                            );

                          return (
                            <label
                              key={
                                opcion
                                  .id_opcion_rh
                              }
                              style={{
                                ...styles.option,

                                ...(seleccionada
                                  ? styles.optionSelected
                                  : {})
                              }}
                            >

                              <input
                                type="radio"
                                name={
                                  `pregunta-${pregunta.id_pregunta_rh}`
                                }
                                checked={
                                  seleccionada
                                }
                                onChange={() =>
                                  seleccionarOpcion(
                                    pregunta
                                      .id_pregunta_rh,

                                    opcion
                                      .id_opcion_rh
                                  )
                                }
                              />

                              <span>
                                {
                                  opcion
                                    .texto_opcion
                                }
                              </span>

                            </label>
                          );
                        }
                      )}

                    </div>
                  )}

                  {pregunta
                    .tipo_respuesta ===
                    "abierta" && (

                    <textarea
                      style={styles.textarea}
                      rows={5}
                      placeholder="Escribe tu respuesta..."
                      value={
                        respuestaActual
                          ?.respuesta ||
                        ""
                      }
                      onChange={(e) =>
                        escribirRespuesta(
                          pregunta
                            .id_pregunta_rh,

                          e.target.value
                        )
                      }
                    />

                  )}

                </div>
              );
            }
          )

        )}

        {prueba?.preguntas?.length >
          0 && (

          <div style={styles.actions}>

            <button
              type="button"
              style={styles.saveButton}
              disabled={
                guardando ||
                finalizando
              }
              onClick={() =>
                guardarRespuestas(
                  true
                )
              }
            >
              {guardando
                ? "Guardando..."
                : "💾 Guardar respuestas"}
            </button>

            <button
              type="button"
              style={styles.finishButton}
              disabled={
                guardando ||
                finalizando
              }
              onClick={
                finalizarPrueba
              }
            >
              {finalizando
                ? "Finalizando..."
                : "✅ Finalizar evaluación"}
            </button>

          </div>

        )}

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

  container: {
    maxWidth: "860px",
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

  notice: {
    marginTop: "22px",
    padding: "14px",
    borderRadius: "10px",
    background: "#f2f4f7",
    color: "#475467",
    lineHeight: "1.6"
  },

  success: {
    maxWidth: "920px",
    margin: "0 auto 16px",
    background: "#ecfdf3",
    border: "1px solid #abefc6",
    padding: "13px",
    borderRadius: "10px",
    boxSizing: "border-box"
  },

  error: {
    maxWidth: "920px",
    margin: "0 auto 16px",
    background: "#fef3f2",
    border: "1px solid #fecdca",
    padding: "13px",
    borderRadius: "10px",
    color: "#b42318",
    boxSizing: "border-box"
  },

  questionCard: {
    background: "#ffffff",
    borderRadius: "16px",
    padding: "24px",
    marginBottom: "16px",
    boxShadow:
      "0 3px 14px rgba(0,0,0,.05)"
  },

  number: {
    fontSize: "13px",
    fontWeight: "700",
    color: "#667085",
    marginBottom: "8px"
  },

  questionText: {
    marginTop: 0,
    lineHeight: 1.5
  },

  options: {
    display: "flex",
    flexDirection: "column",
    gap: "10px",
    marginTop: "18px"
  },

  option: {
    display: "flex",
    alignItems: "center",
    gap: "12px",
    border:
      "1px solid #e4e7ec",
    borderRadius: "10px",
    padding: "13px",
    cursor: "pointer"
  },

  optionSelected: {
    border:
      "2px solid #2563eb",
    background:
      "#eff6ff"
  },

  textarea: {
    width: "100%",
    boxSizing: "border-box",
    border:
      "1px solid #d0d5dd",
    borderRadius: "10px",
    padding: "12px",
    fontSize: "15px",
    resize: "vertical",
    marginTop: "12px"
  },

  actions: {
    background: "#ffffff",
    borderRadius: "16px",
    padding: "20px",
    display: "flex",
    flexWrap: "wrap",
    gap: "12px",
    justifyContent: "flex-end",
    boxShadow:
      "0 3px 14px rgba(0,0,0,.05)"
  },

  saveButton: {
    border:
      "1px solid #d0d5dd",
    background: "#ffffff",
    borderRadius: "10px",
    padding: "12px 18px",
    cursor: "pointer",
    fontWeight: "700"
  },

  finishButton: {
    border: "none",
    background: "#1570ef",
    color: "#ffffff",
    borderRadius: "10px",
    padding: "12px 22px",
    cursor: "pointer",
    fontWeight: "800"
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

export default PruebaGenericaRH;