// src/views/ResponderPrueba.jsx

import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";

const API_URL = import.meta.env.VITE_API_URL || (window.location.protocol === 'https:' ? 'https://reflejoyalma.com' : `http://${window.location.hostname}:5000`);

export default function ResponderPrueba() {
  const { idHabilitacion } = useParams();

  const [prueba, setPrueba] = useState(null);
  const [respuestas, setRespuestas] = useState({});
  const [finalizado, setFinalizado] = useState(null);
  const [loading, setLoading] = useState(true);
  const [enviando, setEnviando] = useState(false);
  const [error, setError] = useState("");

  const esCleaver =
    String(prueba?.tipo || "").toLowerCase() === "cleaver" ||
    Number(prueba?.id_prueba) === 4;

  /* ==================================================
     CARGAR PRUEBA
  ================================================== */
  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);
        setError("");

        if (!idHabilitacion) {
          throw new Error(
            "No se recibió idHabilitacion en la URL"
          );
        }

        console.log(
          "🔗 ID habilitación recibido:",
          idHabilitacion
        );

        const res = await fetch(
          `${API_URL}/api/evaluation/pruebas/habilitacion/${idHabilitacion}`
        );

        const data = await res
          .json()
          .catch(() => ({}));

        if (!res.ok) {
          throw new Error(
            data?.message ||
            "No se pudo cargar la prueba"
          );
        }

        console.log(
          "✅ Prueba recibida:",
          data
        );

        setPrueba(data);
      } catch (err) {
        console.error(
          "❌ Error al obtener prueba:",
          err
        );

        setError(
          err?.message ||
          "No se pudo cargar la prueba."
        );
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, [idHabilitacion]);

  /* ==================================================
     PRUEBAS NORMALES
  ================================================== */
  const handleRespuesta = (
    idPregunta,
    idOpcion
  ) => {
    setRespuestas((prev) => ({
      ...prev,
      [idPregunta]: Number(idOpcion)
    }));
  };

  /* ==================================================
     CLEAVER
  ================================================== */
  const handleCleaverRespuesta = (
    idPregunta,
    tipo,
    idOpcion
  ) => {
    const opcion = Number(idOpcion);

    setRespuestas((prev) => {
      const actual =
        prev[idPregunta] || {
          mas: null,
          menos: null
        };

      /*
        No permitir usar la misma palabra
        como MÁS y MENOS.
      */
      if (
        tipo === "mas" &&
        Number(actual.menos) === opcion
      ) {
        alert(
          "⚠️ Esa palabra ya está seleccionada como MENOS. Elige otra para MÁS."
        );

        return prev;
      }

      if (
        tipo === "menos" &&
        Number(actual.mas) === opcion
      ) {
        alert(
          "⚠️ Esa palabra ya está seleccionada como MÁS. Elige otra para MENOS."
        );

        return prev;
      }

      return {
        ...prev,

        [idPregunta]: {
          ...actual,
          [tipo]: opcion
        }
      };
    });
  };

  /* ==================================================
     VALIDAR CLEAVER
  ================================================== */
  const validarCleaver = () => {
    if (
      !Array.isArray(prueba?.preguntas) ||
      prueba.preguntas.length !== 24
    ) {
      alert(
        "❌ La prueba Cleaver debe contener exactamente 24 grupos."
      );

      return false;
    }

    const incompletos = [];

    for (const pregunta of prueba.preguntas) {
      const respuesta =
        respuestas[pregunta.id_pregunta];

      if (
        !respuesta?.mas ||
        !respuesta?.menos
      ) {
        incompletos.push(
          pregunta.texto ||
          `Grupo ${pregunta.id_pregunta}`
        );
      }
    }

    if (incompletos.length > 0) {
      alert(
        `⚠️ Faltan respuestas en:\n\n${incompletos.join(
          "\n"
        )}\n\nCada grupo necesita una opción MÁS y una MENOS.`
      );

      return false;
    }

    for (const pregunta of prueba.preguntas) {
      const respuesta =
        respuestas[pregunta.id_pregunta];

      if (
        Number(respuesta.mas) ===
        Number(respuesta.menos)
      ) {
        alert(
          `⚠️ MÁS y MENOS deben ser diferentes en ${
            pregunta.texto ||
            `Grupo ${pregunta.id_pregunta}`
          }.`
        );

        return false;
      }
    }

    return true;
  };

  /* ==================================================
     ENVIAR CLEAVER
  ================================================== */
  const enviarCleaver = async () => {
    if (!validarCleaver()) {
      return null;
    }

    const values =
      prueba.preguntas.map(
        (pregunta) => ({
          id_pregunta:
            Number(
              pregunta.id_pregunta
            ),

          id_opcion_mas:
            Number(
              respuestas[
                pregunta.id_pregunta
              ].mas
            ),

          id_opcion_menos:
            Number(
              respuestas[
                pregunta.id_pregunta
              ].menos
            )
        })
      );

    console.log(
      "📤 Respuestas Cleaver:",
      values
    );

    /* ==============================
       GUARDAR RESPUESTAS
    ============================== */
    const resGuardar = await fetch(
      `${API_URL}/api/cleaver/respuestas`,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json"
        },

        body: JSON.stringify({
          id_habilitacion:
            prueba.id_habilitacion,

          respuestas: values
        })
      }
    );

    const dataGuardar =
      await resGuardar
        .json()
        .catch(() => ({}));

    if (!resGuardar.ok) {
      throw new Error(
        dataGuardar?.message ||
        "No se pudieron guardar las respuestas Cleaver"
      );
    }

    console.log(
      "✅ Respuestas Cleaver guardadas:",
      dataGuardar
    );

    /* ==============================
       FINALIZAR CLEAVER
    ============================== */
    const resFinal = await fetch(
      `${API_URL}/api/cleaver/finalizar`,
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/json"
        },

        body: JSON.stringify({
          id_habilitacion:
            prueba.id_habilitacion
        })
      }
    );

    const dataFinal =
      await resFinal
        .json()
        .catch(() => ({}));

    if (!resFinal.ok) {
      throw new Error(
        dataFinal?.message ||
        "No se pudo finalizar la prueba Cleaver"
      );
    }

    console.log(
      "✅ Resultado Cleaver guardado:",
      dataFinal
    );

    return dataFinal;
  };

  /* ==================================================
     ENVIAR PRUEBA NORMAL
  ================================================== */
  const enviarPruebaNormal = async () => {
    if (
      !Array.isArray(prueba?.preguntas) ||
      prueba.preguntas.length === 0
    ) {
      alert(
        "❌ Esta prueba no tiene preguntas."
      );

      return null;
    }

    const cantidadPreguntas =
      prueba.preguntas.length;

    const cantidadRespuestas =
      Object.keys(respuestas).length;

    if (
      cantidadRespuestas <
      cantidadPreguntas
    ) {
      alert(
        "⚠️ Debes responder todas las preguntas antes de enviar la prueba."
      );

      return null;
    }

    const values =
      prueba.preguntas.map(
        (pregunta) => ({
          id_paciente:
            prueba.id_paciente,

          id_prueba:
            prueba.id_prueba,

          id_pregunta:
            Number(
              pregunta.id_pregunta
            ),

          id_opcion:
            Number(
              respuestas[
                pregunta.id_pregunta
              ]
            )
        })
      );

    console.log(
      "📤 Respuestas normales:",
      values
    );

    /* ==============================
       GUARDAR
    ============================== */
    const resRespuestas =
      await fetch(
        `${API_URL}/api/evaluation/respuestas/publico`,
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/json"
          },

          body: JSON.stringify({
            id_habilitacion:
              prueba.id_habilitacion,

            respuestas:
              values
          })
        }
      );

    const dataRespuestas =
      await resRespuestas
        .json()
        .catch(() => ({}));

    if (!resRespuestas.ok) {
      throw new Error(
        dataRespuestas?.message ||
        "No se pudieron guardar las respuestas"
      );
    }

    console.log(
      "✅ Respuestas guardadas:",
      dataRespuestas
    );

    /* ==============================
       FINALIZAR
    ============================== */
    const resFinal =
      await fetch(
        `${API_URL}/api/evaluation/pruebas/${prueba.id_prueba}/finalizar/publico`,
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/json"
          },

          body: JSON.stringify({
            id_paciente:
              prueba.id_paciente,

            id_habilitacion:
              prueba.id_habilitacion
          })
        }
      );

    const dataFinal =
      await resFinal
        .json()
        .catch(() => ({}));

    if (!resFinal.ok) {
      throw new Error(
        dataFinal?.message ||
        "No se pudo finalizar la prueba"
      );
    }

    console.log(
      "✅ Resultado final:",
      dataFinal
    );

    return dataFinal;
  };

  /* ==================================================
     ENVIAR
  ================================================== */
  const handleEnviar = async () => {
    if (!prueba || enviando) {
      return;
    }

    try {
      setEnviando(true);
      setError("");

      let dataFinal = null;

      if (esCleaver) {
        dataFinal =
          await enviarCleaver();
      } else {
        dataFinal =
          await enviarPruebaNormal();
      }

      /*
        Si la validación detuvo el envío,
        no mostrar pantalla de finalizado.
      */
      if (!dataFinal) {
        return;
      }

      setFinalizado(
        dataFinal
      );
    } catch (err) {
      console.error(
        "❌ Error al enviar respuestas:",
        err
      );

      const mensaje =
        err?.message ||
        "No se pudieron enviar las respuestas.";

      setError(mensaje);

      alert(
        `❌ ${mensaje}`
      );
    } finally {
      setEnviando(false);
    }
  };

  /* ==================================================
     CARGANDO
  ================================================== */
  if (loading) {
    return (
      <div style={loadingContainer}>
        <div style={loadingIcon}>
          🧪
        </div>

        <p style={loadingText}>
          ⏳ Cargando prueba...
        </p>
      </div>
    );
  }

  /* ==================================================
     ERROR DE CARGA
  ================================================== */
  if (!prueba) {
    return (
      <div style={loadingContainer}>
        <div style={errorIcon}>
          ⚠️
        </div>

        <h2 style={errorTitle}>
          No se pudo cargar la prueba
        </h2>

        <p style={errorText}>
          {error ||
            "La prueba no está disponible."}
        </p>
      </div>
    );
  }

  /* ==================================================
     FINALIZADO
  ================================================== */
  if (finalizado) {
    return (
      <div style={container}>
        <div style={successContainer}>
          <div style={successIcon}>
            ✅
          </div>

          <h2 style={successTitle}>
            Prueba enviada correctamente
          </h2>

          <p style={successText}>
            Tus respuestas han sido
            registradas correctamente.
          </p>

          <p style={successSubtext}>
            Los resultados serán revisados
            por el profesional responsable.
          </p>

          <p style={successSubtext}>
            Ya puedes cerrar esta ventana.
          </p>
        </div>
      </div>
    );
  }

  /* ==================================================
     VISTA
  ================================================== */
  return (
    <div style={container}>

      <h2 style={title}>
        🧪 {prueba.nombre}
      </h2>

      <p style={description}>
        {prueba.descripcion ||
          "Responde las siguientes preguntas."}
      </p>

      {/* =================================================
          INSTRUCCIONES CLEAVER
      ================================================= */}
      {esCleaver && (
        <div style={cleaverInstructions}>
          <h3 style={instructionTitle}>
            Instrucciones
          </h3>

          <p style={instructionText}>
            En cada grupo encontrarás
            cuatro palabras.
          </p>

          <p style={instructionText}>
            Selecciona como{" "}
            <strong>MÁS</strong> la palabra
            que mejor te describe y como{" "}
            <strong>MENOS</strong> la palabra
            que menos te describe.
          </p>

          <p style={instructionText}>
            La misma palabra no puede ser
            seleccionada como MÁS y MENOS
            dentro del mismo grupo.
          </p>
        </div>
      )}

      {/* =================================================
          ERROR
      ================================================= */}
      {error && (
        <div style={errorBox}>
          ⚠️ {error}
        </div>
      )}

      {/* =================================================
          PREGUNTAS
      ================================================= */}
      {prueba.preguntas?.map(
        (p, index) => {

          /* ==========================================
             CLEAVER
          ========================================== */
          if (esCleaver) {
            const respuesta =
              respuestas[
                p.id_pregunta
              ] || {
                mas: null,
                menos: null
              };

            const grupoCompleto =
              Boolean(
                respuesta.mas &&
                respuesta.menos
              );

            return (
              <div
                key={`preg-${p.id_pregunta}`}
                style={{
                  ...cleaverQuestionBox,

                  border:
                    grupoCompleto
                      ? "1px solid #A5D6A7"
                      : "1px solid #DDE5F0"
                }}
              >

                <div style={groupHeader}>
                  <div style={groupNumber}>
                    {index + 1}
                  </div>

                  <div>
                    <div style={groupLabel}>
                      GRUPO
                    </div>

                    <div style={groupTitle}>
                      {p.texto ||
                        `Grupo ${index + 1}`}
                    </div>
                  </div>
                </div>

                <div style={cleaverTableHeader}>
                  <div style={wordHeader}>
                    Palabra
                  </div>

                  <div style={choiceHeader}>
                    MÁS
                  </div>

                  <div style={choiceHeader}>
                    MENOS
                  </div>
                </div>

                {p.opciones?.map(
                  (o) => {
                    const idOpcion =
                      Number(
                        o.id_opcion
                      );

                    const seleccionadoMas =
                      Number(
                        respuesta.mas
                      ) ===
                      idOpcion;

                    const seleccionadoMenos =
                      Number(
                        respuesta.menos
                      ) ===
                      idOpcion;

                    const bloqueadoMas =
                      Number(
                        respuesta.menos
                      ) ===
                      idOpcion;

                    const bloqueadoMenos =
                      Number(
                        respuesta.mas
                      ) ===
                      idOpcion;

                    return (
                      <div
                        key={
                          `op-${p.id_pregunta}-${o.id_opcion}`
                        }
                        style={{
                          ...cleaverOptionRow,

                          background:
                            seleccionadoMas ||
                            seleccionadoMenos
                              ? "#F5F8FF"
                              : "#FFFFFF"
                        }}
                      >

                        <div style={wordCell}>
                          {o.texto}
                        </div>

                        {/* MÁS */}
                        <label
                          style={{
                            ...cleaverChoiceCell,

                            cursor:
                              bloqueadoMas
                                ? "not-allowed"
                                : "pointer",

                            opacity:
                              bloqueadoMas
                                ? 0.35
                                : 1
                          }}
                        >
                          <input
                            type="radio"
                            name={
                              `mas_${p.id_pregunta}`
                            }
                            checked={
                              seleccionadoMas
                            }
                            disabled={
                              bloqueadoMas
                            }
                            onChange={() =>
                              handleCleaverRespuesta(
                                p.id_pregunta,
                                "mas",
                                idOpcion
                              )
                            }
                            style={
                              cleaverRadio
                            }
                          />
                        </label>

                        {/* MENOS */}
                        <label
                          style={{
                            ...cleaverChoiceCell,

                            cursor:
                              bloqueadoMenos
                                ? "not-allowed"
                                : "pointer",

                            opacity:
                              bloqueadoMenos
                                ? 0.35
                                : 1
                          }}
                        >
                          <input
                            type="radio"
                            name={
                              `menos_${p.id_pregunta}`
                            }
                            checked={
                              seleccionadoMenos
                            }
                            disabled={
                              bloqueadoMenos
                            }
                            onChange={() =>
                              handleCleaverRespuesta(
                                p.id_pregunta,
                                "menos",
                                idOpcion
                              )
                            }
                            style={
                              cleaverRadio
                            }
                          />
                        </label>
                      </div>
                    );
                  }
                )}

                <div
                  style={{
                    ...groupStatus,

                    color:
                      grupoCompleto
                        ? "#2E7D32"
                        : "#607D8B",

                    fontWeight:
                      grupoCompleto
                        ? "700"
                        : "400"
                  }}
                >
                  {grupoCompleto
                    ? "✅ Grupo completo"
                    : "Selecciona una opción MÁS y una MENOS"}
                </div>

              </div>
            );
          }

          /* ==========================================
             PRUEBAS NORMALES
          ========================================== */
          return (
            <div
              key={`preg-${p.id_pregunta}`}
              style={preguntaBox}
            >

              <p style={questionText}>
                {index + 1}. {p.texto}
              </p>

              {p.opciones?.map(
                (o) => (
                  <label
                    key={
                      `op-${p.id_pregunta}-${o.id_opcion}`
                    }
                    style={
                      normalOption
                    }
                  >

                    <input
                      type="radio"
                      name={
                        `preg_${p.id_pregunta}`
                      }
                      value={
                        o.id_opcion
                      }
                      checked={
                        Number(
                          respuestas[
                            p.id_pregunta
                          ]
                        ) ===
                        Number(
                          o.id_opcion
                        )
                      }
                      onChange={() =>
                        handleRespuesta(
                          p.id_pregunta,
                          Number(
                            o.id_opcion
                          )
                        )
                      }
                      style={{
                        marginRight:
                          "10px"
                      }}
                    />

                    {o.texto}

                  </label>
                )
              )}

            </div>
          );
        }
      )}

      {/* =================================================
          BOTÓN
      ================================================= */}
      <div style={buttonContainer}>
        <button
          type="button"
          style={{
            ...btnEnviar,

            opacity:
              enviando
                ? 0.65
                : 1,

            cursor:
              enviando
                ? "not-allowed"
                : "pointer"
          }}
          disabled={enviando}
          onClick={handleEnviar}
        >
          {enviando
            ? "⏳ Enviando..."
            : "📤 Enviar respuestas"}
        </button>
      </div>
    </div>
  );
}

/* =====================================================
   ESTILOS
===================================================== */

const loadingContainer = {
  maxWidth: "750px",
  margin: "80px auto",
  padding: "40px",
  textAlign: "center",
  fontFamily:
    "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif"
};

const loadingIcon = {
  fontSize: "50px",
  marginBottom: "15px"
};

const loadingText = {
  color: "#607D8B",
  fontSize: "17px"
};

const errorIcon = {
  fontSize: "48px",
  marginBottom: "15px"
};

const errorTitle = {
  color: "#C62828",
  marginBottom: "10px"
};

const errorText = {
  color: "#607D8B",
  fontSize: "16px"
};

const container = {
  maxWidth: "800px",
  margin: "30px auto",
  padding: "30px",
  background: "#ffffff",
  borderRadius: "16px",
  boxShadow:
    "0 6px 20px rgba(0,0,0,0.12)",
  fontFamily:
    "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",
  color: "#212121"
};

const title = {
  textAlign: "center",
  color: "#0D47A1",
  marginBottom: "10px"
};

const description = {
  textAlign: "center",
  marginBottom: "25px",
  color: "#555",
  lineHeight: "1.6"
};

const errorBox = {
  background: "#FFEBEE",
  color: "#B71C1C",
  padding: "14px 16px",
  borderRadius: "10px",
  marginBottom: "20px",
  border: "1px solid #FFCDD2"
};

/* =====================================================
   PRUEBAS NORMALES
===================================================== */

const preguntaBox = {
  marginBottom: "25px",
  padding: "18px",
  background: "#f9f9f9",
  borderRadius: "12px",
  boxShadow:
    "0 3px 8px rgba(0,0,0,0.08)"
};

const questionText = {
  fontWeight: "600",
  marginBottom: "12px",
  color: "#333"
};

const normalOption = {
  display: "flex",
  alignItems: "center",
  marginBottom: "8px",
  cursor: "pointer",
  padding: "8px 10px",
  borderRadius: "6px",
  background: "#ffffff",
  border: "1px solid #ECEFF1"
};

/* =====================================================
   CLEAVER
===================================================== */

const cleaverInstructions = {
  background: "#E3F2FD",
  border: "1px solid #BBDEFB",
  borderRadius: "14px",
  padding: "18px 20px",
  marginBottom: "28px"
};

const instructionTitle = {
  color: "#0D47A1",
  margin: "0 0 10px"
};

const instructionText = {
  color: "#37474F",
  lineHeight: "1.55",
  margin: "5px 0"
};

const cleaverQuestionBox = {
  marginBottom: "24px",
  background: "#ffffff",
  borderRadius: "14px",
  overflow: "hidden",
  boxShadow:
    "0 3px 10px rgba(0,0,0,0.06)"
};

const groupHeader = {
  display: "flex",
  alignItems: "center",
  gap: "12px",
  padding: "16px 18px",
  background: "#F4F7FC",
  borderBottom: "1px solid #DDE5F0"
};

const groupNumber = {
  width: "38px",
  height: "38px",
  borderRadius: "12px",
  background: "#4054B2",
  color: "#ffffff",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontWeight: "700",
  fontSize: "17px"
};

const groupLabel = {
  color: "#90A4AE",
  fontSize: "11px",
  fontWeight: "700",
  letterSpacing: "1px"
};

const groupTitle = {
  color: "#263238",
  fontWeight: "700",
  fontSize: "17px"
};

const cleaverTableHeader = {
  display: "grid",
  gridTemplateColumns:
    "minmax(0, 1fr) 82px 82px",
  background: "#FAFBFD",
  borderBottom: "1px solid #E5EAF0",
  padding: "10px 16px"
};

const wordHeader = {
  fontSize: "12px",
  fontWeight: "700",
  color: "#78909C",
  textTransform: "uppercase"
};

const choiceHeader = {
  fontSize: "12px",
  fontWeight: "700",
  color: "#546E7A",
  textAlign: "center"
};

const cleaverOptionRow = {
  display: "grid",
  gridTemplateColumns:
    "minmax(0, 1fr) 82px 82px",
  alignItems: "center",
  minHeight: "52px",
  padding: "0 16px",
  borderBottom:
    "1px solid #EEF1F4"
};

const wordCell = {
  fontSize: "16px",
  color: "#263238",
  paddingRight: "10px"
};

const cleaverChoiceCell = {
  minHeight: "52px",
  display: "flex",
  alignItems: "center",
  justifyContent: "center"
};

const cleaverRadio = {
  width: "19px",
  height: "19px",
  cursor: "pointer"
};

const groupStatus = {
  padding: "10px 16px",
  fontSize: "13px",
  background: "#FAFBFD",
  textAlign: "right"
};

/* =====================================================
   BOTÓN
===================================================== */

const buttonContainer = {
  textAlign: "center",
  marginTop: "28px"
};

const btnEnviar = {
  background: "#1976D2",
  color: "white",
  border: "none",
  padding: "14px 28px",
  borderRadius: "10px",
  fontWeight: "600",
  fontSize: "16px",
  transition: "all 0.3s ease",
  boxShadow:
    "0 4px 12px rgba(25,118,210,0.35)"
};

/* =====================================================
   FINALIZADO
===================================================== */

const successContainer = {
  textAlign: "center",
  padding: "35px 20px"
};

const successIcon = {
  fontSize: "58px",
  marginBottom: "15px"
};

const successTitle = {
  color: "#2E7D32",
  marginBottom: "12px"
};

const successText = {
  color: "#455A64",
  fontSize: "17px",
  lineHeight: "1.6",
  margin: "0 auto 8px",
  maxWidth: "520px"
};

const successSubtext = {
  color: "#78909C",
  fontSize: "15px",
  lineHeight: "1.5",
  margin: "6px 0"
};