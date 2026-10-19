import React, { useEffect, useState } from "react";
import axios from "axios";

import ClavesBeta3 from "./beta3/ClavesBeta3";
import FigurasBeta3 from "./beta3/FigurasBeta3";
import ParesBeta3 from "./beta3/ParesBeta3";
import ObjetosBeta3 from "./beta3/ObjetosBeta3";
import MatricesBeta3 from "./beta3/MatricesBeta3";

const API_URL = import.meta.env.VITE_API_URL || (window.location.protocol === 'https:' ? 'https://reflejoyalma.com' : `http://${window.location.hostname}:5000`);

const Beta3RH = ({ token, pruebaBase }) => {
  const [prueba, setPrueba] = useState(pruebaBase || null);
  const [subpruebas, setSubpruebas] = useState([]);
  const [indiceSubprueba, setIndiceSubprueba] = useState(0);
  const [subpruebasCompletadas, setSubpruebasCompletadas] = useState([]);
  const [respuestas, setRespuestas] = useState({});
  const [cargando, setCargando] = useState(true);
  const [guardando, setGuardando] = useState(false);
  const [mensaje, setMensaje] = useState("");
  const [error, setError] = useState("");
  const [completada, setCompletada] = useState(false);
  const [resultado, setResultado] = useState(null);

  // ==================================================
  // CARGAR BETA III
  // ==================================================

  useEffect(() => {
    const cargar = async () => {
      try {
        setCargando(true);
        setError("");
        setMensaje("");

        const response = await axios.get(
          `${API_URL}/api/beta3/publica/${token}`
        );

        const pruebaRecibida =
          response.data?.prueba ||
          pruebaBase ||
          null;

        const subpruebasRecibidas =
          Array.isArray(response.data?.subpruebas)
            ? response.data.subpruebas
            : [];

        setPrueba(pruebaRecibida);
        setSubpruebas(subpruebasRecibidas);
        setIndiceSubprueba(0);
      } catch (err) {
        console.error(
          "❌ Error cargando Beta III:",
          err.response?.data || err
        );

        setError(
          err.response?.data?.message ||
          "No fue posible cargar Beta III."
        );
      } finally {
        setCargando(false);
      }
    };

    if (token) {
      cargar();
    }
  }, [token, pruebaBase]);

  // ==================================================
  // GUARDAR SUBPRUEBA
  // ==================================================

  const guardarSubprueba = async (
    subprueba,
    respuestasSubprueba
  ) => {
    try {
      setGuardando(true);
      setError("");

      await axios.post(
        `${API_URL}/api/beta3/publica/${token}/respuestas`,
        {
          id_subprueba: Number(
            subprueba.id_subprueba
          ),

          respuestas: Array.isArray(
            respuestasSubprueba
          )
            ? respuestasSubprueba
            : []
        }
      );

      return true;
    } catch (err) {
      console.error(
        "❌ Error guardando subprueba Beta III:",
        err.response?.data || err
      );

      setError(
        err.response?.data?.message ||
        "No fue posible guardar esta subprueba."
      );

      return false;
    } finally {
      setGuardando(false);
    }
  };

  // ==================================================
  // TERMINAR SUBPRUEBA ACTUAL
  // ==================================================

  const terminarSubprueba = async (
    respuestasSubprueba
  ) => {
    const subprueba =
      subpruebas[indiceSubprueba];

    if (!subprueba) {
      return false;
    }

    setMensaje("");
    setError("");

    // --------------------------------------------------
    // PROTECCIÓN:
    // no marcar terminada una subprueba con 0 respuestas
    // --------------------------------------------------

    if (
      !Array.isArray(respuestasSubprueba) ||
      respuestasSubprueba.length === 0
    ) {
      setError(
        `No se puede terminar "${subprueba.nombre}" sin registrar ninguna respuesta.`
      );

      return false;
    }

    const guardado =
      await guardarSubprueba(
        subprueba,
        respuestasSubprueba
      );

    if (!guardado) {
      return false;
    }

    setRespuestas((prev) => ({
      ...prev,

      [subprueba.id_subprueba]:
        respuestasSubprueba
    }));

    setSubpruebasCompletadas((prev) => {
      const id = Number(
        subprueba.id_subprueba
      );

      if (prev.includes(id)) {
        return prev;
      }

      return [...prev, id];
    });

    setMensaje(
      `${subprueba.nombre} guardada correctamente.`
    );

    if (
      indiceSubprueba <
      subpruebas.length - 1
    ) {
      setIndiceSubprueba(
        (prev) => prev + 1
      );

      window.scrollTo({
        top: 0,
        behavior: "smooth"
      });
    }

    return true;
  };

  // ==================================================
  // FINALIZAR BETA III
  // ==================================================

  const finalizarBeta3 = async () => {
    if (
      subpruebasCompletadas.length !==
      subpruebas.length
    ) {
      setError(
        "Todavía faltan subpruebas por completar."
      );

      return false;
    }

    try {
      setGuardando(true);
      setError("");
      setMensaje("");

      const response =
        await axios.post(
          `${API_URL}/api/beta3/publica/${token}/finalizar`,
          {}
        );

      setResultado(
        response.data?.resultado ||
        null
      );

      setCompletada(true);

      return true;
    } catch (err) {
      // ------------------------------------------------
      // 409 CONTROLADO:
      // faltan claves oficiales de corrección.
      // No es un fallo técnico de la aplicación.
      // ------------------------------------------------

      if (
        err.response?.data?.codigo ===
        "BETA3_CLAVES_INCOMPLETAS"
      ) {
        console.warn(
          "⚠️ Beta III pendiente de claves oficiales:",
          err.response.data
        );

        setError("");

        setMensaje(
          `La evaluación quedó guardada correctamente. Aún faltan ${err.response.data.total_pendientes} claves oficiales de corrección para calcular el resultado final.`
        );

        return false;
      }

      // ------------------------------------------------
      // ERROR REAL
      // ------------------------------------------------

      console.error(
        "❌ Error finalizando Beta III:",
        err.response?.data || err
      );

      setMensaje("");

      setError(
        err.response?.data?.message ||
        "No fue posible finalizar Beta III."
      );

      return false;
    } finally {
      setGuardando(false);
    }
  };

  // ==================================================
  // CARGANDO
  // ==================================================

  if (cargando) {
    return (
      <PantallaMensaje>
        <h2>🧠 MirrorSoul</h2>

        <p>
          Cargando Beta III...
        </p>
      </PantallaMensaje>
    );
  }

  // ==================================================
  // ERROR TOTAL
  // ==================================================

  if (
    error &&
    !subpruebas.length
  ) {
    return (
      <PantallaMensaje>
        <div
          style={{
            fontSize: "48px"
          }}
        >
          ⚠️
        </div>

        <h2>
          No fue posible abrir Beta III
        </h2>

        <p>
          {error}
        </p>
      </PantallaMensaje>
    );
  }

  // ==================================================
  // COMPLETADA
  // ==================================================

  if (completada) {
    return (
      <PantallaMensaje>
        <div
          style={{
            fontSize: "54px"
          }}
        >
          ✅
        </div>

        <h1>
          Evaluación completada
        </h1>

        <p>
          Tus respuestas fueron
          registradas correctamente.
        </p>

        <div style={styles.completeBox}>
          <strong>
            {prueba?.nombre ||
              "Beta III"}
          </strong>

          <p>
            El área de Recursos Humanos
            podrá consultar los resultados
            de esta evaluación.
          </p>
        </div>

        {resultado && (
          <p style={styles.completeText}>
            La evaluación fue procesada
            correctamente.
          </p>
        )}
      </PantallaMensaje>
    );
  }

  // ==================================================
  // SIN SUBPRUEBAS
  // ==================================================

  if (!subpruebas.length) {
    return (
      <PantallaMensaje>
        <h3>
          Beta III todavía no contiene
          subpruebas disponibles.
        </h3>
      </PantallaMensaje>
    );
  }

  // ==================================================
  // SUBPRUEBA ACTUAL
  // ==================================================

  const subprueba =
    subpruebas[indiceSubprueba];

  if (!subprueba) {
    return (
      <PantallaMensaje>
        <h3>
          No fue posible cargar la
          subprueba actual.
        </h3>
      </PantallaMensaje>
    );
  }

  const idSubprueba =
    Number(
      subprueba.id_subprueba
    );

  // ==================================================
  // CONTENIDO
  // ==================================================

  let contenido = null;

  // ==================================================
  // 1. CLAVES
  // ==================================================

  if (idSubprueba === 1) {
    contenido = (
      <ClavesBeta3
        subprueba={subprueba}
        guardando={guardando}
        onTerminar={terminarSubprueba}
      />
    );
  }

  // ==================================================
  // 2. FIGURAS INCOMPLETAS
  // ==================================================

  else if (idSubprueba === 2) {
    contenido = (
      <FigurasBeta3
        subprueba={subprueba}
        guardando={guardando}
        onTerminar={terminarSubprueba}
      />
    );
  }

  // ==================================================
  // 3. PARES IGUALES / DESIGUALES
  // ==================================================

  else if (idSubprueba === 3) {
    contenido = (
      <ParesBeta3
        subprueba={subprueba}
        guardando={guardando}
        onTerminar={terminarSubprueba}
      />
    );
  }

  // ==================================================
  // 4. OBJETOS EQUIVOCADOS
  // ==================================================

  else if (idSubprueba === 4) {
    contenido = (
      <ObjetosBeta3
        subprueba={subprueba}
        guardando={guardando}
        onTerminar={terminarSubprueba}
      />
    );
  }

  // ==================================================
  // 5. MATRICES
  // ==================================================

  else if (idSubprueba === 5) {
    contenido = (
      <MatricesBeta3
        subprueba={subprueba}
        guardando={guardando}
        onTerminar={terminarSubprueba}
      />
    );
  }

  // ==================================================
  // SUBPRUEBA DESCONOCIDA
  // ==================================================

  else {
    contenido = (
      <div style={styles.pendingCard}>
        <div
          style={
            styles.pendingNumber
          }
        >
          ?
        </div>

        <h2>
          Subprueba no reconocida
        </h2>

        <p
          style={
            styles.pendingText
          }
        >
          No existe una interfaz
          configurada para esta
          subprueba.
        </p>
      </div>
    );
  }

  // ==================================================
  // VISTA PRINCIPAL
  // ==================================================

  return (
    <div style={styles.page}>
      <div style={styles.container}>

        {/* ENCABEZADO */}

        <div style={styles.headerCard}>

          <div style={styles.brand}>
            🧠 MirrorSoul
          </div>

          <div style={styles.badge}>
            PRUEBA PSICOMÉTRICA
          </div>

          <h1 style={styles.title}>
            {prueba?.nombre ||
              "Beta III"}
          </h1>

          <p style={styles.description}>
            {prueba?.descripcion ||
              "Prueba psicométrica no verbal de capacidad intelectual compuesta por cinco subpruebas."}
          </p>

          <div style={styles.infoGrid}>

            <InfoBox
              label="Participante"

              value={
                prueba?.participante ||
                prueba?.prospecto_nombre ||
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
        </div>

        {/* PROGRESO */}

        <div style={styles.progressCard}>

          {subpruebas.map(
            (
              item,
              index
            ) => {
              const id =
                Number(
                  item.id_subprueba
                );

              const activa =
                index ===
                indiceSubprueba;

              const completadaItem =
                subpruebasCompletadas
                  .includes(id);

              return (
                <div
                  key={
                    item.id_subprueba
                  }

                  style={{
                    ...styles.progressItem,

                    ...(activa
                      ? styles.progressItemActive
                      : {}),

                    ...(completadaItem
                      ? styles.progressItemDone
                      : {})
                  }}
                >
                  <strong>
                    {index + 1}
                  </strong>

                  <span>
                    {item.nombre}
                  </span>

                  {completadaItem && (
                    <small
                      style={
                        styles.doneText
                      }
                    >
                      ✓ Terminada
                    </small>
                  )}

                  {activa &&
                    !completadaItem && (
                    <small
                      style={
                        styles.activeText
                      }
                    >
                      En curso
                    </small>
                  )}
                </div>
              );
            }
          )}

        </div>

        {/* MENSAJE CORRECTO / AVISO */}

        {mensaje && (
          <div
            style={
              styles.success
            }
          >
            ✅ {mensaje}
          </div>
        )}

        {/* ERROR REAL */}

        {error && (
          <div
            style={
              styles.error
            }
          >
            ❌ {error}
          </div>
        )}

        {/* SUBPRUEBA */}

        {contenido}

        {/* FINALIZACIÓN */}

        {subpruebas.length > 0 &&
          subpruebasCompletadas.length ===
            subpruebas.length && (

          <div
            style={
              styles.finalCard
            }
          >
            <h3>
              Has completado las cinco
              subpruebas.
            </h3>

            <p>
              Ya puedes finalizar
              Beta III.
            </p>

            <button
              type="button"

              style={
                styles.finishButton
              }

              onClick={
                finalizarBeta3
              }

              disabled={
                guardando
              }
            >
              {guardando
                ? "Procesando..."
                : "✅ Finalizar Beta III"}
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
      <span
        style={
          styles.infoLabel
        }
      >
        {label}
      </span>

      <strong>
        {value}
      </strong>
    </div>
  );
}

// ==================================================
// PANTALLA GENERAL
// ==================================================

function PantallaMensaje({
  children
}) {
  return (
    <div style={styles.page}>
      <div
        style={
          styles.messageCard
        }
      >
        {children}
      </div>
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
    maxWidth: "1180px",
    margin: "0 auto"
  },

  headerCard: {
    background: "#ffffff",
    borderRadius: "20px",
    padding: "28px",
    textAlign: "center",
    boxShadow:
      "0 4px 20px rgba(0,0,0,.06)",
    marginBottom: "18px"
  },

  brand: {
    fontSize: "21px",
    fontWeight: "900",
    marginBottom: "10px"
  },

  badge: {
    display: "inline-block",
    background: "#eef4ff",
    color: "#3157a6",
    borderRadius: "999px",
    padding: "6px 13px",
    fontSize: "11px",
    fontWeight: "800"
  },

  title: {
    margin: "12px 0 8px",
    color: "#101828"
  },

  description: {
    color: "#667085",
    lineHeight: "1.6",
    maxWidth: "750px",
    margin:
      "0 auto 10px"
  },

  infoGrid: {
    display: "grid",

    gridTemplateColumns:
      "repeat(auto-fit,minmax(180px,1fr))",

    gap: "12px",
    marginTop: "22px"
  },

  infoBox: {
    background: "#f8fafc",
    borderRadius: "12px",
    padding: "14px",

    display: "flex",
    flexDirection: "column",

    gap: "5px"
  },

  infoLabel: {
    color: "#667085",
    fontSize: "12px"
  },

  progressCard: {
    display: "grid",

    gridTemplateColumns:
      "repeat(5,minmax(0,1fr))",

    gap: "8px",

    background: "#ffffff",

    borderRadius: "16px",

    padding: "14px",

    marginBottom: "18px",

    boxShadow:
      "0 3px 14px rgba(0,0,0,.05)"
  },

  progressItem: {
    minHeight: "72px",

    borderRadius: "11px",

    border:
      "1px solid #e4e7ec",

    background: "#f8fafc",

    color: "#667085",

    display: "flex",

    flexDirection: "column",

    alignItems: "center",

    justifyContent: "center",

    textAlign: "center",

    gap: "3px",

    padding: "6px",

    boxSizing: "border-box",

    fontSize: "12px"
  },

  progressItemActive: {
    background: "#eef4ff",

    border:
      "1px solid #b9ccff",

    color: "#3157a6"
  },

  progressItemDone: {
    background: "#ecfdf3",

    border:
      "1px solid #abefc6",

    color: "#027a48"
  },

  doneText: {
    color: "#027a48",
    fontWeight: "800",
    fontSize: "10px"
  },

  activeText: {
    color: "#3157a6",
    fontWeight: "800",
    fontSize: "10px"
  },

  success: {
    background: "#ecfdf3",

    border:
      "1px solid #abefc6",

    borderRadius: "10px",

    padding: "13px",

    marginBottom: "15px",

    color: "#027a48"
  },

  error: {
    background: "#fef3f2",

    border:
      "1px solid #fecdca",

    borderRadius: "10px",

    padding: "13px",

    marginBottom: "15px",

    color: "#b42318"
  },

  pendingCard: {
    background: "#ffffff",

    borderRadius: "18px",

    padding: "40px 30px",

    textAlign: "center",

    boxShadow:
      "0 4px 20px rgba(0,0,0,.06)"
  },

  pendingNumber: {
    width: "50px",

    height: "50px",

    borderRadius: "14px",

    background: "#eef4ff",

    color: "#3157a6",

    display: "flex",

    alignItems: "center",

    justifyContent: "center",

    margin: "0 auto 14px",

    fontSize: "22px",

    fontWeight: "900"
  },

  pendingText: {
    color: "#667085",

    maxWidth: "620px",

    margin:
      "0 auto 18px",

    lineHeight: "1.6"
  },

  finalCard: {
    marginTop: "18px",

    background: "#ffffff",

    borderRadius: "18px",

    padding: "30px",

    textAlign: "center",

    boxShadow:
      "0 4px 20px rgba(0,0,0,.06)"
  },

  finishButton: {
    border: "none",

    borderRadius: "10px",

    background: "#1570ef",

    color: "#ffffff",

    padding: "13px 25px",

    fontWeight: "800",

    cursor: "pointer"
  },

  messageCard: {
    maxWidth: "760px",

    margin: "80px auto",

    background: "#ffffff",

    borderRadius: "18px",

    padding: "35px",

    textAlign: "center",

    boxShadow:
      "0 4px 20px rgba(0,0,0,.06)"
  },

  completeBox: {
    background: "#f8fafc",

    borderRadius: "12px",

    padding: "18px",

    marginTop: "20px"
  },

  completeText: {
    color: "#667085"
  }
};

export default Beta3RH;