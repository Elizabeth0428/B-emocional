import React, {
  useCallback,
  useEffect,
  useMemo,
  useState
} from "react";

import axios from "axios";

import { getToken } from "../services/AuthService";

import {
  useNavigate,
  useParams
} from "react-router-dom";

const API_URL = import.meta.env.VITE_API_URL || (window.location.protocol === 'https:' ? 'https://reflejoyalma.com' : `http://${window.location.hostname}:5000`);

const PruebasProspecto = () => {
  const { idProspecto } = useParams();
  const navigate = useNavigate();

  const [
    prospecto,
    setProspecto
  ] = useState(null);

  const [
    disponibles,
    setDisponibles
  ] = useState([]);

  const [
    habilitadas,
    setHabilitadas
  ] = useState([]);

  const [
    cargando,
    setCargando
  ] = useState(true);

  const [
    habilitando,
    setHabilitando
  ] = useState(null);

  const [
    mensaje,
    setMensaje
  ] = useState("");

  const [
    error,
    setError
  ] = useState("");

  const token =
    getToken();

  /* ==================================================
     CONFIGURACIÓN AXIOS
  ================================================== */

  const config = useMemo(
    () => ({
      headers: {
        Authorization:
          `Bearer ${token}`
      }
    }),
    [token]
  );

  // ==================================================
  // CARGAR PRUEBAS
  // ==================================================

  const cargarDatos = useCallback(async () => {
    try {
      setCargando(true);
      setError("");

      const [respuestaDisponibles, respuestaHabilitadas] =
        await Promise.all([
          axios.get(
            `${API_URL}/api/prospectos/${idProspecto}/pruebas/disponibles`,
            config
          ),
          axios.get(
            `${API_URL}/api/prospectos/${idProspecto}/pruebas`,
            config
          )
        ]);

      const dataDisponibles = respuestaDisponibles.data;
      const dataHabilitadas = respuestaHabilitadas.data;

      console.log("🧪 Pruebas disponibles:", dataDisponibles);
      console.log("📊 Pruebas habilitadas:", dataHabilitadas);

      setProspecto(
        dataDisponibles?.prospecto ||
        dataHabilitadas?.prospecto ||
        null
      );

      setDisponibles(
        Array.isArray(dataDisponibles?.pruebas)
          ? dataDisponibles.pruebas
          : []
      );

      setHabilitadas(
        Array.isArray(dataHabilitadas?.pruebas)
          ? dataHabilitadas.pruebas
          : []
      );

    } catch (err) {
      console.error(
        "❌ Error cargando pruebas RH:",
        err.response?.data || err
      );

      setError(
        err.response?.data?.message ||
        "No fue posible cargar las pruebas psicométricas."
      );

    } finally {
      setCargando(false);
    }
  }, [idProspecto, config]);

  useEffect(() => {
    cargarDatos();
  }, [cargarDatos]);

  // ==================================================
  // HABILITAR PRUEBA
  // ==================================================

  const habilitarPrueba = async (prueba) => {
    try {
      setMensaje("");
      setError("");
      setHabilitando(prueba.id_prueba_rh);

      const respuesta = await axios.post(
        `${API_URL}/api/prospectos/${idProspecto}/pruebas/habilitar`,
        {
          id_prueba_rh: prueba.id_prueba_rh
        },
        config
      );

      setMensaje(
        respuesta.data?.message ||
        "Prueba habilitada correctamente."
      );

      await cargarDatos();

    } catch (err) {
      console.error(
        "❌ Error habilitando prueba:",
        err.response?.data || err
      );

      setError(
        err.response?.data?.message ||
        "No fue posible habilitar la prueba."
      );

    } finally {
      setHabilitando(null);
    }
  };

  // ==================================================
  // CREAR ENLACE PÚBLICO
  // ==================================================

  const crearEnlacePublico = (tokenPublico) => {
    if (!tokenPublico) return "";

    return (
      `${window.location.origin}` +
      `/prueba-rh/${tokenPublico}`
    );
  };

  // ==================================================
  // COPIAR ENLACE
  // ==================================================

  const copiarEnlace = async (
  tokenPublico
) => {
  const enlace =
    crearEnlacePublico(
      tokenPublico
    );

  if (!enlace) {
    setError(
      "No se encontró el enlace para copiar."
    );
    return;
  }

  try {
    // Intento moderno
    if (
      navigator.clipboard &&
      window.isSecureContext
    ) {
      await navigator.clipboard.writeText(
        enlace
      );
    } else {
      // Respaldo para HTTP / IP local
      const textarea =
        document.createElement(
          "textarea"
        );

      textarea.value =
        enlace;

      textarea.style.position =
        "fixed";

      textarea.style.left =
        "-9999px";

      textarea.style.top =
        "-9999px";

      document.body.appendChild(
        textarea
      );

      textarea.focus();
      textarea.select();

      const copiado =
        document.execCommand(
          "copy"
        );

      document.body.removeChild(
        textarea
      );

      if (!copiado) {
        throw new Error(
          "El navegador rechazó la copia"
        );
      }
    }

    setMensaje(
      "Enlace copiado correctamente."
    );

    setError("");

  } catch (err) {
    console.error(
      "❌ Error copiando enlace:",
      err
    );

    setError(
      "No se pudo copiar automáticamente. Selecciona el enlace y cópialo manualmente."
    );
  }
};

  // ==================================================
  // FORMATEAR FECHA
  // ==================================================

  const formatearFecha = (fecha) => {
    if (!fecha) return "Sin fecha";

    const date = new Date(fecha);

    if (
      Number.isNaN(
        date.getTime()
      )
    ) {
      return fecha;
    }

    return date.toLocaleString(
      "es-MX",
      {
        dateStyle: "medium",
        timeStyle: "short"
      }
    );
  };

  // ==================================================
  // TEXTO ESTATUS
  // ==================================================

  const textoEstatus = (estatus) => {
    switch (estatus) {
      case "habilitada":
        return "Habilitada";

      case "iniciada":
        return "En proceso";

      case "completada":
        return "Completada";

      case "cancelada":
        return "Cancelada";

      default:
        return estatus || "Sin estatus";
    }
  };

  // ==================================================
  // PRUEBA ACTIVA
  // ==================================================

  const pruebaActiva = (idPruebaRH) => {
    return habilitadas.some(
      (prueba) =>
        Number(prueba.id_prueba_rh) ===
          Number(idPruebaRH) &&
        (
          prueba.estatus === "habilitada" ||
          prueba.estatus === "iniciada"
        )
    );
  };

  // ==================================================
  // CARGANDO
  // ==================================================

  if (cargando) {
    return (
      <div style={styles.page}>
        <div style={styles.container}>
          <div style={styles.section}>
            <h2>
              🧠 Pruebas psicométricas
            </h2>

            <p>
              Cargando información...
            </p>
          </div>
        </div>
      </div>
    );
  }

  // ==================================================
  // VISTA
  // ==================================================

  return (
    <div style={styles.page}>
      <div style={styles.container}>

        {/* ==========================================
            ENCABEZADO
        ========================================== */}

        <div style={styles.header}>

          <button
            type="button"
            style={styles.backButton}
            onClick={() =>
              navigate(
                `/prospecto/${idProspecto}`
              )
            }
          >
            ← Regresar al expediente
          </button>

          <h1 style={styles.title}>
            🧠 Pruebas psicométricas
          </h1>

          <p style={styles.subtitle}>
            Evaluaciones de apoyo para el proceso de
            selección y análisis laboral.
          </p>

        </div>

        {/* ==========================================
            PROSPECTO
        ========================================== */}

        {prospecto && (
          <div style={styles.prospectCard}>

            <div style={styles.avatar}>
              {prospecto.nombre
                ?.charAt(0)
                ?.toUpperCase() || "P"}
            </div>

            <div>

              <h2 style={styles.prospectName}>
                {prospecto.nombre}
              </h2>

              <div style={styles.meta}>
                🆔{" "}
                {prospecto.id_mirror ||
                  "Sin ID MirrorSoul"}
              </div>

              <div style={styles.meta}>
                💼{" "}
                {prospecto.puesto ||
                  "Puesto no especificado"}
              </div>

              <div style={styles.meta}>
                ✉️{" "}
                {prospecto.correo ||
                  "Sin correo"}
              </div>

            </div>

          </div>
        )}

        {/* ==========================================
            MENSAJES
        ========================================== */}

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

        {/* ==========================================
            PRUEBAS DISPONIBLES
        ========================================== */}

        <section style={styles.section}>

          <div style={styles.sectionHeader}>

            <div>
              <h2 style={styles.sectionTitle}>
                📋 Pruebas disponibles
              </h2>

              <p style={styles.sectionText}>
                Selecciona una prueba psicométrica para
                habilitarla al prospecto.
              </p>
            </div>

            <div style={styles.counter}>
              {disponibles.length}
            </div>

          </div>

          {disponibles.length === 0 ? (

            <div style={styles.empty}>

              <div style={styles.emptyIcon}>
                🧪
              </div>

              <h3>
                No hay pruebas psicométricas
              </h3>

              <p>
                No se encontraron instrumentos activos
                disponibles.
              </p>

            </div>

          ) : (

            <div style={styles.grid}>

              {disponibles.map((prueba) => {

                const activa =
                  pruebaActiva(
                    prueba.id_prueba_rh
                  );

                return (
                  <div
                    key={prueba.id_prueba_rh}
                    style={styles.testCard}
                  >

                    <div style={styles.testIcon}>
                      🧩
                    </div>

                    <h3 style={styles.testTitle}>
                      {prueba.nombre}
                    </h3>

                    <p style={styles.description}>
                      {prueba.descripcion ||
                        "Prueba psicométrica de Recursos Humanos."}
                    </p>

                    <div style={styles.tags}>

                      {prueba.categoria && (
                        <span style={styles.tag}>
                          {prueba.categoria}
                        </span>
                      )}

                      {prueba.version && (
                        <span style={styles.tag}>
                          Versión {prueba.version}
                        </span>
                      )}

                    </div>

                    <button
                      type="button"

                      style={
                        activa
                          ? styles.disabledButton
                          : styles.primaryButton
                      }

                      disabled={
                        activa ||
                        habilitando ===
                          prueba.id_prueba_rh
                      }

                      onClick={() =>
                        habilitarPrueba(
                          prueba
                        )
                      }
                    >
                      {habilitando ===
                      prueba.id_prueba_rh
                        ? "Habilitando..."
                        : activa
                        ? "Ya habilitada"
                        : "Habilitar prueba"}
                    </button>

                  </div>
                );
              })}

            </div>

          )}

        </section>

        {/* ==========================================
            PRUEBAS DEL PROSPECTO
        ========================================== */}

        <section style={styles.section}>

          <div style={styles.sectionHeader}>

            <div>

              <h2 style={styles.sectionTitle}>
                📊 Pruebas del prospecto
              </h2>

              <p style={styles.sectionText}>
                Consulta el estado de las pruebas
                asignadas.
              </p>

            </div>

            <div style={styles.counter}>
              {habilitadas.length}
            </div>

          </div>

          {habilitadas.length === 0 ? (

            <div style={styles.empty}>
              <p>
                Todavía no se han habilitado pruebas
                para este prospecto.
              </p>
            </div>

          ) : (

            <div style={styles.historyList}>

              {habilitadas.map((prueba) => (

                <div
                  key={
                    prueba.id_habilitacion
                  }
                  style={
                    styles.historyCard
                  }
                >

                  <div style={styles.historyTop}>

                    <div>

                      <h3 style={styles.testTitle}>
                        {prueba.nombre}
                      </h3>

                      <div style={styles.meta}>
                        Habilitada:{" "}
                        {formatearFecha(
                          prueba.fecha_habilitacion
                        )}
                      </div>

                    </div>

                    <span style={styles.status}>
                      {textoEstatus(
                        prueba.estatus
                      )}
                    </span>

                  </div>

                  {prueba.categoria && (
                    <div style={styles.meta}>
                      Categoría:{" "}
                      {prueba.categoria}
                    </div>
                  )}

                  {prueba.version && (
                    <div style={styles.meta}>
                      Versión:{" "}
                      {prueba.version}
                    </div>
                  )}

                  {/* ==================================
                      ENLACE PÚBLICO
                  ================================== */}

                  {(
                    prueba.estatus ===
                      "habilitada" ||
                    prueba.estatus ===
                      "iniciada"
                  ) &&
                    prueba.token_publico && (

                    <div style={styles.linkBox}>

                      <div style={styles.linkLabel}>
                        🔗 Enlace para el prospecto
                      </div>

                      <input
                        readOnly
                        value={
                          crearEnlacePublico(
                            prueba.token_publico
                          )
                        }
                        style={
                          styles.linkInput
                        }
                      />

                      <button
                        type="button"
                        style={
                          styles.secondaryButton
                        }
                        onClick={() =>
                          copiarEnlace(
                            prueba.token_publico
                          )
                        }
                      >
                        📋 Copiar enlace
                      </button>

                    </div>

                  )}

                  {/* ==================================
                      PRUEBA COMPLETADA
                  ================================== */}

                  {prueba.estatus ===
                    "completada" && (

                    <div style={styles.resultBox}>

                      <div style={styles.resultTitle}>
                        ✅ Prueba completada
                      </div>

                      {prueba.fecha_completada && (
                        <div style={styles.meta}>
                          Finalizada:{" "}
                          {formatearFecha(
                            prueba.fecha_completada
                          )}
                        </div>
                      )}

                      {prueba.resultado_texto && (
                        <p style={styles.resultText}>
                          Resultado registrado
                          correctamente.
                        </p>
                      )}

                    </div>

                  )}

                </div>

              ))}

            </div>

          )}

        </section>

      </div>
    </div>
  );
};

// ==================================================
// ESTILOS
// ==================================================

const styles = {

  page: {
    minHeight: "100vh",
    background: "#f6f8fb",
    padding: "30px 20px"
  },

  container: {
    maxWidth: "1180px",
    margin: "0 auto"
  },

  // ==================================================
  // ENCABEZADO
  // ==================================================

  header: {
    marginBottom: "22px"
  },

  title: {
    margin: "14px 0 6px",
    fontSize: "30px"
  },

  subtitle: {
    margin: 0,
    color: "#667085"
  },

  // ==================================================
  // BOTÓN REGRESAR
  // ==================================================

  backButton: {
    border: "none",
    background:
      "linear-gradient(135deg,#66C8F5,#8BD9FF)",
    color: "#073B57",
    padding: "11px 20px",
    borderRadius: "999px",
    cursor: "pointer",
    fontWeight: "800",
    fontSize: "14px",
    boxShadow:
      "0 5px 14px rgba(75,160,210,.25)",
    whiteSpace: "nowrap"
  },

  // ==================================================
  // PROSPECTO
  // ==================================================

  prospectCard: {
    background: "#ffffff",
    borderRadius: "16px",
    padding: "20px",
    display: "flex",
    gap: "18px",
    alignItems: "center",
    marginBottom: "22px",
    boxShadow:
      "0 4px 18px rgba(0,0,0,.06)"
  },

  avatar: {
    width: "58px",
    height: "58px",
    borderRadius: "50%",
    background: "#e8eef9",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "25px",
    fontWeight: "700"
  },

  prospectName: {
    margin: "0 0 8px"
  },

  meta: {
    color: "#667085",
    fontSize: "14px",
    marginTop: "4px"
  },

  // ==================================================
  // SECCIONES
  // ==================================================

  section: {
    background: "#ffffff",
    borderRadius: "16px",
    padding: "24px",
    marginBottom: "24px",
    boxShadow:
      "0 4px 18px rgba(0,0,0,.05)"
  },

  sectionHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "20px",
    marginBottom: "22px"
  },

  sectionTitle: {
    margin: "0 0 5px"
  },

  sectionText: {
    margin: 0,
    color: "#667085"
  },

  counter: {
    minWidth: "42px",
    height: "42px",
    borderRadius: "12px",
    background: "#eef2f7",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontWeight: "700"
  },

  // ==================================================
  // PRUEBAS DISPONIBLES
  // ==================================================

  grid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(250px, 1fr))",
    gap: "18px"
  },

  testCard: {
    border: "1px solid #e4e7ec",
    borderRadius: "14px",
    padding: "20px"
  },

  testIcon: {
    fontSize: "30px",
    marginBottom: "10px"
  },

  testTitle: {
    margin: "0 0 8px"
  },

  description: {
    color: "#667085",
    minHeight: "42px",
    lineHeight: "1.5"
  },

  tags: {
    display: "flex",
    flexWrap: "wrap",
    gap: "8px",
    marginBottom: "16px"
  },

  tag: {
    padding: "5px 9px",
    background: "#f2f4f7",
    borderRadius: "8px",
    fontSize: "12px"
  },

  primaryButton: {
    width: "100%",
    border: "none",
    borderRadius: "10px",
    padding: "11px",
    cursor: "pointer",
    fontWeight: "700",
    background: "#2563eb",
    color: "white"
  },

  disabledButton: {
    width: "100%",
    border: "none",
    borderRadius: "10px",
    padding: "11px",
    fontWeight: "700",
    background: "#e4e7ec",
    color: "#667085"
  },

  secondaryButton: {
    border: "1px solid #d0d5dd",
    borderRadius: "9px",
    background: "#ffffff",
    padding: "9px 12px",
    cursor: "pointer",
    fontWeight: "600"
  },

  // ==================================================
  // PRUEBAS ASIGNADAS
  // ==================================================

  historyList: {
    display: "flex",
    flexDirection: "column",
    gap: "16px"
  },

  historyCard: {
    border: "1px solid #e4e7ec",
    borderRadius: "14px",
    padding: "20px"
  },

  historyTop: {
    display: "flex",
    justifyContent: "space-between",
    gap: "20px",
    marginBottom: "12px"
  },

  status: {
    height: "fit-content",
    padding: "6px 10px",
    borderRadius: "20px",
    background: "#eef2f7",
    fontSize: "13px",
    fontWeight: "700"
  },

  // ==================================================
  // ENLACE PÚBLICO
  // ==================================================

  linkBox: {
    marginTop: "16px",
    padding: "14px",
    borderRadius: "10px",
    background: "#f8fafc"
  },

  linkLabel: {
    fontWeight: "700",
    marginBottom: "8px"
  },

  linkInput: {
    width: "100%",
    boxSizing: "border-box",
    border: "1px solid #d0d5dd",
    borderRadius: "8px",
    padding: "10px",
    marginBottom: "9px"
  },

  // ==================================================
  // PRUEBA COMPLETADA
  // ==================================================

  resultBox: {
    marginTop: "16px",
    padding: "16px",
    borderRadius: "12px",
    background: "#f8fafc"
  },

  resultTitle: {
    fontWeight: "700",
    marginBottom: "8px"
  },

  resultText: {
    color: "#667085",
    marginBottom: 0
  },

  // ==================================================
  // MENSAJES
  // ==================================================

  success: {
    background: "#ecfdf3",
    border: "1px solid #abefc6",
    padding: "13px",
    borderRadius: "10px",
    marginBottom: "18px"
  },

  error: {
    background: "#fef3f2",
    border: "1px solid #fecdca",
    padding: "13px",
    borderRadius: "10px",
    marginBottom: "18px"
  },

  // ==================================================
  // VACÍO
  // ==================================================

  empty: {
    padding: "30px",
    textAlign: "center",
    color: "#667085"
  },

  emptyIcon: {
    fontSize: "38px"
  }
};

export default PruebasProspecto;