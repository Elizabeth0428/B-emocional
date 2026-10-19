import React, { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";
import { useNavigate, useParams } from "react-router-dom";
import { getToken } from "../services/AuthService";

const API_URL = import.meta.env.VITE_API_URL || (window.location.protocol === 'https:' ? 'https://reflejoyalma.com' : `http://${window.location.hostname}:5000`);

const ReporteIAProspecto = () => {
  const { idProspecto } = useParams();
  const navigate = useNavigate();

  const token = getToken();

  const config = useMemo(
    () => ({
      headers: {
        Authorization: `Bearer ${token}`
      }
    }),
    [token]
  );

  const [prospecto, setProspecto] = useState(null);
  const [reportes, setReportes] = useState([]);
  const [reporteSeleccionado, setReporteSeleccionado] = useState(null);
  const [cargando, setCargando] = useState(true);
  const [generando, setGenerando] = useState(false);
  const [cargandoReporte, setCargandoReporte] = useState(false);
  const [mensaje, setMensaje] = useState("");
  const [error, setError] = useState("");

  // ==================================================
  // CARGAR HISTORIAL DE REPORTES
  // ==================================================

  const cargarReportes = useCallback(async () => {
    try {
      setCargando(true);
      setError("");

      const respuesta = await axios.get(
        `${API_URL}/api/prospectos/${idProspecto}/reportes-ia`,
        config
      );

      setProspecto(
        respuesta.data?.prospecto ||
        null
      );

      const lista =
        Array.isArray(
          respuesta.data?.reportes
        )
          ? respuesta.data.reportes
          : [];

      setReportes(lista);

      if (lista.length) {
        setReporteSeleccionado(
          actual =>
            actual ||
            lista[0]
        );
      }
    } catch (err) {
      console.error(
        "❌ Error cargando reportes IA RH:",
        err
      );

      setError(
        err.response?.data?.message ||
        "No fue posible cargar los reportes."
      );
    } finally {
      setCargando(false);
    }
  }, [
    idProspecto,
    config
  ]);

  useEffect(() => {
    cargarReportes();
  }, [cargarReportes]);

  // ==================================================
  // GENERAR NUEVO PREANÁLISIS
  // ==================================================

  const generarReporte = async () => {
    try {
      setGenerando(true);
      setMensaje("");
      setError("");

      const respuesta = await axios.post(
        `${API_URL}/api/prospectos/${idProspecto}/reporte-ia`,
        {},
        config
      );

      const nuevoReporte =
        respuesta.data?.reporte ||
        null;

      if (nuevoReporte) {
        setReporteSeleccionado(
          nuevoReporte
        );
      }

      setMensaje(
        respuesta.data?.message ||
        "Preanálisis laboral generado correctamente."
      );

      await cargarReportes();
    } catch (err) {
      console.error(
        "❌ Error generando reporte IA RH:",
        err
      );

      setError(
        err.response?.data?.message ||
        "No fue posible generar el preanálisis laboral."
      );
    } finally {
      setGenerando(false);
    }
  };

  // ==================================================
  // ABRIR REPORTE
  // ==================================================

  const abrirReporte = async idReporte => {
    try {
      setCargandoReporte(true);
      setError("");

      const respuesta = await axios.get(
        `${API_URL}/api/prospectos/${idProspecto}/reportes-ia/${idReporte}`,
        config
      );

      setReporteSeleccionado(
        respuesta.data?.reporte ||
        null
      );
    } catch (err) {
      console.error(
        "❌ Error obteniendo reporte IA RH:",
        err
      );

      setError(
        err.response?.data?.message ||
        "No fue posible abrir el reporte."
      );
    } finally {
      setCargandoReporte(false);
    }
  };

  // ==================================================
  // FORMATEAR FECHA
  // ==================================================

  const formatearFecha = fecha => {
    if (!fecha) {
      return "Sin fecha";
    }

    const date =
      new Date(fecha);

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
  // OBTENER TRAZABILIDAD
  // ==================================================

  const obtenerGeneradoDesde = reporte => {
    if (!reporte?.generado_desde) {
      return {
        seguimientos: 0,
        entrevistas: 0,
        grabaciones: 0,
        transcripciones: 0,
        pruebas: 0,
        documentos: 0,
        observaciones: 0
      };
    }

    if (
      typeof reporte.generado_desde ===
      "object"
    ) {
      return reporte.generado_desde;
    }

    try {
      return JSON.parse(
        reporte.generado_desde
      );
    } catch {
      return {
        seguimientos: 0,
        entrevistas: 0,
        grabaciones: 0,
        transcripciones: 0,
        pruebas: 0,
        documentos: 0,
        observaciones: 0
      };
    }
  };

  // ==================================================
  // CARGANDO
  // ==================================================

  if (cargando) {
    return (
      <div style={styles.page}>
        <div style={styles.container}>
          <div style={styles.card}>
            <h2>
              🤖 Preanálisis laboral
            </h2>

            <p>
              Cargando información...
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={styles.page}>
      <div style={styles.container}>

        {/* VOLVER */}

        <button
          style={styles.backButton}
          onClick={() =>
            navigate(
              `/prospecto/${idProspecto}`
            )
          }
        >
          ← Volver al expediente
        </button>

        {/* ENCABEZADO */}

        <div style={styles.header}>
          <div>
            <h1 style={styles.title}>
              🤖 Preanálisis laboral
            </h1>

            <p style={styles.subtitle}>
              Integra la información disponible
              del proceso de selección para
              apoyar la revisión de Recursos
              Humanos.
            </p>
          </div>

          <button
            type="button"
            style={styles.generateButton}
            onClick={generarReporte}
            disabled={generando}
          >
            {generando
              ? "Generando..."
              : "✨ Generar preanálisis"}
          </button>
        </div>

        {/* PROSPECTO */}

        {prospecto && (
          <div style={styles.prospectCard}>
            <div style={styles.avatar}>
              {prospecto.nombre
                ?.charAt(0)
                ?.toUpperCase() ||
                "P"}
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
                Estado:{" "}
                <strong>
                  {prospecto.estatus ||
                    "prospecto"}
                </strong>
              </div>
            </div>
          </div>
        )}

        {/* MENSAJES */}

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

        {/* AVISO */}

        <div style={styles.notice}>
          <strong>
            Información de apoyo para RH
          </strong>

          <p style={styles.noticeText}>
            El preanálisis reúne información del
            proceso de selección y sirve como
            apoyo para la revisión humana. No
            sustituye la decisión del responsable
            de Recursos Humanos ni constituye un
            diagnóstico clínico.
          </p>
        </div>

        {/* CONTENIDO */}

        <div style={styles.layout}>

          {/* HISTORIAL */}

          <div style={styles.historyColumn}>
            <div style={styles.card}>
              <div style={styles.cardHeader}>
                <div>
                  <h2 style={styles.cardTitle}>
                    📋 Historial
                  </h2>

                  <p style={styles.cardSubtitle}>
                    Preanálisis generados para
                    este prospecto.
                  </p>
                </div>

                <div style={styles.counter}>
                  {reportes.length}
                </div>
              </div>

              {reportes.length === 0 ? (
                <div style={styles.empty}>
                  <div style={styles.emptyIcon}>
                    🤖
                  </div>

                  <h3>
                    Aún no hay preanálisis
                  </h3>

                  <p>
                    Cuando exista información
                    suficiente del proceso,
                    genera el primer reporte.
                  </p>
                </div>
              ) : (
                <div style={styles.reportList}>
                  {reportes.map(
                    reporte => {
                      const activo =
                        Number(
                          reporteSeleccionado
                            ?.id_reporte
                        ) ===
                        Number(
                          reporte.id_reporte
                        );

                      return (
                        <button
                          key={
                            reporte.id_reporte
                          }
                          type="button"
                          onClick={() =>
                            abrirReporte(
                              reporte.id_reporte
                            )
                          }
                          style={{
                            ...styles.reportItem,

                            ...(activo
                              ? styles.reportItemActive
                              : {})
                          }}
                        >
                          <div style={styles.reportTop}>
                            <strong>
                              Preanálisis #
                              {reporte.id_reporte}
                            </strong>

                            <span style={styles.reportType}>
                              {reporte.tipo_reporte ===
                              "reporte_laboral"
                                ? "Reporte laboral"
                                : "Preanálisis"}
                            </span>
                          </div>

                          <div style={styles.reportDate}>
                            {formatearFecha(
                              reporte.creado_en
                            )}
                          </div>

                          <div style={styles.reportUser}>
                            {reporte.usuario_registro
                              ? `Generado por ${reporte.usuario_registro}`
                              : "Generado por RH"}
                          </div>
                        </button>
                      );
                    }
                  )}
                </div>
              )}
            </div>
          </div>

          {/* REPORTE SELECCIONADO */}

          <div style={styles.reportColumn}>
            <div style={styles.card}>
              <div style={styles.cardHeader}>
                <div>
                  <h2 style={styles.cardTitle}>
                    📄 Reporte
                  </h2>

                  <p style={styles.cardSubtitle}>
                    Información consolidada del
                    proceso.
                  </p>
                </div>
              </div>

              {cargandoReporte ? (
                <div style={styles.empty}>
                  Cargando reporte...
                </div>
              ) : !reporteSeleccionado ? (
                <div style={styles.empty}>
                  <div style={styles.emptyIcon}>
                    📄
                  </div>

                  <p>
                    Selecciona un reporte o
                    genera uno nuevo.
                  </p>
                </div>
              ) : (
                <>
                  <div style={styles.reportInfo}>
                    <div style={styles.infoBlock}>
                      <span style={styles.infoLabel}>
                        Generado
                      </span>

                      <strong>
                        {formatearFecha(
                          reporteSeleccionado.creado_en
                        )}
                      </strong>
                    </div>

                    <div style={styles.infoBlock}>
                      <span style={styles.infoLabel}>
                        Modelo
                      </span>

                      <strong>
                        {reporteSeleccionado.modelo_ia ||
                          "No especificado"}
                      </strong>
                    </div>
                  </div>

                  {(() => {
                    const fuente =
                      obtenerGeneradoDesde(
                        reporteSeleccionado
                      );

                    return (
                      <div style={styles.sourceBox}>
                        <div style={styles.sourceTitle}>
                          🔎 Información utilizada
                        </div>

                        <div style={styles.sourceGrid}>
                          <div style={styles.sourceItem}>
                            <strong>
                              {fuente.seguimientos || 0}
                            </strong>
                            <span>
                              Seguimientos
                            </span>
                          </div>

                          <div style={styles.sourceItem}>
                            <strong>
                              {fuente.entrevistas || 0}
                            </strong>
                            <span>
                              Entrevistas
                            </span>
                          </div>

                          <div style={styles.sourceItem}>
                            <strong>
                              {fuente.grabaciones || 0}
                            </strong>
                            <span>
                              Grabaciones
                            </span>
                          </div>

                          <div style={styles.sourceItem}>
                            <strong>
                              {fuente.transcripciones || 0}
                            </strong>
                            <span>
                              Transcripciones
                            </span>
                          </div>

                          <div style={styles.sourceItem}>
                            <strong>
                              {fuente.pruebas || 0}
                            </strong>
                            <span>
                              Pruebas
                            </span>
                          </div>

                          <div style={styles.sourceItem}>
                            <strong>
                              {fuente.documentos || 0}
                            </strong>
                            <span>
                              Documentos
                            </span>
                          </div>

                          <div style={styles.sourceItem}>
                            <strong>
                              {fuente.observaciones || 0}
                            </strong>
                            <span>
                              Observaciones
                            </span>
                          </div>
                        </div>
                      </div>
                    );
                  })()}

                  <div style={styles.contentBox}>
                    <pre style={styles.contentText}>
                      {reporteSeleccionado.contenido}
                    </pre>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

const styles = {
  page: {
    minHeight: "100vh",
    background: "#f6f8fb",
    padding: "30px 20px"
  },

  container: {
    maxWidth: "1200px",
    margin: "0 auto"
  },

  backButton: {
    border: "none",
    background:
      "linear-gradient(135deg,#64B5F6,#1976D2)",
    color: "#ffffff",
    padding: "10px 20px",
    marginBottom: "18px",
    borderRadius: "30px",
    cursor: "pointer",
    fontWeight: "700",
    fontSize: "14px",
    boxShadow:
      "0 5px 14px rgba(25,118,210,.25)"
  },

  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "20px",
    flexWrap: "wrap",
    marginBottom: "22px"
  },

  title: {
    margin: "0 0 6px",
    fontSize: "30px"
  },

  subtitle: {
    margin: 0,
    color: "#667085",
    maxWidth: "700px"
  },

  generateButton: {
    border: "none",
    borderRadius: "30px",
    background:
      "linear-gradient(135deg,#7C4DFF,#4F46E5)",
    color: "#ffffff",
    padding: "12px 22px",
    cursor: "pointer",
    fontWeight: "800",
    fontSize: "14px",
    boxShadow:
      "0 5px 14px rgba(79,70,229,.24)"
  },

  prospectCard: {
    background: "#ffffff",
    borderRadius: "16px",
    padding: "20px",
    display: "flex",
    alignItems: "center",
    gap: "18px",
    marginBottom: "20px",
    boxShadow:
      "0 4px 18px rgba(0,0,0,.05)"
  },

  avatar: {
    width: "58px",
    height: "58px",
    borderRadius: "50%",
    background: "#e8eef9",
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    fontSize: "25px",
    fontWeight: "700"
  },

  prospectName: {
    margin: "0 0 8px"
  },

  meta: {
    color: "#667085",
    marginTop: "4px",
    fontSize: "14px"
  },

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

  notice: {
    background: "#fffaf0",
    border: "1px solid #f5d99a",
    borderRadius: "12px",
    padding: "16px",
    marginBottom: "22px"
  },

  noticeText: {
    margin: "7px 0 0",
    color: "#5f4b23",
    lineHeight: 1.5
  },

  layout: {
    display: "grid",
    gridTemplateColumns:
      "minmax(280px, 360px) minmax(0, 1fr)",
    gap: "22px",
    alignItems: "start"
  },

  historyColumn: {
    minWidth: 0
  },

  reportColumn: {
    minWidth: 0
  },

  card: {
    background: "#ffffff",
    borderRadius: "16px",
    padding: "22px",
    boxShadow:
      "0 4px 18px rgba(0,0,0,.05)"
  },

  cardHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "15px",
    marginBottom: "20px"
  },

  cardTitle: {
    margin: "0 0 5px"
  },

  cardSubtitle: {
    margin: 0,
    color: "#667085"
  },

  counter: {
    minWidth: "40px",
    height: "40px",
    borderRadius: "10px",
    background: "#eef2f7",
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    fontWeight: "700"
  },

  reportList: {
    display: "flex",
    flexDirection: "column",
    gap: "10px"
  },

  reportItem: {
    width: "100%",
    textAlign: "left",
    border: "1px solid #e4e7ec",
    background: "#ffffff",
    borderRadius: "12px",
    padding: "14px",
    cursor: "pointer"
  },

  reportItemActive: {
    border: "2px solid #2563eb",
    background: "#eff6ff"
  },

  reportTop: {
    display: "flex",
    justifyContent: "space-between",
    gap: "10px",
    alignItems: "center"
  },

  reportType: {
    background: "#f2f4f7",
    borderRadius: "20px",
    padding: "4px 8px",
    fontSize: "11px",
    fontWeight: "700"
  },

  reportDate: {
    color: "#667085",
    fontSize: "13px",
    marginTop: "7px"
  },

  reportUser: {
    color: "#667085",
    fontSize: "12px",
    marginTop: "4px"
  },

  reportInfo: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(180px, 1fr))",
    gap: "12px",
    marginBottom: "18px"
  },

  infoBlock: {
    background: "#f8fafc",
    borderRadius: "10px",
    padding: "12px",
    display: "flex",
    flexDirection: "column",
    gap: "5px"
  },

  infoLabel: {
    color: "#667085",
    fontSize: "12px"
  },

  sourceBox: {
    border: "1px solid #e4e7ec",
    borderRadius: "12px",
    padding: "15px",
    marginBottom: "18px"
  },

  sourceTitle: {
    fontWeight: "700",
    marginBottom: "12px"
  },

  sourceGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(100px, 1fr))",
    gap: "10px"
  },

  sourceItem: {
    background: "#f8fafc",
    borderRadius: "9px",
    padding: "11px",
    textAlign: "center",
    display: "flex",
    flexDirection: "column",
    gap: "4px"
  },

  contentBox: {
    border: "1px solid #e4e7ec",
    borderRadius: "12px",
    padding: "18px",
    background: "#fcfcfd"
  },

  contentText: {
    margin: 0,
    whiteSpace: "pre-wrap",
    wordBreak: "break-word",
    fontFamily: "inherit",
    fontSize: "14px",
    lineHeight: 1.65,
    color: "#344054"
  },

  empty: {
    textAlign: "center",
    padding: "30px",
    color: "#667085"
  },

  emptyIcon: {
    fontSize: "38px",
    marginBottom: "8px"
  }
};

export default ReporteIAProspecto;