// src/components/ReportViewer.jsx

import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getToken } from "../services/AuthService";

export default function ReportViewer({
  reporte,
  iaInsights,
  pacienteId,
  idSesion = null,
}) {
  // =====================================================
  // MODO DE TRABAJO
  // =====================================================
  const modoPreanalisis = Boolean(idSesion);
  const navigate = useNavigate();

  // =====================================================
  // ESTADOS
  // =====================================================
  const [reportesPrevios, setReportesPrevios] = useState([]);
  const [reporteActual, setReporteActual] = useState(reporte || null);
  const [insightsActuales, setInsightsActuales] = useState(
    iaInsights || null
  );
  const [loading, setLoading] = useState(false);
  const [generando, setGenerando] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);
  const [sesionSeleccionada, setSesionSeleccionada] = useState(
    idSesion || ""
  );
  const [reporteAbierto, setReporteAbierto] = useState(null);
  const [reporteSesionEncontrado, setReporteSesionEncontrado] = useState(null);

  // =====================================================
  // ACTUALIZAR REPORTE SI VIENE COMO PROP
  // =====================================================
  useEffect(() => {
    if (reporte) {
      setReporteActual(reporte);
    }
  }, [reporte]);

  // =====================================================
  // ACTUALIZAR INSIGHTS SI VIENEN COMO PROP
  // =====================================================
  useEffect(() => {
    if (iaInsights) {
      setInsightsActuales(iaInsights);
    }
  }, [iaInsights]);

  // =====================================================
  // ACTUALIZAR SESIÓN SI VIENE COMO PROP
  // =====================================================
  useEffect(() => {
    if (idSesion) {
      setSesionSeleccionada(idSesion);
    }
  }, [idSesion]);

  // =====================================================
  // CARGAR REPORTES PREVIOS
  // =====================================================
  useEffect(() => {
    if (!pacienteId) return;

    const fetchReportes = async () => {
      setLoading(true);
      setErrorMsg(null);

      try {
        const token = getToken();

        const res = await fetch(
          `http://localhost:5000/api/reportes/paciente/${pacienteId}`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );

        if (!res.ok) {
          throw new Error(`Error ${res.status}`);
        }

        const data = await res.json();

        console.log("📄 Reportes IA recibidos:", data);

        if (Array.isArray(data)) {
          const ordenados = [...data].sort((a, b) => {
            const fechaA = a.fecha
              ? new Date(a.fecha).getTime()
              : 0;

            const fechaB = b.fecha
              ? new Date(b.fecha).getTime()
              : 0;

            return fechaB - fechaA;
          });

          setReportesPrevios(ordenados);

          // Si estamos en el flujo de una sesión concreta, recuperar
          // automáticamente el Preanálisis IA ya generado para esa sesión.
          if (modoPreanalisis && idSesion) {
            const encontrado = ordenados.find(
              (r) => Number(r.id_sesion) === Number(idSesion)
            );

            if (encontrado) {
              setReporteSesionEncontrado(encontrado);
              setReporteActual(encontrado.contenido || null);
            } else {
              setReporteSesionEncontrado(null);
              setReporteActual(reporte || null);
            }
          }
        } else {
          setReportesPrevios([]);
        }
      } catch (err) {
        console.error(
          "❌ Error cargando reportes previos:",
          err
        );

        setErrorMsg(
          "No se pudieron cargar los reportes anteriores."
        );
      } finally {
        setLoading(false);
      }
    };

    fetchReportes();
  }, [pacienteId, idSesion, modoPreanalisis, reporte]);

  // =====================================================
  // GENERAR NUEVO REPORTE / PREANÁLISIS IA
  // =====================================================
  const generarReporteIA = async () => {
    setErrorMsg(null);
    setSuccessMsg(null);

    // ===================================================
    // VALIDAR PACIENTE
    // ===================================================
    if (!pacienteId) {
      setErrorMsg("No se encontró el paciente.");
      return;
    }

    // ===================================================
    // VALIDAR SESIÓN
    // ===================================================
    if (!sesionSeleccionada) {
      setErrorMsg(
        modoPreanalisis
          ? "No se encontró la sesión clínica que se desea analizar."
          : "Selecciona o indica el ID de la sesión que deseas analizar."
      );
      return;
    }

    setGenerando(true);

    try {
      const token = getToken();

      console.log(
        modoPreanalisis
          ? "🤖 Generando Preanálisis IA..."
          : "🧠 Generando reporte IA...",
        {
          pacienteId,
          id_sesion: Number(sesionSeleccionada),
        }
      );

      // =================================================
      // LLAMADA AL BACKEND
      // =================================================
      const res = await fetch(
        "http://localhost:5000/api/ia/analisis-sesion",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            id_sesion: Number(sesionSeleccionada),
          }),
        }
      );

      // =================================================
      // LEER RESPUESTA
      // =================================================
      const data = await res.json();

      console.log(
        "🤖 Respuesta generación IA:",
        data
      );

      if (!res.ok) {
        throw new Error(
          data?.error ||
            data?.message ||
            `Error ${res.status}`
        );
      }

      // =================================================
      // OBTENER CONTENIDO
      // =================================================
      const contenido =
        data?.analisis ||
        data?.reporte ||
        data?.contenido ||
        data?.resultado ||
        null;

      if (!contenido) {
        throw new Error(
          "La IA respondió correctamente, pero no se recibió el contenido del reporte."
        );
      }

      // =================================================
      // MOSTRAR REPORTE ACTUAL
      // =================================================
      setReporteActual(contenido);
      if (modoPreanalisis) {
        setReporteSesionEncontrado({
          id_sesion: Number(sesionSeleccionada),
          contenido
        });
      }

      // =================================================
      // INSIGHTS
      // =================================================
      if (data?.insights) {
        setInsightsActuales(data.insights);
      }

      // =================================================
      // MENSAJE
      // =================================================
      setSuccessMsg(
        modoPreanalisis
          ? `✅ Preanálisis IA de la sesión #${sesionSeleccionada} generado correctamente.`
          : "✅ El reporte clínico fue generado correctamente."
      );

      // =================================================
      // RECARGAR REPORTES
      // =================================================
      await cargarReportes();
    } catch (error) {
      console.error(
        modoPreanalisis
          ? "❌ Error generando Preanálisis IA:"
          : "❌ Error generando reporte IA:",
        error
      );

      setErrorMsg(
        error?.message ||
          (modoPreanalisis
            ? "No fue posible generar el Preanálisis IA."
            : "No fue posible generar el reporte con IA.")
      );
    } finally {
      setGenerando(false);
    }
  };

  // =====================================================
  // RECARGAR REPORTES
  // =====================================================
  const cargarReportes = async () => {
    if (!pacienteId) return;

    try {
      const token = getToken();

      const res = await fetch(
        `http://localhost:5000/api/reportes/paciente/${pacienteId}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (!res.ok) return;

      const data = await res.json();

      if (Array.isArray(data)) {
        const ordenados = [...data].sort((a, b) => {
          const fechaA = a.fecha
            ? new Date(a.fecha).getTime()
            : 0;

          const fechaB = b.fecha
            ? new Date(b.fecha).getTime()
            : 0;

          return fechaB - fechaA;
        });

        setReportesPrevios(ordenados);

        if (modoPreanalisis && idSesion) {
          const encontrado = ordenados.find(
            (r) => Number(r.id_sesion) === Number(idSesion)
          );

          if (encontrado) {
            setReporteSesionEncontrado(encontrado);
            setReporteActual(encontrado.contenido || null);
          }
        }
      }
    } catch (error) {
      console.error(
        "❌ Error actualizando reportes:",
        error
      );
    }
  };

  // =====================================================
  // DESCARGAR PDF
  // =====================================================
  const descargarPDF = async (idReporte) => {
    try {
      const token = getToken();

      const res = await fetch(
        `http://localhost:5000/api/reportes/${idReporte}/pdf`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (!res.ok) {
        throw new Error(`Error ${res.status}`);
      }

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");

      a.href = url;
      a.download = `reporte_${idReporte}.pdf`;

      document.body.appendChild(a);
      a.click();
      a.remove();

      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error(
        "❌ Error descargando PDF:",
        error
      );

      alert("No fue posible descargar el PDF.");
    }
  };

  // =====================================================
  // ABRIR / CERRAR REPORTE
  // =====================================================
  const toggleReporte = (idReporte) => {
    setReporteAbierto(
      reporteAbierto === idReporte
        ? null
        : idReporte
    );
  };

  // =====================================================
  // RENDER
  // =====================================================
  return (
    <div style={container}>
      {/* =================================================
          ENCABEZADO
      ================================================= */}
      <div style={header}>
        <div>
          <div style={headerEyebrow}>
            {modoPreanalisis
              ? "APOYO CLÍNICO CON INTELIGENCIA ARTIFICIAL"
              : "INTELIGENCIA ARTIFICIAL"}
          </div>

          <h2 style={title}>
            {modoPreanalisis
              ? `🤖 Preanálisis IA — Sesión #${sesionSeleccionada}`
              : "🧠 Reportes automáticos con IA"}
          </h2>

          <p style={subtitle}>
            {modoPreanalisis
              ? "Genera un preanálisis de apoyo con la información registrada en esta sesión antes de completar el cierre clínico."
              : "Genera y consulta reportes clínicos preliminares a partir de la información registrada en las sesiones del paciente."}
          </p>
        </div>
      </div>

      {/* =================================================
          GENERAR
      ================================================= */}
      <section style={generateCard}>
        <div style={generateHeader}>
          <div style={generateIcon}>
            {modoPreanalisis ? "🤖" : "🧠"}
          </div>

          <div>
            <h3 style={generateTitle}>
              {modoPreanalisis
                ? reporteSesionEncontrado
                  ? "Preanálisis IA listo"
                  : "Generar Preanálisis IA"
                : "Generar nuevo reporte IA"}
            </h3>

            <p style={generateDescription}>
              {modoPreanalisis
                ? reporteSesionEncontrado
                  ? "MirrorSoul encontró el Preanálisis IA que ya fue generado para esta sesión clínica."
                  : "MirrorSoul utilizará automáticamente la información asociada a esta sesión clínica."
                : "Selecciona la sesión que deseas analizar y genera un nuevo reporte clínico."}
            </p>
          </div>
        </div>

        <div style={generateControls}>
          {/* ===============================================
              MODO PREANÁLISIS
              ID AUTOMÁTICO
          =============================================== */}
          {modoPreanalisis ? (
            <div style={selectedSessionBox}>
              <div style={selectedSessionLabel}>
                SESIÓN SELECCIONADA
              </div>

              <div style={selectedSessionValue}>
                🧠 Sesión #{sesionSeleccionada}
              </div>

              <div style={selectedSessionText}>
                El identificador fue obtenido automáticamente
                desde la consulta activa.
              </div>
            </div>
          ) : (
            /* =============================================
                MODO GENERAL
                CONSERVA ID MANUAL
            ============================================= */
            <div style={inputContainer}>
              <label style={inputLabel}>
                ID de sesión
              </label>

              <input
                type="number"
                min="1"
                value={sesionSeleccionada}
                onChange={(e) =>
                  setSesionSeleccionada(
                    e.target.value
                  )
                }
                placeholder="Ej. 12"
                style={sessionInput}
                disabled={generando}
              />
            </div>
          )}

          {(!modoPreanalisis || !reporteSesionEncontrado) && (
          <button
            type="button"
            onClick={generarReporteIA}
            disabled={
              generando ||
              !sesionSeleccionada
            }
            style={{
              ...generateButton,
              opacity:
                generando ||
                !sesionSeleccionada
                  ? 0.6
                  : 1,
              cursor:
                generando ||
                !sesionSeleccionada
                  ? "not-allowed"
                  : "pointer",
            }}
          >
            {generando ? (
              <>
                <span style={spinner}>
                  ⏳
                </span>

                {modoPreanalisis
                  ? "Generando Preanálisis..."
                  : "Generando reporte..."}
              </>
            ) : (
              <>
                {modoPreanalisis
                  ? "🤖 Generar Preanálisis IA"
                  : "🧠 Generar reporte IA"}
              </>
            )}
          </button>
          )}
        </div>

        <p style={sessionHelp}>
          {modoPreanalisis
            ? reporteSesionEncontrado
              ? `✅ Ya existe un Preanálisis IA para la sesión #${sesionSeleccionada}. No necesitas generarlo nuevamente.`
              : `💡 No necesitas ingresar un ID. MirrorSoul utilizará automáticamente la sesión #${sesionSeleccionada}.`
            : "💡 El ID de sesión corresponde a la sesión clínica que deseas utilizar para el análisis."}
        </p>
      </section>

      {/* =================================================
          MENSAJE DE ÉXITO
      ================================================= */}
      {successMsg && (
        <div style={successMessage}>
          {successMsg}
        </div>
      )}

      {/* =================================================
          ERROR
      ================================================= */}
      {errorMsg && (
        <div style={errorMessage}>
          ⚠️ {errorMsg}
        </div>
      )}

      {/* =================================================
          REPORTE ACTUAL
      ================================================= */}
      {reporteActual ? (
        <section style={currentReportCard}>
          <div style={currentReportHeader}>
            <div>
              <div style={currentBadge}>
                {modoPreanalisis
                  ? "PREANÁLISIS IA GENERADO"
                  : "REPORTE GENERADO"}
              </div>

              <h3 style={currentReportTitle}>
                {modoPreanalisis
                  ? `🤖 Preanálisis clínico — Sesión #${sesionSeleccionada}`
                  : "📄 Reporte clínico actual"}
              </h3>
            </div>
          </div>

          <div style={currentReportContent}>
            <div style={reportText}>
              {reporteActual}
            </div>
          </div>
        </section>
      ) : (
        <section style={emptyReport}>
          <div style={emptyIcon}>
            {modoPreanalisis ? "🤖" : "📄"}
          </div>

          <h3 style={emptyTitle}>
            {modoPreanalisis
              ? "El Preanálisis IA aún no se ha generado"
              : "Aún no hay un reporte actual"}
          </h3>

          <p style={emptyText}>
            {modoPreanalisis
              ? "Genera el preanálisis de esta sesión para utilizarlo como apoyo antes del cierre clínico."
              : "Genera un reporte utilizando una sesión clínica del paciente."}
          </p>
        </section>
      )}

      {modoPreanalisis && reporteSesionEncontrado && reporteActual && (
        <section style={continueCard}>
          <div>
            <div style={continueEyebrow}>PREANÁLISIS REVISADO</div>
            <h3 style={continueTitle}>📝 Continuar al cierre clínico</h3>
            <p style={continueText}>
              El Preanálisis IA de esta sesión ya está disponible. Continúa con la valoración profesional, el seguimiento y el cierre de la consulta.
            </p>
          </div>

          <button
            type="button"
            style={continueButton}
            onClick={() =>
              navigate(
                `/paciente/${pacienteId}/sesion/${idSesion}/cierre`
              )
            }
          >
            📝 Continuar al cierre clínico →
          </button>
        </section>
      )}

      {/* =================================================
          INSIGHTS IA
      ================================================= */}
      {insightsActuales && (
        <section style={insightsCard}>
          <div style={insightsHeader}>
            <div style={insightsIcon}>
              🤖
            </div>

            <div>
              <h3 style={insightsTitle}>
                Análisis IA complementario
              </h3>

              <p style={insightsSubtitle}>
                Información generada como apoyo
                al análisis clínico.
              </p>
            </div>
          </div>

          <div style={insightsContent}>
            {insightsActuales}
          </div>
        </section>
      )}

      {/* =================================================
          REPORTES ANTERIORES
      ================================================= */}
      <section style={previousSection}>
        <div style={previousHeader}>
          <div>
            <h3 style={previousTitle}>
              📂 Historial de reportes
            </h3>

            <p style={previousDescription}>
              Reportes generados anteriormente para
              este paciente.
            </p>
          </div>

          {reportesPrevios.length > 0 && (
            <span style={reportCount}>
              {reportesPrevios.length}{" "}
              {reportesPrevios.length === 1
                ? "reporte"
                : "reportes"}
            </span>
          )}
        </div>

        {/* =================================================
            CARGANDO
        ================================================= */}
        {loading && (
          <div style={loadingReports}>
            ⏳ Cargando reportes anteriores...
          </div>
        )}

        {/* =================================================
            REPORTES
        ================================================= */}
        {!loading &&
          reportesPrevios.length > 0 && (
            <div style={reportsList}>
              {reportesPrevios.map(
                (r, index) => {
                  const abierto =
                    reporteAbierto ===
                    r.id_reporte;

                  return (
                    <div
                      key={r.id_reporte}
                      style={previousReport}
                    >
                      {/* CABECERA */}
                      <div
                        style={previousReportHeader}
                        onClick={() =>
                          toggleReporte(
                            r.id_reporte
                          )
                        }
                      >
                        <div
                          style={
                            previousReportNumber
                          }
                        >
                          {index + 1}
                        </div>

                        <div
                          style={
                            previousReportInfo
                          }
                        >
                          <div
                            style={
                              previousReportTitle
                            }
                          >
                            📄 Reporte clínico
                          </div>

                          <div
                            style={
                              previousReportMeta
                            }
                          >
                            📅{" "}
                            {r.fecha
                              ? new Date(
                                  r.fecha
                                ).toLocaleString(
                                  "es-MX"
                                )
                              : "Fecha no registrada"}

                            {"  •  "}

                            🧾 #{r.id_reporte}

                            {r.id_sesion && (
                              <>
                                {"  •  "}
                                🧠 Sesión #
                                {r.id_sesion}
                              </>
                            )}
                          </div>
                        </div>

                        <div
                          style={
                            previousReportActions
                          }
                        >
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();

                              descargarPDF(
                                r.id_reporte
                              );
                            }}
                            style={pdfButton}
                          >
                            📄 PDF
                          </button>

                          <span
                            style={expandIcon}
                          >
                            {abierto
                              ? "▲"
                              : "▼"}
                          </span>
                        </div>
                      </div>

                      {/* CONTENIDO DESPLEGABLE */}
                      {abierto && (
                        <div
                          style={
                            previousReportContent
                          }
                        >
                          <div
                            style={
                              previousReportContentInner
                            }
                          >
                            {r.contenido ||
                              "Este reporte no contiene información."}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                }
              )}
            </div>
          )}

        {/* =================================================
            SIN REPORTES
        ================================================= */}
        {!loading &&
          reportesPrevios.length === 0 && (
            <div style={noReports}>
              <div style={noReportsIcon}>
                📂
              </div>

              <h4 style={noReportsTitle}>
                No hay reportes anteriores
              </h4>

              <p style={noReportsText}>
                Cuando generes un reporte IA,
                aparecerá aquí automáticamente.
              </p>
            </div>
          )}
      </section>

      {/* =================================================
          AVISO CLÍNICO
      ================================================= */}
      <div style={clinicalNotice}>
        <span style={noticeIcon}>
          🌱
        </span>

        <div>
          <strong>
            {modoPreanalisis
              ? "Aviso de apoyo clínico"
              : "Aviso clínico"}
          </strong>

          <p>
            {modoPreanalisis
              ? "Este preanálisis es una herramienta de apoyo generada mediante inteligencia artificial. No constituye un diagnóstico. El psicólogo responsable debe revisar la información y mantiene siempre la decisión clínica final."
              : "Este reporte es preliminar y funciona únicamente como herramienta de apoyo. El profesional de la salud mantiene siempre la decisión clínica final."}
          </p>
        </div>
      </div>
    </div>
  );
}

// =====================================================
// ESTILOS
// =====================================================
const container = {
  width: "100%",
  maxWidth: "1100px",
  margin: "0 auto",
  padding: "10px 0 40px",
  boxSizing: "border-box",
};

const header = {
  marginBottom: "25px",
};

const headerEyebrow = {
  color: "#3f51b5",
  fontSize: "11px",
  fontWeight: "800",
  letterSpacing: "1.5px",
  marginBottom: "5px",
};

const title = {
  margin: 0,
  color: "#263238",
  fontSize: "28px",
  fontWeight: "800",
};

const subtitle = {
  margin: "8px 0 0",
  color: "#78909c",
  fontSize: "14px",
  lineHeight: "1.6",
  maxWidth: "720px",
};

// =====================================================
// GENERAR
// =====================================================
const generateCard = {
  background:
    "linear-gradient(135deg, #eef4ff, #f8fbff)",
  border: "1px solid #d9e6f7",
  borderRadius: "18px",
  padding: "22px",
  marginBottom: "22px",
  boxShadow:
    "0 5px 18px rgba(40,80,120,0.06)",
};

const generateHeader = {
  display: "flex",
  alignItems: "center",
  gap: "15px",
  marginBottom: "20px",
};

const generateIcon = {
  width: "52px",
  height: "52px",
  borderRadius: "14px",
  background:
    "linear-gradient(135deg, #3f51b5, #2196f3)",
  color: "#fff",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "25px",
  flexShrink: 0,
};

const generateTitle = {
  margin: 0,
  color: "#263238",
  fontSize: "19px",
  fontWeight: "750",
};

const generateDescription = {
  margin: "5px 0 0",
  color: "#78909c",
  fontSize: "13px",
};

const generateControls = {
  display: "flex",
  alignItems: "flex-end",
  gap: "14px",
  flexWrap: "wrap",
};

const inputContainer = {
  display: "flex",
  flexDirection: "column",
  gap: "6px",
};

const inputLabel = {
  color: "#455a64",
  fontSize: "12px",
  fontWeight: "700",
};

const sessionInput = {
  width: "180px",
  boxSizing: "border-box",
  border: "1px solid #cbd8e6",
  borderRadius: "10px",
  padding: "11px 13px",
  outline: "none",
  background: "#ffffff",
  color: "#263238",
  fontSize: "14px",
};

// =====================================================
// SESIÓN AUTOMÁTICA PREANÁLISIS
// =====================================================
const selectedSessionBox = {
  minWidth: "250px",
  padding: "11px 14px",
  borderRadius: "11px",
  background: "#ffffff",
  border: "1px solid #c7d7f5",
  boxSizing: "border-box",
};

const selectedSessionLabel = {
  color: "#78909c",
  fontSize: "9px",
  fontWeight: "800",
  letterSpacing: "1px",
};

const selectedSessionValue = {
  marginTop: "3px",
  color: "#3949ab",
  fontSize: "15px",
  fontWeight: "800",
};

const selectedSessionText = {
  marginTop: "3px",
  color: "#90a4ae",
  fontSize: "10px",
  lineHeight: "1.4",
};

const generateButton = {
  border: "none",
  borderRadius: "10px",
  padding: "12px 20px",
  background:
    "linear-gradient(135deg, #3f51b5, #1976d2)",
  color: "#ffffff",
  fontSize: "14px",
  fontWeight: "700",
  boxShadow:
    "0 5px 14px rgba(25,118,210,0.25)",
};

const spinner = {
  marginRight: "7px",
};

const sessionHelp = {
  margin: "12px 0 0",
  color: "#78909c",
  fontSize: "12px",
};

// =====================================================
// MENSAJES
// =====================================================
const successMessage = {
  background: "#edf8f0",
  border: "1px solid #c8e6cf",
  color: "#2e7d32",
  padding: "12px 15px",
  borderRadius: "10px",
  marginBottom: "18px",
  fontSize: "13px",
  fontWeight: "600",
};

const errorMessage = {
  background: "#fff3f3",
  border: "1px solid #ffcdd2",
  color: "#c62828",
  padding: "12px 15px",
  borderRadius: "10px",
  marginBottom: "18px",
  fontSize: "13px",
  fontWeight: "600",
};

// =====================================================
// REPORTE ACTUAL
// =====================================================
const currentReportCard = {
  background: "#ffffff",
  border: "1px solid #e1e8ef",
  borderRadius: "18px",
  padding: "22px",
  marginBottom: "22px",
  boxShadow:
    "0 5px 18px rgba(30,60,90,0.06)",
};

const currentReportHeader = {
  marginBottom: "15px",
};

const currentBadge = {
  display: "inline-block",
  background: "#e8f1ff",
  color: "#1565c0",
  padding: "5px 9px",
  borderRadius: "7px",
  fontSize: "10px",
  fontWeight: "800",
  letterSpacing: "0.8px",
  marginBottom: "6px",
};

const currentReportTitle = {
  margin: 0,
  color: "#263238",
  fontSize: "18px",
};

const currentReportContent = {
  background: "#f8fafc",
  borderRadius: "12px",
  padding: "18px",
  border: "1px solid #edf1f5",
};

const reportText = {
  whiteSpace: "pre-wrap",
  color: "#455a64",
  fontSize: "14px",
  lineHeight: "1.7",
};

// =====================================================
// REPORTE VACÍO
// =====================================================
const emptyReport = {
  background: "#ffffff",
  border: "1px dashed #cfd8dc",
  borderRadius: "18px",
  padding: "35px",
  textAlign: "center",
  marginBottom: "22px",
};

const emptyIcon = {
  fontSize: "38px",
  marginBottom: "8px",
};

const emptyTitle = {
  margin: 0,
  color: "#455a64",
  fontSize: "17px",
};

const emptyText = {
  margin: "7px 0 0",
  color: "#90a4ae",
  fontSize: "13px",
};

// =====================================================
// CONTINUAR AL CIERRE CLÍNICO
// =====================================================
const continueCard = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: "18px",
  flexWrap: "wrap",
  background: "linear-gradient(135deg, #eef8f1, #f8fcf9)",
  border: "1px solid #cfe8d5",
  borderRadius: "18px",
  padding: "20px 22px",
  marginBottom: "22px",
  boxShadow: "0 5px 18px rgba(40,100,70,0.06)",
};

const continueEyebrow = {
  color: "#2e7d32",
  fontSize: "10px",
  fontWeight: "800",
  letterSpacing: "1px",
  marginBottom: "5px",
};

const continueTitle = {
  margin: 0,
  color: "#263238",
  fontSize: "18px",
};

const continueText = {
  margin: "6px 0 0",
  color: "#607d8b",
  fontSize: "13px",
  lineHeight: "1.6",
  maxWidth: "650px",
};

const continueButton = {
  border: "none",
  borderRadius: "11px",
  padding: "12px 18px",
  background: "linear-gradient(135deg, #43a047, #2e7d32)",
  color: "#ffffff",
  fontSize: "13px",
  fontWeight: "800",
  cursor: "pointer",
  boxShadow: "0 5px 14px rgba(46,125,50,0.22)",
};

// =====================================================
// INSIGHTS
// =====================================================
const insightsCard = {
  background: "#ffffff",
  border: "1px solid #dce8f5",
  borderRadius: "18px",
  padding: "20px",
  marginBottom: "25px",
  boxShadow:
    "0 5px 18px rgba(30,60,90,0.05)",
};

const insightsHeader = {
  display: "flex",
  alignItems: "center",
  gap: "12px",
};

const insightsIcon = {
  width: "44px",
  height: "44px",
  borderRadius: "12px",
  background: "#eef4ff",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "21px",
};

const insightsTitle = {
  margin: 0,
  color: "#1565c0",
  fontSize: "16px",
};

const insightsSubtitle = {
  margin: "3px 0 0",
  color: "#90a4ae",
  fontSize: "12px",
};

const insightsContent = {
  marginTop: "15px",
  padding: "15px",
  background: "#f8fafc",
  borderRadius: "10px",
  color: "#455a64",
  whiteSpace: "pre-wrap",
  fontSize: "13px",
  lineHeight: "1.6",
};

// =====================================================
// REPORTES ANTERIORES
// =====================================================
const previousSection = {
  marginTop: "25px",
};

const previousHeader = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "flex-end",
  gap: "15px",
  marginBottom: "14px",
};

const previousTitle = {
  margin: 0,
  color: "#263238",
  fontSize: "19px",
};

const previousDescription = {
  margin: "5px 0 0",
  color: "#78909c",
  fontSize: "13px",
};

const reportCount = {
  background: "#eef4ff",
  color: "#3f51b5",
  padding: "6px 10px",
  borderRadius: "20px",
  fontSize: "11px",
  fontWeight: "700",
};

const loadingReports = {
  background: "#ffffff",
  padding: "20px",
  borderRadius: "14px",
  color: "#78909c",
  textAlign: "center",
};

const reportsList = {
  display: "flex",
  flexDirection: "column",
  gap: "10px",
};

const previousReport = {
  background: "#ffffff",
  border: "1px solid #e1e8ef",
  borderRadius: "14px",
  overflow: "hidden",
  boxShadow:
    "0 3px 10px rgba(30,60,90,0.04)",
};

const previousReportHeader = {
  display: "flex",
  alignItems: "center",
  gap: "13px",
  padding: "14px 16px",
  cursor: "pointer",
};

const previousReportNumber = {
  width: "34px",
  height: "34px",
  borderRadius: "10px",
  background: "#eef4ff",
  color: "#3f51b5",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontWeight: "800",
  fontSize: "13px",
  flexShrink: 0,
};

const previousReportInfo = {
  flex: 1,
  minWidth: 0,
};

const previousReportTitle = {
  color: "#263238",
  fontWeight: "700",
  fontSize: "14px",
};

const previousReportMeta = {
  marginTop: "4px",
  color: "#90a4ae",
  fontSize: "11px",
  lineHeight: "1.5",
};

const previousReportActions = {
  display: "flex",
  alignItems: "center",
  gap: "9px",
};

const pdfButton = {
  border: "none",
  borderRadius: "8px",
  padding: "8px 11px",
  background: "#3f51b5",
  color: "#ffffff",
  fontSize: "11px",
  fontWeight: "700",
  cursor: "pointer",
};

const expandIcon = {
  color: "#78909c",
  fontSize: "11px",
  width: "18px",
  textAlign: "center",
};

const previousReportContent = {
  borderTop: "1px solid #edf1f5",
  background: "#f8fafc",
  padding: "15px",
};

const previousReportContentInner = {
  background: "#ffffff",
  borderRadius: "10px",
  padding: "15px",
  whiteSpace: "pre-wrap",
  color: "#455a64",
  fontSize: "13px",
  lineHeight: "1.7",
};

// =====================================================
// SIN REPORTES
// =====================================================
const noReports = {
  background: "#ffffff",
  border: "1px dashed #cfd8dc",
  borderRadius: "14px",
  padding: "30px",
  textAlign: "center",
};

const noReportsIcon = {
  fontSize: "32px",
};

const noReportsTitle = {
  margin: "8px 0 0",
  color: "#546e7a",
  fontSize: "15px",
};

const noReportsText = {
  margin: "5px 0 0",
  color: "#90a4ae",
  fontSize: "12px",
};

// =====================================================
// AVISO CLÍNICO
// =====================================================
const clinicalNotice = {
  display: "flex",
  alignItems: "flex-start",
  gap: "12px",
  background: "#f7fbf8",
  border: "1px solid #dcefe0",
  borderRadius: "14px",
  padding: "15px",
  marginTop: "25px",
  color: "#546e7a",
};

const noticeIcon = {
  fontSize: "20px",
};