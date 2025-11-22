import { useState, useEffect } from "react";
import TestManager from "./TestManager";
import ReportViewer from "./ReportViewer";
import { getToken } from "../services/AuthService";

export default function ChatBot({
  paciente,
  respuestas = {},
  setRespuestas,
  emociones = [],
  mode = "manual",
  onFinishReporte,
  token,
}) {
  const [fase, setFase] = useState("intro");
  const [reporte, setReporte] = useState(null);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);

  // Reset al iniciar nuevo paciente
  useEffect(() => {
    setFase("intro");
    setReporte(null);
    setErrorMsg(null);
  }, [paciente?.id_paciente]);

  const generarReporte = async () => {
    setLoading(true);
    setErrorMsg(null);

    try {
      const activeToken = token || getToken();
      const res = await fetch("http://localhost:5000/api/reportes/generar", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${activeToken}`,
        },
        body: JSON.stringify({ id_paciente: paciente.id_paciente }),
      });

      if (!res.ok) throw new Error(`Servidor respondió ${res.status}`);
      const data = await res.json();

      if (!data.contenido) {
        setReporte({
          contenido: `⚠️ No se pudo generar el reporte automático.
Paciente: ${paciente?.nombre || "N/A"}
Verifique si existen pruebas finalizadas en la base de datos.`,
        });
        setFase("reporte");
        return;
      }

      setReporte(data);
      setFase("reporte");
      if (onFinishReporte) onFinishReporte(data);
    } catch (error) {
      console.error("Error generando reporte:", error);
      setErrorMsg("No se pudo generar el reporte automáticamente.");
      setReporte({
        contenido: `Reporte de emergencia:
Paciente: ${paciente?.nombre || "N/A"}
Este reporte fue generado sin IA debido a un error de conexión.`,
      });
      setFase("reporte");
    } finally {
      setLoading(false);
    }
  };

  // Bloqueo si no hay paciente seleccionado
  if (!paciente) {
    return <p style={{ textAlign: "center" }}>Debe seleccionar un paciente primero.</p>;
  }

  return (
    <div
      style={{
        background: "#fff",
        padding: 24,
        borderRadius: 16,
        boxShadow: "0 8px 20px rgba(0,0,0,0.15)",
        maxWidth: 800,
        margin: "0 auto",
      }}
    >
      {/* INTRO */}
      {fase === "intro" && (
        <div style={{ textAlign: "center" }}>
          <h2>Prediagnóstico de {paciente.nombre}</h2>
          <p>
            Se aplicarán pruebas estandarizadas
            {emociones.length > 0 && (
              <> considerando las emociones detectadas: <b>{emociones.join(", ")}</b></>
            )}
          </p>
          {mode === "ia" && (
            <p style={{ fontStyle: "italic", color: "#666" }}>
              Modo IA activado: se generarán preguntas abiertas y análisis cualitativos al final.
            </p>
          )}
          <button
            onClick={() => setFase("pruebas")}
            style={{
              marginTop: "15px",
              padding: "12px 22px",
              borderRadius: "8px",
              backgroundColor: "#03A9F4",
              color: "white",
              border: "none",
              cursor: "pointer",
              fontWeight: "600",
            }}
          >
            Iniciar pruebas
          </button>
        </div>
      )}

      {/* PRUEBAS */}
      {fase === "pruebas" && (
        <TestManager
          onFinish={generarReporte}
          setRespuestas={setRespuestas}
          onCancel={() => {
            console.log("Reiniciando pruebas desde ChatBot");
            setFase("intro");
          }}
          pacienteId={paciente.id_paciente}
          token={token || getToken()}
        />
      )}

      {/* REPORTE */}
      {fase === "reporte" && (
        <>
          {loading ? (
            <p style={{ textAlign: "center", color: "#666" }}>
              Generando reporte, por favor espere...
            </p>
          ) : (
            <>
              {errorMsg && (
                <p style={{ color: "red", fontWeight: "600", marginBottom: "12px" }}>
                  {errorMsg}
                </p>
              )}
              <ReportViewer
                reporte={reporte?.contenido}
                iaInsights={reporte?.iaInsights}
                pacienteId={paciente.id_paciente}
              />
              <div style={{ textAlign: "center", marginTop: "20px" }}>
                <button
                  onClick={() => {
                    setFase("intro");
                    setRespuestas({});
                  }}
                  style={{
                    padding: "10px 20px",
                    borderRadius: "8px",
                    backgroundColor: "#E74C3C",
                    color: "white",
                    border: "none",
                    cursor: "pointer",
                    fontWeight: "600",
                  }}
                >
                  Reiniciar evaluación
                </button>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
}

