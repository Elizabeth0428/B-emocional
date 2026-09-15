// src/views/SeguimientoView.jsx

import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { getToken } from "../services/AuthService";

export default function SeguimientoView() {

  const { idPaciente } = useParams();
  const navigate = useNavigate();

  const [seguimientos, setSeguimientos] = useState([]);
  const [loading, setLoading] = useState(true);

  const [nuevo, setNuevo] = useState({
    diagnostico: "",
    tratamiento: "",
    evolucion: "",
    observaciones: "",
  });


  // =====================================================
  // OBTENER SEGUIMIENTOS
  // =====================================================

  useEffect(() => {

    const fetchSeguimiento = async () => {

      try {

        const res = await fetch(
          `http://localhost:5000/api/seguimiento/${idPaciente}`,
          {
            headers: {
              Authorization: `Bearer ${getToken()}`
            }
          }
        );


        if (res.ok) {

          const data = await res.json();

          setSeguimientos(
            Array.isArray(data)
              ? data
              : []
          );

        }

      } catch (err) {

        console.error(
          "❌ Error al obtener seguimientos:",
          err
        );

      } finally {

        setLoading(false);

      }

    };


    fetchSeguimiento();

  }, [idPaciente]);


  // =====================================================
  // VOLVER AL EXPEDIENTE
  // =====================================================

  const volverAlExpediente = () => {

    navigate(
      `/paciente/${idPaciente}`
    );

  };


  // =====================================================
  // AGREGAR SEGUIMIENTO
  // =====================================================

  const handleAdd = async () => {

    try {

      if (
        !nuevo.diagnostico &&
        !nuevo.tratamiento &&
        !nuevo.evolucion &&
        !nuevo.observaciones
      ) {

        alert(
          "⚠️ Escribe al menos un dato del seguimiento."
        );

        return;

      }


      const res = await fetch(
        "http://localhost:5000/api/seguimiento",
        {
          method: "POST",

          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${getToken()}`
          },

          body: JSON.stringify({
            ...nuevo,
            id_paciente: Number(idPaciente)
          })

        }
      );


      if (!res.ok) {

        throw new Error(
          "Error al guardar seguimiento"
        );

      }


      const data = await res.json();


      setSeguimientos([
        {
          ...nuevo,
          id_seguimiento:
            data.id_seguimiento,
          fecha: new Date()
        },
        ...seguimientos
      ]);


      setNuevo({
        diagnostico: "",
        tratamiento: "",
        evolucion: "",
        observaciones: ""
      });


      alert(
        "✅ Seguimiento agregado correctamente"
      );


    } catch (err) {

      console.error(
        "❌ Error:",
        err
      );

      alert(
        "❌ No se pudo guardar el seguimiento"
      );

    }

  };


  // =====================================================
  // CARGANDO
  // =====================================================

  if (loading) {

    return (

      <div style={loadingPage}>

        <div style={loadingCard}>

          <div style={loadingIcon}>
            ⏳
          </div>

          <h2 style={loadingTitle}>
            Cargando seguimiento...
          </h2>

          <p style={loadingText}>
            Estamos obteniendo la información clínica
            del paciente.
          </p>

        </div>

      </div>

    );

  }


  // =====================================================
  // RENDER
  // =====================================================

  return (

    <div style={page}>

      <div style={container}>


        {/* =================================================
            ENCABEZADO
        ================================================= */}

        <div style={header}>

          <button
            type="button"
            onClick={volverAlExpediente}
            style={backButton}
          >
            ← Volver al expediente
          </button>


          <div style={headerContent}>

            <div style={headerIcon}>
              📑
            </div>

            <div>

              <div style={eyebrow}>
                EXPEDIENTE DEL PACIENTE
              </div>

              <h1 style={title}>
                Seguimiento Clínico
              </h1>

              <p style={subtitle}>
                Registra y consulta la evolución clínica
                del paciente.
              </p>

            </div>

          </div>

        </div>


        {/* =================================================
            PACIENTE
        ================================================= */}

        <div style={patientBar}>

          <div style={patientBarIcon}>
            👤
          </div>

          <div>

            <span style={patientLabel}>
              Paciente
            </span>

            <strong style={patientId}>
              Expediente #{idPaciente}
            </strong>

          </div>

        </div>


        {/* =================================================
            NUEVO SEGUIMIENTO
        ================================================= */}

        <section style={section}>

          <div style={sectionHeader}>

            <div>

              <h2 style={sectionTitle}>
                ➕ Registrar nuevo seguimiento
              </h2>

              <p style={sectionDescription}>
                Agrega información sobre la evolución
                clínica del paciente.
              </p>

            </div>

          </div>


          <div style={formGrid}>

            <div style={field}>

              <label style={label}>
                🩺 Diagnóstico
              </label>

              <textarea
                placeholder="Escribe el diagnóstico..."
                value={nuevo.diagnostico}
                onChange={(e) =>
                  setNuevo({
                    ...nuevo,
                    diagnostico:
                      e.target.value
                  })
                }
                style={textarea}
              />

            </div>


            <div style={field}>

              <label style={label}>
                💊 Tratamiento
              </label>

              <textarea
                placeholder="Describe el tratamiento..."
                value={nuevo.tratamiento}
                onChange={(e) =>
                  setNuevo({
                    ...nuevo,
                    tratamiento:
                      e.target.value
                  })
                }
                style={textarea}
              />

            </div>


            <div style={field}>

              <label style={label}>
                📈 Evolución
              </label>

              <textarea
                placeholder="Describe la evolución del paciente..."
                value={nuevo.evolucion}
                onChange={(e) =>
                  setNuevo({
                    ...nuevo,
                    evolucion:
                      e.target.value
                  })
                }
                style={textarea}
              />

            </div>


            <div style={field}>

              <label style={label}>
                📝 Observaciones
              </label>

              <textarea
                placeholder="Agrega observaciones..."
                value={nuevo.observaciones}
                onChange={(e) =>
                  setNuevo({
                    ...nuevo,
                    observaciones:
                      e.target.value
                  })
                }
                style={textarea}
              />

            </div>

          </div>


          <div style={formActions}>

            <button
              type="button"
              style={saveButton}
              onClick={handleAdd}
            >
              💾 Guardar seguimiento
            </button>

          </div>

        </section>


        {/* =================================================
            HISTORIAL
        ================================================= */}

        <section style={section}>

          <div style={sectionHeader}>

            <div>

              <h2 style={sectionTitle}>
                📋 Historial de seguimiento
              </h2>

              <p style={sectionDescription}>
                Registro de la evolución clínica
                del paciente.
              </p>

            </div>


            <div style={counter}>

              <strong>
                {seguimientos.length}
              </strong>

              <span>
                registros
              </span>

            </div>

          </div>


          {seguimientos.length > 0 ? (

            <div style={timeline}>

              {seguimientos.map(
                (s, index) => (

                  <div
                    key={
                      s.id_seguimiento
                    }
                    style={timelineItem}
                  >

                    <div style={timelineDot}>
                      {index + 1}
                    </div>


                    <div style={timelineCard}>

                      <div style={dateBadge}>

                        📅{" "}

                        {s.fecha
                          ? new Date(
                              s.fecha
                            ).toLocaleDateString(
                              "es-MX",
                              {
                                day: "2-digit",
                                month: "long",
                                year: "numeric"
                              }
                            )
                          : "Fecha no registrada"}

                      </div>


                      <div style={infoGrid}>

                        <InfoBlock
                          icon="🩺"
                          title="Diagnóstico"
                          value={
                            s.diagnostico
                          }
                        />

                        <InfoBlock
                          icon="💊"
                          title="Tratamiento"
                          value={
                            s.tratamiento
                          }
                        />

                        <InfoBlock
                          icon="📈"
                          title="Evolución"
                          value={
                            s.evolucion
                          }
                        />

                        <InfoBlock
                          icon="📝"
                          title="Observaciones"
                          value={
                            s.observaciones
                          }
                        />

                      </div>

                    </div>

                  </div>

                )
              )}

            </div>

          ) : (

            <div style={emptyState}>

              <div style={emptyIcon}>
                📋
              </div>

              <h3 style={emptyTitle}>
                No hay seguimientos registrados
              </h3>

              <p style={emptyText}>
                Cuando registres un seguimiento,
                aparecerá aquí.
              </p>

            </div>

          )}

        </section>


        {/* =================================================
            PIE
        ================================================= */}

        <div style={footer}>

          <span>
            🧠 MirrorSoul
          </span>

          <button
            type="button"
            onClick={volverAlExpediente}
            style={footerLink}
          >
            ← Expediente del paciente
          </button>

        </div>

      </div>

    </div>

  );

}


// =====================================================
// COMPONENTE INFORMACIÓN
// =====================================================

function InfoBlock({
  icon,
  title,
  value
}) {

  return (

    <div style={infoBlock}>

      <div style={infoBlockTitle}>
        <span>
          {icon}
        </span>

        {title}
      </div>

      <div style={infoBlockValue}>

        {value || "No registrado"}

      </div>

    </div>

  );

}


// =====================================================
// ESTILOS
// =====================================================

const page = {

  minHeight: "100vh",

  background:
    "linear-gradient(135deg, #eef6ff 0%, #f8fbff 50%, #eef4ff 100%)",

  padding: "30px 20px 50px",

  boxSizing: "border-box"

};


const container = {

  maxWidth: "1100px",

  margin: "0 auto"

};


const header = {

  marginBottom: "22px"

};


const backButton = {

  border: "none",

  background: "#ffffff",

  color: "#3155a4",

  padding: "11px 17px",

  borderRadius: "12px",

  cursor: "pointer",

  fontWeight: "700",

  fontSize: "14px",

  boxShadow:
    "0 4px 14px rgba(30,70,120,0.08)",

  marginBottom: "22px"

};


const headerContent = {

  display: "flex",

  alignItems: "center",

  gap: "16px"

};


const headerIcon = {

  width: "62px",

  height: "62px",

  borderRadius: "18px",

  background:
    "linear-gradient(135deg, #5c6bc0, #42a5f5)",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  fontSize: "30px",

  boxShadow:
    "0 8px 20px rgba(63,81,181,0.20)"

};


const eyebrow = {

  fontSize: "11px",

  fontWeight: "800",

  letterSpacing: "2px",

  color: "#5c6bc0",

  marginBottom: "5px"

};


const title = {

  margin: 0,

  color: "#173b70",

  fontSize: "30px",

  fontWeight: "800"

};


const subtitle = {

  margin: "6px 0 0",

  color: "#718096",

  fontSize: "14px"

};


const patientBar = {

  display: "flex",

  alignItems: "center",

  gap: "12px",

  background: "#ffffff",

  border:
    "1px solid #e2e8f0",

  borderRadius: "16px",

  padding: "14px 18px",

  marginBottom: "22px",

  boxShadow:
    "0 6px 20px rgba(30,70,120,0.07)"

};


const patientBarIcon = {

  width: "40px",

  height: "40px",

  borderRadius: "12px",

  background: "#eef4ff",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  fontSize: "19px"

};


const patientLabel = {

  display: "block",

  fontSize: "11px",

  color: "#94a3b8",

  textTransform: "uppercase",

  fontWeight: "700"

};


const patientId = {

  display: "block",

  marginTop: "2px",

  color: "#3155a4",

  fontSize: "14px"

};


const section = {

  background: "#ffffff",

  border:
    "1px solid #e2e8f0",

  borderRadius: "20px",

  padding: "25px",

  boxShadow:
    "0 8px 28px rgba(30,70,120,0.08)",

  marginBottom: "22px"

};


const sectionHeader = {

  display: "flex",

  justifyContent: "space-between",

  alignItems: "center",

  gap: "15px",

  marginBottom: "22px"

};


const sectionTitle = {

  margin: 0,

  color: "#263238",

  fontSize: "21px"

};


const sectionDescription = {

  margin: "6px 0 0",

  color: "#78909c",

  fontSize: "13px"

};


const formGrid = {

  display: "grid",

  gridTemplateColumns:
    "repeat(2, minmax(0, 1fr))",

  gap: "16px"

};


const field = {

  display: "flex",

  flexDirection: "column"

};


const label = {

  color: "#455a64",

  fontSize: "13px",

  fontWeight: "700",

  marginBottom: "7px"

};


const textarea = {

  width: "100%",

  minHeight: "110px",

  resize: "vertical",

  boxSizing: "border-box",

  border:
    "1px solid #dbe3ec",

  borderRadius: "12px",

  padding: "12px",

  fontFamily:
    "'Segoe UI', sans-serif",

  fontSize: "14px",

  color: "#263238",

  outline: "none",

  background: "#f8fafc"

};


const formActions = {

  display: "flex",

  justifyContent: "flex-end",

  marginTop: "18px"

};


const saveButton = {

  border: "none",

  background:
    "linear-gradient(135deg, #5c6bc0, #3949ab)",

  color: "#ffffff",

  padding: "12px 20px",

  borderRadius: "12px",

  cursor: "pointer",

  fontWeight: "700",

  boxShadow:
    "0 6px 15px rgba(63,81,181,0.20)"

};


const counter = {

  display: "flex",

  flexDirection: "column",

  alignItems: "center",

  background: "#eef4ff",

  padding: "8px 15px",

  borderRadius: "12px",

  color: "#3155a4"

};


const timeline = {

  display: "flex",

  flexDirection: "column",

  gap: "18px"

};


const timelineItem = {

  display: "flex",

  gap: "15px",

  alignItems: "flex-start"

};


const timelineDot = {

  minWidth: "38px",

  height: "38px",

  borderRadius: "50%",

  background:
    "linear-gradient(135deg, #5c6bc0, #42a5f5)",

  color: "#ffffff",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  fontWeight: "800",

  fontSize: "13px"

};


const timelineCard = {

  flex: 1,

  background: "#f8fafc",

  border:
    "1px solid #e8edf3",

  borderRadius: "16px",

  padding: "18px"

};


const dateBadge = {

  display: "inline-block",

  background: "#eef4ff",

  color: "#3155a4",

  padding: "6px 10px",

  borderRadius: "8px",

  fontSize: "12px",

  fontWeight: "700",

  marginBottom: "15px"

};


const infoGrid = {

  display: "grid",

  gridTemplateColumns:
    "repeat(2, minmax(0, 1fr))",

  gap: "12px"

};


const infoBlock = {

  background: "#ffffff",

  border:
    "1px solid #edf2f7",

  borderRadius: "12px",

  padding: "13px"

};


const infoBlockTitle = {

  display: "flex",

  alignItems: "center",

  gap: "6px",

  color: "#607d8b",

  fontSize: "12px",

  fontWeight: "800",

  marginBottom: "7px"

};


const infoBlockValue = {

  color: "#263238",

  fontSize: "13px",

  lineHeight: "1.5",

  whiteSpace: "pre-wrap",

  wordBreak: "break-word"

};


const emptyState = {

  textAlign: "center",

  padding: "45px 20px",

  background: "#f8fafc",

  borderRadius: "16px",

  border:
    "1px dashed #cbd5e1"

};


const emptyIcon = {

  fontSize: "45px",

  marginBottom: "10px"

};


const emptyTitle = {

  color: "#173b70",

  margin: "0 0 7px"

};


const emptyText = {

  color: "#718096",

  fontSize: "14px",

  margin: 0

};


const footer = {

  display: "flex",

  justifyContent: "space-between",

  alignItems: "center",

  marginTop: "25px",

  paddingTop: "18px",

  borderTop:
    "1px solid #e2e8f0",

  color: "#94a3b8",

  fontSize: "12px"

};


const footerLink = {

  border: "none",

  background: "transparent",

  color: "#3155a4",

  cursor: "pointer",

  fontWeight: "700"

};


const loadingPage = {

  minHeight: "100vh",

  background:
    "linear-gradient(135deg, #eef6ff, #f8fbff)",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  padding: "30px"

};


const loadingCard = {

  background: "#ffffff",

  borderRadius: "20px",

  padding: "45px",

  textAlign: "center",

  boxShadow:
    "0 10px 30px rgba(30,70,120,0.10)"

};


const loadingIcon = {

  fontSize: "40px",

  marginBottom: "10px"

};


const loadingTitle = {

  margin: 0,

  color: "#173b70"

};


const loadingText = {

  color: "#718096",

  fontSize: "14px"

};