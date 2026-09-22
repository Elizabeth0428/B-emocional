// src/views/HistorialInicialView.jsx

import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { getToken } from "../services/AuthService";

export default function HistorialInicialView() {

  const { idPaciente } = useParams();
  const navigate = useNavigate();

  const [historial, setHistorial] = useState(null);
  const [editMode, setEditMode] = useState(false);
  const [guardando, setGuardando] = useState(false);


  // =====================================================
  // OBTENER HISTORIAL
  // =====================================================

  useEffect(() => {

    const fetchHistorial = async () => {

      try {

        const res = await fetch(
          `https://reflejoyalma.com/api/historial-inicial/${idPaciente}`,
          {
            headers: {
              Authorization: `Bearer ${getToken()}`
            }
          }
        );


        if (res.ok) {

          const data = await res.json();

          console.log(
            "📋 Historial recibido:",
            data
          );

          setHistorial(data);

        } else {

          setHistorial({});

        }

      } catch (err) {

        console.error(
          "❌ Error al obtener historial:",
          err
        );

        setHistorial({});

      }

    };


    fetchHistorial();

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
  // GUARDAR
  // =====================================================

  const handleSave = async () => {

    try {

      setGuardando(true);

      const res = await fetch(
        `https://reflejoyalma.com/api/historial-inicial/${idPaciente}`,
        {
          method: "PUT",

          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${getToken()}`
          },

          body: JSON.stringify(historial)

        }
      );


      if (!res.ok) {

        throw new Error(
          "Error al actualizar historial"
        );

      }


      alert(
        "✅ Historial actualizado correctamente"
      );

      setEditMode(false);


    } catch (err) {

      console.error(
        "❌ Error al guardar:",
        err
      );

      alert(
        "❌ No se pudo actualizar el historial"
      );

    } finally {

      setGuardando(false);

    }

  };


  // =====================================================
  // CARGANDO
  // =====================================================

  if (historial === null) {

    return (

      <div style={loadingPage}>

        <div style={loadingCard}>

          <div style={loadingIcon}>
            ⏳
          </div>

          <h2 style={loadingTitle}>
            Cargando historial...
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
  // SIN HISTORIAL
  // =====================================================

  if (Object.keys(historial).length === 0) {

    return (

      <div style={page}>

        <div style={container}>

          <div style={topBar}>

            <button
              type="button"
              onClick={volverAlExpediente}
              style={backButton}
            >
              ← Volver al expediente
            </button>

          </div>


          <div style={emptyState}>

            <div style={emptyIcon}>
              📋
            </div>

            <h2 style={emptyTitle}>
              Historial clínico inicial
            </h2>

            <p style={emptyText}>
              No hay historial clínico registrado
              para este paciente.
            </p>

            <button
              type="button"
              onClick={volverAlExpediente}
              style={primaryButton}
            >
              👤 Ir al expediente
            </button>

          </div>

        </div>

      </div>

    );

  }


  // =====================================================
  // CAMPOS VISIBLES
  // =====================================================

  const campos = Object.keys(historial).filter(
    (campo) =>
      campo !== "id_paciente" &&
      campo !== "id_historial"
  );


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
              📋
            </div>

            <div>

              <div style={eyebrow}>
                EXPEDIENTE DEL PACIENTE
              </div>

              <h1 style={title}>
                Historial Clínico Inicial
              </h1>

              <p style={subtitle}>
                Información clínica inicial registrada
                del paciente.
              </p>

            </div>

          </div>

        </div>


        {/* =================================================
            INDICADOR DEL PACIENTE
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
            INFORMACIÓN
        ================================================= */}

        <section style={section}>

          <div style={sectionHeader}>

            <div>

              <h2 style={sectionTitle}>
                🩺 Información clínica
              </h2>

              <p style={sectionDescription}>
                Datos registrados durante la evaluación
                clínica inicial.
              </p>

            </div>


            {!editMode && (

              <button
                type="button"
                onClick={() =>
                  setEditMode(true)
                }
                style={editButton}
              >
                ✏️ Editar
              </button>

            )}

          </div>


          <div style={fieldsGrid}>

            {campos.map((campo) => (

              <div
                key={campo}
                style={fieldCard}
              >

                <div style={fieldLabel}>

                  {formatearCampo(campo)}

                </div>


                {editMode ? (

                  <textarea
                    value={
                      historial[campo] ?? ""
                    }

                    onChange={(e) =>

                      setHistorial({
                        ...historial,
                        [campo]:
                          e.target.value
                      })

                    }

                    style={textarea}

                  />

                ) : (

                  <div style={fieldValue}>

                    {historial[campo] ||
                      "No registrado"}

                  </div>

                )}

              </div>

            ))}

          </div>

        </section>


        {/* =================================================
            BOTONES DE EDICIÓN
        ================================================= */}

        {editMode && (

          <div style={editActions}>

            <button
              type="button"
              onClick={handleSave}
              disabled={guardando}
              style={{
                ...saveButton,
                opacity:
                  guardando ? 0.7 : 1
              }}
            >

              {guardando
                ? "⏳ Guardando..."
                : "💾 Guardar cambios"}

            </button>


            <button
              type="button"
              onClick={() =>
                setEditMode(false)
              }
              disabled={guardando}
              style={cancelButton}
            >
              Cancelar
            </button>

          </div>

        )}


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
// FORMATEAR NOMBRE DE CAMPO
// =====================================================

function formatearCampo(campo) {

  return campo
    .replace(/_/g, " ")
    .replace(/\b\w/g, (letra) =>
      letra.toUpperCase()
    );

}


// =====================================================
// 🎨 ESTILOS
// =====================================================

const page = {

  minHeight: "100vh",

  background:
    "linear-gradient(135deg, #eef6ff 0%, #f8fbff 50%, #eef4ff 100%)",

  padding: "30px 20px 50px",

  boxSizing: "border-box",

};


const container = {

  maxWidth: "1100px",

  margin: "0 auto",

};


const header = {

  marginBottom: "22px",

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

  marginBottom: "22px",

};


const headerContent = {

  display: "flex",

  alignItems: "center",

  gap: "16px",

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
    "0 8px 20px rgba(63,81,181,0.20)",

};


const eyebrow = {

  fontSize: "11px",

  fontWeight: "800",

  letterSpacing: "2px",

  color: "#5c6bc0",

  marginBottom: "5px",

};


const title = {

  margin: 0,

  color: "#173b70",

  fontSize: "30px",

  fontWeight: "800",

};


const subtitle = {

  margin: "6px 0 0",

  color: "#718096",

  fontSize: "14px",

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
    "0 6px 20px rgba(30,70,120,0.07)",

};


const patientBarIcon = {

  width: "40px",

  height: "40px",

  borderRadius: "12px",

  background: "#eef4ff",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  fontSize: "19px",

};


const patientLabel = {

  display: "block",

  fontSize: "11px",

  color: "#94a3b8",

  textTransform: "uppercase",

  fontWeight: "700",

};


const patientId = {

  display: "block",

  marginTop: "2px",

  color: "#3155a4",

  fontSize: "14px",

};


const section = {

  background: "#ffffff",

  border:
    "1px solid #e2e8f0",

  borderRadius: "20px",

  padding: "25px",

  boxShadow:
    "0 8px 28px rgba(30,70,120,0.08)",

};


const sectionHeader = {

  display: "flex",

  justifyContent: "space-between",

  alignItems: "center",

  gap: "15px",

  marginBottom: "22px",

};


const sectionTitle = {

  margin: 0,

  color: "#263238",

  fontSize: "21px",

};


const sectionDescription = {

  margin: "6px 0 0",

  color: "#78909c",

  fontSize: "13px",

};


const fieldsGrid = {

  display: "grid",

  gridTemplateColumns:
    "repeat(2, minmax(0, 1fr))",

  gap: "15px",

};


const fieldCard = {

  background: "#f8fafc",

  border:
    "1px solid #edf2f7",

  borderRadius: "14px",

  padding: "16px",

  minHeight: "90px",

  boxSizing: "border-box",

};


const fieldLabel = {

  color: "#607d8b",

  fontSize: "12px",

  fontWeight: "800",

  textTransform: "uppercase",

  letterSpacing: "0.5px",

  marginBottom: "8px",

};


const fieldValue = {

  color: "#263238",

  fontSize: "14px",

  lineHeight: "1.6",

  whiteSpace: "pre-wrap",

  wordBreak: "break-word",

};


const textarea = {

  width: "100%",

  minHeight: "90px",

  resize: "vertical",

  boxSizing: "border-box",

  border:
    "1px solid #cbd5e1",

  borderRadius: "10px",

  padding: "10px",

  fontFamily:
    "'Segoe UI', sans-serif",

  fontSize: "14px",

  color: "#263238",

  outline: "none",

  background: "#ffffff",

};


const editButton = {

  border: "none",

  background: "#eef4ff",

  color: "#3155a4",

  padding: "10px 16px",

  borderRadius: "11px",

  cursor: "pointer",

  fontWeight: "700",

};


const editActions = {

  display: "flex",

  gap: "10px",

  marginTop: "18px",

  justifyContent: "flex-end",

};


const saveButton = {

  border: "none",

  background:
    "linear-gradient(135deg, #43a047, #2e7d32)",

  color: "#ffffff",

  padding: "12px 20px",

  borderRadius: "12px",

  cursor: "pointer",

  fontWeight: "700",

};


const cancelButton = {

  border: "none",

  background: "#f1f5f9",

  color: "#475569",

  padding: "12px 20px",

  borderRadius: "12px",

  cursor: "pointer",

  fontWeight: "700",

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

  fontSize: "12px",

};


const footerLink = {

  border: "none",

  background: "transparent",

  color: "#3155a4",

  cursor: "pointer",

  fontWeight: "700",

};


const loadingPage = {

  minHeight: "100vh",

  background:
    "linear-gradient(135deg, #eef6ff, #f8fbff)",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  padding: "30px",

};


const loadingCard = {

  background: "#ffffff",

  borderRadius: "20px",

  padding: "45px",

  textAlign: "center",

  boxShadow:
    "0 10px 30px rgba(30,70,120,0.10)",

};


const loadingIcon = {

  fontSize: "40px",

  marginBottom: "10px",

};


const loadingTitle = {

  margin: 0,

  color: "#173b70",

};


const loadingText = {

  color: "#718096",

  fontSize: "14px",

};


const emptyState = {

  background: "#ffffff",

  borderRadius: "20px",

  padding: "60px 30px",

  textAlign: "center",

  boxShadow:
    "0 8px 28px rgba(30,70,120,0.08)",

};


const emptyIcon = {

  fontSize: "50px",

  marginBottom: "12px",

};


const emptyTitle = {

  color: "#173b70",

  margin: "0 0 8px",

};


const emptyText = {

  color: "#718096",

  marginBottom: "25px",

};


const primaryButton = {

  border: "none",

  background:
    "linear-gradient(135deg, #5c6bc0, #3949ab)",

  color: "#ffffff",

  padding: "12px 20px",

  borderRadius: "12px",

  cursor: "pointer",

  fontWeight: "700",

};