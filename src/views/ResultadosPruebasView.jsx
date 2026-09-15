// src/views/ResultadosPruebasView.jsx

import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { getToken } from "../services/AuthService";

export default function ResultadosPruebasView() {

  const { idPaciente } = useParams();
  const navigate = useNavigate();

  const [resultados, setResultados] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");


  // =====================================================
  // CARGAR RESULTADOS
  // =====================================================

  useEffect(() => {

    const fetchResultados = async () => {

      try {

        const token = getToken();

      const res = await fetch(
  `http://localhost:5000/api/evaluation/resultados/${idPaciente}`,
  {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  }
);

        if (!res.ok) {
          throw new Error(
            "No se pudieron obtener los resultados"
          );
        }

        const data = await res.json();

        console.log(
          "🧪 Resultados recibidos:",
          data
        );

        setResultados(
  Array.isArray(data)
    ? data
    : data.resultados || []
);

      } catch (err) {

        console.error(
          "❌ Error al obtener resultados:",
          err
        );

        setError(
          "No fue posible cargar los resultados de las pruebas."
        );

      } finally {

        setLoading(false);

      }

    };


    if (idPaciente) {

      fetchResultados();

    } else {

      setLoading(false);

      setError(
        "No se encontró el paciente."
      );

    }

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
  // FORMATEAR FECHA
  // =====================================================

  const formatearFecha = (fecha) => {

    if (!fecha) {
      return "No registrada";
    }


    const fechaObj = new Date(fecha);


    if (
      Number.isNaN(
        fechaObj.getTime()
      )
    ) {

      return "No registrada";

    }


    return fechaObj.toLocaleDateString(
      "es-MX",
      {
        day: "2-digit",
        month: "long",
        year: "numeric",
      }
    );

  };


  // =====================================================
  // CARGANDO
  // =====================================================

  if (loading) {

    return (

      <div style={page}>

        <div style={loadingCard}>

          <div style={loadingIcon}>
            🧪
          </div>

          <h2 style={loadingTitle}>
            Cargando resultados...
          </h2>

          <p style={loadingText}>
            Estamos consultando los resultados de las
            pruebas psicológicas del paciente.
          </p>

        </div>

      </div>

    );

  }


  // =====================================================
  // ERROR
  // =====================================================

  if (error) {

    return (

      <div style={page}>

        <div style={errorCard}>

          <div style={errorIcon}>
            ⚠️
          </div>

          <h2 style={errorTitle}>
            No se pudieron cargar los resultados
          </h2>

          <p style={errorText}>
            {error}
          </p>

          <button
            type="button"
            onClick={volverAlExpediente}
            style={backButton}
          >
            ← Volver al expediente
          </button>

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
              🧪
            </div>


            <div>

              <div style={eyebrow}>
                EXPEDIENTE CLÍNICO
              </div>

              <h1 style={title}>
                Resultados de pruebas
              </h1>

              <p style={subtitle}>
                Consulta los resultados e interpretaciones
                de las pruebas psicológicas realizadas.
              </p>

            </div>

          </div>

        </div>


        {/* =================================================
            RESUMEN
        ================================================= */}

        <div style={summaryCard}>

          <div style={summaryIcon}>
            📊
          </div>


          <div>

            <div style={summaryLabel}>
              RESULTADOS REGISTRADOS
            </div>

            <div style={summaryNumber}>
              {resultados.length}
            </div>

          </div>


          <div style={summaryDescription}>

            {resultados.length === 0

              ? "El paciente todavía no cuenta con resultados registrados."

              : resultados.length === 1

                ? "Se encontró un resultado registrado."

                : "Se encontraron resultados de pruebas realizadas."

            }

          </div>

        </div>


        {/* =================================================
            SIN RESULTADOS
        ================================================= */}

        {resultados.length === 0 ? (

          <div style={emptyCard}>

            <div style={emptyIcon}>
              🧪
            </div>

            <h2 style={emptyTitle}>
              No hay resultados todavía
            </h2>

            <p style={emptyText}>
              Cuando el paciente complete una prueba
              psicológica, sus resultados aparecerán aquí.
            </p>

            <button
              type="button"
              onClick={volverAlExpediente}
              style={emptyButton}
            >
              ← Volver al expediente
            </button>

          </div>

        ) : (

          /* =================================================
             RESULTADOS
          ================================================= */

          <div style={resultsSection}>

            <div style={sectionHeader}>

              <div>

                <h2 style={sectionTitle}>
                  📋 Historial de resultados
                </h2>

                <p style={sectionDescription}>
                  Resultados obtenidos en las pruebas psicológicas.
                </p>

              </div>

            </div>


            <div style={resultsGrid}>

              {resultados.map(
                (resultado, index) => (

                  <div
                    key={
                      resultado.id_resultado ||
                      `${resultado.id_prueba}-${index}`
                    }
                    style={resultCard}
                  >

                    {/* =================================================
                        CABECERA RESULTADO
                    ================================================= */}

                    <div style={resultHeader}>

                      <div style={resultNumber}>
                        {index + 1}
                      </div>


                      <div style={resultTitleContainer}>

                        <div style={resultLabel}>
                          PRUEBA PSICOLÓGICA
                        </div>

                        <h3 style={resultTitle}>

                          {
                            resultado.prueba ||
                            resultado.nombre_prueba ||
                            "Prueba sin nombre"
                          }

                        </h3>

                      </div>

                    </div>


                    {/* =================================================
                        INFORMACIÓN
                    ================================================= */}

                    <div style={resultInfo}>

                      {/* ============================
                          PUNTAJE
                      ============================ */}

                      <div style={infoBox}>

                        <span style={infoBoxIcon}>
                          ⭐
                        </span>


                        <div>

                          <div style={infoBoxLabel}>
                            Puntaje
                          </div>

                          <div style={score}>
                            {
                              resultado.puntaje_total ??
                              "—"
                            }
                          </div>

                        </div>

                      </div>


                      {/* ============================
                          FECHA
                      ============================ */}

                      <div style={infoBox}>

                        <span style={infoBoxIcon}>
                          📅
                        </span>


                        <div>

                          <div style={infoBoxLabel}>
                            Fecha
                          </div>

                          <div style={infoBoxValue}>
                            {
                              formatearFecha(
                                resultado.fecha
                              )
                            }
                          </div>

                        </div>

                      </div>

                    </div>


                    {/* =================================================
                        INTERPRETACIÓN
                    ================================================= */}

                    <div style={interpretation}>

                      <div style={interpretationHeader}>

                        <span style={interpretationIcon}>
                          📖
                        </span>

                        <span style={interpretationTitle}>
                          Interpretación
                        </span>

                      </div>


                      <p style={interpretationText}>

                        {
                          resultado.interpretacion ||
                          "No se registró una interpretación para este resultado."
                        }

                      </p>

                    </div>

                  </div>

                )
              )}

            </div>

          </div>

        )}


        {/* =================================================
            PIE
        ================================================= */}

        <div style={footer}>

          <span>
            🧠 MirrorSoul
          </span>

          <span>
            Expediente del paciente #{idPaciente}
          </span>

        </div>

      </div>

    </div>

  );

}


// =====================================================
// 🎨 ESTILOS
// =====================================================

const page = {

  minHeight: "100vh",

  padding: "30px 20px 50px",

  boxSizing: "border-box",

  background:
    "linear-gradient(135deg, #eef5ff 0%, #f8fbff 45%, #eef4ff 100%)",

  fontFamily:
    "'Segoe UI', Tahoma, Geneva, Verdana, sans-serif",

};


// =====================================================
// CONTENEDOR
// =====================================================

const container = {

  width: "100%",

  maxWidth: "1100px",

  margin: "0 auto",

};


// =====================================================
// HEADER
// =====================================================

const header = {

  marginBottom: "25px",

};


const backButton = {

  border: "none",

  background: "#ffffff",

  color: "#3157a6",

  padding: "10px 16px",

  borderRadius: "12px",

  cursor: "pointer",

  fontWeight: "700",

  fontSize: "14px",

  boxShadow:
    "0 5px 16px rgba(40,70,120,0.08)",

  marginBottom: "22px",

  transition:
    "all 0.2s ease",

};


const headerContent = {

  display: "flex",

  alignItems: "center",

  gap: "18px",

  background: "#ffffff",

  padding: "25px",

  borderRadius: "20px",

  border:
    "1px solid #e2e8f0",

  boxShadow:
    "0 8px 25px rgba(30,70,120,0.08)",

};


const headerIcon = {

  width: "65px",

  height: "65px",

  flexShrink: 0,

  borderRadius: "18px",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  fontSize: "30px",

  background:
    "linear-gradient(135deg, #e3f2fd, #dbe8ff)",

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

  fontSize: "28px",

  fontWeight: "800",

};


const subtitle = {

  margin: "7px 0 0",

  color: "#718096",

  fontSize: "14px",

  lineHeight: "1.5",

};


// =====================================================
// SUMMARY
// =====================================================

const summaryCard = {

  display: "flex",

  alignItems: "center",

  gap: "16px",

  background: "#ffffff",

  borderRadius: "18px",

  padding: "20px 24px",

  marginBottom: "28px",

  border:
    "1px solid #e2e8f0",

  boxShadow:
    "0 6px 20px rgba(30,70,120,0.07)",

};


const summaryIcon = {

  width: "52px",

  height: "52px",

  borderRadius: "14px",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  background: "#eef4ff",

  fontSize: "24px",

};


const summaryLabel = {

  color: "#78909c",

  fontSize: "10px",

  fontWeight: "800",

  letterSpacing: "1.2px",

};


const summaryNumber = {

  color: "#3157a6",

  fontSize: "25px",

  fontWeight: "800",

  marginTop: "2px",

};


const summaryDescription = {

  marginLeft: "auto",

  maxWidth: "430px",

  color: "#718096",

  fontSize: "13px",

  lineHeight: "1.5",

};


// =====================================================
// SECCIÓN
// =====================================================

const resultsSection = {

  marginTop: "5px",

};


const sectionHeader = {

  marginBottom: "18px",

};


const sectionTitle = {

  margin: 0,

  color: "#263238",

  fontSize: "21px",

  fontWeight: "800",

};


const sectionDescription = {

  margin: "5px 0 0",

  color: "#78909c",

  fontSize: "13px",

};


// =====================================================
// GRID DE RESULTADOS
// =====================================================

const resultsGrid = {

  display: "grid",

  gridTemplateColumns:
    "repeat(auto-fit, minmax(420px, 1fr))",

  gap: "20px",

};


// =====================================================
// TARJETA RESULTADO
// =====================================================

const resultCard = {

  background: "#ffffff",

  border:
    "1px solid #e2e8f0",

  borderRadius: "18px",

  padding: "22px",

  boxShadow:
    "0 6px 20px rgba(30,70,120,0.07)",

};


// =====================================================
// HEADER RESULTADO
// =====================================================

const resultHeader = {

  display: "flex",

  alignItems: "center",

  gap: "13px",

  marginBottom: "20px",

};


const resultNumber = {

  width: "42px",

  height: "42px",

  borderRadius: "12px",

  background:
    "linear-gradient(135deg, #5c6bc0, #3949ab)",

  color: "#ffffff",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  fontSize: "16px",

  fontWeight: "800",

  flexShrink: 0,

};


const resultTitleContainer = {

  minWidth: 0,

};


const resultLabel = {

  color: "#90a4ae",

  fontSize: "9px",

  fontWeight: "800",

  letterSpacing: "1px",

  marginBottom: "3px",

};


const resultTitle = {

  margin: 0,

  color: "#263238",

  fontSize: "17px",

  fontWeight: "800",

};


// =====================================================
// INFORMACIÓN
// =====================================================

const resultInfo = {

  display: "grid",

  gridTemplateColumns:
    "1fr 1fr",

  gap: "12px",

  marginBottom: "16px",

};


const infoBox = {

  display: "flex",

  alignItems: "center",

  gap: "10px",

  background: "#f8fafc",

  borderRadius: "12px",

  padding: "12px",

};


const infoBoxIcon = {

  width: "35px",

  height: "35px",

  borderRadius: "10px",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  background: "#e8f1ff",

  fontSize: "16px",

};


const infoBoxLabel = {

  color: "#90a4ae",

  fontSize: "10px",

  fontWeight: "700",

  marginBottom: "2px",

};


const infoBoxValue = {

  color: "#263238",

  fontSize: "12px",

  fontWeight: "700",

};


const score = {

  color: "#3157a6",

  fontSize: "17px",

  fontWeight: "800",

};


// =====================================================
// INTERPRETACIÓN
// =====================================================

const interpretation = {

  background: "#f7f9ff",

  border:
    "1px solid #e2e8ff",

  borderRadius: "13px",

  padding: "15px",

};


const interpretationHeader = {

  display: "flex",

  alignItems: "center",

  gap: "7px",

  marginBottom: "8px",

};


const interpretationIcon = {

  fontSize: "17px",

};


const interpretationTitle = {

  color: "#3949ab",

  fontSize: "13px",

  fontWeight: "800",

};


const interpretationText = {

  margin: 0,

  color: "#546e7a",

  fontSize: "13px",

  lineHeight: "1.6",

};


// =====================================================
// SIN RESULTADOS
// =====================================================

const emptyCard = {

  background: "#ffffff",

  borderRadius: "20px",

  padding: "60px 30px",

  textAlign: "center",

  border:
    "1px solid #e2e8f0",

  boxShadow:
    "0 8px 25px rgba(30,70,120,0.07)",

};


const emptyIcon = {

  fontSize: "50px",

  marginBottom: "10px",

};


const emptyTitle = {

  margin: "0 0 8px",

  color: "#263238",

  fontSize: "21px",

};


const emptyText = {

  maxWidth: "500px",

  margin: "0 auto 20px",

  color: "#78909c",

  fontSize: "14px",

  lineHeight: "1.6",

};


const emptyButton = {

  border: "none",

  background:
    "linear-gradient(135deg, #5c6bc0, #3949ab)",

  color: "#ffffff",

  padding: "11px 18px",

  borderRadius: "11px",

  cursor: "pointer",

  fontWeight: "700",

};


// =====================================================
// LOADING
// =====================================================

const loadingCard = {

  maxWidth: "500px",

  margin: "100px auto",

  background: "#ffffff",

  padding: "45px",

  borderRadius: "20px",

  textAlign: "center",

  boxShadow:
    "0 8px 25px rgba(30,70,120,0.08)",

};


const loadingIcon = {

  fontSize: "45px",

  marginBottom: "10px",

};


const loadingTitle = {

  margin: "0 0 8px",

  color: "#263238",

};


const loadingText = {

  margin: 0,

  color: "#78909c",

  fontSize: "14px",

};


// =====================================================
// ERROR
// =====================================================

const errorCard = {

  maxWidth: "550px",

  margin: "100px auto",

  background: "#ffffff",

  padding: "45px",

  borderRadius: "20px",

  textAlign: "center",

  boxShadow:
    "0 8px 25px rgba(30,70,120,0.08)",

};


const errorIcon = {

  fontSize: "45px",

  marginBottom: "10px",

};


const errorTitle = {

  margin: "0 0 10px",

  color: "#263238",

};


const errorText = {

  color: "#78909c",

  marginBottom: "20px",

};


// =====================================================
// FOOTER
// =====================================================

const footer = {

  display: "flex",

  justifyContent: "space-between",

  borderTop:
    "1px solid #e2e8f0",

  marginTop: "35px",

  paddingTop: "18px",

  color: "#90a4ae",

  fontSize: "12px",

};