// src/views/PruebasView.jsx

import React, { useEffect, useState } from "react";
import axios from "axios";
import { getToken } from "../services/AuthService";

const API_URL = "http://localhost:5000";

export default function PruebasView({
  onBack,
  idPaciente,
  token: tokenProp
}) {

  const [pruebas, setPruebas] = useState([]);
  const [pruebasHabilitadas, setPruebasHabilitadas] = useState([]);

  const [loading, setLoading] = useState(true);
  const [loadingHabilitar, setLoadingHabilitar] = useState(null);

  const [errorMsg, setErrorMsg] = useState("");

  const [enlaceGenerado, setEnlaceGenerado] = useState("");
  const [pruebaGenerada, setPruebaGenerada] = useState(null);

  const token =
    tokenProp || getToken();


  /* ==================================================
     CARGAR PRUEBAS DISPONIBLES
  ================================================== */

  const cargarPruebas = async () => {

    if (!idPaciente) {

      setErrorMsg(
        "⚠️ Primero selecciona un paciente."
      );

      setLoading(false);

      return;
    }


    try {

      setLoading(true);
      setErrorMsg("");


    /* ==============================================
   PRUEBAS DISPONIBLES
============================================== */

const resPruebas =
  await axios.get(
    `${API_URL}/api/evaluation/pruebas`,
    {
      headers: {
        Authorization: `Bearer ${token}`
      }
    }
  );


console.log(
  "🧪 Pruebas recibidas:",
  resPruebas.data
);


setPruebas(
  Array.isArray(resPruebas.data)
    ? resPruebas.data
    : []
);


/* ==============================================
   PRUEBAS YA HABILITADAS
============================================== */

const resHabilitadas =
  await axios.get(
    `${API_URL}/api/evaluation/pruebas/habilitadas/${idPaciente}`,
    {
      headers: {
        Authorization: `Bearer ${token}`
      }
    }
  );


console.log(
  "🔗 Pruebas habilitadas:",
  resHabilitadas.data
);


setPruebasHabilitadas(
  Array.isArray(resHabilitadas.data)
    ? resHabilitadas.data
    : []
);


} catch (error) {

  console.error(
    "❌ Error cargando pruebas:",
    error
  );


  if (
    error?.response?.status === 401 ||
    error?.response?.status === 403
  ) {

    setErrorMsg(
      "❌ Tu sesión expiró. Inicia sesión nuevamente."
    );

  } else {

    setErrorMsg(
      error?.response?.data?.message ||
      "❌ No se pudieron cargar las pruebas."
    );

  }


  setPruebas([]);

} finally {

  setLoading(false);

}

};
  /* ==================================================
     CARGAR AL ENTRAR
  ================================================== */

  useEffect(() => {

    cargarPruebas();

  }, [idPaciente, tokenProp]);

/* ==================================================
   GENERAR ENLACE
================================================== */

const generarEnlace = async (prueba) => {

  if (!idPaciente) {

    alert(
      "⚠️ Primero selecciona un paciente."
    );

    return;

  }


  try {

    setLoadingHabilitar(
      prueba.id_prueba
    );


    setErrorMsg("");


    const response =
      await axios.post(

        `${API_URL}/api/evaluation/pruebas/habilitar`,

        {
          id_paciente:
            idPaciente,

          id_prueba:
            prueba.id_prueba
        },

        {
          headers: {
            Authorization:
              `Bearer ${token}`
          }
        }

      );


  console.log(
    "✅ Prueba habilitada:",
    response.data
  );


  const enlace =
    response.data.enlace;


  setEnlaceGenerado(
    enlace
  );


  setPruebaGenerada(
    prueba
  );

      /* ==============================================
         RECARGAR HABILITADAS
      ============================================== */

      await cargarPruebas();


    } catch (error) {

      console.error(
        "❌ Error generando enlace:",
        error
      );


      alert(
        error?.response?.data?.message ||
        "❌ No se pudo generar el enlace."
      );

    } finally {

      setLoadingHabilitar(
        null
      );

    }

  };


  /* ==================================================
     COPIAR ENLACE
  ================================================== */

  const copiarEnlace = async () => {

    if (!enlaceGenerado)
      return;


    try {

      await navigator.clipboard.writeText(
        enlaceGenerado
      );


      alert(
        "✅ Enlace copiado al portapapeles."
      );


    } catch (error) {

      console.error(
        "Error copiando enlace:",
        error
      );

      alert(
        "No se pudo copiar automáticamente. Copia el enlace manualmente."
      );

    }

  };


  /* ==================================================
     CERRAR ENLACE
  ================================================== */

  const cerrarEnlace = () => {

    setEnlaceGenerado("");
    setPruebaGenerada(null);

  };


  /* ==================================================
     ESTADO DE CARGA
  ================================================== */

  if (loading) {

    return (

      <div style={container}>

        <h2 style={title}>
          🧪 Pruebas psicológicas
        </h2>

        <p style={subtitle}>
          Cargando pruebas disponibles...
        </p>

        <div style={loadingBox}>
          ⏳ Cargando...
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
        🧪 Pruebas psicológicas
      </h2>


      <p style={subtitle}>
        Selecciona una prueba para generar un enlace
        y enviárselo al paciente.
      </p>


      {/* ==============================================
          PACIENTE
      ============================================== */}

      <div style={patientBox}>

        👤 <strong>
          Paciente #{idPaciente}
        </strong>

      </div>


      {/* ==============================================
          ERROR
      ============================================== */}

      {errorMsg && (

        <div style={errorBox}>
          ❌ {errorMsg}
        </div>

      )}


      {/* ==============================================
          ENLACE GENERADO
      ============================================== */}

      {enlaceGenerado && (

        <div style={linkBox}>

          <div style={linkHeader}>

            <div>

              <div style={linkTitle}>
                🔗 Enlace generado
              </div>

              <div style={linkSubtitle}>

                {pruebaGenerada?.nombre}

              </div>

            </div>


            <button
              style={closeButton}
              onClick={cerrarEnlace}
            >
              ✕
            </button>

          </div>


          <p style={linkDescription}>

            Envía este enlace al paciente para que
            pueda responder la prueba desde su
            dispositivo.

          </p>


          <div style={linkInputContainer}>

            <input
              value={enlaceGenerado}
              readOnly
              style={linkInput}
              onClick={(e) =>
                e.target.select()
              }
            />


            <button
              style={copyButton}
              onClick={copiarEnlace}
            >
              📋 Copiar enlace
            </button>

          </div>


          <div style={linkWarning}>

            ⚠️ El paciente no necesita iniciar sesión
            para responder esta prueba.

          </div>

        </div>

      )}


      {/* ==============================================
          PRUEBAS DISPONIBLES
      ============================================== */}

      <div style={section}>

        <div style={sectionHeader}>

          <div>

            <h3 style={sectionTitle}>
              📋 Pruebas disponibles
            </h3>

            <p style={sectionSubtitle}>
              Selecciona una prueba para habilitarla
              al paciente.
            </p>

          </div>


          <span style={countBadge}>

            {pruebas.length} prueba
            {pruebas.length !== 1 ? "s" : ""}

          </span>

        </div>


        {pruebas.length === 0 ? (

          <div style={emptyBox}>

            <div style={emptyIcon}>
              🧪
            </div>

            <h3>
              No hay pruebas disponibles
            </h3>

            <p>
              No existen pruebas activas registradas
              en el sistema.
            </p>

          </div>

        ) : (

          <div style={grid}>

            {pruebas.map((prueba) => {

              const habilitada =
                pruebasHabilitadas.some(
                  (p) =>
                    Number(p.id_prueba) ===
                    Number(prueba.id_prueba)
                );


              return (

                <div
                  key={prueba.id_prueba}
                  style={card}
                >

                  <div style={cardIcon}>
                    🧠
                  </div>


                  <h3 style={cardTitle}>
                    {prueba.nombre}
                  </h3>


                  <div style={typeBadge}>
                    {prueba.tipo}
                  </div>


                  <p style={cardDescription}>
                    {prueba.descripcion ||
                      "Prueba psicológica de evaluación."}
                  </p>


                  {habilitada ? (

                    <div style={alreadyBox}>

                      <div style={alreadyText}>
                        ✓ Habilitada para este paciente
                      </div>


                      <button
                        style={secondaryButton}
                        onClick={() => {

                          const encontrada =
                            pruebasHabilitadas.find(
                              (p) =>
                                Number(
                                  p.id_prueba
                                ) ===
                                Number(
                                  prueba.id_prueba
                                )
                            );


                          if (
                            encontrada?.id_habilitacion
                          ) {

                            const frontendUrl =
                              window.location.origin;

                            const enlace =
                              `${frontendUrl}/prueba/${encontrada.id_habilitacion}`;

                            setEnlaceGenerado(
                              enlace
                            );

                            setPruebaGenerada(
                              prueba
                            );

                          }

                        }}
                      >
                        🔗 Ver enlace
                      </button>

                    </div>

                  ) : (

                    <button
                      style={button}
                      disabled={
                        loadingHabilitar ===
                        prueba.id_prueba
                      }
                      onClick={() =>
                        generarEnlace(prueba)
                      }
                    >

                      {loadingHabilitar ===
                      prueba.id_prueba
                        ? "⏳ Generando..."
                        : "🔗 Generar enlace"}

                    </button>

                  )}

                </div>

              );

            })}

          </div>

        )}

      </div>


      {/* ==============================================
          CÓMO FUNCIONA
      ============================================== */}

      <div style={infoBox}>

        <h3 style={infoTitle}>
          💡 ¿Cómo funciona?
        </h3>

        <ol style={steps}>

          <li>
            Selecciona una prueba.
          </li>

          <li>
            Genera el enlace.
          </li>

          <li>
            Copia el enlace.
          </li>

          <li>
            Envíalo al paciente.
          </li>

          <li>
            El paciente responde desde su dispositivo.
          </li>

        </ol>

      </div>


      {/* ==============================================
          VOLVER
      ============================================== */}

     <button
  style={{
    ...backButton,
    background: "#1565C0",
    color: "#fff"
  }}
  onClick={onBack}
>
  ⬅️ Regresar al historial
</button>

      <p style={footerText}>

        🌱 Las pruebas son herramientas de evaluación
        y sus resultados son preliminares. El psicólogo
        tiene siempre la decisión clínica final.

      </p>

    </div>

  );

}


/* ==================================================
   ESTILOS
================================================== */

const container = {

  maxWidth: "1000px",

  margin: "30px auto",

  padding: "30px",

  background: "#fff",

  borderRadius: "20px",

  boxShadow:
    "0 10px 30px rgba(0,0,0,0.08)"

};


const title = {

  fontSize: "28px",

  fontWeight: "700",

  color: "#263238",

  marginBottom: "8px"

};


const subtitle = {

  fontSize: "16px",

  color: "#607D8B",

  marginBottom: "20px"

};


const patientBox = {

  background:
    "linear-gradient(135deg, #E3F2FD, #F3E5F5)",

  padding: "15px 18px",

  borderRadius: "12px",

  marginBottom: "20px",

  color: "#37474F",

  border:
    "1px solid #CFD8DC"

};


const errorBox = {

  background: "#FFEBEE",

  color: "#C62828",

  padding: "14px",

  borderRadius: "10px",

  marginBottom: "20px",

  border:
    "1px solid #FFCDD2"

};


const loadingBox = {

  padding: "30px",

  textAlign: "center",

  color: "#607D8B",

  background: "#F5F7FA",

  borderRadius: "12px"

};


const linkBox = {

  background:
    "linear-gradient(135deg, #E8F5E9, #E3F2FD)",

  border:
    "1px solid #B2DFDB",

  padding: "20px",

  borderRadius: "16px",

  marginBottom: "25px"

};


const linkHeader = {

  display: "flex",

  justifyContent: "space-between",

  alignItems: "flex-start"

};


const linkTitle = {

  fontSize: "20px",

  fontWeight: "700",

  color: "#1565C0"

};


const linkSubtitle = {

  marginTop: "4px",

  color: "#546E7A",

  fontWeight: "600"

};


const linkDescription = {

  color: "#455A64",

  lineHeight: "1.5"

};


const linkInputContainer = {

  display: "flex",

  gap: "10px",

  marginTop: "15px"

};


const linkInput = {

  flex: 1,

  padding: "12px",

  border:
    "1px solid #B0BEC5",

  borderRadius: "8px",

  background: "#fff",

  fontSize: "14px"

};


const copyButton = {

  padding: "12px 18px",

  border: "none",

  borderRadius: "8px",

  background: "#2E7D32",

  color: "#fff",

  fontWeight: "700",

  cursor: "pointer"

};


const closeButton = {

  border: "none",

  background: "transparent",

  fontSize: "20px",

  cursor: "pointer",

  color: "#607D8B"

};


const linkWarning = {

  marginTop: "14px",

  fontSize: "13px",

  color: "#546E7A"

};


const section = {

  marginTop: "25px"

};


const sectionHeader = {

  display: "flex",

  justifyContent: "space-between",

  alignItems: "center",

  marginBottom: "18px"

};


const sectionTitle = {

  margin: 0,

  fontSize: "20px",

  color: "#263238"

};


const sectionSubtitle = {

  margin:
    "5px 0 0",

  color: "#78909C"

};


const countBadge = {

  background: "#E3F2FD",

  color: "#1565C0",

  padding: "7px 12px",

  borderRadius: "20px",

  fontSize: "13px",

  fontWeight: "700"

};


const grid = {

  display: "grid",

  gridTemplateColumns:
    "repeat(auto-fit, minmax(280px, 1fr))",

  gap: "18px"

};


const card = {

  background: "#FAFAFA",

  border:
    "1px solid #E0E0E0",

  borderRadius: "16px",

  padding: "20px",

  transition: "0.2s",

  boxShadow:
    "0 3px 10px rgba(0,0,0,0.05)"

};


const cardIcon = {

  fontSize: "32px",

  marginBottom: "8px"

};


const cardTitle = {

  fontSize: "18px",

  fontWeight: "700",

  color: "#263238",

  marginBottom: "8px"

};


const typeBadge = {

  display: "inline-block",

  background: "#E8EAF6",

  color: "#3949AB",

  padding: "5px 10px",

  borderRadius: "15px",

  fontSize: "12px",

  fontWeight: "700",

  marginBottom: "12px"

};


const cardDescription = {

  color: "#607D8B",

  fontSize: "14px",

  lineHeight: "1.5",

  minHeight: "45px"

};


const button = {

  width: "100%",

  marginTop: "15px",

  padding: "12px",

  border: "none",

  borderRadius: "9px",

  background: "#5C6BC0",

  color: "#fff",

  fontWeight: "700",

  cursor: "pointer"

};


const secondaryButton = {

  width: "100%",

  marginTop: "10px",

  padding: "10px",

  border:
    "1px solid #5C6BC0",

  borderRadius: "9px",

  background: "#fff",

  color: "#3949AB",

  fontWeight: "700",

  cursor: "pointer"

};


const alreadyBox = {

  marginTop: "12px",

  padding: "10px",

  background: "#E8F5E9",

  borderRadius: "9px"

};


const alreadyText = {

  color: "#2E7D32",

  fontSize: "13px",

  fontWeight: "700"

};


const emptyBox = {

  textAlign: "center",

  padding: "45px 20px",

  background: "#F8F9FA",

  borderRadius: "15px",

  border:
    "1px dashed #CFD8DC"

};


const emptyIcon = {

  fontSize: "45px",

  marginBottom: "10px"

};


const infoBox = {

  marginTop: "30px",

  padding: "20px",

  background: "#FFF8E1",

  borderRadius: "14px",

  border:
    "1px solid #FFE082"

};


const infoTitle = {

  marginTop: 0,

  color: "#795548"

};


const steps = {

  margin: 0,

  paddingLeft: "22px",

  color: "#5D4037",

  lineHeight: "1.9"

};


const backButton = {

  marginTop: "25px",

  padding: "12px 20px",

  border: "none",

  borderRadius: "9px",

  background: "#E74C3C",

  color: "#fff",

  fontWeight: "700",

  cursor: "pointer"

};


const footerText = {

  marginTop: "18px",

  textAlign: "center",

  color: "#78909C",

  fontSize: "13px"

};