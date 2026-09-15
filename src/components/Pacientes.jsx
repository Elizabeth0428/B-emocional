
// src/components/Pacientes.jsx

import { useEffect, useMemo, useState } from "react";
import axios from "axios";

import PacienteDetalle from "./PacienteDetalle.jsx";
import { usePatient } from "./PatientContext.jsx";
import { getToken } from "../services/AuthService";


export default function Pacientes({ onBack }) {

  const [pacientes, setPacientes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [pacienteSeleccionadoLocal, setPacienteSeleccionadoLocal] =
    useState(null);

  const [error, setError] = useState("");

  // 🔎 Buscador
  const [busqueda, setBusqueda] = useState("");

  const { setPaciente } = usePatient();


  // ==================================================
  // CARGAR PACIENTES
  // ==================================================

  useEffect(() => {

    const fetchPacientes = async () => {

      try {

        const token = getToken();

        if (!token) {

          setError(
            "⚠️ No hay sesión activa. Inicia sesión nuevamente."
          );

          setLoading(false);

          return;
        }


        const res = await axios.get(
          "http://localhost:5000/api/pacientes",
          {
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json",
            },
          }
        );


        if (Array.isArray(res.data)) {

          setPacientes(res.data);

        } else if (res.data?.data) {

          setPacientes(res.data.data);

        } else {

          setPacientes([]);

        }

      } catch (err) {

        console.error(
          "❌ Error al obtener pacientes:",
          err
        );


        if (err.response?.status === 401) {

          setError(
            "⚠️ Sesión expirada o token inválido. Vuelve a iniciar sesión."
          );

        } else {

          setError(
            "❌ No se pudieron cargar los pacientes."
          );

        }

      } finally {

        setLoading(false);

      }

    };


    fetchPacientes();

  }, []);


  // ==================================================
  // 🔎 BUSCADOR
  // Busca por:
  // - Nombre
  // - ID MirrorSoul
  // ==================================================

  const pacientesFiltrados = useMemo(() => {

    const texto =
      busqueda
        .trim()
        .toLowerCase();


    if (!texto) {

      return pacientes;

    }


    return pacientes.filter((paciente) => {

      const nombre =
        `${paciente.nombre || ""} ${
          paciente.apellido_paterno || ""
        } ${
          paciente.apellido_materno || ""
        }`.toLowerCase();


      const idMirror =
        String(
          paciente.id_mirror || ""
        ).toLowerCase();


      return (
        nombre.includes(texto) ||
        idMirror.includes(texto)
      );

    });

  }, [pacientes, busqueda]);


  // ==================================================
  // VISTA DEL EXPEDIENTE
  // ==================================================

  if (pacienteSeleccionadoLocal) {

    return (

      <PacienteDetalle
        idPaciente={
          pacienteSeleccionadoLocal
        }

        onBack={() =>
          setPacienteSeleccionadoLocal(null)
        }

      />

    );

  }


  // ==================================================
  // RENDER
  // ==================================================

  return (

    <div style={container}>

      {/* ============================================
          ENCABEZADO
      ============================================ */}

      <div style={header}>

        <div>

          <div style={smallTitle}>
            MIRRORSOUL
          </div>

          <h2 style={title}>
            👥 Pacientes registrados
          </h2>

          <p style={subtitle}>
            Consulta y administra los expedientes de tus pacientes.
          </p>

        </div>


        <div style={counter}>

          <strong style={counterNumber}>
            {pacientes.length}
          </strong>

          <span style={counterLabel}>
            pacientes
          </span>

        </div>

      </div>


      {/* ============================================
          BUSCADOR
      ============================================ */}

      <div style={searchContainer}>

        <span style={searchIcon}>
          🔎
        </span>


        <input
          type="text"
          placeholder="Buscar por nombre o ID MirrorSoul..."
          value={busqueda}
          onChange={(e) =>
            setBusqueda(e.target.value)
          }
          style={searchInput}
        />


        {busqueda && (

          <button
            type="button"
            style={clearButton}
            onClick={() =>
              setBusqueda("")
            }
          >
            ✕
          </button>

        )}

      </div>


      {/* ============================================
          RESULTADOS DEL BUSCADOR
      ============================================ */}

      {!loading && !error && (

        <div style={resultsText}>

          {busqueda

            ? `${pacientesFiltrados.length} resultado${
                pacientesFiltrados.length === 1
                  ? ""
                  : "s"
              } encontrado${
                pacientesFiltrados.length === 1
                  ? ""
                  : "s"
              }`

            : `Mostrando ${pacientes.length} pacientes`

          }

        </div>

      )}


      {/* ============================================
          CARGANDO
      ============================================ */}

      {loading && (

        <div style={emptyBox}>

          <div style={loadingIcon}>
            ⏳
          </div>

          <p>
            Cargando pacientes...
          </p>

        </div>

      )}


      {/* ============================================
          ERROR
      ============================================ */}

      {error && (

        <div style={errorBox}>
          {error}
        </div>

      )}


      {/* ============================================
          SIN RESULTADOS
      ============================================ */}

      {!loading &&
        !error &&
        pacientesFiltrados.length === 0 && (

          <div style={emptyBox}>

            <div style={emptyIcon}>
              👤
            </div>

            <h3>

              {busqueda
                ? "No encontramos pacientes"
                : "No hay pacientes registrados"
              }

            </h3>


            <p>

              {busqueda

                ? "Intenta buscar con otro nombre o ID MirrorSoul."

                : "Los pacientes registrados aparecerán aquí."

              }

            </p>

          </div>

        )}


      {/* ============================================
          LISTA DE PACIENTES
      ============================================ */}

      {!loading &&
        !error &&
        pacientesFiltrados.length > 0 && (

          <div style={grid}>

            {pacientesFiltrados.map(
              (paciente) => {

                const sexo =
                  String(
                    paciente.sexo || ""
                  ).toUpperCase();


                const sexoTexto =
                  sexo === "F"
                    ? "Femenino"
                    : sexo === "M"
                    ? "Masculino"
                    : "No especificado";


                return (

                  <div
                    key={
                      paciente.id_paciente
                    }
                    style={card}
                  >

                    {/* =================================
                        PARTE SUPERIOR
                    ================================= */}

                    <div style={cardTop}>

                      <div style={avatar}>

                        {paciente.nombre
                          ?.charAt(0)
                          ?.toUpperCase() || "👤"}

                      </div>


                      <div style={patientInfo}>

                        <h3 style={patientName}>

                          {paciente.nombre}

                        </h3>


                        {/* =================================
                            ID MIRRORSOUL
                        ================================= */}

                        <div style={patientCode}>

                          <span>
                            🆔 ID MirrorSoul
                          </span>

                          <strong>
                            {paciente.id_mirror || "Pendiente"}
                          </strong>

                        </div>

                      </div>

                    </div>


                    {/* =================================
                        DATOS DEL PACIENTE
                    ================================= */}

                    <div style={dataBox}>

                      <div style={dataItem}>

                        <span style={dataLabel}>
                          Sexo
                        </span>

                        <strong>
                          {sexoTexto}
                        </strong>

                      </div>


                      <div style={dataItem}>

                        <span style={dataLabel}>
                          Edad
                        </span>

                        <strong>
                          {paciente.edad ?? "--"} años
                        </strong>

                      </div>

                    </div>


                    {/* =================================
                        BOTONES
                    ================================= */}

                    <div style={actions}>

                      <button
                        type="button"
                        style={btnDetails}
                        onClick={() =>
                          setPacienteSeleccionadoLocal(
                            paciente.id_paciente
                          )
                        }
                      >

                        🔎

                        <span>
                          Ver expediente
                        </span>

                      </button>


                      <button
                        type="button"
                        style={btnSelect}
                        onClick={() => {

                          setPaciente(
                            paciente
                          );


                          alert(
                            `✅ Paciente ${paciente.nombre} seleccionado para la evaluación`
                          );

                        }}
                      >

                        🧠

                        <span>
                          Seleccionar
                        </span>

                      </button>

                    </div>

                  </div>

                );

              }

            )}

          </div>

        )}


      {/* ============================================
          VOLVER
      ============================================ */}

      <button
        type="button"
        onClick={onBack}
        style={btnBack}
      >

        ⬅️ Volver al inicio

      </button>

    </div>

  );

}


// ==================================================
// 🎨 ESTILOS
// ==================================================

const container = {

  width: "100%",

  maxWidth: "1100px",

  margin: "0 auto",

  padding: "30px 25px 50px",

  fontFamily:
    "'Segoe UI', sans-serif",

  boxSizing: "border-box",

};


const header = {

  display: "flex",

  justifyContent: "space-between",

  alignItems: "center",

  marginBottom: "25px",

};


const smallTitle = {

  fontSize: "12px",

  fontWeight: "800",

  letterSpacing: "3px",

  color: "#5C6BC0",

  marginBottom: "5px",

};


const title = {

  margin: 0,

  fontSize: "30px",

  fontWeight: "800",

  color: "#173B70",

};


const subtitle = {

  margin:
    "7px 0 0",

  color: "#718096",

  fontSize: "14px",

};


const counter = {

  display: "flex",

  flexDirection: "column",

  alignItems: "center",

  justifyContent: "center",

  minWidth: "90px",

  padding: "15px",

  borderRadius: "18px",

  background:
    "rgba(255,255,255,0.85)",

  boxShadow:
    "0 8px 25px rgba(30,70,120,0.08)",

};


const counterNumber = {

  fontSize: "25px",

  color: "#173B70",

};


const counterLabel = {

  fontSize: "12px",

  color: "#718096",

};


const searchContainer = {

  position: "relative",

  display: "flex",

  alignItems: "center",

  background: "#fff",

  borderRadius: "18px",

  padding: "4px 15px",

  boxShadow:
    "0 8px 25px rgba(30,70,120,0.10)",

  border:
    "1px solid #E2E8F0",

  marginBottom: "12px",

};


const searchIcon = {

  fontSize: "20px",

  marginRight: "10px",

};


const searchInput = {

  width: "100%",

  border: "none",

  outline: "none",

  background: "transparent",

  padding: "14px 5px",

  fontSize: "15px",

  color: "#2D3748",

};


const clearButton = {

  border: "none",

  background: "#EDF2F7",

  color: "#718096",

  width: "30px",

  height: "30px",

  borderRadius: "50%",

  cursor: "pointer",

};


const resultsText = {

  fontSize: "13px",

  color: "#718096",

  margin:
    "10px 4px 18px",

};


const grid = {

  display: "grid",

  gridTemplateColumns:
    "repeat(auto-fit, minmax(320px, 1fr))",

  gap: "20px",

};


const card = {

  background:
    "rgba(255,255,255,0.96)",

  borderRadius: "22px",

  padding: "22px",

  boxShadow:
    "0 10px 30px rgba(30,70,120,0.10)",

  border:
    "1px solid rgba(226,232,240,0.8)",

  transition:
    "transform 0.2s ease, box-shadow 0.2s ease",

};


const cardTop = {

  display: "flex",

  alignItems: "center",

  gap: "15px",

  marginBottom: "18px",

};


const avatar = {

  width: "58px",

  height: "58px",

  borderRadius: "18px",

  background:
    "linear-gradient(135deg, #5C6BC0, #42A5F5)",

  color: "#fff",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  fontSize: "24px",

  fontWeight: "800",

  flexShrink: 0,

};


const patientInfo = {

  minWidth: 0,

};


const patientName = {

  margin: 0,

  color: "#173B70",

  fontSize: "19px",

  fontWeight: "750",

};


const patientCode = {

  marginTop: "7px",

  display: "flex",

  flexDirection: "column",

  gap: "2px",

  fontSize: "11px",

  color: "#718096",

};


const patientCodeStrong = {

  color: "#3949AB",

  fontSize: "13px",

  fontWeight: "800",

};


const dataBox = {

  display: "grid",

  gridTemplateColumns:
    "1fr 1fr",

  gap: "10px",

  marginBottom: "18px",

};


const dataItem = {

  display: "flex",

  flexDirection: "column",

  gap: "3px",

  background: "#F7FAFC",

  borderRadius: "12px",

  padding: "10px 12px",

};


const dataLabel = {

  fontSize: "11px",

  color: "#A0AEC0",

  textTransform: "uppercase",

  fontWeight: "700",

};


const actions = {

  display: "grid",

  gridTemplateColumns:
    "1fr 1fr",

  gap: "10px",

};


const btnDetails = {

  border: "none",

  borderRadius: "13px",

  padding: "11px",

  background: "#E3F2FD",

  color: "#1565C0",

  cursor: "pointer",

  fontWeight: "700",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  gap: "6px",

};


const btnSelect = {

  border: "none",

  borderRadius: "13px",

  padding: "11px",

  background:
    "linear-gradient(135deg, #5C6BC0, #3949AB)",

  color: "#fff",

  cursor: "pointer",

  fontWeight: "700",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  gap: "6px",

};


const emptyBox = {

  background:
    "rgba(255,255,255,0.8)",

  borderRadius: "22px",

  padding: "50px 20px",

  textAlign: "center",

  color: "#718096",

};


const emptyIcon = {

  fontSize: "45px",

  marginBottom: "10px",

};


const loadingIcon = {

  fontSize: "35px",

};


const errorBox = {

  background: "#FFF5F5",

  color: "#C53030",

  borderRadius: "15px",

  padding: "18px",

  textAlign: "center",

};


const btnBack = {

  marginTop: "30px",

  padding: "12px 22px",

  borderRadius: "15px",

  border: "none",

  background: "#E3F2FD",

  color: "#1565C0",

  cursor: "pointer",

  fontWeight: "700",

};