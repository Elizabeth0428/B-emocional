// src/components/Pacientes.jsx
import { useEffect, useState } from "react";
import axios from "axios";
import PacienteDetalle from "./PacienteDetalle.jsx";
import { usePatient } from "./PatientContext.jsx";
import { getToken } from "../services/AuthService"; // 👈 obtener token guardado

// ⭐ API PRODUCCIÓN
const API = import.meta.env.VITE_API_URL;

export default function Pacientes({ onBack }) {
  const [pacientes, setPacientes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [pacienteSeleccionadoLocal, setPacienteSeleccionadoLocal] = useState(null);
  const [error, setError] = useState("");

  const { setPaciente } = usePatient();

  // 🔹 Cargar pacientes del backend
  useEffect(() => {
    fetchPacientes();
  }, []);

  const fetchPacientes = async () => {
    try {
      const token = getToken();
      

      if (!token) {
        setError("⚠️ No hay sesión activa. Inicia sesión nuevamente.");
        setLoading(false);
        return;
      }

      const res = await axios.get(`${API}/api/pacientes`, {
        headers: {
          Authorization: `Bearer ${token}`,
          "Content-Type": "application/json",
        },
      });

      if (Array.isArray(res.data)) {
        setPacientes(res.data);
      } else if (res.data.data) {
        setPacientes(res.data.data);
      } else {
        setPacientes([]);
      }
    } catch (err) {
      console.error("❌ Error al obtener pacientes:", err);

      if (err.response?.status === 401) {
        setError("⚠️ Sesión expirada o token inválido. Vuelve a iniciar sesión.");
      } else {
        setError("❌ No se pudieron cargar los pacientes.");
      }
    } finally {
      setLoading(false);
    }
  };

  // 🔴 Eliminar paciente
  const handleEliminarPaciente = async (idPaciente) => {
    if (!window.confirm("⚠️ ¿Seguro que deseas eliminar este paciente? Esta acción no se puede deshacer.")) {
      return;
    }

    try {

      const res = await axios.delete(`${API}/api/pacientes/${idPaciente}`, {
        headers: { Authorization: `Bearer ${getToken()}` },
      });

      if (res.status === 200) {
        alert("✅ Paciente eliminado correctamente");
        setPacientes(pacientes.filter((p) => p.id_paciente !== idPaciente));
      } else {
        alert("❌ No se pudo eliminar paciente");
      }
    } catch (err) {
      console.error("❌ Error al eliminar paciente:", err);
      alert("Error al eliminar paciente");
    }
  };

  // 👉 Si seleccionó un paciente → mostrar su detalle
  if (pacienteSeleccionadoLocal) {
    return (
      <PacienteDetalle
        idPaciente={pacienteSeleccionadoLocal}
        onBack={() => setPacienteSeleccionadoLocal(null)}
      />
    );
  }

  return (
    <div style={container}>
      <h2 style={title}>👥 Pacientes registrados</h2>

      {loading ? (
        <p>Cargando pacientes...</p>
      ) : error ? (
        <p style={{ color: "red" }}>{error}</p>
      ) : pacientes.length === 0 ? (
        <p>No hay pacientes registrados por ahora.</p>
      ) : (
        <ul style={list}>
          {pacientes.map((p, i) => (
            <li
              key={p.id_paciente}
              style={{
                ...card,
                background: colors[i % colors.length],
              }}
            >
              <div style={{ flex: 1 }}>
                <strong>{p.nombre}</strong> – {p.edad} años
                <div style={actions}>
                  {/* Botón Ver Detalles */}
                  <button
                    style={btnVer}
                    onClick={() => setPacienteSeleccionadoLocal(p.id_paciente)}
                  >
                    🔎 Ver detalles
                  </button>

                  {/* Botón Seleccionar */}
                  <button
                    style={btnSelect}
                    onClick={() => {
                      setPaciente(p);
                      alert(`✅ Paciente ${p.nombre} seleccionado para la evaluación`);
                    }}
                  >
                    🧠 Seleccionar
                  </button>

                  {/* 🔴 Botón Eliminar */}
                  <button
                    style={btnDelete}
                    onClick={() => handleEliminarPaciente(p.id_paciente)}
                  >
                    🗑️ Eliminar
                  </button>
                </div>
              </div>
            </li>
          ))}
        </ul>
      )}

      {/* Botón para volver al Dashboard */}
      <button onClick={onBack} style={btnBack}>
        ⬅️ Volver al inicio
      </button>
    </div>
  );
}

// === 🎨 Estilos ===
const container = {
  width: "100%",
  maxWidth: 600,
  margin: "30px auto",
  textAlign: "center",
  fontFamily: "'Segoe UI', sans-serif",
};

const title = {
  marginBottom: 20,
  fontSize: "22px",
  fontWeight: "700",
  color: "#0D47A1",
};

const list = {
  listStyle: "none",
  padding: 0,
  display: "flex",
  flexDirection: "column",
  gap: "16px",
};

const card = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  padding: "16px 20px",
  borderRadius: "18px",
  boxShadow: "0 6px 12px rgba(0,0,0,0.15)",
  color: "#fff",
  fontWeight: "600",
  transition: "transform 0.2s",
};

const actions = {
  marginTop: "10px",
  display: "flex",
  gap: "10px",
};

const btnVer = {
  background: "rgba(255,255,255,0.25)",
  color: "#fff",
  border: "none",
  padding: "8px 14px",
  borderRadius: "12px",
  cursor: "pointer",
  fontWeight: "600",
};

const btnSelect = {
  background: "rgba(0,0,0,0.25)",
  color: "#fff",
  border: "none",
  padding: "8px 14px",
  borderRadius: "12px",
  cursor: "pointer",
  fontWeight: "600",
};

// 🔴 Botón eliminar
const btnDelete = {
  background: "#E53935",
  color: "#fff",
  border: "none",
  padding: "8px 14px",
  borderRadius: "12px",
  cursor: "pointer",
  fontWeight: "600",
};

const btnBack = {
  marginTop: 30,
  padding: "10px 20px",
  borderRadius: "20px",
  border: "none",
  backgroundColor: "#64B5F6",
  color: "#fff",
  cursor: "pointer",
  fontWeight: "600",
};

// 🎨 Colores tipo “emociones”
const colors = ["#FF7043", "#42A5F5", "#7E57C2", "#26C6DA", "#66BB6A", "#FFA726"];
