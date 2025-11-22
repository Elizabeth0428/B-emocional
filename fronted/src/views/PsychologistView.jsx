// src/views/ViewPsychologists.jsx
import React, { useEffect, useState } from "react";
import { getToken } from "../services/AuthService";

const ViewPsychologists = ({ onBack }) => {
  const [psychologists, setPsychologists] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchData = async () => {
      try {
        const token = getToken();
        const res = await fetch("http://localhost:5000/api/psicologos", {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (!res.ok) {
          throw new Error("❌ No autorizado o error al obtener psicólogos");
        }

        const data = await res.json();
        setPsychologists(Array.isArray(data) ? data : []);
      } catch (err) {
        console.error("Error al obtener psicólogos:", err);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  return (
    <div style={container}>
      <h2 style={title}>👨‍⚕️ Psicólogos registrados</h2>

      {loading && <p>⏳ Cargando...</p>}
      {error && <p style={{ color: "red" }}>{error}</p>}

      {!loading && !error && psychologists.length === 0 && (
        <p style={{ color: "#666" }}>⚠️ No hay psicólogos registrados.</p>
      )}

      <ul style={list}>
        {psychologists.map((p) => (
          <li key={p.id_psicologo} style={item}>
            <strong>{p.nombre}</strong> <br />
            📧 Correo: {p.correo} <br />
            🎓 Cédula: {p.cedula_profesional} <br />
            🏥 Especialidad: {p.especialidad || "No especificada"}
          </li>
        ))}
      </ul>

      <button onClick={onBack} style={backButton}>
        ⬅️ Volver
      </button>
    </div>
  );
};

// === Estilos ===
const container = {
  maxWidth: "600px",
  margin: "40px auto",
  padding: "20px",
  background: "#fff",
  borderRadius: "12px",
  boxShadow: "0 6px 12px rgba(0,0,0,0.1)",
  textAlign: "center",
};

const title = { marginBottom: "20px", fontSize: "24px", color: "#3f51b5" };

const list = { listStyle: "none", padding: 0, margin: 0 };

const item = {
  padding: "12px",
  marginBottom: "10px",
  border: "1px solid #ddd",
  borderRadius: "8px",
  background: "#f9f9f9",
  textAlign: "left",
};

const backButton = {
  marginTop: "20px",
  padding: "10px 16px",
  background: "#5C6BC0",
  color: "white",
  border: "none",
  borderRadius: "8px",
  cursor: "pointer",
};

export default ViewPsychologists;

