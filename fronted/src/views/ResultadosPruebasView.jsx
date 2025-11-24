// src/views/ResultadosPruebasView.jsx
import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { getToken } from "../services/AuthService";

const API = import.meta.env.VITE_API_URL; // ⭐ PRODUCCIÓN

export default function ResultadosPruebasView() {
  const { idPaciente } = useParams();
  const navigate = useNavigate();
  const [resultados, setResultados] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchResultados = async () => {
      try {
        const res = await fetch(
          `${API}/api/pacientes/${idPaciente}/reportes-completos`,
          { headers: { Authorization: `Bearer ${getToken()}` } }
        );
        if (res.ok) {
          const data = await res.json();
          setResultados(data.resultados || []);
        }
      } catch (err) {
        console.error("❌ Error al obtener resultados:", err);
      } finally {
        setLoading(false);
      }
    };
    fetchResultados();
  }, [idPaciente]);

  if (loading) return <p style={{ textAlign: "center" }}>⏳ Cargando resultados...</p>;

  return (
    <div style={page}>
      <div style={container}>
        <h2 style={titulo}>🧪 Resultados de Pruebas</h2>

        {resultados.length > 0 ? (
          <table style={tabla}>
            <thead>
              <tr>
                <th style={th}>📋 Prueba</th>
                <th style={th}>📖 Interpretación</th>
                <th style={th}>⭐ Puntaje</th>
                <th style={th}>📅 Fecha</th>
              </tr>
            </thead>
            <tbody>
              {resultados.map((r, index) => (
                <tr key={r.id_resultado} style={index % 2 === 0 ? filaPar : filaImpar}>
                  <td style={td}>{r.prueba}</td>
                  <td style={td}>{r.interpretacion}</td>
                  <td style={{ ...td, fontWeight: "bold" }}>{r.puntaje_total}</td>
                  <td style={td}>
                    {r.fecha ? new Date(r.fecha).toLocaleDateString("es-MX") : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p style={{ textAlign: "center" }}>⚠️ No hay resultados de pruebas</p>
        )}

        <button style={btnBack} onClick={() => navigate(-1)}>
          ⬅ Volver
        </button>
      </div>
    </div>
  );
}

// === Estilos ===
const page = {
  minHeight: "100vh",
  background: "linear-gradient(180deg, #e3f2fd, #bbdefb)",
  display: "flex",
  justifyContent: "center",
  alignItems: "center",
  padding: "20px",
};

const container = {
  padding: "20px",
  maxWidth: "900px",
  width: "100%",
  background: "#ffffff",
  borderRadius: "16px",
  boxShadow: "0 6px 16px rgba(0,0,0,0.1)",
};

const titulo = {
  textAlign: "center",
  marginBottom: "20px",
  fontSize: "22px",
  color: "#0D47A1",
  fontWeight: "bold",
};

const tabla = {
  width: "100%",
  borderCollapse: "collapse",
  marginBottom: "20px",
};

const th = {
  padding: "12px",
  textAlign: "center",
  fontWeight: "bold",
  color: "#0D47A1",
  fontSize: "15px",
  borderBottom: "2px solid #1976D2",
};

const td = {
  padding: "10px",
  textAlign: "center",
  color: "#333",
  fontSize: "14px",
};

const filaPar = { backgroundColor: "#E3F2FD" };
const filaImpar = { backgroundColor: "#ffffff" };

const btnBack = {
  display: "block",
  margin: "20px auto 0",
  padding: "10px 16px",
  borderRadius: "8px",
  border: "none",
  backgroundColor: "#64B5F6",
  color: "#0D47A1",
  fontWeight: "bold",
  cursor: "pointer",
};
