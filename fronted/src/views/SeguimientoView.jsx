// src/views/SeguimientoView.jsx
import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { getToken } from "../services/AuthService";

const API = import.meta.env.VITE_API_URL; // ⭐ PRODUCCIÓN

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

  useEffect(() => {
    const fetchSeguimiento = async () => {
      try {
        const res = await fetch(`${API}/api/seguimiento/${idPaciente}`, {
          headers: { Authorization: `Bearer ${getToken()}` },
        });
        if (res.ok) {
          const data = await res.json();
          setSeguimientos(data);
        }
      } catch (err) {
        console.error("❌ Error al obtener seguimientos:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchSeguimiento();
  }, [idPaciente]);

  const handleAdd = async () => {
    try {
      const res = await fetch(`${API}/api/seguimiento`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${getToken()}`,
        },
        body: JSON.stringify({
          ...nuevo,
          id_paciente: Number(idPaciente),
        }),
      });

      if (!res.ok) throw new Error("Error al guardar seguimiento");

      const data = await res.json();

      setSeguimientos([
        {
          ...nuevo,
          id_seguimiento: data.id_seguimiento,
          fecha: new Date(),
        },
        ...seguimientos,
      ]);

      setNuevo({
        diagnostico: "",
        tratamiento: "",
        evolucion: "",
        observaciones: "",
      });

      alert("✅ Seguimiento agregado");
    } catch (err) {
      console.error("❌ Error:", err);
      alert("❌ No se pudo guardar seguimiento");
    }
  };

  if (loading) return <p>⏳ Cargando...</p>;

  return (
    <div style={background}>
      <div style={container}>
        <h2 style={titulo}>📑 Historial de Seguimiento</h2>

        {/* ➕ Nuevo Seguimiento */}
        <div style={card}>
          <h3 style={{ color: "#3f51b5" }}>➕ Registrar nuevo seguimiento</h3>

          <textarea
            placeholder="Diagnóstico"
            value={nuevo.diagnostico}
            onChange={(e) => setNuevo({ ...nuevo, diagnostico: e.target.value })}
            style={textarea}
          />

          <textarea
            placeholder="Tratamiento"
            value={nuevo.tratamiento}
            onChange={(e) => setNuevo({ ...nuevo, tratamiento: e.target.value })}
            style={textarea}
          />

          <textarea
            placeholder="Evolución"
            value={nuevo.evolucion}
            onChange={(e) => setNuevo({ ...nuevo, evolucion: e.target.value })}
            style={textarea}
          />

          <textarea
            placeholder="Observaciones"
            value={nuevo.observaciones}
            onChange={(e) =>
              setNuevo({ ...nuevo, observaciones: e.target.value })
            }
            style={textarea}
          />

          <button style={btnSave} onClick={handleAdd}>
            💾 Guardar
          </button>
        </div>

        {/* 📋 Tabla de Seguimientos */}
        <div style={card}>
          {seguimientos.length > 0 ? (
            <table style={tabla}>
              <thead>
                <tr>
                  <th>📅 Fecha</th>
                  <th>🩺 Diagnóstico</th>
                  <th>💊 Tratamiento</th>
                  <th>📈 Evolución</th>
                  <th>📝 Observaciones</th>
                </tr>
              </thead>
              <tbody>
                {seguimientos.map((s) => (
                  <tr key={s.id_seguimiento}>
                    <td>{new Date(s.fecha).toLocaleDateString("es-MX")}</td>
                    <td>{s.diagnostico}</td>
                    <td>{s.tratamiento}</td>
                    <td>{s.evolucion}</td>
                    <td>{s.observaciones}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p>⚠️ No hay seguimientos registrados.</p>
          )}
        </div>

        <button style={btnBack} onClick={() => navigate(-1)}>
          ⬅ Volver
        </button>
      </div>
    </div>
  );
}

// === Estilos ===
const background = {
  minHeight: "100vh",
  background: "linear-gradient(135deg, hsla(203, 94%, 80%, 1.00), #aadcfbff)",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  padding: "20px",
};

const container = {
  width: "100%",
  maxWidth: "1000px",
  background: "#ffffffff",
  borderRadius: "15px",
  boxShadow: "0 6px 20px rgba(0,0,0,0.15)",
  padding: "25px",
};

const titulo = {
  textAlign: "center",
  marginBottom: "20px",
  color: "#1c65d1ff",
  fontSize: "24px",
  fontWeight: "bold",
};

const card = {
  background: "#a1efffff",
  padding: "15px",
  borderRadius: "10px",
  boxShadow: "0 2px 6px rgba(0,0,0,0.1)",
  marginBottom: "20px",
};

const textarea = {
  width: "100%",
  marginBottom: "8px",
  padding: "10px",
  borderRadius: "6px",
  border: "1px solid #e8f1f3ff",
};

const tabla = {
  width: "100%",
  borderCollapse: "collapse",
};

const btnSave = {
  background: "#1a1ae3ff",
  color: "white",
  border: "none",
  borderRadius: "6px",
  padding: "10px 16px",
  cursor: "pointer",
  marginTop: "10px",
  fontWeight: "bold",
};

const btnBack = {
  marginTop: "20px",
  padding: "10px 16px",
  borderRadius: "8px",
  border: "none",
  backgroundColor: "#0927eaff",
  color: "#e1f0f5ff",
  cursor: "pointer",
};
