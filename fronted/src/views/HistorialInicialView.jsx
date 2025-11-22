// src/views/HistorialInicialView.jsx
import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { getToken } from "../services/AuthService";

export default function HistorialInicialView() {
  const { idPaciente } = useParams();
  const navigate = useNavigate();
  const [historial, setHistorial] = useState(null);
  const [editMode, setEditMode] = useState(false);

  useEffect(() => {
    const fetchHistorial = async () => {
      try {
        const res = await fetch(
          `http://localhost:5000/api/historial-inicial/${idPaciente}`,
          { headers: { Authorization: `Bearer ${getToken()}` } }
        );
        if (res.ok) {
          const data = await res.json();
          console.log("📋 Historial recibido:", data);
          setHistorial(data);
        } else {
          setHistorial({});
        }
      } catch (err) {
        console.error("❌ Error al obtener historial:", err);
      }
    };
    fetchHistorial();
  }, [idPaciente]);

  const handleSave = async () => {
    try {
      const res = await fetch(
        `http://localhost:5000/api/historial-inicial/${idPaciente}`,
        {
          method: "PUT",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${getToken()}`,
          },
          body: JSON.stringify(historial),
        }
      );
      if (!res.ok) throw new Error("Error al actualizar historial");
      alert("✅ Historial actualizado");
      setEditMode(false);
    } catch (err) {
      console.error("❌ Error al guardar:", err);
      alert("❌ No se pudo actualizar el historial");
    }
  };

  if (historial === null) {
    return <p style={{ textAlign: "center", marginTop: "30px" }}>⏳ Cargando historial...</p>;
  }

  if (Object.keys(historial).length === 0) {
    return (
      <div style={container}>
        <h2>📋 Historial Clínico Inicial</h2>
        <p>⚠️ No hay historial registrado para este paciente.</p>
        <button style={btnBack} onClick={() => navigate(-1)}>⬅ Volver</button>
      </div>
    );
  }

  return (
    <div style={background}>
      <div style={container}>
        <h2 style={title}>🩺 Historial Clínico Inicial</h2>

        <table style={table}>
          <tbody>
            {Object.keys(historial).map((campo, index) =>
              campo !== "id_paciente" && campo !== "id_historial" ? (
                <tr key={campo} style={index % 2 === 0 ? rowEven : rowOdd}>
                  <td style={cellLabel}>{campo.replace(/_/g, " ")}</td>
                  <td style={cellValue}>
                    {editMode ? (
                      <textarea
                        value={historial[campo] || ""}
                        onChange={(e) =>
                          setHistorial({ ...historial, [campo]: e.target.value })
                        }
                        style={textarea}
                      />
                    ) : (
                      historial[campo] || "—"
                    )}
                  </td>
                </tr>
              ) : null
            )}
          </tbody>
        </table>

        {editMode ? (
          <div style={{ marginTop: "20px" }}>
            <button style={btnSave} onClick={handleSave}>💾 Guardar</button>
            <button style={btnCancel} onClick={() => setEditMode(false)}>Cancelar</button>
          </div>
        ) : (
          <button style={btnEdit} onClick={() => setEditMode(true)}>✏️ Editar</button>
        )}

        <button style={btnBack} onClick={() => navigate(-1)}>⬅ Volver</button>
      </div>
    </div>
  );
}

// === Estilos ===
const background = {
  minHeight: "100vh",
  background: "linear-gradient(to bottom, #a1c4fd, #c2e9fb)", // Fondo azul degradado
  padding: "30px 15px",
};

const container = {
  maxWidth: "900px",
  margin: "0 auto",
  padding: "25px",
  background: "#fff",
  borderRadius: "15px",
  boxShadow: "0 6px 20px rgba(0,0,0,0.15)",
};

const title = {
  textAlign: "center",
  fontSize: "26px",
  fontWeight: "bold",
  color: "#1976d2",
  marginBottom: "20px",
};

const table = {
  width: "100%",
  borderCollapse: "collapse",
  marginBottom: "20px",
};

const rowEven = { backgroundColor: "#f1f9ff" };
const rowOdd = { backgroundColor: "#e3f2fd" };

const cellLabel = {
  fontWeight: "bold",
  color: "#0d47a1",
  padding: "12px",
  textTransform: "capitalize",
  width: "35%",
};

const cellValue = {
  padding: "12px",
  color: "#333",
};

const textarea = {
  width: "100%",
  minHeight: "50px",
  borderRadius: "6px",
  border: "1px solid #ccc",
  padding: "8px",
};

const btnSave = { background: "#4CAF50", color: "white", border: "none", padding: "10px 16px", borderRadius: "6px", marginRight: "8px", cursor: "pointer" };
const btnCancel = { background: "#E53935", color: "white", border: "none", padding: "10px 16px", borderRadius: "6px", cursor: "pointer" };
const btnEdit = { background: "#FFC107", color: "black", border: "none", padding: "10px 16px", borderRadius: "6px", cursor: "pointer", marginTop: "10px" };
const btnBack = { marginTop: "15px", padding: "10px 16px", borderRadius: "8px", border: "none", backgroundColor: "#90CAF9", color: "#0D47A1", cursor: "pointer" };
