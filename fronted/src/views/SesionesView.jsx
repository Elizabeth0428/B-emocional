// ✅ src/views/SesionesView.jsx
import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { getToken } from "../services/AuthService";

export default function SesionesView() {
  const { idPaciente } = useParams();
  const navigate = useNavigate();
  const [sesiones, setSesiones] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchSesiones = async () => {
      try {
        const res = await fetch(`http://localhost:5000/api/sesiones/paciente/${idPaciente}`, {
          headers: { Authorization: `Bearer ${getToken()}` },
        });
        if (!res.ok) throw new Error("Error al obtener sesiones");
        const data = await res.json();

        // 🔹 Obtener videos de cada sesión
        const sesionesConVideos = await Promise.all(
          data.map(async (s) => {
            const resVid = await fetch(
              `http://localhost:5000/api/sesiones/${s.id_sesion}/videos`,
              { headers: { Authorization: `Bearer ${getToken()}` } }
            );
            const videos = resVid.ok ? await resVid.json() : [];
            return { ...s, videos };
          })
        );

        setSesiones(sesionesConVideos);
      } catch (err) {
        console.error("❌ Error:", err);
      } finally {
        setLoading(false);
      }
    };

    fetchSesiones();
  }, [idPaciente]);

  if (loading) return <p style={{ textAlign: "center" }}>⏳ Cargando sesiones...</p>;

  return (
    <div style={page}>
      <div style={container}>
        <h2 style={titulo}>📅 Sesiones</h2>

        {sesiones.length > 0 ? (
          <div style={card}>
            <ul style={list}>
              {sesiones.map((s) => (
                <li key={s.id_sesion} style={item}>
                  <b>📅 Fecha:</b> {new Date(s.fecha).toLocaleString("es-MX")} <br />
                  <b>📝 Notas:</b> {s.notas || "Sin notas"}

                  {/* 📹 Videos de esta sesión */}
                  <div style={{ marginTop: "10px", paddingLeft: "10px" }}>
                    <b>🎥 Videos:</b>
                    {s.videos && s.videos.length > 0 ? (
                      s.videos.map((v) => (
                        <div key={v.id_video} style={{ marginTop: "5px" }}>
                          <video
                            src={`http://localhost:5000${v.ruta_video}`}
                            controls
                            style={{ width: "250px", borderRadius: "8px" }}
                          />
                        </div>
                      ))
                    ) : (
                      <p style={{ color: "#555", fontStyle: "italic" }}>
                        🎞 No hay videos en esta sesión.
                      </p>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </div>
        ) : (
          <p style={{ textAlign: "center" }}>⚠️ No hay sesiones registradas.</p>
        )}

        <button style={btnBack} onClick={() => navigate(-1)}>
          ⬅ Volver
        </button>
      </div>
    </div>
  );
}

// 🎨 Estilos (los mismos que ya tenías)
const page = { minHeight: "100vh", background: "linear-gradient(180deg, #e3f2fd, #bbdefb)", display: "flex", justifyContent: "center", alignItems: "center", padding: "20px" };
const container = { padding: "20px", maxWidth: "800px", width: "100%", background: "#ffffff", borderRadius: "16px", boxShadow: "0 6px 16px rgba(0,0,0,0.1)" };
const titulo = { textAlign: "center", marginBottom: "20px", fontSize: "22px", color: "#0D47A1", fontWeight: "bold" };
const card = { background: "#f9f9f9", padding: "15px", borderRadius: "10px", boxShadow: "0 2px 6px rgba(0,0,0,0.1)", marginBottom: "20px" };
const list = { listStyle: "none", padding: 0, margin: 0 };
const item = { background: "#86c2edff", marginBottom: "10px", padding: "12px", borderRadius: "8px", boxShadow: "0 1px 4px rgba(0,0,0,0.1)" };
const btnBack = { display: "block", margin: "0 auto", marginTop: "15px", padding: "10px 16px", borderRadius: "8px", border: "none", backgroundColor: "#64B5F6", color: "#0D47A1", fontWeight: "bold", cursor: "pointer" };
