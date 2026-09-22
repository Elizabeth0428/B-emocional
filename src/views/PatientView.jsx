// src/components/PatientView.jsx
import React, { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { FaUserInjured } from "react-icons/fa";
import { getToken } from "../services/AuthService";

const PatientView = ({ idPaciente }) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchData = async () => {
      try {
        const token = getToken();

        const res = await fetch(
          `https://reflejoyalma.com/api/pacientes/${idPaciente}/reportes-completos`,
          { headers: { Authorization: `Bearer ${token}` } }
        );
        if (!res.ok) throw new Error("Error al obtener la información");

        const json = await res.json();
        setData(json);
      } catch (err) {
        setError("❌ Error al cargar la información del paciente");
      } finally {
        setLoading(false);
      }
    };

    if (idPaciente) fetchData();
  }, [idPaciente]);

  if (loading) {
    return <p style={{ textAlign: "center", marginTop: 40 }}>⏳ Cargando...</p>;
  }

  if (error) {
    return <p style={{ color: "red", textAlign: "center" }}>{error}</p>;
  }

  if (!data) return <p>⚠️ No se encontró información del paciente</p>;

  // 🔹 Ajustamos nombres correctos según backend
  const { paciente, historialInicial, resultados, seguimiento, sesiones } = data;

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6 }}
      style={container}
    >
      <div style={card}>
        <FaUserInjured size={60} color="#1565C0" style={{ marginBottom: 15 }} />
        <h2 style={title}>Perfil del Paciente</h2>

        {paciente && (
          <>
            <p><b>👤 Nombre:</b> {paciente.nombre}</p>
            <p><b>📅 Edad:</b> {paciente.edad}</p>
            <p><b>⚧ Sexo:</b> {paciente.sexo}</p>
            <p><b>📧 Correo:</b> {paciente.correo}</p>
            <p><b>📱 Teléfono:</b> {paciente.telefono}</p>
            <p><b>📍 Dirección:</b> {paciente.direccion}</p>
          </>
        )}

        {/* Historial inicial */}
        <h3 style={subtitle}>📖 Historial clínico inicial</h3>
        {historialInicial ? (
          <>
            <p><b>Diagnóstico:</b> {historialInicial.diagnostico_inicial || "No registrado"}</p>
            <p><b>Tratamiento:</b> {historialInicial.tratamiento_inicial || "No registrado"}</p>
          </>
        ) : (
          <p>⚠️ Aún no se ha registrado historial inicial</p>
        )}

        {/* Resultados de pruebas */}
        <h3 style={subtitle}>🧪 Resultados de pruebas</h3>
        {resultados && resultados.length > 0 ? (
          <ul style={{ textAlign: "left" }}>
            {resultados.map((r, i) => (
              <li key={i}>
                <b>{r.prueba}</b> → {r.interpretacion} ({r.puntaje_total} puntos)
                <span style={{ color: "gray" }}> [{r.fecha}]</span>
              </li>
            ))}
          </ul>
        ) : (
          <p>⚠️ No hay reportes de pruebas</p>
        )}

        {/* Seguimiento */}
        <h3 style={subtitle}>📝 Seguimiento</h3>
        {seguimiento && seguimiento.length > 0 ? (
          <ul style={{ textAlign: "left" }}>
            {seguimiento.map((s, i) => (
              <li key={i}>
                📅 {new Date(s.fecha).toLocaleDateString("es-MX")} → {s.diagnostico}
              </li>
            ))}
          </ul>
        ) : (
          <p>⚠️ Sin seguimiento clínico</p>
        )}

        {/* Sesiones */}
        <h3 style={subtitle}>🎥 Sesiones</h3>
        {sesiones && sesiones.length > 0 ? (
          <ul style={{ textAlign: "left" }}>
            {sesiones.map((s, i) => (
              <li key={i}>
                📅 {new Date(s.fecha).toLocaleDateString("es-MX")} → {s.notas || "Sin notas"}
                {s.videos && s.videos.length > 0 && (
                  <ul>
                    {s.videos.map((v, j) => (
                      <li key={j}>
                        <a href={`https://reflejoyalma.com${v}`} target="_blank" rel="noreferrer">
                          🎬 Ver grabación
                        </a>
                      </li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        ) : (
          <p>⚠️ No hay sesiones registradas</p>
        )}
      </div>
    </motion.div>
  );
};

// src/components/PatientView.jsx
import React, { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { FaUserInjured } from "react-icons/fa";
import { getToken } from "../services/AuthService";

const PatientView = ({ idPaciente }) => {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const fetchData = async () => {
      try {
        const token = getToken();

        const res = await fetch(
          `https://reflejoyalma.com/api/pacientes/${idPaciente}/reportes-completos`,
          { headers: { Authorization: `Bearer ${token}` } }
        );
        if (!res.ok) throw new Error("Error al obtener la información");

        const json = await res.json();
        console.log("👉 JSON recibido:", json); // 👈 Log general
        setData(json);
      } catch (err) {
        setError("❌ Error al cargar la información del paciente");
      } finally {
        setLoading(false);
      }
    };

    if (idPaciente) fetchData();
  }, [idPaciente]);

  if (loading) {
    return <p style={{ textAlign: "center", marginTop: 40 }}>⏳ Cargando...</p>;
  }

  if (error) {
    return <p style={{ color: "red", textAlign: "center" }}>{error}</p>;
  }

  if (!data) return <p>⚠️ No se encontró información del paciente</p>;

  // 🔹 Ajustamos nombres correctos según backend
  const { paciente, historialInicial, resultados, seguimiento, sesiones } = data;

  console.log("👉 Resultados desde backend:", resultados); // 👈 Log específico

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6 }}
      style={container}
    >
      <div style={card}>
        <FaUserInjured size={60} color="#1565C0" style={{ marginBottom: 15 }} />
        <h2 style={title}>Perfil del Paciente</h2>

        {paciente && (
          <>
            <p><b>👤 Nombre:</b> {paciente.nombre}</p>
            <p><b>📅 Edad:</b> {paciente.edad}</p>
            <p><b>⚧ Sexo:</b> {paciente.sexo}</p>
            <p><b>📧 Correo:</b> {paciente.correo}</p>
            <p><b>📱 Teléfono:</b> {paciente.telefono}</p>
            <p><b>📍 Dirección:</b> {paciente.direccion}</p>
          </>
        )}

        {/* Historial inicial */}
        <h3 style={subtitle}>📖 Historial clínico inicial</h3>
        {historialInicial ? (
          <>
            <p><b>Diagnóstico:</b> {historialInicial.diagnostico_inicial || "No registrado"}</p>
            <p><b>Tratamiento:</b> {historialInicial.tratamiento_inicial || "No registrado"}</p>
          </>
        ) : (
          <p>⚠️ Aún no se ha registrado historial inicial</p>
        )}

        {/* Resultados de pruebas */}
        <h3 style={subtitle}>🧪 Resultados de pruebas</h3>
        {resultados && resultados.length > 0 ? (
          <ul style={{ textAlign: "left" }}>
            {resultados.map((r, i) => (
              <li key={i}>
                <b>{r.prueba}</b> → {r.interpretacion} ({r.puntaje_total} puntos)
                <span style={{ color: "gray" }}> [{r.fecha}]</span>
              </li>
            ))}
          </ul>
        ) : (
          <p>⚠️ No hay reportes de pruebas</p>
        )}

        {/* Seguimiento */}
        <h3 style={subtitle}>📝 Seguimiento</h3>
        {seguimiento && seguimiento.length > 0 ? (
          <ul style={{ textAlign: "left" }}>
            {seguimiento.map((s, i) => (
              <li key={i}>
                📅 {new Date(s.fecha).toLocaleDateString("es-MX")} → {s.diagnostico}
              </li>
            ))}
          </ul>
        ) : (
          <p>⚠️ Sin seguimiento clínico</p>
        )}

        {/* Sesiones */}
        <h3 style={subtitle}>🎥 Sesiones</h3>
        {sesiones && sesiones.length > 0 ? (
          <ul style={{ textAlign: "left" }}>
            {sesiones.map((s, i) => (
              <li key={i}>
                📅 {new Date(s.fecha).toLocaleDateString("es-MX")} → {s.notas || "Sin notas"}
                {s.videos && s.videos.length > 0 && (
                  <ul>
                    {s.videos.map((v, j) => (
                      <li key={j}>
                        <a href={`https://reflejoyalma.com${v}`} target="_blank" rel="noreferrer">
                          🎬 Ver grabación
                        </a>
                      </li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        ) : (
          <p>⚠️ No hay sesiones registradas</p>
        )}
      </div>
    </motion.div>
  );
};

// 🎨 Estilos
const container = {
  background: "linear-gradient(135deg, #E3F2FD, #FFFFFF)",
  width: "100%",
  minHeight: "100vh",
  display: "flex",
  justifyContent: "center",
  alignItems: "flex-start",
  padding: 20,
};

const card = {
  backgroundColor: "#fff",
  padding: "40px 30px",
  borderRadius: "20px",
  boxShadow: "0 8px 20px rgba(0,0,0,0.15)",
  textAlign: "center",
  maxWidth: "800px",
  width: "100%",
};

const title = {
  fontSize: "28px",
  fontWeight: "700",
  color: "#0D47A1",
  marginBottom: "15px",
};

const subtitle = {
  fontSize: "20px",
  fontWeight: "600",
  marginTop: "25px",
  color: "#1565C0",
};

export default PatientView;
