// src/views/ReporteClinico.jsx
import React from "react";

const ReporteClinico = ({ paciente, resultados }) => {
  return (
    <div style={container}>
      <h2 style={title}>📄 Reporte Clínico</h2>

      {/* Datos del paciente */}
      <section style={section}>
        <h3 style={subtitle}>👤 Datos del paciente</h3>
        <p><strong>Nombre:</strong> {paciente?.nombre || "Sin nombre"}</p>
        <p><strong>Edad:</strong> {paciente?.edad || "No registrada"}</p>
        <p><strong>Sexo:</strong> {paciente?.sexo || "No especificado"}</p>
        <p><strong>Correo:</strong> {paciente?.correo || "No registrado"}</p>
        <p><strong>Teléfono:</strong> {paciente?.telefono || "No registrado"}</p>
        <p><strong>Dirección:</strong> {paciente?.direccion || "No registrada"}</p>
      </section>

      {/* Emoción inicial */}
      <section style={section}>
        <h3 style={subtitle}>💡 Emoción inicial detectada</h3>
        <p style={highlight}>{resultados.emocion || "No detectada"}</p>
      </section>

      {/* Quiz visual */}
      <section style={section}>
        <h3 style={subtitle}>🖼️ Resultados del Quiz Visual</h3>
        {resultados.quiz?.length > 0 ? (
          <ul style={{ paddingLeft: 20 }}>
            {resultados.quiz.map((r, i) => (
              <li key={i}>
                <strong>{r.pregunta}:</strong> {r.respuesta}
              </li>
            ))}
          </ul>
        ) : (
          <p>No se registraron respuestas.</p>
        )}
      </section>

      {/* Pruebas clínicas */}
      <section style={section}>
        <h3 style={subtitle}>🧪 Pruebas clínicas</h3>
        {resultados.tests && resultados.tests.length > 0 ? (
          resultados.tests.map((t, i) => (
            <div key={i} style={testCard}>
              <p><strong>{t.nombre}</strong> — {t.puntaje_total} puntos</p>
              <p><em>{t.interpretacion}</em></p>
              <p style={{ fontSize: "13px", color: "#777" }}>
                📅 {new Date(t.fecha_sesion).toLocaleDateString()}
              </p>
            </div>
          ))
        ) : (
          <p>No se han aplicado pruebas clínicas.</p>
        )}
      </section>

      {/* Reporte preliminar IA */}
      <section style={section}>
        <h3 style={subtitle}>🤖 Reporte preliminar (IA)</h3>
        <p style={{ fontStyle: "italic", color: "#555", whiteSpace: "pre-line" }}>
          {resultados.ia || "Sin análisis preliminar"}
        </p>
      </section>

      <p style={footer}>
        ⚠️ Este reporte es preliminar. La interpretación final corresponde al
        psicólogo responsable.
      </p>
    </div>
  );
};

// === Estilos reutilizables ===
const container = {
  maxWidth: 850,
  margin: "40px auto",
  padding: "30px",
  backgroundColor: "#FAFAFA",
  borderRadius: "16px",
  boxShadow: "0 6px 16px rgba(0,0,0,0.15)",
  fontFamily: "Segoe UI, sans-serif",
  color: "#333",
};

const title = {
  color: "#3F51B5",
  marginBottom: 20,
  borderBottom: "2px solid #E0E0E0",
  paddingBottom: 8,
};

const section = {
  marginBottom: 24,
  padding: "16px",
  backgroundColor: "#fff",
  borderRadius: "10px",
  boxShadow: "0 4px 10px rgba(0,0,0,0.08)",
};

const subtitle = {
  marginBottom: 10,
  fontSize: "18px",
  color: "#1E88E5",
  borderBottom: "1px solid #E3F2FD",
  paddingBottom: 4,
};

const highlight = {
  fontSize: "18px",
  fontWeight: "600",
  color: "#0277BD",
};

const testCard = {
  marginBottom: "12px",
  padding: "10px",
  background: "#f9f9f9",
  borderRadius: "8px",
  border: "1px solid #eee",
};

const footer = {
  marginTop: 30,
  fontSize: "13px",
  color: "#777",
  textAlign: "center",
};

export default ReporteClinico;
