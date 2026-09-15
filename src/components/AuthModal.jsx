// src/components/Registro.jsx
import React, { useState } from "react";
import { register } from "../services/AuthService"; // ahora usa tu backend (MySQL)

const Registro = ({ onRegisterSuccess, onBack }) => {
  const [form, setForm] = useState({
    cedula_profesional: "",
    nombre: "",
    correo: "",
    password: "",
  });
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleRegister = async () => {
    setError("");
    setLoading(true);

    // Validar
    if (!form.cedula_profesional || !form.nombre || !form.correo || !form.password) {
      setError("⚠️ Todos los campos son obligatorios.");
      setLoading(false);
      return;
    }

    try {
      const data = await register(form); // 👈 ahora va al backend
      if (onRegisterSuccess) onRegisterSuccess(data.user);

      alert("✅ Psicólogo registrado correctamente");
    } catch (err) {
      console.error("❌ Error en registro:", err);
      setError(err.message || "Hubo un error al registrarse.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        maxWidth: 420,
        margin: "60px auto",
        padding: 30,
        backgroundColor: "#fff",
        borderRadius: 16,
        boxShadow: "0 6px 16px rgba(0,0,0,0.15)",
        textAlign: "center",
        fontFamily: "Segoe UI, sans-serif",
      }}
    >
      <h2 style={{ marginBottom: 20, color: "#0D47A1" }}>📝 Registro de Psicólogo</h2>

      <input
        type="text"
        name="cedula_profesional"
        placeholder="Cédula profesional"
        value={form.cedula_profesional}
        onChange={handleChange}
        style={inputStyle}
      />

      <input
        type="text"
        name="nombre"
        placeholder="Nombre completo"
        value={form.nombre}
        onChange={handleChange}
        style={inputStyle}
      />

      <input
        type="email"
        name="correo"
        placeholder="Correo electrónico"
        value={form.correo}
        onChange={handleChange}
        style={inputStyle}
      />

      <input
        type="password"
        name="password"
        placeholder="Contraseña"
        value={form.password}
        onChange={handleChange}
        style={inputStyle}
      />

      {error && <p style={{ color: "red", marginBottom: 10 }}>{error}</p>}

      <button
        onClick={handleRegister}
        disabled={loading}
        style={{
          ...buttonStyle,
          backgroundColor: loading ? "#90CAF9" : "#1976D2",
          cursor: loading ? "not-allowed" : "pointer",
        }}
      >
        {loading ? "Registrando..." : "Registrarme"}
      </button>

      {onBack && (
        <button
          onClick={onBack}
          style={{
            ...buttonStyle,
            marginTop: 12,
            backgroundColor: "#B0BEC5",
          }}
        >
          ⬅️ Volver
        </button>
      )}
    </div>
  );
};

// === Estilos reutilizables ===
const inputStyle = {
  width: "100%",
  padding: "12px",
  marginBottom: "12px",
  borderRadius: "8px",
  border: "1px solid #ccc",
  fontSize: "14px",
};

const buttonStyle = {
  width: "100%",
  padding: "12px",
  border: "none",
  borderRadius: "8px",
  color: "white",
  fontWeight: "600",
  fontSize: "15px",
  transition: "0.3s",
};

export default Registro;
