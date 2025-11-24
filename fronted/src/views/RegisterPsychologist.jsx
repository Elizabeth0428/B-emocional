// src/views/RegisterPsychologist.jsx
import React, { useState } from "react";
import { getToken } from "../services/AuthService";

const API = import.meta.env.VITE_API_URL; // ⭐ Ruta dinámica para producción

const RegisterPsychologist = ({ onBack }) => {
  const [form, setForm] = useState({
    cedula_profesional: "",
    nombre: "",
    correo: "",
    password: "",
    especialidad: "",
    telefono: "",
    direccion: "",
    fecha_nacimiento: "",
  });

  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);

  const handleChange = (e) => {
    setForm({ ...form, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage("");
    setLoading(true);

    try {
      const token = getToken();
      const res = await fetch(`${API}/api/psicologos/register`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(form),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.message || "Error al registrar psicólogo");

      setMessage("✅ Psicólogo registrado correctamente");
      setForm({
        cedula_profesional: "",
        nombre: "",
        correo: "",
        password: "",
        especialidad: "",
        telefono: "",
        direccion: "",
        fecha_nacimiento: "",
      });
    } catch (err) {
      setMessage(`❌ ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={container}>
      <h2>Registrar Psicólogo</h2>
      <form onSubmit={handleSubmit} style={formStyle}>
        <input
          type="text"
          name="cedula_profesional"
          placeholder="Cédula profesional"
          value={form.cedula_profesional}
          onChange={handleChange}
          style={input}
          required
        />
        <input
          type="text"
          name="nombre"
          placeholder="Nombre completo"
          value={form.nombre}
          onChange={handleChange}
          style={input}
          required
        />
        <input
          type="email"
          name="correo"
          placeholder="Correo electrónico"
          value={form.correo}
          onChange={handleChange}
          style={input}
          required
        />
        <input
          type="password"
          name="password"
          placeholder="Contraseña"
          value={form.password}
          onChange={handleChange}
          style={input}
          required
        />
        <input
          type="text"
          name="especialidad"
          placeholder="Especialidad (ej. Clínica, Infantil)"
          value={form.especialidad}
          onChange={handleChange}
          style={input}
        />
        <input
          type="text"
          name="telefono"
          placeholder="Teléfono"
          value={form.telefono}
          onChange={handleChange}
          style={input}
        />
        <input
          type="text"
          name="direccion"
          placeholder="Dirección"
          value={form.direccion}
          onChange={handleChange}
          style={input}
        />
        <input
          type="date"
          name="fecha_nacimiento"
          value={form.fecha_nacimiento}
          onChange={handleChange}
          style={input}
        />

        <button type="submit" style={button} disabled={loading}>
          {loading ? "⏳ Registrando..." : "Registrar"}
        </button>
        <button type="button" style={backButton} onClick={onBack}>
          ⬅️ Volver
        </button>
      </form>

      {message && (
        <p style={{ marginTop: "15px", color: message.startsWith("✅") ? "green" : "red" }}>
          {message}
        </p>
      )}
    </div>
  );
};

// 🎨 Estilos
const container = {
  maxWidth: "480px",
  margin: "60px auto",
  padding: "35px",
  background: "#fff",
  borderRadius: "16px",
  boxShadow: "0 8px 20px rgba(0,0,0,0.1)",
  fontFamily: "'Segoe UI', sans-serif",
  textAlign: "center",
};

const formStyle = { display: "flex", flexDirection: "column", gap: "14px" };
const input = { padding: "12px", borderRadius: "8px", border: "1px solid #ccc" };
const button = {
  padding: "12px",
  background: "#5C6BC0",
  color: "#fff",
  border: "none",
  borderRadius: "8px",
  cursor: "pointer",
};
const backButton = { ...button, background: "#B0BEC5" };

export default RegisterPsychologist;
