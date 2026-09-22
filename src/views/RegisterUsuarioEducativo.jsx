// src/views/RegisterUsuarioEducativo.jsx

import React, { useState } from "react";
import { getCurrentUser } from "../services/AuthService";

const API_URL =
  import.meta.env.VITE_API_URL ||
  "https://reflejoyalma.com";

const RegisterUsuarioEducativo = ({ onBack }) => {

  const user = getCurrentUser();

  const [form, setForm] = useState({
    nombre: "",
    correo: "",
    password: "",
    puesto: "",
    telefono: "",
    direccion: "",
  });

  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");

  const handleChange = (e) => {

    setForm({
      ...form,
      [e.target.name]: e.target.value,
    });

  };

  const handleSubmit = async (e) => {

    e.preventDefault();

    setLoading(true);
    setMessage("");

    try {

      const token =
        localStorage.getItem("token");

      const response =
        await fetch(
          `${API_URL}/api/usuarios-educativo`,
          {
            method: "POST",

            headers: {
              "Content-Type":
                "application/json",

              Authorization:
                `Bearer ${token}`,
            },

            body: JSON.stringify({
              ...form,
              rol: "educativo",
              area: "educativo",
            }),
          }
        );

      const data =
        await response.json();

      if (!response.ok) {

        throw new Error(
          data.message ||
          "Error al registrar usuario educativo"
        );

      }

      setMessage(
        "✅ Usuario educativo registrado correctamente"
      );

      setForm({
        nombre: "",
        correo: "",
        password: "",
        puesto: "",
        telefono: "",
        direccion: "",
      });

    } catch (error) {

      console.error(error);

      setMessage(
        `❌ ${error.message}`
      );

    } finally {

      setLoading(false);

    }

  };

  return (

    <div style={container}>

      <div style={header}>

        <button
          onClick={onBack}
          style={backButton}
        >
          ← Volver
        </button>

        <div>

          <h2 style={title}>
            🎓 Registrar usuario educativo
          </h2>

          <p style={subtitle}>
            Crea un nuevo usuario para el
            área educativa.
          </p>

        </div>

      </div>


      <div style={adminBox}>

        <div style={adminIcon}>
          🛡️
        </div>

        <div>

          <strong style={adminTitle}>
            Administrador
          </strong>

          <div style={adminName}>
            {user?.nombre ||
              "Administrador"}
          </div>

          <small style={adminArea}>
            Área: Educativo
          </small>

        </div>

      </div>


      <form
        onSubmit={handleSubmit}
        style={form}
      >

        <h3 style={sectionTitle}>
          👤 Datos del usuario
        </h3>


        <label style={label}>
          Nombre completo
        </label>

        <input
          type="text"
          name="nombre"
          value={form.nombre}
          onChange={handleChange}
          placeholder="Nombre completo"
          style={input}
          required
        />


        <label style={label}>
          Correo electrónico
        </label>

        <input
          type="email"
          name="correo"
          value={form.correo}
          onChange={handleChange}
          placeholder="correo@ejemplo.com"
          style={input}
          required
        />


        <label style={label}>
          Contraseña
        </label>

        <input
          type="password"
          name="password"
          value={form.password}
          onChange={handleChange}
          placeholder="Contraseña"
          style={input}
          minLength={6}
          required
        />


        <label style={label}>
          Puesto / especialidad
        </label>

        <input
          type="text"
          name="puesto"
          value={form.puesto}
          onChange={handleChange}
          placeholder="Ej. Orientación educativa"
          style={input}
        />


        <label style={label}>
          Teléfono
        </label>

        <input
          type="tel"
          name="telefono"
          value={form.telefono}
          onChange={handleChange}
          placeholder="Teléfono"
          style={input}
        />


        <label style={label}>
          Dirección
        </label>

        <input
          type="text"
          name="direccion"
          value={form.direccion}
          onChange={handleChange}
          placeholder="Dirección"
          style={input}
        />


        <div style={infoBox}>
          🎓 Este usuario será registrado en
          el área <strong>Educativa</strong>.
        </div>


        {message && (

          <div
            style={{
              ...messageBox,

              color:
                message.startsWith("✅")
                  ? "#27833A"
                  : "#C62828",

              background:
                message.startsWith("✅")
                  ? "#ECF9EF"
                  : "#FFF1F1",
            }}
          >
            {message}
          </div>

        )}


        <button
          type="submit"
          disabled={loading}
          style={submitButton}
        >
          {loading
            ? "Registrando..."
            : "Registrar usuario educativo"}
        </button>

      </form>

    </div>

  );

};

const container = {
  maxWidth: "850px",
  margin: "0 auto",
  padding: "40px",
  fontFamily:
    "'Segoe UI', Arial, sans-serif",
};

const header = {
  display: "flex",
  alignItems: "center",
  gap: "20px",
  marginBottom: "30px",
};

const backButton = {
  border: "none",
  background: "#EEF4FF",
  color: "#2167D5",
  padding: "10px 16px",
  borderRadius: "10px",
  cursor: "pointer",
  fontWeight: "700",
};

const title = {
  margin: 0,
  color: "#172B4D",
};

const subtitle = {
  margin: "6px 0 0",
  color: "#718096",
};

const adminBox = {
  display: "flex",
  gap: "16px",
  alignItems: "center",
  padding: "18px",
  background: "#F4F8FF",
  borderRadius: "16px",
  marginBottom: "25px",
};

const adminIcon = {
  width: "52px",
  height: "52px",
  borderRadius: "50%",
  background: "#E8F0FF",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "25px",
};

const adminTitle = {
  color: "#2167D5",
  display: "block",
};

const adminName = {
  fontWeight: "700",
};

const adminArea = {
  color: "#718096",
};

const form = {
  background: "#FFFFFF",
  borderRadius: "18px",
  padding: "30px",
  boxShadow:
    "0 8px 24px rgba(40,80,140,0.08)",
};

const sectionTitle = {
  color: "#2167D5",
};

const label = {
  display: "block",
  marginTop: "16px",
  marginBottom: "7px",
  fontWeight: "700",
};

const input = {
  width: "100%",
  boxSizing: "border-box",
  padding: "13px",
  borderRadius: "10px",
  border: "1px solid #D9E2EF",
  fontSize: "15px",
};

const infoBox = {
  marginTop: "22px",
  padding: "14px",
  borderRadius: "10px",
  background: "#EEF7FF",
  fontSize: "14px",
};

const messageBox = {
  marginTop: "18px",
  padding: "13px",
  borderRadius: "10px",
};

const submitButton = {
  width: "100%",
  marginTop: "25px",
  padding: "14px",
  border: "none",
  borderRadius: "11px",
  background: "#2167D5",
  color: "#FFFFFF",
  fontSize: "16px",
  fontWeight: "700",
  cursor: "pointer",
};

export default RegisterUsuarioEducativo;