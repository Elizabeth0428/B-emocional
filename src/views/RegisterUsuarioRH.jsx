// src/views/RegisterUsuarioRH.jsx

import React, { useState } from "react";
import { getCurrentUser } from "../services/AuthService";

const API_URL =
  import.meta.env.VITE_API_URL ||
  "https://reflejoyalma.com";

const RegisterUsuarioRH = ({ onBack }) => {

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


  // =====================================================
  // CAMBIAR FORMULARIO
  // =====================================================

  const handleChange = (e) => {

    const { name, value } = e.target;

    setForm((prev) => ({
      ...prev,
      [name]: value,
    }));

  };


  // =====================================================
  // REGISTRAR USUARIO RH
  // =====================================================

  const handleSubmit = async (e) => {

    e.preventDefault();

    setMessage("");
    setLoading(true);

    try {

      const token =
        localStorage.getItem("token");


      // =================================================
      // IMPORTANTE:
      // La ruta correcta es usuario-rh
      // SIN "s"
      // =================================================

      const response = await fetch(
        `${API_URL}/api/usuario-rh`,
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
            rol: "rh",
            area: "rh",
          }),
        }
      );


      const data =
        await response.json();


      if (!response.ok) {

        throw new Error(
          data.message ||
          "Error al registrar usuario RH"
        );

      }


      setMessage(
        "✅ Usuario RH registrado correctamente"
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

      console.error(
        "Error al registrar usuario RH:",
        error
      );

      setMessage(
        `❌ ${error.message}`
      );


    } finally {

      setLoading(false);

    }

  };


  // =====================================================
  // RETURN
  // =====================================================

  return (

    <div style={container}>

      {/* =================================================
          HEADER
      ================================================= */}

      <div style={header}>

        <button
          type="button"
          onClick={onBack}
          style={backButton}
        >
          ← Volver
        </button>


        <div>

          <h2 style={title}>
            Registrar usuario RH
          </h2>

          <p style={subtitle}>
            Crea un nuevo usuario para el área
            de Recursos Humanos.
          </p>

        </div>

      </div>


      {/* =================================================
          ADMINISTRADOR
      ================================================= */}

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
            Área: Recursos Humanos
          </small>

        </div>

      </div>


      {/* =================================================
          FORMULARIO
      ================================================= */}

      <form
        onSubmit={handleSubmit}
        style={form}
      >

        <h3 style={sectionTitle}>
          👤 Datos del usuario
        </h3>


        {/* NOMBRE */}

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


        {/* CORREO */}

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


        {/* PASSWORD */}

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


        {/* PUESTO */}

        <label style={label}>
          Puesto / área
        </label>

        <input
          type="text"
          name="puesto"
          value={form.puesto}
          onChange={handleChange}
          placeholder="Ej. Recursos Humanos"
          style={input}
        />


        {/* TELEFONO */}

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


        {/* DIRECCION */}

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


        {/* INFORMACION */}

        <div style={infoBox}>
          👥 Este usuario será registrado en el
          área de <strong>Recursos Humanos</strong>.
        </div>


        {/* MENSAJE */}

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

              border:
                message.startsWith("✅")
                  ? "1px solid #B7E4C1"
                  : "1px solid #F0B8B8",
            }}
          >
            {message}
          </div>

        )}


        {/* BOTON */}

        <button
          type="submit"
          disabled={loading}
          style={{
            ...submitButton,

            opacity:
              loading
                ? 0.7
                : 1,

            cursor:
              loading
                ? "not-allowed"
                : "pointer",
          }}
        >

          {loading
            ? "Registrando..."
            : "Registrar usuario RH"}

        </button>

      </form>

    </div>

  );

};


// =====================================================
// ESTILOS
// =====================================================

const container = {
  maxWidth: "850px",
  margin: "0 auto",
  padding: "40px",
  fontFamily:
    "'Segoe UI', Arial, sans-serif",
  color: "#1A2B4B",
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
  fontSize: "30px",
  color: "#172B4D",
};


const subtitle = {
  margin: "6px 0 0",
  color: "#718096",
};


const adminBox = {
  display: "flex",
  alignItems: "center",
  gap: "16px",
  background: "#F4F8FF",
  border: "1px solid #DCE7F5",
  borderRadius: "16px",
  padding: "18px",
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
  display: "block",
  color: "#2167D5",
};


const adminName = {
  fontWeight: "700",
  marginTop: "3px",
};


const adminArea = {
  display: "block",
  marginTop: "4px",
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
  marginTop: 0,
  color: "#2167D5",
};


const label = {
  display: "block",
  marginTop: "16px",
  marginBottom: "7px",
  fontWeight: "700",
  fontSize: "14px",
};


const input = {
  width: "100%",
  boxSizing: "border-box",
  padding: "13px",
  borderRadius: "10px",
  border: "1px solid #D9E2EF",
  fontSize: "15px",
  outline: "none",
};


const infoBox = {
  marginTop: "22px",
  padding: "14px",
  borderRadius: "10px",
  background: "#EEF7FF",
  color: "#345",
  fontSize: "14px",
};


const messageBox = {
  marginTop: "18px",
  padding: "13px",
  borderRadius: "10px",
  fontWeight: "600",
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
};


export default RegisterUsuarioRH;