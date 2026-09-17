// src/views/RegistrarProspecto.jsx

import React, { useState } from "react";
import { getCurrentUser } from "../services/AuthService";

const API_URL =
  import.meta.env.VITE_API_URL ||
  "http://localhost:5000";

const RegistrarProspecto = ({ onBack }) => {

  const user = getCurrentUser();

  const [form, setForm] = useState({
    nombre: "",
    correo: "",
    telefono: "",
    puesto: "",
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
  // REGISTRAR PROSPECTO
  // =====================================================

  const handleSubmit = async (e) => {

    e.preventDefault();

    setLoading(true);
    setMessage("");

    try {

      const token =
        localStorage.getItem("token");

      const response = await fetch(
        `${API_URL}/api/prospectos`,
        {
          method: "POST",

          headers: {
            "Content-Type": "application/json",

            Authorization:
              `Bearer ${token}`,
          },

          body: JSON.stringify({
            ...form,

            id_admin_padre:
              user?.id_usuario || null,
          }),
        }
      );


      const data =
        await response.json();


      if (!response.ok) {

        throw new Error(
          data.message ||
          "Error al registrar prospecto"
        );

      }


      setMessage(
        "✅ Prospecto registrado correctamente"
      );


      setForm({
        nombre: "",
        correo: "",
        telefono: "",
        puesto: "",
        direccion: "",
      });


    } catch (error) {

      console.error(
        "Error al registrar prospecto:",
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
            Registrar prospecto
          </h2>

          <p style={subtitle}>
            Registra una persona que está en proceso
            de selección.
          </p>

        </div>

      </div>


      {/* =================================================
          USUARIO RH
      ================================================= */}

      <div style={adminBox}>

        <div style={icon}>
          👔
        </div>


        <div>

          <strong style={adminTitle}>
            Recursos Humanos
          </strong>


          <div style={adminName}>
            {user?.nombre || "Usuario RH"}
          </div>


          <small style={adminArea}>
            Nuevo prospecto de selección
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
          👤 Datos del prospecto
        </h3>


        {/* NOMBRE */}

        <div style={field}>

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

        </div>


        {/* CORREO */}

        <div style={field}>

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

        </div>


        {/* TELEFONO */}

        <div style={field}>

          <label style={label}>
            Teléfono
          </label>

          <input
            type="tel"
            name="telefono"
            value={form.telefono}
            onChange={handleChange}
            placeholder="Número telefónico"
            style={input}
          />

        </div>


        {/* PUESTO */}

        <div style={field}>

          <label style={label}>
            Puesto al que aspira
          </label>

          <input
            type="text"
            name="puesto"
            value={form.puesto}
            onChange={handleChange}
            placeholder="Ej. Psicólogo clínico"
            style={input}
          />

        </div>


        {/* DIRECCION */}

        <div style={field}>

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

        </div>


        {/* INFORMACION */}

        <div style={infoBox}>

          📋 Después de registrarlo podrás consultar
          su expediente y continuar con el proceso
          de selección.

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
            : "Registrar prospecto"}

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
  whiteSpace: "nowrap",
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


const icon = {
  width: "52px",
  height: "52px",
  borderRadius: "50%",
  background: "#E8F0FF",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "25px",
  flexShrink: 0,
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
  marginBottom: "25px",
  color: "#2167D5",
};


const field = {
  marginBottom: "18px",
};


const label = {
  display: "block",
  marginBottom: "7px",
  fontWeight: "700",
  fontSize: "14px",
  color: "#344563",
};


const input = {
  width: "100%",
  boxSizing: "border-box",
  padding: "13px 14px",
  borderRadius: "10px",
  border: "1px solid #D9E2EF",
  fontSize: "15px",
  outline: "none",
  background: "#FFFFFF",
  color: "#1A2B4B",
};


const infoBox = {
  marginTop: "22px",
  padding: "14px",
  borderRadius: "10px",
  background: "#EEF7FF",
  color: "#345",
  fontSize: "14px",
  lineHeight: "1.5",
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
  cursor: "pointer",
};


export default RegistrarProspecto;