// src/views/RegisterPsychologist.jsx

import React, { useState } from "react";
import {
  getToken,
  getCurrentUser
} from "../services/AuthService";


const RegisterPsychologist = ({ onBack }) => {

  const user =
    getCurrentUser();


  const esMaster =
    user?.role === 1 &&
    user?.tipo_admin === "master";


  const areaAdministrador =
    user?.area
      ? String(user.area)
          .trim()
          .toLowerCase()
      : null;


  const puedeRegistrar =
    esMaster ||
    areaAdministrador === "clinica";


  const [form, setForm] = useState({
    cedula_profesional: "",
    nombre: "",
    especialidad: "",
    telefono: "",
    direccion: "",
    fecha_nacimiento: "",
    id_organizacion: ""
  });


  const [message, setMessage] =
    useState("");

  const [loading, setLoading] =
    useState(false);

  const [credenciales, setCredenciales] =
    useState(null);


  const handleChange = e => {

    const {
      name,
      value
    } = e.target;


    setForm(prev => ({
      ...prev,
      [name]: value
    }));

  };


  const handleSubmit = async e => {

    e.preventDefault();

    setMessage("");
    setCredenciales(null);


    if (
      !form.nombre.trim()
    ) {

      setMessage(
        "❌ El nombre es obligatorio."
      );

      return;

    }


    if (
      !form.cedula_profesional.trim()
    ) {

      setMessage(
        "❌ La cédula profesional es obligatoria."
      );

      return;

    }


    if (
      esMaster &&
      !form.id_organizacion
    ) {

      setMessage(
        "❌ El Master debe indicar la organización clínica."
      );

      return;

    }


    try {

      setLoading(true);


      const token =
        getToken();


      if (
        !token
      ) {

        throw new Error(
          "No hay una sesión válida de administrador."
        );

      }


      const datos = {

        rol:
          "psicologo",

        area:
          "clinica",

        nombre:
          form.nombre.trim(),

        cedula_profesional:
          form.cedula_profesional.trim(),

        especialidad:
          form.especialidad.trim() || null,

        telefono:
          form.telefono.trim() || null,

        direccion:
          form.direccion.trim() || null,

        fecha_nacimiento:
          form.fecha_nacimiento || null,

        id_organizacion:
          esMaster
            ? Number(
                form.id_organizacion
              )
            : undefined

      };


      const API =
        import.meta.env.VITE_API_URL ||
        `${import.meta.env.VITE_API_URL || window.location.origin}`;


      const response =
        await fetch(
          `${API}/api/psicologos/register`,
          {

            method:
              "POST",

            headers: {

              "Content-Type":
                "application/json",

              Authorization:
                `Bearer ${token}`

            },

            body:
              JSON.stringify(
                datos
              )

          }
        );


      const data =
        await response
          .json()
          .catch(
            () => ({})
          );


      if (
        !response.ok
      ) {

        throw new Error(
          data?.message ||
          "Error al registrar psicólogo."
        );

      }


      setMessage(
        `✅ ${
          data.message ||
          "Psicólogo registrado correctamente."
        }`
      );


      setCredenciales(
        data.credenciales ||
        null
      );


      setForm({
        cedula_profesional: "",
        nombre: "",
        especialidad: "",
        telefono: "",
        direccion: "",
        fecha_nacimiento: "",
        id_organizacion: ""
      });


    } catch (
      err
    ) {

      console.error(
        "❌ Error al registrar psicólogo:",
        err
      );


      setMessage(
        `❌ ${err.message}`
      );


    } finally {

      setLoading(false);

    }

  };


  if (
    !puedeRegistrar
  ) {

    return (

      <div style={container}>

        <div style={deniedBox}>

          <h3>
            Acceso no disponible
          </h3>

          <p>
            Solo un administrador de Clínica puede registrar psicólogos.
          </p>

          <button
            type="button"
            style={backButtonBottom}
            onClick={onBack}
          >
            ← Volver
          </button>

        </div>

      </div>

    );

  }


  return (

    <div style={container}>

      <div style={header}>

        <button
          type="button"
          style={backButton}
          onClick={onBack}
          disabled={loading}
        >
          ← Volver
        </button>


        <div>

          <h2 style={title}>
            Registrar psicólogo
          </h2>

          <p style={subtitle}>
            Registra un nuevo profesional para el módulo clínico.
          </p>

        </div>

      </div>


      <div style={adminInfo}>

        <div style={adminIcon}>
          {esMaster
            ? "👑"
            : "🛡️"}
        </div>


        <div>

          <strong style={adminName}>
            {esMaster
              ? "Administrador Master"
              : "Administrador Clínica"}
          </strong>

          <span style={adminUserName}>
            {user?.nombre ||
              "Administrador"}
          </span>

          <small style={adminArea}>
            Área: Clínica
          </small>

        </div>

      </div>


      <form
        onSubmit={handleSubmit}
        style={formStyle}
      >

        <h3 style={sectionTitle}>
          🧠 Datos del psicólogo
        </h3>


        {esMaster && (

          <>

            <label style={label}>
              ID de organización clínica
            </label>

            <input
              type="number"
              min="1"
              name="id_organizacion"
              placeholder="Ej. 1"
              value={
                form.id_organizacion
              }
              onChange={handleChange}
              style={input}
              required
            />

          </>

        )}


        <label style={label}>
          Cédula profesional
        </label>

        <input
          type="text"
          name="cedula_profesional"
          placeholder="Ej. 12345678"
          value={
            form.cedula_profesional
          }
          onChange={handleChange}
          style={input}
          required
        />


        <label style={label}>
          Nombre completo
        </label>

        <input
          type="text"
          name="nombre"
          placeholder="Nombre completo"
          value={form.nombre}
          onChange={handleChange}
          style={input}
          required
        />


        <label style={label}>
          Especialidad
        </label>

        <input
          type="text"
          name="especialidad"
          placeholder="Ej. Psicología Clínica"
          value={
            form.especialidad
          }
          onChange={handleChange}
          style={input}
        />


        <label style={label}>
          Teléfono
        </label>

        <input
          type="tel"
          name="telefono"
          placeholder="Teléfono"
          value={form.telefono}
          onChange={handleChange}
          style={input}
        />


        <label style={label}>
          Dirección
        </label>

        <input
          type="text"
          name="direccion"
          placeholder="Dirección"
          value={form.direccion}
          onChange={handleChange}
          style={input}
        />


        <label style={label}>
          Fecha de nacimiento
        </label>

        <input
          type="date"
          name="fecha_nacimiento"
          value={
            form.fecha_nacimiento
          }
          onChange={handleChange}
          style={input}
        />


        <div style={infoBox}>

          🧠 MirrorSoul generará automáticamente
          la matrícula del psicólogo y una contraseña
          temporal. El profesional deberá cambiarla
          en su primer inicio de sesión.

        </div>


        {credenciales && (

          <div style={credentialsBox}>

            <div style={credentialsTitle}>
              🔐 Credenciales generadas
            </div>

            <div style={credentialRow}>

              <span>
                Matrícula
              </span>

              <strong>
                {
                  credenciales.matricula
                }
              </strong>

            </div>

            <div style={credentialRow}>

              <span>
                Contraseña temporal
              </span>

              <strong>
                {
                  credenciales.password_temporal
                }
              </strong>

            </div>

            <div style={credentialsNotice}>
              Entrega estas credenciales al psicólogo.
              En su primer acceso deberá crear una nueva contraseña.
            </div>

          </div>

        )}


        {message && (

          <div
            style={{
              ...messageStyle,

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
                  ? "1px solid #C8EBCF"
                  : "1px solid #FFD4D4"
            }}
          >
            {message}
          </div>

        )}


        <button
          type="submit"
          style={{
            ...button,

            opacity:
              loading
                ? 0.7
                : 1
          }}
          disabled={loading}
        >
          {loading
            ? "⏳ Registrando..."
            : "➕ Registrar psicólogo"}
        </button>


        <button
          type="button"
          style={backButtonBottom}
          onClick={onBack}
          disabled={loading}
        >
          ← Volver
        </button>

      </form>

    </div>

  );

};


// ==================================================
// ESTILOS
// ==================================================

const container = {
  maxWidth: "650px",
  margin: "45px auto",
  padding: "35px",
  background: "#FFFFFF",
  borderRadius: "20px",
  boxShadow:
    "0 10px 30px rgba(40,80,140,0.10)",
  fontFamily:
    "'Segoe UI', Arial, sans-serif",
  color: "#172B4D"
};


const header = {
  display: "flex",
  alignItems: "flex-start",
  gap: "18px",
  marginBottom: "22px"
};


const title = {
  margin: 0,
  color: "#172B4D",
  fontSize: "28px",
  fontWeight: "800"
};


const subtitle = {
  margin: "7px 0 0",
  color: "#64748B",
  lineHeight: 1.5
};


const adminInfo = {
  display: "flex",
  alignItems: "center",
  gap: "13px",
  padding: "14px 18px",
  marginBottom: "22px",
  background: "#EEF5FF",
  border: "1px solid #D8E7FF",
  borderRadius: "13px"
};


const adminIcon = {
  width: "45px",
  height: "45px",
  borderRadius: "50%",
  background: "#FFFFFF",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "22px"
};


const adminName = {
  display: "block",
  color: "#172B4D"
};


const adminUserName = {
  display: "block",
  marginTop: "2px",
  color: "#475569"
};


const adminArea = {
  display: "block",
  marginTop: "3px",
  color: "#64748B"
};


const sectionTitle = {
  margin: "0 0 22px",
  fontSize: "19px",
  fontWeight: "800",
  color: "#172B4D"
};


const formStyle = {
  display: "flex",
  flexDirection: "column",
  gap: "10px"
};


const label = {
  fontSize: "14px",
  fontWeight: "700",
  color: "#334155",
  marginTop: "5px"
};


const input = {
  width: "100%",
  boxSizing: "border-box",
  padding: "12px 13px",
  borderRadius: "9px",
  border: "1px solid #CFD8E3",
  fontSize: "14px",
  outline: "none",
  background: "#FFFFFF",
  color: "#1E293B"
};


const infoBox = {
  marginTop: "10px",
  padding: "13px 15px",
  borderRadius: "10px",
  background: "#F8FAFC",
  border: "1px solid #E2E8F0",
  color: "#64748B",
  fontSize: "13px",
  lineHeight: 1.5
};


const credentialsBox = {
  marginTop: "8px",
  padding: "18px",
  borderRadius: "14px",
  background: "#F7F5FF",
  border: "1px solid #DCCFFB"
};


const credentialsTitle = {
  fontWeight: "800",
  color: "#5B3DB4",
  marginBottom: "12px"
};


const credentialRow = {
  display: "flex",
  justifyContent: "space-between",
  gap: "20px",
  padding: "9px 0",
  borderBottom: "1px solid #E8E0FA",
  fontSize: "14px"
};


const credentialsNotice = {
  marginTop: "12px",
  color: "#6B7280",
  fontSize: "13px",
  lineHeight: 1.5
};


const messageStyle = {
  marginTop: "8px",
  padding: "12px 14px",
  borderRadius: "9px",
  fontSize: "14px",
  fontWeight: "600"
};


const button = {
  width: "100%",
  padding: "13px",
  marginTop: "12px",
  background:
    "linear-gradient(135deg, #7B3FE4, #2167D5)",
  color: "#FFFFFF",
  border: "none",
  borderRadius: "9px",
  cursor: "pointer",
  fontSize: "15px",
  fontWeight: "700"
};


const backButton = {
  border: "none",
  background: "#FFFFFF",
  color: "#2167D5",
  padding: "10px 15px",
  borderRadius: "9px",
  fontSize: "14px",
  fontWeight: "700",
  cursor: "pointer",
  boxShadow:
    "0 4px 12px rgba(40,80,140,0.08)",
  whiteSpace: "nowrap"
};


const backButtonBottom = {
  width: "100%",
  padding: "12px",
  marginTop: "5px",
  background: "#E2E8F0",
  color: "#475569",
  border: "none",
  borderRadius: "9px",
  cursor: "pointer",
  fontSize: "14px",
  fontWeight: "700"
};


const deniedBox = {
  padding: "25px",
  textAlign: "center",
  borderRadius: "15px",
  background: "#FFF7F7",
  border: "1px solid #FFD8D8"
};


export default RegisterPsychologist;
