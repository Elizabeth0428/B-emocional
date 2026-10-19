// src/views/RegistrarProspecto.jsx

import React, { useState } from "react";
import { getCurrentUser } from "../services/AuthService";

const API_URL =
  import.meta.env.VITE_API_URL ||
  "https://reflejoyalma.com";

const RegistrarProspecto = ({ onBack }) => {

  const user = getCurrentUser();

  const [form, setForm] = useState({
    nombre: "",
    edad: "",
    sexo: "",
    correo: "",
    telefono: "",
    puesto: "",
    direccion: "",
  });

  const [loading, setLoading] =
    useState(false);

  const [message, setMessage] =
    useState("");

  const [prospectoCreado, setProspectoCreado] =
    useState(null);


  // =====================================================
  // CAMBIAR FORMULARIO
  // =====================================================

  const handleChange = (e) => {

    const {
      name,
      value
    } = e.target;

    setForm((prev) => ({
      ...prev,
      [name]: value,
    }));

    if (message) {
      setMessage("");
    }

  };


  // =====================================================
  // VALIDACIONES FRONTEND
  // =====================================================

  const validarFormulario = () => {

    if (!String(form.nombre).trim()) {
      return "El nombre del prospecto es obligatorio";
    }

    const edadNumero =
      Number(form.edad);

    if (
      !Number.isInteger(edadNumero) ||
      edadNumero < 1 ||
      edadNumero > 120
    ) {
      return "Ingresa una edad válida";
    }

    if (
      form.sexo !== "F" &&
      form.sexo !== "M"
    ) {
      return "Selecciona el sexo del prospecto";
    }

    if (!String(form.correo).trim()) {
      return "El correo del prospecto es obligatorio";
    }

    return null;

  };


  // =====================================================
  // REGISTRAR PROSPECTO
  // =====================================================

  const handleSubmit = async (e) => {

    e.preventDefault();

    if (loading) return;

    const errorValidacion =
      validarFormulario();

    if (errorValidacion) {
      setMessage(
        `❌ ${errorValidacion}`
      );
      return;
    }

    try {

      setLoading(true);
      setMessage("");
      setProspectoCreado(null);

      const token =
        localStorage.getItem("token");

      if (!token) {
        throw new Error(
          "Tu sesión no es válida. Inicia sesión nuevamente."
        );
      }

      const response = await fetch(
        `${API_URL}/api/prospectos`,
        {
          method: "POST",

          headers: {
            "Content-Type":
              "application/json",

            Authorization:
              `Bearer ${token}`,
          },

          body: JSON.stringify({
            nombre:
              form.nombre.trim(),

            edad:
              Number(form.edad),

            sexo:
              form.sexo,

            correo:
              form.correo.trim(),

            telefono:
              form.telefono.trim(),

            puesto:
              form.puesto.trim(),

            direccion:
              form.direccion.trim(),
          }),
        }
      );

      const data =
        await response
          .json()
          .catch(() => ({}));

      if (!response.ok) {

        throw new Error(
          data.message ||
          "Error al registrar prospecto"
        );

      }

      console.log(
        "✅ Prospecto RH registrado:",
        data
      );

      setProspectoCreado(
        data.prospecto || null
      );

      setMessage(
        "✅ Prospecto registrado correctamente"
      );

      setForm({
        nombre: "",
        edad: "",
        sexo: "",
        correo: "",
        telefono: "",
        puesto: "",
        direccion: "",
      });


    } catch (error) {

      console.error(
        "❌ Error al registrar prospecto:",
        error
      );

      setMessage(
        `❌ ${
          error.message ||
          "No se pudo registrar el prospecto"
        }`
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
        style={formStyle}
      >

        <h3 style={sectionTitle}>
          👤 Datos del prospecto
        </h3>


        {/* NOMBRE */}

        <div style={field}>

          <label style={label}>
            Nombre completo *
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


        {/* EDAD + SEXO */}

        <div style={twoColumns}>

          <div style={field}>

            <label style={label}>
              Edad *
            </label>

            <input
              type="number"
              name="edad"
              min="1"
              max="120"
              value={form.edad}
              onChange={handleChange}
              placeholder="Ej. 28"
              style={input}
              required
            />

          </div>


          <div style={field}>

            <label style={label}>
              Sexo *
            </label>

            <select
              name="sexo"
              value={form.sexo}
              onChange={handleChange}
              style={input}
              required
            >

              <option value="">
                Selecciona una opción
              </option>

              <option value="F">
                Femenino
              </option>

              <option value="M">
                Masculino
              </option>

            </select>

          </div>

        </div>


        {/* CORREO */}

        <div style={field}>

          <label style={label}>
            Correo electrónico *
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
            placeholder="Ej. Analista administrativo"
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

          <strong>
            🆔 ID MirrorSoul
          </strong>

          <div style={infoText}>
            El sistema generará automáticamente el
            identificador MirrorSoul del prospecto al
            registrarlo.
          </div>

          <div style={infoText}>
            Después podrás abrir su expediente y
            continuar con pruebas, entrevistas,
            observaciones y el proceso de selección.
          </div>

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


        {/* RESULTADO DEL REGISTRO */}

        {prospectoCreado && (

          <div style={createdCard}>

            <div style={createdIcon}>
              ✅
            </div>

            <div style={createdInfo}>

              <div style={createdTitle}>
                Prospecto creado
              </div>

              <div style={createdName}>
                {prospectoCreado.nombre}
              </div>

              <div style={mirrorBox}>

                <span style={mirrorLabel}>
                  ID MirrorSoul
                </span>

                <strong style={mirrorValue}>
                  {prospectoCreado.id_mirror}
                </strong>

              </div>

              <div style={createdDetails}>

                {prospectoCreado.edad && (
                  <span>
                    🎂 {prospectoCreado.edad} años
                  </span>
                )}

                {prospectoCreado.sexo && (
                  <span>
                    {prospectoCreado.sexo === "F"
                      ? "👩 Femenino"
                      : "👨 Masculino"}
                  </span>
                )}

                {prospectoCreado.puesto && (
                  <span>
                    💼 {prospectoCreado.puesto}
                  </span>
                )}

              </div>

            </div>

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


const formStyle = {
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


const twoColumns = {
  display: "grid",
  gridTemplateColumns:
    "repeat(2, minmax(0, 1fr))",
  gap: "16px",
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
  fontFamily: "inherit",
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


const infoText = {
  marginTop: "5px",
  color: "#64748B",
  fontSize: "12px",
};


const messageBox = {
  marginTop: "18px",
  padding: "13px",
  borderRadius: "10px",
  fontWeight: "600",
};


const createdCard = {
  marginTop: "18px",
  padding: "16px",
  borderRadius: "14px",
  background: "#F0FFF4",
  border: "1px solid #B7E4C7",
  display: "flex",
  alignItems: "flex-start",
  gap: "12px",
};


const createdIcon = {
  width: "38px",
  height: "38px",
  minWidth: "38px",
  borderRadius: "50%",
  background: "#D9F7E5",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "17px",
};


const createdInfo = {
  flex: 1,
};


const createdTitle = {
  fontSize: "11px",
  fontWeight: "800",
  color: "#27833A",
  textTransform: "uppercase",
  letterSpacing: "0.5px",
};


const createdName = {
  marginTop: "3px",
  fontSize: "16px",
  fontWeight: "800",
  color: "#1A2B4B",
};


const mirrorBox = {
  marginTop: "9px",
  display: "flex",
  alignItems: "center",
  gap: "8px",
  flexWrap: "wrap",
};


const mirrorLabel = {
  fontSize: "10px",
  color: "#718096",
  fontWeight: "700",
};


const mirrorValue = {
  padding: "4px 8px",
  borderRadius: "7px",
  background: "#FFFFFF",
  border: "1px solid #B7E4C7",
  color: "#237A57",
  fontSize: "12px",
};


const createdDetails = {
  marginTop: "9px",
  display: "flex",
  flexWrap: "wrap",
  gap: "12px",
  color: "#64748B",
  fontSize: "11px",
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