
// src/views/RegisterAdmin.jsx

import React, { useState } from "react";
import {
  getToken,
  getCurrentUser,
} from "../services/AuthService";

const RegisterAdmin = ({ onBack }) => {

  // =====================================================
  // USUARIO ACTUAL
  // =====================================================

  const user = getCurrentUser();

  // =====================================================
  // ESTADOS
  // =====================================================

  const [form, setForm] = useState({
    nombre: "",
    correo: "",
    password: "",
    area: "rh",
  });

  const [loading, setLoading] = useState(false);
  const [mensaje, setMensaje] = useState("");
  const [error, setError] = useState("");

  // =====================================================
  // CAMBIO DE INPUT
  // =====================================================

  const handleChange = (e) => {

    const { name, value } = e.target;

    setForm((prev) => ({
      ...prev,
      [name]: value,
    }));

    setMensaje("");
    setError("");
  };

  // =====================================================
  // REGISTRAR ADMINISTRADOR
  // =====================================================

  const handleSubmit = async (e) => {

    e.preventDefault();

    setMensaje("");
    setError("");

    // ---------------------------------------------------
    // VALIDAR QUE SEA ADMIN MASTER
    // ---------------------------------------------------

    if (
      user?.role !== 1 ||
      user?.tipo_admin !== "master"
    ) {

      setError(
        "No tienes permisos para registrar administradores."
      );

      return;
    }

    // ---------------------------------------------------
    // VALIDACIONES
    // ---------------------------------------------------

    if (
      !form.nombre.trim() ||
      !form.correo.trim() ||
      !form.password.trim()
    ) {

      setError(
        "Completa todos los campos obligatorios."
      );

      return;
    }

    // ---------------------------------------------------
    // VALIDAR ÁREA
    // ---------------------------------------------------

    const areasPermitidas = [
      "rh",
      "educacion",
      "clinica",
    ];

    if (!areasPermitidas.includes(form.area)) {

      setError(
        "Selecciona un área válida."
      );

      return;
    }

    // ---------------------------------------------------
    // TOKEN
    // ---------------------------------------------------

    const token =
      user?.token || getToken();

    if (!token) {

      setError(
        "No se encontró una sesión válida. Vuelve a iniciar sesión."
      );

      return;
    }

    try {

      setLoading(true);

      // -------------------------------------------------
      // PETICIÓN AL BACKEND
      // -------------------------------------------------

      const response = await fetch(
        "https://reflejoyalma.com/api/admin/register",
        {
          method: "POST",

          headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${token}`,
          },

          body: JSON.stringify({
            nombre: form.nombre.trim(),
            correo: form.correo.trim(),
            password: form.password,
            area: form.area,
          }),
        }
      );

      // -------------------------------------------------
      // RESPUESTA
      // -------------------------------------------------

      const data = await response.json();

      // -------------------------------------------------
      // ERROR DEL SERVIDOR
      // -------------------------------------------------

      if (!response.ok) {

        throw new Error(
          data?.message ||
          "No fue posible registrar al administrador."
        );
      }

      // -------------------------------------------------
      // ÉXITO
      // -------------------------------------------------

      setMensaje(
        data?.message ||
        "Administrador registrado correctamente."
      );

      // -------------------------------------------------
      // LIMPIAR FORMULARIO
      // -------------------------------------------------

      setForm({
        nombre: "",
        correo: "",
        password: "",
        area: "rh",
      });

    } catch (err) {

      console.error(
        "Error registrando administrador:",
        err
      );

      setError(
        err.message ||
        "Ocurrió un error al registrar al administrador."
      );

    } finally {

      setLoading(false);

    }

  };

  // =====================================================
  // VERIFICACIÓN VISUAL DE PERMISOS
  // =====================================================

  if (
    user?.role !== 1 ||
    user?.tipo_admin !== "master"
  ) {

    return (

      <div style={page}>

        <div style={card}>

          <div style={iconError}>
            🔒
          </div>

          <h2 style={title}>
            Acceso restringido
          </h2>

          <p style={description}>
            Esta sección solamente está disponible
            para el Administrador Master.
          </p>

          <button
            style={backButton}
            onClick={onBack}
          >
            ← Volver
          </button>

        </div>

      </div>

    );
  }

  // =====================================================
  // INTERFAZ
  // =====================================================

  return (

    <div style={page}>

      <div style={container}>

        {/* =================================================
            ENCABEZADO
        ================================================= */}

        <div style={header}>

          <button
            style={backButton}
            onClick={onBack}
          >
            ← Volver
          </button>

          <div>

            <h1 style={title}>
              Registrar administrador
            </h1>

            <p style={description}>
              Crea un nuevo administrador normal para
              gestionar un área de MirrorSoul.
            </p>

          </div>

        </div>


        {/* =================================================
            INFORMACIÓN DEL MASTER
        ================================================= */}

        <div style={masterBadge}>

          <div style={masterIcon}>
            👑
          </div>

          <div>

            <strong>
              Administrador Master
            </strong>

            <span>
              {user?.nombre || "Administrador"}
            </span>

          </div>

        </div>


        {/* =================================================
            FORMULARIO
        ================================================= */}

        <form
          onSubmit={handleSubmit}
          style={formCard}
        >

          {/* =================================================
              ENCABEZADO DEL FORMULARIO
          ================================================= */}

          <div style={formHeader}>

            <div style={formIcon}>
              👤
            </div>

            <div>

              <h2 style={formTitle}>
                Datos del administrador
              </h2>

              <p style={formSubtitle}>
                Ingresa la información del nuevo administrador.
              </p>

            </div>

          </div>


          {/* =================================================
              NOMBRE
          ================================================= */}

          <div style={field}>

            <label style={label}>
              Nombre completo
            </label>

            <input
              type="text"
              name="nombre"
              value={form.nombre}
              onChange={handleChange}
              placeholder="Ej. Administrador de RH"
              style={input}
              autoComplete="name"
              disabled={loading}
            />

          </div>


          {/* =================================================
              CORREO
          ================================================= */}

          <div style={field}>

            <label style={label}>
              Correo electrónico
            </label>

            <input
              type="email"
              name="correo"
              value={form.correo}
              onChange={handleChange}
              placeholder="Ej. administrador@empresa.com"
              style={input}
              autoComplete="email"
              disabled={loading}
            />

          </div>


          {/* =================================================
              CONTRASEÑA
          ================================================= */}

          <div style={field}>

            <label style={label}>
              Contraseña
            </label>

            <input
              type="password"
              name="password"
              value={form.password}
              onChange={handleChange}
              placeholder="Crea una contraseña segura"
              style={input}
              autoComplete="new-password"
              disabled={loading}
            />

          </div>


          {/* =================================================
              ÁREA
          ================================================= */}

          <div style={field}>

            <label style={label}>
              Área
            </label>

            <select
              name="area"
              value={form.area}
              onChange={handleChange}
              style={input}
              disabled={loading}
            >

              <option value="rh">
                👥 Recursos Humanos
              </option>

              <option value="educacion">
                🎓 Educación
              </option>

              <option value="clinica">
                🩺 Clínica
              </option>

            </select>

          </div>


          {/* =================================================
              DESCRIPCIÓN DEL ÁREA
          ================================================= */}

          <div style={areaInfo}>

            {form.area === "rh" && (
              <>
                <span style={areaInfoIcon}>
                  👥
                </span>

                <div>
                  <strong>
                    Recursos Humanos
                  </strong>

                  <p>
                    Administración y gestión de evaluaciones
                    dentro del entorno empresarial.
                  </p>
                </div>
              </>
            )}

            {form.area === "educacion" && (
              <>
                <span style={areaInfoIcon}>
                  🎓
                </span>

                <div>
                  <strong>
                    Educación
                  </strong>

                  <p>
                    Gestión de evaluaciones y seguimiento
                    dentro del entorno educativo.
                  </p>
                </div>
              </>
            )}

            {form.area === "clinica" && (
              <>
                <span style={areaInfoIcon}>
                  🩺
                </span>

                <div>
                  <strong>
                    Clínica
                  </strong>

                  <p>
                    Gestión del entorno clínico y
                    seguimiento profesional de pacientes.
                  </p>
                </div>
              </>
            )}

          </div>


          {/* =================================================
              MENSAJE ÉXITO
          ================================================= */}

          {mensaje && (

            <div style={successMessage}>
              ✅ {mensaje}
            </div>

          )}


          {/* =================================================
              MENSAJE ERROR
          ================================================= */}

          {error && (

            <div style={errorMessage}>
              ❌ {error}
            </div>

          )}


          {/* =================================================
              BOTONES
          ================================================= */}

          <div style={actions}>

            <button
              type="button"
              style={cancelButton}
              onClick={onBack}
              disabled={loading}
            >
              Cancelar
            </button>

            <button
              type="submit"
              style={{
                ...submitButton,
                opacity: loading ? 0.7 : 1,
                cursor: loading
                  ? "not-allowed"
                  : "pointer",
              }}
              disabled={loading}
            >

              {loading
                ? "Registrando..."
                : "➕ Registrar administrador"}

            </button>

          </div>

        </form>


        {/* =================================================
            NOTA
        ================================================= */}

        <div style={note}>

          <span style={noteIcon}>
            🔐
          </span>

          <div>

            <strong>
              Importante
            </strong>

            <p>
              El administrador creado será un administrador
              <strong> normal</strong>. No tendrá permisos
              de Administrador Master.
            </p>

          </div>

        </div>

      </div>

    </div>

  );

};


// =========================================================
// ESTILOS
// =========================================================

const page = {

  minHeight: "calc(100vh - 86px)",

  padding: "45px 7%",

  boxSizing: "border-box",

  background: "#F4F9FE",

  fontFamily:
    "'Segoe UI', Arial, sans-serif",

  color: "#172B4D",

};


const container = {

  maxWidth: "900px",

  margin: "0 auto",

};


const card = {

  maxWidth: "600px",

  margin: "80px auto",

  padding: "45px",

  background: "#FFFFFF",

  borderRadius: "20px",

  textAlign: "center",

  boxShadow:
    "0 10px 30px rgba(40,80,140,0.09)",

  border:
    "1px solid #E4EAF2",

};


const header = {

  display: "flex",

  alignItems: "flex-start",

  gap: "22px",

  marginBottom: "25px",

};


const title = {

  margin: "0",

  fontSize: "30px",

  fontWeight: "800",

  color: "#172B4D",

};


const description = {

  margin: "8px 0 0",

  fontSize: "15px",

  lineHeight: "1.6",

  color: "#64748B",

};


const backButton = {

  border: "none",

  background: "#FFFFFF",

  color: "#2167D5",

  padding: "11px 18px",

  borderRadius: "10px",

  fontSize: "14px",

  fontWeight: "700",

  cursor: "pointer",

  boxShadow:
    "0 5px 15px rgba(40,80,140,0.08)",

  whiteSpace: "nowrap",

};


const masterBadge = {

  display: "flex",

  alignItems: "center",

  gap: "14px",

  padding: "15px 20px",

  marginBottom: "20px",

  background: "#EEF5FF",

  border: "1px solid #D8E7FF",

  borderRadius: "14px",

};


const masterIcon = {

  width: "45px",

  height: "45px",

  borderRadius: "50%",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  background: "#FFFFFF",

  fontSize: "22px",

};


const formCard = {

  background: "#FFFFFF",

  borderRadius: "20px",

  padding: "35px",

  boxShadow:
    "0 10px 30px rgba(40,80,140,0.09)",

  border:
    "1px solid #E4EAF2",

};


const formHeader = {

  display: "flex",

  alignItems: "center",

  gap: "15px",

  marginBottom: "30px",

};


const formIcon = {

  width: "52px",

  height: "52px",

  borderRadius: "14px",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  background: "#F3E9FF",

  fontSize: "24px",

};


const formTitle = {

  margin: "0",

  fontSize: "20px",

  fontWeight: "800",

  color: "#172B4D",

};


const formSubtitle = {

  margin: "4px 0 0",

  fontSize: "13px",

  color: "#718096",

};


const field = {

  marginBottom: "20px",

};


const label = {

  display: "block",

  marginBottom: "8px",

  fontSize: "14px",

  fontWeight: "700",

  color: "#334155",

};


const input = {

  width: "100%",

  boxSizing: "border-box",

  padding: "13px 15px",

  borderRadius: "10px",

  border:
    "1px solid #D8E1EC",

  background: "#FAFCFF",

  color: "#1E293B",

  fontSize: "15px",

  outline: "none",

};


const areaInfo = {

  display: "flex",

  alignItems: "flex-start",

  gap: "12px",

  padding: "13px 15px",

  marginTop: "-7px",

  marginBottom: "20px",

  borderRadius: "10px",

  background: "#F7FAFF",

  border:
    "1px solid #E2EAF5",

  color: "#526579",

  fontSize: "13px",

  lineHeight: "1.5",

};


const areaInfoIcon = {

  fontSize: "22px",

  lineHeight: "1",

};


const areaInfoStrong = {

  color: "#334155",

};


const successMessage = {

  padding: "13px 15px",

  marginBottom: "18px",

  borderRadius: "10px",

  background: "#ECF9EF",

  border:
    "1px solid #C8EBCF",

  color: "#27833A",

  fontSize: "14px",

  fontWeight: "600",

};


const errorMessage = {

  padding: "13px 15px",

  marginBottom: "18px",

  borderRadius: "10px",

  background: "#FFF1F1",

  border:
    "1px solid #FFD4D4",

  color: "#C53030",

  fontSize: "14px",

  fontWeight: "600",

};


const actions = {

  display: "flex",

  justifyContent: "flex-end",

  gap: "12px",

  marginTop: "10px",

};


const cancelButton = {

  padding: "13px 22px",

  borderRadius: "10px",

  border:
    "1px solid #D8E1EC",

  background: "#FFFFFF",

  color: "#64748B",

  fontWeight: "700",

  cursor: "pointer",

};


const submitButton = {

  padding: "13px 24px",

  borderRadius: "10px",

  border: "none",

  background:
    "linear-gradient(135deg, #7B3FE4, #2167D5)",

  color: "#FFFFFF",

  fontWeight: "700",

  fontSize: "14px",

  cursor: "pointer",

  boxShadow:
    "0 7px 18px rgba(70,80,180,0.22)",

};


const note = {

  display: "flex",

  alignItems: "flex-start",

  gap: "12px",

  marginTop: "20px",

  padding: "16px 20px",

  background: "#FFFDF3",

  border:
    "1px solid #F3E7AE",

  borderRadius: "12px",

  color: "#6B5E20",

  fontSize: "13px",

  lineHeight: "1.5",

};


const noteIcon = {

  fontSize: "20px",

};


const iconError = {

  fontSize: "48px",

  marginBottom: "15px",

};


// =========================================================
// EXPORT
// =========================================================

export default RegisterAdmin;
