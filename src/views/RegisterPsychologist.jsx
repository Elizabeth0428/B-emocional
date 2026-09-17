// src/views/RegisterPsychologist.jsx

import React, { useState } from "react";
import {
  getToken,
  getCurrentUser
} from "../services/AuthService";

const RegisterPsychologist = ({ onBack }) => {

  // ==================================================
  // USUARIO ACTUAL
  // ==================================================

  const user = getCurrentUser();


  // ==================================================
  // DETERMINAR ÁREA DEL ADMINISTRADOR
  // ==================================================

  const areaAdministrador =
    user?.area
      ? String(user.area).trim().toLowerCase()
      : null;


  // ==================================================
  // DETERMINAR SI ES MASTER
  // ==================================================

  const esMaster =
    user?.role === 1 &&
    user?.tipo_admin === "master";


  // ==================================================
  // DETERMINAR ROL INICIAL
  //
  // MASTER:
  // comienza como psicólogo.
  //
  // ADMIN NORMAL:
  // comienza con el rol correspondiente
  // a su propia área.
  // ==================================================

  const obtenerRolInicial = () => {

    if (esMaster) {
      return "psicologo";
    }

    if (areaAdministrador === "rh") {
      return "rh";
    }

    if (areaAdministrador === "educativo") {
      return "educativo";
    }

    if (areaAdministrador === "independiente") {
      return "independiente";
    }

    if (areaAdministrador === "clinica") {
      return "psicologo";
    }

    return "psicologo";
  };


  // ==================================================
  // DETERMINAR ÁREA INICIAL
  // ==================================================

  const obtenerAreaInicial = () => {

    if (esMaster) {
      return "clinica";
    }

    if (areaAdministrador) {
      return areaAdministrador;
    }

    return "clinica";
  };


  // ==================================================
  // FORMULARIO
  // ==================================================

  const [form, setForm] = useState({

    rol: obtenerRolInicial(),

    cedula_profesional: "",

    nombre: "",

    correo: "",

    password: "",

    especialidad: "",

    telefono: "",

    direccion: "",

    fecha_nacimiento: "",

    area: obtenerAreaInicial(),

  });


  const [message, setMessage] = useState("");

  const [loading, setLoading] = useState(false);


  // ==================================================
  // CAMBIO DE CAMPOS
  // ==================================================

  const handleChange = (e) => {

    const {
      name,
      value
    } = e.target;


    setForm((prev) => ({

      ...prev,

      [name]: value,

    }));

  };


  // ==================================================
  // CAMBIAR ROL
  //
  // SOLAMENTE EL MASTER PUEDE HACERLO.
  // ==================================================

  const handleRolChange = (e) => {

    if (!esMaster) {
      return;
    }


    const nuevoRol = e.target.value;


    let nuevaArea = "clinica";


    // --------------------------------------------------
    // PSICÓLOGO
    // --------------------------------------------------

    if (nuevoRol === "psicologo") {

      nuevaArea = "clinica";

    }


    // --------------------------------------------------
    // RECURSOS HUMANOS
    // --------------------------------------------------

    else if (nuevoRol === "rh") {

      nuevaArea = "rh";

    }


    // --------------------------------------------------
    // EDUCATIVO
    // --------------------------------------------------

    else if (nuevoRol === "educativo") {

      nuevaArea = "educativo";

    }


    // --------------------------------------------------
    // INDEPENDIENTE
    // --------------------------------------------------

    else if (nuevoRol === "independiente") {

      nuevaArea = "independiente";

    }


    setForm((prev) => ({

      ...prev,

      rol: nuevoRol,

      area: nuevaArea,

    }));

  };


  // ==================================================
  // REGISTRAR USUARIO
  // ==================================================

  const handleSubmit = async (e) => {

    e.preventDefault();

    setMessage("");


    // ==================================================
    // VALIDACIÓN LOCAL
    // ==================================================

    if (
      !form.nombre.trim() ||
      !form.correo.trim() ||
      !form.password.trim()
    ) {

      setMessage(
        "❌ Completa los campos obligatorios."
      );

      return;

    }


    if (form.password.length < 6) {

      setMessage(
        "❌ La contraseña debe tener al menos 6 caracteres."
      );

      return;

    }


    if (!form.rol) {

      setMessage(
        "❌ Selecciona el tipo de usuario."
      );

      return;

    }


    // ==================================================
    // VALIDAR CÉDULA PARA PSICÓLOGO
    // ==================================================

    if (
      form.rol === "psicologo" &&
      !form.cedula_profesional.trim()
    ) {

      setMessage(
        "❌ La cédula profesional es obligatoria para el psicólogo."
      );

      return;

    }


    try {

      setLoading(true);


      // ==================================================
      // TOKEN
      // ==================================================

      const token = getToken();


      if (!token) {

        throw new Error(
          "No hay una sesión válida de administrador."
        );

      }


      // ==================================================
      // DATOS QUE SE ENVÍAN
      // ==================================================

      const datos = {

        rol:
          form.rol,

        nombre:
          form.nombre.trim(),

        correo:
          form.correo.trim().toLowerCase(),

        password:
          form.password,

        area:
          form.area || null,

        cedula_profesional:
          form.cedula_profesional.trim() || null,

        especialidad:
          form.especialidad.trim() || null,

        telefono:
          form.telefono.trim() || null,

        direccion:
          form.direccion.trim() || null,

        fecha_nacimiento:
          form.fecha_nacimiento || null,

      };


      console.log(
        "📤 Datos enviados al backend:",
        datos
      );


      // ==================================================
      // URL DEL BACKEND
      // ==================================================

      const API =
        import.meta.env.VITE_API_URL;


      // ==================================================
      // PETICIÓN
      // ==================================================

      const res = await fetch(
        `${API}/api/psicologos/register`,
        {

          method: "POST",

          headers: {

            "Content-Type":
              "application/json",

            Authorization:
              `Bearer ${token}`,

          },

          body:
            JSON.stringify(datos),

        }
      );


      // ==================================================
      // RESPUESTA
      // ==================================================

      const data =
        await res.json();


      if (!res.ok) {

        throw new Error(

          data?.message ||
          "Error al registrar usuario."

        );

      }


      // ==================================================
      // ÉXITO
      // ==================================================

      setMessage(

        `✅ ${
          data.message ||
          "Usuario registrado correctamente."
        }`

      );


      // ==================================================
      // LIMPIAR FORMULARIO
      //
      // IMPORTANTE:
      // después de registrar, volvemos al rol
      // correspondiente al administrador.
      // ==================================================

      setForm({

        rol:
          obtenerRolInicial(),

        cedula_profesional:
          "",

        nombre:
          "",

        correo:
          "",

        password:
          "",

        especialidad:
          "",

        telefono:
          "",

        direccion:
          "",

        fecha_nacimiento:
          "",

        area:
          obtenerAreaInicial(),

      });


    } catch (err) {

      console.error(
        "❌ Error al registrar usuario:",
        err
      );


      setMessage(
        `❌ ${err.message}`
      );


    } finally {

      setLoading(false);

    }

  };


  // ==================================================
  // DETERMINAR TIPO
  // ==================================================

  const esPsicologo =
    form.rol === "psicologo";


  const esRH =
    form.rol === "rh";


  const esEducativo =
    form.rol === "educativo";


  const esIndependiente =
    form.rol === "independiente";


  // ==================================================
  // PERMISOS
  //
  // MASTER:
  // puede crear cualquier tipo.
  //
  // ADMIN NORMAL:
  // solamente puede crear usuarios
  // de su propia área.
  // ==================================================

  const puedeCrearPsicologo =
    esMaster ||
    areaAdministrador === "clinica";


  const puedeCrearRH =
    esMaster ||
    areaAdministrador === "rh";


  const puedeCrearEducativo =
    esMaster ||
    areaAdministrador === "educativo";


  const puedeCrearIndependiente =
    esMaster ||
    areaAdministrador === "independiente";


  // ==================================================
  // INTERFAZ
  // ==================================================

  return (

    <div style={container}>

      {/* ==================================================
          ENCABEZADO
      ================================================== */}

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
            Registrar usuario
          </h2>


          <p style={subtitle}>
            Crea una nueva cuenta para trabajar
            en MirrorSoul.
          </p>

        </div>

      </div>


      {/* ==================================================
          INFORMACIÓN DEL ADMIN
      ================================================== */}

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
              : "Administrador"}

          </strong>


          <span style={adminUserName}>

            {user?.nombre ||
              "Administrador"}

          </span>


          {!esMaster &&
            areaAdministrador && (

              <small style={adminArea}>

                Área:{" "}

                {areaAdministrador === "rh"
                  ? "Recursos Humanos"
                  : areaAdministrador === "educativo"
                  ? "Educativo"
                  : areaAdministrador === "clinica"
                  ? "Clínica"
                  : "Independiente"}

              </small>

            )}


          {esMaster && (

            <small style={adminArea}>

              Acceso completo a todas las áreas

            </small>

          )}

        </div>

      </div>


      {/* ==================================================
          FORMULARIO
      ================================================== */}

      <form
        onSubmit={handleSubmit}
        style={formStyle}
      >

        <h3 style={sectionTitle}>
          👤 Datos del usuario
        </h3>


        {/* ==================================================
            ROL
        ================================================== */}

        <label style={label}>
          Tipo de usuario
        </label>


        <select
          name="rol"
          value={form.rol}
          onChange={handleRolChange}
          style={input}
          required
          disabled={!esMaster}
        >

          {puedeCrearPsicologo && (

            <option value="psicologo">
              🧠 Psicólogo
            </option>

          )}


          {puedeCrearRH && (

            <option value="rh">
              👥 Recursos Humanos
            </option>

          )}


          {puedeCrearEducativo && (

            <option value="educativo">
              🎓 Educativo
            </option>

          )}


          {puedeCrearIndependiente && (

            <option value="independiente">
              👤 Independiente
            </option>

          )}

        </select>


        {/* ==================================================
            ÁREA
        ================================================== */}

        <label style={label}>
          Área de trabajo
        </label>


        <select
          name="area"
          value={form.area}
          onChange={handleChange}
          style={{
            ...input,

            background:
              !esMaster
                ? "#F1F5F9"
                : "#FFFFFF",

            cursor:
              !esMaster
                ? "not-allowed"
                : "pointer",

          }}
          disabled={!esMaster}
        >

          <option value="clinica">
            🧠 Clínica
          </option>

          <option value="rh">
            👥 Recursos Humanos
          </option>

          <option value="educativo">
            🎓 Educativo
          </option>

          <option value="independiente">
            👤 Independiente
          </option>

        </select>


        {/* ==================================================
            CÉDULA PROFESIONAL
        ================================================== */}

        {esPsicologo && (

          <>

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

          </>

        )}


        {/* ==================================================
            NOMBRE
        ================================================== */}

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


        {/* ==================================================
            CORREO
        ================================================== */}

        <label style={label}>
          Correo electrónico
        </label>


        <input
          type="email"
          name="correo"
          placeholder="Correo electrónico"
          value={form.correo}
          onChange={handleChange}
          style={input}
          required
        />


        {/* ==================================================
            CONTRASEÑA
        ================================================== */}

        <label style={label}>
          Contraseña
        </label>


        <input
          type="password"
          name="password"
          placeholder="Contraseña"
          value={form.password}
          onChange={handleChange}
          style={input}
          required
        />


        {/* ==================================================
            ESPECIALIDAD / PUESTO
        ================================================== */}

        <label style={label}>

          {esPsicologo
            ? "Especialidad"
            : esRH
            ? "Puesto / área"
            : esEducativo
            ? "Puesto / especialidad"
            : "Especialidad"}

        </label>


        <input
          type="text"
          name="especialidad"
          placeholder={
            esPsicologo
              ? "Ej. Psicología Clínica"
              : esRH
              ? "Ej. Recursos Humanos"
              : esEducativo
              ? "Ej. Orientación educativa"
              : "Especialidad"
          }
          value={
            form.especialidad
          }
          onChange={handleChange}
          style={input}
        />


        {/* ==================================================
            TELÉFONO
        ================================================== */}

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


        {/* ==================================================
            DIRECCIÓN
        ================================================== */}

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


        {/* ==================================================
            FECHA DE NACIMIENTO
        ================================================== */}

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


        {/* ==================================================
            AVISO SEGÚN TIPO
        ================================================== */}

        <div style={infoBox}>

          {esPsicologo && (

            <>
              🧠 Este usuario será registrado como{" "}
              <strong>Psicólogo</strong> y tendrá
              acceso al módulo clínico.
            </>

          )}


          {esRH && (

            <>
              👥 Este usuario será registrado con rol{" "}
              <strong>Recursos Humanos</strong>.
            </>

          )}


          {esEducativo && (

            <>
              🎓 Este usuario será registrado con rol{" "}
              <strong>Educativo</strong> y tendrá
              acceso al módulo educativo.
            </>

          )}


          {esIndependiente && (

            <>
              👤 Este usuario será registrado como{" "}
              <strong>Independiente</strong>.
            </>

          )}

        </div>


        {/* ==================================================
            MENSAJE
        ================================================== */}

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
                  : "1px solid #FFD4D4",

            }}
          >

            {message}

          </div>

        )}


        {/* ==================================================
            BOTÓN REGISTRAR
        ================================================== */}

        <button
          type="submit"
          style={{
            ...button,

            opacity:
              loading
                ? 0.7
                : 1,
          }}
          disabled={loading}
        >

          {loading
            ? "⏳ Registrando..."
            : "➕ Registrar usuario"}

        </button>


        {/* ==================================================
            BOTÓN VOLVER
        ================================================== */}

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

  color: "#172B4D",

};


const header = {

  display: "flex",

  alignItems: "flex-start",

  gap: "18px",

  marginBottom: "22px",

};


const title = {

  margin: "0",

  color: "#172B4D",

  fontSize: "28px",

  fontWeight: "800",

};


const subtitle = {

  margin: "7px 0 0",

  color: "#64748B",

  lineHeight: "1.5",

};


const adminInfo = {

  display: "flex",

  alignItems: "center",

  gap: "13px",

  padding: "14px 18px",

  marginBottom: "22px",

  background: "#EEF5FF",

  border:
    "1px solid #D8E7FF",

  borderRadius: "13px",

};


const adminIcon = {

  width: "45px",

  height: "45px",

  borderRadius: "50%",

  background: "#FFFFFF",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  fontSize: "22px",

};


const adminName = {

  display: "block",

  color: "#172B4D",

};


const adminUserName = {

  display: "block",

  marginTop: "2px",

  color: "#475569",

};


const adminArea = {

  display: "block",

  marginTop: "3px",

  color: "#64748B",

};


const sectionTitle = {

  margin:
    "0 0 22px",

  fontSize: "19px",

  fontWeight: "800",

  color: "#172B4D",

};


const formStyle = {

  display: "flex",

  flexDirection: "column",

  gap: "10px",

};


const label = {

  fontSize: "14px",

  fontWeight: "700",

  color: "#334155",

  marginTop: "5px",

};


const input = {

  width: "100%",

  boxSizing: "border-box",

  padding: "12px 13px",

  borderRadius: "9px",

  border:
    "1px solid #CFD8E3",

  fontSize: "14px",

  outline: "none",

  background: "#FFFFFF",

  color: "#1E293B",

};


const infoBox = {

  marginTop: "10px",

  padding: "13px 15px",

  borderRadius: "10px",

  background: "#F8FAFC",

  border:
    "1px solid #E2E8F0",

  color: "#64748B",

  fontSize: "13px",

  lineHeight: "1.5",

};


const messageStyle = {

  marginTop: "8px",

  padding: "12px 14px",

  borderRadius: "9px",

  fontSize: "14px",

  fontWeight: "600",

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

  fontWeight: "700",

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

  whiteSpace: "nowrap",

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

  fontWeight: "700",

};


export default RegisterPsychologist;