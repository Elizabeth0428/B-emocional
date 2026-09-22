
// src/views/UsuariosRH.jsx

import React, { useEffect, useState } from "react";
import { getCurrentUser } from "../services/AuthService";

const API_URL =
  import.meta.env.VITE_API_URL ||
  "https://reflejoyalma.com";


const UsuariosRH = ({ onBack }) => {

  const user = getCurrentUser();

  const [usuarios, setUsuarios] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [busqueda, setBusqueda] = useState("");

  const [usuarioSeleccionado, setUsuarioSeleccionado] =
    useState(null);

  const [modo, setModo] =
    useState(null);


  // =====================================================
  // CARGAR USUARIOS
  // =====================================================

  const cargarUsuarios = async () => {

    try {

      setLoading(true);
      setError("");

      const token =
        localStorage.getItem("token");


      const response = await fetch(
        `${API_URL}/api/usuario-rh`,
        {
          method: "GET",

          headers: {
            Authorization:
              `Bearer ${token}`,

            "Content-Type":
              "application/json",
          },
        }
      );


      const data =
        await response.json();


      if (!response.ok) {

        throw new Error(
          data.message ||
          "Error al obtener usuarios RH"
        );

      }


      setUsuarios(
        Array.isArray(data)
          ? data
          : data.usuarios || []
      );


    } catch (err) {

      console.error(
        "Error usuarios RH:",
        err
      );

      setError(
        err.message ||
        "No se pudieron cargar los usuarios RH"
      );

    } finally {

      setLoading(false);

    }

  };


  // =====================================================
  // CARGAR AL ENTRAR
  // =====================================================

  useEffect(() => {

    cargarUsuarios();

  }, []);


  // =====================================================
  // BUSCADOR
  // =====================================================

  const usuariosFiltrados =
    usuarios.filter((usuario) => {

      const texto =
        busqueda
          .toLowerCase()
          .trim();


      if (!texto) {
        return true;
      }


      return (

        String(
          usuario.nombre || ""
        )
          .toLowerCase()
          .includes(texto)

        ||

        String(
          usuario.correo || ""
        )
          .toLowerCase()
          .includes(texto)

        ||

        String(
          usuario.puesto || ""
        )
          .toLowerCase()
          .includes(texto)

        ||

        String(
          usuario.telefono || ""
        )
          .toLowerCase()
          .includes(texto)

      );

    });


  // =====================================================
  // VER FICHA
  // =====================================================

  const verFicha = async (usuario) => {

    try {

      const token =
        localStorage.getItem("token");


      const response = await fetch(
        `${API_URL}/api/usuario-rh/${usuario.id_usuario}`,
        {
          method: "GET",

          headers: {
            Authorization:
              `Bearer ${token}`,

            "Content-Type":
              "application/json",
          },
        }
      );


      const data =
        await response.json();


      if (!response.ok) {

        throw new Error(
          data.message ||
          "No se pudo obtener la ficha"
        );

      }


      setUsuarioSeleccionado(
        data.usuario
      );

      setModo("ver");


    } catch (err) {

      console.error(
        "Error al obtener ficha:",
        err
      );

      setError(
        err.message ||
        "No se pudo obtener la ficha"
      );

    }

  };


  // =====================================================
  // EDITAR
  // =====================================================

  const editarUsuario = async (usuario) => {

    try {

      const token =
        localStorage.getItem("token");


      const response = await fetch(
        `${API_URL}/api/usuario-rh/${usuario.id_usuario}`,
        {
          method: "GET",

          headers: {
            Authorization:
              `Bearer ${token}`,

            "Content-Type":
              "application/json",
          },
        }
      );


      const data =
        await response.json();


      if (!response.ok) {

        throw new Error(
          data.message ||
          "No se pudo obtener la ficha"
        );

      }


      setUsuarioSeleccionado(
        data.usuario
      );

      setModo("editar");


    } catch (err) {

      console.error(
        "Error al editar usuario:",
        err
      );

      setError(
        err.message ||
        "No se pudo abrir la ficha"
      );

    }

  };


  // =====================================================
  // CERRAR FICHA
  // =====================================================

  const cerrarFicha = () => {

    setUsuarioSeleccionado(null);
    setModo(null);

  };


  // =====================================================
  // SI HAY FICHA ABIERTA
  // =====================================================

  if (
    usuarioSeleccionado &&
    modo
  ) {

    return (

      <FichaUsuarioRH
        usuario={usuarioSeleccionado}
        modo={modo}
        onClose={cerrarFicha}
        onGuardado={(usuarioActualizado) => {

          setUsuarios((prev) =>
            prev.map((u) =>
              u.id_usuario ===
              usuarioActualizado.id_usuario
                ? usuarioActualizado
                : u
            )
          );

          setUsuarioSeleccionado(
            usuarioActualizado
          );

          setModo("ver");

        }}
      />

    );

  }


  // =====================================================
  // RETURN PRINCIPAL
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
            👥 Usuarios de Recursos Humanos
          </h2>


          <p style={subtitle}>
            Consulta y administra los usuarios RH
            bajo tu administración.
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
          BUSCADOR
      ================================================= */}

      <div style={searchBox}>

        <input
          type="text"
          value={busqueda}
          onChange={(e) =>
            setBusqueda(e.target.value)
          }
          placeholder="🔎 Buscar por nombre, correo, puesto o teléfono..."
          style={searchInput}
        />

      </div>


      {/* =================================================
          CONTADOR
      ================================================= */}

      <div style={counter}>

        Mostrando{" "}

        <strong>
          {usuariosFiltrados.length}
        </strong>{" "}

        de{" "}

        <strong>
          {usuarios.length}
        </strong>{" "}

        usuarios RH

      </div>


      {/* =================================================
          CARGANDO
      ================================================= */}

      {loading && (

        <div style={empty}>
          ⏳ Cargando usuarios...
        </div>

      )}


      {/* =================================================
          ERROR
      ================================================= */}

      {error && (

        <div style={errorBox}>

          ❌ {error}

          <button
            type="button"
            onClick={() =>
              setError("")
            }
            style={closeError}
          >
            ×
          </button>

        </div>

      )}


      {/* =================================================
          SIN RESULTADOS
      ================================================= */}

      {!loading &&
        !error &&
        usuariosFiltrados.length === 0 && (

          <div style={empty}>

            {busqueda

              ? "🔎 No se encontraron usuarios con esa búsqueda."

              : "👥 No hay usuarios RH registrados."

            }

          </div>

        )}


      {/* =================================================
          LISTA
      ================================================= */}

      {!loading &&
        !error &&
        usuariosFiltrados.length > 0 && (

          <div style={grid}>

            {usuariosFiltrados.map(
              (usuario) => (

                <div
                  key={
                    usuario.id_usuario ||
                    usuario.correo
                  }
                  style={userCard}
                >

                  <div style={avatar}>
                    👤
                  </div>


                  <h3 style={userName}>

                    {usuario.nombre ||
                      "Usuario sin nombre"}

                  </h3>


                  <div style={userData}>

                    📧{" "}

                    {usuario.correo ||
                      "Sin correo"}

                  </div>


                  <div style={userData}>

                    💼{" "}

                    {usuario.puesto ||
                      "Sin puesto registrado"}

                  </div>


                  <div style={userData}>

                    📞{" "}

                    {usuario.telefono ||
                      "Sin teléfono"}

                  </div>


                  <div style={userData}>

                    📍{" "}

                    {usuario.direccion ||
                      "Sin dirección"}

                  </div>


                  <div style={badge}>

                    👥 Recursos Humanos

                  </div>


                  {/* =================================================
                      ACCIONES
                  ================================================= */}

                  <div style={actions}>

                    <button
                      type="button"
                      onClick={() =>
                        verFicha(usuario)
                      }
                      style={viewButton}
                    >
                      👁️ Ver ficha
                    </button>


                    <button
                      type="button"
                      onClick={() =>
                        editarUsuario(usuario)
                      }
                      style={editButton}
                    >
                      ✏️ Editar
                    </button>

                  </div>

                </div>

              )
            )}

          </div>

        )}

    </div>

  );

};


// ============================================================
// FICHA DEL USUARIO RH
// ============================================================

const FichaUsuarioRH = ({
  usuario,
  modo,
  onClose,
  onGuardado,
}) => {

  const [form, setForm] = useState({

    nombre:
      usuario.nombre || "",

    correo:
      usuario.correo || "",

    puesto:
      usuario.puesto || "",

    telefono:
      usuario.telefono || "",

    direccion:
      usuario.direccion || "",

    password: "",

  });


  const [loading, setLoading] =
    useState(false);


  const [message, setMessage] =
    useState("");


  const handleChange = (e) => {

    const {
      name,
      value,
    } = e.target;


    setForm((prev) => ({
      ...prev,
      [name]: value,
    }));

  };


  // =====================================================
  // GUARDAR
  // =====================================================

  const guardarCambios = async (e) => {

    e.preventDefault();

    setLoading(true);
    setMessage("");


    try {

      const token =
        localStorage.getItem("token");


      const body = {

        nombre:
          form.nombre,

        correo:
          form.correo,

        puesto:
          form.puesto,

        telefono:
          form.telefono,

        direccion:
          form.direccion,

      };


      if (
        form.password &&
        form.password.trim()
      ) {

        body.password =
          form.password;

      }


      const response =
        await fetch(
          `${API_URL}/api/usuario-rh/${usuario.id_usuario}`,
          {
            method: "PUT",

            headers: {
              "Content-Type":
                "application/json",

              Authorization:
                `Bearer ${token}`,
            },

            body:
              JSON.stringify(body),
          }
        );


      const data =
        await response.json();


      if (!response.ok) {

        throw new Error(
          data.message ||
          "No se pudieron guardar los cambios"
        );

      }


      setMessage(
        "✅ Cambios guardados correctamente"
      );


      setTimeout(() => {

        onGuardado(
          data.usuario
        );

      }, 700);


    } catch (error) {

      console.error(
        "Error al actualizar usuario RH:",
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
  // MODO VER
  // =====================================================

  if (modo === "ver") {

    return (

      <div style={container}>

        <div style={header}>

          <button
            type="button"
            onClick={onClose}
            style={backButton}
          >
            ← Volver
          </button>


          <div>

            <h2 style={title}>
              👤 Ficha del usuario
            </h2>

            <p style={subtitle}>
              Información completa del usuario de
              Recursos Humanos.
            </p>

          </div>

        </div>


        <div style={profileCard}>

          <div style={profileAvatar}>
            👤
          </div>


          <h2 style={profileName}>
            {usuario.nombre}
          </h2>


          <div style={profileBadge}>
            👥 Recursos Humanos
          </div>


          <div style={detailsGrid}>

            <InfoItem
              icon="📧"
              label="Correo electrónico"
              value={usuario.correo}
            />


            <InfoItem
              icon="📞"
              label="Teléfono"
              value={
                usuario.telefono ||
                "No registrado"
              }
            />


            <InfoItem
              icon="💼"
              label="Puesto"
              value={
                usuario.puesto ||
                "No registrado"
              }
            />


            <InfoItem
              icon="📍"
              label="Dirección"
              value={
                usuario.direccion ||
                "No registrada"
              }
            />


            <InfoItem
              icon="👥"
              label="Área"
              value="Recursos Humanos"
            />


            <InfoItem
              icon="🔐"
              label="Rol"
              value="Usuario RH"
            />

          </div>


          <div style={profileActions}>

            <button
              type="button"
              onClick={() =>
                onClose()
              }
              style={secondaryButton}
            >
              Cerrar
            </button>


            <button
              type="button"
              onClick={() =>
                window.location.hash =
                  "editar-rh"
              }
              style={editButton}
            >
              ✏️ Editar información
            </button>

          </div>

        </div>

      </div>

    );

  }


  // =====================================================
  // MODO EDITAR
  // =====================================================

  return (

    <div style={container}>

      <div style={header}>

        <button
          type="button"
          onClick={onClose}
          style={backButton}
        >
          ← Volver
        </button>


        <div>

          <h2 style={title}>
            ✏️ Editar usuario RH
          </h2>


          <p style={subtitle}>
            Modifica la información del usuario.
          </p>

        </div>

      </div>


      <form
        onSubmit={guardarCambios}
        style={profileCard}
      >

        <h3 style={sectionTitle}>
          👤 Datos personales
        </h3>


        <label style={label}>
          Nombre completo
        </label>

        <input
          type="text"
          name="nombre"
          value={form.nombre}
          onChange={handleChange}
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
          style={input}
          required
        />


        <label style={label}>
          Puesto
        </label>

        <input
          type="text"
          name="puesto"
          value={form.puesto}
          onChange={handleChange}
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
          style={input}
        />


        <div style={passwordBox}>

          <h4 style={passwordTitle}>
            🔐 Cambiar contraseña
          </h4>

          <p style={passwordText}>
            Déjalo vacío si no deseas cambiar
            la contraseña.
          </p>


          <input
            type="password"
            name="password"
            value={form.password}
            onChange={handleChange}
            placeholder="Nueva contraseña"
            minLength={6}
            style={input}
          />

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


        <div style={profileActions}>

          <button
            type="button"
            onClick={onClose}
            style={secondaryButton}
          >
            Cancelar
          </button>


          <button
            type="submit"
            disabled={loading}
            style={submitButton}
          >

            {loading
              ? "Guardando..."
              : "💾 Guardar cambios"}

          </button>

        </div>

      </form>

    </div>

  );

};


// ============================================================
// COMPONENTE INFO
// ============================================================

const InfoItem = ({
  icon,
  label,
  value,
}) => (

  <div style={infoItem}>

    <div style={infoIcon}>
      {icon}
    </div>

    <div>

      <div style={infoLabel}>
        {label}
      </div>

      <div style={infoValue}>
        {value || "No registrado"}
      </div>

    </div>

  </div>

);


// ============================================================
// ESTILOS
// ============================================================

const container = {
  maxWidth: "1150px",
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

const searchBox = {
  background: "#FFFFFF",
  padding: "18px",
  borderRadius: "15px",
  boxShadow:
    "0 6px 18px rgba(40,80,140,0.07)",
};

const searchInput = {
  width: "100%",
  boxSizing: "border-box",
  padding: "14px",
  borderRadius: "10px",
  border: "1px solid #D9E2EF",
  fontSize: "15px",
  outline: "none",
};

const counter = {
  margin: "18px 0",
  color: "#596B82",
};

const grid = {
  display: "grid",
  gridTemplateColumns:
    "repeat(auto-fit, minmax(280px, 1fr))",
  gap: "22px",
};

const userCard = {
  background: "#FFFFFF",
  borderRadius: "18px",
  padding: "25px",
  boxShadow:
    "0 8px 22px rgba(40,80,140,0.08)",
  borderBottom:
    "4px solid #4A7FF5",
};

const avatar = {
  width: "65px",
  height: "65px",
  borderRadius: "50%",
  background: "#EAF1FF",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "30px",
  marginBottom: "15px",
};

const userName = {
  margin: "0 0 15px",
  color: "#2167D5",
};

const userData = {
  marginBottom: "9px",
  color: "#596B82",
  fontSize: "14px",
};

const badge = {
  display: "inline-block",
  marginTop: "10px",
  padding: "7px 10px",
  borderRadius: "20px",
  background: "#EEF7FF",
  color: "#2167D5",
  fontSize: "12px",
  fontWeight: "700",
};

const actions = {
  display: "flex",
  gap: "10px",
  marginTop: "20px",
};

const viewButton = {
  flex: 1,
  border: "none",
  borderRadius: "10px",
  padding: "11px",
  background: "#EEF4FF",
  color: "#2167D5",
  fontWeight: "700",
  cursor: "pointer",
};

const editButton = {
  flex: 1,
  border: "none",
  borderRadius: "10px",
  padding: "11px",
  background: "#2167D5",
  color: "#FFFFFF",
  fontWeight: "700",
  cursor: "pointer",
};

const empty = {
  padding: "50px",
  textAlign: "center",
  color: "#718096",
};

const errorBox = {
  position: "relative",
  padding: "15px 45px 15px 15px",
  background: "#FFF1F1",
  color: "#C62828",
  borderRadius: "10px",
};

const closeError = {
  position: "absolute",
  right: "12px",
  top: "8px",
  border: "none",
  background: "transparent",
  fontSize: "20px",
  cursor: "pointer",
};

const profileCard = {
  background: "#FFFFFF",
  borderRadius: "20px",
  padding: "35px",
  boxShadow:
    "0 8px 25px rgba(40,80,140,0.09)",
};

const profileAvatar = {
  width: "90px",
  height: "90px",
  borderRadius: "50%",
  background: "#EAF1FF",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "42px",
  margin: "0 auto 15px",
};

const profileName = {
  textAlign: "center",
  margin: "0 0 10px",
  color: "#2167D5",
};

const profileBadge = {
  width: "fit-content",
  margin: "0 auto 30px",
  padding: "8px 14px",
  borderRadius: "20px",
  background: "#EEF7FF",
  color: "#2167D5",
  fontWeight: "700",
  fontSize: "13px",
};

const detailsGrid = {
  display: "grid",
  gridTemplateColumns:
    "repeat(auto-fit, minmax(280px, 1fr))",
  gap: "18px",
};

const infoItem = {
  display: "flex",
  alignItems: "center",
  gap: "14px",
  padding: "18px",
  borderRadius: "14px",
  background: "#F7FAFE",
  border: "1px solid #E4EAF2",
};

const infoIcon = {
  fontSize: "25px",
};

const infoLabel = {
  fontSize: "12px",
  color: "#718096",
  marginBottom: "4px",
};

const infoValue = {
  fontWeight: "700",
  color: "#1A2B4B",
};

const profileActions = {
  display: "flex",
  justifyContent: "flex-end",
  gap: "12px",
  marginTop: "30px",
};

const secondaryButton = {
  border: "1px solid #D9E2EF",
  background: "#FFFFFF",
  color: "#596B82",
  padding: "12px 18px",
  borderRadius: "10px",
  cursor: "pointer",
  fontWeight: "700",
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

const passwordBox = {
  marginTop: "25px",
  padding: "20px",
  borderRadius: "14px",
  background: "#F7FAFE",
  border: "1px solid #E1E8F2",
};

const passwordTitle = {
  margin: "0 0 5px",
  color: "#2167D5",
};

const passwordText = {
  margin: "0 0 15px",
  color: "#718096",
  fontSize: "13px",
};

const messageBox = {
  marginTop: "18px",
  padding: "13px",
  borderRadius: "10px",
  fontWeight: "600",
};

const submitButton = {
  border: "none",
  background: "#2167D5",
  color: "#FFFFFF",
  padding: "12px 20px",
  borderRadius: "10px",
  cursor: "pointer",
  fontWeight: "700",
};


// ============================================================
// EXPORT
// ============================================================

export default UsuariosRH;

