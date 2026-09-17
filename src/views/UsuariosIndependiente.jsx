// src/views/UsuariosIndependiente.jsx

import React, { useEffect, useState } from "react";

const API_URL =
  import.meta.env.VITE_API_URL ||
  "http://localhost:5000";

const UsuariosIndependiente = ({ onBack }) => {

  const [usuarios, setUsuarios] =
    useState([]);

  const [busqueda, setBusqueda] =
    useState("");

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");

  const cargarUsuarios = async () => {

    try {

      setLoading(true);

      const token =
        localStorage.getItem("token");

      const response =
        await fetch(
          `${API_URL}/api/usuarios-independiente`,
          {
            headers: {
              Authorization:
                `Bearer ${token}`,
            },
          }
        );

      const data =
        await response.json();

      if (!response.ok) {

        throw new Error(
          data.message ||
          "Error al obtener usuarios"
        );

      }

      setUsuarios(
        Array.isArray(data)
          ? data
          : data.usuarios || []
      );

    } catch (err) {

      setError(err.message);

    } finally {

      setLoading(false);

    }

  };

  useEffect(() => {

    cargarUsuarios();

  }, []);

  const filtrados =
    usuarios.filter((usuario) => {

      const texto =
        busqueda
          .toLowerCase()
          .trim();

      return (

        !texto ||

        String(usuario.nombre || "")
          .toLowerCase()
          .includes(texto)

        ||

        String(usuario.correo || "")
          .toLowerCase()
          .includes(texto)

        ||

        String(
          usuario.especialidad || ""
        )
          .toLowerCase()
          .includes(texto)

      );

    });

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
            👤 Usuarios independientes
          </h2>

          <p style={subtitle}>
            Usuarios independientes registrados
            por tu administración.
          </p>

        </div>

      </div>


      <input
        value={busqueda}
        onChange={(e) =>
          setBusqueda(e.target.value)
        }
        placeholder="🔎 Buscar usuario..."
        style={searchInput}
      />


      <p style={counter}>
        Mostrando{" "}
        <strong>{filtrados.length}</strong>
        {" "}de{" "}
        <strong>{usuarios.length}</strong>
        {" "}usuarios
      </p>


      {loading && (
        <div style={empty}>
          Cargando usuarios...
        </div>
      )}


      {error && (
        <div style={errorBox}>
          ❌ {error}
        </div>
      )}


      {!loading &&
        !error &&
        filtrados.length === 0 && (

          <div style={empty}>
            👤 No hay usuarios independientes
            registrados.
          </div>

        )}


      {!loading &&
        !error &&
        filtrados.length > 0 && (

          <div style={grid}>

            {filtrados.map(
              (usuario) => (

                <div
                  key={usuario.id_usuario}
                  style={card}
                >

                  <div style={avatar}>
                    👤
                  </div>

                  <h3 style={name}>
                    {usuario.nombre}
                  </h3>

                  <p style={data}>
                    📧 {usuario.correo}
                  </p>

                  <p style={data}>
                    🧠{" "}
                    {usuario.especialidad ||
                      usuario.puesto ||
                      "Sin especialidad"}
                  </p>

                  <p style={data}>
                    📞{" "}
                    {usuario.telefono ||
                      "Sin teléfono"}
                  </p>

                  <span style={badge}>
                    👤 Independiente
                  </span>

                </div>

              )
            )}

          </div>

        )}

    </div>

  );

};

const container = {
  maxWidth: "1150px",
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
  color: "#718096",
};

const searchInput = {
  width: "100%",
  boxSizing: "border-box",
  padding: "14px",
  borderRadius: "10px",
  border: "1px solid #D9E2EF",
  fontSize: "15px",
};

const counter = {
  margin: "18px 0",
  color: "#596B82",
};

const grid = {
  display: "grid",
  gridTemplateColumns:
    "repeat(auto-fit, minmax(260px, 1fr))",
  gap: "22px",
};

const card = {
  background: "#FFFFFF",
  padding: "25px",
  borderRadius: "18px",
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
};

const name = {
  color: "#2167D5",
};

const data = {
  color: "#596B82",
  fontSize: "14px",
};

const badge = {
  display: "inline-block",
  marginTop: "8px",
  padding: "7px 10px",
  borderRadius: "20px",
  background: "#EEF7FF",
  color: "#2167D5",
  fontSize: "12px",
  fontWeight: "700",
};

const empty = {
  padding: "50px",
  textAlign: "center",
  color: "#718096",
};

const errorBox = {
  padding: "15px",
  borderRadius: "10px",
  background: "#FFF1F1",
  color: "#C62828",
};

export default UsuariosIndependiente;