// src/views/PsychologistView.jsx

import React, { useEffect, useState } from "react";
import {
  getToken,
  getCurrentUser
} from "../services/AuthService";

const PsychologistView = ({ onBack }) => {

  const [psychologists, setPsychologists] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");


  useEffect(() => {

    const fetchData = async () => {

      try {

        // ==================================================
        // USUARIO ACTUAL
        // ==================================================

        const user = getCurrentUser();

        console.log(
          "🔎 Usuario actual en PsychologistView:",
          user
        );


        // ==================================================
        // NORMALIZAR DATOS
        // ==================================================

        const role =
          user?.role !== undefined &&
          user?.role !== null
            ? Number(user.role)
            : null;


        const tipoAdmin =
          user?.tipo_admin
            ? String(user.tipo_admin)
                .trim()
                .toLowerCase()
            : null;


        const area =
          user?.area
            ? String(user.area)
                .trim()
                .toLowerCase()
            : null;


        // ==================================================
        // PERMISOS
        //
        // MASTER:
        // Puede ver psicólogos.
        //
        // ADMIN NORMAL CLÍNICA:
        // Puede ver psicólogos.
        //
        // RH:
        // NO puede ver psicólogos.
        //
        // EDUCATIVO:
        // NO puede ver psicólogos.
        //
        // INDEPENDIENTE:
        // NO puede ver psicólogos.
        // ==================================================

        const esMaster =
          role === 1 &&
          tipoAdmin === "master";


        const esAdminClinica =
          role === 1 &&
          tipoAdmin === "normal" &&
          area === "clinica";


        const puedeVerPsicologos =
          esMaster ||
          esAdminClinica;


        // ==================================================
        // SIN PERMISO
        // ==================================================

        if (!puedeVerPsicologos) {

          setPsychologists([]);

          setError(
            "No tienes acceso al módulo de psicólogos."
          );

          setLoading(false);

          return;

        }


        // ==================================================
        // TOKEN
        // ==================================================

        const token = getToken();


        if (!token) {

          setError(
            "Sesión no válida. Inicia sesión nuevamente."
          );

          setLoading(false);

          return;

        }


        // ==================================================
        // CONSULTAR BACKEND
        // ==================================================

        const res = await fetch(
          "http://localhost:5000/api/psicologos",
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


        // ==================================================
        // ERROR HTTP
        // ==================================================

        if (!res.ok) {

          const data =
            await res.json()
              .catch(() => ({}));


          throw new Error(
            data.message ||
            "Error al obtener psicólogos"
          );

        }


        // ==================================================
        // DATOS
        // ==================================================

        const data =
          await res.json();


        console.log(
          "👨‍⚕️ Psicólogos recibidos:",
          data
        );


        setPsychologists(
          Array.isArray(data)
            ? data
            : []
        );


      } catch (err) {

        console.error(
          "❌ Error al obtener psicólogos:",
          err
        );


        setError(
          err.message ||
          "Error al obtener psicólogos"
        );


      } finally {

        setLoading(false);

      }

    };


    fetchData();

  }, []);


  // ========================================================
  // RETURN
  // ========================================================

  return (

    <div style={container}>

      <h2 style={title}>
        👨‍⚕️ Psicólogos registrados
      </h2>


      {/* ==================================================
          CARGANDO
      ================================================== */}

      {loading && (

        <p style={loadingText}>
          ⏳ Cargando psicólogos...
        </p>

      )}


      {/* ==================================================
          ERROR
      ================================================== */}

      {!loading && error && (

        <div style={errorBox}>

          ⚠️ {error}

        </div>

      )}


      {/* ==================================================
          SIN PSICÓLOGOS
      ================================================== */}

      {!loading &&
        !error &&
        psychologists.length === 0 && (

          <div style={emptyBox}>

            <div style={emptyIcon}>
              👨‍⚕️
            </div>

            <strong>
              No hay psicólogos registrados.
            </strong>

            <p>
              Cuando registres un psicólogo,
              aparecerá aquí.
            </p>

          </div>

        )}


      {/* ==================================================
          LISTA
      ================================================== */}

      {!loading &&
        !error &&
        psychologists.length > 0 && (

          <div style={list}>

            {psychologists.map((p) => (

              <div
                key={p.id_psicologo}
                style={item}
              >

                <div style={nameRow}>

                  <div style={avatar}>
                    👨‍⚕️
                  </div>

                  <div>

                    <strong style={psychologistName}>
                      {p.nombre}
                    </strong>

                  </div>

                </div>


                <div style={dataRow}>
                  📧 <strong>Correo:</strong>{" "}
                  {p.correo}
                </div>


                <div style={dataRow}>
                  🎓 <strong>Cédula:</strong>{" "}
                  {p.cedula_profesional || "No registrada"}
                </div>


                <div style={dataRow}>
                  🏥 <strong>Especialidad:</strong>{" "}
                  {p.especialidad || "No especificada"}
                </div>

              </div>

            ))}

          </div>

        )}


      {/* ==================================================
          VOLVER
      ================================================== */}

      <button
        onClick={onBack}
        style={backButton}
      >

        ⬅️ Volver

      </button>

    </div>

  );

};


// ============================================================
// ESTILOS
// ============================================================

const container = {

  maxWidth: "760px",

  margin: "40px auto",

  padding: "30px",

  background: "#FFFFFF",

  borderRadius: "18px",

  boxShadow:
    "0 8px 24px rgba(40,80,140,0.10)",

  boxSizing: "border-box",

};


const title = {

  margin: "0 0 25px",

  fontSize: "26px",

  color: "#3F51B5",

  textAlign: "center",

};


const loadingText = {

  textAlign: "center",

  color: "#667085",

};


const errorBox = {

  padding: "14px",

  borderRadius: "10px",

  background: "#FFF3F3",

  border: "1px solid #FFD6D6",

  color: "#C62828",

  textAlign: "center",

};


const emptyBox = {

  padding: "35px 20px",

  textAlign: "center",

  color: "#667085",

  background: "#F8FAFC",

  borderRadius: "14px",

  border: "1px solid #E4EAF2",

};


const emptyIcon = {

  fontSize: "42px",

  marginBottom: "10px",

};


const list = {

  display: "flex",

  flexDirection: "column",

  gap: "14px",

};


const item = {

  padding: "20px",

  border: "1px solid #E1E7EF",

  borderRadius: "14px",

  background: "#F9FBFE",

};


const nameRow = {

  display: "flex",

  alignItems: "center",

  gap: "12px",

  marginBottom: "15px",

};


const avatar = {

  width: "46px",

  height: "46px",

  borderRadius: "50%",

  background: "#EAF1FF",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  fontSize: "23px",

};


const psychologistName = {

  fontSize: "18px",

  color: "#2167D5",

};


const dataRow = {

  marginTop: "7px",

  fontSize: "14px",

  color: "#4B5563",

};


const backButton = {

  display: "block",

  margin: "25px auto 0",

  padding: "11px 20px",

  background: "#5C6BC0",

  color: "#FFFFFF",

  border: "none",

  borderRadius: "9px",

  cursor: "pointer",

  fontSize: "14px",

};


export default PsychologistView;