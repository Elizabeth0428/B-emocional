// ==================================================
// src/views/SeguimientoProspecto.jsx
// ==================================================

import React, {
  useEffect,
  useState
} from "react";

import {
  useNavigate,
  useParams
} from "react-router-dom";

import {
  getToken
} from "../services/AuthService";


const API_URL =
  import.meta.env.VITE_API_URL ||
  "https://reflejoyalma.com";


// ==================================================
// SEGUIMIENTO DEL PROSPECTO
// ==================================================

const SeguimientoProspecto = () => {

  const navigate =
    useNavigate();

  const {
    idProspecto
  } = useParams();


  // ==================================================
  // ESTADOS
  // ==================================================

  const [
    prospecto,
    setProspecto
  ] = useState(null);

  const [
    loading,
    setLoading
  ] = useState(true);

  const [
    guardando,
    setGuardando
  ] = useState(false);

  const [
    error,
    setError
  ] = useState("");

  const [
    mensaje,
    setMensaje
  ] = useState("");


  const [
    form,
    setForm
  ] = useState({

    etapa:
      "evaluacion_inicial",

    actividad:
      "",

    observacion:
      "",

    resultado:
      "pendiente",

    proxima_accion:
      "",

    fecha_proxima_accion:
      ""

  });


  // ==================================================
  // CARGAR PROSPECTO
  //
  // Usamos el endpoint de seguimiento porque también
  // devuelve los datos básicos del prospecto.
  //
  // El historial NO se muestra aquí.
  // Se conserva para el expediente final.
  // ==================================================

  const cargarProspecto =
    async () => {

      try {

        setLoading(true);

        setError("");


        const token =
          getToken();


        if (!token) {

          throw new Error(
            "Tu sesión no es válida. Inicia sesión nuevamente."
          );
        }


        const response =
          await fetch(
            `${API_URL}/api/prospectos/${idProspecto}/seguimiento`,
            {

              method:
                "GET",

              headers: {

                Authorization:
                  `Bearer ${token}`,

                "Content-Type":
                  "application/json"

              }

            }
          );


        const data =
          await response
            .json()
            .catch(
              () => ({})
            );


        if (!response.ok) {

          throw new Error(
            data.message ||
            "No se pudo cargar el seguimiento del prospecto"
          );
        }


        setProspecto(
          data.prospecto ||
          null
        );


      } catch (err) {

        console.error(
          "❌ Error cargando seguimiento:",
          err
        );


        setError(
          err.message ||
          "No se pudo cargar el seguimiento"
        );


      } finally {

        setLoading(false);

      }

    };


  // ==================================================
  // CARGAR AL ENTRAR
  // ==================================================

  useEffect(
    () => {

      if (
        idProspecto
      ) {

        cargarProspecto();

      }

    },
    [
      idProspecto
    ]
  );


  // ==================================================
  // CAMBIAR FORMULARIO
  // ==================================================

  const handleChange =
    e => {

      const {
        name,
        value
      } = e.target;


      setForm(
        prev => ({

          ...prev,

          [name]:
            value

        })
      );


      if (
        mensaje
      ) {

        setMensaje("");

      }

    };


  // ==================================================
  // REGISTRAR SEGUIMIENTO
  // ==================================================

  const handleSubmit =
    async e => {

      e.preventDefault();


      if (
        guardando
      ) {

        return;

      }


      if (
        !String(
          form.actividad
        ).trim()
      ) {

        setMensaje(
          "❌ La actividad es obligatoria"
        );

        return;

      }


      try {

        setGuardando(true);

        setMensaje("");


        const token =
          getToken();


        if (
          !token
        ) {

          throw new Error(
            "Tu sesión no es válida"
          );

        }


        const response =
          await fetch(
            `${API_URL}/api/prospectos/${idProspecto}/seguimiento`,
            {

              method:
                "POST",

              headers: {

                Authorization:
                  `Bearer ${token}`,

                "Content-Type":
                  "application/json"

              },

              body:
                JSON.stringify({

                  etapa:
                    form.etapa,

                  actividad:
                    form.actividad.trim(),

                  observacion:
                    form.observacion.trim(),

                  resultado:
                    form.resultado,

                  proxima_accion:
                    form.proxima_accion.trim(),

                  fecha_proxima_accion:
                    form.fecha_proxima_accion ||
                    null

                })

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
            data.message ||
            "No se pudo registrar el seguimiento"
          );

        }


        setMensaje(
          "✅ Seguimiento registrado correctamente. Se agregó al expediente final del proceso."
        );


        setForm({

          etapa:
            "evaluacion_inicial",

          actividad:
            "",

          observacion:
            "",

          resultado:
            "pendiente",

          proxima_accion:
            "",

          fecha_proxima_accion:
            ""

        });


        // Actualizamos solamente información básica
        // del prospecto. No mostramos aquí el historial.
        await cargarProspecto();


      } catch (err) {

        console.error(
          "❌ Error guardando seguimiento:",
          err
        );


        setMensaje(
          `❌ ${
            err.message ||
            "No se pudo registrar el seguimiento"
          }`
        );


      } finally {

        setGuardando(false);

      }

    };


  // ==================================================
  // CARGANDO
  // ==================================================

  if (
    loading
  ) {

    return (

      <div style={loadingContainer}>

        <div style={loadingIcon}>
          ⏳
        </div>

        <h3>
          Cargando seguimiento...
        </h3>

        <p>
          Estamos obteniendo la información
          del proceso de selección.
        </p>

      </div>

    );

  }


  // ==================================================
  // ERROR
  // ==================================================

  if (
    error
  ) {

    return (

      <div style={errorContainer}>

        <div style={errorIcon}>
          ⚠️
        </div>

        <h2>
          No se pudo cargar el seguimiento
        </h2>

        <p>
          {error}
        </p>

        <button
          type="button"
          onClick={() =>
            navigate(
              `/prospecto/${idProspecto}`
            )
          }
          style={backButton}
        >
          ⬅ Volver al expediente
        </button>

      </div>

    );

  }


  // ==================================================
  // RETURN
  // ==================================================

  return (

    <div style={page}>


      {/* ==================================================
          HEADER
      ================================================== */}

      <div style={header}>

        <button
          type="button"
          onClick={() =>
            navigate(
              `/prospecto/${idProspecto}`
            )
          }
          style={backButton}
        >
          ⬅ Volver
        </button>


        <div style={headerInfo}>

          <div style={headerLabel}>
            RECURSOS HUMANOS
          </div>

          <h1 style={title}>
            📋 Seguimiento del proceso
          </h1>

          <p style={subtitle}>
            Registra actividades, avances,
            pendientes y acontecimientos
            importantes del proceso de selección.
          </p>

        </div>

      </div>


      {/* ==================================================
          PROSPECTO
      ================================================== */}

      <div style={prospectBox}>

        <div style={prospectIcon}>
          👤
        </div>


        <div>

          <div style={prospectLabel}>
            PROSPECTO
          </div>

          <div style={prospectName}>

            {prospecto?.nombre ||
              "Prospecto"}

          </div>

          <div style={prospectMirror}>

            🆔{" "}

            {prospecto?.id_mirror ||
              "Sin ID MirrorSoul"}

          </div>

        </div>

      </div>


      {/* ==================================================
          FORMULARIO
      ================================================== */}

      <section style={section}>

        <div style={formCard}>

          <div style={formHeader}>

            <div style={formHeaderIcon}>
              ➕
            </div>


            <div>

              <h2 style={sectionTitle}>
                Registrar seguimiento
              </h2>

              <p style={sectionDescription}>
                Agrega una actividad realizada
                durante el proceso de selección.
              </p>

            </div>

          </div>


          <form
            onSubmit={handleSubmit}
          >


            {/* ==============================================
                ETAPA
            ============================================== */}

            <div style={field}>

              <label style={label}>
                Etapa del proceso
              </label>

              <select
                name="etapa"
                value={
                  form.etapa
                }
                onChange={
                  handleChange
                }
                style={input}
              >

                <option value="registro">
                  Registro
                </option>

                <option value="evaluacion_inicial">
                  Evaluación inicial
                </option>

                <option value="pruebas">
                  Pruebas psicométricas
                </option>

                <option value="entrevista">
                  Entrevista
                </option>

                <option value="revision">
                  Revisión
                </option>

                <option value="decision">
                  Decisión
                </option>

                <option value="seguimiento">
                  Seguimiento
                </option>

              </select>

            </div>


            {/* ==============================================
                ACTIVIDAD
            ============================================== */}

            <div style={field}>

              <label style={label}>
                Actividad *
              </label>

              <input
                type="text"
                name="actividad"
                value={
                  form.actividad
                }
                onChange={
                  handleChange
                }
                placeholder="Ej. Revisión de perfil, contacto telefónico, envío de información..."
                style={input}
                required
              />

            </div>


            {/* ==============================================
                OBSERVACIÓN
            ============================================== */}

            <div style={field}>

              <label style={label}>
                Observación
              </label>

              <textarea
                name="observacion"
                value={
                  form.observacion
                }
                onChange={
                  handleChange
                }
                placeholder="Describe lo relevante de esta actividad..."
                style={textarea}
                rows={4}
              />

            </div>


            {/* ==============================================
                RESULTADO
            ============================================== */}

            <div style={field}>

              <label style={label}>
                Resultado
              </label>

              <select
                name="resultado"
                value={
                  form.resultado
                }
                onChange={
                  handleChange
                }
                style={input}
              >

                <option value="pendiente">
                  Pendiente
                </option>

                <option value="continua">
                  Continúa
                </option>

                <option value="detenido">
                  Detenido
                </option>

                <option value="aprobado">
                  Aprobado
                </option>

                <option value="no_aprobado">
                  No aprobado
                </option>

              </select>

            </div>


            {/* ==============================================
                PRÓXIMA ACCIÓN
            ============================================== */}

            <div style={field}>

              <label style={label}>
                Próxima acción
              </label>

              <textarea
                name="proxima_accion"
                value={
                  form.proxima_accion
                }
                onChange={
                  handleChange
                }
                placeholder="Ej. Aplicar pruebas psicométricas, programar segunda entrevista..."
                style={textarea}
                rows={3}
              />

            </div>


            {/* ==============================================
                FECHA PRÓXIMA ACCIÓN
            ============================================== */}

            <div style={field}>

              <label style={label}>
                Fecha de próxima acción
              </label>

              <input
                type="datetime-local"
                name="fecha_proxima_accion"
                value={
                  form.fecha_proxima_accion
                }
                onChange={
                  handleChange
                }
                style={input}
              />

            </div>


            {/* ==============================================
                MENSAJE
            ============================================== */}

            {mensaje && (

              <div
                style={{

                  ...messageBox,

                  color:
                    mensaje.startsWith(
                      "✅"
                    )
                      ? "#27843A"
                      : "#C62828",

                  background:
                    mensaje.startsWith(
                      "✅"
                    )
                      ? "#ECF9EF"
                      : "#FFF1F1",

                  border:
                    mensaje.startsWith(
                      "✅"
                    )
                      ? "1px solid #B7E4C7"
                      : "1px solid #F0B8B8"

                }}
              >
                {mensaje}
              </div>

            )}


            {/* ==============================================
                GUARDAR
            ============================================== */}

            <button
              type="submit"
              disabled={
                guardando
              }
              style={{

                ...saveButton,

                opacity:
                  guardando
                    ? 0.7
                    : 1,

                cursor:
                  guardando
                    ? "not-allowed"
                    : "pointer"

              }}
            >

              {guardando
                ? "⏳ Guardando..."
                : "💾 Guardar seguimiento"}

            </button>

          </form>

        </div>

      </section>


      {/* ==================================================
          AVISO DE EXPEDIENTE
      ================================================== */}

      <section style={section}>

        <div style={expedienteNotice}>

          <div style={expedienteNoticeIcon}>
            📂
          </div>


          <div style={expedienteNoticeContent}>

            <h3 style={expedienteNoticeTitle}>
              Seguimiento guardado en el expediente
            </h3>

            <p style={expedienteNoticeText}>
              Los registros realizados en esta sección
              se conservan automáticamente dentro del
              proceso de selección del prospecto.
            </p>

            <p style={expedienteNoticeText}>
              El historial completo de actividades,
              observaciones, resultados y próximas
              acciones podrá consultarse junto con
              entrevistas, pruebas, documentos y demás
              evidencias en el expediente final.
            </p>

          </div>

        </div>

      </section>


      {/* ==================================================
          RECORDATORIO
      ================================================== */}

      <div style={infoNotice}>

        <div style={infoNoticeIcon}>
          💡
        </div>


        <div>

          <strong>
            ¿Para qué sirve Seguimiento?
          </strong>

          <p style={infoNoticeText}>
            Utiliza esta sección para registrar
            acontecimientos importantes entre una
            etapa y otra del proceso: contactos,
            pendientes, revisiones, avances o
            próximas acciones.
          </p>

        </div>

      </div>


      {/* ==================================================
          FOOTER
      ================================================== */}

      <footer style={footer}>

        <span>
          🧠 MirrorSoul
        </span>

        <span>
          Recursos Humanos · Seguimiento
        </span>

      </footer>

    </div>

  );

};


// ==================================================
// ESTILOS
// ==================================================

const page = {

  maxWidth:
    "1100px",

  margin:
    "0 auto",

  padding:
    "40px 25px 60px",

  fontFamily:
    "'Segoe UI', Arial, sans-serif",

  color:
    "#263238"

};


const header = {

  display:
    "flex",

  alignItems:
    "flex-start",

  gap:
    "20px",

  marginBottom:
    "25px"

};


const headerInfo = {

  flex:
    1

};


const headerLabel = {

  fontSize:
    "12px",

  fontWeight:
    "800",

  letterSpacing:
    "1.5px",

  color:
    "#607D8B"

};


const title = {

  margin:
    "5px 0 0",

  fontSize:
    "30px",

  color:
    "#263238"

};


const subtitle = {

  margin:
    "7px 0 0",

  color:
    "#78909C",

  lineHeight:
    1.5

};


const backButton = {

  border:
    "none",

  background:
    "#EEF3F8",

  color:
    "#263238",

  padding:
    "10px 16px",

  borderRadius:
    "10px",

  cursor:
    "pointer",

  fontWeight:
    "700"

};


const prospectBox = {

  display:
    "flex",

  alignItems:
    "center",

  gap:
    "15px",

  background:
    "#FFFFFF",

  border:
    "1px solid #E1E8EF",

  borderRadius:
    "16px",

  padding:
    "18px",

  marginBottom:
    "30px",

  boxShadow:
    "0 5px 18px rgba(30,60,90,.05)"

};


const prospectIcon = {

  width:
    "50px",

  height:
    "50px",

  minWidth:
    "50px",

  borderRadius:
    "14px",

  background:
    "#EEF4FF",

  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  fontSize:
    "23px"

};


const prospectLabel = {

  fontSize:
    "10px",

  fontWeight:
    "800",

  letterSpacing:
    "1px",

  color:
    "#90A4AE"

};


const prospectName = {

  marginTop:
    "3px",

  fontSize:
    "18px",

  fontWeight:
    "800"

};


const prospectMirror = {

  marginTop:
    "4px",

  fontSize:
    "12px",

  color:
    "#607D8B"

};


const section = {

  marginBottom:
    "35px"

};


const formCard = {

  background:
    "#FFFFFF",

  border:
    "1px solid #E1E8EF",

  borderRadius:
    "18px",

  padding:
    "25px",

  boxShadow:
    "0 6px 20px rgba(30,60,90,.05)"

};


const formHeader = {

  display:
    "flex",

  alignItems:
    "flex-start",

  gap:
    "13px",

  marginBottom:
    "23px"

};


const formHeaderIcon = {

  width:
    "45px",

  height:
    "45px",

  minWidth:
    "45px",

  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  borderRadius:
    "12px",

  background:
    "#EEF4FF",

  fontSize:
    "20px"

};


const sectionTitle = {

  margin:
    0,

  fontSize:
    "21px",

  color:
    "#263238"

};


const sectionDescription = {

  margin:
    "6px 0 0",

  color:
    "#78909C",

  fontSize:
    "14px",

  lineHeight:
    1.5

};


const field = {

  marginBottom:
    "18px"

};


const label = {

  display:
    "block",

  marginBottom:
    "7px",

  fontWeight:
    "700",

  fontSize:
    "13px",

  color:
    "#455A64"

};


const input = {

  width:
    "100%",

  boxSizing:
    "border-box",

  padding:
    "12px 13px",

  borderRadius:
    "10px",

  border:
    "1px solid #D9E2EF",

  fontSize:
    "14px",

  background:
    "#FFFFFF",

  color:
    "#263238",

  fontFamily:
    "inherit"

};


const textarea = {

  ...input,

  resize:
    "vertical"

};


const messageBox = {

  marginTop:
    "15px",

  marginBottom:
    "15px",

  padding:
    "12px",

  borderRadius:
    "10px",

  fontWeight:
    "600",

  lineHeight:
    1.5

};


const saveButton = {

  width:
    "100%",

  border:
    "none",

  background:
    "#2167D5",

  color:
    "#FFFFFF",

  padding:
    "13px",

  borderRadius:
    "10px",

  fontWeight:
    "800",

  fontSize:
    "15px",

  cursor:
    "pointer",

  boxShadow:
    "0 5px 13px rgba(33,103,213,.18)"

};


// ==================================================
// AVISO EXPEDIENTE
// ==================================================

const expedienteNotice = {

  display:
    "flex",

  alignItems:
    "flex-start",

  gap:
    "14px",

  padding:
    "20px",

  background:
    "#F5F8FF",

  border:
    "1px solid #DCE6F5",

  borderRadius:
    "16px"

};


const expedienteNoticeIcon = {

  width:
    "48px",

  height:
    "48px",

  minWidth:
    "48px",

  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  borderRadius:
    "13px",

  background:
    "#E8F1FF",

  fontSize:
    "22px"

};


const expedienteNoticeContent = {

  flex:
    1

};


const expedienteNoticeTitle = {

  margin:
    "0 0 7px",

  fontSize:
    "16px",

  color:
    "#263238"

};


const expedienteNoticeText = {

  margin:
    "4px 0",

  color:
    "#607D8B",

  fontSize:
    "13px",

  lineHeight:
    1.6

};


// ==================================================
// AVISO INFORMATIVO
// ==================================================

const infoNotice = {

  display:
    "flex",

  alignItems:
    "flex-start",

  gap:
    "13px",

  background:
    "#FFF9E8",

  border:
    "1px solid #F3E2A5",

  borderRadius:
    "14px",

  padding:
    "17px",

  color:
    "#6B5A16"

};


const infoNoticeIcon = {

  width:
    "40px",

  height:
    "40px",

  minWidth:
    "40px",

  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  background:
    "#FFF3C4",

  borderRadius:
    "11px",

  fontSize:
    "19px"

};


const infoNoticeText = {

  margin:
    "5px 0 0",

  fontSize:
    "13px",

  lineHeight:
    1.55

};


// ==================================================
// FOOTER
// ==================================================

const footer = {

  borderTop:
    "1px solid #E1E8EF",

  marginTop:
    "45px",

  paddingTop:
    "18px",

  display:
    "flex",

  justifyContent:
    "space-between",

  gap:
    "15px",

  flexWrap:
    "wrap",

  color:
    "#90A4AE",

  fontSize:
    "12px"

};


// ==================================================
// CARGANDO / ERROR
// ==================================================

const loadingContainer = {

  textAlign:
    "center",

  padding:
    "80px 20px",

  color:
    "#607D8B"

};


const loadingIcon = {

  fontSize:
    "40px",

  marginBottom:
    "10px"

};


const errorContainer = {

  maxWidth:
    "600px",

  margin:
    "80px auto",

  textAlign:
    "center",

  background:
    "#FFFFFF",

  padding:
    "40px",

  borderRadius:
    "16px",

  boxShadow:
    "0 5px 20px rgba(0,0,0,.08)"

};


const errorIcon = {

  fontSize:
    "45px",

  marginBottom:
    "10px"

};


export default SeguimientoProspecto;