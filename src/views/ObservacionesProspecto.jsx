// ==================================================
// src/views/ObservacionesProspecto.jsx
// ==================================================

import React, {
  useEffect,
  useMemo,
  useState
} from "react";

import axios from "axios";

import {
  useNavigate,
  useParams
} from "react-router-dom";

import {
  getToken
} from "../services/AuthService";

const API_URL = import.meta.env.VITE_API_URL || (window.location.protocol === 'https:' ? 'https://reflejoyalma.com' : `http://${window.location.hostname}:5000`);

// ==================================================
// OBSERVACIONES RH DEL PROSPECTO
// ==================================================

const ObservacionesProspecto = () => {
  const {
    idProspecto
  } = useParams();

  const navigate =
    useNavigate();

  // ==================================================
  // TOKEN
  // ==================================================

  const token =
    getToken();

  const config =
    useMemo(
      () => ({
        headers: {
          Authorization:
            `Bearer ${token}`
        }
      }),
      [token]
    );

  // ==================================================
  // FORMULARIO INICIAL
  // ==================================================

  const formularioInicial = {
    tipo:
      "general",

    titulo:
      "",

    observacion:
      "",

    relevancia:
      "informativa",

    fecha:
      ""
  };

  // ==================================================
  // ESTADOS
  // ==================================================

  const [
    prospecto,
    setProspecto
  ] = useState(null);

  const [
    form,
    setForm
  ] = useState(
    formularioInicial
  );

  const [
    cargando,
    setCargando
  ] = useState(true);

  const [
    guardando,
    setGuardando
  ] = useState(false);

  const [
    mensaje,
    setMensaje
  ] = useState("");

  const [
    error,
    setError
  ] = useState("");

  // ==================================================
  // CARGAR DATOS BÁSICOS DEL PROSPECTO
  //
  // El endpoint puede regresar también observaciones,
  // pero NO las mostramos aquí.
  //
  // El historial se consulta en el expediente final.
  // ==================================================

  const cargarProspecto =
    async () => {
      try {
        setCargando(true);
        setError("");

        if (!token) {
          throw new Error(
            "Tu sesión no es válida. Inicia sesión nuevamente."
          );
        }

        const respuesta =
          await axios.get(
            `${API_URL}/api/prospectos/${idProspecto}/observaciones`,
            config
          );

        setProspecto(
          respuesta.data?.prospecto ||
          null
        );
      } catch (err) {
        console.error(
          "❌ Error cargando observaciones RH:",
          err
        );

        console.error(
          "📦 Respuesta backend:",
          err.response?.data
        );

        console.error(
          "📡 Status:",
          err.response?.status
        );

        setError(
          err.response?.data?.message ||
          err.response?.data?.error ||
          err.message ||
          "No fue posible cargar la información del prospecto."
        );
      } finally {
        setCargando(false);
      }
    };

  // ==================================================
  // CARGAR AL ENTRAR
  // ==================================================

  useEffect(
    () => {
      if (idProspecto) {
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

  const cambiarCampo =
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

      setMensaje("");
      setError("");
    };

  // ==================================================
  // GUARDAR OBSERVACIÓN
  // ==================================================

  const guardarObservacion =
    async e => {
      e.preventDefault();

      if (guardando) {
        return;
      }

      const observacionTexto =
        String(
          form.observacion ||
          ""
        ).trim();

      if (!observacionTexto) {
        setError(
          "La observación es obligatoria."
        );

        return;
      }

      try {
        setGuardando(true);
        setMensaje("");
        setError("");

        if (!token) {
          throw new Error(
            "Tu sesión no es válida."
          );
        }

        const payload = {
          tipo:
            form.tipo,

          titulo:
            String(
              form.titulo ||
              ""
            ).trim() ||
            null,

          observacion:
            observacionTexto,

          relevancia:
            form.relevancia,

          fecha:
            form.fecha ||
            null
        };

        console.log(
          "📤 Guardando observación RH:",
          {
            idProspecto,
            payload
          }
        );

        const respuesta =
          await axios.post(
            `${API_URL}/api/prospectos/${idProspecto}/observaciones`,
            payload,
            config
          );

        console.log(
          "✅ Observación RH guardada:",
          respuesta.data
        );

        setMensaje(
          respuesta.data?.message ||
          "Observación registrada correctamente."
        );

        setForm(
          formularioInicial
        );

        // Actualizamos los datos básicos del prospecto.
        // No mostramos aquí el historial.

        await cargarProspecto();
      } catch (err) {
        console.error(
          "❌ Error guardando observación RH:",
          err
        );

        console.error(
          "📦 Respuesta backend:",
          err.response?.data
        );

        console.error(
          "📡 Status:",
          err.response?.status
        );

        setError(
          err.response?.data?.message ||
          err.response?.data?.error ||
          err.message ||
          "No fue posible guardar la observación."
        );
      } finally {
        setGuardando(false);
      }
    };

  // ==================================================
  // CARGANDO
  // ==================================================

  if (cargando) {
    return (
      <div style={styles.page}>
        <div style={styles.container}>
          <div style={styles.loadingCard}>
            <div style={styles.loadingIcon}>
              📝
            </div>

            <h2>
              Observaciones RH
            </h2>

            <p style={styles.loadingText}>
              Cargando información del prospecto...
            </p>
          </div>
        </div>
      </div>
    );
  }

  // ==================================================
  // VISTA
  // ==================================================

  return (
    <div style={styles.page}>
      <div style={styles.container}>

        {/* BOTÓN VOLVER */}

        <button
          type="button"
          style={styles.backButton}
          onClick={() =>
            navigate(
              `/prospecto/${idProspecto}`
            )
          }
        >
          <span style={styles.backArrow}>
            ←
          </span>

          Volver al expediente
        </button>

        {/* ENCABEZADO */}

        <div style={styles.header}>
          <div>
            <div style={styles.headerLabel}>
              RECURSOS HUMANOS
            </div>

            <h1 style={styles.title}>
              📝 Observaciones RH
            </h1>

            <p style={styles.subtitle}>
              Registra información relevante obtenida
              durante el proceso de evaluación y selección.
            </p>
          </div>
        </div>

        {/* PROSPECTO */}

        {prospecto && (
          <div style={styles.prospectCard}>
            <div style={styles.avatar}>
              {prospecto.nombre
                ?.charAt(0)
                ?.toUpperCase() ||
                "P"}
            </div>

            <div>
              <div style={styles.prospectLabel}>
                PROSPECTO
              </div>

              <h2 style={styles.prospectName}>
                {prospecto.nombre}
              </h2>

              <div style={styles.meta}>
                🆔{" "}
                {prospecto.id_mirror ||
                  "Sin ID MirrorSoul"}
              </div>

              <div style={styles.meta}>
                💼{" "}
                {prospecto.puesto ||
                  "Puesto no especificado"}
              </div>

              <div style={styles.meta}>
                ✉️{" "}
                {prospecto.correo ||
                  "Sin correo"}
              </div>
            </div>
          </div>
        )}

        {/* MENSAJE */}

        {mensaje && (
          <div style={styles.success}>
            <span style={styles.messageIcon}>
              ✅
            </span>

            <div>
              <strong>
                Observación registrada
              </strong>

              <div style={styles.messageText}>
                {mensaje}
              </div>

              <div style={styles.messageSecondary}>
                La información quedó almacenada
                para el expediente final del proceso.
              </div>
            </div>
          </div>
        )}

        {/* ERROR */}

        {error && (
          <div style={styles.error}>
            ❌ {error}
          </div>
        )}

        {/* FORMULARIO */}

        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <div style={styles.cardHeaderIcon}>
              ➕
            </div>

            <div>
              <h2 style={styles.cardTitle}>
                Nueva observación
              </h2>

              <p style={styles.cardSubtitle}>
                Registra información relevante
                encontrada durante cualquier etapa
                del proceso de selección.
              </p>
            </div>
          </div>

          <form
            onSubmit={
              guardarObservacion
            }
          >

            {/* TIPO / RELEVANCIA */}

            <div style={styles.gridTwo}>

              <div style={styles.field}>
                <label style={styles.label}>
                  Tipo
                </label>

                <select
                  name="tipo"
                  value={
                    form.tipo
                  }
                  onChange={
                    cambiarCampo
                  }
                  style={styles.input}
                >
                  <option value="general">
                    General
                  </option>

                  <option value="entrevista">
                    Entrevista
                  </option>

                  <option value="conducta">
                    Conducta
                  </option>

                  <option value="experiencia">
                    Experiencia
                  </option>

                  <option value="competencias">
                    Competencias
                  </option>

                  <option value="documentacion">
                    Documentación
                  </option>

                  <option value="referencias">
                    Referencias
                  </option>

                  <option value="proceso">
                    Proceso
                  </option>
                </select>
              </div>

              <div style={styles.field}>
                <label style={styles.label}>
                  Relevancia
                </label>

                <select
                  name="relevancia"
                  value={
                    form.relevancia
                  }
                  onChange={
                    cambiarCampo
                  }
                  style={styles.input}
                >
                  <option value="informativa">
                    Informativa
                  </option>

                  <option value="fortaleza">
                    Fortaleza
                  </option>

                  <option value="atencion">
                    Atención
                  </option>
                </select>
              </div>
            </div>

            {/* TÍTULO / FECHA */}

            <div style={styles.gridTwo}>
              <div style={styles.field}>
                <label style={styles.label}>
                  Título
                </label>

                <input
                  type="text"
                  name="titulo"
                  value={
                    form.titulo
                  }
                  onChange={
                    cambiarCampo
                  }
                  style={styles.input}
                  placeholder="Ej. Trabajo bajo presión"
                />
              </div>

              <div style={styles.field}>
                <label style={styles.label}>
                  Fecha
                </label>

                <input
                  type="datetime-local"
                  name="fecha"
                  value={
                    form.fecha
                  }
                  onChange={
                    cambiarCampo
                  }
                  style={styles.input}
                />

                <small style={styles.helpText}>
                  Si la dejas vacía,
                  se utilizará la fecha actual.
                </small>
              </div>
            </div>

            {/* OBSERVACIÓN */}

            <div style={styles.field}>
              <label style={styles.label}>
                Observación *
              </label>

              <textarea
                name="observacion"
                value={
                  form.observacion
                }
                onChange={
                  cambiarCampo
                }
                style={styles.textarea}
                rows={6}
                placeholder="Escribe aquí la observación del proceso..."
                required
              />
            </div>

            {/* BOTÓN GUARDAR */}

            <div style={styles.actions}>
              <button
                type="submit"
                style={{
                  ...styles.primaryButton,

                  opacity:
                    guardando
                      ? 0.7
                      : 1,

                  cursor:
                    guardando
                      ? "not-allowed"
                      : "pointer"
                }}
                disabled={
                  guardando
                }
              >
                {guardando
                  ? "⏳ Guardando..."
                  : "➕ Registrar observación"}
              </button>
            </div>
          </form>
        </div>

        {/* AVISO EXPEDIENTE FINAL */}

        <div style={styles.expedienteCard}>
          <div style={styles.expedienteIcon}>
            📂
          </div>

          <div style={styles.expedienteContent}>
            <h3 style={styles.expedienteTitle}>
              Observaciones guardadas en el expediente
            </h3>

            <p style={styles.expedienteText}>
              Las observaciones registradas en esta
              sección se almacenan automáticamente
              como parte del proceso de selección.
            </p>

            <p style={styles.expedienteText}>
              El historial completo se mostrará en el
              expediente final junto con entrevistas,
              pruebas psicométricas, seguimiento,
              documentos y demás evidencias.
            </p>
          </div>
        </div>

        {/* AVISO RH */}

        <div style={styles.infoCard}>
          <div style={styles.infoIcon}>
            💡
          </div>

          <div>
            <strong>
              Observaciones de Recursos Humanos
            </strong>

            <p style={styles.infoText}>
              Utiliza esta sección para registrar
              información que complemente el proceso,
              por ejemplo conducta observada,
              experiencia, competencias,
              documentación, referencias o aspectos
              importantes detectados por RH.
            </p>
          </div>
        </div>

        {/* FOOTER */}

        <footer style={styles.pageFooter}>
          <span>
            🧠 MirrorSoul
          </span>

          <span>
            Recursos Humanos · Observaciones
          </span>
        </footer>
      </div>
    </div>
  );
};

// ==================================================
// ESTILOS
// ==================================================

const styles = {
  page: {
    minHeight: "100vh",
    background: "#f6f8fb",
    padding: "30px 20px",
    fontFamily:
      "'Segoe UI', Arial, sans-serif",
    color: "#263238"
  },

  container: {
    maxWidth: "1100px",
    margin: "0 auto"
  },

  backButton: {
    border: "none",
    background:
      "linear-gradient(135deg,#64B5F6,#1976D2)",
    color: "#ffffff",
    padding: "10px 21px",
    marginBottom: "20px",
    borderRadius: "30px",
    cursor: "pointer",
    fontWeight: "700",
    fontSize: "14px",
    display: "inline-flex",
    alignItems: "center",
    justifyContent: "center",
    gap: "8px",
    boxShadow:
      "0 5px 15px rgba(25,118,210,.26)",
    transition:
      "transform .2s ease, box-shadow .2s ease"
  },

  backArrow: {
    fontSize: "19px",
    lineHeight: 1
  },

  header: {
    marginBottom: "22px"
  },

  headerLabel: {
    color: "#607D8B",
    fontSize: "11px",
    fontWeight: "800",
    letterSpacing: "1.3px",
    marginBottom: "5px"
  },

  title: {
    margin: "0 0 6px",
    fontSize: "30px",
    color: "#263238"
  },

  subtitle: {
    margin: 0,
    color: "#667085",
    lineHeight: 1.55
  },

  prospectCard: {
    background: "#ffffff",
    borderRadius: "16px",
    padding: "20px",
    display: "flex",
    alignItems: "center",
    gap: "18px",
    marginBottom: "22px",
    border: "1px solid #E1E8EF",
    boxShadow:
      "0 4px 18px rgba(0,0,0,.05)"
  },

  avatar: {
    width: "58px",
    height: "58px",
    minWidth: "58px",
    borderRadius: "16px",
    background:
      "linear-gradient(135deg,#E8F1FF,#EEE8FF)",
    color: "#2167D5",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "25px",
    fontWeight: "800"
  },

  prospectLabel: {
    fontSize: "10px",
    fontWeight: "800",
    letterSpacing: "1px",
    color: "#90A4AE"
  },

  prospectName: {
    margin: "3px 0 8px",
    color: "#263238"
  },

  meta: {
    color: "#667085",
    fontSize: "14px",
    marginTop: "4px"
  },

  card: {
    background: "#ffffff",
    borderRadius: "18px",
    padding: "26px",
    marginBottom: "24px",
    border: "1px solid #E1E8EF",
    boxShadow:
      "0 6px 20px rgba(30,60,90,.05)"
  },

  cardHeader: {
    display: "flex",
    alignItems: "flex-start",
    gap: "13px",
    marginBottom: "22px"
  },

  cardHeaderIcon: {
    width: "46px",
    height: "46px",
    minWidth: "46px",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    borderRadius: "13px",
    background: "#EEF4FF",
    fontSize: "20px"
  },

  cardTitle: {
    margin: "0 0 5px",
    fontSize: "21px"
  },

  cardSubtitle: {
    margin: 0,
    color: "#667085",
    lineHeight: 1.5
  },

  gridTwo: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(240px,1fr))",
    gap: "16px"
  },

  field: {
    marginBottom: "17px"
  },

  label: {
    display: "block",
    marginBottom: "7px",
    fontWeight: "700",
    fontSize: "14px",
    color: "#344054"
  },

  input: {
    width: "100%",
    boxSizing: "border-box",
    border: "1px solid #d0d5dd",
    borderRadius: "11px",
    padding: "12px 13px",
    fontSize: "15px",
    background: "#ffffff",
    color: "#263238",
    fontFamily: "inherit"
  },

  textarea: {
    width: "100%",
    boxSizing: "border-box",
    border: "1px solid #d0d5dd",
    borderRadius: "11px",
    padding: "13px",
    fontSize: "15px",
    resize: "vertical",
    fontFamily: "inherit",
    lineHeight: 1.5
  },

  helpText: {
    display: "block",
    marginTop: "6px",
    color: "#667085",
    fontSize: "12px"
  },

  actions: {
    display: "flex",
    justifyContent: "flex-end",
    flexWrap: "wrap",
    gap: "10px",
    marginTop: "5px"
  },

  primaryButton: {
    border: "none",
    borderRadius: "30px",
    background:
      "linear-gradient(135deg,#3B82F6,#2563EB)",
    color: "#ffffff",
    padding: "12px 22px",
    cursor: "pointer",
    fontWeight: "800",
    fontSize: "14px",
    boxShadow:
      "0 5px 14px rgba(37,99,235,.22)"
  },

  success: {
    display: "flex",
    alignItems: "flex-start",
    gap: "10px",
    background: "#ECF9EF",
    border: "1px solid #B7E4C7",
    borderRadius: "12px",
    padding: "14px",
    marginBottom: "18px",
    color: "#27843A"
  },

  messageIcon: {
    fontSize: "19px"
  },

  messageText: {
    marginTop: "3px",
    fontSize: "13px"
  },

  messageSecondary: {
    marginTop: "3px",
    fontSize: "12px",
    color: "#4B8057"
  },

  error: {
    background: "#fef3f2",
    border: "1px solid #fecdca",
    color: "#B42318",
    borderRadius: "10px",
    padding: "13px",
    marginBottom: "18px"
  },

  expedienteCard: {
    display: "flex",
    alignItems: "flex-start",
    gap: "14px",
    background: "#F5F8FF",
    border: "1px solid #DCE6F5",
    borderRadius: "16px",
    padding: "20px",
    marginBottom: "20px"
  },

  expedienteIcon: {
    width: "48px",
    height: "48px",
    minWidth: "48px",
    borderRadius: "13px",
    background: "#E8F1FF",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "22px"
  },

  expedienteContent: {
    flex: 1
  },

  expedienteTitle: {
    margin: "0 0 7px",
    color: "#263238",
    fontSize: "16px"
  },

  expedienteText: {
    margin: "4px 0",
    color: "#607D8B",
    fontSize: "13px",
    lineHeight: 1.6
  },

  infoCard: {
    display: "flex",
    alignItems: "flex-start",
    gap: "13px",
    background: "#FFF9E8",
    border: "1px solid #F3E2A5",
    borderRadius: "14px",
    padding: "17px",
    color: "#6B5A16"
  },

  infoIcon: {
    width: "40px",
    height: "40px",
    minWidth: "40px",
    borderRadius: "11px",
    background: "#FFF3C4",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "19px"
  },

  infoText: {
    margin: "5px 0 0",
    fontSize: "13px",
    lineHeight: 1.55
  },

  pageFooter: {
    borderTop: "1px solid #E1E8EF",
    marginTop: "40px",
    paddingTop: "18px",
    display: "flex",
    justifyContent: "space-between",
    gap: "15px",
    flexWrap: "wrap",
    color: "#90A4AE",
    fontSize: "12px"
  },

  loadingCard: {
    maxWidth: "500px",
    margin: "80px auto",
    textAlign: "center",
    background: "#ffffff",
    padding: "35px",
    borderRadius: "18px",
    boxShadow:
      "0 5px 20px rgba(0,0,0,.07)"
  },

  loadingIcon: {
    fontSize: "40px",
    marginBottom: "8px"
  },

  loadingText: {
    color: "#667085"
  }
};

export default ObservacionesProspecto;