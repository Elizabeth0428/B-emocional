// ==================================================
// src/views/EntrevistasProspecto.jsx
// ==================================================

import React, { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { getToken } from "../services/AuthService";
import VideoRecorder from "../components/VideoRecorder";

const API_URL = import.meta.env.VITE_API_URL || (window.location.protocol === 'https:' ? 'https://reflejoyalma.com' : `http://${window.location.hostname}:5000`);

// ==================================================
// ENTREVISTAS DEL PROSPECTO
// ==================================================

const EntrevistasProspecto = () => {
  const navigate = useNavigate();
  const { idProspecto } = useParams();

  // ==================================================
  // ESTADOS
  // ==================================================

  const [prospecto, setProspecto] = useState(null);
  const [loading, setLoading] = useState(true);
  const [guardando, setGuardando] = useState(false);
  const [error, setError] = useState("");
  const [mensaje, setMensaje] = useState("");

  const [entrevistaActual, setEntrevistaActual] =
    useState(null);

  const [creandoSalaId, setCreandoSalaId] =
    useState(null);

  const [
    entrevistaPresencialActiva,
    setEntrevistaPresencialActiva
  ] = useState(null);

  const [transcribiendoId, setTranscribiendoId] =
    useState(null);

  // ==================================================
  // FORMULARIO
  // ==================================================

  const formularioInicial = {
    tipo_entrevista: "Entrevista inicial",
    modalidad: "presencial",
    fecha_entrevista: "",
    motivo: "",
    observaciones: ""
  };

  const [form, setForm] =
    useState(formularioInicial);

  // ==================================================
  // CARGAR PROSPECTO
  // ==================================================

  useEffect(() => {
    if (!idProspecto) {
      setLoading(false);
      setError(
        "No se recibió el identificador del prospecto."
      );
      return;
    }

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
              `${API_URL}/api/prospectos/${idProspecto}`,
              {
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
              .catch(() => ({}));

          if (!response.ok) {
            throw new Error(
              data.message ||
              "No se pudo cargar el prospecto."
            );
          }

          setProspecto(
            data.prospecto ||
            data.data ||
            data
          );

        } catch (err) {
          console.error(
            "❌ Error cargando prospecto:",
            err
          );

          setError(
            err.message ||
            "No fue posible cargar el prospecto."
          );

        } finally {
          setLoading(false);
        }
      };

    cargarProspecto();

  }, [idProspecto]);

  // ==================================================
  // CAMBIAR FORMULARIO
  // ==================================================

  const handleChange =
    event => {
      const {
        name,
        value
      } = event.target;

      setForm(
        prev => ({
          ...prev,
          [name]: value
        })
      );

      setMensaje("");
    };

  // ==================================================
  // LIMPIAR FORMULARIO
  // ==================================================

  const limpiarFormulario =
    () => {
      setForm(
        formularioInicial
      );
    };

  // ==================================================
  // BUSCAR ENTREVISTA RECIÉN CREADA
  // ==================================================

  const buscarEntrevistaCreada =
    async token => {
      const response =
        await fetch(
          `${API_URL}/api/prospectos/${idProspecto}/entrevistas`,
          {
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
          .catch(() => ({}));

      if (!response.ok) {
        return null;
      }

      const lista =
        Array.isArray(
          data.entrevistas
        )
          ? data.entrevistas
          : [];

      if (!lista.length) {
        return null;
      }

      return [...lista]
        .sort(
          (a, b) =>
            Number(
              b.id_entrevista || 0
            ) -
            Number(
              a.id_entrevista || 0
            )
        )[0];
    };

  // ==================================================
  // GUARDAR ENTREVISTA
  // ==================================================

  const handleSubmit =
    async event => {
      event.preventDefault();

      if (guardando) {
        return;
      }

      if (!form.fecha_entrevista) {
        setMensaje(
          "❌ La fecha y hora son obligatorias."
        );
        return;
      }

      try {
        setGuardando(true);
        setMensaje("");

        const token =
          getToken();

        if (!token) {
          throw new Error(
            "Tu sesión no es válida."
          );
        }

        const body = {
          tipo_entrevista:
            form.tipo_entrevista,

          modalidad:
            form.modalidad,

          fecha_entrevista:
            form.fecha_entrevista,

          motivo:
            String(
              form.motivo || ""
            ).trim(),

          observaciones:
            String(
              form.observaciones || ""
            ).trim(),

          // Valores internos.
          // No se muestran aquí como resultado.
          resultado:
            "pendiente",

          estatus:
            "programada"
        };

        const response =
          await fetch(
            `${API_URL}/api/prospectos/${idProspecto}/entrevistas`,
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
                JSON.stringify(
                  body
                )
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
            "No se pudo guardar la entrevista."
          );
        }

        let entrevista =
          data.entrevista ||
          data.data ||
          null;

        if (
          !entrevista?.id_entrevista &&
          data.id_entrevista
        ) {
          entrevista = {
            id_entrevista:
              data.id_entrevista,

            ...body
          };
        }

        // Si el backend no devuelve el objeto,
        // obtenemos la entrevista recién creada.
        if (
          !entrevista?.id_entrevista
        ) {
          entrevista =
            await buscarEntrevistaCreada(
              token
            );
        }

        if (
          !entrevista?.id_entrevista
        ) {
          throw new Error(
            "La entrevista se guardó, pero no se pudo obtener su identificador para realizarla."
          );
        }

        setEntrevistaActual(
          entrevista
        );

        setMensaje(
          "✅ Entrevista registrada. Ya puedes realizarla."
        );

        limpiarFormulario();

      } catch (err) {
        console.error(
          "❌ Error guardando entrevista:",
          err
        );

        setMensaje(
          `❌ ${
            err.message ||
            "No se pudo guardar la entrevista."
          }`
        );

      } finally {
        setGuardando(false);
      }
    };

  // ==================================================
  // ACTUALIZAR ESTATUS
  // ==================================================

  const actualizarEstatusEntrevista =
    async (
      idEntrevista,
      estatus
    ) => {
      try {
        const token =
          getToken();

        if (!token) {
          return;
        }

        await fetch(
          `${API_URL}/api/prospectos/${idProspecto}/entrevistas/${idEntrevista}`,
          {
            method:
              "PUT",

            headers: {
              Authorization:
                `Bearer ${token}`,

              "Content-Type":
                "application/json"
            },

            body:
              JSON.stringify({
                estatus
              })
          }
        );

      } catch (err) {
        console.warn(
          "⚠️ No se pudo actualizar el estatus:",
          err
        );
      }
    };

  // ==================================================
  // VIDEOLLAMADA
  // ==================================================

  const iniciarVideollamadaRH =
    async entrevista => {
      if (
        !entrevista?.id_entrevista
      ) {
        setMensaje(
          "❌ No se pudo identificar la entrevista."
        );
        return;
      }

      try {
        setCreandoSalaId(
          entrevista.id_entrevista
        );

        setMensaje("");

        const token =
          getToken();

        if (!token) {
          throw new Error(
            "Tu sesión no es válida."
          );
        }

        const response =
          await fetch(
            `${API_URL}/api/prospectos/${idProspecto}/entrevistas/${entrevista.id_entrevista}/videollamada`,
            {
              method:
                "POST",

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
            "No se pudo preparar la videollamada."
          );
        }

        if (!data.sala) {
          throw new Error(
            "El backend no devolvió una sala válida."
          );
        }

        navigate(
          `/SalaVideollamadaRH/${data.sala}`
        );

      } catch (err) {
        console.error(
          "❌ Error iniciando videollamada:",
          err
        );

        setMensaje(
          `❌ ${
            err.message ||
            "No se pudo iniciar la videollamada."
          }`
        );

      } finally {
        setCreandoSalaId(
          null
        );
      }
    };

  // ==================================================
  // ENTREVISTA PRESENCIAL
  // ==================================================

  const iniciarEntrevistaPresencial =
    entrevista => {
      if (
        entrevistaPresencialActiva ===
        entrevista.id_entrevista
      ) {
        setEntrevistaPresencialActiva(
          null
        );
        return;
      }

      setEntrevistaPresencialActiva(
        entrevista.id_entrevista
      );

      setMensaje("");
    };

  // ==================================================
  // TRANSCRIBIR AUDIO
  // ==================================================

  const transcribirGrabacion =
    async (
      archivo,
      idEntrevista
    ) => {
      const idVideo =
        Number(
          archivo?.id_video_rh ||
          archivo?.id_video ||
          0
        );

      if (!idVideo) {
        setMensaje(
          "⚠️ La grabación se guardó, pero no se recibió el identificador para transcribirla."
        );
        return;
      }

      try {
        setTranscribiendoId(
          idEntrevista
        );

        setMensaje(
          "🎙️ Grabación guardada. Generando transcripción..."
        );

        const token =
          getToken();

        if (!token) {
          throw new Error(
            "Tu sesión no es válida."
          );
        }

        const response =
          await fetch(
            `${API_URL}/api/archivos-rh/${idVideo}/transcribir`,
            {
              method:
                "POST",

              headers: {
                Authorization:
                  `Bearer ${token}`
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
            data.error ||
            "No se pudo transcribir la entrevista."
          );
        }

        await actualizarEstatusEntrevista(
          idEntrevista,
          "realizada"
        );

        setMensaje(
          "✅ Entrevista realizada. Audio y transcripción quedaron guardados en el expediente."
        );

        setEntrevistaPresencialActiva(
          null
        );

        setEntrevistaActual(
          null
        );

      } catch (err) {
        console.error(
          "❌ Error transcribiendo:",
          err
        );

        setMensaje(
          `⚠️ El audio fue guardado, pero la transcripción no pudo completarse: ${
            err.message ||
            "Error desconocido"
          }`
        );

      } finally {
        setTranscribiendoId(
          null
        );
      }
    };

  // ==================================================
  // CARGANDO
  // ==================================================

  if (loading) {
    return (
      <div style={loadingContainer}>
        <div style={loadingIcon}>
          ⏳
        </div>

        <h3>
          Cargando entrevistas...
        </h3>
      </div>
    );
  }

  // ==================================================
  // ERROR
  // ==================================================

  if (error) {
    return (
      <div style={errorContainer}>
        <div style={errorIcon}>
          ⚠️
        </div>

        <h2>
          No se pudo abrir entrevistas
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
          ← Regresar al expediente
        </button>
      </div>
    );
  }

  // ==================================================
  // VISTA
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
          ← Regresar al expediente
        </button>

        <div style={headerInfo}>
          <div style={headerLabel}>
            PROCESO DE SELECCIÓN
          </div>

          <h1 style={title}>
            📅 Entrevistas
          </h1>

          <p style={subtitle}>
            Registra una entrevista y,
            al guardarla, realiza la
            videollamada o la grabación
            presencial.
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
              `Prospecto #${idProspecto}`}
          </div>
        </div>
      </div>

      {/* ==================================================
          REGISTRAR ENTREVISTA
      ================================================== */}

      <section style={section}>
        <div style={formCard}>

          <h2 style={sectionTitle}>
            ➕ Registrar entrevista
          </h2>

          <p style={sectionDescription}>
            Registra los datos necesarios.
            Después de guardar aparecerá
            únicamente la herramienta para
            realizar esta entrevista.
          </p>

          <form
            onSubmit={handleSubmit}
          >

            <div style={twoColumns}>

              {/* ==========================================
                  TIPO
              ========================================== */}

              <div style={field}>
                <label style={label}>
                  Tipo de entrevista
                </label>

                <select
                  name="tipo_entrevista"
                  value={
                    form.tipo_entrevista
                  }
                  onChange={
                    handleChange
                  }
                  style={input}
                >
                  <option value="Entrevista inicial">
                    Entrevista inicial
                  </option>

                  <option value="Entrevista técnica">
                    Entrevista técnica
                  </option>

                  <option value="Entrevista de seguimiento">
                    Entrevista de seguimiento
                  </option>

                  <option value="Segunda entrevista">
                    Segunda entrevista
                  </option>

                  <option value="Entrevista final">
                    Entrevista final
                  </option>
                </select>
              </div>

              {/* ==========================================
                  MODALIDAD
              ========================================== */}

              <div style={field}>
                <label style={label}>
                  Modalidad
                </label>

                <select
                  name="modalidad"
                  value={
                    form.modalidad
                  }
                  onChange={
                    handleChange
                  }
                  style={input}
                >
                  <option value="presencial">
                    🏢 Presencial
                  </option>

                  <option value="videollamada">
                    🎥 Videollamada
                  </option>
                </select>
              </div>

            </div>

            {/* ==========================================
                FECHA
            ========================================== */}

            <div style={field}>
              <label style={label}>
                Fecha y hora *
              </label>

              <input
                type="datetime-local"
                name="fecha_entrevista"
                value={
                  form.fecha_entrevista
                }
                onChange={
                  handleChange
                }
                style={input}
                required
              />
            </div>

            {/* ==========================================
                MOTIVO
            ========================================== */}

            <div style={field}>
              <label style={label}>
                Motivo / objetivo
              </label>

              <input
                type="text"
                name="motivo"
                value={
                  form.motivo
                }
                onChange={
                  handleChange
                }
                placeholder="Ej. Conocer experiencia y competencias del candidato"
                style={input}
              />
            </div>

            {/* ==========================================
                OBSERVACIONES
            ========================================== */}

            <div style={field}>
              <label style={label}>
                Observaciones
              </label>

              <textarea
                name="observaciones"
                value={
                  form.observaciones
                }
                onChange={
                  handleChange
                }
                placeholder="Registra información relevante de la entrevista..."
                rows={4}
                style={textarea}
              />
            </div>

            {/* ==========================================
                MENSAJE
            ========================================== */}

            {mensaje && (
              <div
                style={
                  obtenerEstiloMensaje(
                    mensaje
                  )
                }
              >
                {mensaje}
              </div>
            )}

            {/* ==========================================
                GUARDAR
            ========================================== */}

            <div style={formActions}>
              <button
                type="submit"
                disabled={
                  guardando
                }
                style={{
                  ...saveButton,

                  opacity:
                    guardando
                      ? 0.65
                      : 1
                }}
              >
                {guardando
                  ? "⏳ Guardando..."
                  : "💾 Guardar entrevista"}
              </button>
            </div>

          </form>
        </div>
      </section>

      {/* ==================================================
          REALIZAR ENTREVISTA RECIÉN CREADA
      ================================================== */}

      {entrevistaActual && (

        <section style={section}>
          <div style={readyCard}>

            <div style={readyHeader}>
              <div>
                <div style={readyLabel}>
                  ENTREVISTA LISTA PARA REALIZAR
                </div>

                <h2 style={readyTitle}>
                  {entrevistaActual.tipo_entrevista ||
                    "Entrevista"}
                </h2>

                <div style={readyMeta}>
                  {entrevistaActual.modalidad ===
                  "videollamada"
                    ? "🎥 Videollamada"
                    : "🏢 Presencial"}
                </div>
              </div>
            </div>

            {/* ==========================================
                VIDEOLLAMADA
            ========================================== */}

            {entrevistaActual.modalidad ===
            "videollamada" ? (

              <div style={actionBox}>
                <div>
                  <strong>
                    🎥 Entrevista a distancia
                  </strong>

                  <p style={actionText}>
                    Genera la sala para iniciar
                    la videollamada con el prospecto.
                  </p>
                </div>

                <button
                  type="button"

                  disabled={
                    creandoSalaId ===
                    entrevistaActual.id_entrevista
                  }

                  onClick={() =>
                    iniciarVideollamadaRH(
                      entrevistaActual
                    )
                  }

                  style={videoCallButton}
                >
                  {creandoSalaId ===
                  entrevistaActual.id_entrevista
                    ? "⏳ Generando sala..."
                    : "🎥 Iniciar videollamada"}
                </button>
              </div>

            ) : (

              <>
                {/* ========================================
                    AUDIO PRESENCIAL
                ======================================== */}

                <div style={actionBox}>
                  <div>
                    <strong>
                      🎙️ Entrevista presencial
                    </strong>

                    <p style={actionText}>
                      Inicia la grabación de audio
                      mientras realizas la entrevista.
                    </p>
                  </div>

                  <button
                    type="button"

                    onClick={() =>
                      iniciarEntrevistaPresencial(
                        entrevistaActual
                      )
                    }

                    style={audioButton}
                  >
                    {entrevistaPresencialActiva ===
                    entrevistaActual.id_entrevista
                      ? "Cerrar grabador"
                      : "🎙️ Grabar entrevista"}
                  </button>
                </div>

                {/* ========================================
                    GRABADOR
                ======================================== */}

                {entrevistaPresencialActiva ===
                  entrevistaActual.id_entrevista && (

                  <div style={recorderWorkspace}>

                    <div style={recorderHeader}>
                      <div style={recorderIcon}>
                        🎙️
                      </div>

                      <div>
                        <strong>
                          Grabación de audio
                        </strong>

                        <p style={recorderDescription}>
                          Al finalizar, MirrorSoul
                          guardará el audio y generará
                          la transcripción para el
                          expediente.
                        </p>
                      </div>
                    </div>

                    <VideoRecorder
                      contexto="rh"

                      idProspecto={
                        Number(
                          idProspecto
                        )
                      }

                      idEntrevista={
                        Number(
                          entrevistaActual.id_entrevista
                        )
                      }

                      tipo="audio"

                      onSaved={data =>
                        transcribirGrabacion(
                          data,
                          entrevistaActual.id_entrevista
                        )
                      }
                    />

                    {transcribiendoId ===
                      entrevistaActual.id_entrevista && (

                      <div style={processingBox}>
                        ⏳ Guardando y
                        transcribiendo audio...
                      </div>

                    )}

                  </div>

                )}

              </>

            )}

          </div>
        </section>

      )}

      {/* ==================================================
          FOOTER
      ================================================== */}

      <footer style={footer}>
        <span>
          🧠 MirrorSoul
        </span>

        <span>
          Recursos Humanos · Entrevistas
        </span>
      </footer>

    </div>
  );
};

// ==================================================
// MENSAJES
// ==================================================

function obtenerEstiloMensaje(
  mensaje
) {
  if (
    String(
      mensaje
    ).startsWith(
      "✅"
    )
  ) {
    return {
      ...messageBox,
      color:
        "#27843A",
      background:
        "#ECF9EF",
      border:
        "1px solid #B7E4C7"
    };
  }

  if (
    String(
      mensaje
    ).startsWith(
      "⚠️"
    ) ||
    String(
      mensaje
    ).startsWith(
      "🎙️"
    )
  ) {
    return {
      ...messageBox,
      color:
        "#8A6500",
      background:
        "#FFF9E8",
      border:
        "1px solid #F3E2A5"
    };
  }

  return {
    ...messageBox,
    color:
      "#C62828",
    background:
      "#FFF1F1",
    border:
      "1px solid #F0B8B8"
  };
}

// ==================================================
// ESTILOS
// ==================================================

const page = {
  maxWidth: "1100px",
  margin: "0 auto",
  padding: "35px 25px 60px",
  fontFamily: "'Segoe UI', Arial, sans-serif",
  color: "#263238"
};

// ==================================================
// HEADER
// ==================================================

const header = {
  display: "flex",
  alignItems: "flex-start",
  gap: "20px",
  marginBottom: "25px",
  flexWrap: "wrap"
};

const headerInfo = {
  flex: 1
};

const headerLabel = {
  fontSize: "11px",
  fontWeight: "900",
  letterSpacing: "1.3px",
  color: "#607D8B"
};

const title = {
  margin: "5px 0 0",
  fontSize: "29px",
  color: "#263238"
};

const subtitle = {
  margin: "7px 0 0",
  color: "#78909C",
  lineHeight: 1.5
};

// ==================================================
// BOTÓN REGRESAR
// ==================================================

const backButton = {
  border: "none",
  background:
    "linear-gradient(135deg,#66C8F5,#8BD9FF)",
  color: "#073B57",
  padding: "11px 20px",
  borderRadius: "999px",
  cursor: "pointer",
  fontWeight: "800",
  fontSize: "14px",
  boxShadow:
    "0 5px 14px rgba(75,160,210,.25)",
  whiteSpace: "nowrap"
};

// ==================================================
// PROSPECTO
// ==================================================

const prospectBox = {
  display: "flex",
  alignItems: "center",
  gap: "15px",
  background: "#FFFFFF",
  border: "1px solid #E1E8EF",
  borderRadius: "16px",
  padding: "18px",
  marginBottom: "25px",
  boxShadow:
    "0 5px 18px rgba(30,60,90,.05)"
};

const prospectIcon = {
  width: "50px",
  height: "50px",
  minWidth: "50px",
  borderRadius: "14px",
  background: "#EEF4FF",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "23px"
};

const prospectLabel = {
  fontSize: "10px",
  fontWeight: "800",
  letterSpacing: "1px",
  color: "#90A4AE"
};

const prospectName = {
  marginTop: "3px",
  fontSize: "18px",
  fontWeight: "800"
};

const prospectMirror = {
  marginTop: "4px",
  fontSize: "12px",
  color: "#607D8B"
};

// ==================================================
// FORMULARIO
// ==================================================

const section = {
  marginBottom: "25px"
};

const formCard = {
  background: "#FFFFFF",
  border: "1px solid #E1E8EF",
  borderRadius: "18px",
  padding: "24px",
  boxShadow:
    "0 6px 20px rgba(30,60,90,.05)"
};

const sectionTitle = {
  margin: 0,
  fontSize: "21px",
  color: "#263238"
};

const sectionDescription = {
  margin: "6px 0 22px",
  color: "#78909C",
  fontSize: "14px",
  lineHeight: 1.5
};

const twoColumns = {
  display: "grid",
  gridTemplateColumns:
    "repeat(auto-fit,minmax(240px,1fr))",
  gap: "16px"
};

const field = {
  marginBottom: "18px"
};

const label = {
  display: "block",
  marginBottom: "7px",
  fontWeight: "700",
  fontSize: "13px",
  color: "#455A64"
};

const input = {
  width: "100%",
  boxSizing: "border-box",
  padding: "12px 13px",
  borderRadius: "10px",
  border: "1px solid #D9E2EF",
  fontSize: "14px",
  background: "#FFFFFF",
  color: "#263238",
  fontFamily: "inherit"
};

const textarea = {
  ...input,
  resize: "vertical"
};

const formActions = {
  display: "flex",
  justifyContent: "flex-end",
  marginTop: "20px"
};

const saveButton = {
  border: "none",
  background: "#2167D5",
  color: "#FFFFFF",
  padding: "12px 20px",
  borderRadius: "999px",
  fontWeight: "800",
  cursor: "pointer"
};

// ==================================================
// REALIZAR ENTREVISTA
// ==================================================

const readyCard = {
  background: "#FFFFFF",
  border: "1px solid #D9E5F2",
  borderRadius: "18px",
  padding: "22px",
  boxShadow:
    "0 5px 18px rgba(30,60,90,.06)"
};

const readyHeader = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "flex-start",
  gap: "15px",
  marginBottom: "17px"
};

const readyLabel = {
  fontSize: "10px",
  fontWeight: "900",
  letterSpacing: "1px",
  color: "#607D8B"
};

const readyTitle = {
  margin: "4px 0 0",
  fontSize: "20px"
};

const readyMeta = {
  marginTop: "5px",
  color: "#78909C",
  fontSize: "13px"
};

const actionBox = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: "15px",
  flexWrap: "wrap",
  padding: "16px",
  background: "#F8FAFC",
  border: "1px solid #E5EBF1",
  borderRadius: "12px"
};

const actionText = {
  margin: "5px 0 0",
  color: "#78909C",
  fontSize: "12px",
  lineHeight: 1.5
};

const videoCallButton = {
  border: "none",
  background: "#7540D5",
  color: "#FFFFFF",
  padding: "11px 18px",
  borderRadius: "999px",
  cursor: "pointer",
  fontWeight: "800"
};

const audioButton = {
  border: "none",
  background: "#2167D5",
  color: "#FFFFFF",
  padding: "11px 18px",
  borderRadius: "999px",
  cursor: "pointer",
  fontWeight: "800"
};

// ==================================================
// GRABADOR
// ==================================================

const recorderWorkspace = {
  marginTop: "15px",
  padding: "18px",
  border: "1px solid #D5E2FA",
  background: "#F4F8FF",
  borderRadius: "14px"
};

const recorderHeader = {
  display: "flex",
  alignItems: "flex-start",
  gap: "12px",
  marginBottom: "14px"
};

const recorderIcon = {
  width: "42px",
  height: "42px",
  minWidth: "42px",
  borderRadius: "11px",
  background: "#DDEAFF",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "20px"
};

const recorderDescription = {
  margin: "5px 0 0",
  color: "#607D8B",
  fontSize: "12px",
  lineHeight: 1.5
};

const processingBox = {
  marginTop: "12px",
  padding: "10px",
  background: "#FFF9E8",
  color: "#8A6500",
  borderRadius: "8px",
  fontWeight: "700",
  fontSize: "12px"
};

// ==================================================
// MENSAJES
// ==================================================

const messageBox = {
  marginTop: "15px",
  padding: "12px",
  borderRadius: "10px",
  fontWeight: "600",
  fontSize: "13px"
};

// ==================================================
// FOOTER
// ==================================================

const footer = {
  borderTop: "1px solid #E1E8EF",
  marginTop: "40px",
  paddingTop: "18px",
  display: "flex",
  justifyContent: "space-between",
  gap: "15px",
  flexWrap: "wrap",
  color: "#90A4AE",
  fontSize: "12px"
};

// ==================================================
// LOADING / ERROR
// ==================================================

const loadingContainer = {
  textAlign: "center",
  padding: "80px 20px",
  color: "#607D8B"
};

const loadingIcon = {
  fontSize: "40px"
};

const errorContainer = {
  maxWidth: "600px",
  margin: "80px auto",
  textAlign: "center",
  background: "#FFFFFF",
  padding: "40px",
  borderRadius: "16px",
  boxShadow:
    "0 5px 20px rgba(0,0,0,.08)"
};

const errorIcon = {
  fontSize: "45px"
};

export default EntrevistasProspecto;