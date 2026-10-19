import React, {
  useCallback,
  useEffect,
  useMemo,
  useState
} from "react";

import axios from "axios";

import {
  useNavigate,
  useParams
} from "react-router-dom";


const API_URL =
  import.meta.env.VITE_API_URL ||
  "https://reflejoyalma.com";


const DecisionProspecto = () => {

  const { idProspecto } =
    useParams();

  const navigate =
    useNavigate();

  const token =
    localStorage.getItem("token");


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


  const [prospecto, setProspecto] =
    useState(null);

  const [decisionActual, setDecisionActual] =
    useState(null);

  const [historial, setHistorial] =
    useState([]);

  const [cargando, setCargando] =
    useState(true);

  const [guardando, setGuardando] =
    useState(false);

  const [mensaje, setMensaje] =
    useState("");

  const [error, setError] =
    useState("");


  const [form, setForm] =
    useState({
      decision: "",
      motivo: "",
      observaciones: "",
      departamento: "",
      fecha_contratacion: ""
    });


  // ==================================================
  // CARGAR DECISIÓN
  // ==================================================

  const cargarDecision =
    useCallback(
      async () => {

        try {

          setCargando(true);
          setError("");


          const respuesta =
            await axios.get(
              `${API_URL}/api/prospectos/${idProspecto}/decision`,
              config
            );


          setProspecto(
            respuesta.data?.prospecto ||
            null
          );


          setDecisionActual(
            respuesta.data?.decision ||
            null
          );


          setHistorial(
            Array.isArray(
              respuesta.data?.historial
            )
              ? respuesta.data.historial
              : []
          );


        } catch (err) {

          console.error(
            "❌ Error cargando decisión RH:",
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
            "No fue posible cargar la información de decisión."
          );


        } finally {

          setCargando(false);

        }

      },
      [
        idProspecto,
        config
      ]
    );


  useEffect(
    () => {
      cargarDecision();
    },
    [cargarDecision]
  );


  // ==================================================
  // CAMBIAR CAMPOS
  // ==================================================

  const cambiarCampo = e => {

    const {
      name,
      value
    } = e.target;


    setForm(
      prev => ({
        ...prev,
        [name]: value
      })
    );


    setMensaje("");
    setError("");

  };


  // ==================================================
  // SELECCIONAR DECISIÓN
  // ==================================================

  const seleccionarDecision =
    tipo => {

      setForm(
        prev => ({
          ...prev,
          decision: tipo
        })
      );


      setMensaje("");
      setError("");

    };


  // ==================================================
  // REGISTRAR DECISIÓN
  // ==================================================

  const guardarDecision =
    async e => {

      e.preventDefault();


      if (!form.decision) {

        setError(
          "Debes seleccionar una decisión."
        );

        return;

      }


      if (
        form.decision ===
          "contratar" &&
        !String(
          form.departamento || ""
        ).trim()
      ) {

        setError(
          "Indica el departamento del nuevo empleado."
        );

        return;

      }


      const textoConfirmacion =
        form.decision ===
        "contratar"
          ? "¿Confirmas que deseas contratar a este prospecto y convertirlo en empleado?"
          : "¿Confirmas que deseas marcar este prospecto como no contratado?";


      const confirmar =
        window.confirm(
          textoConfirmacion
        );


      if (!confirmar) {
        return;
      }


      try {

        setGuardando(true);
        setMensaje("");
        setError("");


        const payload = {

          decision:
            form.decision,

          motivo:
            String(
              form.motivo || ""
            ).trim() ||
            null,

          observaciones:
            String(
              form.observaciones || ""
            ).trim() ||
            null,

          departamento:
            form.decision ===
            "contratar"
              ? String(
                  form.departamento || ""
                ).trim()
              : null,

          fecha_contratacion:
            form.decision ===
              "contratar" &&
            form.fecha_contratacion
              ? form.fecha_contratacion
              : null

        };


        console.log(
          "📤 Registrando decisión RH:",
          {
            idProspecto,
            url:
              `${API_URL}/api/prospectos/${idProspecto}/decision`,
            payload
          }
        );


        const respuesta =
          await axios.post(
            `${API_URL}/api/prospectos/${idProspecto}/decision`,
            payload,
            config
          );


        console.log(
          "✅ Decisión RH registrada:",
          respuesta.data
        );


        setMensaje(
          respuesta.data?.message ||
          "Decisión registrada correctamente."
        );


        // ==================================================
        // CONTRATACIÓN EXITOSA
        // ABRIR EXPEDIENTE DEL EMPLEADO
        // ==================================================

        if (
          form.decision ===
            "contratar" &&
          respuesta.data?.empleado
            ?.id_empleado
        ) {

          const idEmpleado =
            respuesta.data.empleado
              .id_empleado;


          console.log(
            "👔 Prospecto convertido en empleado:",
            idEmpleado
          );


          navigate(
            `/empleado/${idEmpleado}`
          );

          return;

        }


        // ==================================================
        // NO CONTRATAR
        // RECARGAR DECISIÓN
        // ==================================================

        await cargarDecision();


      } catch (err) {

        console.error(
          "❌ Error registrando decisión RH:",
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
          "No fue posible registrar la decisión."
        );


      } finally {

        setGuardando(false);

      }

    };


  // ==================================================
  // FORMATEAR FECHA
  // ==================================================

  const formatearFecha =
    fecha => {

      if (!fecha) {
        return "Sin fecha";
      }


      const date =
        new Date(
          fecha
        );


      if (
        Number.isNaN(
          date.getTime()
        )
      ) {
        return fecha;
      }


      return date.toLocaleString(
        "es-MX",
        {
          dateStyle: "medium",
          timeStyle: "short"
        }
      );

    };


  // ==================================================
  // ESTADO FINAL
  // ==================================================

  const decisionFinalizada =
    prospecto?.estatus ===
      "contratado" ||
    prospecto?.estatus ===
      "no_contratado";


  // ==================================================
  // CARGANDO
  // ==================================================

  if (cargando) {

    return (

      <div style={styles.page}>

        <div style={styles.container}>

          <div style={styles.card}>

            <h2>
              ⚖️ Decisión RH
            </h2>

            <p>
              Cargando información...
            </p>

          </div>

        </div>

      </div>

    );

  }


  return (

    <div style={styles.page}>

      <div style={styles.container}>


        {/* ==========================================
            VOLVER
        ========================================== */}

        <button
          type="button"
          style={styles.backButton}
          onClick={() =>
            navigate(
              `/prospecto/${idProspecto}`
            )
          }
        >
          ← Volver al expediente
        </button>


        {/* ==========================================
            ENCABEZADO
        ========================================== */}

        <div style={styles.header}>

          <h1 style={styles.title}>
            ⚖️ Decisión RH
          </h1>

          <p style={styles.subtitle}>
            Registra la decisión final del
            proceso de selección.
          </p>

        </div>


        {/* ==========================================
            PROSPECTO
        ========================================== */}

        {prospecto && (

          <div style={styles.prospectCard}>

            <div style={styles.avatar}>

              {
                prospecto.nombre
                  ?.charAt(0)
                  ?.toUpperCase() ||
                "P"
              }

            </div>


            <div>

              <h2 style={styles.prospectName}>
                {prospecto.nombre}
              </h2>


              <div style={styles.meta}>
                🆔{" "}
                {
                  prospecto.id_mirror ||
                  "Sin ID MirrorSoul"
                }
              </div>


              <div style={styles.meta}>
                💼{" "}
                {
                  prospecto.puesto ||
                  "Puesto no especificado"
                }
              </div>


              <div style={styles.meta}>

                Estado actual:{" "}

                <strong>
                  {
                    prospecto.estatus ||
                    "prospecto"
                  }
                </strong>

              </div>

            </div>

          </div>

        )}


        {/* ==========================================
            MENSAJES
        ========================================== */}

        {mensaje && (

          <div style={styles.success}>
            ✅ {mensaje}
          </div>

        )}


        {error && (

          <div style={styles.error}>
            ❌ {error}
          </div>

        )}


        {/* ==========================================
            DECISIÓN YA TOMADA
        ========================================== */}

        {decisionFinalizada ? (

          <div style={styles.card}>

            <div
              style={
                prospecto?.estatus ===
                "contratado"
                  ? styles.finalSuccess
                  : styles.finalRejected
              }
            >

              <div style={styles.bigIcon}>

                {
                  prospecto?.estatus ===
                  "contratado"
                    ? "✅"
                    : "📋"
                }

              </div>


              <h2>

                {
                  prospecto?.estatus ===
                  "contratado"
                    ? "Prospecto contratado"
                    : "Prospecto no contratado"
                }

              </h2>


              {decisionActual && (

                <>

                  <p>

                    Decisión registrada el{" "}

                    <strong>

                      {
                        formatearFecha(
                          decisionActual.fecha_decision
                        )
                      }

                    </strong>

                  </p>


                  {decisionActual.motivo && (

                    <div style={styles.detailBox}>

                      <strong>
                        Motivo
                      </strong>

                      <p>
                        {
                          decisionActual.motivo
                        }
                      </p>

                    </div>

                  )}


                  {decisionActual.observaciones && (

                    <div style={styles.detailBox}>

                      <strong>
                        Observaciones
                      </strong>

                      <p>
                        {
                          decisionActual.observaciones
                        }
                      </p>

                    </div>

                  )}


                  {decisionActual.usuario_registro && (

                    <p style={styles.meta}>

                      Decisión registrada por:{" "}

                      <strong>
                        {
                          decisionActual.usuario_registro
                        }
                      </strong>

                    </p>

                  )}

                </>

              )}


              {/* ======================================
                  EMPLEADO CREADO
              ====================================== */}

              {prospecto?.estatus ===
                "contratado" &&
                decisionActual?.id_empleado && (

                <div style={styles.employeeBox}>

                  <h3>
                    👔 Empleado creado
                  </h3>


                  <div style={styles.employeeGrid}>

                    <div>

                      <span style={styles.labelSmall}>
                        ID MirrorSoul
                      </span>

                      <strong>
                        {
                          decisionActual.empleado_id_mirror ||
                          prospecto.id_mirror
                        }
                      </strong>

                    </div>


                    <div>

                      <span style={styles.labelSmall}>
                        Puesto
                      </span>

                      <strong>
                        {
                          decisionActual.empleado_puesto ||
                          prospecto.puesto ||
                          "No especificado"
                        }
                      </strong>

                    </div>


                    <div>

                      <span style={styles.labelSmall}>
                        Departamento
                      </span>

                      <strong>
                        {
                          decisionActual.departamento ||
                          "No especificado"
                        }
                      </strong>

                    </div>


                    <div>

                      <span style={styles.labelSmall}>
                        Fecha contratación
                      </span>

                      <strong>
                        {
                          decisionActual.fecha_contratacion ||
                          "No especificada"
                        }
                      </strong>

                    </div>

                  </div>


                  <div style={styles.employeeActions}>

                    <button
                      type="button"
                      style={styles.employeeButton}
                      onClick={() =>
                        navigate(
                          `/empleado/${decisionActual.id_empleado}`
                        )
                      }
                    >
                      👔 Abrir expediente del empleado
                    </button>

                  </div>

                </div>

              )}

            </div>

          </div>

        ) : (

          <>


            {/* ========================================
                SELECCIÓN
            ======================================== */}

            <div style={styles.card}>

              <h2 style={styles.cardTitle}>
                Selecciona una decisión
              </h2>


              <p style={styles.cardSubtitle}>
                La decisión es responsabilidad
                del área de Recursos Humanos.
              </p>


              <div style={styles.decisionGrid}>


                {/* CONTRATAR */}

                <button
                  type="button"
                  onClick={() =>
                    seleccionarDecision(
                      "contratar"
                    )
                  }
                  style={{
                    ...styles.decisionCard,

                    ...(form.decision ===
                    "contratar"
                      ? styles.hireSelected
                      : {})
                  }}
                >

                  <div style={styles.decisionIcon}>
                    ✅
                  </div>

                  <h3>
                    Contratar
                  </h3>

                  <p>
                    Convierte al prospecto en
                    empleado conservando todo
                    su historial del proceso.
                  </p>

                </button>


                {/* NO CONTRATAR */}

                <button
                  type="button"
                  onClick={() =>
                    seleccionarDecision(
                      "no_contratar"
                    )
                  }
                  style={{
                    ...styles.decisionCard,

                    ...(form.decision ===
                    "no_contratar"
                      ? styles.rejectSelected
                      : {})
                  }}
                >

                  <div style={styles.decisionIcon}>
                    📋
                  </div>

                  <h3>
                    No contratar
                  </h3>

                  <p>
                    Cierra el proceso conservando
                    el expediente y toda la
                    información registrada.
                  </p>

                </button>

              </div>

            </div>


            {/* ========================================
                FORMULARIO
            ======================================== */}

            {form.decision && (

              <div style={styles.card}>

                <h2 style={styles.cardTitle}>

                  {
                    form.decision ===
                    "contratar"
                      ? "👔 Datos de contratación"
                      : "📋 Cierre del proceso"
                  }

                </h2>


                <form
                  onSubmit={
                    guardarDecision
                  }
                >


                  {/* =================================
                      CONTRATAR
                  ================================= */}

                  {form.decision ===
                    "contratar" && (

                    <div style={styles.gridTwo}>


                      <div style={styles.field}>

                        <label style={styles.label}>
                          Departamento *
                        </label>

                        <input
                          type="text"
                          name="departamento"
                          value={
                            form.departamento
                          }
                          onChange={
                            cambiarCampo
                          }
                          style={styles.input}
                          placeholder="Ej. Administración"
                        />

                      </div>


                      <div style={styles.field}>

                        <label style={styles.label}>
                          Fecha de contratación
                        </label>

                        <input
                          type="date"
                          name="fecha_contratacion"
                          value={
                            form.fecha_contratacion
                          }
                          onChange={
                            cambiarCampo
                          }
                          style={styles.input}
                        />

                        <small style={styles.helpText}>
                          Si se deja vacía,
                          se utilizará la fecha actual.
                        </small>

                      </div>

                    </div>

                  )}


                  {/* =================================
                      MOTIVO
                  ================================= */}

                  <div style={styles.field}>

                    <label style={styles.label}>
                      Motivo
                    </label>

                    <textarea
                      name="motivo"
                      value={
                        form.motivo
                      }
                      onChange={
                        cambiarCampo
                      }
                      rows={4}
                      style={styles.textarea}
                      placeholder={
                        form.decision ===
                        "contratar"
                          ? "Describe brevemente los elementos considerados para la decisión..."
                          : "Describe brevemente el motivo de cierre del proceso..."
                      }
                    />

                  </div>


                  {/* =================================
                      OBSERVACIONES
                  ================================= */}

                  <div style={styles.field}>

                    <label style={styles.label}>
                      Observaciones adicionales
                    </label>

                    <textarea
                      name="observaciones"
                      value={
                        form.observaciones
                      }
                      onChange={
                        cambiarCampo
                      }
                      rows={5}
                      style={styles.textarea}
                      placeholder="Información adicional del proceso..."
                    />

                  </div>


                  {/* =================================
                      AVISO
                  ================================= */}

                  {form.decision ===
                    "contratar" && (

                    <div style={styles.infoNotice}>

                      <strong>
                        🔗 Continuidad del expediente
                      </strong>

                      <p>
                        Al contratar, MirrorSoul
                        conservará el mismo ID
                        del prospecto y lo
                        vinculará con su nuevo
                        expediente como empleado.
                        No será necesario volver
                        a registrar sus datos.
                      </p>

                    </div>

                  )}


                  <div style={styles.actions}>


                    <button
                      type="button"
                      style={styles.cancelButton}
                      onClick={() =>
                        seleccionarDecision(
                          ""
                        )
                      }
                    >
                      Cancelar
                    </button>


                    <button
                      type="submit"
                      disabled={guardando}
                      style={
                        form.decision ===
                        "contratar"
                          ? styles.hireButton
                          : styles.rejectButton
                      }
                    >

                      {
                        guardando
                          ? "Guardando..."
                          : form.decision ===
                            "contratar"
                          ? "✅ Confirmar contratación"
                          : "📋 Confirmar no contratación"
                      }

                    </button>

                  </div>

                </form>

              </div>

            )}

          </>

        )}


        {/* ==========================================
            HISTORIAL
        ========================================== */}

        {historial.length > 0 && (

          <div style={styles.card}>

            <div style={styles.cardHeader}>

              <div>

                <h2 style={styles.cardTitle}>
                  📜 Historial de decisiones
                </h2>

                <p style={styles.cardSubtitle}>
                  Registro de decisiones asociadas
                  al proceso.
                </p>

              </div>


              <div style={styles.counter}>
                {historial.length}
              </div>

            </div>


            <div style={styles.historyList}>

              {historial.map(
                item => (

                  <div
                    key={
                      item.id_decision
                    }
                    style={styles.historyCard}
                  >

                    <div style={styles.historyTop}>

                      <strong>

                        {
                          item.decision ===
                          "contratar"
                            ? "✅ Contratar"
                            : "📋 No contratar"
                        }

                      </strong>


                      <span style={styles.meta}>

                        {
                          formatearFecha(
                            item.fecha_decision
                          )
                        }

                      </span>

                    </div>


                    {item.motivo && (

                      <p>

                        <strong>
                          Motivo:
                        </strong>{" "}

                        {item.motivo}

                      </p>

                    )}


                    {item.usuario_registro && (

                      <div style={styles.meta}>

                        Registrado por{" "}

                        {
                          item.usuario_registro
                        }

                      </div>

                    )}

                  </div>

                )
              )}

            </div>

          </div>

        )}

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
    padding: "30px 20px"
  },

  container: {
    maxWidth: "1100px",
    margin: "0 auto"
  },

  backButton: {
    border: "none",
    background: "transparent",
    padding: 0,
    marginBottom: "14px",
    cursor: "pointer",
    color: "#344054",
    fontWeight: "700"
  },

  header: {
    marginBottom: "22px"
  },

  title: {
    margin: "0 0 6px",
    fontSize: "30px"
  },

  subtitle: {
    margin: 0,
    color: "#667085"
  },

  prospectCard: {
    background: "#ffffff",
    borderRadius: "16px",
    padding: "20px",
    display: "flex",
    gap: "18px",
    alignItems: "center",
    marginBottom: "22px",
    boxShadow:
      "0 4px 18px rgba(0,0,0,.05)"
  },

  avatar: {
    width: "58px",
    height: "58px",
    borderRadius: "50%",
    background: "#e8eef9",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontWeight: "700",
    fontSize: "25px"
  },

  prospectName: {
    margin: "0 0 8px"
  },

  meta: {
    color: "#667085",
    fontSize: "14px",
    marginTop: "4px"
  },

  card: {
    background: "#ffffff",
    borderRadius: "16px",
    padding: "24px",
    marginBottom: "24px",
    boxShadow:
      "0 4px 18px rgba(0,0,0,.05)"
  },

  cardHeader: {
    display: "flex",
    justifyContent: "space-between",
    gap: "20px",
    alignItems: "flex-start",
    marginBottom: "20px"
  },

  cardTitle: {
    margin: "0 0 5px"
  },

  cardSubtitle: {
    margin: 0,
    color: "#667085"
  },

  decisionGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(260px, 1fr))",
    gap: "18px",
    marginTop: "20px"
  },

  decisionCard: {
    textAlign: "left",
    border: "2px solid #e4e7ec",
    background: "#ffffff",
    borderRadius: "14px",
    padding: "22px",
    cursor: "pointer"
  },

  hireSelected: {
    border: "2px solid #16a34a",
    background: "#f0fdf4"
  },

  rejectSelected: {
    border: "2px solid #dc2626",
    background: "#fef2f2"
  },

  decisionIcon: {
    fontSize: "34px"
  },

  gridTwo: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(240px, 1fr))",
    gap: "16px"
  },

  field: {
    marginBottom: "18px"
  },

  label: {
    display: "block",
    fontWeight: "700",
    marginBottom: "7px"
  },

  input: {
    width: "100%",
    boxSizing: "border-box",
    border: "1px solid #d0d5dd",
    borderRadius: "10px",
    padding: "11px 12px",
    fontSize: "15px"
  },

  textarea: {
    width: "100%",
    boxSizing: "border-box",
    border: "1px solid #d0d5dd",
    borderRadius: "10px",
    padding: "12px",
    resize: "vertical",
    fontSize: "15px"
  },

  helpText: {
    display: "block",
    marginTop: "6px",
    color: "#667085"
  },

  infoNotice: {
    background: "#eff6ff",
    border: "1px solid #bfdbfe",
    borderRadius: "12px",
    padding: "15px",
    marginBottom: "20px",
    color: "#1e3a8a"
  },

  actions: {
    display: "flex",
    justifyContent: "flex-end",
    flexWrap: "wrap",
    gap: "10px"
  },

  cancelButton: {
    border: "1px solid #d0d5dd",
    borderRadius: "10px",
    background: "#ffffff",
    padding: "11px 17px",
    cursor: "pointer",
    fontWeight: "700"
  },

  hireButton: {
    border: "none",
    borderRadius: "10px",
    background: "#16a34a",
    color: "#ffffff",
    padding: "11px 17px",
    cursor: "pointer",
    fontWeight: "700"
  },

  rejectButton: {
    border: "none",
    borderRadius: "10px",
    background: "#dc2626",
    color: "#ffffff",
    padding: "11px 17px",
    cursor: "pointer",
    fontWeight: "700"
  },

  success: {
    background: "#ecfdf3",
    border: "1px solid #abefc6",
    padding: "13px",
    borderRadius: "10px",
    marginBottom: "18px"
  },

  error: {
    background: "#fef3f2",
    border: "1px solid #fecdca",
    padding: "13px",
    borderRadius: "10px",
    marginBottom: "18px"
  },

  finalSuccess: {
    textAlign: "center",
    background: "#f0fdf4",
    border: "1px solid #bbf7d0",
    borderRadius: "14px",
    padding: "24px"
  },

  finalRejected: {
    textAlign: "center",
    background: "#fafafa",
    border: "1px solid #e4e7ec",
    borderRadius: "14px",
    padding: "24px"
  },

  bigIcon: {
    fontSize: "46px"
  },

  detailBox: {
    maxWidth: "700px",
    margin: "14px auto",
    background: "#ffffff",
    borderRadius: "10px",
    padding: "14px",
    textAlign: "left"
  },

  employeeBox: {
    marginTop: "22px",
    background: "#ffffff",
    borderRadius: "12px",
    padding: "18px",
    textAlign: "left"
  },

  employeeGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(180px, 1fr))",
    gap: "14px"
  },

  employeeActions: {
    marginTop: "18px",
    display: "flex",
    justifyContent: "flex-end"
  },

  employeeButton: {
    border: "none",
    borderRadius: "10px",
    background: "#2563eb",
    color: "#ffffff",
    padding: "11px 17px",
    cursor: "pointer",
    fontWeight: "700"
  },

  labelSmall: {
    display: "block",
    color: "#667085",
    fontSize: "12px",
    marginBottom: "4px"
  },

  historyList: {
    display: "flex",
    flexDirection: "column",
    gap: "12px"
  },

  historyCard: {
    border: "1px solid #e4e7ec",
    borderRadius: "12px",
    padding: "15px"
  },

  historyTop: {
    display: "flex",
    justifyContent: "space-between",
    gap: "15px"
  },

  counter: {
    width: "42px",
    height: "42px",
    borderRadius: "10px",
    background: "#eef2f7",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontWeight: "700"
  }

};


export default DecisionProspecto;