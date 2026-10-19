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


const SeguimientoEmpleado = () => {

  const { idEmpleado } =
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


  const [empleado, setEmpleado] =
    useState(null);

  const [seguimientos, setSeguimientos] =
    useState([]);

  const [cargando, setCargando] =
    useState(true);

  const [guardando, setGuardando] =
    useState(false);

  const [error, setError] =
    useState("");

  const [mensaje, setMensaje] =
    useState("");

  const [editandoId, setEditandoId] =
    useState(null);


  const [form, setForm] =
    useState({
      fecha: "",
      tipo: "seguimiento",
      motivo: "",
      observacion: "",
      accion_realizada: "",
      resultado: "pendiente",
      proxima_accion: "",
      fecha_proxima_accion: ""
    });


  // ==================================================
  // CARGAR SEGUIMIENTO
  // ==================================================

  const cargarSeguimientos =
    useCallback(
      async () => {

        try {

          setCargando(true);
          setError("");

          const respuesta =
            await axios.get(
              `/api/empleados/${idEmpleado}/seguimiento`,
              config
            );


          setEmpleado(
            respuesta.data?.empleado ||
            null
          );


          setSeguimientos(
            Array.isArray(
              respuesta.data?.seguimientos
            )
              ? respuesta.data.seguimientos
              : []
          );

        } catch (err) {

          console.error(
            "❌ Error cargando seguimiento laboral:",
            err
          );

          setError(
            err.response?.data?.message ||
            "No fue posible cargar el seguimiento laboral."
          );

        } finally {

          setCargando(false);

        }

      },
      [
        idEmpleado,
        config
      ]
    );


  useEffect(
    () => {
      cargarSeguimientos();
    },
    [cargarSeguimientos]
  );


  // ==================================================
  // CAMBIAR CAMPO
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
          [name]: value
        })
      );

      setError("");
      setMensaje("");

    };


  // ==================================================
  // LIMPIAR FORMULARIO
  // ==================================================

  const limpiarFormulario =
    () => {

      setForm({
        fecha: "",
        tipo: "seguimiento",
        motivo: "",
        observacion: "",
        accion_realizada: "",
        resultado: "pendiente",
        proxima_accion: "",
        fecha_proxima_accion: ""
      });

      setEditandoId(
        null
      );

    };


  // ==================================================
  // CONVERTIR FECHA A INPUT DATETIME-LOCAL
  // ==================================================

  const fechaParaInput =
    fecha => {

      if (!fecha) {
        return "";
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
        return "";
      }

      const offset =
        date.getTimezoneOffset();

      const local =
        new Date(
          date.getTime() -
          offset * 60000
        );

      return local
        .toISOString()
        .slice(
          0,
          16
        );

    };


  // ==================================================
  // GUARDAR
  // ==================================================

  const guardarSeguimiento =
    async e => {

      e.preventDefault();

      if (
        !String(
          form.observacion || ""
        ).trim()
      ) {

        setError(
          "La observación es obligatoria."
        );

        return;
      }


      try {

        setGuardando(true);
        setError("");
        setMensaje("");


        const payload = {

          fecha:
            form.fecha ||
            null,

          tipo:
            form.tipo,

          motivo:
            String(
              form.motivo || ""
            ).trim() ||
            null,

          observacion:
            String(
              form.observacion || ""
            ).trim(),

          accion_realizada:
            String(
              form.accion_realizada || ""
            ).trim() ||
            null,

          resultado:
            form.resultado,

          proxima_accion:
            String(
              form.proxima_accion || ""
            ).trim() ||
            null,

          fecha_proxima_accion:
            form.fecha_proxima_accion ||
            null

        };


        if (
          editandoId
        ) {

          const respuesta =
            await axios.put(
              `/api/empleados/${idEmpleado}/seguimiento/${editandoId}`,
              payload,
              config
            );

          setMensaje(
            respuesta.data?.message ||
            "Seguimiento actualizado correctamente."
          );

        } else {

          const respuesta =
            await axios.post(
              `/api/empleados/${idEmpleado}/seguimiento`,
              payload,
              config
            );

          setMensaje(
            respuesta.data?.message ||
            "Seguimiento registrado correctamente."
          );

        }


        limpiarFormulario();

        await cargarSeguimientos();


      } catch (err) {

        console.error(
          "❌ Error guardando seguimiento laboral:",
          err
        );

        setError(
          err.response?.data?.message ||
          "No fue posible guardar el seguimiento laboral."
        );

      } finally {

        setGuardando(false);

      }

    };


  // ==================================================
  // EDITAR
  // ==================================================

  const editarSeguimiento =
    item => {

      setEditandoId(
        item.id_seguimiento
      );


      setForm({

        fecha:
          fechaParaInput(
            item.fecha
          ),

        tipo:
          item.tipo ||
          "seguimiento",

        motivo:
          item.motivo ||
          "",

        observacion:
          item.observacion ||
          "",

        accion_realizada:
          item.accion_realizada ||
          "",

        resultado:
          item.resultado ||
          "pendiente",

        proxima_accion:
          item.proxima_accion ||
          "",

        fecha_proxima_accion:
          fechaParaInput(
            item.fecha_proxima_accion
          )

      });


      window.scrollTo({
        top: 0,
        behavior: "smooth"
      });

    };


  // ==================================================
  // ELIMINAR
  // ==================================================

  const eliminarSeguimiento =
    async idSeguimiento => {

      const confirmar =
        window.confirm(
          "¿Deseas eliminar este seguimiento laboral?"
        );


      if (!confirmar) {
        return;
      }


      try {

        setError("");
        setMensaje("");


        const respuesta =
          await axios.delete(
            `/api/empleados/${idEmpleado}/seguimiento/${idSeguimiento}`,
            config
          );


        setMensaje(
          respuesta.data?.message ||
          "Seguimiento eliminado correctamente."
        );


        if (
          Number(
            editandoId
          ) ===
          Number(
            idSeguimiento
          )
        ) {

          limpiarFormulario();

        }


        await cargarSeguimientos();


      } catch (err) {

        console.error(
          "❌ Error eliminando seguimiento:",
          err
        );

        setError(
          err.response?.data?.message ||
          "No fue posible eliminar el seguimiento."
        );

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
  // TEXTO TIPO
  // ==================================================

  const textoTipo =
    tipo => {

      const tipos = {
        general: "General",
        desempeno: "Desempeño",
        bienestar: "Bienestar",
        incidencia: "Incidencia",
        adaptacion: "Adaptación",
        seguimiento: "Seguimiento",
        prevencion: "Prevención"
      };

      return (
        tipos[tipo] ||
        tipo ||
        "Seguimiento"
      );

    };


  // ==================================================
  // TEXTO RESULTADO
  // ==================================================

  const textoResultado =
    resultado => {

      const resultados = {

        pendiente:
          "Pendiente",

        continua:
          "Continúa",

        resuelto:
          "Resuelto",

        requiere_atencion:
          "Requiere atención",

        canalizacion_sugerida:
          "Canalización sugerida"

      };


      return (
        resultados[
          resultado
        ] ||
        resultado ||
        "Pendiente"
      );

    };


  // ==================================================
  // CARGANDO
  // ==================================================

  if (
    cargando
  ) {

    return (

      <div style={styles.page}>

        <div style={styles.container}>

          <div style={styles.card}>

            <h2>
              📈 Seguimiento laboral
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
              `/empleado/${idEmpleado}`
            )
          }
        >
          ← Volver al expediente laboral
        </button>


        {/* ==========================================
            ENCABEZADO
        ========================================== */}

        <div style={styles.header}>

          <div>

            <h1 style={styles.title}>
              📈 Seguimiento laboral
            </h1>

            <p style={styles.subtitle}>
              Registra acontecimientos,
              acuerdos y acciones de seguimiento
              relacionadas con la vida laboral
              del empleado.
            </p>

          </div>

        </div>


        {/* ==========================================
            EMPLEADO
        ========================================== */}

        {empleado && (

          <div style={styles.employeeCard}>

            <div style={styles.avatar}>

              {
                empleado.nombre
                  ?.charAt(0)
                  ?.toUpperCase() ||
                "E"
              }

            </div>


            <div>

              <h2 style={styles.employeeName}>
                {empleado.nombre}
              </h2>

              <div style={styles.meta}>
                🆔{" "}
                {
                  empleado.id_mirror ||
                  "Sin ID MirrorSoul"
                }
              </div>

              <div style={styles.meta}>
                💼{" "}
                {
                  empleado.puesto ||
                  "Puesto no especificado"
                }
              </div>

              <div style={styles.meta}>
                Departamento:{" "}
                <strong>
                  {
                    empleado.departamento ||
                    "No especificado"
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
            FORMULARIO
        ========================================== */}

        <div style={styles.card}>

          <div style={styles.cardHeader}>

            <div>

              <h2 style={styles.cardTitle}>
                {
                  editandoId
                    ? "✏️ Editar seguimiento"
                    : "➕ Registrar seguimiento"
                }
              </h2>

              <p style={styles.cardSubtitle}>
                Registra información objetiva
                relacionada con el contexto
                laboral.
              </p>

            </div>

          </div>


          <form
            onSubmit={
              guardarSeguimiento
            }
          >

            <div style={styles.gridTwo}>


              {/* FECHA */}

              <div style={styles.field}>

                <label style={styles.label}>
                  Fecha
                </label>

                <input
                  type="datetime-local"
                  name="fecha"
                  value={form.fecha}
                  onChange={cambiarCampo}
                  style={styles.input}
                />

                <small style={styles.helpText}>
                  Si se deja vacía,
                  se utilizará la fecha actual.
                </small>

              </div>


              {/* TIPO */}

              <div style={styles.field}>

                <label style={styles.label}>
                  Tipo de seguimiento
                </label>

                <select
                  name="tipo"
                  value={form.tipo}
                  onChange={cambiarCampo}
                  style={styles.input}
                >

                  <option value="seguimiento">
                    Seguimiento
                  </option>

                  <option value="adaptacion">
                    Adaptación
                  </option>

                  <option value="desempeno">
                    Desempeño
                  </option>

                  <option value="bienestar">
                    Bienestar
                  </option>

                  <option value="prevencion">
                    Prevención
                  </option>

                  <option value="incidencia">
                    Incidencia
                  </option>

                  <option value="general">
                    General
                  </option>

                </select>

              </div>

            </div>


            {/* MOTIVO */}

            <div style={styles.field}>

              <label style={styles.label}>
                Motivo
              </label>

              <input
                type="text"
                name="motivo"
                value={form.motivo}
                onChange={cambiarCampo}
                style={styles.input}
                placeholder="Ej. Seguimiento del primer mes"
              />

            </div>


            {/* OBSERVACIÓN */}

            <div style={styles.field}>

              <label style={styles.label}>
                Observación *
              </label>

              <textarea
                name="observacion"
                value={form.observacion}
                onChange={cambiarCampo}
                style={styles.textarea}
                rows={5}
                placeholder="Describe de manera objetiva la situación o información relevante..."
              />

            </div>


            {/* ACCIÓN REALIZADA */}

            <div style={styles.field}>

              <label style={styles.label}>
                Acción realizada
              </label>

              <textarea
                name="accion_realizada"
                value={form.accion_realizada}
                onChange={cambiarCampo}
                style={styles.textarea}
                rows={3}
                placeholder="Ej. Reunión de seguimiento con RH..."
              />

            </div>


            <div style={styles.gridTwo}>


              {/* RESULTADO */}

              <div style={styles.field}>

                <label style={styles.label}>
                  Resultado
                </label>

                <select
                  name="resultado"
                  value={form.resultado}
                  onChange={cambiarCampo}
                  style={styles.input}
                >

                  <option value="pendiente">
                    Pendiente
                  </option>

                  <option value="continua">
                    Continúa
                  </option>

                  <option value="resuelto">
                    Resuelto
                  </option>

                  <option value="requiere_atencion">
                    Requiere atención
                  </option>

                  <option value="canalizacion_sugerida">
                    Canalización sugerida
                  </option>

                </select>

              </div>


              {/* PRÓXIMA FECHA */}

              <div style={styles.field}>

                <label style={styles.label}>
                  Fecha próxima acción
                </label>

                <input
                  type="datetime-local"
                  name="fecha_proxima_accion"
                  value={
                    form.fecha_proxima_accion
                  }
                  onChange={cambiarCampo}
                  style={styles.input}
                />

              </div>

            </div>


            {/* PRÓXIMA ACCIÓN */}

            <div style={styles.field}>

              <label style={styles.label}>
                Próxima acción
              </label>

              <textarea
                name="proxima_accion"
                value={
                  form.proxima_accion
                }
                onChange={cambiarCampo}
                style={styles.textarea}
                rows={3}
                placeholder="Ej. Revisar adaptación en 30 días..."
              />

            </div>


            {/* AVISO */}

            <div style={styles.notice}>

              <strong>
                ℹ️ Seguimiento RH
              </strong>

              <p style={styles.noticeText}>
                Este apartado corresponde al
                seguimiento laboral. Evita
                registrar diagnósticos clínicos.
                Si se detectan indicadores que
                requieran apoyo especializado,
                pueden documentarse para una
                posible canalización posterior.
              </p>

            </div>


            {/* BOTONES */}

            <div style={styles.actions}>

              {editandoId && (

                <button
                  type="button"
                  style={styles.cancelButton}
                  onClick={
                    limpiarFormulario
                  }
                >
                  Cancelar edición
                </button>

              )}


              <button
                type="submit"
                disabled={guardando}
                style={styles.primaryButton}
              >

                {
                  guardando
                    ? "Guardando..."
                    : editandoId
                    ? "Guardar cambios"
                    : "Registrar seguimiento"
                }

              </button>

            </div>

          </form>

        </div>


        {/* ==========================================
            HISTORIAL
        ========================================== */}

        <div style={styles.card}>

          <div style={styles.cardHeader}>

            <div>

              <h2 style={styles.cardTitle}>
                📋 Historial de seguimiento
              </h2>

              <p style={styles.cardSubtitle}>
                Registros laborales del empleado.
              </p>

            </div>


            <div style={styles.counter}>
              {seguimientos.length}
            </div>

          </div>


          {seguimientos.length ===
          0 ? (

            <div style={styles.empty}>

              <div style={styles.emptyIcon}>
                📈
              </div>

              <h3>
                Sin seguimiento registrado
              </h3>

              <p>
                Registra el primer seguimiento
                laboral del empleado.
              </p>

            </div>

          ) : (

            <div style={styles.timeline}>

              {seguimientos.map(
                item => (

                  <div
                    key={
                      item.id_seguimiento
                    }
                    style={styles.timelineCard}
                  >

                    <div style={styles.timelineHeader}>

                      <div>

                        <div style={styles.badges}>

                          <span style={styles.typeBadge}>
                            {
                              textoTipo(
                                item.tipo
                              )
                            }
                          </span>

                          <span style={styles.resultBadge}>
                            {
                              textoResultado(
                                item.resultado
                              )
                            }
                          </span>

                        </div>


                        <h3 style={styles.itemTitle}>
                          {
                            item.motivo ||
                            "Seguimiento laboral"
                          }
                        </h3>

                      </div>


                      <div style={styles.dateText}>
                        {
                          formatearFecha(
                            item.fecha
                          )
                        }
                      </div>

                    </div>


                    {/* OBSERVACIÓN */}

                    <div style={styles.section}>

                      <strong>
                        Observación
                      </strong>

                      <p style={styles.text}>
                        {item.observacion}
                      </p>

                    </div>


                    {/* ACCIÓN */}

                    {item.accion_realizada && (

                      <div style={styles.section}>

                        <strong>
                          Acción realizada
                        </strong>

                        <p style={styles.text}>
                          {
                            item.accion_realizada
                          }
                        </p>

                      </div>

                    )}


                    {/* PRÓXIMA ACCIÓN */}

                    {item.proxima_accion && (

                      <div style={styles.nextAction}>

                        <strong>
                          📌 Próxima acción
                        </strong>

                        <p style={styles.text}>
                          {
                            item.proxima_accion
                          }
                        </p>

                        {item.fecha_proxima_accion && (

                          <small style={styles.meta}>
                            Fecha prevista:{" "}
                            {
                              formatearFecha(
                                item.fecha_proxima_accion
                              )
                            }
                          </small>

                        )}

                      </div>

                    )}


                    {/* REGISTRADO POR */}

                    {item.usuario_registro && (

                      <div style={styles.registeredBy}>
                        Registrado por{" "}
                        <strong>
                          {
                            item.usuario_registro
                          }
                        </strong>
                      </div>

                    )}


                    {/* ACCIONES */}

                    <div style={styles.itemActions}>

                      <button
                        type="button"
                        style={styles.editButton}
                        onClick={() =>
                          editarSeguimiento(
                            item
                          )
                        }
                      >
                        ✏️ Editar
                      </button>


                      <button
                        type="button"
                        style={styles.deleteButton}
                        onClick={() =>
                          eliminarSeguimiento(
                            item.id_seguimiento
                          )
                        }
                      >
                        🗑️ Eliminar
                      </button>

                    </div>

                  </div>

                )
              )}

            </div>

          )}

        </div>

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
    maxWidth: "1050px",
    margin: "0 auto"
  },

  backButton: {
    border: "none",
    background: "transparent",
    padding: 0,
    marginBottom: "15px",
    cursor: "pointer",
    color: "#344054",
    fontWeight: "700"
  },

  header: {
    marginBottom: "22px"
  },

  title: {
    margin: "0 0 7px",
    fontSize: "30px"
  },

  subtitle: {
    margin: 0,
    color: "#667085",
    maxWidth: "700px",
    lineHeight: 1.5
  },

  employeeCard: {
    background: "#ffffff",
    borderRadius: "16px",
    padding: "20px",
    display: "flex",
    alignItems: "center",
    gap: "17px",
    marginBottom: "22px",
    boxShadow:
      "0 4px 18px rgba(0,0,0,.05)"
  },

  avatar: {
    width: "58px",
    height: "58px",
    minWidth: "58px",
    borderRadius: "50%",
    background: "#e8eef9",
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    fontWeight: "800",
    fontSize: "25px"
  },

  employeeName: {
    margin: "0 0 6px"
  },

  meta: {
    color: "#667085",
    fontSize: "13px",
    marginTop: "4px"
  },

  card: {
    background: "#ffffff",
    borderRadius: "16px",
    padding: "24px",
    marginBottom: "22px",
    boxShadow:
      "0 4px 18px rgba(0,0,0,.05)"
  },

  cardHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "15px",
    marginBottom: "20px"
  },

  cardTitle: {
    margin: "0 0 5px"
  },

  cardSubtitle: {
    margin: 0,
    color: "#667085"
  },

  gridTwo: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(230px, 1fr))",
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
    fontSize: "15px",
    background: "#ffffff"
  },

  textarea: {
    width: "100%",
    boxSizing: "border-box",
    border: "1px solid #d0d5dd",
    borderRadius: "10px",
    padding: "12px",
    resize: "vertical",
    fontSize: "15px",
    fontFamily: "inherit"
  },

  helpText: {
    display: "block",
    marginTop: "6px",
    color: "#667085"
  },

  notice: {
    background: "#eff6ff",
    border: "1px solid #bfdbfe",
    borderRadius: "12px",
    padding: "15px",
    marginBottom: "20px",
    color: "#1e3a8a"
  },

  noticeText: {
    margin: "7px 0 0",
    lineHeight: 1.5
  },

  actions: {
    display: "flex",
    justifyContent: "flex-end",
    flexWrap: "wrap",
    gap: "10px"
  },

  primaryButton: {
    border: "none",
    borderRadius: "10px",
    background: "#2563eb",
    color: "#ffffff",
    padding: "11px 17px",
    cursor: "pointer",
    fontWeight: "700"
  },

  cancelButton: {
    border: "1px solid #d0d5dd",
    borderRadius: "10px",
    background: "#ffffff",
    padding: "11px 17px",
    cursor: "pointer",
    fontWeight: "700"
  },

  success: {
    background: "#ecfdf3",
    border: "1px solid #abefc6",
    borderRadius: "10px",
    padding: "13px",
    marginBottom: "18px"
  },

  error: {
    background: "#fef3f2",
    border: "1px solid #fecdca",
    borderRadius: "10px",
    padding: "13px",
    marginBottom: "18px"
  },

  counter: {
    minWidth: "42px",
    height: "42px",
    borderRadius: "10px",
    background: "#eef2f7",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontWeight: "700"
  },

  timeline: {
    display: "flex",
    flexDirection: "column",
    gap: "15px"
  },

  timelineCard: {
    border: "1px solid #e4e7ec",
    borderRadius: "14px",
    padding: "18px"
  },

  timelineHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    flexWrap: "wrap",
    gap: "12px",
    marginBottom: "15px"
  },

  badges: {
    display: "flex",
    flexWrap: "wrap",
    gap: "7px",
    marginBottom: "8px"
  },

  typeBadge: {
    background: "#eef4ff",
    color: "#3538cd",
    padding: "5px 9px",
    borderRadius: "20px",
    fontSize: "12px",
    fontWeight: "700"
  },

  resultBadge: {
    background: "#f2f4f7",
    color: "#344054",
    padding: "5px 9px",
    borderRadius: "20px",
    fontSize: "12px",
    fontWeight: "700"
  },

  itemTitle: {
    margin: 0,
    fontSize: "18px"
  },

  dateText: {
    color: "#667085",
    fontSize: "13px"
  },

  section: {
    marginTop: "13px"
  },

  text: {
    margin: "6px 0 0",
    lineHeight: 1.55,
    whiteSpace: "pre-wrap",
    color: "#344054"
  },

  nextAction: {
    marginTop: "15px",
    background: "#f8fafc",
    borderRadius: "10px",
    padding: "13px"
  },

  registeredBy: {
    borderTop: "1px solid #eaecf0",
    marginTop: "16px",
    paddingTop: "12px",
    color: "#667085",
    fontSize: "13px"
  },

  itemActions: {
    display: "flex",
    justifyContent: "flex-end",
    gap: "9px",
    flexWrap: "wrap",
    marginTop: "14px"
  },

  editButton: {
    border: "1px solid #d0d5dd",
    borderRadius: "8px",
    background: "#ffffff",
    padding: "8px 11px",
    cursor: "pointer",
    fontWeight: "700"
  },

  deleteButton: {
    border: "1px solid #fecdca",
    borderRadius: "8px",
    background: "#fff5f5",
    color: "#b42318",
    padding: "8px 11px",
    cursor: "pointer",
    fontWeight: "700"
  },

  empty: {
    textAlign: "center",
    padding: "32px",
    color: "#667085"
  },

  emptyIcon: {
    fontSize: "39px"
  }

};


export default SeguimientoEmpleado;