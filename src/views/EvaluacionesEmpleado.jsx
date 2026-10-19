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


const EvaluacionesEmpleado = () => {

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

  const [pruebasDisponibles, setPruebasDisponibles] =
    useState([]);

  const [evaluaciones, setEvaluaciones] =
    useState([]);

  const [cargando, setCargando] =
    useState(true);

  const [habilitando, setHabilitando] =
    useState(false);

  const [error, setError] =
    useState("");

  const [mensaje, setMensaje] =
    useState("");

  const [form, setForm] =
    useState({
      id_prueba_rh: "",
      motivo: "",
      tipo_evaluacion: "periodica"
    });


  // ==================================================
  // CARGAR INFORMACIÓN
  // ==================================================

  const cargarDatos =
    useCallback(
      async () => {

        try {

          setCargando(true);
          setError("");


          const [
            respuestaDisponibles,
            respuestaEvaluaciones
          ] = await Promise.all([

            axios.get(
              `/api/empleados/${idEmpleado}/evaluaciones/disponibles`,
              config
            ),

            axios.get(
              `/api/empleados/${idEmpleado}/evaluaciones`,
              config
            )

          ]);


          setEmpleado(
            respuestaEvaluaciones.data?.empleado ||
            respuestaDisponibles.data?.empleado ||
            null
          );


          setPruebasDisponibles(
            Array.isArray(
              respuestaDisponibles.data?.pruebas
            )
              ? respuestaDisponibles.data.pruebas
              : []
          );


          setEvaluaciones(
            Array.isArray(
              respuestaEvaluaciones.data?.evaluaciones
            )
              ? respuestaEvaluaciones.data.evaluaciones
              : []
          );


        } catch (err) {

          console.error(
            "❌ Error cargando evaluaciones del empleado:",
            err
          );

          setError(
            err.response?.data?.message ||
            "No fue posible cargar las evaluaciones."
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
      cargarDatos();
    },
    [cargarDatos]
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
          [name]: value
        })
      );

      setError("");
      setMensaje("");

    };


  // ==================================================
  // HABILITAR EVALUACIÓN
  // ==================================================

  const habilitarEvaluacion =
    async e => {

      e.preventDefault();


      const idPrueba =
        Number(
          form.id_prueba_rh
        );


      if (
        !Number.isInteger(
          idPrueba
        ) ||
        idPrueba <= 0
      ) {

        setError(
          "Selecciona una evaluación."
        );

        return;
      }


      try {

        setHabilitando(true);
        setError("");
        setMensaje("");


        const respuesta =
          await axios.post(
            `/api/empleados/${idEmpleado}/evaluaciones/habilitar`,
            {
              id_prueba_rh:
                idPrueba,

              motivo:
                String(
                  form.motivo || ""
                ).trim() ||
                null,

              tipo_evaluacion:
                form.tipo_evaluacion
            },
            config
          );


        setMensaje(
          respuesta.data?.message ||
          "Evaluación habilitada correctamente."
        );


        setForm({
          id_prueba_rh: "",
          motivo: "",
          tipo_evaluacion: "periodica"
        });


        await cargarDatos();


      } catch (err) {

        console.error(
          "❌ Error habilitando evaluación:",
          err
        );

        setError(
          err.response?.data?.message ||
          "No fue posible habilitar la evaluación."
        );

      } finally {

        setHabilitando(false);

      }

    };


  // ==================================================
  // CANCELAR EVALUACIÓN
  // ==================================================

  const cancelarEvaluacion =
    async idHabilitacion => {

      const confirmar =
        window.confirm(
          "¿Deseas cancelar esta evaluación?"
        );


      if (!confirmar) {
        return;
      }


      try {

        setError("");
        setMensaje("");


        const respuesta =
          await axios.put(
            `/api/empleados/${idEmpleado}/evaluaciones/${idHabilitacion}/cancelar`,
            {},
            config
          );


        setMensaje(
          respuesta.data?.message ||
          "Evaluación cancelada correctamente."
        );


        await cargarDatos();


      } catch (err) {

        console.error(
          "❌ Error cancelando evaluación:",
          err
        );

        setError(
          err.response?.data?.message ||
          "No fue posible cancelar la evaluación."
        );

      }

    };


  // ==================================================
  // COPIAR ENLACE
  // ==================================================

  const copiarEnlace =
    async tokenPublico => {

      const enlace =
        `${window.location.origin}/evaluacion-empleado/${tokenPublico}`;


      try {

        await navigator.clipboard.writeText(
          enlace
        );

        setMensaje(
          "Enlace copiado correctamente."
        );

      } catch (error) {

        console.error(
          "❌ Error copiando enlace:",
          error
        );

        setError(
          "No fue posible copiar el enlace."
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

        periodica:
          "Periódica",

        seguimiento:
          "Seguimiento",

        bienestar:
          "Bienestar",

        prevencion:
          "Prevención",

        riesgo_psicosocial:
          "Riesgo psicosocial",

        otro:
          "Otro"

      };


      return (
        tipos[tipo] ||
        tipo ||
        "Evaluación"
      );

    };


  // ==================================================
  // ESTADO
  // ==================================================

  const obtenerEstado =
    estatus => {

      const estados = {

        habilitada: {
          texto: "Pendiente",
          fondo: "#fff7e6",
          color: "#b7791f"
        },

        iniciada: {
          texto: "Iniciada",
          fondo: "#eef4ff",
          color: "#2167d5"
        },

        completada: {
          texto: "Completada",
          fondo: "#ecfdf3",
          color: "#067647"
        },

        cancelada: {
          texto: "Cancelada",
          fondo: "#f2f4f7",
          color: "#667085"
        }

      };


      return (
        estados[
          String(
            estatus || ""
          ).toLowerCase()
        ] ||
        estados.habilitada
      );

    };


  // ==================================================
  // CARGANDO
  // ==================================================

  if (cargando) {

    return (

      <div style={styles.page}>

        <div style={styles.container}>

          <div style={styles.card}>

            <h2>
              🧠 Evaluaciones periódicas
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
              🧠 Evaluaciones periódicas
            </h1>

            <p style={styles.subtitle}>
              Habilita evaluaciones de seguimiento,
              prevención y bienestar durante la
              relación laboral.
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
            HABILITAR EVALUACIÓN
        ========================================== */}

        <div style={styles.card}>

          <div style={styles.cardHeader}>

            <div>

              <h2 style={styles.cardTitle}>
                ➕ Nueva evaluación
              </h2>

              <p style={styles.cardSubtitle}>
                Selecciona una prueba RH y genera
                un enlace para el empleado.
              </p>

            </div>

          </div>


          <form
            onSubmit={
              habilitarEvaluacion
            }
          >

            <div style={styles.gridTwo}>


              {/* PRUEBA */}

              <div style={styles.field}>

                <label style={styles.label}>
                  Evaluación *
                </label>

                <select
                  name="id_prueba_rh"
                  value={
                    form.id_prueba_rh
                  }
                  onChange={
                    cambiarCampo
                  }
                  style={styles.input}
                >

                  <option value="">
                    Selecciona una prueba
                  </option>

                  {pruebasDisponibles.map(
                    prueba => (

                      <option
                        key={
                          prueba.id_prueba_rh
                        }
                        value={
                          prueba.id_prueba_rh
                        }
                      >
                        {prueba.nombre}
                      </option>

                    )
                  )}

                </select>

              </div>


              {/* TIPO */}

              <div style={styles.field}>

                <label style={styles.label}>
                  Tipo de evaluación
                </label>

                <select
                  name="tipo_evaluacion"
                  value={
                    form.tipo_evaluacion
                  }
                  onChange={
                    cambiarCampo
                  }
                  style={styles.input}
                >

                  <option value="periodica">
                    Periódica
                  </option>

                  <option value="seguimiento">
                    Seguimiento
                  </option>

                  <option value="bienestar">
                    Bienestar
                  </option>

                  <option value="prevencion">
                    Prevención
                  </option>

                  <option value="riesgo_psicosocial">
                    Riesgo psicosocial
                  </option>

                  <option value="otro">
                    Otro
                  </option>

                </select>

              </div>

            </div>


            {/* MOTIVO */}

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
                style={styles.textarea}
                rows={3}
                placeholder="Ej. Evaluación de seguimiento a los 3 meses..."
              />

            </div>


            <div style={styles.notice}>

              <strong>
                ℹ️ Evaluación laboral
              </strong>

              <p style={styles.noticeText}>
                Las evaluaciones de este módulo
                corresponden a seguimiento,
                prevención y contexto laboral.
                Los resultados no deben utilizarse
                como diagnóstico clínico.
              </p>

            </div>


            <div style={styles.actions}>

              <button
                type="submit"
                disabled={
                  habilitando ||
                  pruebasDisponibles.length === 0
                }
                style={styles.primaryButton}
              >

                {
                  habilitando
                    ? "Generando..."
                    : "🔗 Habilitar evaluación"
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
                📋 Historial de evaluaciones
              </h2>

              <p style={styles.cardSubtitle}>
                Aplicaciones realizadas durante
                la relación laboral.
              </p>

            </div>


            <div style={styles.counter}>
              {evaluaciones.length}
            </div>

          </div>


          {evaluaciones.length ===
          0 ? (

            <div style={styles.empty}>

              <div style={styles.emptyIcon}>
                🧠
              </div>

              <h3>
                Sin evaluaciones
              </h3>

              <p>
                Todavía no se han habilitado
                evaluaciones para este empleado.
              </p>

            </div>

          ) : (

            <div style={styles.evaluationList}>

              {evaluaciones.map(
                evaluacion => {

                  const estado =
                    obtenerEstado(
                      evaluacion.estatus
                    );


                  const enlace =
                    `${window.location.origin}/evaluacion-empleado/${evaluacion.token_publico}`;


                  return (

                    <div
                      key={
                        evaluacion.id_habilitacion
                      }
                      style={styles.evaluationCard}
                    >

                      {/* CABECERA */}

                      <div style={styles.evaluationHeader}>

                        <div>

                          <div style={styles.badges}>

                            <span style={styles.typeBadge}>
                              {
                                textoTipo(
                                  evaluacion.tipo_evaluacion
                                )
                              }
                            </span>


                            <span
                              style={{
                                ...styles.statusBadge,
                                background:
                                  estado.fondo,
                                color:
                                  estado.color
                              }}
                            >
                              {estado.texto}
                            </span>

                          </div>


                          <h3 style={styles.evaluationTitle}>
                            {
                              evaluacion.prueba_nombre ||
                              "Evaluación RH"
                            }
                          </h3>


                          {evaluacion.categoria && (

                            <div style={styles.meta}>
                              Categoría:{" "}
                              {
                                evaluacion.categoria
                              }
                            </div>

                          )}

                        </div>


                        <div style={styles.dateText}>
                          {
                            formatearFecha(
                              evaluacion.fecha_habilitacion
                            )
                          }
                        </div>

                      </div>


                      {/* MOTIVO */}

                      {evaluacion.motivo && (

                        <div style={styles.section}>

                          <strong>
                            Motivo
                          </strong>

                          <p style={styles.text}>
                            {
                              evaluacion.motivo
                            }
                          </p>

                        </div>

                      )}


                      {/* ENLACE */}

                      {(
                        evaluacion.estatus ===
                          "habilitada" ||
                        evaluacion.estatus ===
                          "iniciada"
                      ) && (

                        <div style={styles.linkBox}>

                          <strong>
                            🔗 Enlace del empleado
                          </strong>

                          <div style={styles.linkText}>
                            {enlace}
                          </div>


                          <button
                            type="button"
                            style={styles.copyButton}
                            onClick={() =>
                              copiarEnlace(
                                evaluacion.token_publico
                              )
                            }
                          >
                            📋 Copiar enlace
                          </button>

                        </div>

                      )}


                      {/* RESULTADO */}

                      {evaluacion.estatus ===
                        "completada" && (

                        <div style={styles.resultBox}>

                          <div style={styles.resultTitle}>
                            ✅ Evaluación completada
                          </div>


                          <div style={styles.resultGrid}>

                            <div>

                              <span style={styles.smallLabel}>
                                Fecha
                              </span>

                              <strong>
                                {
                                  formatearFecha(
                                    evaluacion.fecha_completada
                                  )
                                }
                              </strong>

                            </div>


                            <div>

                              <span style={styles.smallLabel}>
                                Puntaje bruto
                              </span>

                              <strong>
                                {
                                  evaluacion.puntaje_total ??
                                  "No disponible"
                                }
                              </strong>

                            </div>

                          </div>


                          {evaluacion.resultado_texto && (

                            <div style={styles.section}>

                              <strong>
                                Resultado
                              </strong>

                              <p style={styles.text}>
                                {
                                  evaluacion.resultado_texto
                                }
                              </p>

                            </div>

                          )}


                          {evaluacion.interpretacion_laboral && (

                            <div style={styles.section}>

                              <strong>
                                Interpretación laboral
                              </strong>

                              <p style={styles.text}>
                                {
                                  evaluacion.interpretacion_laboral
                                }
                              </p>

                            </div>

                          )}


                          {evaluacion.indicadores_prevencion && (

                            <div style={styles.section}>

                              <strong>
                                Indicadores de prevención
                              </strong>

                              <p style={styles.text}>
                                {
                                  evaluacion.indicadores_prevencion
                                }
                              </p>

                            </div>

                          )}

                        </div>

                      )}


                      {/* ACCIONES */}

                      {(
                        evaluacion.estatus ===
                          "habilitada" ||
                        evaluacion.estatus ===
                          "iniciada"
                      ) && (

                        <div style={styles.itemActions}>

                          <button
                            type="button"
                            style={styles.cancelEvaluationButton}
                            onClick={() =>
                              cancelarEvaluacion(
                                evaluacion.id_habilitacion
                              )
                            }
                          >
                            Cancelar evaluación
                          </button>

                        </div>

                      )}

                    </div>

                  );

                }
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
    background: "#ffffff",
    fontSize: "15px"
  },

  textarea: {
    width: "100%",
    boxSizing: "border-box",
    border: "1px solid #d0d5dd",
    borderRadius: "10px",
    padding: "12px",
    resize: "vertical",
    fontFamily: "inherit",
    fontSize: "15px"
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
    justifyContent: "flex-end"
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
    justifyContent: "center",
    alignItems: "center",
    fontWeight: "700"
  },

  evaluationList: {
    display: "flex",
    flexDirection: "column",
    gap: "16px"
  },

  evaluationCard: {
    border: "1px solid #e4e7ec",
    borderRadius: "14px",
    padding: "18px"
  },

  evaluationHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    flexWrap: "wrap",
    gap: "12px"
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

  statusBadge: {
    padding: "5px 9px",
    borderRadius: "20px",
    fontSize: "12px",
    fontWeight: "700"
  },

  evaluationTitle: {
    margin: 0,
    fontSize: "18px"
  },

  dateText: {
    color: "#667085",
    fontSize: "13px"
  },

  section: {
    marginTop: "14px"
  },

  text: {
    margin: "6px 0 0",
    whiteSpace: "pre-wrap",
    lineHeight: 1.55,
    color: "#344054"
  },

  linkBox: {
    marginTop: "16px",
    background: "#f8fafc",
    borderRadius: "10px",
    padding: "14px"
  },

  linkText: {
    wordBreak: "break-all",
    color: "#475467",
    fontSize: "13px",
    margin: "7px 0 10px"
  },

  copyButton: {
    border: "1px solid #d0d5dd",
    background: "#ffffff",
    borderRadius: "8px",
    padding: "8px 11px",
    cursor: "pointer",
    fontWeight: "700"
  },

  resultBox: {
    marginTop: "16px",
    background: "#f0fdf4",
    border: "1px solid #bbf7d0",
    borderRadius: "10px",
    padding: "15px"
  },

  resultTitle: {
    fontWeight: "800",
    color: "#166534",
    marginBottom: "12px"
  },

  resultGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(160px, 1fr))",
    gap: "12px"
  },

  smallLabel: {
    display: "block",
    color: "#667085",
    fontSize: "12px",
    marginBottom: "4px"
  },

  itemActions: {
    display: "flex",
    justifyContent: "flex-end",
    marginTop: "15px"
  },

  cancelEvaluationButton: {
    border: "1px solid #fecdca",
    background: "#fff5f5",
    color: "#b42318",
    borderRadius: "8px",
    padding: "8px 11px",
    cursor: "pointer",
    fontWeight: "700"
  },

  empty: {
    textAlign: "center",
    padding: "34px",
    color: "#667085"
  },

  emptyIcon: {
    fontSize: "40px"
  }

};


export default EvaluacionesEmpleado;