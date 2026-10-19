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


const Nom035Empleado = () => {

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

  const [cuestionarios, setCuestionarios] =
    useState([]);

  const [aplicaciones, setAplicaciones] =
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
      id_cuestionario: "",
      tipo_aplicacion: "periodica",
      motivo: ""
    });


  // ==================================================
  // CARGAR DATOS
  // ==================================================

  const cargarDatos =
    useCallback(
      async () => {

        try {

          setCargando(true);
          setError("");


          const [
            respuestaCuestionarios,
            respuestaAplicaciones
          ] = await Promise.all([

            axios.get(
              `/api/empleados/${idEmpleado}/nom035/cuestionarios`,
              config
            ),

            axios.get(
              `/api/empleados/${idEmpleado}/nom035`,
              config
            )

          ]);


          setEmpleado(
            respuestaAplicaciones.data?.empleado ||
            respuestaCuestionarios.data?.empleado ||
            null
          );


          setCuestionarios(
            Array.isArray(
              respuestaCuestionarios.data?.cuestionarios
            )
              ? respuestaCuestionarios.data.cuestionarios
              : []
          );


          setAplicaciones(
            Array.isArray(
              respuestaAplicaciones.data?.aplicaciones
            )
              ? respuestaAplicaciones.data.aplicaciones
              : []
          );


        } catch (err) {

          console.error(
            "❌ Error cargando NOM-035:",
            err
          );


          setError(
            err.response?.data?.message ||
            "No fue posible cargar el módulo NOM-035."
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
  // HABILITAR CUESTIONARIO
  // ==================================================

  const habilitarCuestionario =
    async e => {

      e.preventDefault();


      const idCuestionario =
        Number(
          form.id_cuestionario
        );


      if (
        !Number.isInteger(
          idCuestionario
        ) ||
        idCuestionario <= 0
      ) {

        setError(
          "Selecciona un cuestionario NOM-035."
        );

        return;
      }


      try {

        setHabilitando(true);
        setError("");
        setMensaje("");


        const respuesta =
          await axios.post(
            `/api/empleados/${idEmpleado}/nom035/habilitar`,
            {
              id_cuestionario:
                idCuestionario,

              tipo_aplicacion:
                form.tipo_aplicacion,

              motivo:
                String(
                  form.motivo ||
                  ""
                ).trim() ||
                null
            },
            config
          );


        setMensaje(
          respuesta.data?.message ||
          "Cuestionario NOM-035 habilitado correctamente."
        );


        setForm({
          id_cuestionario: "",
          tipo_aplicacion: "periodica",
          motivo: ""
        });


        await cargarDatos();


      } catch (err) {

        console.error(
          "❌ Error habilitando NOM-035:",
          err
        );


        setError(
          err.response?.data?.message ||
          "No fue posible habilitar el cuestionario."
        );


      } finally {

        setHabilitando(false);

      }

    };


  // ==================================================
  // CANCELAR APLICACIÓN
  // ==================================================

  const cancelarAplicacion =
    async idAplicacion => {

      const confirmar =
        window.confirm(
          "¿Deseas cancelar esta aplicación NOM-035?"
        );


      if (!confirmar) {
        return;
      }


      try {

        setError("");
        setMensaje("");


        const respuesta =
          await axios.put(
            `/api/empleados/${idEmpleado}/nom035/${idAplicacion}/cancelar`,
            {},
            config
          );


        setMensaje(
          respuesta.data?.message ||
          "Aplicación cancelada correctamente."
        );


        await cargarDatos();


      } catch (err) {

        console.error(
          "❌ Error cancelando aplicación NOM-035:",
          err
        );


        setError(
          err.response?.data?.message ||
          "No fue posible cancelar la aplicación."
        );

      }

    };


  // ==================================================
  // COPIAR ENLACE
  // ==================================================

  const copiarEnlace =
    async tokenPublico => {

      const enlace =
        `${window.location.origin}/nom035/${tokenPublico}`;


      try {

        await navigator.clipboard.writeText(
          enlace
        );


        setMensaje(
          "Enlace NOM-035 copiado correctamente."
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
  // TIPO APLICACIÓN
  // ==================================================

  const textoTipoAplicacion =
    tipo => {

      const tipos = {

        inicial:
          "Inicial",

        periodica:
          "Periódica",

        seguimiento:
          "Seguimiento",

        extraordinaria:
          "Extraordinaria"

      };


      return (
        tipos[tipo] ||
        tipo ||
        "Aplicación"
      );

    };


  // ==================================================
  // TIPO CUESTIONARIO
  // ==================================================

  const textoTipoCuestionario =
    tipo => {

      const tipos = {

        acontecimiento_traumatico:
          "Acontecimiento traumático severo",

        factores_riesgo:
          "Factores de riesgo psicosocial",

        factores_riesgo_entorno:
          "Factores de riesgo y entorno organizacional"

      };


      return (
        tipos[tipo] ||
        tipo ||
        "NOM-035"
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
            estatus ||
            ""
          ).toLowerCase()
        ] ||
        estados.habilitada
      );

    };


  // ==================================================
  // NIVEL DE RIESGO
  // ==================================================

  const textoNivelRiesgo =
    nivel => {

      if (!nivel) {
        return "Pendiente de cálculo";
      }


      const niveles = {

        nulo:
          "Nulo",

        bajo:
          "Bajo",

        medio:
          "Medio",

        alto:
          "Alto",

        muy_alto:
          "Muy alto",

        no_aplica:
          "No aplica"

      };


      return (
        niveles[nivel] ||
        nivel
      );

    };


  // ==================================================
  // PARSEAR JSON
  // ==================================================

  const parsearJSON =
    valor => {

      if (!valor) {
        return [];
      }


      if (
        Array.isArray(
          valor
        )
      ) {
        return valor;
      }


      try {

        const parsed =
          JSON.parse(
            valor
          );


        return Array.isArray(
          parsed
        )
          ? parsed
          : [];

      } catch {

        return [];

      }

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
              📋 NOM-035
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

          <h1 style={styles.title}>
            📋 NOM-035
          </h1>

          <p style={styles.subtitle}>
            Gestiona aplicaciones relacionadas con
            factores de riesgo psicosocial y
            seguimiento preventivo del empleado.
          </p>

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
            INFORMACIÓN
        ========================================== */}

        <div style={styles.notice}>

          <strong>
            ℹ️ Módulo NOM-035
          </strong>

          <p style={styles.noticeText}>
            Este módulo está separado de las
            evaluaciones psicométricas generales
            de RH. Cada aplicación conserva su
            propio historial, respuestas y
            resultados.
          </p>

        </div>


        {/* ==========================================
            HABILITAR CUESTIONARIO
        ========================================== */}

        <div style={styles.card}>

          <div style={styles.cardHeader}>

            <div>

              <h2 style={styles.cardTitle}>
                ➕ Nueva aplicación
              </h2>

              <p style={styles.cardSubtitle}>
                Selecciona un cuestionario NOM-035
                y genera un enlace para el empleado.
              </p>

            </div>

          </div>


          <form
            onSubmit={
              habilitarCuestionario
            }
          >

            <div style={styles.gridTwo}>


              {/* CUESTIONARIO */}

              <div style={styles.field}>

                <label style={styles.label}>
                  Cuestionario *
                </label>

                <select
                  name="id_cuestionario"
                  value={
                    form.id_cuestionario
                  }
                  onChange={
                    cambiarCampo
                  }
                  style={styles.input}
                >

                  <option value="">
                    Selecciona un cuestionario
                  </option>


                  {cuestionarios.map(
                    cuestionario => (

                      <option
                        key={
                          cuestionario.id_cuestionario
                        }
                        value={
                          cuestionario.id_cuestionario
                        }
                      >
                        Guía {cuestionario.guia}
                        {" - "}
                        {cuestionario.nombre}
                      </option>

                    )
                  )}

                </select>

              </div>


              {/* TIPO APLICACIÓN */}

              <div style={styles.field}>

                <label style={styles.label}>
                  Tipo de aplicación
                </label>

                <select
                  name="tipo_aplicacion"
                  value={
                    form.tipo_aplicacion
                  }
                  onChange={
                    cambiarCampo
                  }
                  style={styles.input}
                >

                  <option value="inicial">
                    Inicial
                  </option>

                  <option value="periodica">
                    Periódica
                  </option>

                  <option value="seguimiento">
                    Seguimiento
                  </option>

                  <option value="extraordinaria">
                    Extraordinaria
                  </option>

                </select>

              </div>

            </div>


            {/* INFO CUESTIONARIO SELECCIONADO */}

            {form.id_cuestionario && (

              (() => {

                const cuestionario =
                  cuestionarios.find(
                    item =>
                      Number(
                        item.id_cuestionario
                      ) ===
                      Number(
                        form.id_cuestionario
                      )
                  );


                if (!cuestionario) {
                  return null;
                }


                return (

                  <div style={styles.questionnaireInfo}>

                    <div style={styles.guideBadge}>
                      Guía {cuestionario.guia}
                    </div>


                    <strong>
                      {
                        cuestionario.nombre
                      }
                    </strong>


                    {cuestionario.descripcion && (

                      <p style={styles.text}>
                        {
                          cuestionario.descripcion
                        }
                      </p>

                    )}


                    <small style={styles.meta}>
                      {
                        textoTipoCuestionario(
                          cuestionario.tipo
                        )
                      }
                    </small>

                  </div>

                );

              })()

            )}


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
                placeholder="Ej. Aplicación periódica de seguimiento..."
              />

            </div>


            <div style={styles.actions}>

              <button
                type="submit"
                disabled={
                  habilitando ||
                  cuestionarios.length === 0
                }
                style={styles.primaryButton}
              >

                {
                  habilitando
                    ? "Generando..."
                    : "🔗 Habilitar cuestionario"
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
                📚 Historial NOM-035
              </h2>

              <p style={styles.cardSubtitle}>
                Aplicaciones realizadas y pendientes
                del empleado.
              </p>

            </div>


            <div style={styles.counter}>
              {aplicaciones.length}
            </div>

          </div>


          {aplicaciones.length ===
          0 ? (

            <div style={styles.empty}>

              <div style={styles.emptyIcon}>
                📋
              </div>

              <h3>
                Sin aplicaciones NOM-035
              </h3>

              <p>
                Todavía no se ha habilitado ningún
                cuestionario para este empleado.
              </p>

            </div>

          ) : (

            <div style={styles.list}>

              {aplicaciones.map(
                aplicacion => {

                  const estado =
                    obtenerEstado(
                      aplicacion.estatus
                    );


                  const enlace =
                    `${window.location.origin}/nom035/${aplicacion.token_publico}`;


                  const categorias =
                    parsearJSON(
                      aplicacion.categorias
                    );


                  const dominios =
                    parsearJSON(
                      aplicacion.dominios
                    );


                  return (

                    <div
                      key={
                        aplicacion.id_aplicacion
                      }
                      style={styles.applicationCard}
                    >

                      {/* CABECERA */}

                      <div style={styles.applicationHeader}>

                        <div>

                          <div style={styles.badges}>

                            <span style={styles.guideBadge}>
                              Guía {aplicacion.guia}
                            </span>


                            <span style={styles.typeBadge}>
                              {
                                textoTipoAplicacion(
                                  aplicacion.tipo_aplicacion
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


                          <h3 style={styles.applicationTitle}>
                            {
                              aplicacion.cuestionario_nombre ||
                              "Cuestionario NOM-035"
                            }
                          </h3>


                          <div style={styles.meta}>
                            {
                              textoTipoCuestionario(
                                aplicacion.cuestionario_tipo
                              )
                            }
                          </div>

                        </div>


                        <div style={styles.dateText}>
                          {
                            formatearFecha(
                              aplicacion.fecha_habilitacion
                            )
                          }
                        </div>

                      </div>


                      {/* MOTIVO */}

                      {aplicacion.motivo && (

                        <div style={styles.section}>

                          <strong>
                            Motivo
                          </strong>

                          <p style={styles.text}>
                            {
                              aplicacion.motivo
                            }
                          </p>

                        </div>

                      )}


                      {/* ENLACE */}

                      {(
                        aplicacion.estatus ===
                          "habilitada" ||
                        aplicacion.estatus ===
                          "iniciada"
                      ) && (

                        <div style={styles.linkBox}>

                          <strong>
                            🔗 Enlace para el empleado
                          </strong>


                          <div style={styles.linkText}>
                            {enlace}
                          </div>


                          <button
                            type="button"
                            style={styles.copyButton}
                            onClick={() =>
                              copiarEnlace(
                                aplicacion.token_publico
                              )
                            }
                          >
                            📋 Copiar enlace
                          </button>

                        </div>

                      )}


                      {/* RESULTADO */}

                      {aplicacion.estatus ===
                        "completada" && (

                        <div style={styles.resultBox}>

                          <div style={styles.resultTitle}>
                            ✅ Aplicación completada
                          </div>


                          <div style={styles.resultGrid}>


                            <div>

                              <span style={styles.smallLabel}>
                                Fecha
                              </span>

                              <strong>
                                {
                                  formatearFecha(
                                    aplicacion.fecha_completada
                                  )
                                }
                              </strong>

                            </div>


                            <div>

                              <span style={styles.smallLabel}>
                                Puntaje acumulado
                              </span>

                              <strong>
                                {
                                  aplicacion.puntaje_total ??
                                  "No disponible"
                                }
                              </strong>

                            </div>


                            <div>

                              <span style={styles.smallLabel}>
                                Nivel
                              </span>

                              <strong>
                                {
                                  textoNivelRiesgo(
                                    aplicacion.nivel_riesgo
                                  )
                                }
                              </strong>

                            </div>

                          </div>


                          {!aplicacion.nivel_riesgo && (

                            <div style={styles.pendingCalculation}>

                              <strong>
                                ⚙️ Calificación pendiente
                              </strong>

                              <p style={styles.pendingText}>
                                El cuestionario ya fue
                                contestado y sus puntajes
                                fueron almacenados. La
                                clasificación por nivel se
                                habilitará al incorporar las
                                reglas de calificación de la
                                guía correspondiente.
                              </p>

                            </div>

                          )}


                          {aplicacion.resultado_general && (

                            <div style={styles.section}>

                              <strong>
                                Resultado general
                              </strong>

                              <p style={styles.text}>
                                {
                                  aplicacion.resultado_general
                                }
                              </p>

                            </div>

                          )}


                          {/* CATEGORÍAS */}

                          {categorias.length > 0 && (

                            <div style={styles.section}>

                              <strong>
                                Categorías
                              </strong>


                              <div style={styles.scoreList}>

                                {categorias.map(
                                  (
                                    categoria,
                                    index
                                  ) => (

                                    <div
                                      key={
                                        `${categoria.nombre}-${index}`
                                      }
                                      style={styles.scoreRow}
                                    >

                                      <span>
                                        {
                                          categoria.nombre
                                        }
                                      </span>

                                      <strong>
                                        {
                                          categoria.puntaje
                                        }
                                      </strong>

                                    </div>

                                  )
                                )}

                              </div>

                            </div>

                          )}


                          {/* DOMINIOS */}

                          {dominios.length > 0 && (

                            <div style={styles.section}>

                              <strong>
                                Dominios
                              </strong>


                              <div style={styles.scoreList}>

                                {dominios.map(
                                  (
                                    dominio,
                                    index
                                  ) => (

                                    <div
                                      key={
                                        `${dominio.nombre}-${index}`
                                      }
                                      style={styles.scoreRow}
                                    >

                                      <span>
                                        {
                                          dominio.nombre
                                        }
                                      </span>

                                      <strong>
                                        {
                                          dominio.puntaje
                                        }
                                      </strong>

                                    </div>

                                  )
                                )}

                              </div>

                            </div>

                          )}


                          {aplicacion.recomendaciones && (

                            <div style={styles.section}>

                              <strong>
                                Recomendaciones
                              </strong>

                              <p style={styles.text}>
                                {
                                  aplicacion.recomendaciones
                                }
                              </p>

                            </div>

                          )}

                        </div>

                      )}


                      {/* CANCELAR */}

                      {(
                        aplicacion.estatus ===
                          "habilitada" ||
                        aplicacion.estatus ===
                          "iniciada"
                      ) && (

                        <div style={styles.itemActions}>

                          <button
                            type="button"
                            style={styles.cancelButton}
                            onClick={() =>
                              cancelarAplicacion(
                                aplicacion.id_aplicacion
                              )
                            }
                          >
                            Cancelar aplicación
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


        {/* ==========================================
            AVISO FINAL
        ========================================== */}

        <div style={styles.footerNotice}>

          <strong>
            📌 Importante
          </strong>

          <p style={styles.footerText}>
            MirrorSoul conservará cada aplicación
            NOM-035 de manera independiente. Los
            resultados de este módulo no deben
            mezclarse con diagnósticos clínicos ni
            con el expediente psicológico del
            empleado.
          </p>

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
    maxWidth: "750px",
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
    marginBottom: "22px",
    color: "#1e3a8a"
  },

  noticeText: {
    margin: "7px 0 0",
    lineHeight: 1.5
  },

  questionnaireInfo: {
    background: "#f8fafc",
    border: "1px solid #e4e7ec",
    borderRadius: "12px",
    padding: "15px",
    marginBottom: "18px"
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

  list: {
    display: "flex",
    flexDirection: "column",
    gap: "16px"
  },

  applicationCard: {
    border: "1px solid #e4e7ec",
    borderRadius: "14px",
    padding: "18px"
  },

  applicationHeader: {
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

  guideBadge: {
    background: "#ede9fe",
    color: "#5b21b6",
    padding: "5px 9px",
    borderRadius: "20px",
    fontSize: "12px",
    fontWeight: "800"
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

  applicationTitle: {
    margin: 0,
    fontSize: "18px"
  },

  dateText: {
    color: "#667085",
    fontSize: "13px"
  },

  section: {
    marginTop: "15px"
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

  pendingCalculation: {
    background: "#fff7ed",
    border: "1px solid #fed7aa",
    borderRadius: "10px",
    padding: "13px",
    marginTop: "15px",
    color: "#9a3412"
  },

  pendingText: {
    margin: "6px 0 0",
    lineHeight: 1.5
  },

  scoreList: {
    marginTop: "9px",
    display: "flex",
    flexDirection: "column",
    gap: "7px"
  },

  scoreRow: {
    background: "#ffffff",
    border: "1px solid #e4e7ec",
    borderRadius: "8px",
    padding: "9px 11px",
    display: "flex",
    justifyContent: "space-between",
    gap: "12px"
  },

  itemActions: {
    display: "flex",
    justifyContent: "flex-end",
    marginTop: "15px"
  },

  cancelButton: {
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
  },

  footerNotice: {
    background: "#ffffff",
    borderRadius: "12px",
    padding: "16px",
    marginBottom: "25px",
    boxShadow:
      "0 3px 14px rgba(0,0,0,.04)"
  },

  footerText: {
    margin: "7px 0 0",
    color: "#667085",
    lineHeight: 1.5
  }

};


export default Nom035Empleado;