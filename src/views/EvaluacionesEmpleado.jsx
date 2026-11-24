// src/views/EvaluacionesEmpleado.jsx

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

import {
  getToken
} from "../services/AuthService";

const API_URL =
  import.meta.env.VITE_API_URL ||
  `${import.meta.env.VITE_API_URL || window.location.origin}`;

const FORM_INICIAL = {
  id_prueba_rh: "",
  motivo: "",
  tipo_evaluacion: "periodica"
};

const EvaluacionesEmpleado = () => {
  const { idEmpleado } =
    useParams();

  const navigate =
    useNavigate();

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

  const [
    empleado,
    setEmpleado
  ] = useState(null);

  const [
    pruebasDisponibles,
    setPruebasDisponibles
  ] = useState([]);

  const [
    evaluaciones,
    setEvaluaciones
  ] = useState([]);

  const [
    cargando,
    setCargando
  ] = useState(true);

  const [
    habilitando,
    setHabilitando
  ] = useState(false);

  const [
    procesandoId,
    setProcesandoId
  ] = useState(null);

  const [
    error,
    setError
  ] = useState("");

  const [
    mensaje,
    setMensaje
  ] = useState("");

  const [
    formularioAbierto,
    setFormularioAbierto
  ] = useState(false);

  const [
    activasAbiertas,
    setActivasAbiertas
  ] = useState(true);

  const [
    historialAbierto,
    setHistorialAbierto
  ] = useState(true);

  const [
    resultadosAbiertos,
    setResultadosAbiertos
  ] = useState({});

  const [
    evolucionAbierta,
    setEvolucionAbierta
  ] = useState(false);

  const [
    form,
    setForm
  ] = useState(
    FORM_INICIAL
  );

  // ==================================================
  // CARGAR INFORMACIÓN
  // ==================================================

  const cargarDatos =
    useCallback(
      async () => {
        try {
          setCargando(true);
          setError("");

          if (!token) {
            throw new Error(
              "Tu sesión no es válida."
            );
          }

          const [
            respuestaDisponibles,
            respuestaEvaluaciones
          ] =
            await Promise.all([
              axios.get(
                `${API_URL}/api/empleados/${idEmpleado}/evaluaciones/disponibles`,
                config
              ),

              axios.get(
                `${API_URL}/api/empleados/${idEmpleado}/evaluaciones`,
                config
              )
            ]);

          setEmpleado(
            respuestaEvaluaciones
              .data?.empleado ||
            respuestaDisponibles
              .data?.empleado ||
            null
          );

          setPruebasDisponibles(
            Array.isArray(
              respuestaDisponibles
                .data?.pruebas
            )
              ? respuestaDisponibles
                  .data.pruebas
              : []
          );

          setEvaluaciones(
            Array.isArray(
              respuestaEvaluaciones
                .data?.evaluaciones
            )
              ? respuestaEvaluaciones
                  .data.evaluaciones
              : []
          );

        } catch (err) {
          console.error(
            "❌ Error cargando evaluaciones del empleado:",
            err
          );

          setError(
            err.response?.data
              ?.message ||
            err.message ||
            "No fue posible cargar las evaluaciones."
          );

        } finally {
          setCargando(false);
        }
      },
      [
        idEmpleado,
        config,
        token
      ]
    );

  useEffect(
    () => {
      cargarDatos();
    },
    [cargarDatos]
  );

  // ==================================================
  // CLASIFICAR EVALUACIONES
  // ==================================================

  const evaluacionesActivas =
    useMemo(
      () =>
        evaluaciones.filter(
          item =>
            item.estatus ===
              "habilitada" ||
            item.estatus ===
              "iniciada"
        ),
      [evaluaciones]
    );

  const evaluacionesHistorial =
    useMemo(
      () =>
        evaluaciones.filter(
          item =>
            item.estatus ===
              "completada" ||
            item.estatus ===
              "cancelada"
        ),
      [evaluaciones]
    );

  const completadas =
    useMemo(
      () =>
        evaluaciones.filter(
          item =>
            item.estatus ===
            "completada"
        ),
      [evaluaciones]
    );

  const canceladas =
    useMemo(
      () =>
        evaluaciones.filter(
          item =>
            item.estatus ===
            "cancelada"
        ),
      [evaluaciones]
    );

  // ==================================================
  // AGRUPAR COMPLETADAS POR PRUEBA
  // PARA EVOLUCIÓN
  // ==================================================

  const gruposEvolucion =
    useMemo(
      () => {
        const grupos = {};

        completadas.forEach(
          item => {
            const clave =
              String(
                item.id_prueba_rh
              );

            if (!grupos[clave]) {
              grupos[clave] = {
                id_prueba_rh:
                  item.id_prueba_rh,

                nombre:
                  item.prueba_nombre ||
                  "Evaluación RH",

                categoria:
                  item.categoria ||
                  null,

                version:
                  item.version ||
                  null,

                registros: []
              };
            }

            grupos[clave]
              .registros
              .push(item);
          }
        );

        return Object.values(
          grupos
        )
          .filter(
            grupo =>
              grupo.registros
                .length > 1
          )
          .map(
            grupo => ({
              ...grupo,

              registros:
                [...grupo.registros]
                  .sort(
                    (a, b) =>
                      new Date(
                        a.fecha_completada ||
                        a.fecha_resultado ||
                        0
                      ) -
                      new Date(
                        b.fecha_completada ||
                        b.fecha_resultado ||
                        0
                      )
                  )
            })
          );
      },
      [completadas]
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
            `${API_URL}/api/empleados/${idEmpleado}/evaluaciones/habilitar`,
            {
              id_prueba_rh:
                idPrueba,

              motivo:
                String(
                  form.motivo ||
                  ""
                ).trim() ||
                null,

              tipo_evaluacion:
                form.tipo_evaluacion
            },
            config
          );

        setMensaje(
          respuesta.data
            ?.message ||
          "Evaluación habilitada correctamente."
        );

        setForm(
          FORM_INICIAL
        );

        setFormularioAbierto(
          false
        );

        setActivasAbiertas(
          true
        );

        await cargarDatos();

      } catch (err) {
        console.error(
          "❌ Error habilitando evaluación:",
          err
        );

        setError(
          err.response?.data
            ?.message ||
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
          "¿Deseas cancelar esta evaluación? El registro permanecerá en el historial."
        );

      if (!confirmar) {
        return;
      }

      try {
        setProcesandoId(
          idHabilitacion
        );

        setError("");
        setMensaje("");

        const respuesta =
          await axios.put(
            `${API_URL}/api/empleados/${idEmpleado}/evaluaciones/${idHabilitacion}/cancelar`,
            {},
            config
          );

        setMensaje(
          respuesta.data
            ?.message ||
          "Evaluación cancelada correctamente."
        );

        await cargarDatos();

      } catch (err) {
        console.error(
          "❌ Error cancelando evaluación:",
          err
        );

        setError(
          err.response?.data
            ?.message ||
          "No fue posible cancelar la evaluación."
        );

      } finally {
        setProcesandoId(
          null
        );
      }
    };

  // ==================================================
  // ELIMINAR EVALUACIÓN CANCELADA
  // ==================================================

  const eliminarEvaluacion =
    async idHabilitacion => {

      const confirmar =
        window.confirm(
          "¿Seguro que deseas eliminar definitivamente esta evaluación cancelada? Esta acción no se puede deshacer."
        );

      if (!confirmar) {
        return;
      }

      try {

        setProcesandoId(
          idHabilitacion
        );

        setError("");
        setMensaje("");

        const respuesta =
          await axios.delete(
            `${API_URL}/api/empleados/${idEmpleado}/evaluaciones/${idHabilitacion}`,
            config
          );

        setMensaje(
          respuesta.data
            ?.message ||
          "Evaluación eliminada correctamente."
        );

        setResultadosAbiertos(
          prev => {
            const copia = {
              ...prev
            };

            delete copia[
              idHabilitacion
            ];

            return copia;
          }
        );

        await cargarDatos();

      } catch (err) {

        console.error(
          "❌ Error eliminando evaluación:",
          err
        );

        setError(
          err.response?.data
            ?.message ||
          "No fue posible eliminar la evaluación."
        );

      } finally {

        setProcesandoId(
          null
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
        await navigator
          .clipboard
          .writeText(
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
  // ABRIR EVALUACIÓN EN OTRA PESTAÑA
  // ==================================================

  const abrirEvaluacion =
    tokenPublico => {
      const enlace =
        `${window.location.origin}/evaluacion-empleado/${tokenPublico}`;

      window.open(
        enlace,
        "_blank",
        "noopener,noreferrer"
      );
    };

  // ==================================================
  // RESULTADO ACORDEÓN
  // ==================================================

  const alternarResultado =
    idHabilitacion => {
      setResultadosAbiertos(
        prev => ({
          ...prev,
          [idHabilitacion]:
            !prev[
              idHabilitacion
            ]
        })
      );
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

      return date
        .toLocaleString(
          "es-MX",
          {
            dateStyle:
              "medium",

            timeStyle:
              "short"
          }
        );
    };

  const formatearFechaCorta =
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

      return date
        .toLocaleDateString(
          "es-MX",
          {
            day:
              "2-digit",

            month:
              "short",

            year:
              "numeric"
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
          texto:
            "Pendiente",
          fondo:
            "#fff7e6",
          color:
            "#b7791f"
        },

        iniciada: {
          texto:
            "Iniciada",
          fondo:
            "#eef4ff",
          color:
            "#2167d5"
        },

        completada: {
          texto:
            "Completada",
          fondo:
            "#ecfdf3",
          color:
            "#067647"
        },

        cancelada: {
          texto:
            "Cancelada",
          fondo:
            "#f2f4f7",
          color:
            "#667085"
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
  // RESULTADO COMPLETO
  // ==================================================

  const tieneDetalleResultado =
    evaluacion =>
      Boolean(
        evaluacion
          .resultado_texto ||
        evaluacion
          .interpretacion ||
        evaluacion
          .interpretacion_laboral ||
        evaluacion
          .fortalezas ||
        evaluacion
          .areas_atencion ||
        evaluacion
          .indicadores_prevencion ||
        evaluacion
          .recomendaciones ||
        evaluacion
          .preevaluacion_ia
      );

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

  // ==================================================
  // VISTA
  // ==================================================

  return (
    <div style={styles.page}>
      <div style={styles.container}>

        {/* VOLVER */}

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

        {/* ENCABEZADO */}

        <div style={styles.headerRow}>
          <div>
            <h1 style={styles.title}>
              🧠 Evaluaciones periódicas
            </h1>

            <p style={styles.subtitle}>
              Aplica instrumentos de seguimiento,
              bienestar, prevención y contexto laboral,
              conservando el historial de cada aplicación.
            </p>
          </div>

          <button
            type="button"
            style={styles.newButton}
            onClick={() => {
              setFormularioAbierto(
                prev => !prev
              );

              setError("");
              setMensaje("");
            }}
          >
            {
              formularioAbierto
                ? "✕ Cerrar formulario"
                : "＋ Nueva evaluación"
            }
          </button>
        </div>

        {/* EMPLEADO */}

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

            <div style={{ flex: 1 }}>
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

              {empleado.responsable_actual && (
                <div style={styles.meta}>
                  👤 Responsable RH actual:{" "}
                  <strong>
                    {
                      empleado
                        .responsable_actual
                    }
                  </strong>
                </div>
              )}
            </div>
          </div>
        )}

        {/* RESUMEN */}

        <div style={styles.summaryGrid}>
          <div style={styles.summaryCard}>
            <div style={styles.summaryNumber}>
              {evaluaciones.length}
            </div>

            <div style={styles.summaryLabel}>
              Total
            </div>
          </div>

          <div style={styles.summaryCard}>
            <div style={styles.summaryNumber}>
              {evaluacionesActivas.length}
            </div>

            <div style={styles.summaryLabel}>
              Pendientes / iniciadas
            </div>
          </div>

          <div style={styles.summaryCard}>
            <div style={styles.summaryNumber}>
              {completadas.length}
            </div>

            <div style={styles.summaryLabel}>
              Completadas
            </div>
          </div>

          <div style={styles.summaryCard}>
            <div style={styles.summaryNumber}>
              {canceladas.length}
            </div>

            <div style={styles.summaryLabel}>
              Canceladas
            </div>
          </div>
        </div>

        {/* MENSAJES */}

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

        {/* NUEVA EVALUACIÓN */}

        {formularioAbierto && (
          <div style={styles.card}>
            <div style={styles.cardHeader}>
              <div>
                <h2 style={styles.cardTitle}>
                  ➕ Nueva evaluación
                </h2>

                <p style={styles.cardSubtitle}>
                  Selecciona una prueba RH y genera
                  un enlace individual para el empleado.
                </p>
              </div>
            </div>

            <form
              onSubmit={
                habilitarEvaluacion
              }
            >
              <div style={styles.gridTwo}>

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
                          {
                            prueba.version
                              ? ` · v${prueba.version}`
                              : ""
                          }
                        </option>
                      )
                    )}
                  </select>

                  {pruebasDisponibles.length ===
                    0 && (
                    <small style={styles.helpText}>
                      No existen pruebas RH activas
                      disponibles.
                    </small>
                  )}
                </div>

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
                  Los resultados deben interpretarse
                  dentro del contexto laboral y no
                  representan por sí solos un diagnóstico
                  médico o psicológico.
                </p>
              </div>

              <div style={styles.actions}>
                <button
                  type="button"
                  style={styles.secondaryButton}
                  onClick={() => {
                    setFormularioAbierto(
                      false
                    );

                    setForm(
                      FORM_INICIAL
                    );
                  }}
                >
                  Cancelar
                </button>

                <button
                  type="submit"
                  disabled={
                    habilitando ||
                    pruebasDisponibles.length ===
                      0
                  }
                  style={{
                    ...styles.primaryButton,

                    opacity:
                      habilitando ||
                      pruebasDisponibles.length ===
                        0
                        ? 0.6
                        : 1
                  }}
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
        )}

        {/* ==========================================
            EVALUACIONES ACTIVAS
        ========================================== */}

        <div style={styles.card}>
          <button
            type="button"
            style={styles.sectionHeaderButton}
            onClick={() =>
              setActivasAbiertas(
                prev => !prev
              )
            }
          >
            <div>
              <h2 style={styles.cardTitle}>
                ⏳ Evaluaciones activas
              </h2>

              <p style={styles.cardSubtitle}>
                Evaluaciones pendientes de iniciar
                o actualmente en proceso.
              </p>
            </div>

            <div style={styles.headerRight}>
              <span style={styles.counter}>
                {
                  evaluacionesActivas
                    .length
                }
              </span>

              <span style={styles.arrow}>
                {
                  activasAbiertas
                    ? "▲"
                    : "▼"
                }
              </span>
            </div>
          </button>

          {activasAbiertas && (
            <>
              {evaluacionesActivas.length ===
              0 ? (
                <div style={styles.emptyCompact}>
                  ✅ No hay evaluaciones pendientes.
                </div>
              ) : (
                <div style={styles.evaluationList}>
                  {evaluacionesActivas.map(
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
                          style={styles.activeCard}
                        >
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
                                  {
                                    estado.texto
                                  }
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

                              {evaluacion.version && (
                                <div style={styles.meta}>
                                  Versión:{" "}
                                  {
                                    evaluacion.version
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

                          <div style={styles.traceBox}>
                            <span>
                              Habilitada por:{" "}
                              <strong>
                                {
                                  evaluacion.usuario_registro ||
                                  "Usuario no disponible"
                                }
                              </strong>
                            </span>

                            {evaluacion.fecha_inicio && (
                              <span>
                                Inicio:{" "}
                                {
                                  formatearFecha(
                                    evaluacion.fecha_inicio
                                  )
                                }
                              </span>
                            )}
                          </div>

                          <div style={styles.linkBox}>
                            <strong>
                              🔗 Enlace del empleado
                            </strong>

                            <div style={styles.linkText}>
                              {enlace}
                            </div>

                            <div style={styles.linkActions}>
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

                              <button
                                type="button"
                                style={styles.openButton}
                                onClick={() =>
                                  abrirEvaluacion(
                                    evaluacion.token_publico
                                  )
                                }
                              >
                                ↗ Abrir
                              </button>
                            </div>
                          </div>

                          <div style={styles.itemActions}>
                            <button
                              type="button"
                              disabled={
                                procesandoId ===
                                evaluacion.id_habilitacion
                              }
                              style={{
                                ...styles.cancelEvaluationButton,

                                opacity:
                                  procesandoId ===
                                  evaluacion.id_habilitacion
                                    ? 0.6
                                    : 1
                              }}
                              onClick={() =>
                                cancelarEvaluacion(
                                  evaluacion.id_habilitacion
                                )
                              }
                            >
                              {
                                procesandoId ===
                                evaluacion.id_habilitacion
                                  ? "Cancelando..."
                                  : "Cancelar evaluación"
                              }
                            </button>
                          </div>
                        </div>
                      );
                    }
                  )}
                </div>
              )}
            </>
          )}
        </div>

        {/* ==========================================
            EVOLUCIÓN
        ========================================== */}

        {gruposEvolucion.length >
          0 && (
          <div style={styles.card}>
            <button
              type="button"
              style={styles.sectionHeaderButton}
              onClick={() =>
                setEvolucionAbierta(
                  prev => !prev
                )
              }
            >
              <div>
                <h2 style={styles.cardTitle}>
                  📊 Evolución periódica
                </h2>

                <p style={styles.cardSubtitle}>
                  Comparación de aplicaciones repetidas
                  del mismo instrumento.
                </p>
              </div>

              <span style={styles.arrow}>
                {
                  evolucionAbierta
                    ? "▲"
                    : "▼"
                }
              </span>
            </button>

            {evolucionAbierta && (
              <div style={styles.evolutionList}>
                {gruposEvolucion.map(
                  grupo => (
                    <div
                      key={
                        grupo.id_prueba_rh
                      }
                      style={styles.evolutionCard}
                    >
                      <h3 style={styles.evolutionTitle}>
                        {grupo.nombre}
                      </h3>

                      <div style={styles.meta}>
                        {
                          grupo.categoria
                            ? `Categoría: ${grupo.categoria}`
                            : "Evaluación RH"
                        }

                        {grupo.version
                          ? ` · Versión ${grupo.version}`
                          : ""}
                      </div>

                      <div style={styles.evolutionWarning}>
                        La comparación del puntaje bruto
                        solo es válida cuando las aplicaciones
                        corresponden al mismo instrumento y
                        versión.
                      </div>

                      <div style={styles.evolutionRows}>
                        {grupo.registros.map(
                          item => (
                            <div
                              key={
                                item.id_habilitacion
                              }
                              style={styles.evolutionRow}
                            >
                              <span>
                                {
                                  formatearFechaCorta(
                                    item.fecha_completada ||
                                    item.fecha_resultado
                                  )
                                }
                              </span>

                              <strong>
                                Puntaje:{" "}
                                {
                                  item.puntaje_total ??
                                  "N/D"
                                }
                              </strong>
                            </div>
                          )
                        )}
                      </div>
                    </div>
                  )
                )}
              </div>
            )}
          </div>
        )}

        {/* ==========================================
            HISTORIAL
        ========================================== */}

        <div style={styles.card}>
          <button
            type="button"
            style={styles.sectionHeaderButton}
            onClick={() =>
              setHistorialAbierto(
                prev => !prev
              )
            }
          >
            <div>
              <h2 style={styles.cardTitle}>
                📁 Historial de evaluaciones
              </h2>

              <p style={styles.cardSubtitle}>
                Evaluaciones completadas y canceladas
                durante la relación laboral.
              </p>
            </div>

            <div style={styles.headerRight}>
              <span style={styles.counter}>
                {
                  evaluacionesHistorial
                    .length
                }
              </span>

              <span style={styles.arrow}>
                {
                  historialAbierto
                    ? "▲"
                    : "▼"
                }
              </span>
            </div>
          </button>

          {historialAbierto && (
            <>
              {evaluacionesHistorial.length ===
              0 ? (
                <div style={styles.empty}>
                  <div style={styles.emptyIcon}>
                    🧠
                  </div>

                  <h3>
                    Sin historial
                  </h3>

                  <p>
                    Todavía no existen evaluaciones
                    completadas o canceladas.
                  </p>
                </div>
              ) : (
                <div style={styles.evaluationList}>
                  {evaluacionesHistorial.map(
                    evaluacion => {
                      const estado =
                        obtenerEstado(
                          evaluacion.estatus
                        );

                      const detalleAbierto =
                        Boolean(
                          resultadosAbiertos[
                            evaluacion.id_habilitacion
                          ]
                        );

                      return (
                        <div
                          key={
                            evaluacion.id_habilitacion
                          }
                          style={{
                            ...styles.historyCard,

                            ...(evaluacion.estatus ===
                            "cancelada"
                              ? styles.cancelledCard
                              : {})
                          }}
                        >
                          <button
                            type="button"
                            style={styles.historyHeader}
                            onClick={() =>
                              alternarResultado(
                                evaluacion.id_habilitacion
                              )
                            }
                          >
                            <div style={styles.historyMain}>
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
                                  {
                                    estado.texto
                                  }
                                </span>
                              </div>

                              <div style={styles.historyTitle}>
                                {
                                  evaluacion.prueba_nombre ||
                                  "Evaluación RH"
                                }
                              </div>

                              <div style={styles.historyMeta}>
                                {
                                  evaluacion.categoria
                                    ? `${evaluacion.categoria} · `
                                    : ""
                                }

                                {
                                  formatearFechaCorta(
                                    evaluacion.fecha_completada ||
                                    evaluacion.fecha_habilitacion
                                  )
                                }
                              </div>
                            </div>

                            <div style={styles.historySide}>
                              {evaluacion.estatus ===
                                "completada" && (
                                <div style={styles.scorePreview}>
                                  Puntaje:{" "}
                                  <strong>
                                    {
                                      evaluacion.puntaje_total ??
                                      "N/D"
                                    }
                                  </strong>
                                </div>
                              )}

                              <div style={styles.viewDetail}>
                                {
                                  detalleAbierto
                                    ? "Cerrar ▲"
                                    : "Ver detalle ▼"
                                }
                              </div>
                            </div>
                          </button>

                          {detalleAbierto && (
                            <div style={styles.historyDetail}>

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

                              <div style={styles.traceBox}>
                                <span>
                                  Habilitada por:{" "}
                                  <strong>
                                    {
                                      evaluacion.usuario_registro ||
                                      "Usuario no disponible"
                                    }
                                  </strong>
                                </span>

                                <span>
                                  Fecha habilitación:{" "}
                                  {
                                    formatearFecha(
                                      evaluacion.fecha_habilitacion
                                    )
                                  }
                                </span>
                              </div>

                              {evaluacion.estatus ===
                                "cancelada" && (
                                <div style={styles.cancelledBox}>
                                  <strong>
                                    ⚪ Evaluación cancelada
                                  </strong>

                                  <p style={styles.noticeText}>
                                    La evaluación quedó registrada
                                    en el historial y ya no puede
                                    responderse.
                                  </p>
                                </div>
                              )}

                              {evaluacion.estatus ===
                                "cancelada" && (
                                <div style={styles.itemActions}>
                                  <button
                                    type="button"
                                    disabled={
                                      procesandoId ===
                                      evaluacion.id_habilitacion
                                    }
                                    style={{
                                      ...styles.deleteEvaluationButton,

                                      opacity:
                                        procesandoId ===
                                        evaluacion.id_habilitacion
                                          ? 0.6
                                          : 1
                                    }}
                                    onClick={() =>
                                      eliminarEvaluacion(
                                        evaluacion.id_habilitacion
                                      )
                                    }
                                  >
                                    {
                                      procesandoId ===
                                      evaluacion.id_habilitacion
                                        ? "Eliminando..."
                                        : "🗑 Eliminar evaluación"
                                    }
                                  </button>
                                </div>
                              )}

                              {evaluacion.estatus ===
                                "completada" && (
                                <div style={styles.resultBox}>
                                  <div style={styles.resultTitle}>
                                    ✅ Resultado de la evaluación
                                  </div>

                                  <div style={styles.resultGrid}>
                                    <div>
                                      <span style={styles.smallLabel}>
                                        Fecha completada
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
                                    <div style={styles.resultSection}>
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
  <div style={styles.resultSection}>
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

{evaluacion.interpretacion && (
  <div style={styles.resultSection}>
    <strong>
      Interpretación
    </strong>

    <p style={styles.text}>
      {
        evaluacion.interpretacion
      }
    </p>
  </div>
)}

                                  {evaluacion.fortalezas && (
                                    <div style={styles.goodBox}>
                                      <strong>
                                        💪 Fortalezas
                                      </strong>

                                      <p style={styles.text}>
                                        {
                                          evaluacion.fortalezas
                                        }
                                      </p>
                                    </div>
                                  )}

                                  {evaluacion.areas_atencion && (
                                    <div style={styles.warningBox}>
                                      <strong>
                                        ⚠️ Áreas de atención
                                      </strong>

                                      <p style={styles.text}>
                                        {
                                          evaluacion.areas_atencion
                                        }
                                      </p>
                                    </div>
                                  )}

                                  {evaluacion.indicadores_prevencion && (
                                    <div style={styles.preventionBox}>
                                      <strong>
                                        🛡️ Indicadores de prevención
                                      </strong>

                                      <p style={styles.text}>
                                        {
                                          evaluacion.indicadores_prevencion
                                        }
                                      </p>
                                    </div>
                                  )}

                                  {evaluacion.recomendaciones && (
                                    <div style={styles.recommendationBox}>
                                      <strong>
                                        📌 Recomendaciones
                                      </strong>

                                      <p style={styles.text}>
                                        {
                                          evaluacion.recomendaciones
                                        }
                                      </p>
                                    </div>
                                  )}

                                  {evaluacion.preevaluacion_ia ? (
                                    <div style={styles.aiEvaluationBox}>
                                      <div style={styles.aiEvaluationHeader}>
                                        <div>
                                          <div style={styles.aiEvaluationEyebrow}>
                                            🤖 MIRRORSOUL IA
                                          </div>

                                          <strong style={styles.aiEvaluationTitle}>
                                            Pre-evaluación IA
                                          </strong>
                                        </div>

                                        <span style={styles.aiOrientativeBadge}>
                                          Orientativa
                                        </span>
                                      </div>

                                      <div style={styles.aiEvaluationContent}>
                                        {
                                          evaluacion.preevaluacion_ia
                                        }
                                      </div>

                                      <div style={styles.aiEvaluationMeta}>
                                        {evaluacion.fecha_preevaluacion_ia && (
                                          <span>
                                            📅{" "}
                                            {
                                              formatearFecha(
                                                evaluacion.fecha_preevaluacion_ia
                                              )
                                            }
                                          </span>
                                        )}

                                        {evaluacion.ia_proveedor && (
                                          <span>
                                            🤖 Proveedor:{" "}
                                            <strong>
                                              {
                                                evaluacion.ia_proveedor
                                              }
                                            </strong>
                                          </span>
                                        )}

                                        {evaluacion.ia_modelo && (
                                          <span>
                                            ⚙️ Modelo:{" "}
                                            <strong>
                                              {
                                                evaluacion.ia_modelo
                                              }
                                            </strong>
                                          </span>
                                        )}
                                      </div>

                                      <div style={styles.aiDisclaimer}>
                                        Esta pre-evaluación fue generada
                                        exclusivamente a partir del resultado
                                        de esta evaluación laboral. Es una
                                        herramienta orientativa para Recursos
                                        Humanos y no constituye un diagnóstico
                                        médico o psicológico.
                                      </div>
                                    </div>
                                  ) : (
                                    <div style={styles.aiPendingBox}>
                                      <div style={styles.aiPendingHeader}>
                                        🤖 Pre-evaluación IA
                                      </div>

                                      <p style={styles.aiPendingText}>
                                        Esta evaluación no cuenta con una
                                        pre-evaluación IA registrada.
                                      </p>
                                    </div>
                                  )}

                                  {!tieneDetalleResultado(
                                    evaluacion
                                  ) && (
                                    <div style={styles.basicResultNotice}>
                                      Por ahora este instrumento
                                      únicamente tiene disponible
                                      el puntaje bruto.
                                    </div>
                                  )}

                                  <div style={styles.resultDisclaimer}>
                                    El resultado debe interpretarse
                                    dentro del contexto laboral y junto
                                    con otras fuentes de información.
                                    No constituye por sí solo un
                                    diagnóstico clínico.
                                  </div>
                                </div>
                              )}

                            </div>
                          )}
                        </div>
                      );
                    }
                  )}
                </div>
              )}
            </>
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
    background:
      "linear-gradient(135deg,#f4f8fd 0%,#f8fbff 55%,#eef5fd 100%)",
    padding: "30px 20px",
    boxSizing: "border-box"
  },

  container: {
    maxWidth: "1100px",
    margin: "0 auto"
  },

  backButton: {
    border: "none",
    background: "transparent",
    padding: 0,
    marginBottom: "15px",
    cursor: "pointer",
    color: "#344054",
    fontWeight: "700",
    fontSize: "14px"
  },

  headerRow: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    flexWrap: "wrap",
    gap: "18px",
    marginBottom: "22px"
  },

  title: {
    margin: "0 0 7px",
    fontSize: "30px",
    color: "#173e70"
  },

  subtitle: {
    margin: 0,
    color: "#667085",
    maxWidth: "760px",
    lineHeight: 1.6
  },

  newButton: {
    border: "none",
    borderRadius: "11px",
    background: "#2167d5",
    color: "#ffffff",
    padding: "12px 17px",
    cursor: "pointer",
    fontWeight: "800",
    whiteSpace: "nowrap"
  },

  employeeCard: {
    background: "#ffffff",
    borderRadius: "18px",
    padding: "20px",
    display: "flex",
    alignItems: "center",
    gap: "17px",
    marginBottom: "18px",
    boxShadow:
      "0 8px 24px rgba(30,64,120,.07)",
    border: "1px solid #e6edf6"
  },

  avatar: {
    width: "62px",
    height: "62px",
    minWidth: "62px",
    borderRadius: "50%",
    background: "#e7f0ff",
    color: "#2167d5",
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    fontWeight: "900",
    fontSize: "25px"
  },

  employeeName: {
    margin: "0 0 6px",
    color: "#173e70"
  },

  meta: {
    color: "#667085",
    fontSize: "13px",
    marginTop: "4px"
  },

  summaryGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(150px,1fr))",
    gap: "12px",
    marginBottom: "22px"
  },

  summaryCard: {
    background: "#ffffff",
    border: "1px solid #e3ebf5",
    borderRadius: "14px",
    padding: "16px",
    textAlign: "center",
    boxShadow:
      "0 5px 16px rgba(30,64,120,.05)"
  },

  summaryNumber: {
    fontSize: "25px",
    fontWeight: "900",
    color: "#173e70"
  },

  summaryLabel: {
    color: "#667085",
    fontSize: "12px",
    fontWeight: "700",
    marginTop: "4px"
  },

  card: {
    background: "#ffffff",
    borderRadius: "18px",
    padding: "24px",
    marginBottom: "22px",
    boxShadow:
      "0 8px 24px rgba(30,64,120,.07)",
    border: "1px solid #e6edf6"
  },

  cardHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "15px",
    marginBottom: "20px"
  },

  cardTitle: {
    margin: "0 0 5px",
    color: "#173e70"
  },

  cardSubtitle: {
    margin: 0,
    color: "#667085",
    lineHeight: 1.5
  },

  sectionHeaderButton: {
    width: "100%",
    border: "none",
    background: "transparent",
    padding: 0,
    cursor: "pointer",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    textAlign: "left",
    gap: "16px",
    marginBottom: "8px"
  },

  headerRight: {
    display: "flex",
    alignItems: "center",
    gap: "12px"
  },

  arrow: {
    color: "#667085",
    fontSize: "12px"
  },

  gridTwo: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(230px,1fr))",
    gap: "16px"
  },

  field: {
    marginBottom: "18px"
  },

  label: {
    display: "block",
    fontWeight: "800",
    marginBottom: "7px",
    color: "#344054"
  },

  input: {
    width: "100%",
    boxSizing: "border-box",
    border: "1px solid #d0d5dd",
    borderRadius: "10px",
    padding: "11px 12px",
    background: "#ffffff",
    fontSize: "15px",
    outline: "none"
  },

  textarea: {
    width: "100%",
    boxSizing: "border-box",
    border: "1px solid #d0d5dd",
    borderRadius: "10px",
    padding: "12px",
    resize: "vertical",
    fontFamily: "inherit",
    fontSize: "15px",
    outline: "none",
    lineHeight: 1.5
  },

  helpText: {
    display: "block",
    color: "#667085",
    marginTop: "6px"
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
    background: "#2167d5",
    color: "#ffffff",
    padding: "11px 17px",
    cursor: "pointer",
    fontWeight: "800"
  },

  secondaryButton: {
    border: "1px solid #d0d5dd",
    borderRadius: "10px",
    background: "#ffffff",
    color: "#344054",
    padding: "11px 17px",
    cursor: "pointer",
    fontWeight: "700"
  },

  success: {
    background: "#ecfdf3",
    border: "1px solid #abefc6",
    color: "#067647",
    borderRadius: "10px",
    padding: "13px",
    marginBottom: "18px"
  },

  error: {
    background: "#fef3f2",
    border: "1px solid #fecdca",
    color: "#b42318",
    borderRadius: "10px",
    padding: "13px",
    marginBottom: "18px"
  },

  counter: {
    minWidth: "38px",
    height: "38px",
    borderRadius: "10px",
    background: "#eef4ff",
    color: "#2167d5",
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    fontWeight: "900"
  },

  evaluationList: {
    display: "flex",
    flexDirection: "column",
    gap: "14px",
    marginTop: "18px"
  },

  activeCard: {
    border: "1px solid #dbe7f5",
    borderRadius: "14px",
    padding: "18px",
    background: "#ffffff"
  },

  historyCard: {
    border: "1px solid #e4e7ec",
    borderRadius: "14px",
    background: "#ffffff",
    overflow: "hidden"
  },

  cancelledCard: {
    background: "#fafafa",
    opacity: 0.85
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
    fontWeight: "800"
  },

  statusBadge: {
    padding: "5px 9px",
    borderRadius: "20px",
    fontSize: "12px",
    fontWeight: "800"
  },

  evaluationTitle: {
    margin: 0,
    fontSize: "18px",
    color: "#173e70"
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

  traceBox: {
    marginTop: "14px",
    background: "#f8fafc",
    border: "1px solid #e4e7ec",
    borderRadius: "10px",
    padding: "11px 13px",
    color: "#667085",
    fontSize: "12px",
    display: "flex",
    justifyContent: "space-between",
    gap: "10px",
    flexWrap: "wrap"
  },

  linkBox: {
    marginTop: "16px",
    background: "#f8fafc",
    borderRadius: "10px",
    padding: "14px",
    border: "1px solid #e4e7ec"
  },

  linkText: {
    wordBreak: "break-all",
    color: "#475467",
    fontSize: "13px",
    margin: "7px 0 10px"
  },

  linkActions: {
    display: "flex",
    gap: "8px",
    flexWrap: "wrap"
  },

  copyButton: {
    border: "1px solid #d0d5dd",
    background: "#ffffff",
    borderRadius: "8px",
    padding: "8px 11px",
    cursor: "pointer",
    fontWeight: "700"
  },

  openButton: {
    border: "1px solid #bfdbfe",
    background: "#eff6ff",
    color: "#175cd3",
    borderRadius: "8px",
    padding: "8px 11px",
    cursor: "pointer",
    fontWeight: "700"
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

  deleteEvaluationButton: {
    border: "1px solid #f04438",
    background: "#fff5f5",
    color: "#b42318",
    borderRadius: "8px",
    padding: "9px 13px",
    cursor: "pointer",
    fontWeight: "800"
  },

  historyHeader: {
    width: "100%",
    border: "none",
    background: "transparent",
    padding: "16px",
    cursor: "pointer",
    textAlign: "left",
    display: "flex",
    justifyContent: "space-between",
    gap: "16px"
  },

  historyMain: {
    flex: 1,
    minWidth: 0
  },

  historySide: {
    minWidth: "145px",
    textAlign: "right"
  },

  historyTitle: {
    color: "#173e70",
    fontWeight: "900",
    fontSize: "16px"
  },

  historyMeta: {
    color: "#667085",
    fontSize: "12px",
    marginTop: "5px"
  },

  scorePreview: {
    fontSize: "13px",
    color: "#344054"
  },

  viewDetail: {
    color: "#2167d5",
    fontSize: "12px",
    fontWeight: "800",
    marginTop: "7px"
  },

  historyDetail: {
    borderTop: "1px solid #e4e7ec",
    padding: "17px"
  },

  resultBox: {
    marginTop: "16px",
    background: "#f0fdf4",
    border: "1px solid #bbf7d0",
    borderRadius: "10px",
    padding: "15px"
  },

  resultTitle: {
    fontWeight: "900",
    color: "#166534",
    marginBottom: "12px"
  },

  resultGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(180px,1fr))",
    gap: "12px",
    marginBottom: "15px"
  },

  smallLabel: {
    display: "block",
    color: "#667085",
    fontSize: "12px",
    marginBottom: "4px"
  },

  resultSection: {
    marginTop: "14px",
    paddingTop: "14px",
    borderTop: "1px solid #d1fadf"
  },

  goodBox: {
    background: "#ecfdf3",
    border: "1px solid #abefc6",
    borderRadius: "10px",
    padding: "13px",
    marginTop: "14px"
  },

  warningBox: {
    background: "#fffaeb",
    border: "1px solid #fedf89",
    borderRadius: "10px",
    padding: "13px",
    marginTop: "14px"
  },

  preventionBox: {
    background: "#eff8ff",
    border: "1px solid #b2ddff",
    borderRadius: "10px",
    padding: "13px",
    marginTop: "14px"
  },

  recommendationBox: {
    background: "#f9f5ff",
    border: "1px solid #d6bbfb",
    borderRadius: "10px",
    padding: "13px",
    marginTop: "14px"
  },

  aiEvaluationBox: {
    marginTop: "16px",
    background:
      "linear-gradient(135deg,#f5f3ff 0%,#faf5ff 100%)",
    border: "1px solid #ddd6fe",
    borderRadius: "12px",
    padding: "16px"
  },

  aiEvaluationHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "12px",
    flexWrap: "wrap",
    marginBottom: "14px"
  },

  aiEvaluationEyebrow: {
    color: "#7c3aed",
    fontSize: "11px",
    fontWeight: "900",
    letterSpacing: ".5px",
    marginBottom: "4px"
  },

  aiEvaluationTitle: {
    color: "#4c1d95",
    fontSize: "16px"
  },

  aiOrientativeBadge: {
    background: "#ede9fe",
    color: "#6d28d9",
    border: "1px solid #ddd6fe",
    borderRadius: "999px",
    padding: "5px 9px",
    fontSize: "11px",
    fontWeight: "800"
  },

  aiEvaluationContent: {
    whiteSpace: "pre-wrap",
    lineHeight: "1.65",
    color: "#344054",
    fontSize: "14px",
    background: "#ffffff",
    border: "1px solid #ede9fe",
    borderRadius: "9px",
    padding: "14px"
  },

  aiEvaluationMeta: {
    display: "flex",
    flexWrap: "wrap",
    gap: "8px 16px",
    marginTop: "12px",
    color: "#667085",
    fontSize: "11px"
  },

  aiDisclaimer: {
    marginTop: "12px",
    paddingTop: "10px",
    borderTop: "1px solid #ddd6fe",
    color: "#6b7280",
    fontSize: "11px",
    lineHeight: "1.5"
  },

  aiPendingBox: {
    marginTop: "16px",
    background: "#f8fafc",
    border: "1px dashed #cbd5e1",
    borderRadius: "10px",
    padding: "13px"
  },

  aiPendingHeader: {
    fontWeight: "800",
    color: "#475467"
  },

  aiPendingText: {
    margin: "6px 0 0",
    color: "#667085",
    fontSize: "13px",
    lineHeight: "1.5"
  },

  basicResultNotice: {
    marginTop: "14px",
    color: "#667085",
    fontSize: "13px"
  },

  resultDisclaimer: {
    marginTop: "15px",
    paddingTop: "12px",
    borderTop: "1px solid #d1fadf",
    color: "#667085",
    fontSize: "12px",
    lineHeight: 1.5
  },

  cancelledBox: {
    marginTop: "15px",
    background: "#f2f4f7",
    border: "1px solid #d0d5dd",
    borderRadius: "10px",
    padding: "13px",
    color: "#475467"
  },

  evolutionList: {
    display: "flex",
    flexDirection: "column",
    gap: "14px",
    marginTop: "18px"
  },

  evolutionCard: {
    border: "1px solid #e4e7ec",
    borderRadius: "12px",
    padding: "15px"
  },

  evolutionTitle: {
    margin: "0 0 5px",
    color: "#173e70"
  },

  evolutionWarning: {
    marginTop: "10px",
    fontSize: "12px",
    color: "#667085",
    background: "#f8fafc",
    padding: "9px 11px",
    borderRadius: "8px"
  },

  evolutionRows: {
    marginTop: "12px",
    display: "flex",
    flexDirection: "column",
    gap: "8px"
  },

  evolutionRow: {
    display: "flex",
    justifyContent: "space-between",
    gap: "12px",
    padding: "10px 12px",
    background: "#f8fafc",
    borderRadius: "8px",
    color: "#475467"
  },

  empty: {
    textAlign: "center",
    padding: "34px",
    color: "#667085"
  },

  emptyCompact: {
    padding: "20px 0 4px",
    color: "#667085",
    textAlign: "center"
  },

  emptyIcon: {
    fontSize: "40px"
  }
};

export default EvaluacionesEmpleado;