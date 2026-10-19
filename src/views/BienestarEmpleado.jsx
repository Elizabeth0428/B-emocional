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


const BienestarEmpleado = () => {

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

  const [resumen, setResumen] =
    useState(null);

  const [seguimientos, setSeguimientos] =
    useState([]);

  const [evaluaciones, setEvaluaciones] =
    useState([]);

  const [acciones, setAcciones] =
    useState([]);

  const [proximasRevisiones, setProximasRevisiones] =
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
      tipo: "prevencion",
      origen: "iniciativa_rh",
      descripcion: "",
      accion_realizada: "",
      responsable: "",
      resultado: "pendiente",
      proxima_accion: "",
      fecha_proxima_revision: "",
      observaciones: ""
    });


  // ==================================================
  // CARGAR PANEL
  // ==================================================

  const cargarPanel =
    useCallback(
      async () => {

        try {

          setCargando(true);
          setError("");

          const respuesta =
            await axios.get(
              `/api/empleados/${idEmpleado}/bienestar`,
              config
            );


          setEmpleado(
            respuesta.data?.empleado ||
            null
          );


          setResumen(
            respuesta.data?.resumen ||
            null
          );


          setSeguimientos(
            Array.isArray(
              respuesta.data?.seguimientos
            )
              ? respuesta.data.seguimientos
              : []
          );


          setEvaluaciones(
            Array.isArray(
              respuesta.data?.evaluaciones
            )
              ? respuesta.data.evaluaciones
              : []
          );


          setAcciones(
            Array.isArray(
              respuesta.data?.acciones_preventivas
            )
              ? respuesta.data.acciones_preventivas
              : []
          );


          setProximasRevisiones(
            Array.isArray(
              respuesta.data?.proximas_revisiones
            )
              ? respuesta.data.proximas_revisiones
              : []
          );


        } catch (err) {

          console.error(
            "❌ Error cargando bienestar:",
            err
          );

          setError(
            err.response?.data?.message ||
            "No fue posible cargar el módulo de bienestar."
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
      cargarPanel();
    },
    [cargarPanel]
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
  // FECHA PARA INPUT
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
  // LIMPIAR FORMULARIO
  // ==================================================

  const limpiarFormulario =
    () => {

      setForm({
        fecha: "",
        tipo: "prevencion",
        origen: "iniciativa_rh",
        descripcion: "",
        accion_realizada: "",
        responsable: "",
        resultado: "pendiente",
        proxima_accion: "",
        fecha_proxima_revision: "",
        observaciones: ""
      });


      setEditandoId(
        null
      );

    };


  // ==================================================
  // GUARDAR ACCIÓN
  // ==================================================

  const guardarAccion =
    async e => {

      e.preventDefault();


      if (
        !String(
          form.descripcion ||
          ""
        ).trim()
      ) {

        setError(
          "La descripción es obligatoria."
        );

        return;
      }


      if (
        !String(
          form.accion_realizada ||
          ""
        ).trim()
      ) {

        setError(
          "La acción realizada es obligatoria."
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

          origen:
            form.origen,

          descripcion:
            String(
              form.descripcion
            ).trim(),

          accion_realizada:
            String(
              form.accion_realizada
            ).trim(),

          responsable:
            String(
              form.responsable ||
              ""
            ).trim() ||
            null,

          resultado:
            form.resultado,

          proxima_accion:
            String(
              form.proxima_accion ||
              ""
            ).trim() ||
            null,

          fecha_proxima_revision:
            form.fecha_proxima_revision ||
            null,

          observaciones:
            String(
              form.observaciones ||
              ""
            ).trim() ||
            null

        };


        if (
          editandoId
        ) {

          const respuesta =
            await axios.put(
              `/api/empleados/${idEmpleado}/bienestar/acciones/${editandoId}`,
              payload,
              config
            );


          setMensaje(
            respuesta.data?.message ||
            "Acción preventiva actualizada."
          );

        } else {

          const respuesta =
            await axios.post(
              `/api/empleados/${idEmpleado}/bienestar/acciones`,
              payload,
              config
            );


          setMensaje(
            respuesta.data?.message ||
            "Acción preventiva registrada."
          );

        }


        limpiarFormulario();

        await cargarPanel();


      } catch (err) {

        console.error(
          "❌ Error guardando acción preventiva:",
          err
        );


        setError(
          err.response?.data?.message ||
          "No fue posible guardar la acción preventiva."
        );


      } finally {

        setGuardando(false);

      }

    };


  // ==================================================
  // EDITAR ACCIÓN
  // ==================================================

  const editarAccion =
    accion => {

      setEditandoId(
        accion.id_accion
      );


      setForm({

        fecha:
          fechaParaInput(
            accion.fecha
          ),

        tipo:
          accion.tipo ||
          "prevencion",

        origen:
          accion.origen ||
          "iniciativa_rh",

        descripcion:
          accion.descripcion ||
          "",

        accion_realizada:
          accion.accion_realizada ||
          "",

        responsable:
          accion.responsable ||
          "",

        resultado:
          accion.resultado ||
          "pendiente",

        proxima_accion:
          accion.proxima_accion ||
          "",

        fecha_proxima_revision:
          fechaParaInput(
            accion.fecha_proxima_revision
          ),

        observaciones:
          accion.observaciones ||
          ""

      });


      window.scrollTo({
        top: 0,
        behavior: "smooth"
      });

    };


  // ==================================================
  // ELIMINAR ACCIÓN
  // ==================================================

  const eliminarAccion =
    async idAccion => {

      const confirmar =
        window.confirm(
          "¿Deseas eliminar esta acción preventiva?"
        );


      if (!confirmar) {
        return;
      }


      try {

        setError("");
        setMensaje("");


        const respuesta =
          await axios.delete(
            `/api/empleados/${idEmpleado}/bienestar/acciones/${idAccion}`,
            config
          );


        setMensaje(
          respuesta.data?.message ||
          "Acción preventiva eliminada."
        );


        if (
          Number(
            editandoId
          ) ===
          Number(
            idAccion
          )
        ) {

          limpiarFormulario();

        }


        await cargarPanel();


      } catch (err) {

        console.error(
          "❌ Error eliminando acción preventiva:",
          err
        );


        setError(
          err.response?.data?.message ||
          "No fue posible eliminar la acción preventiva."
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

        seguimiento:
          "Seguimiento",

        carga_trabajo:
          "Carga de trabajo",

        adaptacion:
          "Adaptación",

        clima_laboral:
          "Clima laboral",

        conflicto:
          "Conflicto",

        bienestar:
          "Bienestar",

        prevencion:
          "Prevención",

        orientacion:
          "Orientación",

        otro:
          "Otro"

      };


      return (
        tipos[tipo] ||
        tipo ||
        "Acción"
      );

    };


  // ==================================================
  // TEXTO ORIGEN
  // ==================================================

  const textoOrigen =
    origen => {

      const origenes = {

        seguimiento:
          "Seguimiento",

        evaluacion:
          "Evaluación",

        observacion_rh:
          "Observación RH",

        solicitud_empleado:
          "Solicitud del empleado",

        iniciativa_rh:
          "Iniciativa RH",

        otro:
          "Otro"

      };


      return (
        origenes[origen] ||
        origen ||
        "RH"
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

        en_seguimiento:
          "En seguimiento",

        completada:
          "Completada",

        sin_cambio:
          "Sin cambio",

        mejora_observada:
          "Mejora observada",

        requiere_nueva_revision:
          "Requiere nueva revisión"

      };


      return (
        resultados[resultado] ||
        resultado ||
        "Pendiente"
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
              🌿 Bienestar y prevención
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
            🌿 Bienestar y prevención
          </h1>

          <p style={styles.subtitle}>
            Consulta el seguimiento preventivo del
            empleado y registra acciones realizadas
            por Recursos Humanos.
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
            RESUMEN
        ========================================== */}

        <div style={styles.summaryGrid}>

          <div style={styles.summaryCard}>

            <div style={styles.summaryIcon}>
              📋
            </div>

            <div style={styles.summaryNumber}>
              {
                resumen?.seguimientos?.total ??
                0
              }
            </div>

            <div style={styles.summaryLabel}>
              Seguimientos
            </div>

            <small style={styles.summaryDetail}>
              {
                resumen?.seguimientos
                  ?.requiere_atencion ??
                0
              } requieren atención
            </small>

          </div>


          <div style={styles.summaryCard}>

            <div style={styles.summaryIcon}>
              🧠
            </div>

            <div style={styles.summaryNumber}>
              {
                resumen?.evaluaciones?.total ??
                0
              }
            </div>

            <div style={styles.summaryLabel}>
              Evaluaciones
            </div>

            <small style={styles.summaryDetail}>
              {
                resumen?.evaluaciones
                  ?.completadas ??
                0
              } completadas
            </small>

          </div>


          <div style={styles.summaryCard}>

            <div style={styles.summaryIcon}>
              🌱
            </div>

            <div style={styles.summaryNumber}>
              {
                resumen?.acciones_preventivas
                  ?.total ??
                0
              }
            </div>

            <div style={styles.summaryLabel}>
              Acciones preventivas
            </div>

            <small style={styles.summaryDetail}>
              {
                resumen?.acciones_preventivas
                  ?.en_seguimiento ??
                0
              } en seguimiento
            </small>

          </div>


          <div style={styles.summaryCard}>

            <div style={styles.summaryIcon}>
              📅
            </div>

            <div style={styles.summaryNumber}>
              {
                proximasRevisiones.length
              }
            </div>

            <div style={styles.summaryLabel}>
              Próximas revisiones
            </div>

            <small style={styles.summaryDetail}>
              Seguimiento pendiente
            </small>

          </div>

        </div>


        {/* ==========================================
            NUEVA ACCIÓN PREVENTIVA
        ========================================== */}

        <div style={styles.card}>

          <div style={styles.cardHeader}>

            <div>

              <h2 style={styles.cardTitle}>
                {
                  editandoId
                    ? "✏️ Editar acción preventiva"
                    : "➕ Registrar acción preventiva"
                }
              </h2>

              <p style={styles.cardSubtitle}>
                Documenta las medidas preventivas
                realizadas por RH.
              </p>

            </div>

          </div>


          <form
            onSubmit={
              guardarAccion
            }
          >

            <div style={styles.gridTwo}>


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

              </div>


              <div style={styles.field}>

                <label style={styles.label}>
                  Tipo
                </label>

                <select
                  name="tipo"
                  value={form.tipo}
                  onChange={cambiarCampo}
                  style={styles.input}
                >

                  <option value="prevencion">
                    Prevención
                  </option>

                  <option value="seguimiento">
                    Seguimiento
                  </option>

                  <option value="carga_trabajo">
                    Carga de trabajo
                  </option>

                  <option value="adaptacion">
                    Adaptación
                  </option>

                  <option value="clima_laboral">
                    Clima laboral
                  </option>

                  <option value="conflicto">
                    Conflicto
                  </option>

                  <option value="bienestar">
                    Bienestar
                  </option>

                  <option value="orientacion">
                    Orientación
                  </option>

                  <option value="otro">
                    Otro
                  </option>

                </select>

              </div>

            </div>


            <div style={styles.gridTwo}>


              <div style={styles.field}>

                <label style={styles.label}>
                  Origen
                </label>

                <select
                  name="origen"
                  value={form.origen}
                  onChange={cambiarCampo}
                  style={styles.input}
                >

                  <option value="iniciativa_rh">
                    Iniciativa RH
                  </option>

                  <option value="seguimiento">
                    Seguimiento
                  </option>

                  <option value="evaluacion">
                    Evaluación
                  </option>

                  <option value="observacion_rh">
                    Observación RH
                  </option>

                  <option value="solicitud_empleado">
                    Solicitud del empleado
                  </option>

                  <option value="otro">
                    Otro
                  </option>

                </select>

              </div>


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

                  <option value="en_seguimiento">
                    En seguimiento
                  </option>

                  <option value="completada">
                    Completada
                  </option>

                  <option value="sin_cambio">
                    Sin cambio
                  </option>

                  <option value="mejora_observada">
                    Mejora observada
                  </option>

                  <option value="requiere_nueva_revision">
                    Requiere nueva revisión
                  </option>

                </select>

              </div>

            </div>


            <div style={styles.field}>

              <label style={styles.label}>
                Descripción *
              </label>

              <textarea
                name="descripcion"
                value={form.descripcion}
                onChange={cambiarCampo}
                style={styles.textarea}
                rows={4}
                placeholder="Describe el motivo laboral o preventivo que origina la acción..."
              />

            </div>


            <div style={styles.field}>

              <label style={styles.label}>
                Acción realizada *
              </label>

              <textarea
                name="accion_realizada"
                value={form.accion_realizada}
                onChange={cambiarCampo}
                style={styles.textarea}
                rows={4}
                placeholder="Ej. Reunión con responsable de área, ajuste de carga, orientación..."
              />

            </div>


            <div style={styles.field}>

              <label style={styles.label}>
                Responsable
              </label>

              <input
                type="text"
                name="responsable"
                value={form.responsable}
                onChange={cambiarCampo}
                style={styles.input}
                placeholder="Ej. Recursos Humanos / Jefe de área"
              />

            </div>


            <div style={styles.gridTwo}>


              <div style={styles.field}>

                <label style={styles.label}>
                  Próxima acción
                </label>

                <textarea
                  name="proxima_accion"
                  value={form.proxima_accion}
                  onChange={cambiarCampo}
                  style={styles.textarea}
                  rows={3}
                  placeholder="Ej. Revisar nuevamente la carga laboral..."
                />

              </div>


              <div style={styles.field}>

                <label style={styles.label}>
                  Fecha próxima revisión
                </label>

                <input
                  type="datetime-local"
                  name="fecha_proxima_revision"
                  value={
                    form.fecha_proxima_revision
                  }
                  onChange={cambiarCampo}
                  style={styles.input}
                />

              </div>

            </div>


            <div style={styles.field}>

              <label style={styles.label}>
                Observaciones adicionales
              </label>

              <textarea
                name="observaciones"
                value={form.observaciones}
                onChange={cambiarCampo}
                style={styles.textarea}
                rows={3}
                placeholder="Información complementaria..."
              />

            </div>


            <div style={styles.notice}>

              <strong>
                ℹ️ Uso preventivo
              </strong>

              <p style={styles.noticeText}>
                Registra únicamente información
                relacionada con el contexto laboral,
                acciones de prevención y seguimiento
                de RH. Este módulo no sustituye una
                valoración clínica.
              </p>

            </div>


            <div style={styles.actions}>

              {editandoId && (

                <button
                  type="button"
                  style={styles.secondaryButton}
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
                    : "Registrar acción"
                }

              </button>

            </div>

          </form>

        </div>


        {/* ==========================================
            PRÓXIMAS REVISIONES
        ========================================== */}

        <div style={styles.card}>

          <div style={styles.cardHeader}>

            <div>

              <h2 style={styles.cardTitle}>
                📅 Próximas revisiones
              </h2>

              <p style={styles.cardSubtitle}>
                Acciones y seguimientos que tienen
                una fecha futura registrada.
              </p>

            </div>


            <div style={styles.counter}>
              {
                proximasRevisiones.length
              }
            </div>

          </div>


          {proximasRevisiones.length ===
          0 ? (

            <div style={styles.empty}>
              No hay revisiones programadas.
            </div>

          ) : (

            <div style={styles.list}>

              {proximasRevisiones.map(
                (
                  revision,
                  index
                ) => (

                  <div
                    key={
                      `${revision.origen}-${revision.id_registro}-${index}`
                    }
                    style={styles.smallCard}
                  >

                    <div>

                      <strong>
                        {
                          revision.origen ===
                          "accion_preventiva"
                            ? "🌱 Acción preventiva"
                            : "📋 Seguimiento"
                        }
                      </strong>

                      <p style={styles.text}>
                        {
                          revision.descripcion ||
                          "Revisión pendiente"
                        }
                      </p>

                    </div>


                    <div style={styles.dateText}>
                      {
                        formatearFecha(
                          revision.fecha
                        )
                      }
                    </div>

                  </div>

                )
              )}

            </div>

          )}

        </div>


        {/* ==========================================
            ACCIONES PREVENTIVAS
        ========================================== */}

        <div style={styles.card}>

          <div style={styles.cardHeader}>

            <div>

              <h2 style={styles.cardTitle}>
                🌱 Acciones preventivas
              </h2>

              <p style={styles.cardSubtitle}>
                Historial de medidas realizadas
                durante el seguimiento laboral.
              </p>

            </div>


            <div style={styles.counter}>
              {acciones.length}
            </div>

          </div>


          {acciones.length ===
          0 ? (

            <div style={styles.empty}>

              <div style={styles.emptyIcon}>
                🌿
              </div>

              <h3>
                Sin acciones preventivas
              </h3>

              <p>
                Todavía no se han registrado acciones.
              </p>

            </div>

          ) : (

            <div style={styles.list}>

              {acciones.map(
                accion => (

                  <div
                    key={
                      accion.id_accion
                    }
                    style={styles.historyCard}
                  >

                    <div style={styles.historyHeader}>

                      <div>

                        <div style={styles.badges}>

                          <span style={styles.badge}>
                            {
                              textoTipo(
                                accion.tipo
                              )
                            }
                          </span>

                          <span style={styles.badgeGray}>
                            {
                              textoOrigen(
                                accion.origen
                              )
                            }
                          </span>

                          <span style={styles.badgeGray}>
                            {
                              textoResultado(
                                accion.resultado
                              )
                            }
                          </span>

                        </div>


                        <h3 style={styles.itemTitle}>
                          {
                            accion.descripcion
                          }
                        </h3>

                      </div>


                      <div style={styles.dateText}>
                        {
                          formatearFecha(
                            accion.fecha
                          )
                        }
                      </div>

                    </div>


                    <div style={styles.section}>

                      <strong>
                        Acción realizada
                      </strong>

                      <p style={styles.text}>
                        {
                          accion.accion_realizada
                        }
                      </p>

                    </div>


                    {accion.responsable && (

                      <div style={styles.section}>

                        <strong>
                          Responsable
                        </strong>

                        <p style={styles.text}>
                          {
                            accion.responsable
                          }
                        </p>

                      </div>

                    )}


                    {accion.proxima_accion && (

                      <div style={styles.nextBox}>

                        <strong>
                          📌 Próxima acción
                        </strong>

                        <p style={styles.text}>
                          {
                            accion.proxima_accion
                          }
                        </p>

                        {accion.fecha_proxima_revision && (

                          <small style={styles.meta}>
                            Próxima revisión:{" "}
                            {
                              formatearFecha(
                                accion.fecha_proxima_revision
                              )
                            }
                          </small>

                        )}

                      </div>

                    )}


                    {accion.observaciones && (

                      <div style={styles.section}>

                        <strong>
                          Observaciones
                        </strong>

                        <p style={styles.text}>
                          {
                            accion.observaciones
                          }
                        </p>

                      </div>

                    )}


                    {accion.usuario_registro && (

                      <div style={styles.registeredBy}>
                        Registrado por{" "}
                        <strong>
                          {
                            accion.usuario_registro
                          }
                        </strong>
                      </div>

                    )}


                    <div style={styles.itemActions}>

                      <button
                        type="button"
                        style={styles.editButton}
                        onClick={() =>
                          editarAccion(
                            accion
                          )
                        }
                      >
                        ✏️ Editar
                      </button>


                      <button
                        type="button"
                        style={styles.deleteButton}
                        onClick={() =>
                          eliminarAccion(
                            accion.id_accion
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


        {/* ==========================================
            SEGUIMIENTOS RECIENTES
        ========================================== */}

        <div style={styles.card}>

          <div style={styles.cardHeader}>

            <div>

              <h2 style={styles.cardTitle}>
                📋 Seguimientos recientes
              </h2>

              <p style={styles.cardSubtitle}>
                Últimos registros del seguimiento
                laboral.
              </p>

            </div>

          </div>


          {seguimientos.length ===
          0 ? (

            <div style={styles.empty}>
              Sin seguimientos registrados.
            </div>

          ) : (

            <div style={styles.list}>

              {seguimientos.map(
                seguimiento => (

                  <div
                    key={
                      seguimiento.id_seguimiento
                    }
                    style={styles.smallCard}
                  >

                    <div>

                      <strong>
                        {
                          seguimiento.motivo ||
                          "Seguimiento laboral"
                        }
                      </strong>

                      <p style={styles.text}>
                        {
                          seguimiento.observacion
                        }
                      </p>

                      <small style={styles.meta}>
                        Resultado:{" "}
                        {
                          seguimiento.resultado
                        }
                      </small>

                    </div>


                    <div style={styles.dateText}>
                      {
                        formatearFecha(
                          seguimiento.fecha
                        )
                      }
                    </div>

                  </div>

                )
              )}

            </div>

          )}

        </div>


        {/* ==========================================
            EVALUACIONES RECIENTES
        ========================================== */}

        <div style={styles.card}>

          <div style={styles.cardHeader}>

            <div>

              <h2 style={styles.cardTitle}>
                🧠 Evaluaciones recientes
              </h2>

              <p style={styles.cardSubtitle}>
                Últimas evaluaciones aplicadas al
                empleado.
              </p>

            </div>

          </div>


          {evaluaciones.length ===
          0 ? (

            <div style={styles.empty}>
              Sin evaluaciones registradas.
            </div>

          ) : (

            <div style={styles.list}>

              {evaluaciones.map(
                evaluacion => (

                  <div
                    key={
                      evaluacion.id_habilitacion
                    }
                    style={styles.smallCard}
                  >

                    <div>

                      <strong>
                        {
                          evaluacion.prueba_nombre ||
                          "Evaluación RH"
                        }
                      </strong>

                      <p style={styles.text}>
                        Tipo:{" "}
                        {
                          evaluacion.tipo_evaluacion
                        }
                      </p>

                      <small style={styles.meta}>
                        Estado:{" "}
                        {
                          evaluacion.estatus
                        }
                      </small>

                      {evaluacion.estatus ===
                        "completada" && (

                        <div style={styles.score}>
                          Puntaje bruto:{" "}
                          <strong>
                            {
                              evaluacion.puntaje_total ??
                              "No disponible"
                            }
                          </strong>
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

  summaryGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(190px, 1fr))",
    gap: "15px",
    marginBottom: "22px"
  },

  summaryCard: {
    background: "#ffffff",
    borderRadius: "14px",
    padding: "18px",
    boxShadow:
      "0 4px 18px rgba(0,0,0,.05)"
  },

  summaryIcon: {
    fontSize: "24px"
  },

  summaryNumber: {
    fontSize: "28px",
    fontWeight: "800",
    marginTop: "7px"
  },

  summaryLabel: {
    fontWeight: "700",
    marginTop: "2px"
  },

  summaryDetail: {
    display: "block",
    color: "#667085",
    marginTop: "6px"
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

  secondaryButton: {
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
    justifyContent: "center",
    alignItems: "center",
    fontWeight: "700"
  },

  list: {
    display: "flex",
    flexDirection: "column",
    gap: "14px"
  },

  historyCard: {
    border: "1px solid #e4e7ec",
    borderRadius: "14px",
    padding: "18px"
  },

  historyHeader: {
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

  badge: {
    background: "#ecfdf3",
    color: "#067647",
    padding: "5px 9px",
    borderRadius: "20px",
    fontSize: "12px",
    fontWeight: "700"
  },

  badgeGray: {
    background: "#f2f4f7",
    color: "#475467",
    padding: "5px 9px",
    borderRadius: "20px",
    fontSize: "12px",
    fontWeight: "700"
  },

  itemTitle: {
    margin: 0,
    fontSize: "18px",
    lineHeight: 1.4
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

  nextBox: {
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

  smallCard: {
    border: "1px solid #e4e7ec",
    borderRadius: "12px",
    padding: "15px",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    flexWrap: "wrap",
    gap: "12px"
  },

  dateText: {
    color: "#667085",
    fontSize: "13px"
  },

  score: {
    marginTop: "7px",
    color: "#344054"
  },

  empty: {
    textAlign: "center",
    padding: "28px",
    color: "#667085"
  },

  emptyIcon: {
    fontSize: "38px"
  }

};


export default BienestarEmpleado;