import React, { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";
import { useNavigate, useParams } from "react-router-dom";
import { getToken } from "../services/AuthService";

const API_URL =
  import.meta.env.VITE_API_URL ||
  `${import.meta.env.VITE_API_URL || window.location.origin}`;

const FORM_INICIAL = {
  fecha: "",
  origen: "iniciativa_rh",
  descripcion: "",
  accion_realizada: "",
  responsable: "",
  resultado: "pendiente",
  estado: "abierto",
  proxima_accion: "",
  fecha_proxima_revision: "",
  observaciones: ""
};

const BienestarEmpleado = () => {
  const { idEmpleado } = useParams();
  const navigate = useNavigate();
  const token = getToken();

  const config = useMemo(
    () => ({
      headers: {
        Authorization: `Bearer ${token}`
      }
    }),
    [token]
  );

  const [empleado, setEmpleado] = useState(null);
  const [resumen, setResumen] = useState(null);
  const [acciones, setAcciones] = useState([]);
  const [evaluaciones, setEvaluaciones] = useState([]);
  const [proximasRevisiones, setProximasRevisiones] = useState([]);

  const [cargando, setCargando] = useState(true);
  const [guardando, setGuardando] = useState(false);
  const [procesandoId, setProcesandoId] = useState(null);

  const [error, setError] = useState("");
  const [mensaje, setMensaje] = useState("");

  const [formularioAbierto, setFormularioAbierto] = useState(false);
  const [editandoId, setEditandoId] = useState(null);

  const [form, setForm] = useState(FORM_INICIAL);

  const [seccionesAbiertas, setSeccionesAbiertas] = useState({
    acciones: true,
    evaluaciones: true,
    revisiones: true
  });

  const [detallesAbiertos, setDetallesAbiertos] = useState({});

  // ==================================================
  // CARGAR PANEL
  // ==================================================

  const cargarPanel = useCallback(async () => {
    try {
      setCargando(true);
      setError("");

      if (!token) {
        throw new Error("Tu sesión no es válida.");
      }

      const respuesta = await axios.get(
        `${API_URL}/api/empleados/${idEmpleado}/bienestar`,
        config
      );

      setEmpleado(respuesta.data?.empleado || null);
      setResumen(respuesta.data?.resumen || null);

      setEvaluaciones(
        Array.isArray(respuesta.data?.evaluaciones)
          ? respuesta.data.evaluaciones
          : []
      );

      setProximasRevisiones(
        Array.isArray(respuesta.data?.proximas_revisiones)
          ? respuesta.data.proximas_revisiones
          : []
      );

      /*
       * El endpoint general puede seguir regresando
       * acciones_preventivas.
       * Las usamos como carga inicial si existen.
       */
      if (Array.isArray(respuesta.data?.acciones_preventivas)) {
        setAcciones(respuesta.data.acciones_preventivas);
      } else {
        const accionesRespuesta = await axios.get(
          `${API_URL}/api/empleados/${idEmpleado}/bienestar/acciones`,
          config
        );

        setAcciones(
          Array.isArray(accionesRespuesta.data?.acciones)
            ? accionesRespuesta.data.acciones
            : Array.isArray(accionesRespuesta.data)
            ? accionesRespuesta.data
            : []
        );
      }
    } catch (err) {
      console.error("❌ Error cargando Bienestar:", err);

      setError(
        err.response?.data?.message ||
          err.message ||
          "No fue posible cargar el módulo de Bienestar."
      );
    } finally {
      setCargando(false);
    }
  }, [idEmpleado, config, token]);

  useEffect(() => {
    cargarPanel();
  }, [cargarPanel]);

  // ==================================================
  // ESTADÍSTICAS
  // ==================================================

  const accionesActivas = useMemo(
    () =>
      acciones.filter(
        item =>
          item.estado === "abierto" ||
          item.estado === "en_seguimiento"
      ),
    [acciones]
  );

  const accionesCerradas = useMemo(
    () => acciones.filter(item => item.estado === "cerrado"),
    [acciones]
  );

  const accionesAnuladas = useMemo(
    () => acciones.filter(item => item.estado === "anulado"),
    [acciones]
  );

  const requierenAtencion = useMemo(() => {
    const desdeResumen = Number(
      resumen?.evaluaciones?.requiere_atencion ??
        resumen?.requiere_atencion ??
        0
    );

    if (desdeResumen > 0) {
      return desdeResumen;
    }

    return evaluaciones.filter(
      item =>
        item.resultado === "requiere_atencion" ||
        item.requiere_atencion === true ||
        item.requiere_atencion === 1
    ).length;
  }, [resumen, evaluaciones]);

  const canalizaciones = useMemo(() => {
    const desdeResumen = Number(
      resumen?.evaluaciones?.canalizaciones_sugeridas ??
        resumen?.canalizaciones_sugeridas ??
        0
    );

    if (desdeResumen > 0) {
      return desdeResumen;
    }

    return evaluaciones.filter(
      item =>
        item.resultado === "canalizacion_sugerida" ||
        item.canalizacion_sugerida === true ||
        item.canalizacion_sugerida === 1
    ).length;
  }, [resumen, evaluaciones]);

  // ==================================================
  // SECCIONES
  // ==================================================

  const alternarSeccion = nombre => {
    setSeccionesAbiertas(prev => ({
      ...prev,
      [nombre]: !prev[nombre]
    }));
  };

  const alternarDetalle = id => {
    setDetallesAbiertos(prev => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  // ==================================================
  // FORMULARIO
  // ==================================================

  const cambiarCampo = e => {
    const { name, value } = e.target;

    setForm(prev => ({
      ...prev,
      [name]: value
    }));

    setError("");
    setMensaje("");
  };

  const limpiarFormulario = () => {
    setForm(FORM_INICIAL);
    setEditandoId(null);
  };

  const abrirFormulario = () => {
    limpiarFormulario();
    setFormularioAbierto(true);
    setError("");
    setMensaje("");

    window.scrollTo({
      top: 0,
      behavior: "smooth"
    });
  };

  const cerrarFormulario = () => {
    limpiarFormulario();
    setFormularioAbierto(false);
  };

  // ==================================================
  // FECHAS
  // ==================================================

  const fechaParaInput = fecha => {
    if (!fecha) {
      return "";
    }

    const date = new Date(fecha);

    if (Number.isNaN(date.getTime())) {
      return "";
    }

    const offset = date.getTimezoneOffset();

    const local = new Date(
      date.getTime() - offset * 60000
    );

    return local.toISOString().slice(0, 16);
  };

  const formatearFecha = fecha => {
    if (!fecha) {
      return "Sin fecha";
    }

    const date = new Date(fecha);

    if (Number.isNaN(date.getTime())) {
      return fecha;
    }

    return date.toLocaleString("es-MX", {
      dateStyle: "medium",
      timeStyle: "short"
    });
  };

  // ==================================================
  // GUARDAR ACCIÓN
  // ==================================================

  const guardarAccion = async e => {
    e.preventDefault();

    if (!String(form.descripcion || "").trim()) {
      setError(
        "Debes indicar la situación, factor o necesidad preventiva."
      );
      return;
    }

    if (!String(form.accion_realizada || "").trim()) {
      setError(
        "Debes indicar la acción preventiva o medida implementada."
      );
      return;
    }

    try {
      setGuardando(true);
      setError("");
      setMensaje("");

      const payload = {
        fecha: form.fecha || null,
        tipo: "prevencion",
        origen: form.origen || "iniciativa_rh",

        descripcion:
          String(form.descripcion || "").trim(),

        accion_realizada:
          String(form.accion_realizada || "").trim(),

        responsable:
          String(form.responsable || "").trim() ||
          null,

        resultado:
          form.resultado || "pendiente",

        estado:
          form.estado || "abierto",

        proxima_accion:
          String(form.proxima_accion || "").trim() ||
          null,

        fecha_proxima_revision:
          form.fecha_proxima_revision || null,

        observaciones:
          String(form.observaciones || "").trim() ||
          null
      };

      let respuesta;

      if (editandoId) {
        respuesta = await axios.put(
          `${API_URL}/api/empleados/${idEmpleado}/bienestar/acciones/${editandoId}`,
          payload,
          config
        );
      } else {
        respuesta = await axios.post(
          `${API_URL}/api/empleados/${idEmpleado}/bienestar/acciones`,
          payload,
          config
        );
      }

      setMensaje(
        respuesta.data?.message ||
          (editandoId
            ? "Acción preventiva actualizada correctamente."
            : "Acción preventiva registrada correctamente.")
      );

      limpiarFormulario();
      setFormularioAbierto(false);

      setSeccionesAbiertas(prev => ({
        ...prev,
        acciones: true
      }));

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
  // EDITAR
  // ==================================================

  const editarAccion = accion => {
    if (
      accion.estado === "cerrado" ||
      accion.estado === "anulado"
    ) {
      setError(
        "Las acciones cerradas o anuladas ya no pueden modificarse."
      );
      return;
    }

    setEditandoId(accion.id_accion);

    setForm({
      fecha:
        fechaParaInput(accion.fecha),

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

      estado:
        accion.estado ||
        "abierto",

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

    setFormularioAbierto(true);
    setError("");
    setMensaje("");

    window.scrollTo({
      top: 0,
      behavior: "smooth"
    });
  };

  // ==================================================
  // CERRAR
  // ==================================================

  const cerrarAccion = async accion => {
    const confirmar = window.confirm(
      "¿Deseas cerrar esta acción preventiva? Una vez cerrada ya no podrá editarse."
    );

    if (!confirmar) {
      return;
    }

    try {
      setProcesandoId(accion.id_accion);
      setError("");
      setMensaje("");

      const respuesta = await axios.put(
        `${API_URL}/api/empleados/${idEmpleado}/bienestar/acciones/${accion.id_accion}`,
        {
          estado: "cerrado",
          resultado:
            accion.resultado === "pendiente"
              ? "completado"
              : accion.resultado
        },
        config
      );

      setMensaje(
        respuesta.data?.message ||
          "Acción preventiva cerrada correctamente."
      );

      if (
        Number(editandoId) ===
        Number(accion.id_accion)
      ) {
        cerrarFormulario();
      }

      await cargarPanel();
    } catch (err) {
      console.error(
        "❌ Error cerrando acción preventiva:",
        err
      );

      setError(
        err.response?.data?.message ||
          "No fue posible cerrar la acción preventiva."
      );
    } finally {
      setProcesandoId(null);
    }
  };

  // ==================================================
  // ANULAR
  // ==================================================

  const anularAccion = async accion => {
    const motivo = window.prompt(
      "Indica el motivo de la anulación. El registro permanecerá visible por trazabilidad:"
    );

    if (motivo === null) {
      return;
    }

    const motivoLimpio =
      String(motivo).trim();

    if (!motivoLimpio) {
      setError(
        "Debes indicar el motivo de la anulación."
      );
      return;
    }

    const confirmar = window.confirm(
      "¿Confirmas la anulación de esta acción preventiva?"
    );

    if (!confirmar) {
      return;
    }

    try {
      setProcesandoId(accion.id_accion);
      setError("");
      setMensaje("");

      const respuesta = await axios.delete(
        `${API_URL}/api/empleados/${idEmpleado}/bienestar/acciones/${accion.id_accion}`,
        {
          ...config,
          data: {
            motivo_anulacion:
              motivoLimpio
          }
        }
      );

      setMensaje(
        respuesta.data?.message ||
          "Acción preventiva anulada correctamente."
      );

      if (
        Number(editandoId) ===
        Number(accion.id_accion)
      ) {
        cerrarFormulario();
      }

      await cargarPanel();
    } catch (err) {
      console.error(
        "❌ Error anulando acción preventiva:",
        err
      );

      setError(
        err.response?.data?.message ||
          "No fue posible anular la acción preventiva."
      );
    } finally {
      setProcesandoId(null);
    }
  };

  // ==================================================
  // TEXTOS
  // ==================================================

  const textoOrigen = origen => {
    const opciones = {
      iniciativa_rh: "Iniciativa de RH",
      evaluacion: "Evaluación preventiva",
      observacion: "Observación laboral",
      solicitud_empleado: "Solicitud del empleado",
      solicitud_supervisor: "Solicitud del supervisor",
      seguimiento: "Seguimiento preventivo",
      otro: "Otro"
    };

    return (
      opciones[origen] ||
      origen ||
      "No especificado"
    );
  };

  const textoResultado = resultado => {
    const opciones = {
      pendiente: "Pendiente",
      en_revision: "En revisión",
      sin_cambio: "Sin cambio",
      mejora: "Mejora",
      mejora_observada: "Mejora observada",
      completado: "Completado",
      completada: "Completada",
      requiere_atencion: "Requiere atención",
      canalizacion_sugerida:
        "Canalización sugerida"
    };

    return (
      opciones[resultado] ||
      resultado ||
      "Pendiente"
    );
  };

  const estadoInfo = estado => {
    const opciones = {
      abierto: {
        texto: "Abierto",
        fondo: "#fff7ed",
        color: "#c2410c"
      },

      en_seguimiento: {
        texto: "En seguimiento",
        fondo: "#eff6ff",
        color: "#175cd3"
      },

      cerrado: {
        texto: "Cerrado",
        fondo: "#ecfdf3",
        color: "#067647"
      },

      anulado: {
        texto: "Anulado",
        fondo: "#f2f4f7",
        color: "#667085"
      }
    };

    return (
      opciones[
        String(estado || "").toLowerCase()
      ] ||
      opciones.abierto
    );
  };

  const estadoEvaluacion = estado => {
    const opciones = {
      habilitada: {
        texto: "Pendiente",
        fondo: "#fff7ed",
        color: "#b54708"
      },

      iniciada: {
        texto: "Iniciada",
        fondo: "#eff6ff",
        color: "#175cd3"
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

    return opciones[estado] || opciones.habilitada;
  };

  // ==================================================
  // CARD ACCIÓN
  // ==================================================

  const renderAccion = accion => {
    const estado =
      estadoInfo(accion.estado);

    const abierto =
      Boolean(
        detallesAbiertos[
          accion.id_accion
        ]
      );

    const bloqueado =
      accion.estado === "cerrado" ||
      accion.estado === "anulado";

    return (
      <div
        key={accion.id_accion}
        style={{
          ...styles.recordCard,
          opacity:
            accion.estado === "anulado"
              ? 0.72
              : 1
        }}
      >
        <button
          type="button"
          style={styles.recordHeader}
          onClick={() =>
            alternarDetalle(
              accion.id_accion
            )
          }
        >
          <div style={styles.recordMain}>
            <div style={styles.badges}>
              <span
                style={styles.originBadge}
              >
                🛡️{" "}
                {textoOrigen(
                  accion.origen
                )}
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

            <h3 style={styles.recordTitle}>
              {accion.descripcion ||
                "Acción preventiva"}
            </h3>

            <div style={styles.recordMeta}>
              {formatearFecha(
                accion.fecha
              )}

              {accion.usuario_registro
                ? ` · Registrada por ${accion.usuario_registro}`
                : ""}
            </div>
          </div>

          <span style={styles.detailLink}>
            {abierto
              ? "Cerrar ▲"
              : "Ver detalle ▼"}
          </span>
        </button>

        {abierto && (
          <div style={styles.recordDetail}>

            {accion.accion_realizada && (
              <div style={styles.detailBlock}>
                <strong>
                  🛡️ Acción o medida preventiva
                </strong>

                <p style={styles.text}>
                  {
                    accion.accion_realizada
                  }
                </p>
              </div>
            )}

            {accion.responsable && (
              <div style={styles.detailBlock}>
                <strong>
                  👤 Responsable
                </strong>

                <p style={styles.text}>
                  {accion.responsable}
                </p>
              </div>
            )}

            {accion.resultado && (
              <div style={styles.resultBox}>
                <strong>
                  Resultado:
                </strong>{" "}
                {textoResultado(
                  accion.resultado
                )}
              </div>
            )}

            {accion.observaciones && (
              <div style={styles.detailBlock}>
                <strong>
                  📝 Observaciones
                </strong>

                <p style={styles.text}>
                  {accion.observaciones}
                </p>
              </div>
            )}

            {(accion.proxima_accion ||
              accion.fecha_proxima_revision) &&
              accion.estado !==
                "anulado" && (
                <div style={styles.nextBox}>
                  <strong>
                    📅 Próxima revisión
                  </strong>

                  {accion.proxima_accion && (
                    <p style={styles.text}>
                      {
                        accion.proxima_accion
                      }
                    </p>
                  )}

                  {accion.fecha_proxima_revision && (
                    <div
                      style={styles.nextDate}
                    >
                      {formatearFecha(
                        accion.fecha_proxima_revision
                      )}
                    </div>
                  )}
                </div>
              )}

            {accion.estado ===
              "cerrado" && (
              <div style={styles.closedBox}>
                <strong>
                  ✅ Acción preventiva cerrada
                </strong>

                {accion.fecha_cierre && (
                  <div
                    style={styles.auditText}
                  >
                    Fecha:{" "}
                    {formatearFecha(
                      accion.fecha_cierre
                    )}
                  </div>
                )}
              </div>
            )}

            {accion.estado ===
              "anulado" && (
              <div style={styles.cancelBox}>
                <strong>
                  ⚪ Registro anulado
                </strong>

                {accion.motivo_anulacion && (
                  <p style={styles.text}>
                    <strong>
                      Motivo:
                    </strong>{" "}
                    {
                      accion.motivo_anulacion
                    }
                  </p>
                )}

                {accion.fecha_anulacion && (
                  <div
                    style={styles.auditText}
                  >
                    Fecha:{" "}
                    {formatearFecha(
                      accion.fecha_anulacion
                    )}
                  </div>
                )}
              </div>
            )}

            {!bloqueado && (
              <div style={styles.actions}>
                <button
                  type="button"
                  style={styles.editButton}
                  disabled={
                    procesandoId ===
                    accion.id_accion
                  }
                  onClick={() =>
                    editarAccion(accion)
                  }
                >
                  ✏️ Editar
                </button>

                <button
                  type="button"
                  style={styles.closeButton}
                  disabled={
                    procesandoId ===
                    accion.id_accion
                  }
                  onClick={() =>
                    cerrarAccion(accion)
                  }
                >
                  ✅ Cerrar
                </button>

                <button
                  type="button"
                  style={styles.annulButton}
                  disabled={
                    procesandoId ===
                    accion.id_accion
                  }
                  onClick={() =>
                    anularAccion(accion)
                  }
                >
                  ⚪ Anular
                </button>
              </div>
            )}
          </div>
        )}
      </div>
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
              💙 Bienestar y prevención
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
          ← Volver al expediente del empleado
        </button>

        {/* CABECERA */}
        <div style={styles.headerRow}>
          <div>
            <h1 style={styles.title}>
              💙 Bienestar y prevención
            </h1>

            <p style={styles.subtitle}>
              Seguimiento preventivo del bienestar
              laboral, evaluaciones periódicas y
              acciones de apoyo para el empleado.
            </p>
          </div>

          <button
            type="button"
            style={styles.newButton}
            onClick={
              formularioAbierto
                ? cerrarFormulario
                : abrirFormulario
            }
          >
            {formularioAbierto
              ? "✕ Cerrar formulario"
              : "＋ Nueva acción preventiva"}
          </button>
        </div>

        {/* EMPLEADO */}
        {empleado && (
          <div style={styles.employeeCard}>
            <div style={styles.avatar}>
              {empleado.nombre
                ?.charAt(0)
                ?.toUpperCase() ||
                "E"}
            </div>

            <div style={{ flex: 1 }}>
              <h2 style={styles.employeeName}>
                {empleado.nombre}
              </h2>

              <div style={styles.meta}>
                🆔{" "}
                {empleado.id_mirror ||
                  "Sin ID MirrorSoul"}
              </div>

              <div style={styles.meta}>
                💼{" "}
                {empleado.puesto ||
                  "Puesto no especificado"}
              </div>

              <div style={styles.meta}>
                Departamento:{" "}
                <strong>
                  {empleado.departamento ||
                    "No especificado"}
                </strong>
              </div>

              {empleado.responsable_actual && (
                <div style={styles.meta}>
                  👤 Responsable RH:{" "}
                  <strong>
                    {
                      empleado.responsable_actual
                    }
                  </strong>
                </div>
              )}
            </div>
          </div>
        )}

        {/* AVISO */}
        <div style={styles.infoBox}>
          <div style={styles.infoIcon}>
            ℹ️
          </div>

          <div>
            <strong>
              Módulo preventivo de RH
            </strong>

            <p style={styles.infoText}>
              Este módulo permite registrar acciones
              preventivas y revisar evaluaciones
              relacionadas con el bienestar laboral.
              La información debe documentarse de
              forma objetiva y no constituye un
              diagnóstico médico o psicológico.
            </p>
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

        {/* FORMULARIO */}
        {formularioAbierto && (
          <div style={styles.card}>
            <div style={styles.cardHeader}>
              <div>
                <h2 style={styles.cardTitle}>
                  {editandoId
                    ? "✏️ Editar acción preventiva"
                    : "🛡️ Nueva acción preventiva"}
                </h2>

                <p style={styles.cardSubtitle}>
                  Documenta la situación observada,
                  la medida implementada y la revisión
                  posterior.
                </p>
              </div>
            </div>

            <form onSubmit={guardarAccion}>

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
                    Origen
                  </label>

                  <select
                    name="origen"
                    value={form.origen}
                    onChange={cambiarCampo}
                    style={styles.input}
                  >
                    <option value="iniciativa_rh">
                      RH / iniciativa preventiva
                    </option>

                    <option value="evaluacion">
                      Evaluación preventiva
                    </option>

                    <option value="observacion">
                      Observación laboral
                    </option>

                    <option value="solicitud_empleado">
                      Solicitud del empleado
                    </option>

                    <option value="solicitud_supervisor">
                      Solicitud del supervisor
                    </option>

                    <option value="seguimiento">
                      Seguimiento preventivo
                    </option>

                    <option value="otro">
                      Otro
                    </option>
                  </select>
                </div>
              </div>

              <div style={styles.field}>
                <label style={styles.label}>
                  💙 Situación, factor o necesidad
                  preventiva *
                </label>

                <textarea
                  name="descripcion"
                  value={form.descripcion}
                  onChange={cambiarCampo}
                  style={styles.textarea}
                  rows={4}
                  placeholder="Ej. Carga de trabajo elevada, dificultad de adaptación, fatiga referida, situación recurrente, necesidad de apoyo..."
                />
              </div>

              <div style={styles.field}>
                <label style={styles.label}>
                  🛡️ Acción o medida preventiva *
                </label>

                <textarea
                  name="accion_realizada"
                  value={
                    form.accion_realizada
                  }
                  onChange={cambiarCampo}
                  style={styles.textarea}
                  rows={4}
                  placeholder="Describe la medida implementada o acordada: revisión de carga, acompañamiento, ajuste temporal, orientación, capacitación..."
                />
              </div>

              <div style={styles.field}>
                <label style={styles.label}>
                  👤 Responsable
                </label>

                <input
                  type="text"
                  name="responsable"
                  value={form.responsable}
                  onChange={cambiarCampo}
                  style={styles.input}
                  placeholder="Ej. RH, supervisor, gerente, responsable de área..."
                />
              </div>

              <div style={styles.gridTwo}>
                <div style={styles.field}>
                  <label style={styles.label}>
                    Resultado actual
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

                    <option value="en_revision">
                      En revisión
                    </option>

                    <option value="sin_cambio">
                      Sin cambio
                    </option>

                    <option value="mejora">
                      Mejora
                    </option>

                    <option value="requiere_atencion">
                      Requiere atención
                    </option>

                    <option value="canalizacion_sugerida">
                      Canalización sugerida
                    </option>

                    <option value="completado">
                      Completado
                    </option>
                  </select>
                </div>

                <div style={styles.field}>
                  <label style={styles.label}>
                    Estado
                  </label>

                  <select
                    name="estado"
                    value={form.estado}
                    onChange={cambiarCampo}
                    style={styles.input}
                  >
                    <option value="abierto">
                      Abierto
                    </option>

                    <option value="en_seguimiento">
                      En seguimiento
                    </option>

                    <option value="cerrado">
                      Cerrar al guardar
                    </option>
                  </select>

                  {form.estado === "cerrado" && (
                    <small
                      style={styles.warningText}
                    >
                      ⚠️ Una vez cerrada ya no podrá
                      editarse.
                    </small>
                  )}
                </div>
              </div>

              <div style={styles.gridTwo}>
                <div style={styles.field}>
                  <label style={styles.label}>
                    📌 Próxima acción / revisión
                  </label>

                  <textarea
                    name="proxima_accion"
                    value={
                      form.proxima_accion
                    }
                    onChange={cambiarCampo}
                    style={styles.textarea}
                    rows={3}
                    placeholder="Ej. Revisar evolución, confirmar ajuste de carga, verificar cumplimiento..."
                  />
                </div>

                <div style={styles.field}>
                  <label style={styles.label}>
                    Fecha de próxima revisión
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
                  📝 Observaciones
                </label>

                <textarea
                  name="observaciones"
                  value={form.observaciones}
                  onChange={cambiarCampo}
                  style={styles.textarea}
                  rows={3}
                  placeholder="Información adicional relevante para el seguimiento preventivo..."
                />
              </div>

              <div style={styles.notice}>
                <strong>
                  ℹ️ Información preventiva
                </strong>

                <p style={styles.infoText}>
                  Evita registrar diagnósticos clínicos.
                  Si se identifican indicadores que
                  requieren valoración especializada,
                  registra la necesidad de atención o
                  canalización y continúa el proceso
                  desde el módulo correspondiente.
                </p>
              </div>

              <div style={styles.formActions}>
                <button
                  type="button"
                  style={styles.cancelButton}
                  onClick={cerrarFormulario}
                >
                  Cancelar
                </button>

                <button
                  type="submit"
                  disabled={guardando}
                  style={{
                    ...styles.primaryButton,
                    opacity:
                      guardando
                        ? 0.65
                        : 1
                  }}
                >
                  {guardando
                    ? "Guardando..."
                    : editandoId
                    ? "Guardar cambios"
                    : form.estado ===
                      "cerrado"
                    ? "Registrar y cerrar"
                    : "Registrar acción"}
                </button>
              </div>
            </form>
          </div>
        )}

        {/* RESUMEN */}
        <div style={styles.summaryGrid}>

          <div style={styles.summaryCard}>
            <div style={styles.summaryIcon}>
              🛡️
            </div>

            <div style={styles.summaryNumber}>
              {acciones.length}
            </div>

            <div style={styles.summaryLabel}>
              Acciones
            </div>

            <small style={styles.summaryDetail}>
              Registros preventivos
            </small>
          </div>

          <div style={styles.summaryCard}>
            <div style={styles.summaryIcon}>
              ⏳
            </div>

            <div style={styles.summaryNumber}>
              {accionesActivas.length}
            </div>

            <div style={styles.summaryLabel}>
              Activas
            </div>

            <small style={styles.summaryDetail}>
              Abiertas o en seguimiento
            </small>
          </div>

          <div style={styles.summaryCard}>
            <div style={styles.summaryIcon}>
              ✅
            </div>

            <div style={styles.summaryNumber}>
              {accionesCerradas.length}
            </div>

            <div style={styles.summaryLabel}>
              Cerradas
            </div>

            <small style={styles.summaryDetail}>
              Acciones concluidas
            </small>
          </div>

          <div style={styles.summaryCard}>
            <div style={styles.summaryIcon}>
              🧠
            </div>

            <div style={styles.summaryNumber}>
              {evaluaciones.length}
            </div>

            <div style={styles.summaryLabel}>
              Evaluaciones
            </div>

            <small style={styles.summaryDetail}>
              Evaluaciones preventivas
            </small>
          </div>

          <div style={styles.summaryCard}>
            <div style={styles.summaryIcon}>
              ⚠️
            </div>

            <div style={styles.summaryNumber}>
              {requierenAtencion}
            </div>

            <div style={styles.summaryLabel}>
              Atención
            </div>

            <small style={styles.summaryDetail}>
              Indicadores a revisar
            </small>
          </div>

          <div style={styles.summaryCard}>
            <div style={styles.summaryIcon}>
              🩺
            </div>

            <div style={styles.summaryNumber}>
              {canalizaciones}
            </div>

            <div style={styles.summaryLabel}>
              Canalización
            </div>

            <small style={styles.summaryDetail}>
              Sugerencias registradas
            </small>
          </div>
        </div>

        {/* ACCIONES PREVENTIVAS */}
        <div style={styles.card}>
          <button
            type="button"
            style={styles.sectionHeader}
            onClick={() =>
              alternarSeccion("acciones")
            }
          >
            <div>
              <h2 style={styles.cardTitle}>
                🛡️ Acciones preventivas
              </h2>

              <p style={styles.cardSubtitle}>
                Medidas implementadas por RH o la
                empresa para reducir riesgos, brindar
                apoyo y revisar la evolución del
                bienestar laboral.
              </p>
            </div>

            <div style={styles.headerRight}>
              <span style={styles.counter}>
                {acciones.length}
              </span>

              <span style={styles.arrow}>
                {seccionesAbiertas.acciones
                  ? "▲"
                  : "▼"}
              </span>
            </div>
          </button>

          {seccionesAbiertas.acciones && (
            <div style={styles.sectionContent}>
              {acciones.length === 0 ? (
                <div style={styles.empty}>
                  <div style={styles.emptyIcon}>
                    🛡️
                  </div>

                  <h3>
                    Sin acciones preventivas
                  </h3>

                  <p>
                    Todavía no se han registrado
                    acciones preventivas para este
                    empleado.
                  </p>

                  <button
                    type="button"
                    style={styles.primaryButton}
                    onClick={abrirFormulario}
                  >
                    ＋ Registrar primera acción
                  </button>
                </div>
              ) : (
                <div style={styles.list}>
                  {acciones.map(
                    renderAccion
                  )}
                </div>
              )}

              {accionesAnuladas.length > 0 && (
                <div style={styles.traceNotice}>
                  ⚪ Los registros anulados se
                  conservan visibles para mantener
                  trazabilidad.
                </div>
              )}
            </div>
          )}
        </div>

        {/* EVALUACIONES */}
        <div style={styles.card}>
          <button
            type="button"
            style={styles.sectionHeader}
            onClick={() =>
              alternarSeccion(
                "evaluaciones"
              )
            }
          >
            <div>
              <h2 style={styles.cardTitle}>
                🧠 Evaluaciones preventivas
              </h2>

              <p style={styles.cardSubtitle}>
                Evaluaciones periódicas y herramientas
                de detección relacionadas con el
                bienestar laboral.
              </p>
            </div>

            <div style={styles.headerRight}>
              <span style={styles.counter}>
                {evaluaciones.length}
              </span>

              <span style={styles.arrow}>
                {seccionesAbiertas
                  .evaluaciones
                  ? "▲"
                  : "▼"}
              </span>
            </div>
          </button>

          {seccionesAbiertas
            .evaluaciones && (
            <div style={styles.sectionContent}>

              {evaluaciones.length ===
              0 ? (
                <div style={styles.empty}>
                  <div
                    style={styles.emptyIcon}
                  >
                    🧠
                  </div>

                  <h3>
                    Sin evaluaciones
                  </h3>

                  <p>
                    Todavía no existen
                    evaluaciones preventivas
                    asociadas a este empleado.
                  </p>
                </div>
              ) : (
                <div style={styles.list}>

                  {evaluaciones.map(
                    evaluacion => {
                      const estado =
                        estadoEvaluacion(
                          evaluacion.estatus
                        );

                      return (
                        <div
                          key={
                            evaluacion.id_habilitacion ||
                            evaluacion.id_resultado ||
                            evaluacion.id
                          }
                          style={
                            styles.evaluationCard
                          }
                        >
                          <div
                            style={
                              styles.evaluationHeader
                            }
                          >
                            <div>
                              <h3
                                style={
                                  styles.recordTitle
                                }
                              >
                                {evaluacion.prueba_nombre ||
                                  evaluacion.nombre_prueba ||
                                  "Evaluación"}
                              </h3>

                              <div
                                style={
                                  styles.recordMeta
                                }
                              >
                                {evaluacion.categoria ||
                                  "Evaluación preventiva"}

                                {evaluacion.fecha_habilitacion && (
                                  <>
                                    {" · "}
                                    {formatearFecha(
                                      evaluacion.fecha_habilitacion
                                    )}
                                  </>
                                )}
                              </div>
                            </div>

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

                          {evaluacion.motivo && (
                            <div
                              style={
                                styles.detailBlock
                              }
                            >
                              <strong>
                                Motivo
                              </strong>

                              <p
                                style={styles.text}
                              >
                                {
                                  evaluacion.motivo
                                }
                              </p>
                            </div>
                          )}

                          {evaluacion.estatus ===
                            "completada" && (
                            <div
                              style={
                                styles.evaluationResult
                              }
                            >
                              <div>
                                <span
                                  style={
                                    styles.smallLabel
                                  }
                                >
                                  Puntaje
                                </span>

                                <strong>
                                  {evaluacion.puntaje_total ??
                                    evaluacion.puntaje ??
                                    "No disponible"}
                                </strong>
                              </div>

                              {evaluacion.interpretacion_laboral && (
                                <div>
                                  <span
                                    style={
                                      styles.smallLabel
                                    }
                                  >
                                    Interpretación
                                    preventiva
                                  </span>

                                  <strong>
                                    {
                                      evaluacion.interpretacion_laboral
                                    }
                                  </strong>
                                </div>
                              )}
                            </div>
                          )}

                          {evaluacion.areas_atencion && (
                            <div
                              style={
                                styles.attentionBox
                              }
                            >
                              <strong>
                                ⚠️ Áreas que
                                requieren revisión
                              </strong>

                              <p
                                style={styles.text}
                              >
                                {
                                  evaluacion.areas_atencion
                                }
                              </p>
                            </div>
                          )}

                          {evaluacion.recomendaciones && (
                            <div
                              style={
                                styles.recommendationBox
                              }
                            >
                              <strong>
                                📌 Recomendaciones
                              </strong>

                              <p
                                style={styles.text}
                              >
                                {
                                  evaluacion.recomendaciones
                                }
                              </p>
                            </div>
                          )}
                        </div>
                      );
                    }
                  )}
                </div>
              )}

              <div style={styles.disclaimer}>
                Las evaluaciones de este módulo
                tienen una finalidad preventiva y
                de detección. No constituyen un
                diagnóstico clínico. Cuando existan
                indicadores que requieran atención,
                debe continuarse con seguimiento o
                canalización profesional.
              </div>
            </div>
          )}
        </div>

        {/* PRÓXIMAS REVISIONES */}
        <div style={styles.card}>
          <button
            type="button"
            style={styles.sectionHeader}
            onClick={() =>
              alternarSeccion(
                "revisiones"
              )
            }
          >
            <div>
              <h2 style={styles.cardTitle}>
                📅 Próximas revisiones
              </h2>

              <p style={styles.cardSubtitle}>
                Acciones y evaluaciones que tienen
                una fecha programada para revisión.
              </p>
            </div>

            <div style={styles.headerRight}>
              <span style={styles.counter}>
                {
                  proximasRevisiones.length
                }
              </span>

              <span style={styles.arrow}>
                {seccionesAbiertas
                  .revisiones
                  ? "▲"
                  : "▼"}
              </span>
            </div>
          </button>

          {seccionesAbiertas
            .revisiones && (
            <div style={styles.sectionContent}>

              {proximasRevisiones.length ===
              0 ? (
                <div style={styles.empty}>
                  <div
                    style={styles.emptyIcon}
                  >
                    📅
                  </div>

                  <h3>
                    Sin revisiones próximas
                  </h3>

                  <p>
                    No existen fechas futuras
                    pendientes de revisión.
                  </p>
                </div>
              ) : (
                <div style={styles.list}>
                  {proximasRevisiones.map(
                    (revision, index) => (
                      <div
                        key={
                          `${revision.origen || "revision"}-${revision.id_registro || revision.id_accion || index}`
                        }
                        style={
                          styles.reviewCard
                        }
                      >
                        <div>
                          <strong>
                            {revision.origen ===
                              "evaluacion"
                              ? "🧠 Revisión de evaluación"
                              : "🛡️ Revisión preventiva"}
                          </strong>

                          <p
                            style={styles.text}
                          >
                            {revision.descripcion ||
                              revision.proxima_accion ||
                              "Revisión programada"}
                          </p>
                        </div>

                        <div
                          style={
                            styles.reviewDate
                          }
                        >
                          {formatearFecha(
                            revision.fecha ||
                              revision.fecha_proxima_revision
                          )}
                        </div>
                      </div>
                    )
                  )}
                </div>
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
    background:
      "linear-gradient(135deg,#f5f8fc 0%,#f8fbff 50%,#eef5fd 100%)",
    padding: "30px 20px",
    boxSizing: "border-box"
  },

  container: {
    maxWidth: "1120px",
    margin: "0 auto"
  },

  backButton: {
    border: "none",
    background: "transparent",
    padding: 0,
    marginBottom: "16px",
    cursor: "pointer",
    color: "#344054",
    fontWeight: "700",
    fontSize: "14px"
  },

  headerRow: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "20px",
    flexWrap: "wrap",
    marginBottom: "22px"
  },

  title: {
    margin: "0 0 7px",
    fontSize: "31px",
    color: "#123f73"
  },

  subtitle: {
    margin: 0,
    color: "#667085",
    maxWidth: "780px",
    lineHeight: 1.6
  },

  newButton: {
    border: "none",
    background: "#2167d5",
    color: "#ffffff",
    borderRadius: "11px",
    padding: "12px 17px",
    cursor: "pointer",
    fontWeight: "800",
    whiteSpace: "nowrap"
  },

  employeeCard: {
    background: "#ffffff",
    border: "1px solid #e4ebf4",
    borderRadius: "18px",
    padding: "20px",
    display: "flex",
    alignItems: "center",
    gap: "17px",
    marginBottom: "18px",
    boxShadow:
      "0 7px 22px rgba(30,64,120,.06)"
  },

  avatar: {
    width: "62px",
    height: "62px",
    minWidth: "62px",
    borderRadius: "50%",
    background: "#e9f2ff",
    color: "#2167d5",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "25px",
    fontWeight: "900"
  },

  employeeName: {
    margin: "0 0 6px",
    color: "#123f73"
  },

  meta: {
    color: "#667085",
    fontSize: "13px",
    marginTop: "4px"
  },

  infoBox: {
    display: "flex",
    alignItems: "flex-start",
    gap: "12px",
    padding: "16px",
    marginBottom: "20px",
    borderRadius: "14px",
    border: "1px solid #bfdbfe",
    background: "#eff6ff",
    color: "#1e3a8a"
  },

  infoIcon: {
    fontSize: "22px"
  },

  infoText: {
    margin: "6px 0 0",
    lineHeight: 1.55
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

  summaryGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(150px,1fr))",
    gap: "12px",
    marginBottom: "22px"
  },

  summaryCard: {
    background: "#ffffff",
    border: "1px solid #e4ebf4",
    borderRadius: "15px",
    padding: "16px",
    textAlign: "center",
    boxShadow:
      "0 5px 16px rgba(30,64,120,.05)"
  },

  summaryIcon: {
    fontSize: "22px",
    marginBottom: "5px"
  },

  summaryNumber: {
    color: "#123f73",
    fontSize: "25px",
    fontWeight: "900"
  },

  summaryLabel: {
    color: "#344054",
    fontSize: "13px",
    fontWeight: "800",
    marginTop: "3px"
  },

  summaryDetail: {
    display: "block",
    marginTop: "5px",
    color: "#667085"
  },

  card: {
    background: "#ffffff",
    border: "1px solid #e4ebf4",
    borderRadius: "18px",
    padding: "22px",
    marginBottom: "20px",
    boxShadow:
      "0 7px 22px rgba(30,64,120,.06)"
  },

  cardHeader: {
    marginBottom: "20px"
  },

  cardTitle: {
    margin: "0 0 5px",
    color: "#123f73",
    fontSize: "21px"
  },

  cardSubtitle: {
    margin: 0,
    color: "#667085",
    lineHeight: 1.5
  },

  sectionHeader: {
    width: "100%",
    border: "none",
    background: "transparent",
    padding: 0,
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "16px",
    textAlign: "left",
    cursor: "pointer"
  },

  headerRight: {
    display: "flex",
    alignItems: "center",
    gap: "10px"
  },

  counter: {
    minWidth: "38px",
    height: "38px",
    borderRadius: "10px",
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    background: "#eef4ff",
    color: "#2167d5",
    fontWeight: "900"
  },

  arrow: {
    color: "#667085",
    fontSize: "12px"
  },

  sectionContent: {
    marginTop: "18px"
  },

  gridTwo: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(270px,1fr))",
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
    fontSize: "15px",
    background: "#ffffff",
    outline: "none"
  },

  textarea: {
    width: "100%",
    boxSizing: "border-box",
    border: "1px solid #d0d5dd",
    borderRadius: "10px",
    padding: "12px",
    resize: "vertical",
    fontSize: "15px",
    fontFamily: "inherit",
    outline: "none",
    lineHeight: 1.5
  },

  warningText: {
    display: "block",
    marginTop: "7px",
    color: "#b54708",
    fontWeight: "700"
  },

  notice: {
    background: "#f8fafc",
    border: "1px solid #d0d5dd",
    borderRadius: "12px",
    padding: "15px",
    marginBottom: "20px",
    color: "#475467"
  },

  formActions: {
    display: "flex",
    justifyContent: "flex-end",
    gap: "10px",
    flexWrap: "wrap"
  },

  primaryButton: {
    border: "none",
    borderRadius: "10px",
    background: "#2167d5",
    color: "#ffffff",
    padding: "11px 16px",
    cursor: "pointer",
    fontWeight: "800"
  },

  cancelButton: {
    border: "1px solid #d0d5dd",
    borderRadius: "10px",
    background: "#ffffff",
    color: "#344054",
    padding: "11px 16px",
    cursor: "pointer",
    fontWeight: "700"
  },

  list: {
    display: "flex",
    flexDirection: "column",
    gap: "12px"
  },

  recordCard: {
    border: "1px solid #e4e7ec",
    borderRadius: "13px",
    overflow: "hidden",
    background: "#ffffff"
  },

  recordHeader: {
    width: "100%",
    border: "none",
    background: "transparent",
    padding: "16px",
    cursor: "pointer",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "15px",
    textAlign: "left"
  },

  recordMain: {
    flex: 1,
    minWidth: 0
  },

  badges: {
    display: "flex",
    flexWrap: "wrap",
    gap: "7px",
    marginBottom: "8px"
  },

  originBadge: {
    padding: "5px 9px",
    borderRadius: "20px",
    background: "#f8fafc",
    border: "1px solid #e4e7ec",
    color: "#475467",
    fontSize: "12px",
    fontWeight: "800"
  },

  statusBadge: {
    padding: "5px 9px",
    borderRadius: "20px",
    fontSize: "12px",
    fontWeight: "800"
  },

  recordTitle: {
    margin: 0,
    color: "#123f73",
    fontSize: "17px"
  },

  recordMeta: {
    color: "#667085",
    fontSize: "12px",
    marginTop: "5px"
  },

  detailLink: {
    color: "#2167d5",
    fontSize: "12px",
    fontWeight: "800",
    whiteSpace: "nowrap"
  },

  recordDetail: {
    padding: "0 17px 17px",
    borderTop: "1px solid #e4e7ec"
  },

  detailBlock: {
    marginTop: "14px"
  },

  text: {
    margin: "6px 0 0",
    color: "#344054",
    lineHeight: 1.55,
    whiteSpace: "pre-wrap"
  },

  resultBox: {
    marginTop: "14px",
    padding: "11px 13px",
    borderRadius: "9px",
    background: "#f8fafc",
    color: "#344054"
  },

  nextBox: {
    marginTop: "14px",
    padding: "13px",
    borderRadius: "10px",
    background: "#eff6ff",
    border: "1px solid #bfdbfe"
  },

  nextDate: {
    color: "#175cd3",
    fontWeight: "800",
    fontSize: "12px",
    marginTop: "8px"
  },

  closedBox: {
    marginTop: "14px",
    padding: "13px",
    background: "#ecfdf3",
    border: "1px solid #abefc6",
    borderRadius: "10px",
    color: "#067647"
  },

  cancelBox: {
    marginTop: "14px",
    padding: "13px",
    background: "#f2f4f7",
    border: "1px solid #d0d5dd",
    borderRadius: "10px",
    color: "#475467"
  },

  auditText: {
    marginTop: "6px",
    fontSize: "13px"
  },

  actions: {
    display: "flex",
    justifyContent: "flex-end",
    gap: "9px",
    flexWrap: "wrap",
    marginTop: "15px"
  },

  editButton: {
    border: "1px solid #d0d5dd",
    borderRadius: "8px",
    background: "#ffffff",
    color: "#344054",
    padding: "9px 12px",
    cursor: "pointer",
    fontWeight: "700"
  },

  closeButton: {
    border: "1px solid #abefc6",
    borderRadius: "8px",
    background: "#ecfdf3",
    color: "#067647",
    padding: "9px 12px",
    cursor: "pointer",
    fontWeight: "800"
  },

  annulButton: {
    border: "1px solid #d0d5dd",
    borderRadius: "8px",
    background: "#f9fafb",
    color: "#475467",
    padding: "9px 12px",
    cursor: "pointer",
    fontWeight: "700"
  },

  evaluationCard: {
    border: "1px solid #e4e7ec",
    borderRadius: "13px",
    padding: "16px"
  },

  evaluationHeader: {
    display: "flex",
    justifyContent: "space-between",
    gap: "14px",
    flexWrap: "wrap",
    alignItems: "flex-start"
  },

  evaluationResult: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(180px,1fr))",
    gap: "12px",
    padding: "13px",
    marginTop: "14px",
    background: "#f0fdf4",
    border: "1px solid #bbf7d0",
    borderRadius: "10px"
  },

  smallLabel: {
    display: "block",
    color: "#667085",
    fontSize: "11px",
    marginBottom: "4px"
  },

  attentionBox: {
    marginTop: "14px",
    padding: "13px",
    background: "#fffaeb",
    border: "1px solid #fedf89",
    borderRadius: "10px"
  },

  recommendationBox: {
    marginTop: "14px",
    padding: "13px",
    background: "#f9f5ff",
    border: "1px solid #d6bbfb",
    borderRadius: "10px"
  },

  disclaimer: {
    marginTop: "16px",
    padding: "13px",
    background: "#f8fafc",
    borderRadius: "10px",
    color: "#667085",
    fontSize: "12px",
    lineHeight: 1.55
  },

  reviewCard: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "15px",
    padding: "14px",
    border: "1px solid #e4e7ec",
    borderRadius: "11px"
  },

  reviewDate: {
    color: "#175cd3",
    fontWeight: "800",
    fontSize: "12px",
    whiteSpace: "nowrap"
  },

  traceNotice: {
    marginTop: "14px",
    padding: "11px",
    background: "#f8fafc",
    border: "1px solid #e4e7ec",
    borderRadius: "9px",
    color: "#667085",
    fontSize: "12px"
  },

  empty: {
    textAlign: "center",
    padding: "30px 18px",
    color: "#667085"
  },

  emptyIcon: {
    fontSize: "37px"
  }
};

export default BienestarEmpleado;