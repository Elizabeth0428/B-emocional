import React, { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";
import { useNavigate, useParams } from "react-router-dom";
import { getToken } from "../services/AuthService";

const API_URL = import.meta.env.VITE_API_URL || `${import.meta.env.VITE_API_URL || window.location.origin}`;

const FORM_INICIAL = {
  fecha: "",
  tipo: "seguimiento",
  prioridad: "media",
  motivo: "",
  participantes: "",
  version_empleado: "",
  version_supervisor: "",
  observacion: "",
  accion_realizada: "",
  acuerdo: "",
  compromiso_empresa: "",
  compromiso_empleado: "",
  resultado: "pendiente",
  estado: "abierto",
  proxima_accion: "",
  fecha_proxima_accion: ""
};

const CATEGORIAS = [
  {
    tipo: "incidencia",
    icono: "🚨",
    titulo: "Incidencias laborales",
    descripcion: "Conflictos, incumplimientos, eventos o situaciones que requieren documentación."
  },
  {
    tipo: "seguimiento",
    icono: "📈",
    titulo: "Seguimientos generales",
    descripcion: "Revisiones y continuidad de situaciones previamente registradas."
  },
  {
    tipo: "desempeno",
    icono: "🎯",
    titulo: "Desempeño",
    descripcion: "Evolución, resultados, objetivos, retroalimentación y áreas de mejora."
  },
  {
    tipo: "adaptacion",
    icono: "🌱",
    titulo: "Adaptación",
    descripcion: "Integración al puesto, equipo, funciones y entorno laboral."
  },
  {
    tipo: "general",
    icono: "📁",
    titulo: "Otros registros",
    descripcion: "Información laboral que no corresponde a otra categoría."
  }
];

const CONFIG_REGISTRO = {
  incidencia: {
    titulo: "Incidencia laboral",
    descripcion: "Documenta hechos, versiones de las partes, acciones y acuerdos relacionados con una situación concreta.",
    motivo: "Motivo / asunto",
    motivoPlaceholder: "Ej. Diferencia entre compañeros, incumplimiento, queja o evento...",
    participantes: "👥 Personas involucradas",
    participantesPlaceholder: "Ej. Empleado, supervisor, compañero, testigo, RH...",
    versionEmpleado: "👤 Versión del empleado",
    versionEmpleadoPlaceholder: "Registra objetivamente lo expresado por el empleado...",
    versionSupervisor: "🏢 Versión del supervisor / responsable / testigo",
    versionSupervisorPlaceholder: "Registra lo informado por la otra parte o responsable...",
    observacion: "📝 Descripción objetiva de la situación *",
    observacionPlaceholder: "Describe hechos, fechas, circunstancias y datos relevantes...",
    accion: "✅ Acción realizada por RH / empresa",
    accionPlaceholder: "Describe qué acción realizó RH o la empresa...",
    acuerdo: "🤝 Acuerdo alcanzado",
    acuerdoPlaceholder: "Describe los acuerdos concretos establecidos...",
    compromisoEmpresa: "🏢 Compromiso de la empresa",
    compromisoEmpleado: "👤 Compromiso del empleado",
    proximaAccion: "📌 Próxima acción",
    proximaPlaceholder: "Ej. Revisar cumplimiento del acuerdo...",
    fechaProxima: "Fecha próxima revisión"
  },

  seguimiento: {
    titulo: "Seguimiento",
    descripcion: "Registra la evolución y continuidad de una situación previamente documentada.",
    motivo: "Asunto del seguimiento",
    motivoPlaceholder: "Ej. Revisión de acuerdo, continuidad de incidencia, avance de compromiso...",
    participantes: "🔗 Situación / personas relacionadas",
    participantesPlaceholder: "Indica el antecedente o las personas relacionadas, si aplica...",
    versionEmpleado: "📈 Avances reportados por el empleado",
    versionEmpleadoPlaceholder: "¿Qué ha cambiado desde la revisión anterior?",
    versionSupervisor: "👀 Cambios observados por supervisor / RH",
    versionSupervisorPlaceholder: "Registra cambios, cumplimiento o hechos observados...",
    observacion: "📝 Estado actual del seguimiento *",
    observacionPlaceholder: "Describe el avance actual y los hechos relevantes desde la última revisión...",
    accion: "✅ Acción realizada en esta revisión",
    accionPlaceholder: "Describe las acciones realizadas durante este seguimiento...",
    acuerdo: "🤝 Acuerdos pendientes o nuevos acuerdos",
    acuerdoPlaceholder: "Registra acuerdos que continúan o que se establecieron ahora...",
    compromisoEmpresa: "🏢 Próximo compromiso de la empresa",
    compromisoEmpleado: "👤 Próximo compromiso del empleado",
    proximaAccion: "📌 Siguiente revisión / acción",
    proximaPlaceholder: "Indica qué se revisará o realizará después...",
    fechaProxima: "Fecha de siguiente revisión"
  },

  desempeno: {
    titulo: "Desempeño",
    descripcion: "Documenta objetivos, fortalezas, áreas de mejora, retroalimentación y compromisos laborales.",
    motivo: "Área / aspecto evaluado",
    motivoPlaceholder: "Ej. Calidad, productividad, puntualidad, cumplimiento de objetivos...",
    participantes: "👤 Responsable de la retroalimentación",
    participantesPlaceholder: "Ej. Supervisor directo, gerente, RH...",
    versionEmpleado: "💪 Fortalezas observadas",
    versionEmpleadoPlaceholder: "Registra fortalezas, logros o conductas positivas observadas...",
    versionSupervisor: "🎯 Áreas de mejora",
    versionSupervisorPlaceholder: "Registra aspectos concretos que requieren mejora...",
    observacion: "📝 Objetivo, expectativa o situación evaluada *",
    observacionPlaceholder: "Describe el objetivo esperado y los hechos o resultados observados...",
    accion: "💬 Retroalimentación brindada",
    accionPlaceholder: "Describe la retroalimentación, orientación o apoyo proporcionado...",
    acuerdo: "🤝 Plan / acuerdo de mejora",
    acuerdoPlaceholder: "Describe acciones y objetivos acordados...",
    compromisoEmpresa: "🏢 Apoyo / compromiso de la empresa",
    compromisoEmpleado: "👤 Compromiso del empleado",
    proximaAccion: "📌 Aspecto a revisar",
    proximaPlaceholder: "Indica qué objetivo o avance se revisará posteriormente...",
    fechaProxima: "Fecha de revisión de desempeño"
  },

  adaptacion: {
    titulo: "Adaptación",
    descripcion: "Registra la integración del empleado al puesto, equipo, funciones y entorno laboral.",
    motivo: "Etapa / área de adaptación",
    motivoPlaceholder: "Ej. Integración al puesto, equipo, funciones, horario, procesos...",
    participantes: "👥 Personas de apoyo relacionadas",
    participantesPlaceholder: "Ej. Supervisor, mentor, compañero, RH...",
    versionEmpleado: "🌱 Percepción del empleado",
    versionEmpleadoPlaceholder: "¿Cómo refiere su adaptación al puesto o entorno?",
    versionSupervisor: "👀 Observación del supervisor / RH",
    versionSupervisorPlaceholder: "Describe lo observado respecto a su integración y desempeño inicial...",
    observacion: "📝 Situación o dificultad de adaptación *",
    observacionPlaceholder: "Describe de forma objetiva qué aspecto de adaptación se está revisando...",
    accion: "🧩 Apoyo brindado",
    accionPlaceholder: "Ej. Capacitación, acompañamiento, ajuste de funciones, orientación...",
    acuerdo: "🤝 Acuerdos de adaptación",
    acuerdoPlaceholder: "Registra los acuerdos establecidos para facilitar la adaptación...",
    compromisoEmpresa: "🏢 Apoyo de la empresa",
    compromisoEmpleado: "👤 Compromiso del empleado",
    proximaAccion: "📌 Evolución a revisar",
    proximaPlaceholder: "Indica qué aspecto de adaptación se revisará después...",
    fechaProxima: "Fecha de próxima revisión"
  },

  general: {
    titulo: "Otro registro laboral",
    descripcion: "Registra información laboral relevante que no corresponde a otra categoría.",
    motivo: "Asunto",
    motivoPlaceholder: "Describe brevemente el asunto del registro...",
    participantes: "👥 Personas relacionadas",
    participantesPlaceholder: "Indica personas relacionadas, si aplica...",
    versionEmpleado: null,
    versionSupervisor: null,
    observacion: "📝 Descripción del registro *",
    observacionPlaceholder: "Describe la información laboral relevante...",
    accion: "✅ Acción realizada",
    accionPlaceholder: "Describe acciones realizadas, si aplica...",
    acuerdo: "🤝 Acuerdo / conclusión",
    acuerdoPlaceholder: "Registra acuerdos o conclusiones, si aplica...",
    compromisoEmpresa: null,
    compromisoEmpleado: null,
    proximaAccion: "📌 Próxima acción",
    proximaPlaceholder: "Indica la siguiente acción, si aplica...",
    fechaProxima: "Fecha próxima acción"
  }
};

const obtenerConfigRegistro = tipo =>
  CONFIG_REGISTRO[tipo] || CONFIG_REGISTRO.general;

const SeguimientoEmpleado = () => {
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
  const [seguimientos, setSeguimientos] = useState([]);
  const [cargando, setCargando] = useState(true);
  const [guardando, setGuardando] = useState(false);
  const [procesandoId, setProcesandoId] = useState(null);
  const [error, setError] = useState("");
  const [mensaje, setMensaje] = useState("");
  const [editandoId, setEditandoId] = useState(null);
  const [formularioAbierto, setFormularioAbierto] = useState(false);
  const [carpetasAbiertas, setCarpetasAbiertas] = useState({});
  const [detallesAbiertos, setDetallesAbiertos] = useState({});
  const [evidenciasAbiertas, setEvidenciasAbiertas] = useState({});
  const [evidenciasPorSeguimiento, setEvidenciasPorSeguimiento] = useState({});
  const [cargandoEvidencias, setCargandoEvidencias] = useState({});
  const [subiendoEvidenciaId, setSubiendoEvidenciaId] = useState(null);
  const [formulariosEvidencia, setFormulariosEvidencia] = useState({});
  const [form, setForm] = useState(FORM_INICIAL);

  const cargarSeguimientos = useCallback(async () => {
    try {
      setCargando(true);
      setError("");

      if (!token) {
        throw new Error("Tu sesión no es válida.");
      }

      const respuesta = await axios.get(
        `${API_URL}/api/empleados/${idEmpleado}/seguimiento`,
        config
      );

      setEmpleado(respuesta.data?.empleado || null);

      setSeguimientos(
        Array.isArray(respuesta.data?.seguimientos)
          ? respuesta.data.seguimientos
          : []
      );
    } catch (err) {
      console.error("❌ Error cargando seguimiento laboral:", err);

      setError(
        err.response?.data?.message ||
          err.message ||
          "No fue posible cargar el seguimiento laboral."
      );
    } finally {
      setCargando(false);
    }
  }, [idEmpleado, config, token]);

  useEffect(() => {
    cargarSeguimientos();
  }, [cargarSeguimientos]);

  /*
   * BIENESTAR Y PREVENCIÓN YA NO PERTENECEN A ESTE MÓDULO.
   *
   * Si existen registros antiguos en la BD con esos tipos,
   * no los borramos, simplemente no se muestran aquí.
   */
  const seguimientosLaborales = useMemo(
    () =>
      seguimientos.filter(
        item =>
          !["bienestar", "prevencion"].includes(item.tipo)
      ),
    [seguimientos]
  );

  const expedientePorCategoria = useMemo(() => {
    const grupos = {};

    CATEGORIAS.forEach(categoria => {
      grupos[categoria.tipo] = [];
    });

    seguimientosLaborales.forEach(item => {
      const tipo = item.tipo || "general";

      if (!grupos[tipo]) {
        grupos.general.push(item);
        return;
      }

      grupos[tipo].push(item);
    });

    return grupos;
  }, [seguimientosLaborales]);

  const totalAbiertos = seguimientosLaborales.filter(
    item =>
      item.estado === "abierto" ||
      item.estado === "en_seguimiento"
  ).length;

  const totalCerrados = seguimientosLaborales.filter(
    item => item.estado === "cerrado"
  ).length;

  const totalAlta = seguimientosLaborales.filter(
    item =>
      item.prioridad === "alta" &&
      item.estado !== "cerrado" &&
      item.estado !== "anulado"
  ).length;

  const alternarCarpeta = tipo => {
    setCarpetasAbiertas(prev => ({
      ...prev,
      [tipo]: !prev[tipo]
    }));
  };

  const alternarDetalle = id => {
    setDetallesAbiertos(prev => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  const formularioEvidenciaInicial = {
    tipo_evidencia: "documento",
    titulo: "",
    descripcion: "",
    fecha_evidencia: "",
    file: null
  };

  const obtenerFormularioEvidencia = idSeguimiento =>
    formulariosEvidencia[idSeguimiento] || {
      ...formularioEvidenciaInicial
    };

  const cargarEvidencias = async idSeguimiento => {
    try {
      setCargandoEvidencias(prev => ({
        ...prev,
        [idSeguimiento]: true
      }));

      const respuesta = await axios.get(
        `${API_URL}/api/empleados/${idEmpleado}/seguimiento/${idSeguimiento}/evidencias`,
        config
      );

      setEvidenciasPorSeguimiento(prev => ({
        ...prev,
        [idSeguimiento]: Array.isArray(respuesta.data?.evidencias)
          ? respuesta.data.evidencias
          : []
      }));
    } catch (err) {
      console.error("❌ Error cargando evidencias:", err);

      setError(
        err.response?.data?.message ||
          "No fue posible cargar las evidencias."
      );
    } finally {
      setCargandoEvidencias(prev => ({
        ...prev,
        [idSeguimiento]: false
      }));
    }
  };

  const alternarEvidencias = async idSeguimiento => {
    const seAbrira = !evidenciasAbiertas[idSeguimiento];

    setEvidenciasAbiertas(prev => ({
      ...prev,
      [idSeguimiento]: seAbrira
    }));

    if (
      seAbrira &&
      evidenciasPorSeguimiento[idSeguimiento] === undefined
    ) {
      await cargarEvidencias(idSeguimiento);
    }
  };

  const cambiarCampoEvidencia = (idSeguimiento, e) => {
    const { name, value } = e.target;

    setFormulariosEvidencia(prev => ({
      ...prev,
      [idSeguimiento]: {
        ...formularioEvidenciaInicial,
        ...prev[idSeguimiento],
        [name]: value
      }
    }));

    setError("");
    setMensaje("");
  };

  const cambiarArchivoEvidencia = (idSeguimiento, e) => {
    const archivo = e.target.files?.[0] || null;

    setFormulariosEvidencia(prev => ({
      ...prev,
      [idSeguimiento]: {
        ...formularioEvidenciaInicial,
        ...prev[idSeguimiento],
        file: archivo
      }
    }));

    setError("");
    setMensaje("");
  };

  const subirEvidencia = async (e, item) => {
    e.preventDefault();

    const idSeguimiento = item.id_seguimiento;

    const evidenciaForm =
      obtenerFormularioEvidencia(idSeguimiento);

    if (!evidenciaForm.file) {
      setError(
        "Selecciona un archivo para agregar como evidencia."
      );
      return;
    }

    try {
      setSubiendoEvidenciaId(idSeguimiento);
      setError("");
      setMensaje("");

      const datos = new FormData();

      datos.append("file", evidenciaForm.file);

      datos.append(
        "tipo_evidencia",
        evidenciaForm.tipo_evidencia || "documento"
      );

      if (String(evidenciaForm.titulo || "").trim()) {
        datos.append(
          "titulo",
          String(evidenciaForm.titulo).trim()
        );
      }

      if (String(evidenciaForm.descripcion || "").trim()) {
        datos.append(
          "descripcion",
          String(evidenciaForm.descripcion).trim()
        );
      }

      if (evidenciaForm.fecha_evidencia) {
        datos.append(
          "fecha_evidencia",
          evidenciaForm.fecha_evidencia
        );
      }

      const respuesta = await axios.post(
        `${API_URL}/api/empleados/${idEmpleado}/seguimiento/${idSeguimiento}/evidencias`,
        datos,
        {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      );

      setMensaje(
        respuesta.data?.message ||
          "Evidencia agregada correctamente."
      );

      setFormulariosEvidencia(prev => ({
        ...prev,
        [idSeguimiento]: {
          ...formularioEvidenciaInicial
        }
      }));

      await cargarEvidencias(idSeguimiento);
    } catch (err) {
      console.error("❌ Error subiendo evidencia:", err);

      setError(
        err.response?.data?.message ||
          "No fue posible guardar la evidencia."
      );
    } finally {
      setSubiendoEvidenciaId(null);
    }
  };

  const anularEvidencia = async (item, evidencia) => {
    const motivo = window.prompt(
      "Indica el motivo de la anulación. La evidencia permanecerá visible en el expediente:"
    );

    if (motivo === null) {
      return;
    }

    const motivoLimpio = String(motivo).trim();

    if (!motivoLimpio) {
      setError(
        "Debes indicar el motivo de la anulación."
      );
      return;
    }

    const confirmar = window.confirm(
      "¿Confirmas la anulación de esta evidencia? El archivo permanecerá registrado en el expediente."
    );

    if (!confirmar) {
      return;
    }

    try {
      setProcesandoId(
        `evidencia-${evidencia.id_evidencia}`
      );

      setError("");
      setMensaje("");

      const respuesta = await axios.delete(
        `${API_URL}/api/empleados/${idEmpleado}/seguimiento/${item.id_seguimiento}/evidencias/${evidencia.id_evidencia}`,
        {
          ...config,
          data: {
            motivo_anulacion: motivoLimpio
          }
        }
      );

      setMensaje(
        respuesta.data?.message ||
          "Evidencia anulada correctamente."
      );

      await cargarEvidencias(item.id_seguimiento);
    } catch (err) {
      console.error("❌ Error anulando evidencia:", err);

      setError(
        err.response?.data?.message ||
          "No fue posible anular la evidencia."
      );
    } finally {
      setProcesandoId(null);
    }
  };

  const obtenerUrlArchivo = ruta => {
    if (!ruta) {
      return "#";
    }

    if (/^https?:\/\//i.test(ruta)) {
      return ruta;
    }

    return `${API_URL}${ruta}`;
  };

  const textoTipoEvidencia = tipo => {
    const tipos = {
      documento: "Documento",
      acta: "Acta",
      correo: "Correo",
      imagen: "Imagen",
      constancia: "Constancia",
      carta: "Carta",
      otro: "Otro"
    };

    return tipos[tipo] || tipo || "Documento";
  };

  const iconoEvidencia = evidencia => {
    const mime = String(
      evidencia?.mime_type || ""
    ).toLowerCase();

    if (mime.startsWith("image/")) {
      return "🖼️";
    }

    if (mime === "application/pdf") {
      return "📕";
    }

    if (mime.includes("word")) {
      return "📘";
    }

    return "📄";
  };

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

  const cerrarFormulario = () => {
    limpiarFormulario();
    setFormularioAbierto(false);
  };

  const abrirNuevoSeguimiento = () => {
    limpiarFormulario();
    setFormularioAbierto(true);
    setError("");
    setMensaje("");

    window.scrollTo({
      top: 0,
      behavior: "smooth"
    });
  };

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

  const guardarSeguimiento = async e => {
    e.preventDefault();

    if (!String(form.observacion || "").trim()) {
      setError(
        `El campo "${obtenerConfigRegistro(form.tipo).observacion.replace(
          /^[^A-Za-zÁÉÍÓÚÜÑáéíóúüñ]*/,
          ""
        )}" es obligatorio.`
      );
      return;
    }

    try {
      setGuardando(true);
      setError("");
      setMensaje("");

      const payload = {
        fecha: form.fecha || null,
        tipo: form.tipo,
        prioridad: form.prioridad,

        motivo:
          String(form.motivo || "").trim() || null,

        participantes:
          String(form.participantes || "").trim() || null,

        version_empleado:
          String(form.version_empleado || "").trim() ||
          null,

        version_supervisor:
          String(form.version_supervisor || "").trim() ||
          null,

        observacion:
          String(form.observacion || "").trim(),

        accion_realizada:
          String(form.accion_realizada || "").trim() ||
          null,

        acuerdo:
          String(form.acuerdo || "").trim() || null,

        compromiso_empresa:
          String(form.compromiso_empresa || "").trim() ||
          null,

        compromiso_empleado:
          String(form.compromiso_empleado || "").trim() ||
          null,

        resultado: form.resultado,
        estado: form.estado,

        proxima_accion:
          String(form.proxima_accion || "").trim() ||
          null,

        fecha_proxima_accion:
          form.fecha_proxima_accion || null
      };

      let respuesta;

      if (editandoId) {
        respuesta = await axios.put(
          `${API_URL}/api/empleados/${idEmpleado}/seguimiento/${editandoId}`,
          payload,
          config
        );
      } else {
        respuesta = await axios.post(
          `${API_URL}/api/empleados/${idEmpleado}/seguimiento`,
          payload,
          config
        );
      }

      setMensaje(
        respuesta.data?.message ||
          (editandoId
            ? "Registro laboral actualizado correctamente."
            : "Registro laboral guardado correctamente.")
      );

      const tipoGuardado = form.tipo;

      limpiarFormulario();
      setFormularioAbierto(false);

      setCarpetasAbiertas(prev => ({
        ...prev,
        [tipoGuardado]: true
      }));

      await cargarSeguimientos();
    } catch (err) {
      console.error(
        "❌ Error guardando seguimiento laboral:",
        err
      );

      setError(
        err.response?.data?.message ||
          "No fue posible guardar el registro laboral."
      );
    } finally {
      setGuardando(false);
    }
  };

  const editarSeguimiento = item => {
    if (
      item.estado === "cerrado" ||
      item.estado === "anulado"
    ) {
      setError(
        "Los seguimientos cerrados o anulados ya no pueden modificarse."
      );
      return;
    }

    setEditandoId(item.id_seguimiento);

    let participantes = item.participantes || "";

    if (Array.isArray(participantes)) {
      participantes = participantes.join(", ");
    }

    setForm({
      fecha: fechaParaInput(item.fecha),
      tipo: item.tipo || "seguimiento",
      prioridad: item.prioridad || "media",
      motivo: item.motivo || "",
      participantes,

      version_empleado:
        item.version_empleado || "",

      version_supervisor:
        item.version_supervisor || "",

      observacion: item.observacion || "",

      accion_realizada:
        item.accion_realizada || "",

      acuerdo: item.acuerdo || "",

      compromiso_empresa:
        item.compromiso_empresa || "",

      compromiso_empleado:
        item.compromiso_empleado || "",

      resultado: item.resultado || "pendiente",
      estado: item.estado || "abierto",

      proxima_accion:
        item.proxima_accion || "",

      fecha_proxima_accion:
        fechaParaInput(item.fecha_proxima_accion)
    });

    setFormularioAbierto(true);
    setMensaje("");
    setError("");

    window.scrollTo({
      top: 0,
      behavior: "smooth"
    });
  };

  const cerrarSeguimiento = async item => {
    const confirmar = window.confirm(
      "¿Deseas cerrar este seguimiento? Una vez cerrado ya no podrá editarse."
    );

    if (!confirmar) {
      return;
    }

    try {
      setProcesandoId(item.id_seguimiento);
      setError("");
      setMensaje("");

      const respuesta = await axios.put(
        `${API_URL}/api/empleados/${idEmpleado}/seguimiento/${item.id_seguimiento}`,
        {
          estado: "cerrado",
          resultado:
            item.resultado === "pendiente"
              ? "resuelto"
              : item.resultado
        },
        config
      );

      setMensaje(
        respuesta.data?.message ||
          "Seguimiento cerrado correctamente."
      );

      if (
        Number(editandoId) ===
        Number(item.id_seguimiento)
      ) {
        cerrarFormulario();
      }

      await cargarSeguimientos();
    } catch (err) {
      console.error(
        "❌ Error cerrando seguimiento:",
        err
      );

      setError(
        err.response?.data?.message ||
          "No fue posible cerrar el seguimiento."
      );
    } finally {
      setProcesandoId(null);
    }
  };

  const anularSeguimiento = async item => {
    const motivo = window.prompt(
      "Indica el motivo de la anulación. El registro permanecerá visible en el expediente:"
    );

    if (motivo === null) {
      return;
    }

    const motivoLimpio = String(motivo).trim();

    if (!motivoLimpio) {
      setError(
        "Debes indicar el motivo de la anulación."
      );
      return;
    }

    const confirmar = window.confirm(
      "¿Confirmas la anulación? El registro no será eliminado y permanecerá en el expediente."
    );

    if (!confirmar) {
      return;
    }

    try {
      setProcesandoId(item.id_seguimiento);
      setError("");
      setMensaje("");

      const respuesta = await axios.delete(
        `${API_URL}/api/empleados/${idEmpleado}/seguimiento/${item.id_seguimiento}`,
        {
          ...config,
          data: {
            motivo_anulacion: motivoLimpio
          }
        }
      );

      setMensaje(
        respuesta.data?.message ||
          "Seguimiento anulado correctamente."
      );

      if (
        Number(editandoId) ===
        Number(item.id_seguimiento)
      ) {
        cerrarFormulario();
      }

      await cargarSeguimientos();
    } catch (err) {
      console.error(
        "❌ Error anulando seguimiento:",
        err
      );

      setError(
        err.response?.data?.message ||
          "No fue posible anular el seguimiento."
      );
    } finally {
      setProcesandoId(null);
    }
  };

  const textoTipo = tipo => {
    const tipos = {
      general: "General",
      desempeno: "Desempeño",
      incidencia: "Incidencia",
      adaptacion: "Adaptación",
      seguimiento: "Seguimiento"
    };

    return tipos[tipo] || tipo || "Seguimiento";
  };

  const textoResultado = resultado => {
    const resultados = {
      pendiente: "Pendiente",
      continua: "Continúa",
      resuelto: "Resuelto",
      requiere_atencion: "Requiere atención",
      canalizacion_sugerida: "Canalización sugerida"
    };

    return (
      resultados[resultado] ||
      resultado ||
      "Pendiente"
    );
  };

  const textoEstado = estado => {
    const estados = {
      abierto: "Abierto",
      en_seguimiento: "En seguimiento",
      cerrado: "Cerrado",
      anulado: "Anulado"
    };

    return estados[estado] || estado || "Abierto";
  };

  const textoPrioridad = prioridad => {
    const prioridades = {
      baja: "Baja",
      media: "Media",
      alta: "Alta"
    };

    return prioridades[prioridad] || "Media";
  };

  const estiloPrioridad = prioridad => {
    if (prioridad === "alta") {
      return styles.priorityHigh;
    }

    if (prioridad === "baja") {
      return styles.priorityLow;
    }

    return styles.priorityMedium;
  };

  const estiloEstado = estado => {
    if (estado === "cerrado") {
      return styles.statusClosed;
    }

    if (estado === "anulado") {
      return styles.statusCancelled;
    }

    if (estado === "en_seguimiento") {
      return styles.statusFollowing;
    }

    return styles.statusOpen;
  };

  if (cargando) {
    return (
      <div style={styles.page}>
        <div style={styles.container}>
          <div style={styles.card}>
            <h2>📁 Expediente laboral</h2>
            <p>Cargando expediente...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div style={styles.page}>
      <div style={styles.container}>

        {/* VOLVER */}
        <button
          type="button"
          style={styles.backButton}
          onClick={() =>
            navigate(`/empleado/${idEmpleado}`)
          }
        >
          ← Volver al expediente laboral
        </button>

        {/* ENCABEZADO */}
        <div style={styles.headerRow}>
          <div>
            <h1 style={styles.title}>
              📁 Expediente laboral
            </h1>

            <p style={styles.subtitle}>
              Historial organizado de incidencias,
              seguimientos, desempeño, adaptación y
              otros registros laborales.
            </p>
          </div>

          <button
            type="button"
            style={styles.newButton}
            onClick={
              formularioAbierto
                ? cerrarFormulario
                : abrirNuevoSeguimiento
            }
          >
            {formularioAbierto
              ? "✕ Cerrar formulario"
              : "＋ Nuevo registro"}
          </button>
        </div>

        {/* EMPLEADO */}
        {empleado && (
          <div style={styles.employeeCard}>
            <div style={styles.avatar}>
              {empleado.nombre
                ?.charAt(0)
                ?.toUpperCase() || "E"}
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
                  👤 Responsable RH actual:{" "}
                  <strong>
                    {empleado.responsable_actual}
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
              {seguimientosLaborales.length}
            </div>
            <div style={styles.summaryLabel}>
              Registros
            </div>
          </div>

          <div style={styles.summaryCard}>
            <div style={styles.summaryNumber}>
              {totalAbiertos}
            </div>
            <div style={styles.summaryLabel}>
              Abiertos
            </div>
          </div>

          <div style={styles.summaryCard}>
            <div style={styles.summaryNumber}>
              {totalCerrados}
            </div>
            <div style={styles.summaryLabel}>
              Cerrados
            </div>
          </div>

          <div style={styles.summaryCard}>
            <div style={styles.summaryNumber}>
              {totalAlta}
            </div>
            <div style={styles.summaryLabel}>
              Prioridad alta
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

        {/* FORMULARIO */}
        {formularioAbierto && (
          <div style={styles.card}>

            <div style={styles.cardHeader}>
              <div>
                <h2 style={styles.cardTitle}>
                  {editandoId
                    ? "✏️ Editar registro abierto"
                    : `➕ Registrar ${obtenerConfigRegistro(form.tipo).titulo}`}
                </h2>

                <p style={styles.cardSubtitle}>
                  Registra hechos, versiones, acciones
                  y acuerdos de manera objetiva.
                </p>
              </div>
            </div>

            <div style={styles.protectionNotice}>
              <strong>
                🛡️ Registro objetivo y preventivo
              </strong>

              <p style={styles.noticeText}>
                Documenta hechos comprobables,
                escucha a las partes y registra también
                las acciones realizadas por la empresa.
              </p>
            </div>

            <form onSubmit={guardarSeguimiento}>

              {(() => {
                const cfg =
                  obtenerConfigRegistro(form.tipo);

                return (
                  <>
                    <div style={styles.formTypeIntro}>
                      <strong>
                        {cfg.titulo}
                      </strong>

                      <span>
                        {cfg.descripcion}
                      </span>
                    </div>

                    <div style={styles.gridThree}>
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
                          Tipo de registro
                        </label>

                        <select
                          name="tipo"
                          value={form.tipo}
                          onChange={cambiarCampo}
                          style={styles.input}
                        >
                          <option value="incidencia">
                            🚨 Incidencia
                          </option>

                          <option value="seguimiento">
                            📈 Seguimiento
                          </option>

                          <option value="desempeno">
                            🎯 Desempeño
                          </option>

                          <option value="adaptacion">
                            🌱 Adaptación
                          </option>

                          <option value="general">
                            📁 Otro registro
                          </option>
                        </select>
                      </div>

                      <div style={styles.field}>
                        <label style={styles.label}>
                          Prioridad
                        </label>

                        <select
                          name="prioridad"
                          value={form.prioridad}
                          onChange={cambiarCampo}
                          style={styles.input}
                        >
                          <option value="baja">
                            🟢 Baja
                          </option>

                          <option value="media">
                            🟡 Media
                          </option>

                          <option value="alta">
                            🔴 Alta
                          </option>
                        </select>
                      </div>
                    </div>

                    <div style={styles.field}>
                      <label style={styles.label}>
                        {cfg.motivo}
                      </label>

                      <input
                        type="text"
                        name="motivo"
                        value={form.motivo}
                        onChange={cambiarCampo}
                        style={styles.input}
                        placeholder={
                          cfg.motivoPlaceholder
                        }
                      />
                    </div>

                    {cfg.participantes && (
                      <div style={styles.field}>
                        <label style={styles.label}>
                          {cfg.participantes}
                        </label>

                        <input
                          type="text"
                          name="participantes"
                          value={form.participantes}
                          onChange={cambiarCampo}
                          style={styles.input}
                          placeholder={
                            cfg.participantesPlaceholder
                          }
                        />
                      </div>
                    )}

                    {(cfg.versionEmpleado ||
                      cfg.versionSupervisor) && (
                      <div style={styles.gridTwo}>

                        {cfg.versionEmpleado && (
                          <div style={styles.field}>
                            <label style={styles.label}>
                              {cfg.versionEmpleado}
                            </label>

                            <textarea
                              name="version_empleado"
                              value={
                                form.version_empleado
                              }
                              onChange={cambiarCampo}
                              style={styles.textarea}
                              rows={4}
                              placeholder={
                                cfg.versionEmpleadoPlaceholder
                              }
                            />
                          </div>
                        )}

                        {cfg.versionSupervisor && (
                          <div style={styles.field}>
                            <label style={styles.label}>
                              {cfg.versionSupervisor}
                            </label>

                            <textarea
                              name="version_supervisor"
                              value={
                                form.version_supervisor
                              }
                              onChange={cambiarCampo}
                              style={styles.textarea}
                              rows={4}
                              placeholder={
                                cfg.versionSupervisorPlaceholder
                              }
                            />
                          </div>
                        )}
                      </div>
                    )}

                    <div style={styles.field}>
                      <label style={styles.label}>
                        {cfg.observacion}
                      </label>

                      <textarea
                        name="observacion"
                        value={form.observacion}
                        onChange={cambiarCampo}
                        style={styles.textarea}
                        rows={5}
                        placeholder={
                          cfg.observacionPlaceholder
                        }
                      />
                    </div>

                    {cfg.accion && (
                      <div style={styles.field}>
                        <label style={styles.label}>
                          {cfg.accion}
                        </label>

                        <textarea
                          name="accion_realizada"
                          value={
                            form.accion_realizada
                          }
                          onChange={cambiarCampo}
                          style={styles.textarea}
                          rows={3}
                          placeholder={
                            cfg.accionPlaceholder
                          }
                        />
                      </div>
                    )}

                    {cfg.acuerdo && (
                      <div style={styles.field}>
                        <label style={styles.label}>
                          {cfg.acuerdo}
                        </label>

                        <textarea
                          name="acuerdo"
                          value={form.acuerdo}
                          onChange={cambiarCampo}
                          style={styles.textarea}
                          rows={3}
                          placeholder={
                            cfg.acuerdoPlaceholder
                          }
                        />
                      </div>
                    )}

                    {(cfg.compromisoEmpresa ||
                      cfg.compromisoEmpleado) && (
                      <div style={styles.gridTwo}>

                        {cfg.compromisoEmpresa && (
                          <div style={styles.field}>
                            <label style={styles.label}>
                              {cfg.compromisoEmpresa}
                            </label>

                            <textarea
                              name="compromiso_empresa"
                              value={
                                form.compromiso_empresa
                              }
                              onChange={cambiarCampo}
                              style={styles.textarea}
                              rows={3}
                              placeholder="Registra la medida, apoyo o compromiso correspondiente..."
                            />
                          </div>
                        )}

                        {cfg.compromisoEmpleado && (
                          <div style={styles.field}>
                            <label style={styles.label}>
                              {cfg.compromisoEmpleado}
                            </label>

                            <textarea
                              name="compromiso_empleado"
                              value={
                                form.compromiso_empleado
                              }
                              onChange={cambiarCampo}
                              style={styles.textarea}
                              rows={3}
                              placeholder="Registra el compromiso asumido por el empleado..."
                            />
                          </div>
                        )}
                      </div>
                    )}

                    <div style={styles.gridTwo}>
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
                            Continúa seguimiento
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
                            ⚠️ Una vez cerrado no podrá
                            editarse.
                          </small>
                        )}
                      </div>
                    </div>

                    <div style={styles.gridTwo}>
                      <div style={styles.field}>
                        <label style={styles.label}>
                          {cfg.proximaAccion}
                        </label>

                        <textarea
                          name="proxima_accion"
                          value={form.proxima_accion}
                          onChange={cambiarCampo}
                          style={styles.textarea}
                          rows={3}
                          placeholder={
                            cfg.proximaPlaceholder
                          }
                        />
                      </div>

                      <div style={styles.field}>
                        <label style={styles.label}>
                          {cfg.fechaProxima}
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
                  </>
                );
              })()}

              <div style={styles.notice}>
                <strong>
                  ℹ️ Expediente laboral, no expediente
                  clínico
                </strong>

                <p style={styles.noticeText}>
                  Registra únicamente información
                  laboral objetiva. Los temas de
                  bienestar y prevención se gestionan
                  en su módulo correspondiente.
                </p>
              </div>

              <div style={styles.actions}>
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
                    opacity: guardando ? 0.65 : 1
                  }}
                >
                  {guardando
                    ? "Guardando..."
                    : editandoId
                    ? "Guardar cambios"
                    : form.estado === "cerrado"
                    ? "Registrar y cerrar"
                    : "Registrar seguimiento"}
                </button>
              </div>
            </form>
          </div>
        )}

        {/* EXPEDIENTE POR CARPETAS */}
        <div style={styles.card}>

          <div style={styles.cardHeader}>
            <div>
              <h2 style={styles.cardTitle}>
                📁 Registros del expediente laboral
              </h2>

              <p style={styles.cardSubtitle}>
                Los registros están organizados por
                tipo. Abre únicamente la carpeta que
                necesites consultar.
              </p>
            </div>

            <div style={styles.counter}>
              {seguimientosLaborales.length}
            </div>
          </div>

          {seguimientosLaborales.length === 0 ? (
            <div style={styles.empty}>
              <div style={styles.emptyIcon}>
                🗂️
              </div>

              <h3>Expediente vacío</h3>

              <p>
                Todavía no existen registros de
                seguimiento laboral.
              </p>
            </div>
          ) : (
            <div style={styles.folders}>

              {CATEGORIAS.map(categoria => {
                const registros =
                  expedientePorCategoria[
                    categoria.tipo
                  ] || [];

                const abierta = Boolean(
                  carpetasAbiertas[categoria.tipo]
                );

                const activos = registros.filter(
                  item =>
                    item.estado === "abierto" ||
                    item.estado === "en_seguimiento"
                ).length;

                const cerrados = registros.filter(
                  item => item.estado === "cerrado"
                ).length;

                const anulados = registros.filter(
                  item => item.estado === "anulado"
                ).length;

                return (
                  <div
                    key={categoria.tipo}
                    style={styles.folder}
                  >

                    {/* CABECERA CARPETA */}
                    <button
                      type="button"
                      onClick={() =>
                        alternarCarpeta(
                          categoria.tipo
                        )
                      }
                      style={styles.folderHeader}
                    >
                      <div style={styles.folderLeft}>
                        <div style={styles.folderIcon}>
                          {categoria.icono}
                        </div>

                        <div style={styles.folderText}>
                          <div
                            style={styles.folderTitle}
                          >
                            {categoria.titulo}
                          </div>

                          <div
                            style={
                              styles.folderDescription
                            }
                          >
                            {categoria.descripcion}
                          </div>

                          {registros.length > 0 && (
                            <div
                              style={
                                styles.folderStats
                              }
                            >
                              {activos > 0 && (
                                <span>
                                  🟡 {activos} activos
                                </span>
                              )}

                              {cerrados > 0 && (
                                <span>
                                  ✅ {cerrados} cerrados
                                </span>
                              )}

                              {anulados > 0 && (
                                <span>
                                  ⚪ {anulados} anulados
                                </span>
                              )}
                            </div>
                          )}
                        </div>
                      </div>

                      <div style={styles.folderRight}>
                        <span
                          style={styles.folderCounter}
                        >
                          {registros.length}
                        </span>

                        <span style={styles.arrow}>
                          {abierta ? "▲" : "▼"}
                        </span>
                      </div>
                    </button>

                    {/* CONTENIDO CARPETA */}
                    {abierta && (
                      <div
                        style={styles.folderContent}
                      >
                        {registros.length === 0 ? (
                          <div
                            style={styles.folderEmpty}
                          >
                            No hay registros en este
                            expediente.
                          </div>
                        ) : (
                          registros.map(item => {
                            const detalleAbierto =
                              Boolean(
                                detallesAbiertos[
                                  item.id_seguimiento
                                ]
                              );

                            const bloqueado =
                              item.estado ===
                                "cerrado" ||
                              item.estado ===
                                "anulado";

                            return (
                              <div
                                key={
                                  item.id_seguimiento
                                }
                                style={{
                                  ...styles.recordCard,
                                  ...(item.estado ===
                                  "anulado"
                                    ? styles.recordCancelled
                                    : {})
                                }}
                              >

                                {/* RESUMEN */}
                                <button
                                  type="button"
                                  onClick={() =>
                                    alternarDetalle(
                                      item.id_seguimiento
                                    )
                                  }
                                  style={
                                    styles.recordHeader
                                  }
                                >
                                  <div
                                    style={
                                      styles.recordMain
                                    }
                                  >
                                    <div
                                      style={styles.badges}
                                    >
                                      <span
                                        style={{
                                          ...styles.priorityBadge,
                                          ...estiloPrioridad(
                                            item.prioridad
                                          )
                                        }}
                                      >
                                        {textoPrioridad(
                                          item.prioridad
                                        )}
                                      </span>

                                      <span
                                        style={
                                          styles.resultBadge
                                        }
                                      >
                                        {textoResultado(
                                          item.resultado
                                        )}
                                      </span>

                                      <span
                                        style={{
                                          ...styles.statusBadge,
                                          ...estiloEstado(
                                            item.estado
                                          )
                                        }}
                                      >
                                        {textoEstado(
                                          item.estado
                                        )}
                                      </span>
                                    </div>

                                    <div
                                      style={
                                        styles.recordTitle
                                      }
                                    >
                                      {item.motivo ||
                                        textoTipo(
                                          item.tipo
                                        )}
                                    </div>

                                    <div
                                      style={
                                        styles.recordPreview
                                      }
                                    >
                                      {item.observacion
                                        ? item.observacion
                                            .length > 120
                                          ? `${item.observacion.slice(
                                              0,
                                              120
                                            )}...`
                                          : item.observacion
                                        : "Sin descripción"}
                                    </div>
                                  </div>

                                  <div
                                    style={
                                      styles.recordSide
                                    }
                                  >
                                    <div
                                      style={
                                        styles.dateText
                                      }
                                    >
                                      {formatearFecha(
                                        item.fecha
                                      )}
                                    </div>

                                    <div
                                      style={
                                        styles.viewDetail
                                      }
                                    >
                                      {detalleAbierto
                                        ? "Cerrar detalle ▲"
                                        : "Ver detalle ▼"}
                                    </div>
                                  </div>
                                </button>

                                {/* DETALLE */}
                                {detalleAbierto &&
                                  (() => {
                                    const cfgDetalle =
                                      obtenerConfigRegistro(
                                        item.tipo
                                      );

                                    return (
                                      <div
                                        style={
                                          styles.recordDetail
                                        }
                                      >

                                        {item.participantes && (
                                          <div
                                            style={
                                              styles.infoStrip
                                            }
                                          >
                                            <strong>
                                              {cfgDetalle.participantes ||
                                                "👥 Personas relacionadas"}
                                              :
                                            </strong>{" "}
                                            {Array.isArray(
                                              item.participantes
                                            )
                                              ? item.participantes.join(
                                                  ", "
                                                )
                                              : item.participantes}
                                          </div>
                                        )}

                                        {(item.version_empleado ||
                                          item.version_supervisor) && (
                                          <div
                                            style={
                                              styles.versionGrid
                                            }
                                          >

                                            {item.version_empleado && (
                                              <div
                                                style={
                                                  styles.versionBox
                                                }
                                              >
                                                <strong>
                                                  {cfgDetalle.versionEmpleado ||
                                                    "👤 Información del empleado"}
                                                </strong>

                                                <p
                                                  style={
                                                    styles.text
                                                  }
                                                >
                                                  {
                                                    item.version_empleado
                                                  }
                                                </p>
                                              </div>
                                            )}

                                            {item.version_supervisor && (
                                              <div
                                                style={
                                                  styles.versionBox
                                                }
                                              >
                                                <strong>
                                                  {cfgDetalle.versionSupervisor ||
                                                    "🏢 Información del responsable"}
                                                </strong>

                                                <p
                                                  style={
                                                    styles.text
                                                  }
                                                >
                                                  {
                                                    item.version_supervisor
                                                  }
                                                </p>
                                              </div>
                                            )}
                                          </div>
                                        )}

                                        <div
                                          style={
                                            styles.section
                                          }
                                        >
                                          <strong>
                                            {
                                              cfgDetalle.observacion
                                            }
                                          </strong>

                                          <p
                                            style={
                                              styles.text
                                            }
                                          >
                                            {
                                              item.observacion
                                            }
                                          </p>
                                        </div>

                                        {item.accion_realizada && (
                                          <div
                                            style={
                                              styles.section
                                            }
                                          >
                                            <strong>
                                              {cfgDetalle.accion ||
                                                "✅ Acción realizada"}
                                            </strong>

                                            <p
                                              style={
                                                styles.text
                                              }
                                            >
                                              {
                                                item.accion_realizada
                                              }
                                            </p>
                                          </div>
                                        )}

                                        {item.acuerdo && (
                                          <div
                                            style={
                                              styles.agreementBox
                                            }
                                          >
                                            <strong>
                                              {cfgDetalle.acuerdo ||
                                                "🤝 Acuerdo / conclusión"}
                                            </strong>

                                            <p
                                              style={
                                                styles.text
                                              }
                                            >
                                              {
                                                item.acuerdo
                                              }
                                            </p>
                                          </div>
                                        )}

                                        {(item.compromiso_empresa ||
                                          item.compromiso_empleado) && (
                                          <div
                                            style={
                                              styles.commitmentGrid
                                            }
                                          >

                                            {item.compromiso_empresa && (
                                              <div
                                                style={
                                                  styles.companyCommitment
                                                }
                                              >
                                                <strong>
                                                  {cfgDetalle.compromisoEmpresa ||
                                                    "🏢 Compromiso / medida de la empresa"}
                                                </strong>

                                                <p
                                                  style={
                                                    styles.text
                                                  }
                                                >
                                                  {
                                                    item.compromiso_empresa
                                                  }
                                                </p>
                                              </div>
                                            )}

                                            {item.compromiso_empleado && (
                                              <div
                                                style={
                                                  styles.employeeCommitment
                                                }
                                              >
                                                <strong>
                                                  {cfgDetalle.compromisoEmpleado ||
                                                    "👤 Compromiso del empleado"}
                                                </strong>

                                                <p
                                                  style={
                                                    styles.text
                                                  }
                                                >
                                                  {
                                                    item.compromiso_empleado
                                                  }
                                                </p>
                                              </div>
                                            )}
                                          </div>
                                        )}

                                        {(item.proxima_accion ||
                                          item.fecha_proxima_accion) &&
                                          item.estado !==
                                            "anulado" && (
                                            <div
                                              style={
                                                styles.nextAction
                                              }
                                            >
                                              <strong>
                                                {
                                                  cfgDetalle.proximaAccion
                                                }
                                              </strong>

                                              {item.proxima_accion && (
                                                <p
                                                  style={
                                                    styles.text
                                                  }
                                                >
                                                  {
                                                    item.proxima_accion
                                                  }
                                                </p>
                                              )}

                                              {item.fecha_proxima_accion && (
                                                <small
                                                  style={
                                                    styles.meta
                                                  }
                                                >
                                                  Fecha
                                                  prevista:{" "}
                                                  {formatearFecha(
                                                    item.fecha_proxima_accion
                                                  )}
                                                </small>
                                              )}
                                            </div>
                                          )}

                                        {item.estado ===
                                          "cerrado" && (
                                          <div
                                            style={
                                              styles.closedBox
                                            }
                                          >
                                            <strong>
                                              🔒 Seguimiento
                                              cerrado
                                            </strong>

                                            <div
                                              style={
                                                styles.auditText
                                              }
                                            >
                                              Fecha:{" "}
                                              {formatearFecha(
                                                item.fecha_cierre
                                              )}
                                            </div>

                                            {item.usuario_cierre && (
                                              <div
                                                style={
                                                  styles.auditText
                                                }
                                              >
                                                Cerrado por:{" "}
                                                <strong>
                                                  {
                                                    item.usuario_cierre
                                                  }
                                                </strong>
                                              </div>
                                            )}

                                            <div
                                              style={
                                                styles.auditText
                                              }
                                            >
                                              El contenido
                                              original ya no
                                              puede
                                              modificarse.
                                            </div>
                                          </div>
                                        )}

                                        {item.estado ===
                                          "anulado" && (
                                          <div
                                            style={
                                              styles.cancelledBox
                                            }
                                          >
                                            <strong>
                                              ⚪ Registro
                                              anulado
                                            </strong>

                                            {item.motivo_anulacion && (
                                              <p
                                                style={
                                                  styles.text
                                                }
                                              >
                                                <strong>
                                                  Motivo:
                                                </strong>{" "}
                                                {
                                                  item.motivo_anulacion
                                                }
                                              </p>
                                            )}

                                            <div
                                              style={
                                                styles.auditText
                                              }
                                            >
                                              Fecha:{" "}
                                              {formatearFecha(
                                                item.fecha_anulacion
                                              )}
                                            </div>

                                            {item.usuario_anulacion && (
                                              <div
                                                style={
                                                  styles.auditText
                                                }
                                              >
                                                Anulado por:{" "}
                                                <strong>
                                                  {
                                                    item.usuario_anulacion
                                                  }
                                                </strong>
                                              </div>
                                            )}
                                          </div>
                                        )}

                                        {/* EVIDENCIAS */}
                                        <div
                                          style={
                                            styles.evidenceSection
                                          }
                                        >
                                          <button
                                            type="button"
                                            style={
                                              styles.evidenceHeader
                                            }
                                            onClick={() =>
                                              alternarEvidencias(
                                                item.id_seguimiento
                                              )
                                            }
                                          >
                                            <span
                                              style={
                                                styles.evidenceHeaderTitle
                                              }
                                            >
                                              📎 Evidencias
                                            </span>

                                            <span
                                              style={
                                                styles.evidenceHeaderRight
                                              }
                                            >
                                              <span
                                                style={
                                                  styles.evidenceCounter
                                                }
                                              >
                                                {evidenciasPorSeguimiento[
                                                  item
                                                    .id_seguimiento
                                                ]?.length ??
                                                  "—"}
                                              </span>

                                              <span>
                                                {evidenciasAbiertas[
                                                  item
                                                    .id_seguimiento
                                                ]
                                                  ? "▲"
                                                  : "▼"}
                                              </span>
                                            </span>
                                          </button>

                                          {evidenciasAbiertas[
                                            item
                                              .id_seguimiento
                                          ] && (
                                            <div
                                              style={
                                                styles.evidenceContent
                                              }
                                            >
                                              {cargandoEvidencias[
                                                item
                                                  .id_seguimiento
                                              ] ? (
                                                <div
                                                  style={
                                                    styles.evidenceLoading
                                                  }
                                                >
                                                  Cargando
                                                  evidencias...
                                                </div>
                                              ) : (
                                                <>
                                                  {(evidenciasPorSeguimiento[
                                                    item
                                                      .id_seguimiento
                                                  ] || [])
                                                    .length ===
                                                  0 ? (
                                                    <div
                                                      style={
                                                        styles.evidenceEmpty
                                                      }
                                                    >
                                                      📂 No
                                                      hay
                                                      evidencias
                                                      registradas
                                                      para
                                                      este
                                                      seguimiento.
                                                    </div>
                                                  ) : (
                                                    <div
                                                      style={
                                                        styles.evidenceList
                                                      }
                                                    >
                                                      {(evidenciasPorSeguimiento[
                                                        item
                                                          .id_seguimiento
                                                      ] ||
                                                        []).map(
                                                        evidencia => {
                                                          const evidenciaAnulada =
                                                            evidencia.estado ===
                                                            "anulado";

                                                          return (
                                                            <div
                                                              key={
                                                                evidencia.id_evidencia
                                                              }
                                                              style={{
                                                                ...styles.evidenceCard,
                                                                ...(evidenciaAnulada
                                                                  ? styles.evidenceCardCancelled
                                                                  : {})
                                                              }}
                                                            >
                                                              <div
                                                                style={
                                                                  styles.evidenceTop
                                                                }
                                                              >
                                                                <div
                                                                  style={
                                                                    styles.evidenceIcon
                                                                  }
                                                                >
                                                                  {iconoEvidencia(
                                                                    evidencia
                                                                  )}
                                                                </div>

                                                                <div
                                                                  style={
                                                                    styles.evidenceInfo
                                                                  }
                                                                >
                                                                  <div
                                                                    style={
                                                                      styles.evidenceTitle
                                                                    }
                                                                  >
                                                                    {evidencia.titulo ||
                                                                      evidencia.nombre_original ||
                                                                      "Evidencia"}
                                                                  </div>

                                                                  <div
                                                                    style={
                                                                      styles.evidenceMeta
                                                                    }
                                                                  >
                                                                    {textoTipoEvidencia(
                                                                      evidencia.tipo_evidencia
                                                                    )}{" "}
                                                                    ·{" "}
                                                                    {
                                                                      evidencia.nombre_original
                                                                    }
                                                                  </div>

                                                                  {evidencia.descripcion && (
                                                                    <div
                                                                      style={
                                                                        styles.evidenceDescription
                                                                      }
                                                                    >
                                                                      {
                                                                        evidencia.descripcion
                                                                      }
                                                                    </div>
                                                                  )}

                                                                  <div
                                                                    style={
                                                                      styles.evidenceMeta
                                                                    }
                                                                  >
                                                                    Agregada:{" "}
                                                                    {formatearFecha(
                                                                      evidencia.fecha_subida
                                                                    )}

                                                                    {evidencia.usuario_registro && (
                                                                      <>
                                                                        {" "}
                                                                        ·
                                                                        Por:{" "}
                                                                        <strong>
                                                                          {
                                                                            evidencia.usuario_registro
                                                                          }
                                                                        </strong>
                                                                      </>
                                                                    )}
                                                                  </div>

                                                                  {evidencia.fecha_evidencia && (
                                                                    <div
                                                                      style={
                                                                        styles.evidenceMeta
                                                                      }
                                                                    >
                                                                      Fecha
                                                                      de la
                                                                      evidencia:{" "}
                                                                      {formatearFecha(
                                                                        evidencia.fecha_evidencia
                                                                      )}
                                                                    </div>
                                                                  )}
                                                                </div>

                                                                <div
                                                                  style={
                                                                    styles.evidenceActions
                                                                  }
                                                                >
                                                                  <a
                                                                    href={obtenerUrlArchivo(
                                                                      evidencia.ruta_archivo
                                                                    )}
                                                                    target="_blank"
                                                                    rel="noreferrer"
                                                                    style={
                                                                      styles.viewFileButton
                                                                    }
                                                                  >
                                                                    👁️ Ver
                                                                  </a>

                                                                  {!evidenciaAnulada && (
                                                                    <button
                                                                      type="button"
                                                                      style={
                                                                        styles.annulEvidenceButton
                                                                      }
                                                                      disabled={
                                                                        procesandoId ===
                                                                        `evidencia-${evidencia.id_evidencia}`
                                                                      }
                                                                      onClick={() =>
                                                                        anularEvidencia(
                                                                          item,
                                                                          evidencia
                                                                        )
                                                                      }
                                                                    >
                                                                      ⚪
                                                                      Anular
                                                                    </button>
                                                                  )}
                                                                </div>
                                                              </div>

                                                              {evidenciaAnulada && (
                                                                <div
                                                                  style={
                                                                    styles.evidenceCancelledNotice
                                                                  }
                                                                >
                                                                  <strong>
                                                                    ⚪
                                                                    Evidencia
                                                                    anulada
                                                                  </strong>

                                                                  {evidencia.motivo_anulacion && (
                                                                    <div
                                                                      style={
                                                                        styles.evidenceMeta
                                                                      }
                                                                    >
                                                                      Motivo:{" "}
                                                                      {
                                                                        evidencia.motivo_anulacion
                                                                      }
                                                                    </div>
                                                                  )}

                                                                  <div
                                                                    style={
                                                                      styles.evidenceMeta
                                                                    }
                                                                  >
                                                                    Fecha:{" "}
                                                                    {formatearFecha(
                                                                      evidencia.fecha_anulacion
                                                                    )}
                                                                  </div>

                                                                  {evidencia.usuario_anulacion && (
                                                                    <div
                                                                      style={
                                                                        styles.evidenceMeta
                                                                      }
                                                                    >
                                                                      Anulada
                                                                      por:{" "}
                                                                      <strong>
                                                                        {
                                                                          evidencia.usuario_anulacion
                                                                        }
                                                                      </strong>
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

                                                  {item.estado !==
                                                    "anulado" && (
                                                    <form
                                                      onSubmit={e =>
                                                        subirEvidencia(
                                                          e,
                                                          item
                                                        )
                                                      }
                                                      style={
                                                        styles.evidenceForm
                                                      }
                                                    >
                                                      <div
                                                        style={
                                                          styles.evidenceFormHeader
                                                        }
                                                      >
                                                        <strong>
                                                          ＋
                                                          Agregar
                                                          evidencia
                                                        </strong>

                                                        <span
                                                          style={
                                                            styles.evidenceHint
                                                          }
                                                        >
                                                          PDF,
                                                          JPG,
                                                          PNG,
                                                          WEBP,
                                                          DOC o
                                                          DOCX ·
                                                          Máx.
                                                          10 MB
                                                        </span>
                                                      </div>

                                                      <div
                                                        style={
                                                          styles.gridTwo
                                                        }
                                                      >
                                                        <div
                                                          style={
                                                            styles.field
                                                          }
                                                        >
                                                          <label
                                                            style={
                                                              styles.label
                                                            }
                                                          >
                                                            Tipo
                                                            de
                                                            evidencia
                                                          </label>

                                                          <select
                                                            name="tipo_evidencia"
                                                            value={
                                                              obtenerFormularioEvidencia(
                                                                item.id_seguimiento
                                                              )
                                                                .tipo_evidencia
                                                            }
                                                            onChange={e =>
                                                              cambiarCampoEvidencia(
                                                                item.id_seguimiento,
                                                                e
                                                              )
                                                            }
                                                            style={
                                                              styles.input
                                                            }
                                                          >
                                                            <option value="documento">
                                                              Documento
                                                            </option>
                                                            <option value="acta">
                                                              Acta
                                                            </option>
                                                            <option value="correo">
                                                              Correo
                                                            </option>
                                                            <option value="imagen">
                                                              Imagen
                                                            </option>
                                                            <option value="constancia">
                                                              Constancia
                                                            </option>
                                                            <option value="carta">
                                                              Carta
                                                            </option>
                                                            <option value="otro">
                                                              Otro
                                                            </option>
                                                          </select>
                                                        </div>

                                                        <div
                                                          style={
                                                            styles.field
                                                          }
                                                        >
                                                          <label
                                                            style={
                                                              styles.label
                                                            }
                                                          >
                                                            Fecha
                                                            de la
                                                            evidencia
                                                          </label>

                                                          <input
                                                            type="datetime-local"
                                                            name="fecha_evidencia"
                                                            value={
                                                              obtenerFormularioEvidencia(
                                                                item.id_seguimiento
                                                              )
                                                                .fecha_evidencia
                                                            }
                                                            onChange={e =>
                                                              cambiarCampoEvidencia(
                                                                item.id_seguimiento,
                                                                e
                                                              )
                                                            }
                                                            style={
                                                              styles.input
                                                            }
                                                          />
                                                        </div>
                                                      </div>

                                                      <div
                                                        style={
                                                          styles.field
                                                        }
                                                      >
                                                        <label
                                                          style={
                                                            styles.label
                                                          }
                                                        >
                                                          Título
                                                        </label>

                                                        <input
                                                          type="text"
                                                          name="titulo"
                                                          value={
                                                            obtenerFormularioEvidencia(
                                                              item.id_seguimiento
                                                            )
                                                              .titulo
                                                          }
                                                          onChange={e =>
                                                            cambiarCampoEvidencia(
                                                              item.id_seguimiento,
                                                              e
                                                            )
                                                          }
                                                          style={
                                                            styles.input
                                                          }
                                                          placeholder="Ej. Acta de reunión, correo del supervisor..."
                                                        />
                                                      </div>

                                                      <div
                                                        style={
                                                          styles.field
                                                        }
                                                      >
                                                        <label
                                                          style={
                                                            styles.label
                                                          }
                                                        >
                                                          Descripción
                                                        </label>

                                                        <textarea
                                                          name="descripcion"
                                                          value={
                                                            obtenerFormularioEvidencia(
                                                              item.id_seguimiento
                                                            )
                                                              .descripcion
                                                          }
                                                          onChange={e =>
                                                            cambiarCampoEvidencia(
                                                              item.id_seguimiento,
                                                              e
                                                            )
                                                          }
                                                          style={
                                                            styles.textarea
                                                          }
                                                          rows={
                                                            2
                                                          }
                                                          placeholder="Explica brevemente qué acredita o documenta este archivo..."
                                                        />
                                                      </div>

                                                      <div
                                                        style={
                                                          styles.field
                                                        }
                                                      >
                                                        <label
                                                          style={
                                                            styles.label
                                                          }
                                                        >
                                                          Archivo
                                                          *
                                                        </label>

                                                        <input
                                                          type="file"
                                                          accept=".pdf,.jpg,.jpeg,.png,.webp,.doc,.docx"
                                                          onChange={e =>
                                                            cambiarArchivoEvidencia(
                                                              item.id_seguimiento,
                                                              e
                                                            )
                                                          }
                                                          style={
                                                            styles.fileInput
                                                          }
                                                        />

                                                        {obtenerFormularioEvidencia(
                                                          item.id_seguimiento
                                                        )
                                                          .file && (
                                                          <div
                                                            style={
                                                              styles.selectedFile
                                                            }
                                                          >
                                                            📎{" "}
                                                            {
                                                              obtenerFormularioEvidencia(
                                                                item.id_seguimiento
                                                              )
                                                                .file
                                                                .name
                                                            }
                                                          </div>
                                                        )}
                                                      </div>

                                                      <div
                                                        style={
                                                          styles.evidenceSubmitRow
                                                        }
                                                      >
                                                        <button
                                                          type="submit"
                                                          disabled={
                                                            subiendoEvidenciaId ===
                                                            item.id_seguimiento
                                                          }
                                                          style={{
                                                            ...styles.addEvidenceButton,
                                                            opacity:
                                                              subiendoEvidenciaId ===
                                                              item.id_seguimiento
                                                                ? 0.65
                                                                : 1
                                                          }}
                                                        >
                                                          {subiendoEvidenciaId ===
                                                          item.id_seguimiento
                                                            ? "Subiendo..."
                                                            : "📎 Agregar evidencia"}
                                                        </button>
                                                      </div>
                                                    </form>
                                                  )}

                                                  {item.estado ===
                                                    "anulado" && (
                                                    <div
                                                      style={
                                                        styles.evidenceLocked
                                                      }
                                                    >
                                                      🔒 No
                                                      se
                                                      pueden
                                                      agregar
                                                      nuevas
                                                      evidencias
                                                      a un
                                                      seguimiento
                                                      anulado.
                                                    </div>
                                                  )}
                                                </>
                                              )}
                                            </div>
                                          )}
                                        </div>

                                        <div
                                          style={
                                            styles.registeredBy
                                          }
                                        >
                                          <span>
                                            Registrado por{" "}
                                            <strong>
                                              {item.usuario_registro ||
                                                "Usuario no disponible"}
                                            </strong>
                                          </span>

                                          <span>
                                            Creado:{" "}
                                            {formatearFecha(
                                              item.creado_en
                                            )}
                                          </span>
                                        </div>

                                        {!bloqueado && (
                                          <div
                                            style={
                                              styles.itemActions
                                            }
                                          >
                                            <button
                                              type="button"
                                              style={
                                                styles.editButton
                                              }
                                              disabled={
                                                procesandoId ===
                                                item.id_seguimiento
                                              }
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
                                              style={
                                                styles.closeButton
                                              }
                                              disabled={
                                                procesandoId ===
                                                item.id_seguimiento
                                              }
                                              onClick={() =>
                                                cerrarSeguimiento(
                                                  item
                                                )
                                              }
                                            >
                                              🔒 Cerrar
                                            </button>

                                            <button
                                              type="button"
                                              style={
                                                styles.deleteButton
                                              }
                                              disabled={
                                                procesandoId ===
                                                item.id_seguimiento
                                              }
                                              onClick={() =>
                                                anularSeguimiento(
                                                  item
                                                )
                                              }
                                            >
                                              ⚪ Anular
                                            </button>
                                          </div>
                                        )}
                                      </div>
                                    );
                                  })()}
                              </div>
                            );
                          })
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

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
    gap: "20px",
    flexWrap: "wrap",
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
    fontWeight: "800",
    cursor: "pointer",
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
    padding: "15px",
    textAlign: "center",
    boxShadow:
      "0 5px 16px rgba(30,64,120,.05)"
  },

  summaryNumber: {
    fontSize: "24px",
    fontWeight: "900",
    color: "#173e70"
  },

  summaryLabel: {
    color: "#667085",
    fontSize: "12px",
    marginTop: "4px",
    fontWeight: "700"
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

  gridTwo: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(270px,1fr))",
    gap: "16px"
  },

  formTypeIntro: {
    display: "flex",
    flexDirection: "column",
    gap: "5px",
    background: "#f8fbff",
    border: "1px solid #dbe7f5",
    borderRadius: "12px",
    padding: "14px 16px",
    marginBottom: "18px",
    color: "#344054",
    lineHeight: 1.5
  },

  gridThree: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(210px,1fr))",
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
    background: "#eff6ff",
    border: "1px solid #bfdbfe",
    borderRadius: "12px",
    padding: "15px",
    marginBottom: "20px",
    color: "#1e3a8a"
  },

  protectionNotice: {
    background: "#f0f9ff",
    border: "1px solid #bae6fd",
    borderRadius: "14px",
    padding: "16px 18px",
    marginBottom: "22px",
    color: "#0c4a6e"
  },

  noticeText: {
    margin: "7px 0 0",
    lineHeight: 1.55
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
    padding: "12px 18px",
    cursor: "pointer",
    fontWeight: "800"
  },

  cancelButton: {
    border: "1px solid #d0d5dd",
    borderRadius: "10px",
    background: "#ffffff",
    color: "#344054",
    padding: "12px 18px",
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
    minWidth: "42px",
    height: "42px",
    borderRadius: "10px",
    background: "#eef4ff",
    color: "#2167d5",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontWeight: "900"
  },

  folders: {
    display: "flex",
    flexDirection: "column",
    gap: "12px"
  },

  folder: {
    border: "1px solid #e2e8f0",
    borderRadius: "15px",
    overflow: "hidden",
    background: "#ffffff"
  },

  folderHeader: {
    width: "100%",
    border: "none",
    background: "#ffffff",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: "15px",
    padding: "17px 18px",
    cursor: "pointer",
    textAlign: "left"
  },

  folderLeft: {
    display: "flex",
    alignItems: "center",
    gap: "14px",
    minWidth: 0
  },

  folderIcon: {
    width: "46px",
    height: "46px",
    minWidth: "46px",
    borderRadius: "12px",
    background: "#f1f5fb",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: "23px"
  },

  folderText: {
    minWidth: 0
  },

  folderTitle: {
    fontSize: "17px",
    fontWeight: "900",
    color: "#173e70",
    marginBottom: "3px"
  },

  folderDescription: {
    color: "#667085",
    fontSize: "13px",
    lineHeight: 1.45
  },

  folderStats: {
    display: "flex",
    flexWrap: "wrap",
    gap: "12px",
    color: "#667085",
    fontSize: "11px",
    fontWeight: "700",
    marginTop: "7px"
  },

  folderRight: {
    display: "flex",
    alignItems: "center",
    gap: "14px"
  },

  folderCounter: {
    minWidth: "32px",
    height: "32px",
    borderRadius: "9px",
    background: "#eef4ff",
    color: "#2167d5",
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    fontWeight: "900",
    fontSize: "13px"
  },

  arrow: {
    color: "#667085",
    fontSize: "12px"
  },

  folderContent: {
    borderTop: "1px solid #e4e7ec",
    background: "#f8fafc",
    padding: "14px"
  },

  folderEmpty: {
    padding: "18px",
    textAlign: "center",
    color: "#98a2b3"
  },

  recordCard: {
    background: "#ffffff",
    border: "1px solid #e4e7ec",
    borderRadius: "12px",
    marginBottom: "10px",
    overflow: "hidden"
  },

  recordCancelled: {
    opacity: 0.78,
    background: "#fafafa"
  },

  recordHeader: {
    width: "100%",
    border: "none",
    background: "transparent",
    padding: "14px",
    cursor: "pointer",
    textAlign: "left",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-start",
    gap: "16px"
  },

  recordMain: {
    flex: 1,
    minWidth: 0
  },

  recordSide: {
    textAlign: "right",
    minWidth: "150px"
  },

  recordTitle: {
    fontWeight: "900",
    color: "#173e70",
    fontSize: "16px",
    marginTop: "5px"
  },

  recordPreview: {
    marginTop: "7px",
    color: "#667085",
    fontSize: "13px",
    lineHeight: 1.45
  },

  viewDetail: {
    color: "#2167d5",
    fontSize: "12px",
    fontWeight: "800",
    marginTop: "8px"
  },

  recordDetail: {
    borderTop: "1px solid #e4e7ec",
    padding: "17px"
  },

  badges: {
    display: "flex",
    flexWrap: "wrap",
    gap: "7px"
  },

  resultBadge: {
    background: "#f2f4f7",
    color: "#344054",
    padding: "5px 9px",
    borderRadius: "20px",
    fontSize: "12px",
    fontWeight: "800"
  },

  priorityBadge: {
    padding: "5px 9px",
    borderRadius: "20px",
    fontSize: "12px",
    fontWeight: "800"
  },

  priorityHigh: {
    background: "#fef3f2",
    color: "#b42318"
  },

  priorityMedium: {
    background: "#fffaeb",
    color: "#b54708"
  },

  priorityLow: {
    background: "#ecfdf3",
    color: "#067647"
  },

  statusBadge: {
    padding: "5px 9px",
    borderRadius: "20px",
    fontSize: "12px",
    fontWeight: "800"
  },

  statusOpen: {
    background: "#eef4ff",
    color: "#175cd3"
  },

  statusFollowing: {
    background: "#fffaeb",
    color: "#b54708"
  },

  statusClosed: {
    background: "#ecfdf3",
    color: "#067647"
  },

  statusCancelled: {
    background: "#f2f4f7",
    color: "#667085"
  },

  dateText: {
    color: "#667085",
    fontSize: "12px"
  },

  section: {
    marginTop: "14px"
  },

  text: {
    margin: "6px 0 0",
    lineHeight: 1.58,
    whiteSpace: "pre-wrap",
    color: "#344054"
  },

  infoStrip: {
    background: "#f8fafc",
    border: "1px solid #e4e7ec",
    borderRadius: "10px",
    padding: "11px 13px",
    color: "#475467",
    marginBottom: "14px",
    lineHeight: 1.5
  },

  versionGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(280px,1fr))",
    gap: "12px",
    marginTop: "14px"
  },

  versionBox: {
    background: "#f8fafc",
    border: "1px solid #e4e7ec",
    borderRadius: "11px",
    padding: "14px"
  },

  agreementBox: {
    marginTop: "15px",
    background: "#f0fdf4",
    border: "1px solid #bbf7d0",
    borderRadius: "11px",
    padding: "14px"
  },

  commitmentGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(280px,1fr))",
    gap: "12px",
    marginTop: "15px"
  },

  companyCommitment: {
    background: "#eff6ff",
    border: "1px solid #bfdbfe",
    borderRadius: "11px",
    padding: "14px"
  },

  employeeCommitment: {
    background: "#fff7ed",
    border: "1px solid #fed7aa",
    borderRadius: "11px",
    padding: "14px"
  },

  nextAction: {
    marginTop: "15px",
    background: "#f8fafc",
    border: "1px solid #e4e7ec",
    borderRadius: "10px",
    padding: "13px"
  },

  closedBox: {
    marginTop: "15px",
    background: "#ecfdf3",
    border: "1px solid #abefc6",
    borderRadius: "11px",
    padding: "14px",
    color: "#067647"
  },

  cancelledBox: {
    marginTop: "15px",
    background: "#f2f4f7",
    border: "1px solid #d0d5dd",
    borderRadius: "11px",
    padding: "14px",
    color: "#475467"
  },

  auditText: {
    marginTop: "6px",
    fontSize: "13px"
  },

  registeredBy: {
    borderTop: "1px solid #eaecf0",
    marginTop: "17px",
    paddingTop: "12px",
    color: "#667085",
    fontSize: "13px",
    display: "flex",
    justifyContent: "space-between",
    gap: "10px",
    flexWrap: "wrap"
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

  deleteButton: {
    border: "1px solid #d0d5dd",
    borderRadius: "8px",
    background: "#f9fafb",
    color: "#475467",
    padding: "9px 12px",
    cursor: "pointer",
    fontWeight: "700"
  },

  evidenceSection: {
    marginTop: "17px",
    border: "1px solid #dbe5f1",
    borderRadius: "12px",
    overflow: "hidden",
    background: "#ffffff"
  },

  evidenceHeader: {
    width: "100%",
    border: "none",
    background: "#f8fbff",
    padding: "13px 14px",
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    gap: "12px",
    cursor: "pointer",
    textAlign: "left"
  },

  evidenceHeaderTitle: {
    fontWeight: "900",
    color: "#173e70"
  },

  evidenceHeaderRight: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    color: "#667085",
    fontSize: "12px"
  },

  evidenceCounter: {
    minWidth: "28px",
    height: "28px",
    borderRadius: "8px",
    background: "#e7f0ff",
    color: "#2167d5",
    display: "inline-flex",
    justifyContent: "center",
    alignItems: "center",
    fontWeight: "900"
  },

  evidenceContent: {
    borderTop: "1px solid #e4e7ec",
    padding: "14px"
  },

  evidenceLoading: {
    padding: "16px",
    textAlign: "center",
    color: "#667085"
  },

  evidenceEmpty: {
    padding: "14px",
    background: "#f8fafc",
    border: "1px dashed #d0d5dd",
    borderRadius: "10px",
    textAlign: "center",
    color: "#667085"
  },

  evidenceList: {
    display: "flex",
    flexDirection: "column",
    gap: "10px"
  },

  evidenceCard: {
    border: "1px solid #e4e7ec",
    borderRadius: "11px",
    padding: "13px",
    background: "#ffffff"
  },

  evidenceCardCancelled: {
    background: "#f9fafb",
    opacity: 0.8
  },

  evidenceTop: {
    display: "flex",
    alignItems: "flex-start",
    gap: "12px",
    flexWrap: "wrap"
  },

  evidenceIcon: {
    width: "38px",
    height: "38px",
    minWidth: "38px",
    borderRadius: "9px",
    background: "#eef4ff",
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    fontSize: "18px"
  },

  evidenceInfo: {
    flex: 1,
    minWidth: "220px"
  },

  evidenceTitle: {
    fontWeight: "900",
    color: "#173e70",
    overflowWrap: "anywhere"
  },

  evidenceMeta: {
    color: "#667085",
    fontSize: "12px",
    marginTop: "4px",
    lineHeight: 1.45,
    overflowWrap: "anywhere"
  },

  evidenceDescription: {
    color: "#344054",
    fontSize: "13px",
    lineHeight: 1.5,
    marginTop: "7px",
    whiteSpace: "pre-wrap"
  },

  evidenceActions: {
    display: "flex",
    gap: "7px",
    flexWrap: "wrap"
  },

  viewFileButton: {
    display: "inline-flex",
    alignItems: "center",
    textDecoration: "none",
    border: "1px solid #bfdbfe",
    background: "#eff6ff",
    color: "#175cd3",
    borderRadius: "8px",
    padding: "8px 10px",
    fontSize: "12px",
    fontWeight: "800"
  },

  annulEvidenceButton: {
    border: "1px solid #d0d5dd",
    background: "#ffffff",
    color: "#475467",
    borderRadius: "8px",
    padding: "8px 10px",
    fontSize: "12px",
    fontWeight: "800",
    cursor: "pointer"
  },

  evidenceCancelledNotice: {
    marginTop: "10px",
    background: "#f2f4f7",
    border: "1px solid #d0d5dd",
    borderRadius: "9px",
    padding: "10px",
    color: "#475467"
  },

  evidenceForm: {
    marginTop: "14px",
    paddingTop: "14px",
    borderTop: "1px solid #e4e7ec"
  },

  evidenceFormHeader: {
    display: "flex",
    justifyContent: "space-between",
    gap: "12px",
    flexWrap: "wrap",
    marginBottom: "14px",
    color: "#173e70"
  },

  evidenceHint: {
    color: "#667085",
    fontSize: "12px",
    fontWeight: "600"
  },

  fileInput: {
    width: "100%",
    boxSizing: "border-box",
    border: "1px dashed #98a2b3",
    borderRadius: "10px",
    padding: "12px",
    background: "#f8fafc"
  },

  selectedFile: {
    marginTop: "7px",
    fontSize: "12px",
    color: "#344054",
    overflowWrap: "anywhere"
  },

  evidenceSubmitRow: {
    display: "flex",
    justifyContent: "flex-end"
  },

  addEvidenceButton: {
    border: "none",
    borderRadius: "9px",
    background: "#175cd3",
    color: "#ffffff",
    padding: "10px 14px",
    cursor: "pointer",
    fontWeight: "800"
  },

  evidenceLocked: {
    marginTop: "12px",
    background: "#f2f4f7",
    border: "1px solid #d0d5dd",
    borderRadius: "9px",
    padding: "11px",
    color: "#667085",
    fontSize: "13px"
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