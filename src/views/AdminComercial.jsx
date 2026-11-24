// ==================================================
// src/views/AdminComercial.jsx
// ==================================================

import React, {
  useEffect,
  useMemo,
  useState
} from "react";

import {
  getCurrentUser,
  getToken
} from "../services/AuthService";


// ==================================================
// API
// ==================================================

const API_URL =
  import.meta.env.VITE_API_URL ||
  `${import.meta.env.VITE_API_URL || window.location.origin}`;


// ==================================================
// COMPONENTE
// ==================================================

const AdminComercial = ({
  onBack
}) => {

  const user =
    getCurrentUser();

  const token =
    getToken();


  // ==================================================
  // VALIDAR MASTER
  // ==================================================

  const tipoAdmin =
    String(
      user?.tipo_admin || ""
    )
      .trim()
      .toLowerCase();


  const rol =
    String(
      user?.rol || ""
    )
      .trim()
      .toLowerCase();


  const esMaster =
    Number(
      user?.role
    ) === 1 &&
    rol === "admin" &&
    tipoAdmin === "master";


  // ==================================================
  // ESTADOS
  // ==================================================

  const [
    tabActivo,
    setTabActivo
  ] =
    useState(
      "resumen"
    );


  const [
    loading,
    setLoading
  ] =
    useState(true);


  const [
    error,
    setError
  ] =
    useState("");


  const [
    mensaje,
    setMensaje
  ] =
    useState("");


  const [
    organizaciones,
    setOrganizaciones
  ] =
    useState([]);


  const [
    planes,
    setPlanes
  ] =
    useState([]);


  const [
    organizacionSeleccionada,
    setOrganizacionSeleccionada
  ] =
    useState(null);


  const [
    detalleOrganizacion,
    setDetalleOrganizacion
  ] =
    useState(null);


  const [
    detalleComercial,
    setDetalleComercial
  ] =
    useState(null);


  const [
    licenciasOrganizacion,
    setLicenciasOrganizacion
  ] =
    useState(null);


  const [
    mostrarModalPlan,
    setMostrarModalPlan
  ] =
    useState(false);


  const [
    planEditando,
    setPlanEditando
  ] =
    useState(null);


  const [
    guardandoPlan,
    setGuardandoPlan
  ] =
    useState(false);


  const [
    procesandoOrganizacion,
    setProcesandoOrganizacion
  ] =
    useState(false);


  const [
    tabDetalleOrganizacion,
    setTabDetalleOrganizacion
  ] =
    useState("informacion");


  const [
    accionComercial,
    setAccionComercial
  ] =
    useState(null);


  const [
    formBeneficio,
    setFormBeneficio
  ] =
    useState({
      tipo_beneficio: "cortesia",
      id_plan: "",
      licencias_totales: 1,
      meses: 1,
      dias: 15,
      motivo: ""
    });


  const [
    licenciasAjuste,
    setLicenciasAjuste
  ] =
    useState(1);


  const [backups, setBackups] = useState([]);
  const [estadoBackup, setEstadoBackup] = useState(null);
  const [cargandoBackups, setCargandoBackups] = useState(false);
  const [creandoBackup, setCreandoBackup] = useState(false);


  // ==================================================
  // FORM PLAN
  // ==================================================

  const [
    formPlan,
    setFormPlan
  ] =
    useState({
      nombre: "",
      codigo: "",
      descripcion: "",
      tipo: "clinica",
      precio_mensual: "",
      precio_anual: "",
      licencias_incluidas: 1,
      permite_admin: 1,
      periodo_prueba_dias: 0,
      max_pacientes: "",
      destacado: 0,
      activo: 1
    });


  // ==================================================
  // HEADERS
  // ==================================================

  const headers =
    useMemo(
      () => ({
        Authorization:
          `Bearer ${token}`,
        "Content-Type":
          "application/json"
      }),
      [
        token
      ]
    );


  // ==================================================
  // PETICIÓN AUXILIAR
  // ==================================================

  const apiFetch =
    async (
      url,
      options = {}
    ) => {

      const response =
        await fetch(
          `${API_URL}${url}`,
          {
            ...options,

            headers: {
              ...headers,
              ...(
                options.headers ||
                {}
              )
            }
          }
        );


      let data = null;


      try {

        data =
          await response.json();

      }

      catch {

        data = null;

      }


      if (
        !response.ok
      ) {

        const errorApi =
          new Error(
            data?.message ||
            `Error HTTP ${response.status}`
          );


        errorApi.status =
          response.status;


        errorApi.data =
          data;


        throw errorApi;

      }


      return data;

    };


  // ==================================================
  // CARGAR ORGANIZACIONES
  // ==================================================

  const cargarOrganizaciones =
    async () => {

      const data =
        await apiFetch(
          "/api/organizaciones"
        );


      const lista =
        Array.isArray(
          data
        )
          ? data
          : Array.isArray(
              data?.organizaciones
            )
          ? data.organizaciones
          : Array.isArray(
              data?.data
            )
          ? data.data
          : [];


      setOrganizaciones(
        lista
      );

    };


  // ==================================================
  // CARGAR PLANES
  // ==================================================

  const cargarPlanes =
    async () => {

      const data =
        await apiFetch(
          "/api/planes"
        );


      const lista =
        Array.isArray(
          data?.planes
        )
          ? data.planes
          : [];


      setPlanes(
        lista
      );

    };


  const cargarBackups = async () => {
    try {
      setCargandoBackups(true);

      const listaData = await apiFetch(
        "/api/backups"
      );

      const estadoData = await apiFetch(
        "/api/backups/status"
      );

      setBackups(
        Array.isArray(listaData?.backups)
          ? listaData.backups
          : []
      );

      setEstadoBackup(
        estadoData || null
      );

    } finally {
      setCargandoBackups(false);
    }
  };


  const crearBackupManual = async () => {
    try {
      setCreandoBackup(true);
      setError("");
      setMensaje("");

      const data = await apiFetch(
        "/api/backups",
        {
          method: "POST",
          body: JSON.stringify({})
        }
      );

      setMensaje(
        data?.message ||
        "Respaldo creado correctamente."
      );

      await cargarBackups();

    } catch (err) {
      console.error(
        "❌ Error creando respaldo:",
        err
      );

      setError(
        err.message ||
        "No se pudo crear el respaldo."
      );

    } finally {
      setCreandoBackup(false);
    }
  };


  const descargarBackup = async nombre => {
    try {
      setError("");

      const response = await fetch(
        `${API_URL}/api/backups/${encodeURIComponent(nombre)}/download`,
        {
          headers: {
            Authorization:
              `Bearer ${token}`
          }
        }
      );

      if (!response.ok) {
        throw new Error(
          "No se pudo descargar el respaldo."
        );
      }

      const blob =
        await response.blob();

      const url =
        window.URL.createObjectURL(blob);

      const enlace =
        document.createElement("a");

      enlace.href = url;
      enlace.download = nombre;

      document.body.appendChild(enlace);
      enlace.click();
      enlace.remove();

      window.URL.revokeObjectURL(url);

    } catch (err) {
      console.error(
        "❌ Error descargando respaldo:",
        err
      );

      setError(
        err.message ||
        "No se pudo descargar el respaldo."
      );
    }
  };


  // ==================================================
  // CARGA INICIAL
  // ==================================================

  const cargarDatos =
    async () => {

      try {

        setLoading(
          true
        );

        setError(
          ""
        );


        await Promise.all([
          cargarOrganizaciones(),
          cargarPlanes()
        ]);

      }

      catch (
        err
      ) {

        console.error(
          "❌ Error cargando administración comercial:",
          err
        );


        setError(
          err.message ||
          "No se pudo cargar la información comercial."
        );

      }

      finally {

        setLoading(
          false
        );

      }

    };


  useEffect(
    () => {

      if (
        esMaster &&
        token
      ) {

        cargarDatos();

      }

    },
    [
      esMaster,
      token
    ]
  );


  // ==================================================
  // MÉTRICAS
  // ==================================================

  const metricas =
    useMemo(
      () => {

        const organizacionesActivas =
          organizaciones.filter(
            item =>
              String(
                item.estado ||
                ""
              )
                .toLowerCase() ===
              "activa"
          ).length;


        const planesActivos =
          planes.filter(
            item =>
              Number(
                item.activo
              ) === 1
          ).length;


        const suscripcionesActivas =
          planes.reduce(
            (
              total,
              plan
            ) =>
              total +
              Number(
                plan
                  .suscripciones_activas ||
                0
              ),
            0
          );


        const totalSuscripciones =
          planes.reduce(
            (
              total,
              plan
            ) =>
              total +
              Number(
                plan
                  .total_suscripciones ||
                0
              ),
            0
          );


        return {
          organizaciones:
            organizaciones.length,

          organizacionesActivas,

          planes:
            planes.length,

          planesActivos,

          suscripcionesActivas,

          totalSuscripciones
        };

      },
      [
        organizaciones,
        planes
      ]
    );


  // ==================================================
  // DETALLE ORGANIZACIÓN
  // ==================================================

  const abrirOrganizacion =
    async organizacion => {

      try {

        setError(
          ""
        );

        setMensaje(
          ""
        );


        setOrganizacionSeleccionada(
          organizacion
        );


        setDetalleOrganizacion(
          null
        );


        setDetalleComercial(
          null
        );


        setLicenciasOrganizacion(
          null
        );


        const id =
          organizacion
            .id_organizacion;


        const [
          detalle,
          licencias
        ] =
          await Promise.all([

            apiFetch(
              `/api/organizaciones/${id}`
            ),

            apiFetch(
              `/api/organizaciones/${id}/licencias`
            )

          ]);


        // ================================================
        // GUARDAR RESPUESTA COMPLETA
        // ================================================

        setDetalleComercial(
          detalle
        );


        // ================================================
        // COMPATIBILIDAD CON EL MODAL ACTUAL
        // ================================================

        setDetalleOrganizacion(
          detalle
            ?.organizacion ||
          detalle
            ?.data ||
          detalle
        );


        const resumenLicencias =
          licencias
            ?.licencias ||
          detalle
            ?.resumen_licencias ||
          licencias
            ?.data ||
          licencias;


        setLicenciasOrganizacion(
          resumenLicencias
        );


        const suscripcionActual =
          detalle
            ?.suscripcion ||
          detalle
            ?.organizacion
            ?.suscripcion ||
          null;


        const licenciasActuales =
          Number(
            suscripcionActual
              ?.licencias_totales ??
            resumenLicencias
              ?.licencias_totales ??
            resumenLicencias
              ?.total ??
            1
          );


        setLicenciasAjuste(
          licenciasActuales
        );


        setFormBeneficio({
          tipo_beneficio:
            "cortesia",

          id_plan:
            suscripcionActual
              ?.id_plan ||
            "",

          licencias_totales:
            licenciasActuales,

          meses:
            1,

          dias:
            15,

          motivo:
            ""
        });


        setTabDetalleOrganizacion(
          "informacion"
        );


        setAccionComercial(
          null
        );


        // ================================================
        // ACTUALIZAR TAMBIÉN LA ORGANIZACIÓN
        // SELECCIONADA CON LOS DATOS MÁS RECIENTES
        // ================================================

        if (
          detalle
            ?.organizacion
        ) {

          setOrganizacionSeleccionada(
            detalle.organizacion
          );

        }

      }

      catch (
        err
      ) {

        console.error(
          "❌ Error obteniendo organización:",
          err
        );


        setError(
          err.message ||
          "No se pudo obtener el detalle de la organización."
        );

      }

    };


  // ==================================================
  // RENOVAR SUSCRIPCIÓN
  // ==================================================

  const renovarOrganizacion =
    async () => {

      if (
        !organizacionSeleccionada
      ) {

        return;

      }


      try {

        setProcesandoOrganizacion(
          true
        );

        setError(
          ""
        );

        setMensaje(
          ""
        );


        const id =
          organizacionSeleccionada
            .id_organizacion;


        const data =
          await apiFetch(
            `/api/organizaciones/${id}/suscripcion/renovar`,
            {
              method:
                "PATCH",

              body:
                JSON.stringify(
                  {}
                )
            }
          );


        setMensaje(
          data?.message ||
          "Suscripción renovada correctamente."
        );


        await cargarOrganizaciones();


        await abrirOrganizacion(
          organizacionSeleccionada
        );

      }

      catch (
        err
      ) {

        setError(
          err.message
        );

      }

      finally {

        setProcesandoOrganizacion(
          false
        );

      }

    };


  // ==================================================
  // ACTIVAR SUSCRIPCIÓN
  // ==================================================

  const activarOrganizacion =
    async () => {

      if (
        !organizacionSeleccionada
      ) {

        return;

      }


      try {

        setProcesandoOrganizacion(
          true
        );

        setError(
          ""
        );

        setMensaje(
          ""
        );


        const id =
          organizacionSeleccionada
            .id_organizacion;


        const data =
          await apiFetch(
            `/api/organizaciones/${id}/suscripcion/activar`,
            {
              method:
                "PATCH",

              body:
                JSON.stringify(
                  {}
                )
            }
          );


        setMensaje(
          data?.message ||
          "Suscripción activada correctamente."
        );


        await cargarOrganizaciones();


        await abrirOrganizacion(
          organizacionSeleccionada
        );

      }

      catch (
        err
      ) {

        setError(
          err.message
        );

      }

      finally {

        setProcesandoOrganizacion(
          false
        );

      }

    };


  // ==================================================
  // PREPARAR BENEFICIO MASTER
  // ==================================================

  const prepararBeneficio =
    tipo => {

      const suscripcionActual =
        detalleComercial
          ?.suscripcion ||
        detalleOrganizacion
          ?.suscripcion ||
        null;


      const totalLicencias =
        Number(
          suscripcionActual
            ?.licencias_totales ??
          licenciasOrganizacion
            ?.licencias_totales ??
          licenciasOrganizacion
            ?.total ??
          1
        );


      setFormBeneficio({
        tipo_beneficio:
          tipo,

        id_plan:
          suscripcionActual
            ?.id_plan ||
          detalleOrganizacion
            ?.id_plan ||
          "",

        licencias_totales:
          totalLicencias,

        meses:
          1,

        dias:
          15,

        motivo:
          ""
      });


      setAccionComercial(
        tipo
      );


      setTabDetalleOrganizacion(
        "suscripcion"
      );

    };


  // ==================================================
  // CAMBIAR FORM BENEFICIO
  // ==================================================

  const cambiarFormBeneficio =
    e => {

      const {
        name,
        value
      } =
        e.target;


      setFormBeneficio(
        actual => ({
          ...actual,
          [name]:
            value
        })
      );

    };


  // ==================================================
  // GUARDAR BENEFICIO MASTER
  // ==================================================

  const guardarBeneficio =
    async e => {

      e.preventDefault();


      if (
        !organizacionSeleccionada
      ) {

        return;

      }


      try {

        setProcesandoOrganizacion(
          true
        );

        setError(
          ""
        );

        setMensaje(
          ""
        );


        const id =
          organizacionSeleccionada
            .id_organizacion;


        const payload = {

          tipo_beneficio:
            formBeneficio
              .tipo_beneficio,

          id_plan:
            Number(
              formBeneficio
                .id_plan
            ),

          licencias_totales:
            Number(
              formBeneficio
                .licencias_totales
            ),

          motivo:
            formBeneficio
              .motivo ||
            null

        };


        if (
          formBeneficio
            .tipo_beneficio ===
          "cortesia"
        ) {

          payload.meses =
            Number(
              formBeneficio
                .meses
            );

        }


        if (
          formBeneficio
            .tipo_beneficio ===
          "prueba"
        ) {

          payload.dias =
            Number(
              formBeneficio
                .dias
            );

        }


        const data =
          await apiFetch(
            `/api/organizaciones/${id}/beneficio`,
            {
              method:
                "POST",

              body:
                JSON.stringify(
                  payload
                )
            }
          );


        setMensaje(
          data?.message ||
          "Beneficio aplicado correctamente."
        );


        setAccionComercial(
          null
        );


        await cargarOrganizaciones();


        await abrirOrganizacion(
          organizacionSeleccionada
        );

      }

      catch (
        err
      ) {

        setError(
          err.message ||
          "No se pudo aplicar el beneficio."
        );

      }

      finally {

        setProcesandoOrganizacion(
          false
        );

      }

    };


  // ==================================================
  // AJUSTAR LICENCIAS DESDE MASTER
  // ==================================================

  const guardarAjusteLicencias =
    async () => {

      if (
        !organizacionSeleccionada
      ) {

        return;

      }


      try {

        setProcesandoOrganizacion(
          true
        );

        setError(
          ""
        );

        setMensaje(
          ""
        );


        const id =
          organizacionSeleccionada
            .id_organizacion;


        const data =
          await apiFetch(
            `/api/organizaciones/${id}/licencias`,
            {
              method:
                "PATCH",

              body:
                JSON.stringify({
                  licencias_totales:
                    Number(
                      licenciasAjuste
                    )
                })
            }
          );


        setMensaje(
          data?.message ||
          "Licencias actualizadas correctamente."
        );


        await cargarOrganizaciones();


        await abrirOrganizacion(
          organizacionSeleccionada
        );

      }

      catch (
        err
      ) {

        setError(
          err.message ||
          "No se pudieron actualizar las licencias."
        );

      }

      finally {

        setProcesandoOrganizacion(
          false
        );

      }

    };


  // ==================================================
  // NUEVO PLAN
  // ==================================================

  const nuevoPlan =
    () => {

      setPlanEditando(
        null
      );


      setFormPlan({
        nombre: "",
        codigo: "",
        descripcion: "",
        tipo: "clinica",
        precio_mensual: "",
        precio_anual: "",
        licencias_incluidas: 1,
        permite_admin: 1,
        periodo_prueba_dias: 0,
        max_pacientes: "",
        destacado: 0,
        activo: 1
      });


      setMostrarModalPlan(
        true
      );

    };


  // ==================================================
  // EDITAR PLAN
  // ==================================================

  const editarPlan =
    plan => {

      setPlanEditando(
        plan
      );


      setFormPlan({
        nombre:
          plan.nombre ||
          "",

        codigo:
          plan.codigo ||
          "",

        descripcion:
          plan.descripcion ||
          "",

        tipo:
          plan.tipo ||
          "clinica",

        precio_mensual:
          plan.precio_mensual ??
          "",

        precio_anual:
          plan.precio_anual ??
          "",

        licencias_incluidas:
          plan.licencias_incluidas ??
          1,

        permite_admin:
          Number(
            plan.permite_admin
          ) === 1
            ? 1
            : 0,

        periodo_prueba_dias:
          plan.periodo_prueba_dias ??
          0,

        max_pacientes:
          plan.max_pacientes ??
          "",

        destacado:
          Number(
            plan.destacado
          ) === 1
            ? 1
            : 0,

        activo:
          Number(
            plan.activo
          ) === 1
            ? 1
            : 0
      });


      setMostrarModalPlan(
        true
      );

    };


  // ==================================================
  // CAMBIAR FORM
  // ==================================================

  const cambiarFormPlan =
    e => {

      const {
        name,
        value
      } =
        e.target;


      setFormPlan(
        actual => ({
          ...actual,
          [name]:
            value
        })
      );

    };


  // ==================================================
  // GUARDAR PLAN
  // ==================================================

  const guardarPlan =
    async e => {

      e.preventDefault();


      try {

        setGuardandoPlan(
          true
        );

        setError(
          ""
        );

        setMensaje(
          ""
        );


        const payload = {

          nombre:
            formPlan.nombre,

          codigo:
            formPlan.codigo,

          descripcion:
            formPlan.descripcion,

          tipo:
            formPlan.tipo,

          precio_mensual:
            Number(
              formPlan
                .precio_mensual ||
              0
            ),

          precio_anual:
            Number(
              formPlan
                .precio_anual ||
              0
            ),

          licencias_incluidas:
            Number(
              formPlan
                .licencias_incluidas
            ),

          permite_admin:
            Number(
              formPlan
                .permite_admin
            ),

          periodo_prueba_dias:
            Number(
              formPlan
                .periodo_prueba_dias ||
              0
            ),

          max_pacientes:
            formPlan.max_pacientes ===
              ""
              ? null
              : Number(
                  formPlan
                    .max_pacientes
                ),

          destacado:
            Number(
              formPlan
                .destacado
            ),

          activo:
            Number(
              formPlan
                .activo
            )

        };


        let data;


        if (
          planEditando
        ) {

          data =
            await apiFetch(
              `/api/planes/${planEditando.id_plan}`,
              {
                method:
                  "PATCH",

                body:
                  JSON.stringify(
                    payload
                  )
              }
            );

        }

        else {

          data =
            await apiFetch(
              "/api/planes",
              {
                method:
                  "POST",

                body:
                  JSON.stringify(
                    payload
                  )
              }
            );

        }


        setMensaje(
          data?.message ||
          "Plan guardado correctamente."
        );


        setMostrarModalPlan(
          false
        );


        await cargarPlanes();

      }

      catch (
        err
      ) {

        setError(
          err.message
        );

      }

      finally {

        setGuardandoPlan(
          false
        );

      }

    };


  // ==================================================
  // CAMBIAR ESTADO PLAN
  // ==================================================

  const cambiarEstadoPlan =
    async plan => {

      try {

        setError(
          ""
        );

        setMensaje(
          ""
        );


        const nuevoEstado =
          Number(
            plan.activo
          ) === 1
            ? 0
            : 1;


        const data =
          await apiFetch(
            `/api/planes/${plan.id_plan}/estado`,
            {
              method:
                "PATCH",

              body:
                JSON.stringify({
                  activo:
                    nuevoEstado
                })
            }
          );


        setMensaje(
          data?.message ||
          "Estado actualizado."
        );


        await cargarPlanes();

      }

      catch (
        err
      ) {

        setError(
          err.message
        );

      }

    };


  // ==================================================
  // FORMATOS
  // ==================================================

  const formatearFecha =
    valor => {

      if (
        !valor
      ) {

        return "—";

      }


      const fecha =
        new Date(
          valor
        );


      if (
        Number.isNaN(
          fecha.getTime()
        )
      ) {

        return "—";

      }


      return fecha.toLocaleDateString(
        "es-MX",
        {
          year:
            "numeric",

          month:
            "short",

          day:
            "2-digit"
        }
      );

    };


  const formatearPrecio =
    valor => {

      if (
        valor === null ||
        valor === undefined
      ) {

        return "Sin definir";

      }


      return new Intl.NumberFormat(
        "es-MX",
        {
          style:
            "currency",

          currency:
            "MXN"
        }
      ).format(
        Number(valor)
      );

    };


  const horaBackup =
    estadoBackup &&
    estadoBackup.hora !== undefined
      ? String(estadoBackup.hora).padStart(2, "0") + ":00"
      : "02:00";


  const retencionBackup =
    estadoBackup &&
    estadoBackup.dias_retencion !== undefined
      ? estadoBackup.dias_retencion + " días"
      : "7 días";


  const totalBackups =
    estadoBackup &&
    estadoBackup.total_respaldos !== undefined
      ? estadoBackup.total_respaldos
      : backups.length;


  const ultimoBackup =
    estadoBackup &&
    estadoBackup.ultimo_respaldo
      ? estadoBackup.ultimo_respaldo.fecha
      : null;


  // ==================================================
  // NO MASTER
  // ==================================================

  if (
    !esMaster
  ) {

    return (
      <div style={page}>

        <div style={accessDenied}>

          <div style={bigIcon}>
            🔒
          </div>

          <h2>
            Acceso restringido
          </h2>

          <p>
            Esta sección está disponible únicamente para el Administrador Master.
          </p>

          <button
            type="button"
            style={primaryButton}
            onClick={
              onBack
            }
          >
            ← Volver
          </button>

        </div>

      </div>
    );

  }


  // ==================================================
  // RENDER
  // ==================================================

  return (

    <div
      style={
        page
      }
    >

      {/* ==================================================
          HEADER
      ================================================== */}

      <div
        style={
          header
        }
      >

        <div>

          <button
            type="button"
            style={
              backButton
            }
            onClick={
              onBack
            }
          >
            ← Volver
          </button>


          <h1
            style={
              title
            }
          >
            🛡️ Administración Comercial
          </h1>


          <p
            style={
              subtitle
            }
          >
            Gestiona organizaciones, suscripciones,
            licencias y planes de MirrorSoul.
          </p>

        </div>


        <button
          type="button"
          style={
            refreshButton
          }
          onClick={
            cargarDatos
          }
        >
          🔄 Actualizar
        </button>

      </div>


      {/* ==================================================
          MENSAJES
      ================================================== */}

      {error && (

        <div
          style={
            errorBox
          }
        >
          ❌ {error}
        </div>

      )}


      {mensaje && (

        <div
          style={
            successBox
          }
        >
          ✅ {mensaje}
        </div>

      )}


      {/* ==================================================
          TABS
      ================================================== */}

      <div
        style={
          tabs
        }
      >

        <TabButton
          activo={
            tabActivo ===
            "resumen"
          }
          onClick={() =>
            setTabActivo(
              "resumen"
            )
          }
        >
          📊 Resumen
        </TabButton>


        <TabButton
          activo={
            tabActivo ===
            "organizaciones"
          }
          onClick={() =>
            setTabActivo(
              "organizaciones"
            )
          }
        >
          🏢 Organizaciones
        </TabButton>


        <TabButton
          activo={
            tabActivo ===
            "planes"
          }
          onClick={() =>
            setTabActivo(
              "planes"
            )
          }
        >
          📦 Planes
        </TabButton>


        <TabButton
          activo={
            tabActivo ===
            "respaldos"
          }
          onClick={() => {
            setTabActivo(
              "respaldos"
            );

            cargarBackups()
              .catch(
                err =>
                  setError(
                    err.message
                  )
              );
          }}
        >
          🗄️ Respaldos
        </TabButton>

      </div>


      {/* ==================================================
          LOADING
      ================================================== */}

      {loading ? (

        <div
          style={
            loadingBox
          }
        >
          Cargando información comercial...
        </div>

      ) : (

        <>

          {/* ==================================================
              RESUMEN
          ================================================== */}

          {tabActivo ===
            "resumen" && (

            <>

              <div
                style={
                  metricsGrid
                }
              >

                <MetricCard
                  icon="🏢"
                  label="Organizaciones"
                  value={
                    metricas.organizaciones
                  }
                  detail={
                    `${metricas.organizacionesActivas} activas`
                  }
                />


                <MetricCard
                  icon="📦"
                  label="Planes"
                  value={
                    metricas.planes
                  }
                  detail={
                    `${metricas.planesActivos} activos`
                  }
                />


                <MetricCard
                  icon="💳"
                  label="Suscripciones"
                  value={
                    metricas.totalSuscripciones
                  }
                  detail={
                    `${metricas.suscripcionesActivas} activas`
                  }
                />


                <MetricCard
                  icon="🎟️"
                  label="Licencias"
                  value={
                    organizaciones.reduce(
                      (
                        total,
                        item
                      ) =>
                        total +
                        Number(
                          item
                            .licencias_totales ||
                          0
                        ),
                      0
                    )
                  }
                  detail="Contratadas"
                />

              </div>


              <section
                style={
                  sectionCard
                }
              >

                <div
                  style={
                    sectionHeader
                  }
                >

                  <div>

                    <h2
                      style={
                        sectionTitle
                      }
                    >
                      Organizaciones recientes
                    </h2>

                    <p
                      style={
                        sectionDescription
                      }
                    >
                      Estado general de las organizaciones registradas.
                    </p>

                  </div>

                </div>


                <OrganizacionesTable
                  organizaciones={
                    organizaciones
                  }
                  onOpen={
                    abrirOrganizacion
                  }
                />

              </section>

            </>

          )}


          {/* ==================================================
              ORGANIZACIONES
          ================================================== */}

          {tabActivo ===
            "organizaciones" && (

            <section
              style={
                sectionCard
              }
            >

              <div
                style={
                  sectionHeader
                }
              >

                <div>

                  <h2
                    style={
                      sectionTitle
                    }
                  >
                    🏢 Organizaciones
                  </h2>


                  <p
                    style={
                      sectionDescription
                    }
                  >
                    Consulta el plan, suscripción y licencias de cada organización.
                  </p>

                </div>

              </div>


              <OrganizacionesTable
                organizaciones={
                  organizaciones
                }
                onOpen={
                  abrirOrganizacion
                }
              />

            </section>

          )}


          {/* ==================================================
              PLANES
          ================================================== */}

          {tabActivo ===
            "planes" && (

            <section
              style={
                sectionCard
              }
            >

              <div
                style={
                  sectionHeader
                }
              >

                <div>

                  <h2
                    style={
                      sectionTitle
                    }
                  >
                    📦 Planes
                  </h2>


                  <p
                    style={
                      sectionDescription
                    }
                  >
                    Crea, modifica, activa o desactiva los planes comerciales.
                  </p>

                </div>


                <button
                  type="button"
                  style={
                    primaryButton
                  }
                  onClick={
                    nuevoPlan
                  }
                >
                  + Nuevo plan
                </button>

              </div>


              <div
                style={
                  cardsPlans
                }
              >

                {planes.map(
                  plan => (

                    <div
                      key={
                        plan.id_plan
                      }
                      style={
                        planCard
                      }
                    >

                      <div
                        style={
                          planTop
                        }
                      >

                        <div>

                          <div
                            style={
                              planName
                            }
                          >
                            {
                              plan.nombre
                            }
                          </div>


                          <div
                            style={
                              planCode
                            }
                          >
                            {
                              plan.codigo
                            }
                          </div>

                        </div>


                        <StatusBadge
                          activo={
                            Number(
                              plan.activo
                            ) === 1
                          }
                        />

                      </div>


                      <div
                        style={
                          planType
                        }
                      >
                        {String(
                          plan.tipo ||
                          ""
                        ).toUpperCase()}
                      </div>


                      <p
                        style={
                          planDescription
                        }
                      >
                        {
                          plan.descripcion ||
                          "Sin descripción"
                        }
                      </p>


                      <div
                        style={
                          planDataGrid
                        }
                      >

                        <InfoItem
                          label="Mensual"
                          value={
                            formatearPrecio(
                              plan
                                .precio_mensual
                            )
                          }
                        />


                        <InfoItem
                          label="Anual"
                          value={
                            formatearPrecio(
                              plan
                                .precio_anual
                            )
                          }
                        />


                        <InfoItem
                          label="Licencias"
                          value={
                            plan
                              .licencias_incluidas
                          }
                        />


                        <InfoItem
                          label="Suscripciones"
                          value={
                            plan
                              .total_suscripciones ||
                            0
                          }
                        />


                        <InfoItem
                          label="Activas"
                          value={
                            plan
                              .suscripciones_activas ||
                            0
                          }
                        />


                        <InfoItem
                          label="Prueba"
                          value={
                            `${plan.periodo_prueba_dias || 0} días`
                          }
                        />

                      </div>


                      <div
                        style={
                          planActions
                        }
                      >

                        <button
                          type="button"
                          style={
                            secondaryButton
                          }
                          onClick={() =>
                            editarPlan(
                              plan
                            )
                          }
                        >
                          ✏️ Editar
                        </button>


                        <button
                          type="button"
                          style={
                            Number(
                              plan.activo
                            ) === 1
                              ? dangerButton
                              : activateButton
                          }
                          onClick={() =>
                            cambiarEstadoPlan(
                              plan
                            )
                          }
                        >
                          {Number(
                            plan.activo
                          ) === 1
                            ? "Desactivar"
                            : "Activar"}
                        </button>

                      </div>

                    </div>

                  )
                )}

              </div>

            </section>

          )}

          {/* ==================================================
              RESPALDOS
          ================================================== */}

          {tabActivo ===
            "respaldos" && (

            <section
              style={
                sectionCard
              }
            >

              <div
                style={
                  sectionHeader
                }
              >

                <div>
                  <h2
                    style={
                      sectionTitle
                    }
                  >
                    🗄️ Respaldos de base de datos
                  </h2>

                  <p
                    style={
                      sectionDescription
                    }
                  >
                    El sistema crea un respaldo diario y conserva los últimos 7 días.
                  </p>
                </div>


                <button
                  type="button"
                  style={
                    primaryButton
                  }
                  disabled={
                    creandoBackup
                  }
                  onClick={
                    crearBackupManual
                  }
                >
                  {creandoBackup
                    ? "Creando..."
                    : "🗄️ Crear respaldo ahora"}
                </button>

              </div>


              <div
                style={
                  backupGrid
                }
              >
                <InfoItem
                  label="Estado"
                  value={
                    estadoBackup &&
                    estadoBackup.sistema === "activo"
                      ? "✅ Activo"
                      : "—"
                  }
                />

                <InfoItem
                  label="Frecuencia"
                  value="Diario"
                />

                <InfoItem
                  label="Hora"
                  value={
                    horaBackup
                  }
                />

                <InfoItem
                  label="Retención"
                  value={
                    retencionBackup
                  }
                />

                <InfoItem
                  label="Guardados"
                  value={
                    totalBackups
                  }
                />

                <InfoItem
                  label="Último respaldo"
                  value={
                    formatearFecha(
                      ultimoBackup
                    )
                  }
                />
              </div>


              <div
                style={
                  backupMessage
                }
              >
                🔐 Primero se crea el respaldo nuevo. Solo después se eliminan los archivos con más de 7 días.
              </div>


              <div
                style={{
                  ...sectionHeader,
                  marginTop: "22px"
                }}
              >
                <div>
                  <h3
                    style={{
                      ...sectionTitle,
                      fontSize: "18px"
                    }}
                  >
                    Historial
                  </h3>
                </div>

                <button
                  type="button"
                  style={
                    refreshButton
                  }
                  onClick={() =>
                    cargarBackups()
                      .catch(
                        err =>
                          setError(
                            err.message
                          )
                      )
                  }
                >
                  🔄 Actualizar
                </button>
              </div>


              {cargandoBackups ? (
                <div
                  style={
                    loadingBox
                  }
                >
                  Cargando respaldos...
                </div>
              ) : backups.length === 0 ? (
                <div
                  style={
                    emptyState
                  }
                >
                  No hay respaldos disponibles.
                </div>
              ) : (
                <div
                  style={
                    tableWrapper
                  }
                >
                  <table
                    style={
                      table
                    }
                  >
                    <thead>
                      <tr>
                        <th style={th}>
                          Archivo
                        </th>

                        <th style={th}>
                          Fecha
                        </th>

                        <th style={th}>
                          Tamaño
                        </th>

                        <th style={th}>
                          Acción
                        </th>
                      </tr>
                    </thead>

                    <tbody>
                      {backups.map(
                        backup => (
                          <tr
                            key={
                              backup.nombre
                            }
                          >
                            <td style={td}>
                              {backup.nombre}
                            </td>

                            <td style={td}>
                              {formatearFecha(
                                backup.fecha
                              )}
                            </td>

                            <td style={td}>
                              {backup.tamaño_mb !== undefined
                                ? backup.tamaño_mb + " MB"
                                : "—"}
                            </td>

                            <td style={td}>
                              <button
                                type="button"
                                style={
                                  smallButton
                                }
                                onClick={() =>
                                  descargarBackup(
                                    backup.nombre
                                  )
                                }
                              >
                                ⬇️ Descargar
                              </button>
                            </td>
                          </tr>
                        )
                      )}
                    </tbody>
                  </table>
                </div>
              )}

            </section>

          )}

        </>

      )}


      {/* ==================================================
          MODAL ORGANIZACIÓN / CENTRO DE CONTROL MASTER
      ================================================== */}

      {organizacionSeleccionada && (

        <div
          style={
            modalOverlay
          }
          onClick={() => {
            setOrganizacionSeleccionada(
              null
            );

            setAccionComercial(
              null
            );
          }}
        >

          <div
            style={
              modalControlCenter
            }
            onClick={
              e =>
                e.stopPropagation()
            }
          >

            <div
              style={
                modalHeader
              }
            >

              <div>

                <div
                  style={
                    controlCenterEyebrow
                  }
                >
                  🛡️ CENTRO DE CONTROL MASTER
                </div>

                <h2
                  style={
                    modalTitle
                  }
                >
                  🏢 {
                    organizacionSeleccionada
                      .nombre
                  }
                </h2>


                <p
                  style={
                    modalSubtitle
                  }
                >
                  Administración comercial, usuarios, licencias y soporte.
                </p>

              </div>


              <button
                type="button"
                style={
                  closeButton
                }
                onClick={() => {
                  setOrganizacionSeleccionada(
                    null
                  );

                  setAccionComercial(
                    null
                  );
                }}
              >
                ✕
              </button>

            </div>


            {/* =============================================
                RESUMEN SUPERIOR
            ============================================= */}

            <div
              style={
                masterSummaryGrid
              }
            >

              <InfoItem
                label="Tipo"
                value={
                  organizacionSeleccionada
                    .tipo ||
                  "—"
                }
              />


              <InfoItem
                label="Organización"
                value={
                  organizacionSeleccionada
                    .estado ||
                  "—"
                }
              />


              <InfoItem
                label="Suscripción"
                value={
                  detalleComercial
                    ?.suscripcion
                    ?.estado ||
                  detalleOrganizacion
                    ?.estado_suscripcion ||
                  "—"
                }
              />


              <InfoItem
                label="Plan"
                value={
                  detalleComercial
                    ?.suscripcion
                    ?.plan_nombre ||
                  detalleOrganizacion
                    ?.plan_nombre ||
                  detalleOrganizacion
                    ?.plan ||
                  "—"
                }
              />


              <InfoItem
                label="Licencias"
                value={
                  `${detalleComercial
                    ?.resumen_licencias
                    ?.usadas ??
                    licenciasOrganizacion
                      ?.licencias_usadas ??
                    0} / ${detalleComercial
                    ?.resumen_licencias
                    ?.totales ??
                    licenciasOrganizacion
                      ?.licencias_totales ??
                    0}`
                }
              />


              <InfoItem
                label="Diagnóstico"
                value={
                  detalleComercial
                    ?.diagnostico
                    ?.correcto
                    ? "✅ Correcto"
                    : detalleComercial
                        ?.diagnostico
                        ?.total_problemas
                      ? `⚠️ ${detalleComercial.diagnostico.total_problemas} problema(s)`
                      : "—"
                }
              />

            </div>


            {/* =============================================
                ACCIONES RÁPIDAS
            ============================================= */}

            <div
              style={
                quickActionsSection
              }
            >

              <div
                style={
                  quickActionsTitle
                }
              >
                Acciones rápidas
              </div>


              <div
                style={
                  quickActionsGrid
                }
              >

                <button
                  type="button"
                  style={
                    masterActionButton
                  }
                  disabled={
                    procesandoOrganizacion
                  }
                  onClick={() =>
                    prepararBeneficio(
                      "cortesia"
                    )
                  }
                >
                  <span style={masterActionIcon}>
                    🎁
                  </span>

                  <span>
                    <strong>
                      Regalar membresía
                    </strong>

                    <small style={masterActionDescription}>
                      Cortesía por meses
                    </small>
                  </span>
                </button>


                <button
                  type="button"
                  style={
                    masterActionButton
                  }
                  disabled={
                    procesandoOrganizacion
                  }
                  onClick={() =>
                    prepararBeneficio(
                      "prueba"
                    )
                  }
                >
                  <span style={masterActionIcon}>
                    🧪
                  </span>

                  <span>
                    <strong>
                      Prueba gratis
                    </strong>

                    <small style={masterActionDescription}>
                      Acceso por días
                    </small>
                  </span>
                </button>


                <button
                  type="button"
                  style={
                    masterActionButton
                  }
                  disabled={
                    procesandoOrganizacion
                  }
                  onClick={() => {
                    setAccionComercial(
                      "licencias"
                    );

                    setTabDetalleOrganizacion(
                      "licencias"
                    );
                  }}
                >
                  <span style={masterActionIcon}>
                    🎟️
                  </span>

                  <span>
                    <strong>
                      Ajustar licencias
                    </strong>

                    <small style={masterActionDescription}>
                      Aumentar o reducir
                    </small>
                  </span>
                </button>


                <button
                  type="button"
                  style={
                    masterActionButton
                  }
                  disabled={
                    procesandoOrganizacion
                  }
                  onClick={
                    renovarOrganizacion
                  }
                >
                  <span style={masterActionIcon}>
                    🔄
                  </span>

                  <span>
                    <strong>
                      Renovar
                    </strong>

                    <small style={masterActionDescription}>
                      Extender suscripción
                    </small>
                  </span>
                </button>


                <button
                  type="button"
                  style={
                    masterActionButton
                  }
                  disabled={
                    procesandoOrganizacion
                  }
                  onClick={
                    activarOrganizacion
                  }
                >
                  <span style={masterActionIcon}>
                    ✅
                  </span>

                  <span>
                    <strong>
                      Activar
                    </strong>

                    <small style={masterActionDescription}>
                      Reactivar acceso
                    </small>
                  </span>
                </button>

              </div>

            </div>


            {/* =============================================
                TABS DEL DETALLE
            ============================================= */}

            <div
              style={
                detailTabs
              }
            >

              {[
                [
                  "informacion",
                  "🏢 Información"
                ],
                [
                  "suscripcion",
                  "💳 Suscripción"
                ],
                [
                  "licencias",
                  "🎟️ Licencias"
                ],
                [
                  "usuarios",
                  "👥 Usuarios"
                ],
                [
                  "pagos",
                  "💰 Pagos"
                ],
                [
                  "soporte",
                  "🛠️ Soporte"
                ]
              ].map(
                ([clave, etiqueta]) => (

                  <button
                    key={
                      clave
                    }
                    type="button"
                    style={{
                      ...detailTabButton,

                      ...(tabDetalleOrganizacion ===
                      clave
                        ? detailTabButtonActive
                        : {})
                    }}
                    onClick={() => {
                      setTabDetalleOrganizacion(
                        clave
                      );

                      if (
                        clave !==
                          "suscripcion" &&
                        clave !==
                          "licencias"
                      ) {

                        setAccionComercial(
                          null
                        );

                      }
                    }}
                  >
                    {etiqueta}
                  </button>

                )
              )}

            </div>


            {/* =============================================
                INFORMACIÓN
            ============================================= */}

            {tabDetalleOrganizacion ===
              "informacion" && (

              <div
                style={
                  detailPanel
                }
              >

                <h3 style={detailPanelTitle}>
                  🏢 Datos de la organización
                </h3>


                <div
                  style={
                    detailGrid
                  }
                >

                  <InfoItem
                    label="Responsable"
                    value={
                      organizacionSeleccionada
                        .responsable ||
                      "—"
                    }
                  />


                  <InfoItem
                    label="Correo"
                    value={
                      organizacionSeleccionada
                        .correo ||
                      "—"
                    }
                  />


                  <InfoItem
                    label="Teléfono"
                    value={
                      organizacionSeleccionada
                        .telefono ||
                      "—"
                    }
                  />


                  <InfoItem
                    label="RFC"
                    value={
                      organizacionSeleccionada
                        .rfc ||
                      "—"
                    }
                  />


                  <InfoItem
                    label="Dirección"
                    value={
                      organizacionSeleccionada
                        .direccion ||
                      "—"
                    }
                  />


                  <InfoItem
                    label="Usuarios registrados"
                    value={
                      detalleComercial
                        ?.usuarios
                        ?.length ??
                      detalleOrganizacion
                        ?.total_usuarios ??
                      0
                    }
                  />

                </div>

              </div>

            )}


            {/* =============================================
                SUSCRIPCIÓN
            ============================================= */}

            {tabDetalleOrganizacion ===
              "suscripcion" && (

              <div
                style={
                  detailPanel
                }
              >

                <h3 style={detailPanelTitle}>
                  💳 Suscripción actual
                </h3>


                <div
                  style={
                    detailGrid
                  }
                >

                  <InfoItem
                    label="Plan"
                    value={
                      detalleComercial
                        ?.suscripcion
                        ?.plan_nombre ||
                      "—"
                    }
                  />


                  <InfoItem
                    label="Estado"
                    value={
                      detalleComercial
                        ?.suscripcion
                        ?.estado ||
                      "—"
                    }
                  />


                  <InfoItem
                    label="Origen"
                    value={
                      detalleComercial
                        ?.suscripcion
                        ?.origen_suscripcion ||
                      "—"
                    }
                  />


                  <InfoItem
                    label="Fecha inicio"
                    value={
                      formatearFecha(
                        detalleComercial
                          ?.suscripcion
                          ?.fecha_inicio
                      )
                    }
                  />


                  <InfoItem
                    label="Fecha fin"
                    value={
                      formatearFecha(
                        detalleComercial
                          ?.suscripcion
                          ?.fecha_fin
                      )
                    }
                  />


                  <InfoItem
                    label="Próxima renovación"
                    value={
                      formatearFecha(
                        detalleComercial
                          ?.suscripcion
                          ?.proxima_renovacion
                      )
                    }
                  />


                  <InfoItem
                    label="Motivo beneficio"
                    value={
                      detalleComercial
                        ?.suscripcion
                        ?.motivo_beneficio ||
                      "—"
                    }
                  />


                  <InfoItem
                    label="Otorgado por"
                    value={
                      detalleComercial
                        ?.suscripcion
                        ?.otorgado_por
                        ? `Master #${detalleComercial.suscripcion.otorgado_por}`
                        : "—"
                    }
                  />

                </div>


                {(accionComercial ===
                  "cortesia" ||
                  accionComercial ===
                  "prueba") && (

                  <form
                    style={
                      actionFormCard
                    }
                    onSubmit={
                      guardarBeneficio
                    }
                  >

                    <div
                      style={
                        actionFormHeader
                      }
                    >

                      <div>

                        <strong>
                          {accionComercial ===
                          "cortesia"
                            ? "🎁 Regalar membresía"
                            : "🧪 Otorgar prueba gratuita"}
                        </strong>

                        <div
                          style={
                            actionFormSubtitle
                          }
                        >
                          Esta acción no crea un pago.
                        </div>

                      </div>


                      <button
                        type="button"
                        style={
                          miniCloseButton
                        }
                        onClick={() =>
                          setAccionComercial(
                            null
                          )
                        }
                      >
                        ✕
                      </button>

                    </div>


                    <div
                      style={
                        formGrid
                      }
                    >

                      <Field
                        label="Plan"
                      >
                        <select
                          required
                          name="id_plan"
                          value={
                            formBeneficio
                              .id_plan
                          }
                          onChange={
                            cambiarFormBeneficio
                          }
                          style={
                            input
                          }
                        >
                          <option value="">
                            Selecciona
                          </option>

                          {planes
                            .filter(
                              plan => {

                                const tipoOrg =
                                  String(
                                    organizacionSeleccionada
                                      ?.tipo ||
                                    ""
                                  )
                                    .toLowerCase();


                                const tipoPlan =
                                  String(
                                    plan.tipo ||
                                    ""
                                  )
                                    .toLowerCase();


                                return (
                                  tipoPlan ===
                                    tipoOrg ||
                                  (
                                    tipoOrg ===
                                      "independiente" &&
                                    tipoPlan ===
                                      "psicologo"
                                  )
                                );

                              }
                            )
                            .map(
                              plan => (

                                <option
                                  key={
                                    plan.id_plan
                                  }
                                  value={
                                    plan.id_plan
                                  }
                                >
                                  {plan.nombre}
                                </option>

                              )
                            )}

                        </select>
                      </Field>


                      <Field
                        label="Licencias"
                      >
                        <input
                          required
                          type="number"
                          min="1"
                          max="10000"
                          name="licencias_totales"
                          value={
                            formBeneficio
                              .licencias_totales
                          }
                          onChange={
                            cambiarFormBeneficio
                          }
                          style={
                            input
                          }
                        />
                      </Field>


                      {accionComercial ===
                        "cortesia" ? (

                        <Field
                          label="Meses de cortesía"
                        >
                          <input
                            required
                            type="number"
                            min="1"
                            max="36"
                            name="meses"
                            value={
                              formBeneficio
                                .meses
                            }
                            onChange={
                              cambiarFormBeneficio
                            }
                            style={
                              input
                            }
                          />
                        </Field>

                      ) : (

                        <Field
                          label="Días de prueba"
                        >
                          <input
                            required
                            type="number"
                            min="1"
                            max="365"
                            name="dias"
                            value={
                              formBeneficio
                                .dias
                            }
                            onChange={
                              cambiarFormBeneficio
                            }
                            style={
                              input
                            }
                          />
                        </Field>

                      )}

                    </div>


                    <Field
                      label="Motivo"
                    >
                      <textarea
                        name="motivo"
                        value={
                          formBeneficio
                            .motivo
                        }
                        onChange={
                          cambiarFormBeneficio
                        }
                        style={{
                          ...input,
                          minHeight:
                            "80px",
                          resize:
                            "vertical"
                        }}
                        placeholder="Ej. cortesía comercial, demostración, soporte..."
                      />
                    </Field>


                    <div
                      style={
                        modalActions
                      }
                    >

                      <button
                        type="button"
                        style={
                          secondaryButton
                        }
                        disabled={
                          procesandoOrganizacion
                        }
                        onClick={() =>
                          setAccionComercial(
                            null
                          )
                        }
                      >
                        Cancelar
                      </button>


                      <button
                        type="submit"
                        style={
                          primaryButton
                        }
                        disabled={
                          procesandoOrganizacion
                        }
                      >
                        {procesandoOrganizacion
                          ? "Procesando..."
                          : accionComercial ===
                            "cortesia"
                          ? "🎁 Otorgar cortesía"
                          : "🧪 Otorgar prueba"}
                      </button>

                    </div>

                  </form>

                )}

              </div>

            )}


            {/* =============================================
                LICENCIAS
            ============================================= */}

            {tabDetalleOrganizacion ===
              "licencias" && (

              <div
                style={
                  detailPanel
                }
              >

                <h3 style={detailPanelTitle}>
                  🎟️ Control de licencias
                </h3>


                <div
                  style={
                    detailGrid
                  }
                >

                  <InfoItem
                    label="Totales"
                    value={
                      detalleComercial
                        ?.resumen_licencias
                        ?.totales ??
                      licenciasOrganizacion
                        ?.licencias_totales ??
                      0
                    }
                  />


                  <InfoItem
                    label="Usadas"
                    value={
                      detalleComercial
                        ?.resumen_licencias
                        ?.usadas ??
                      licenciasOrganizacion
                        ?.licencias_usadas ??
                      0
                    }
                  />


                  <InfoItem
                    label="Disponibles"
                    value={
                      detalleComercial
                        ?.resumen_licencias
                        ?.disponibles ??
                      licenciasOrganizacion
                        ?.licencias_disponibles ??
                      0
                    }
                  />


                  <InfoItem
                    label="Suspendidas"
                    value={
                      detalleComercial
                        ?.resumen_licencias
                        ?.suspendidas ??
                      licenciasOrganizacion
                        ?.licencias_suspendidas ??
                      0
                    }
                  />


                  <InfoItem
                    label="Canceladas"
                    value={
                      detalleComercial
                        ?.resumen_licencias
                        ?.canceladas ??
                      0
                    }
                  />

                </div>


                {accionComercial ===
                  "licencias" && (

                  <div
                    style={
                      actionFormCard
                    }
                  >

                    <div
                      style={
                        actionFormHeader
                      }
                    >

                      <div>

                        <strong>
                          🎟️ Ajustar licencias contratadas
                        </strong>

                        <div
                          style={
                            actionFormSubtitle
                          }
                        >
                          No modifica la fecha de renovación.
                        </div>

                      </div>


                      <button
                        type="button"
                        style={
                          miniCloseButton
                        }
                        onClick={() =>
                          setAccionComercial(
                            null
                          )
                        }
                      >
                        ✕
                      </button>

                    </div>


                    <div
                      style={
                        licenseAdjustRow
                      }
                    >

                      <div
                        style={{
                          flex:
                            1
                        }}
                      >

                        <Field
                          label="Nuevo total de licencias"
                        >
                          <input
                            type="number"
                            min="1"
                            max="10000"
                            value={
                              licenciasAjuste
                            }
                            onChange={
                              e =>
                                setLicenciasAjuste(
                                  e.target.value
                                )
                            }
                            style={
                              input
                            }
                          />
                        </Field>

                      </div>


                      <button
                        type="button"
                        style={
                          primaryButton
                        }
                        disabled={
                          procesandoOrganizacion
                        }
                        onClick={
                          guardarAjusteLicencias
                        }
                      >
                        {procesandoOrganizacion
                          ? "Guardando..."
                          : "Guardar ajuste"}
                      </button>

                    </div>

                  </div>

                )}


                <div
                  style={
                    tableSection
                  }
                >

                  <div
                    style={
                      tableSectionTitle
                    }
                  >
                    Licencias individuales
                  </div>


                  {!detalleComercial
                    ?.licencias
                    ?.length ? (

                    <div
                      style={
                        emptyState
                      }
                    >
                      No hay licencias registradas.
                    </div>

                  ) : (

                    <div
                      style={
                        tableWrapper
                      }
                    >

                      <table
                        style={
                          table
                        }
                      >

                        <thead>
                          <tr>
                            <th style={th}>
                              ID
                            </th>

                            <th style={th}>
                              Estado
                            </th>

                            <th style={th}>
                              Usuario
                            </th>

                            <th style={th}>
                              Matrícula
                            </th>

                            <th style={th}>
                              Tipo
                            </th>
                          </tr>
                        </thead>


                        <tbody>

                          {detalleComercial
                            .licencias
                            .map(
                              licencia => (

                                <tr
                                  key={
                                    licencia.id_licencia
                                  }
                                >

                                  <td style={td}>
                                    #{licencia.id_licencia}
                                  </td>

                                  <td style={td}>
                                    {licencia.estado}
                                  </td>

                                  <td style={td}>
                                    {licencia.usuario_nombre ||
                                      "Disponible"}
                                  </td>

                                  <td style={td}>
                                    {licencia.usuario_matricula ||
                                      "—"}
                                  </td>

                                  <td style={td}>
                                    {licencia.tipo ||
                                      "—"}
                                  </td>

                                </tr>

                              )
                            )}

                        </tbody>

                      </table>

                    </div>

                  )}

                </div>

              </div>

            )}


            {/* =============================================
                USUARIOS
            ============================================= */}

            {tabDetalleOrganizacion ===
              "usuarios" && (

              <div
                style={
                  detailPanel
                }
              >

                <h3 style={detailPanelTitle}>
                  👥 Usuarios de la organización
                </h3>


                {!detalleComercial
                  ?.usuarios
                  ?.length ? (

                  <div
                    style={
                      emptyState
                    }
                  >
                    No hay usuarios registrados.
                  </div>

                ) : (

                  <div
                    style={
                      tableWrapper
                    }
                  >

                    <table
                      style={
                        table
                      }
                    >

                      <thead>
                        <tr>
                          <th style={th}>
                            Usuario
                          </th>

                          <th style={th}>
                            Acceso
                          </th>

                          <th style={th}>
                            Rol
                          </th>

                          <th style={th}>
                            Estado
                          </th>

                          <th style={th}>
                            Admin padre
                          </th>
                        </tr>
                      </thead>


                      <tbody>

                        {detalleComercial
                          .usuarios
                          .map(
                            usuario => (

                              <tr
                                key={
                                  usuario.id_usuario
                                }
                              >

                                <td style={td}>
                                  <strong>
                                    {usuario.nombre}
                                  </strong>

                                  <div style={smallMuted}>
                                    #{usuario.id_usuario}
                                  </div>
                                </td>

                                <td style={td}>
                                  {usuario.matricula ||
                                    usuario.correo ||
                                    "—"}
                                </td>

                                <td style={td}>
                                  {usuario.rol ||
                                    "—"}

                                  {usuario.tipo_admin
                                    ? ` / ${usuario.tipo_admin}`
                                    : ""}
                                </td>

                                <td style={td}>
                                  {usuario.estado ||
                                    "—"}
                                </td>

                                <td style={td}>
                                  {usuario.id_admin_padre ??
                                    "—"}
                                </td>

                              </tr>

                            )
                          )}

                      </tbody>

                    </table>

                  </div>

                )}

              </div>

            )}


            {/* =============================================
                PAGOS
            ============================================= */}

            {tabDetalleOrganizacion ===
              "pagos" && (

              <div
                style={
                  detailPanel
                }
              >

                <h3 style={detailPanelTitle}>
                  💰 Historial de pagos
                </h3>


                {!detalleComercial
                  ?.pagos
                  ?.length ? (

                  <div
                    style={
                      emptyState
                    }
                  >
                    Esta organización no tiene pagos registrados.
                  </div>

                ) : (

                  <div
                    style={
                      tableWrapper
                    }
                  >

                    <table
                      style={
                        table
                      }
                    >

                      <thead>
                        <tr>
                          <th style={th}>
                            ID
                          </th>

                          <th style={th}>
                            Plan
                          </th>

                          <th style={th}>
                            Monto
                          </th>

                          <th style={th}>
                            Periodo
                          </th>

                          <th style={th}>
                            Estado
                          </th>

                          <th style={th}>
                            Fecha
                          </th>
                        </tr>
                      </thead>


                      <tbody>

                        {detalleComercial
                          .pagos
                          .map(
                            pago => (

                              <tr
                                key={
                                  pago.id_pago
                                }
                              >

                                <td style={td}>
                                  #{pago.id_pago}
                                </td>

                                <td style={td}>
                                  {pago.plan_nombre ||
                                    "—"}
                                </td>

                                <td style={td}>
                                  {formatearPrecio(
                                    pago.monto
                                  )}
                                </td>

                                <td style={td}>
                                  {pago.periodo ||
                                    "—"}
                                </td>

                                <td style={td}>
                                  {pago.estado ||
                                    "—"}
                                </td>

                                <td style={td}>
                                  {formatearFecha(
                                    pago.fecha_pago ||
                                    pago.creado_en
                                  )}
                                </td>

                              </tr>

                            )
                          )}

                      </tbody>

                    </table>

                  </div>

                )}

              </div>

            )}


            {/* =============================================
                SOPORTE
            ============================================= */}

            {tabDetalleOrganizacion ===
              "soporte" && (

              <div
                style={
                  detailPanel
                }
              >

                <h3 style={detailPanelTitle}>
                  🛠️ Diagnóstico comercial
                </h3>


                <div
                  style={{
                    ...diagnosticBox,

                    ...(detalleComercial
                      ?.diagnostico
                      ?.correcto
                      ? diagnosticBoxOk
                      : diagnosticBoxWarning)
                  }}
                >

                  <div
                    style={
                      diagnosticTitle
                    }
                  >
                    {detalleComercial
                      ?.diagnostico
                      ?.correcto
                      ? "✅ La organización está consistente"
                      : "⚠️ Se detectaron inconsistencias"}
                  </div>


                  <div
                    style={
                      diagnosticText
                    }
                  >
                    {detalleComercial
                      ?.diagnostico
                      ?.correcto
                      ? "No se detectaron problemas entre organización, suscripción y licencias."
                      : `${detalleComercial
                          ?.diagnostico
                          ?.total_problemas ||
                        0} problema(s) requieren revisión.`}
                  </div>

                </div>


                {detalleComercial
                  ?.diagnostico
                  ?.problemas
                  ?.map(
                    (
                      problema,
                      index
                    ) => (

                      <div
                        key={
                          `${problema.codigo}-${index}`
                        }
                        style={
                          diagnosticProblem
                        }
                      >

                        <strong>
                          {problema.codigo}
                        </strong>

                        <div
                          style={
                            diagnosticText
                          }
                        >
                          {problema.mensaje}
                        </div>

                      </div>

                    )
                  )}

              </div>

            )}


            <div
              style={
                modalFooterStatus
              }
            >

              <span>
                {procesandoOrganizacion
                  ? "⏳ Procesando operación..."
                  : "🔐 Acciones disponibles solo para Administrador Master"}
              </span>

              <span>
                Organización #{organizacionSeleccionada.id_organizacion}
              </span>

            </div>

          </div>

        </div>

      )}


      {/* ==================================================
          MODAL PLAN
      ================================================== */}

      {mostrarModalPlan && (

        <div
          style={
            modalOverlay
          }
          onClick={() =>
            setMostrarModalPlan(
              false
            )
          }
        >

          <form
            style={
              modalLarge
            }
            onSubmit={
              guardarPlan
            }
            onClick={
              e =>
                e.stopPropagation()
            }
          >

            <div
              style={
                modalHeader
              }
            >

              <div>

                <h2
                  style={
                    modalTitle
                  }
                >
                  {planEditando
                    ? "✏️ Editar plan"
                    : "➕ Nuevo plan"}
                </h2>


                <p
                  style={
                    modalSubtitle
                  }
                >
                  Configuración comercial del plan.
                </p>

              </div>


              <button
                type="button"
                style={
                  closeButton
                }
                onClick={() =>
                  setMostrarModalPlan(
                    false
                  )
                }
              >
                ✕
              </button>

            </div>


            <div
              style={
                formGrid
              }
            >

              <Field
                label="Nombre"
              >
                <input
                  required
                  name="nombre"
                  value={
                    formPlan.nombre
                  }
                  onChange={
                    cambiarFormPlan
                  }
                  style={
                    input
                  }
                />
              </Field>


              <Field
                label="Código"
              >
                <input
                  required
                  name="codigo"
                  value={
                    formPlan.codigo
                  }
                  onChange={
                    cambiarFormPlan
                  }
                  style={
                    input
                  }
                />
              </Field>


              <Field
                label="Tipo"
              >
                <select
                  name="tipo"
                  value={
                    formPlan.tipo
                  }
                  onChange={
                    cambiarFormPlan
                  }
                  style={
                    input
                  }
                >
                  <option value="clinica">
                    Clínica
                  </option>

                  <option value="rh">
                    RH
                  </option>

                  <option value="educativo">
                    Educativo
                  </option>

                  <option value="psicologo">
                    Psicólogo
                  </option>

                  <option value="independiente">
                    Independiente
                  </option>
                </select>
              </Field>


              <Field
                label="Licencias incluidas"
              >
                <input
                  required
                  type="number"
                  min="1"
                  name="licencias_incluidas"
                  value={
                    formPlan
                      .licencias_incluidas
                  }
                  onChange={
                    cambiarFormPlan
                  }
                  style={
                    input
                  }
                />
              </Field>


              <Field
                label="Precio mensual"
              >
                <input
                  type="number"
                  min="0"
                  step="0.01"
                  name="precio_mensual"
                  value={
                    formPlan
                      .precio_mensual
                  }
                  onChange={
                    cambiarFormPlan
                  }
                  style={
                    input
                  }
                />
              </Field>


              <Field
                label="Precio anual"
              >
                <input
                  type="number"
                  min="0"
                  step="0.01"
                  name="precio_anual"
                  value={
                    formPlan
                      .precio_anual
                  }
                  onChange={
                    cambiarFormPlan
                  }
                  style={
                    input
                  }
                />
              </Field>


              <Field
                label="Días de prueba"
              >
                <input
                  type="number"
                  min="0"
                  name="periodo_prueba_dias"
                  value={
                    formPlan
                      .periodo_prueba_dias
                  }
                  onChange={
                    cambiarFormPlan
                  }
                  style={
                    input
                  }
                />
              </Field>


              <Field
                label="Máximo pacientes"
              >
                <input
                  type="number"
                  min="0"
                  name="max_pacientes"
                  value={
                    formPlan
                      .max_pacientes
                  }
                  onChange={
                    cambiarFormPlan
                  }
                  style={
                    input
                  }
                  placeholder="Sin límite"
                />
              </Field>


              <Field
                label="Permite administrador"
              >
                <select
                  name="permite_admin"
                  value={
                    formPlan
                      .permite_admin
                  }
                  onChange={
                    cambiarFormPlan
                  }
                  style={
                    input
                  }
                >
                  <option value={1}>
                    Sí
                  </option>

                  <option value={0}>
                    No
                  </option>
                </select>
              </Field>


              <Field
                label="Destacado"
              >
                <select
                  name="destacado"
                  value={
                    formPlan
                      .destacado
                  }
                  onChange={
                    cambiarFormPlan
                  }
                  style={
                    input
                  }
                >
                  <option value={0}>
                    No
                  </option>

                  <option value={1}>
                    Sí
                  </option>
                </select>
              </Field>


              <Field
                label="Estado"
              >
                <select
                  name="activo"
                  value={
                    formPlan.activo
                  }
                  onChange={
                    cambiarFormPlan
                  }
                  style={
                    input
                  }
                >
                  <option value={1}>
                    Activo
                  </option>

                  <option value={0}>
                    Inactivo
                  </option>
                </select>
              </Field>

            </div>


            <Field
              label="Descripción"
            >
              <textarea
                name="descripcion"
                value={
                  formPlan.descripcion
                }
                onChange={
                  cambiarFormPlan
                }
                style={{
                  ...input,
                  minHeight:
                    100,
                  resize:
                    "vertical"
                }}
              />
            </Field>


            <div
              style={
                modalActions
              }
            >

              <button
                type="button"
                style={
                  secondaryButton
                }
                onClick={() =>
                  setMostrarModalPlan(
                    false
                  )
                }
              >
                Cancelar
              </button>


              <button
                type="submit"
                style={
                  primaryButton
                }
                disabled={
                  guardandoPlan
                }
              >
                {guardandoPlan
                  ? "Guardando..."
                  : planEditando
                  ? "Guardar cambios"
                  : "Crear plan"}
              </button>

            </div>

          </form>

        </div>

      )}

    </div>

  );

};


// ==================================================
// TAB
// ==================================================

const TabButton = ({
  activo,
  onClick,
  children
}) => (

  <button
    type="button"
    onClick={
      onClick
    }
    style={{
      ...tabButton,

      ...(activo
        ? tabButtonActive
        : {})
    }}
  >
    {children}
  </button>

);


// ==================================================
// MÉTRICA
// ==================================================

const MetricCard = ({
  icon,
  label,
  value,
  detail
}) => (

  <div
    style={
      metricCard
    }
  >

    <div
      style={
        metricIcon
      }
    >
      {icon}
    </div>


    <div>

      <div
        style={
          metricLabel
        }
      >
        {label}
      </div>


      <div
        style={
          metricValue
        }
      >
        {value}
      </div>


      <div
        style={
          metricDetail
        }
      >
        {detail}
      </div>

    </div>

  </div>

);


// ==================================================
// TABLA ORGANIZACIONES
// ==================================================

const OrganizacionesTable = ({
  organizaciones,
  onOpen
}) => {

  if (
    !organizaciones.length
  ) {

    return (
      <div
        style={
          emptyState
        }
      >
        No hay organizaciones registradas.
      </div>
    );

  }


  return (

    <div
      style={
        tableWrapper
      }
    >

      <table
        style={
          table
        }
      >

        <thead>

          <tr>

            <th style={th}>
              Organización
            </th>

            <th style={th}>
              Tipo
            </th>

            <th style={th}>
              Estado
            </th>

            <th style={th}>
              Plan
            </th>

            <th style={th}>
              Suscripción
            </th>

            <th style={th}>
              Licencias
            </th>

            <th style={th}>
              Acción
            </th>

          </tr>

        </thead>


        <tbody>

          {organizaciones.map(
            item => (

              <tr
                key={
                  item
                    .id_organizacion
                }
              >

                <td style={td}>

                  <strong>
                    {
                      item.nombre
                    }
                  </strong>

                  <div
                    style={
                      smallMuted
                    }
                  >
                    {
                      item.correo ||
                      ""
                    }
                  </div>

                </td>


                <td style={td}>
                  {
                    item.tipo ||
                    "—"
                  }
                </td>


                <td style={td}>

                  <StatusBadge
                    activo={
                      String(
                        item.estado ||
                        ""
                      )
                        .toLowerCase() ===
                      "activa"
                    }
                    label={
                      item.estado
                    }
                  />

                </td>


                <td style={td}>
                  {
                    item.plan ||
                    item.plan_nombre ||
                    "—"
                  }
                </td>


                <td style={td}>
                  {
                    item
                      .estado_suscripcion ||
                    item
                      .suscripcion_estado ||
                    "—"
                  }
                </td>


                <td style={td}>
                  {
                    item
                      .licencias_totales ??
                    "—"
                  }
                </td>


                <td style={td}>

                  <button
                    type="button"
                    style={
                      smallButton
                    }
                    onClick={() =>
                      onOpen(
                        item
                      )
                    }
                  >
                    Ver detalle
                  </button>

                </td>

              </tr>

            )
          )}

        </tbody>

      </table>

    </div>

  );

};


// ==================================================
// INFO
// ==================================================

const InfoItem = ({
  label,
  value
}) => (

  <div
    style={
      infoItem
    }
  >

    <div
      style={
        infoLabel
      }
    >
      {label}
    </div>


    <div
      style={
        infoValue
      }
    >
      {
        value === null ||
        value === undefined ||
        value === ""
          ? "—"
          : value
      }
    </div>

  </div>

);


// ==================================================
// FIELD
// ==================================================

const Field = ({
  label,
  children
}) => (

  <label
    style={
      field
    }
  >

    <span
      style={
        fieldLabel
      }
    >
      {label}
    </span>

    {children}

  </label>

);


// ==================================================
// STATUS
// ==================================================

const StatusBadge = ({
  activo,
  label
}) => (

  <span
    style={{
      ...statusBadge,

      background:
        activo
          ? "#EAF8EE"
          : "#FDECEC",

      color:
        activo
          ? "#2F9B4A"
          : "#CB3B3B"
    }}
  >
    {label ||
      (
        activo
          ? "Activo"
          : "Inactivo"
      )}
  </span>

);


// ==================================================
// ESTILOS
// ==================================================

const page = {
  minHeight:
    "100vh",

  padding:
    "28px",

  background:
    "#F5F7FB",

  boxSizing:
    "border-box",

  fontFamily:
    "Inter, Arial, sans-serif",

  color:
    "#27304A"
};


const header = {
  display:
    "flex",

  alignItems:
    "flex-start",

  justifyContent:
    "space-between",

  gap:
    "20px",

  marginBottom:
    "24px"
};


const backButton = {
  border:
    "none",

  background:
    "transparent",

  color:
    "#65708A",

  fontSize:
    "14px",

  cursor:
    "pointer",

  padding:
    "0 0 10px"
};


const title = {
  margin:
    0,

  fontSize:
    "30px",

  color:
    "#30385A"
};


const subtitle = {
  margin:
    "8px 0 0",

  color:
    "#788198",

  lineHeight:
    1.5
};


const refreshButton = {
  border:
    "1px solid #D8DDEC",

  background:
    "#FFFFFF",

  color:
    "#4E5A78",

  borderRadius:
    "12px",

  padding:
    "11px 16px",

  cursor:
    "pointer",

  fontWeight:
    700
};


const tabs = {
  display:
    "flex",

  gap:
    "10px",

  flexWrap:
    "wrap",

  marginBottom:
    "22px"
};


const tabButton = {
  border:
    "1px solid #E0E4EF",

  background:
    "#FFFFFF",

  color:
    "#626D87",

  borderRadius:
    "12px",

  padding:
    "11px 18px",

  cursor:
    "pointer",

  fontWeight:
    700
};


const tabButtonActive = {
  background:
    "#7048E8",

  color:
    "#FFFFFF",

  borderColor:
    "#7048E8",

  boxShadow:
    "0 8px 18px rgba(112,72,232,.18)"
};


const metricsGrid = {
  display:
    "grid",

  gridTemplateColumns:
    "repeat(auto-fit, minmax(210px, 1fr))",

  gap:
    "18px",

  marginBottom:
    "24px"
};


const metricCard = {
  background:
    "#FFFFFF",

  borderRadius:
    "18px",

  padding:
    "20px",

  display:
    "flex",

  alignItems:
    "center",

  gap:
    "16px",

  boxShadow:
    "0 8px 22px rgba(65,80,120,.07)",

  border:
    "1px solid #EEF0F6"
};


const metricIcon = {
  width:
    "52px",

  height:
    "52px",

  borderRadius:
    "16px",

  background:
    "#F1EDFF",

  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  fontSize:
    "25px"
};


const metricLabel = {
  fontSize:
    "13px",

  color:
    "#7A849C",

  fontWeight:
    700
};


const metricValue = {
  fontSize:
    "27px",

  fontWeight:
    800,

  color:
    "#303852",

  margin:
    "4px 0"
};


const metricDetail = {
  fontSize:
    "12px",

  color:
    "#8991A6"
};


const sectionCard = {
  background:
    "#FFFFFF",

  border:
    "1px solid #EBEEF5",

  borderRadius:
    "18px",

  padding:
    "22px",

  boxShadow:
    "0 8px 24px rgba(65,80,120,.06)"
};


const sectionHeader = {
  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "space-between",

  gap:
    "18px",

  marginBottom:
    "18px"
};


const sectionTitle = {
  margin:
    0,

  fontSize:
    "21px",

  color:
    "#333C59"
};


const sectionDescription = {
  margin:
    "6px 0 0",

  color:
    "#81899E",

  fontSize:
    "14px"
};


const tableWrapper = {
  width:
    "100%",

  overflowX:
    "auto"
};


const table = {
  width:
    "100%",

  borderCollapse:
    "collapse",

  minWidth:
    "900px"
};


const th = {
  textAlign:
    "left",

  fontSize:
    "12px",

  textTransform:
    "uppercase",

  color:
    "#7E879E",

  padding:
    "12px",

  borderBottom:
    "1px solid #E7EAF2"
};


const td = {
  padding:
    "14px 12px",

  borderBottom:
    "1px solid #EFF1F6",

  fontSize:
    "14px",

  color:
    "#4B5572"
};


const smallMuted = {
  color:
    "#939BAE",

  fontSize:
    "12px",

  marginTop:
    "4px"
};


const statusBadge = {
  display:
    "inline-flex",

  alignItems:
    "center",

  borderRadius:
    "999px",

  padding:
    "5px 10px",

  fontSize:
    "12px",

  fontWeight:
    800,

  textTransform:
    "capitalize"
};


const smallButton = {
  border:
    "none",

  background:
    "#F0ECFF",

  color:
    "#6F49D7",

  borderRadius:
    "9px",

  padding:
    "8px 11px",

  cursor:
    "pointer",

  fontWeight:
    700
};


const primaryButton = {
  border:
    "none",

  background:
    "#7048E8",

  color:
    "#FFFFFF",

  borderRadius:
    "11px",

  padding:
    "11px 17px",

  cursor:
    "pointer",

  fontWeight:
    800
};


const secondaryButton = {
  border:
    "1px solid #D9DEEA",

  background:
    "#FFFFFF",

  color:
    "#59647F",

  borderRadius:
    "11px",

  padding:
    "10px 15px",

  cursor:
    "pointer",

  fontWeight:
    700
};


const dangerButton = {
  border:
    "none",

  background:
    "#FDEDED",

  color:
    "#C53A3A",

  borderRadius:
    "11px",

  padding:
    "10px 15px",

  cursor:
    "pointer",

  fontWeight:
    700
};


const activateButton = {
  border:
    "none",

  background:
    "#EAF8EE",

  color:
    "#2F9B4A",

  borderRadius:
    "11px",

  padding:
    "10px 15px",

  cursor:
    "pointer",

  fontWeight:
    700
};


const cardsPlans = {
  display:
    "grid",

  gridTemplateColumns:
    "repeat(auto-fit, minmax(290px, 1fr))",

  gap:
    "18px"
};


const planCard = {
  border:
    "1px solid #E8EBF3",

  borderRadius:
    "16px",

  padding:
    "18px",

  background:
    "#FCFCFE"
};


const planTop = {
  display:
    "flex",

  alignItems:
    "flex-start",

  justifyContent:
    "space-between",

  gap:
    "12px"
};


const planName = {
  fontSize:
    "18px",

  fontWeight:
    800,

  color:
    "#35405D"
};


const planCode = {
  marginTop:
    "4px",

  color:
    "#8A92A6",

  fontSize:
    "12px",

  fontFamily:
    "monospace"
};


const planType = {
  display:
    "inline-block",

  margin:
    "14px 0 6px",

  padding:
    "4px 8px",

  borderRadius:
    "8px",

  background:
    "#EAF1FF",

  color:
    "#3C6FD1",

  fontSize:
    "11px",

  fontWeight:
    800
};


const planDescription = {
  color:
    "#747D93",

  lineHeight:
    1.5,

  minHeight:
    "44px"
};


const planDataGrid = {
  display:
    "grid",

  gridTemplateColumns:
    "repeat(2, 1fr)",

  gap:
    "10px",

  margin:
    "16px 0"
};


const planActions = {
  display:
    "flex",

  gap:
    "10px",

  flexWrap:
    "wrap"
};


const infoItem = {
  background:
    "#F7F8FC",

  borderRadius:
    "11px",

  padding:
    "11px"
};


const infoLabel = {
  color:
    "#8A92A6",

  fontSize:
    "11px",

  fontWeight:
    700,

  textTransform:
    "uppercase"
};


const infoValue = {
  color:
    "#3D4660",

  fontSize:
    "14px",

  fontWeight:
    800,

  marginTop:
    "5px",

  wordBreak:
    "break-word"
};


const modalOverlay = {
  position:
    "fixed",

  inset:
    0,

  background:
    "rgba(31,37,56,.55)",

  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  padding:
    "22px",

  zIndex:
    9999,

  overflowY:
    "auto"
};


const modalLarge = {
  width:
    "min(900px, 100%)",

  maxHeight:
    "92vh",

  overflowY:
    "auto",

  background:
    "#FFFFFF",

  borderRadius:
    "20px",

  padding:
    "24px",

  boxShadow:
    "0 24px 60px rgba(15,20,40,.25)"
};


const modalHeader = {
  display:
    "flex",

  alignItems:
    "flex-start",

  justifyContent:
    "space-between",

  gap:
    "18px",

  marginBottom:
    "20px"
};


const modalTitle = {
  margin:
    0,

  color:
    "#333B57"
};


const modalSubtitle = {
  color:
    "#848DA3",

  margin:
    "6px 0 0"
};


const closeButton = {
  border:
    "none",

  background:
    "#F0F2F7",

  width:
    "36px",

  height:
    "36px",

  borderRadius:
    "50%",

  cursor:
    "pointer",

  color:
    "#616B83"
};


const detailGrid = {
  display:
    "grid",

  gridTemplateColumns:
    "repeat(auto-fit, minmax(170px, 1fr))",

  gap:
    "12px"
};


const detailSection = {
  marginTop:
    "22px",

  paddingTop:
    "18px",

  borderTop:
    "1px solid #ECEFF5"
};


const modalActions = {
  marginTop:
    "24px",

  display:
    "flex",

  justifyContent:
    "flex-end",

  gap:
    "10px",

  flexWrap:
    "wrap"
};


const modalControlCenter = {
  width:
    "min(1180px, 100%)",

  maxHeight:
    "94vh",

  overflowY:
    "auto",

  background:
    "#FFFFFF",

  borderRadius:
    "22px",

  padding:
    "24px",

  boxShadow:
    "0 28px 70px rgba(15,20,40,.28)"
};


const controlCenterEyebrow = {
  fontSize:
    "11px",

  fontWeight:
    900,

  letterSpacing:
    ".08em",

  color:
    "#7048E8",

  marginBottom:
    "7px"
};


const masterSummaryGrid = {
  display:
    "grid",

  gridTemplateColumns:
    "repeat(auto-fit, minmax(145px, 1fr))",

  gap:
    "10px",

  marginBottom:
    "18px"
};


const quickActionsSection = {
  background:
    "#F8F7FE",

  border:
    "1px solid #ECE8FB",

  borderRadius:
    "16px",

  padding:
    "15px",

  marginBottom:
    "18px"
};


const quickActionsTitle = {
  fontSize:
    "12px",

  fontWeight:
    900,

  color:
    "#555F78",

  marginBottom:
    "10px",

  textTransform:
    "uppercase",

  letterSpacing:
    ".04em"
};


const quickActionsGrid = {
  display:
    "grid",

  gridTemplateColumns:
    "repeat(auto-fit, minmax(160px, 1fr))",

  gap:
    "10px"
};


const masterActionButton = {
  border:
    "1px solid #E4E0F5",

  background:
    "#FFFFFF",

  borderRadius:
    "13px",

  padding:
    "12px",

  cursor:
    "pointer",

  display:
    "flex",

  alignItems:
    "center",

  gap:
    "10px",

  color:
    "#3E4761",

  textAlign:
    "left",

  minHeight:
    "66px"
};


const masterActionIcon = {
  fontSize:
    "22px",

  width:
    "30px",

  textAlign:
    "center"
};


const masterActionDescription = {
  display:
    "block",

  color:
    "#8B93A6",

  fontSize:
    "11px",

  fontWeight:
    600,

  marginTop:
    "3px"
};


const detailTabs = {
  display:
    "flex",

  gap:
    "8px",

  overflowX:
    "auto",

  paddingBottom:
    "8px",

  borderBottom:
    "1px solid #ECEFF5"
};


const detailTabButton = {
  border:
    "1px solid transparent",

  background:
    "transparent",

  color:
    "#7A839A",

  borderRadius:
    "10px",

  padding:
    "9px 12px",

  whiteSpace:
    "nowrap",

  cursor:
    "pointer",

  fontWeight:
    800,

  fontSize:
    "13px"
};


const detailTabButtonActive = {
  background:
    "#F0ECFF",

  color:
    "#6740D7",

  border:
    "1px solid #DED5FF"
};


const detailPanel = {
  padding:
    "20px 0 4px"
};


const detailPanelTitle = {
  margin:
    "0 0 14px",

  color:
    "#38425E",

  fontSize:
    "18px"
};


const actionFormCard = {
  marginTop:
    "18px",

  padding:
    "18px",

  borderRadius:
    "15px",

  border:
    "1px solid #E4DDFD",

  background:
    "#FAF9FF"
};


const actionFormHeader = {
  display:
    "flex",

  justifyContent:
    "space-between",

  alignItems:
    "flex-start",

  gap:
    "12px",

  marginBottom:
    "16px",

  color:
    "#414A66"
};


const actionFormSubtitle = {
  color:
    "#8B93A8",

  fontSize:
    "12px",

  marginTop:
    "4px"
};


const miniCloseButton = {
  border:
    "none",

  background:
    "#EEEAFB",

  color:
    "#6C5BA3",

  width:
    "30px",

  height:
    "30px",

  borderRadius:
    "50%",

  cursor:
    "pointer"
};


const licenseAdjustRow = {
  display:
    "flex",

  gap:
    "12px",

  alignItems:
    "flex-end",

  flexWrap:
    "wrap"
};


const tableSection = {
  marginTop:
    "20px"
};


const tableSectionTitle = {
  color:
    "#566079",

  fontSize:
    "13px",

  fontWeight:
    900,

  marginBottom:
    "10px",

  textTransform:
    "uppercase"
};


const diagnosticBox = {
  borderRadius:
    "14px",

  padding:
    "16px",

  border:
    "1px solid"
};


const diagnosticBoxOk = {
  background:
    "#F0FAF3",

  borderColor:
    "#CFECD7"
};


const diagnosticBoxWarning = {
  background:
    "#FFF8E8",

  borderColor:
    "#F0DCA6"
};


const diagnosticTitle = {
  fontWeight:
    900,

  color:
    "#3E4863",

  marginBottom:
    "5px"
};


const diagnosticText = {
  color:
    "#737D93",

  fontSize:
    "13px",

  lineHeight:
    1.5
};


const diagnosticProblem = {
  marginTop:
    "10px",

  border:
    "1px solid #F1D8D8",

  background:
    "#FFF7F7",

  borderRadius:
    "12px",

  padding:
    "12px",

  color:
    "#8F4848"
};


const modalFooterStatus = {
  marginTop:
    "18px",

  paddingTop:
    "14px",

  borderTop:
    "1px solid #ECEFF5",

  display:
    "flex",

  justifyContent:
    "space-between",

  gap:
    "12px",

  flexWrap:
    "wrap",

  color:
    "#929AAF",

  fontSize:
    "11px",

  fontWeight:
    700
};


const formGrid = {
  display:
    "grid",

  gridTemplateColumns:
    "repeat(auto-fit, minmax(230px, 1fr))",

  gap:
    "15px",

  marginBottom:
    "15px"
};


const field = {
  display:
    "flex",

  flexDirection:
    "column",

  gap:
    "6px"
};


const fieldLabel = {
  color:
    "#59637E",

  fontSize:
    "13px",

  fontWeight:
    800
};


const input = {
  border:
    "1px solid #DDE1EC",

  borderRadius:
    "10px",

  padding:
    "11px 12px",

  fontSize:
    "14px",

  outline:
    "none",

  background:
    "#FFFFFF",

  color:
    "#333C58"
};


const errorBox = {
  background:
    "#FDEEEE",

  border:
    "1px solid #F5CACA",

  color:
    "#B83939",

  padding:
    "12px 14px",

  borderRadius:
    "11px",

  marginBottom:
    "16px"
};


const successBox = {
  background:
    "#ECF9EF",

  border:
    "1px solid #C9ECD1",

  color:
    "#2D8C45",

  padding:
    "12px 14px",

  borderRadius:
    "11px",

  marginBottom:
    "16px"
};


const loadingBox = {
  background:
    "#FFFFFF",

  borderRadius:
    "15px",

  padding:
    "35px",

  textAlign:
    "center",

  color:
    "#7A849B",

  boxShadow:
    "0 8px 20px rgba(60,70,110,.06)"
};


const emptyState = {
  padding:
    "30px",

  textAlign:
    "center",

  color:
    "#8991A6"
};


const backupGrid = {
  display: "grid",
  gridTemplateColumns:
    "repeat(auto-fit, minmax(170px, 1fr))",
  gap: "12px",
  marginBottom: "18px"
};


const backupMessage = {
  padding: "14px 16px",
  borderRadius: "12px",
  background: "#F7F5FF",
  border: "1px solid #E3DDFB",
  color: "#5F557B",
  fontSize: "13px",
  lineHeight: 1.5
};


const accessDenied = {
  maxWidth:
    "480px",

  margin:
    "80px auto",

  padding:
    "36px",

  textAlign:
    "center",

  background:
    "#FFFFFF",

  borderRadius:
    "20px",

  boxShadow:
    "0 12px 30px rgba(60,70,110,.08)"
};


const bigIcon = {
  fontSize:
    "46px",

  marginBottom:
    "12px"
};


// ==================================================
// EXPORT
// ==================================================

export default AdminComercial;