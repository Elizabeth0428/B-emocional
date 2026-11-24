// ==================================================
// src/views/MisCanalizacionesPsicologo.jsx
// ==================================================

import React, {
  useEffect,
  useMemo,
  useState
} from "react";

import {
  useNavigate
} from "react-router-dom";

import {
  getToken
} from "../services/AuthService";

import RegistrarPaciente from "../components/RegistrarPaciente.jsx";


// ==================================================
// API
// ==================================================

const API_URL =
  import.meta.env.VITE_API_URL ||
  `${import.meta.env.VITE_API_URL || window.location.origin}`;


// ==================================================
// MOTIVOS DE RECHAZO
// ==================================================

const MOTIVOS_RECHAZO = [

  {
    value:
      "agenda_llena",

    label:
      "Agenda llena"
  },

  {
    value:
      "sin_disponibilidad_horario",

    label:
      "No tengo disponibilidad de horario"
  },

  {
    value:
      "no_atiende_caso",

    label:
      "No atiendo actualmente este tipo de caso"
  },

  {
    value:
      "periodo_ausencia",

    label:
      "Periodo de ausencia"
  },

  {
    value:
      "capacidad_maxima",

    label:
      "Capacidad máxima alcanzada"
  },

  {
    value:
      "otro",

    label:
      "Otro"
  }

];


// ==================================================
// ETIQUETAS
// ==================================================

const ETIQUETAS_ESTADO = {

  pendiente:
    "Pendiente de respuesta",

  aceptada:
    "Aceptada",

  rechazada:
    "Rechazada"

};


const ETIQUETAS_ORIGEN = {

  nom035:
    "NOM-035",

  estres_laboral:
    "Estrés laboral",

  otra_prueba:
    "Evaluación psicológica",

  entrevista_rh:
    "Entrevista RH",

  observacion_rh:
    "Observación RH"

};


// ==================================================
// FORMATEAR FECHA
// ==================================================

const formatearFecha =
  valor => {

    if (!valor) {
      return "Sin fecha";
    }


    const fecha =
      new Date(valor);


    if (
      Number.isNaN(
        fecha.getTime()
      )
    ) {

      return String(valor);

    }


    return fecha.toLocaleDateString(
      "es-MX",
      {
        day:
          "2-digit",

        month:
          "short",

        year:
          "numeric",

        hour:
          "2-digit",

        minute:
          "2-digit"
      }
    );

  };


// ==================================================
// CONTACTO DESPUÉS DE ACEPTAR
// ==================================================

const normalizarTelefonoWhatsApp =
  telefono => {

    const digitos =
      String(
        telefono || ""
      ).replace(
        /\D/g,
        ""
      );


    if (!digitos) {
      return "";
    }


    if (
      digitos.length === 10
    ) {
      return `52${digitos}`;
    }


    return digitos;
  };


const textoModalidad =
  valor => {

    const texto =
      String(
        valor || ""
      )
        .trim()
        .toLowerCase();


    if (
      texto === "presencial"
    ) {
      return "Presencial";
    }


    if (
      texto === "videollamada"
    ) {
      return "Videollamada";
    }


    if (
      texto === "indistinta"
    ) {
      return "Indistinta";
    }


    return valor ||
      "Por definir";
  };


// ==================================================
// COMPONENTE
// ==================================================

function MisCanalizacionesPsicologo() {

  const navigate =
    useNavigate();


  const token =
    getToken();


  // ==================================================
  // ESTADOS
  // ==================================================

  const [
    cargando,
    setCargando
  ] =
    useState(true);


  const [
    procesando,
    setProcesando
  ] =
    useState(false);


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
    canalizaciones,
    setCanalizaciones
  ] =
    useState([]);


  const [
    psicologo,
    setPsicologo
  ] =
    useState(null);


  const [
    filtro,
    setFiltro
  ] =
    useState(
      "pendiente"
    );


  const [
    modalRechazo,
    setModalRechazo
  ] =
    useState(null);


  const [
    motivoRechazo,
    setMotivoRechazo
  ] =
    useState("");


  const [
    observacionRechazo,
    setObservacionRechazo
  ] =
    useState("");


  const [
    estadoProfesional,
    setEstadoProfesional
  ] =
    useState(
      "disponible"
    );


  const [
    capacidadMaxima,
    setCapacidadMaxima
  ] =
    useState(
      ""
    );


  const [
    canalizacionParaPaciente,
    setCanalizacionParaPaciente
  ] =
    useState(null);


  // ==================================================
  // CARGAR CANALIZACIONES
  // ==================================================

  const cargarCanalizaciones =
    async () => {

      try {

        setCargando(
          true
        );

        setError("");


        if (!token) {

          throw new Error(
            "No se encontró una sesión válida."
          );

        }


        const respuesta =
          await fetch(
            `${API_URL}/api/psicologos/canalizaciones`,
            {

              headers: {

                Authorization:
                  `Bearer ${token}`

              }

            }
          );


        const data =
          await respuesta
            .json()
            .catch(
              () => ({})
            );


        if (
          !respuesta.ok
        ) {

          throw new Error(
            data?.message ||
            "No fue posible cargar las canalizaciones."
          );

        }


        setCanalizaciones(
          Array.isArray(
            data?.canalizaciones
          )
            ? data.canalizaciones
            : []
        );


        setPsicologo(
          data?.psicologo ||
          null
        );


      } catch (err) {

        console.error(
          "❌ Error cargando canalizaciones:",
          err
        );


        setError(
          err?.message ||
          "No fue posible cargar las canalizaciones."
        );


      } finally {

        setCargando(
          false
        );

      }

    };


  useEffect(
    () => {

      cargarCanalizaciones();

      // eslint-disable-next-line react-hooks/exhaustive-deps
    },
    []
  );


  // ==================================================
  // CONTADORES
  // ==================================================

  const resumen =
    useMemo(
      () => {

        const resultado = {

          pendiente:
            0,

          aceptada:
            0,

          rechazada:
            0,

          total:
            canalizaciones.length

        };


        canalizaciones
          .forEach(
            item => {

              const estado =
                item
                  ?.estado_respuesta_profesional ||
                "pendiente";


              if (
                estado ===
                "aceptada"
              ) {

                resultado
                  .aceptada +=
                  1;

              }

              else if (
                estado ===
                "rechazada"
              ) {

                resultado
                  .rechazada +=
                  1;

              }

              else {

                resultado
                  .pendiente +=
                  1;

              }

            }
          );


        return resultado;

      },
      [
        canalizaciones
      ]
    );


  // ==================================================
  // LISTADO FILTRADO
  // ==================================================

  const canalizacionesFiltradas =
    useMemo(
      () => {

        if (
          filtro ===
          "todas"
        ) {

          return canalizaciones;

        }


        return canalizaciones
          .filter(
            item => {

              const estado =
                item
                  ?.estado_respuesta_profesional ||
                "pendiente";


              return estado ===
                filtro;

            }
          );

      },
      [
        canalizaciones,
        filtro
      ]
    );


  // ==================================================
  // ACEPTAR CANALIZACIÓN
  // ==================================================

  const aceptarCanalizacion =
    async item => {

      const confirmar =
        window.confirm(
          `¿Deseas aceptar la canalización de ${item?.empleado_nombre || "este empleado"}?`
        );


      if (
        !confirmar
      ) {
        return;
      }


      try {

        setProcesando(
          true
        );

        setError("");
        setMensaje("");


        const respuesta =
          await fetch(
            `${API_URL}/api/psicologos/canalizaciones/${item.id_opcion}/aceptar`,
            {

              method:
                "PUT",

              headers: {

                "Content-Type":
                  "application/json",

                Authorization:
                  `Bearer ${token}`

              }

            }
          );


        const data =
          await respuesta
            .json()
            .catch(
              () => ({})
            );


        if (
          !respuesta.ok
        ) {

          throw new Error(
            data?.message ||
            "No fue posible aceptar la canalización."
          );

        }


        setMensaje(
          data?.message ||
          "Canalización aceptada correctamente."
        );


        await cargarCanalizaciones();


      } catch (err) {

        console.error(
          "❌ Error aceptando canalización:",
          err
        );


        setError(
          err?.message ||
          "No fue posible aceptar la canalización."
        );


      } finally {

        setProcesando(
          false
        );

      }

    };


  // ==================================================
  // ABRIR MODAL DE RECHAZO
  // ==================================================

  const abrirRechazo =
    item => {

      setModalRechazo(
        item
      );

      setMotivoRechazo(
        ""
      );

      setObservacionRechazo(
        ""
      );


      const capacidadActual =
        Number(
          psicologo
            ?.capacidad_maxima
        );


      const pacientesActivos =
        Number(
          psicologo
            ?.pacientes_activos
        ) || 0;


      setCapacidadMaxima(
        Number.isFinite(
          capacidadActual
        ) &&
        capacidadActual > 0
          ? String(
              capacidadActual
            )
          : ""
      );


      if (
        psicologo
          ?.pausa_temporal === 1 ||
        psicologo
          ?.pausa_temporal === true
      ) {

        setEstadoProfesional(
          "pausa_temporal"
        );

      }

      else if (
        Number.isFinite(
          capacidadActual
        ) &&
        capacidadActual > 0 &&
        pacientesActivos >=
          capacidadActual
      ) {

        setEstadoProfesional(
          "cupo_completo"
        );

      }

      else {

        setEstadoProfesional(
          "disponible"
        );

      }


      setError("");
      setMensaje("");

    };


  // ==================================================
  // CERRAR MODAL
  // ==================================================

  const cerrarModalRechazo =
    () => {

      if (
        procesando
      ) {
        return;
      }


      setModalRechazo(
        null
      );

      setMotivoRechazo(
        ""
      );

      setObservacionRechazo(
        ""
      );


      setEstadoProfesional(
        "disponible"
      );


      setCapacidadMaxima(
        ""
      );

    };


  // ==================================================
  // CONFIRMAR RECHAZO
  // ==================================================

  const confirmarRechazo =
    async () => {

      if (
        !modalRechazo
      ) {
        return;
      }


      const pacientesActivos =
        Number(
          psicologo
            ?.pacientes_activos
        ) || 0;


      const capacidadNumero =
        Number(
          capacidadMaxima
        );


      const capacidadValida =
        Number.isFinite(
          capacidadNumero
        ) &&
        capacidadNumero > 0
          ? capacidadNumero
          : null;


      const cuposDisponibles =
        capacidadValida
          ? Math.max(
              capacidadValida -
              pacientesActivos,
              0
            )
          : null;


      if (
        !motivoRechazo
      ) {

        setError(
          "Selecciona el motivo del rechazo."
        );

        return;

      }


      if (
        motivoRechazo ===
          "otro" &&
        !String(
          observacionRechazo ||
          ""
        ).trim()
      ) {

        setError(
          "Escribe el motivo del rechazo."
        );

        return;

      }


      if (
        capacidadMaxima &&
        !capacidadValida
      ) {

        setError(
          "La capacidad máxima debe ser mayor a 0."
        );

        return;

      }


      try {

        setProcesando(
          true
        );

        setError("");
        setMensaje("");


        const respuesta =
          await fetch(
            `${API_URL}/api/psicologos/canalizaciones/${modalRechazo.id_opcion}/rechazar`,
            {

              method:
                "PUT",

              headers: {

                "Content-Type":
                  "application/json",

                Authorization:
                  `Bearer ${token}`

              },

              body:
                JSON.stringify({

                  motivo_rechazo:
                    motivoRechazo,

                  observacion:
                    String(
                      observacionRechazo ||
                      ""
                    ).trim(),

                  estado_profesional:
                    estadoProfesional,

                  activo_canalizacion:
                    estadoProfesional ===
                      "disponible"
                      ? 1
                      : 0,

                  pausa_temporal:
                    estadoProfesional ===
                      "pausa_temporal"
                      ? 1
                      : 0,

                  capacidad_maxima:
                    capacidadValida,

                  pacientes_activos:
                    pacientesActivos,

                  cupos_disponibles:
                    cuposDisponibles

                })

            }
          );


        const data =
          await respuesta
            .json()
            .catch(
              () => ({})
            );


        if (
          !respuesta.ok
        ) {

          throw new Error(
            data?.message ||
            "No fue posible rechazar la canalización."
          );

        }


        setMensaje(
          data?.message ||
          "Canalización rechazada correctamente."
        );


        setModalRechazo(
          null
        );

        setMotivoRechazo(
          ""
        );

        setObservacionRechazo(
          ""
        );


        await cargarCanalizaciones();


      } catch (err) {

        console.error(
          "❌ Error rechazando canalización:",
          err
        );


        setError(
          err?.message ||
          "No fue posible rechazar la canalización."
        );


      } finally {

        setProcesando(
          false
        );

      }

    };


  // ==================================================
  // CONTACTAR DESPUÉS DE ACEPTAR
  // ==================================================

  const contactarWhatsApp =
    item => {

      if (
        item
          ?.estado_respuesta_profesional !==
          "aceptada" ||
        !item?.telefono
      ) {
        return;
      }


      const telefono =
        normalizarTelefonoWhatsApp(
          item.telefono
        );


      if (!telefono) {
        return;
      }


      const mensaje =
        [
          "Hola.",
          "",
          "Soy la profesional que aceptó tu canalización de apoyo.",
          "Me comunico contigo para coordinar el inicio de la atención."
        ].join("\n");


      window.open(
        `https://wa.me/${telefono}?text=${encodeURIComponent(mensaje)}`,
        "_blank",
        "noopener,noreferrer"
      );

    };


  const contactarCorreo =
    item => {

      if (
        item
          ?.estado_respuesta_profesional !==
          "aceptada" ||
        !item?.correo
      ) {
        return;
      }


      const asunto =
        "Contacto para coordinar tu atención";


      const cuerpo =
        [
          "Hola.",
          "",
          "Soy la profesional que aceptó tu canalización de apoyo.",
          "Me comunico contigo para coordinar el inicio de la atención."
        ].join("\n");


      window.location.href =
        `mailto:${item.correo}?subject=${encodeURIComponent(asunto)}&body=${encodeURIComponent(cuerpo)}`;

    };


  // ==================================================
  // INICIAR ATENCIÓN
  // ABRE FORMULARIO DE PACIENTE
  // ==================================================

  const iniciarAtencion =
    item => {

      if (
        item
          ?.estado_respuesta_profesional !==
        "aceptada"
      ) {

        setError(
          "Primero debes aceptar la canalización."
        );

        return;

      }


      setError("");
      setMensaje("");

      setCanalizacionParaPaciente(
        item
      );

    };


  const cerrarRegistroPaciente =
    () => {

      if (
        procesando
      ) {
        return;
      }

      setCanalizacionParaPaciente(
        null
      );

    };


  const pacienteCreadoDesdeCanalizacion =
    paciente => {

      setCanalizacionParaPaciente(
        null
      );

      if (
        paciente?.id_paciente
      ) {

        navigate(
          `/paciente/${paciente.id_paciente}`
        );

      }

      else {

        cargarCanalizaciones();

      }

    };


  // ==================================================
  // ESTILO DEL ESTADO
  // ==================================================

  const obtenerEstiloEstado =
    estado => {

      if (
        estado ===
        "aceptada"
      ) {

        return styles
          .estadoAceptada;

      }


      if (
        estado ===
        "rechazada"
      ) {

        return styles
          .estadoRechazada;

      }


      return styles
        .estadoPendiente;

    };


  // ==================================================
  // CARGANDO
  // ==================================================

  if (
    cargando
  ) {

    return (

      <div style={styles.page}>

        <div style={styles.loadingCard}>

          <div style={styles.loadingIcon}>
            📨
          </div>

          <h2>
            Canalizaciones recibidas
          </h2>

          <p>
            Cargando solicitudes...
          </p>

        </div>

      </div>

    );

  }


  // ==================================================
  // RENDER
  // ==================================================

  return (

    <div style={styles.page}>

      <div style={styles.container}>

        {/* ============================================
            CABECERA
        ============================================ */}

        <div style={styles.header}>

          <div>

            <button
              type="button"
              style={styles.backButton}
              onClick={
                () =>
                  navigate(
                    "/dashboard"
                  )
              }
            >
              ← Volver al dashboard
            </button>


            <h1 style={styles.title}>
              📨 Canalizaciones recibidas
            </h1>


            <p style={styles.subtitle}>
              Revisa las personas que te seleccionaron
              como profesional mediante una canalización
              de Recursos Humanos.
            </p>

          </div>


          {psicologo && (

            <div style={styles.psychologistBox}>

              <span style={styles.psychologistLabel}>
                Profesional
              </span>

              <strong style={styles.psychologistName}>
                {psicologo.nombre}
              </strong>

              <span style={styles.psychologistSpecialty}>
                {psicologo.especialidad ||
                  "Psicología"}
              </span>

            </div>

          )}

        </div>


        {/* ============================================
            MENSAJES
        ============================================ */}

        {error && (

          <div style={styles.errorBox}>
            ⚠️ {error}
          </div>

        )}


        {mensaje && (

          <div style={styles.successBox}>
            ✅ {mensaje}
          </div>

        )}


        {/* ============================================
            RESUMEN
        ============================================ */}

        <div style={styles.summaryGrid}>

          <ResumenCard
            icon="⏳"
            label="Pendientes"
            value={
              resumen.pendiente
            }
            active={
              filtro ===
              "pendiente"
            }
            onClick={
              () =>
                setFiltro(
                  "pendiente"
                )
            }
          />


          <ResumenCard
            icon="✅"
            label="Aceptadas"
            value={
              resumen.aceptada
            }
            active={
              filtro ===
              "aceptada"
            }
            onClick={
              () =>
                setFiltro(
                  "aceptada"
                )
            }
          />


          <ResumenCard
            icon="❌"
            label="Rechazadas"
            value={
              resumen.rechazada
            }
            active={
              filtro ===
              "rechazada"
            }
            onClick={
              () =>
                setFiltro(
                  "rechazada"
                )
            }
          />


          <ResumenCard
            icon="📋"
            label="Todas"
            value={
              resumen.total
            }
            active={
              filtro ===
              "todas"
            }
            onClick={
              () =>
                setFiltro(
                  "todas"
                )
            }
          />

        </div>


        {/* ============================================
            AVISO
        ============================================ */}

        <div style={styles.noticeBox}>

          <div style={styles.noticeIcon}>
            🔐
          </div>

          <div>

            <strong>
              Información inicial de canalización
            </strong>

            <p style={styles.noticeText}>
              Esta solicitud todavía no constituye un
              expediente clínico. Antes de aceptar solo
              se muestra la información necesaria para
              tomar la decisión. El teléfono y el correo
              se habilitan únicamente después de aceptar.
            </p>

          </div>

        </div>


        {/* ============================================
            LISTADO
        ============================================ */}

        <div style={styles.listHeader}>

          <div>

            <h2 style={styles.sectionTitle}>

              {filtro ===
              "pendiente"
                ? "Pendientes de respuesta"
                : filtro ===
                    "aceptada"
                  ? "Canalizaciones aceptadas"
                  : filtro ===
                      "rechazada"
                    ? "Canalizaciones rechazadas"
                    : "Todas las canalizaciones"}

            </h2>

            <span style={styles.resultCount}>

              {
                canalizacionesFiltradas
                  .length
              } solicitud{
                canalizacionesFiltradas
                  .length === 1
                  ? ""
                  : "es"
              }

            </span>

          </div>

        </div>


        {canalizacionesFiltradas
          .length === 0 ? (

          <div style={styles.emptyCard}>

            <div style={styles.emptyIcon}>
              📨
            </div>

            <h3>
              No hay canalizaciones en esta sección
            </h3>

            <p>
              Cuando un empleado te seleccione
              mediante Recursos Humanos,
              aparecerá aquí.
            </p>

          </div>

        ) : (

          <div style={styles.cardsList}>

            {canalizacionesFiltradas
              .map(
                item => {

                  const estado =
                    item
                      ?.estado_respuesta_profesional ||
                    "pendiente";


                  const aceptada =
                    estado ===
                    "aceptada";


                  return (

                    <div
                      key={
                        item.id_opcion
                      }
                      style={
                        styles
                          .requestCard
                      }
                    >

                      {/* ==============================
                          ENCABEZADO
                      ============================== */}

                      <div style={styles.requestTop}>

                        <div style={styles.employeeBlock}>

                          <div style={styles.employeeAvatar}>
                            👤
                          </div>


                          <div>

                            <h3 style={styles.employeeName}>
                              {
                                item
                                  .empleado_nombre ||
                                "Empleado"
                              }
                            </h3>

                          </div>

                        </div>


                        <span
                          style={{
                            ...styles.statusBadge,
                            ...obtenerEstiloEstado(
                              estado
                            )
                          }}
                        >
                          {
                            ETIQUETAS_ESTADO[
                              estado
                            ] ||
                            estado
                          }
                        </span>

                      </div>


                      {/* ==============================
                          MODALIDAD
                      ============================== */}

                      <div style={styles.dataGrid}>

                        <DataItem
                          label="Modalidad"
                          value={
                            textoModalidad(
                              item
                                .modalidad_atencion_preferida
                            )
                          }
                        />


                        {aceptada &&
                          item.telefono && (

                          <DataItem
                            label="Teléfono"
                            value={
                              item.telefono
                            }
                          />

                        )}


                        {aceptada &&
                          item.correo && (

                          <DataItem
                            label="Correo"
                            value={
                              item.correo
                            }
                          />

                        )}

                      </div>


                      {/* ==============================
                          MOTIVO DE CANALIZACIÓN
                      ============================== */}

                      <div style={styles.reasonBox}>

                        <span style={styles.reasonLabel}>
                          Motivo de canalización
                        </span>

                        <p style={styles.reasonText}>
                          {
                            item.motivo ||
                            "Sin motivo especificado"
                          }
                        </p>

                      </div>


                      {/* ==============================
                          RESPUESTA RECHAZADA
                      ============================== */}

                      {estado ===
                        "rechazada" && (

                        <div style={styles.rejectedInfo}>

                          <strong>
                            Motivo de rechazo:
                          </strong>

                          <span>
                            {
                              MOTIVOS_RECHAZO
                                .find(
                                  motivo =>
                                    motivo.value ===
                                    item
                                      .motivo_rechazo_profesional
                                )
                                ?.label ||
                              item
                                .motivo_rechazo_profesional ||
                              "No especificado"
                            }
                          </span>


                          {item
                            .observacion_respuesta_profesional && (

                            <p>
                              {
                                item
                                  .observacion_respuesta_profesional
                              }
                            </p>

                          )}


                          <small>
                            {
                              formatearFecha(
                                item
                                  .fecha_respuesta_profesional
                              )
                            }
                          </small>

                        </div>

                      )}


                      {/* ==============================
                          RESPUESTA ACEPTADA + CONTACTO
                      ============================== */}

                      {aceptada && (

                        <div style={styles.acceptedInfo}>

                          <strong>
                            ✅ Canalización aceptada
                          </strong>

                          <span>
                            Ya puedes comunicarte con la
                            persona para coordinar el
                            inicio de la atención.
                          </span>


                          <small>
                            {
                              formatearFecha(
                                item
                                  .fecha_respuesta_profesional
                              )
                            }
                          </small>


                          <div style={styles.contactActions}>

                            {item.telefono && (

                              <button
                                type="button"
                                style={styles.whatsappButton}
                                onClick={
                                  () =>
                                    contactarWhatsApp(
                                      item
                                    )
                                }
                              >
                                💬 Contactar por WhatsApp
                              </button>

                            )}


                            {item.correo && (

                              <button
                                type="button"
                                style={styles.emailButton}
                                onClick={
                                  () =>
                                    contactarCorreo(
                                      item
                                    )
                                }
                              >
                                ✉️ Enviar correo
                              </button>

                            )}

                          </div>


                          <div style={styles.startCareArea}>

                            <div style={styles.startCareText}>

                              <strong>
                                ¿Ya estableciste contacto?
                              </strong>

                              <span>
                                Cuando la persona confirme que desea
                                iniciar la atención, completa sus datos
                                antes de crear el expediente clínico.
                              </span>

                            </div>


                            <button
                              type="button"
                              style={styles.startCareButton}
                              disabled={procesando}
                              onClick={() => iniciarAtencion(item)}
                            >
                              {
                                procesando
                                  ? "Procesando..."
                                  : "👤 Iniciar atención"
                              }
                            </button>

                          </div>

                        </div>

                      )}


                      {/* ==============================
                          ACCIONES
                      ============================== */}

                      {estado ===
                        "pendiente" && (

                        <div style={styles.actions}>

                          <button
                            type="button"
                            style={styles.acceptButton}
                            disabled={
                              procesando
                            }
                            onClick={
                              () =>
                                aceptarCanalizacion(
                                  item
                                )
                            }
                          >
                            ✓ Aceptar canalización
                          </button>


                          <button
                            type="button"
                            style={styles.rejectButton}
                            disabled={
                              procesando
                            }
                            onClick={
                              () =>
                                abrirRechazo(
                                  item
                                )
                            }
                          >
                            ✕ Rechazar
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


      {/* ============================================
          MODAL REGISTRAR PACIENTE
      ============================================ */}

      {canalizacionParaPaciente && (

        <div
          style={styles.overlay}
          onClick={
            cerrarRegistroPaciente
          }
        >

          <div
            style={styles.patientModal}
            onClick={
              e =>
                e.stopPropagation()
            }
          >

            <RegistrarPaciente
              desdeCanalizacion
              idCanalizacion={
                canalizacionParaPaciente
                  .id_canalizacion
              }
              datosIniciales={{
                nombre:
                  canalizacionParaPaciente
                    .empleado_nombre ||
                  "",
                correo:
                  canalizacionParaPaciente
                    .correo ||
                  "",
                telefono:
                  canalizacionParaPaciente
                    .telefono ||
                  ""
              }}
              onBack={
                cerrarRegistroPaciente
              }
              onComplete={
                pacienteCreadoDesdeCanalizacion
              }
            />

          </div>

        </div>

      )}


      {/* ============================================
          MODAL RECHAZO
      ============================================ */}

      {modalRechazo && (

        <div
          style={styles.overlay}
          onClick={
            cerrarModalRechazo
          }
        >

          <div
            style={styles.modal}
            onClick={
              e =>
                e.stopPropagation()
            }
          >

            <button
              type="button"
              style={styles.modalClose}
              onClick={
                cerrarModalRechazo
              }
              disabled={
                procesando
              }
            >
              ×
            </button>


            <div style={styles.modalIcon}>
              ❌
            </div>


            <h2 style={styles.modalTitle}>
              Rechazar canalización
            </h2>


            <p style={styles.modalDescription}>
              Indica por qué no puedes atender a{" "}
              <strong>
                {
                  modalRechazo
                    ?.empleado_nombre ||
                  "esta persona"
                }
              </strong>
              .
            </p>


            <label style={styles.label}>
              Motivo del rechazo *
            </label>


            <select
              style={styles.select}
              value={
                motivoRechazo
              }
              onChange={
                e => {

                  setMotivoRechazo(
                    e.target.value
                  );

                  setError("");

                }
              }
              disabled={
                procesando
              }
            >

              <option value="">
                Selecciona un motivo
              </option>


              {MOTIVOS_RECHAZO
                .map(
                  motivo => (

                    <option
                      key={
                        motivo.value
                      }
                      value={
                        motivo.value
                      }
                    >
                      {
                        motivo.label
                      }
                    </option>

                  )
                )}

            </select>


            <label style={styles.label}>
              Observación
              {motivoRechazo ===
                "otro"
                ? " *"
                : " opcional"}
            </label>


            <textarea
              style={styles.textarea}
              value={
                observacionRechazo
              }
              onChange={
                e =>
                  setObservacionRechazo(
                    e.target.value
                  )
              }
              placeholder="Puedes agregar información adicional..."
              disabled={
                procesando
              }
              rows={5}
            />


            {/* ============================================
                DISPONIBILIDAD PROFESIONAL
            ============================================ */}

            <div style={styles.availabilityBox}>

              <div style={styles.availabilityHeader}>

                <div>

                  <strong style={styles.availabilityTitle}>
                    Disponibilidad profesional
                  </strong>

                  <p style={styles.availabilityDescription}>
                    Actualiza tu estado para que el sistema sepa
                    si puedes recibir nuevas canalizaciones.
                  </p>

                </div>

              </div>


              <label style={styles.label}>
                Estado profesional
              </label>


              <select
                style={styles.select}
                value={
                  estadoProfesional
                }
                onChange={
                  e =>
                    setEstadoProfesional(
                      e.target.value
                    )
                }
                disabled={
                  procesando
                }
              >

                <option value="disponible">
                  Disponible
                </option>

                <option value="cupo_completo">
                  Cupo completo
                </option>

                <option value="pausa_temporal">
                  Pausa temporal
                </option>

                <option value="no_disponible">
                  No disponible temporalmente
                </option>

              </select>


              <label style={styles.label}>
                Capacidad máxima de pacientes
              </label>


              <input
                type="number"
                min="1"
                step="1"
                style={styles.input}
                value={
                  capacidadMaxima
                }
                onChange={
                  e =>
                    setCapacidadMaxima(
                      e.target.value
                    )
                }
                placeholder="Ej. 15"
                disabled={
                  procesando
                }
              />


              <div style={styles.capacityGrid}>

                <div style={styles.capacityItem}>

                  <span style={styles.capacityLabel}>
                    Pacientes activos
                  </span>

                  <strong style={styles.capacityValue}>
                    {
                      Number(
                        psicologo
                          ?.pacientes_activos
                      ) || 0
                    }
                  </strong>

                </div>


                <div style={styles.capacityItem}>

                  <span style={styles.capacityLabel}>
                    Cupos disponibles
                  </span>

                  <strong style={styles.capacityValue}>
                    {
                      capacidadMaxima
                        ? Math.max(
                            Number(
                              capacidadMaxima
                            ) -
                            (
                              Number(
                                psicologo
                                  ?.pacientes_activos
                              ) || 0
                            ),
                            0
                          )
                        : "—"
                    }
                  </strong>

                </div>

              </div>


              <div style={styles.availabilityHint}>

                {
                  estadoProfesional ===
                    "disponible"
                    ? "✅ Tu perfil podrá seguir apareciendo en nuevas canalizaciones si tienes cupo."
                    : estadoProfesional ===
                        "cupo_completo"
                      ? "⛔ Tu perfil no deberá aparecer en nuevas canalizaciones hasta liberar cupo."
                      : estadoProfesional ===
                          "pausa_temporal"
                        ? "⏸ Tu perfil quedará en pausa temporal para nuevas canalizaciones."
                        : "⚠️ Tu perfil quedará temporalmente fuera de nuevas canalizaciones."
                }

              </div>

            </div>


            {/* ============================================
                INFORMACIÓN DEL RECHAZO
            ============================================ */}

            <div style={styles.modalNotice}>

              <strong>
                ¿Qué ocurrirá?
              </strong>

              <p>
                Recursos Humanos será informado
                de que esta canalización necesita
                nuevas opciones de profesionales.
                El empleado podrá seleccionar otra
                opción cuando RH vuelva a enviarlas.
              </p>

            </div>


            <div style={styles.modalActions}>

              <button
                type="button"
                style={styles.cancelButton}
                onClick={
                  cerrarModalRechazo
                }
                disabled={
                  procesando
                }
              >
                Cancelar
              </button>


              <button
                type="button"
                style={styles.confirmRejectButton}
                onClick={
                  confirmarRechazo
                }
                disabled={
                  procesando
                }
              >
                {
                  procesando
                    ? "Procesando..."
                    : "Confirmar rechazo"
                }
              </button>

            </div>

          </div>

        </div>

      )}

    </div>

  );

}


// ==================================================
// RESUMEN CARD
// ==================================================

const ResumenCard = ({
  icon,
  label,
  value,
  active,
  onClick
}) => {

  return (

    <button
      type="button"
      onClick={
        onClick
      }
      style={{
        ...styles.summaryCard,
        ...(active
          ? styles
              .summaryCardActive
          : {})
      }}
    >

      <div style={styles.summaryIcon}>
        {icon}
      </div>

      <div>

        <div style={styles.summaryValue}>
          {value}
        </div>

        <div style={styles.summaryLabel}>
          {label}
        </div>

      </div>

    </button>

  );

};


// ==================================================
// DATA ITEM
// ==================================================

const DataItem = ({
  label,
  value
}) => {

  return (

    <div style={styles.dataItem}>

      <span style={styles.dataLabel}>
        {label}
      </span>

      <strong style={styles.dataValue}>
        {value || "—"}
      </strong>

    </div>

  );

};


// ==================================================
// ESTILOS
// ==================================================

const styles = {

  // ==================================================
  // PÁGINA GENERAL
  // ==================================================

  page: {minHeight:"100vh",background:"#F4F9FE",padding:"40px 6% 70px",boxSizing:"border-box",fontFamily:"'Segoe UI',Arial,sans-serif",color:"#1A2B4B"},
  container: {maxWidth:"1250px",margin:"0 auto"},


  // ==================================================
  // CABECERA
  // ==================================================

  header: {display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:"25px",marginBottom:"30px",flexWrap:"wrap"},
  backButton: {appearance:"none",WebkitAppearance:"none",display:"inline-flex",alignItems:"center",justifyContent:"center",minHeight:"44px",padding:"11px 22px",marginBottom:"18px",border:"none",borderRadius:"999px",background:"linear-gradient(135deg,#64B5F6,#1976D2)",color:"#ffffff",cursor:"pointer",fontWeight:"700",fontSize:"15px",boxShadow:"0 5px 14px rgba(25,118,210,.22)"},
  title: {margin:"0 0 8px",fontSize:"34px",color:"#19355E"},
  subtitle: {margin:0,maxWidth:"720px",lineHeight:1.65,color:"#60708D",fontSize:"16px"},
  psychologistBox: {minWidth:"220px",background:"#FFFFFF",border:"1px solid #E2EAF6",borderRadius:"18px",padding:"18px 20px",boxShadow:"0 8px 22px rgba(32,71,123,.08)"},
  psychologistLabel: {display:"block",color:"#8491A8",fontSize:"12px",textTransform:"uppercase",fontWeight:"700",marginBottom:"5px"},
  psychologistName: {display:"block",color:"#234A80",fontSize:"17px",marginBottom:"4px"},
  psychologistSpecialty: {color:"#66758E",fontSize:"13px"},


  // ==================================================
  // MENSAJES
  // ==================================================

  errorBox: {background:"#FFF0F0",border:"1px solid #F5B8B8",color:"#B52A2A",padding:"14px 18px",borderRadius:"14px",marginBottom:"18px",fontWeight:"600"},
  successBox: {background:"#ECF9EF",border:"1px solid #BCE8C5",color:"#28763A",padding:"14px 18px",borderRadius:"14px",marginBottom:"18px",fontWeight:"600"},


  // ==================================================
  // TARJETAS DE RESUMEN
  // ==================================================

  summaryGrid: {display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(190px,1fr))",gap:"16px",marginBottom:"26px"},
  summaryCard: {display:"flex",alignItems:"center",gap:"14px",width:"100%",padding:"18px",background:"#FFFFFF",border:"2px solid transparent",borderRadius:"18px",cursor:"pointer",boxShadow:"0 6px 18px rgba(40,80,140,.07)",textAlign:"left"},
  summaryCardActive: {borderColor:"#4A7FF5",boxShadow:"0 8px 24px rgba(74,127,245,.16)"},
  summaryIcon: {width:"46px",height:"46px",display:"flex",alignItems:"center",justifyContent:"center",borderRadius:"14px",background:"#EEF4FF",fontSize:"22px"},
  summaryValue: {fontSize:"26px",fontWeight:"800",color:"#213F71"},
  summaryLabel: {marginTop:"2px",color:"#72809A",fontSize:"14px",fontWeight:"600"},


  // ==================================================
  // AVISO DE PRIVACIDAD
  // ==================================================

  noticeBox: {display:"flex",alignItems:"flex-start",gap:"15px",padding:"18px",background:"#EFF7FF",border:"1px solid #CCE4FB",borderRadius:"18px",marginBottom:"28px"},
  noticeIcon: {fontSize:"25px"},
  noticeText: {margin:"5px 0 0",color:"#56708D",lineHeight:1.55},


  // ==================================================
  // LISTADO DE CANALIZACIONES
  // ==================================================

  listHeader: {display:"flex",justifyContent:"space-between",alignItems:"center",marginBottom:"18px"},
  sectionTitle: {margin:"0 0 4px",fontSize:"23px",color:"#203F6F"},
  resultCount: {color:"#8390A6",fontSize:"14px"},
  cardsList: {display:"grid",gap:"20px"},


  // ==================================================
  // TARJETA DE CANALIZACIÓN
  // ==================================================

  requestCard: {background:"#FFFFFF",border:"1px solid #E0E8F4",borderRadius:"22px",padding:"24px",boxShadow:"0 9px 26px rgba(40,80,140,.08)"},
  requestTop: {display:"flex",justifyContent:"space-between",alignItems:"center",gap:"15px",flexWrap:"wrap",paddingBottom:"18px",borderBottom:"1px solid #EDF1F7"},
  employeeBlock: {display:"flex",alignItems:"center",gap:"13px"},
  employeeAvatar: {width:"50px",height:"50px",display:"flex",alignItems:"center",justifyContent:"center",borderRadius:"15px",background:"#EEF4FF",fontSize:"24px"},
  employeeName: {margin:"0 0 4px",color:"#203F6F",fontSize:"19px"},


  // ==================================================
  // ESTADOS DE CANALIZACIÓN
  // ==================================================

  statusBadge: {display:"inline-flex",alignItems:"center",justifyContent:"center",padding:"8px 13px",borderRadius:"999px",fontSize:"13px",fontWeight:"700"},
  estadoPendiente: {background:"#FFF6DD",color:"#A16A00"},
  estadoAceptada: {background:"#EAF8ED",color:"#2E7A3D"},
  estadoRechazada: {background:"#FFF0F0",color:"#B33131"},


  // ==================================================
  // DATOS DE LA CANALIZACIÓN
  // ==================================================

  dataGrid: {display:"grid",gridTemplateColumns:"repeat(auto-fit,minmax(190px,1fr))",gap:"14px",marginTop:"20px"},
  dataItem: {padding:"14px",background:"#F8FAFD",border:"1px solid #EDF1F6",borderRadius:"14px"},
  dataLabel: {display:"block",marginBottom:"6px",color:"#8995AA",fontSize:"12px",fontWeight:"700",textTransform:"uppercase"},
  dataValue: {color:"#334A6D",fontSize:"14px"},
  reasonBox: {marginTop:"18px",padding:"16px",background:"#F6F2FF",border:"1px solid #E1D5FF",borderRadius:"15px"},
  reasonLabel: {display:"block",color:"#7655B8",fontWeight:"700",marginBottom:"6px",fontSize:"13px"},
  reasonText: {margin:0,color:"#5E5870",lineHeight:1.5},


  // ==================================================
  // BOTONES ACEPTAR / RECHAZAR
  // ==================================================

  actions: {display:"flex",gap:"12px",flexWrap:"wrap",marginTop:"22px",paddingTop:"18px",borderTop:"1px solid #EDF1F7"},
  acceptButton: {border:"none",borderRadius:"12px",padding:"12px 20px",background:"#45B95C",color:"#FFFFFF",fontWeight:"700",cursor:"pointer",fontSize:"14px"},
  rejectButton: {border:"1px solid #E36565",borderRadius:"12px",padding:"12px 20px",background:"#FFFFFF",color:"#C73B3B",fontWeight:"700",cursor:"pointer",fontSize:"14px"},


  // ==================================================
  // INFORMACIÓN DE RESPUESTA
  // ==================================================

  rejectedInfo: {display:"flex",flexDirection:"column",gap:"6px",marginTop:"20px",padding:"16px",background:"#FFF5F5",border:"1px solid #F4CACA",borderRadius:"15px",color:"#9D3636"},
  acceptedInfo: {display:"flex",flexDirection:"column",gap:"6px",marginTop:"20px",padding:"16px",background:"#F0FAF2",border:"1px solid #CBEAD1",borderRadius:"15px",color:"#347745"},


  // ==================================================
  // BOTONES DE CONTACTO
  // ==================================================

  contactActions: {display:"flex",gap:"10px",flexWrap:"wrap",marginTop:"12px"},
  whatsappButton: {border:"none",borderRadius:"12px",padding:"11px 16px",background:"#25D366",color:"#FFFFFF",fontWeight:"700",cursor:"pointer",fontSize:"14px"},
  emailButton: {border:"1px solid #4A7FF5",borderRadius:"12px",padding:"11px 16px",background:"#FFFFFF",color:"#315FC5",fontWeight:"700",cursor:"pointer",fontSize:"14px"},


  // ==================================================
  // INICIAR ATENCIÓN
  // ==================================================

  startCareArea: {marginTop:"18px",paddingTop:"18px",borderTop:"1px solid #CBEAD1",display:"flex",alignItems:"center",justifyContent:"space-between",gap:"16px",flexWrap:"wrap"},
  startCareText: {display:"flex",flexDirection:"column",gap:"4px",flex:"1 1 320px",color:"#3C6847"},
  startCareButton: {border:"none",borderRadius:"12px",padding:"12px 20px",background:"#1E7A4D",color:"#FFFFFF",fontWeight:"700",cursor:"pointer",fontSize:"14px"},


  // ==================================================
  // ESTADOS VACÍOS / CARGA
  // ==================================================

  emptyCard: {textAlign:"center",padding:"55px 25px",background:"#FFFFFF",border:"1px dashed #CFD9E8",borderRadius:"22px",color:"#687892"},
  emptyIcon: {fontSize:"46px",marginBottom:"12px"},
  loadingCard: {width:"min(460px,90%)",margin:"100px auto",background:"#FFFFFF",borderRadius:"22px",padding:"45px",textAlign:"center",boxShadow:"0 10px 30px rgba(40,80,140,.10)",color:"#536681"},
  loadingIcon: {fontSize:"50px",marginBottom:"15px"},


  // ==================================================
  // OVERLAY Y MODALES
  // ==================================================

  overlay: {position:"fixed",inset:0,background:"rgba(21,35,58,.55)",display:"flex",alignItems:"center",justifyContent:"center",zIndex:9999,padding:"20px"},
  modal: {position:"relative",width:"min(620px,100%)",maxHeight:"92vh",overflowY:"auto",background:"#FFFFFF",borderRadius:"24px",padding:"30px",boxSizing:"border-box",boxShadow:"0 20px 60px rgba(10,30,60,.25)"},
  patientModal: {position:"relative",width:"min(950px,100%)",maxHeight:"94vh",overflowY:"auto",background:"#F4F9FE",borderRadius:"24px",padding:"18px",boxSizing:"border-box",boxShadow:"0 24px 70px rgba(10,30,60,.28)"},
  modalClose: {position:"absolute",top:"14px",right:"16px",width:"36px",height:"36px",border:"none",borderRadius:"50%",background:"#F2F4F8",color:"#55657D",cursor:"pointer",fontSize:"22px"},
  modalIcon: {fontSize:"40px",marginBottom:"10px"},
  modalTitle: {margin:"0 0 8px",color:"#253F68",fontSize:"25px"},
  modalDescription: {margin:"0 0 22px",color:"#66758E",lineHeight:1.5},


  // ==================================================
  // CAMPOS DEL MODAL
  // ==================================================

  label: {display:"block",margin:"16px 0 7px",fontWeight:"700",color:"#405573",fontSize:"14px"},
  select: {width:"100%",height:"46px",border:"1px solid #CBD6E5",borderRadius:"11px",padding:"0 12px",fontSize:"14px",color:"#344A69",background:"#FFFFFF",boxSizing:"border-box"},
  input: {width:"100%",height:"46px",border:"1px solid #CBD6E5",borderRadius:"11px",padding:"0 12px",fontSize:"14px",color:"#344A69",background:"#FFFFFF",boxSizing:"border-box"},
  textarea: {width:"100%",border:"1px solid #CBD6E5",borderRadius:"11px",padding:"12px",fontSize:"14px",fontFamily:"inherit",resize:"vertical",boxSizing:"border-box",color:"#344A69"},


  // ==================================================
  // DISPONIBILIDAD Y CAPACIDAD PROFESIONAL
  // ==================================================

  availabilityBox: {marginTop:"22px",padding:"18px",background:"#F7FAFF",border:"1px solid #DCE7F5",borderRadius:"16px"},
  availabilityHeader: {display:"flex",justifyContent:"space-between",alignItems:"flex-start",gap:"12px"},
  availabilityTitle: {display:"block",color:"#284D7E",fontSize:"15px"},
  availabilityDescription: {margin:"5px 0 0",color:"#6C7E96",fontSize:"13px",lineHeight:1.5},
  capacityGrid: {display:"grid",gridTemplateColumns:"repeat(2,minmax(0,1fr))",gap:"12px",marginTop:"16px"},
  capacityItem: {padding:"13px 14px",background:"#FFFFFF",border:"1px solid #E2EAF4",borderRadius:"12px"},
  capacityLabel: {display:"block",marginBottom:"4px",color:"#8491A7",fontSize:"12px",fontWeight:"700",textTransform:"uppercase"},
  capacityValue: {color:"#29476F",fontSize:"20px"},
  availabilityHint: {marginTop:"14px",padding:"11px 12px",background:"#FFFFFF",border:"1px dashed #CCD9E9",borderRadius:"11px",color:"#5A6E89",fontSize:"13px",lineHeight:1.5},


  // ==================================================
  // AVISO DEL RECHAZO
  // ==================================================

  modalNotice: {marginTop:"18px",padding:"14px",background:"#FFF8E9",border:"1px solid #F1DFAF",borderRadius:"13px",color:"#7F682D",lineHeight:1.5},


  // ==================================================
  // BOTONES DEL MODAL
  // ==================================================

  modalActions: {display:"flex",justifyContent:"flex-end",gap:"10px",marginTop:"24px",flexWrap:"wrap"},
  cancelButton: {border:"1px solid #C9D3E1",background:"#FFFFFF",color:"#53657F",padding:"11px 18px",borderRadius:"11px",cursor:"pointer",fontWeight:"700"},
  confirmRejectButton: {border:"none",background:"#D84A4A",color:"#FFFFFF",padding:"11px 18px",borderRadius:"11px",cursor:"pointer",fontWeight:"700"}

};


export default MisCanalizacionesPsicologo;