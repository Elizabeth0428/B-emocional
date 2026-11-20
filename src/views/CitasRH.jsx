import React, {
  useEffect,
  useMemo,
  useState
} from "react";

import axios
from "axios";

import {
  getToken
} from "../services/AuthService";


// ==================================================
// API
// ==================================================

const API_URL =
  import.meta.env.VITE_API_URL ||
  `http://${window.location.hostname}:5000`;


// ==================================================
// FORMULARIO INICIAL
// ==================================================

const formularioInicial = {
  titulo: "",
  tipo_actividad: "actividad",
  fecha: "",
  hora_inicio: "",
  hora_fin: "",
  descripcion: "",
  ubicacion: "",
  enlace: "",
  persona_relacionada: "",
  recordatorio_activo: 0,
  minutos_recordatorio: 30,
  estado: "pendiente"
};


// ==================================================
// TIPOS
// ==================================================

const tiposActividad = [
  {
    value: "actividad",
    label: "Actividad",
    icon: "📌"
  },
  {
    value: "entrevista",
    label: "Entrevista",
    icon: "👤"
  },
  {
    value: "reunion",
    label: "Reunión",
    icon: "👥"
  },
  {
    value: "llamada",
    label: "Llamada",
    icon: "📞"
  },
  {
    value: "seguimiento",
    label: "Seguimiento",
    icon: "🔁"
  },
  {
    value: "evaluacion",
    label: "Evaluación",
    icon: "🧪"
  },
  {
    value: "recordatorio",
    label: "Recordatorio",
    icon: "⏰"
  },
  {
    value: "otro",
    label: "Otro",
    icon: "📝"
  }
];


const diasSemana = [
  "Lun",
  "Mar",
  "Mié",
  "Jue",
  "Vie",
  "Sáb",
  "Dom"
];


// ==================================================
// AUXILIARES
// ==================================================

const obtenerTipo =
  tipo =>
    tiposActividad.find(
      item =>
        item.value === tipo
    ) || {
      label: "Actividad",
      icon: "📌"
    };


const fechaInput =
  valor => {

    if (!valor) {
      return "";
    }

    return String(valor)
      .slice(0, 10);
  };


const formatearHora =
  valor => {

    if (!valor) {
      return "";
    }

    return String(valor)
      .slice(0, 5);
  };


const formatearFecha =
  valor => {

    if (!valor) {
      return "";
    }

    const fecha =
      new Date(
        `${fechaInput(valor)}T12:00:00`
      );

    if (
      Number.isNaN(
        fecha.getTime()
      )
    ) {
      return valor;
    }

    return fecha.toLocaleDateString(
      "es-MX",
      {
        weekday: "long",
        day: "numeric",
        month: "long",
        year: "numeric"
      }
    );
  };


const crearFechaLocal =
  (
    year,
    month,
    day
  ) => {

    const fecha =
      new Date(
        year,
        month,
        day,
        12,
        0,
        0,
        0
      );

    return fecha;
  };


const fechaAString =
  fecha => {

    const year =
      fecha.getFullYear();

    const month =
      String(
        fecha.getMonth() + 1
      ).padStart(
        2,
        "0"
      );

    const day =
      String(
        fecha.getDate()
      ).padStart(
        2,
        "0"
      );

    return `${year}-${month}-${day}`;
  };


const nombreMes =
  fecha => {

    const texto =
      fecha.toLocaleDateString(
        "es-MX",
        {
          month: "long",
          year: "numeric"
        }
      );

    return (
      texto
        .charAt(0)
        .toUpperCase() +
      texto.slice(1)
    );
  };


const esMismaFecha =
  (
    fechaA,
    fechaB
  ) => {

    return (
      fechaInput(
        fechaA
      ) ===
      fechaInput(
        fechaB
      )
    );
  };


// ==================================================
// COMPONENTE
// ==================================================

export default function CitasRH({
  onBack
}) {

  // ==================================================
  // ESTADOS
  // ==================================================

  const [
    actividades,
    setActividades
  ] = useState([]);


  const [
    cargando,
    setCargando
  ] = useState(true);


  const [
    guardando,
    setGuardando
  ] = useState(false);


  const [
    error,
    setError
  ] = useState("");


  const [
    mensaje,
    setMensaje
  ] = useState("");


  const [
    mostrarFormulario,
    setMostrarFormulario
  ] = useState(false);


  const [
    editando,
    setEditando
  ] = useState(null);


  const [
    formulario,
    setFormulario
  ] = useState({
    ...formularioInicial
  });


  const [
    filtroEstado,
    setFiltroEstado
  ] = useState("todos");


  const [
    filtroTipo,
    setFiltroTipo
  ] = useState("todos");


  const [
    filtroFecha,
    setFiltroFecha
  ] = useState("");


  const [
    mesActual,
    setMesActual
  ] = useState(
    () => {

      const hoy =
        new Date();

      return crearFechaLocal(
        hoy.getFullYear(),
        hoy.getMonth(),
        1
      );
    }
  );


  const [
    fechaSeleccionada,
    setFechaSeleccionada
  ] = useState(
    fechaAString(
      new Date()
    )
  );


  // ==================================================
  // CARGAR AGENDA
  // ==================================================

  const cargarAgenda =
    async () => {

      try {

        setCargando(
          true
        );

        setError("");

        const token =
          getToken();

        if (!token) {

          setError(
            "Tu sesión no es válida."
          );

          return;
        }


        const {
          data
        } =
          await axios.get(
            `${API_URL}/api/agenda-rh`,
            {
              headers: {
                Authorization:
                  `Bearer ${token}`
              }
            }
          );


        setActividades(
          Array.isArray(
            data?.actividades
          )
            ? data.actividades
            : []
        );

      } catch (err) {

        console.error(
          "❌ Error cargando Agenda RH:",
          err
        );

        setError(
          err.response
            ?.data
            ?.message ||
          "No fue posible cargar la agenda."
        );

      } finally {

        setCargando(
          false
        );

      }
    };


  useEffect(
    () => {

      cargarAgenda();

    },
    []
  );


  // ==================================================
  // RESUMEN
  // ==================================================

  const resumen =
    useMemo(
      () => {

        return {

          total:
            actividades.length,

          pendientes:
            actividades.filter(
              item =>
                item.estado ===
                "pendiente"
            ).length,

          realizadas:
            actividades.filter(
              item =>
                item.estado ===
                "realizado"
            ).length,

          canceladas:
            actividades.filter(
              item =>
                item.estado ===
                "cancelado"
            ).length

        };

      },
      [
        actividades
      ]
    );


  // ==================================================
  // CALENDARIO
  // ==================================================

  const diasCalendario =
    useMemo(
      () => {

        const year =
          mesActual
            .getFullYear();

        const month =
          mesActual
            .getMonth();


        const primerDia =
          crearFechaLocal(
            year,
            month,
            1
          );


        const diaSemanaJS =
          primerDia
            .getDay();


        const desplazamiento =
          diaSemanaJS === 0
            ? 6
            : diaSemanaJS - 1;


        const inicio =
          crearFechaLocal(
            year,
            month,
            1 -
              desplazamiento
          );


        const dias =
          [];


        for (
          let i = 0;
          i < 42;
          i++
        ) {

          const fecha =
            crearFechaLocal(
              inicio.getFullYear(),
              inicio.getMonth(),
              inicio.getDate() +
                i
            );


          const fechaTexto =
            fechaAString(
              fecha
            );


          const eventos =
            actividades
              .filter(
                actividad =>
                  esMismaFecha(
                    actividad.fecha,
                    fechaTexto
                  )
              )
              .sort(
                (
                  a,
                  b
                ) => {

                  const horaA =
                    formatearHora(
                      a.hora_inicio
                    ) ||
                    "99:99";

                  const horaB =
                    formatearHora(
                      b.hora_inicio
                    ) ||
                    "99:99";

                  return horaA
                    .localeCompare(
                      horaB
                    );
                }
              );


          dias.push({

            fecha,

            fechaTexto,

            esMesActual:
              fecha.getMonth() ===
              month,

            eventos

          });

        }


        return dias;

      },
      [
        mesActual,
        actividades
      ]
    );


  // ==================================================
  // FILTROS
  // ==================================================

  const actividadesFiltradas =
    useMemo(
      () => {

        return actividades.filter(
          actividad => {

            if (
              filtroEstado !==
                "todos" &&
              actividad.estado !==
                filtroEstado
            ) {
              return false;
            }


            if (
              filtroTipo !==
                "todos" &&
              actividad
                .tipo_actividad !==
                filtroTipo
            ) {
              return false;
            }


            if (
              filtroFecha &&
              fechaInput(
                actividad.fecha
              ) !==
                filtroFecha
            ) {
              return false;
            }


            return true;

          }
        );

      },
      [
        actividades,
        filtroEstado,
        filtroTipo,
        filtroFecha
      ]
    );


  // ==================================================
  // ACTIVIDADES DEL DÍA SELECCIONADO
  // ==================================================

  const actividadesDia =
    useMemo(
      () => {

        if (
          !fechaSeleccionada
        ) {
          return [];
        }


        return actividades
          .filter(
            actividad =>
              fechaInput(
                actividad.fecha
              ) ===
              fechaSeleccionada
          )
          .sort(
            (
              a,
              b
            ) => {

              const horaA =
                formatearHora(
                  a.hora_inicio
                ) ||
                "99:99";

              const horaB =
                formatearHora(
                  b.hora_inicio
                ) ||
                "99:99";

              return horaA
                .localeCompare(
                  horaB
                );

            }
          );

      },
      [
        actividades,
        fechaSeleccionada
      ]
    );


  // ==================================================
  // CAMBIAR FORMULARIO
  // ==================================================

  const cambiar =
    e => {

      const {
        name,
        value,
        type,
        checked
      } =
        e.target;


      setFormulario(
        anterior => ({
          ...anterior,

          [name]:
            type ===
            "checkbox"
              ? checked
                ? 1
                : 0
              : value
        })
      );

    };


  // ==================================================
  // NUEVA ACTIVIDAD
  // ==================================================

  const nuevaActividad =
    (
      fecha =
        ""
    ) => {

      setEditando(
        null
      );


      setFormulario({

        ...formularioInicial,

        fecha:
          fecha ||
          fechaSeleccionada ||
          fechaAString(
            new Date()
          )

      });


      setError("");
      setMensaje("");


      setMostrarFormulario(
        true
      );

    };


  // ==================================================
  // SELECCIONAR DÍA
  // ==================================================

  const seleccionarDia =
    dia => {

      setFechaSeleccionada(
        dia.fechaTexto
      );


      if (
        !dia.esMesActual
      ) {

        setMesActual(
          crearFechaLocal(
            dia.fecha
              .getFullYear(),

            dia.fecha
              .getMonth(),

            1
          )
        );

      }

    };


  // ==================================================
  // DOBLE CLIC DÍA = NUEVA ACTIVIDAD
  // ==================================================

  const agregarEnDia =
    dia => {

      setFechaSeleccionada(
        dia.fechaTexto
      );

      nuevaActividad(
        dia.fechaTexto
      );

    };


  // ==================================================
  // MES ANTERIOR
  // ==================================================

  const mesAnterior =
    () => {

      setMesActual(
        anterior =>
          crearFechaLocal(
            anterior
              .getFullYear(),

            anterior
              .getMonth() -
              1,

            1
          )
      );

    };


  // ==================================================
  // MES SIGUIENTE
  // ==================================================

  const mesSiguiente =
    () => {

      setMesActual(
        anterior =>
          crearFechaLocal(
            anterior
              .getFullYear(),

            anterior
              .getMonth() +
              1,

            1
          )
      );

    };


  // ==================================================
  // IR A HOY
  // ==================================================

  const irHoy =
    () => {

      const hoy =
        new Date();


      setMesActual(
        crearFechaLocal(
          hoy.getFullYear(),
          hoy.getMonth(),
          1
        )
      );


      setFechaSeleccionada(
        fechaAString(
          hoy
        )
      );

    };


  // ==================================================
  // EDITAR
  // ==================================================

  const editarActividad =
    actividad => {

      setEditando(
        actividad.id_agenda
      );


      setFormulario({

        titulo:
          actividad.titulo ||
          "",

        tipo_actividad:
          actividad
            .tipo_actividad ||
          "actividad",

        fecha:
          fechaInput(
            actividad.fecha
          ),

        hora_inicio:
          formatearHora(
            actividad
              .hora_inicio
          ),

        hora_fin:
          formatearHora(
            actividad
              .hora_fin
          ),

        descripcion:
          actividad.descripcion ||
          "",

        ubicacion:
          actividad.ubicacion ||
          "",

        enlace:
          actividad.enlace ||
          "",

        persona_relacionada:
          actividad
            .persona_relacionada ||
          "",

        recordatorio_activo:
          Number(
            actividad
              .recordatorio_activo
          ) === 1
            ? 1
            : 0,

        minutos_recordatorio:
          actividad
            .minutos_recordatorio ||
          30,

        estado:
          actividad.estado ||
          "pendiente"

      });


      setError("");
      setMensaje("");


      setMostrarFormulario(
        true
      );

    };


  // ==================================================
  // CERRAR FORMULARIO
  // ==================================================

  const cerrarFormulario =
    () => {

      setMostrarFormulario(
        false
      );

      setEditando(
        null
      );

      setFormulario({
        ...formularioInicial
      });

    };


  // ==================================================
  // GUARDAR
  // ==================================================

  const guardarActividad =
    async e => {

      e.preventDefault();


      if (
        !formulario
          .titulo
          .trim()
      ) {

        setError(
          "Escribe el título de la actividad."
        );

        return;
      }


      if (
        !formulario.fecha
      ) {

        setError(
          "Selecciona una fecha."
        );

        return;
      }


      if (
        formulario
          .hora_inicio &&
        formulario
          .hora_fin &&
        formulario
          .hora_fin <
          formulario
            .hora_inicio
      ) {

        setError(
          "La hora de término no puede ser anterior a la hora de inicio."
        );

        return;
      }


      try {

        setGuardando(
          true
        );

        setError("");
        setMensaje("");


        const token =
          getToken();


        if (!token) {

          setError(
            "Tu sesión no es válida."
          );

          return;
        }


        const payload = {

          titulo:
            formulario
              .titulo
              .trim(),

          tipo_actividad:
            formulario
              .tipo_actividad,

          fecha:
            formulario.fecha,

          hora_inicio:
            formulario
              .hora_inicio ||
            null,

          hora_fin:
            formulario
              .hora_fin ||
            null,

          descripcion:
            formulario
              .descripcion
              .trim() ||
            null,

          ubicacion:
            formulario
              .ubicacion
              .trim() ||
            null,

          enlace:
            formulario
              .enlace
              .trim() ||
            null,

          persona_relacionada:
            formulario
              .persona_relacionada
              .trim() ||
            null,

          recordatorio_activo:
            Number(
              formulario
                .recordatorio_activo
            ) === 1
              ? 1
              : 0,

          minutos_recordatorio:
            Number(
              formulario
                .recordatorio_activo
            ) === 1
              ? Number(
                  formulario
                    .minutos_recordatorio
                ) ||
                30
              : null,

          estado:
            formulario.estado

        };


        if (
          editando
        ) {

          await axios.put(

            `${API_URL}/api/agenda-rh/${editando}`,

            payload,

            {
              headers: {
                Authorization:
                  `Bearer ${token}`
              }
            }

          );


          setMensaje(
            "Actividad actualizada correctamente."
          );

        } else {

          await axios.post(

            `${API_URL}/api/agenda-rh`,

            payload,

            {
              headers: {
                Authorization:
                  `Bearer ${token}`
              }
            }

          );


          setMensaje(
            "Actividad registrada correctamente."
          );

        }


        setFechaSeleccionada(
          formulario.fecha
        );


        const fechaGuardada =
          new Date(
            `${formulario.fecha}T12:00:00`
          );


        setMesActual(
          crearFechaLocal(
            fechaGuardada
              .getFullYear(),

            fechaGuardada
              .getMonth(),

            1
          )
        );


        cerrarFormulario();

        await cargarAgenda();

      } catch (err) {

        console.error(
          "❌ Error guardando actividad:",
          err
        );


        setError(
          err.response
            ?.data
            ?.message ||
          "No fue posible guardar la actividad."
        );

      } finally {

        setGuardando(
          false
        );

      }

    };


  // ==================================================
  // CAMBIAR ESTADO
  // ==================================================

  const cambiarEstado =
    async (
      actividad,
      nuevoEstado
    ) => {

      try {

        setError("");

        const token =
          getToken();


        await axios.put(

          `${API_URL}/api/agenda-rh/${actividad.id_agenda}`,

          {

            titulo:
              actividad.titulo,

            tipo_actividad:
              actividad
                .tipo_actividad,

            fecha:
              fechaInput(
                actividad.fecha
              ),

            hora_inicio:
              formatearHora(
                actividad
                  .hora_inicio
              ) ||
              null,

            hora_fin:
              formatearHora(
                actividad
                  .hora_fin
              ) ||
              null,

            descripcion:
              actividad
                .descripcion ||
              null,

            ubicacion:
              actividad
                .ubicacion ||
              null,

            enlace:
              actividad
                .enlace ||
              null,

            persona_relacionada:
              actividad
                .persona_relacionada ||
              null,

            recordatorio_activo:
              Number(
                actividad
                  .recordatorio_activo
              ) === 1
                ? 1
                : 0,

            minutos_recordatorio:
              actividad
                .minutos_recordatorio ||
              null,

            estado:
              nuevoEstado

          },

          {
            headers: {
              Authorization:
                `Bearer ${token}`
            }
          }

        );


        setMensaje(
          nuevoEstado ===
          "realizado"
            ? "Actividad marcada como realizada."
            : nuevoEstado ===
              "cancelado"
            ? "Actividad cancelada."
            : "Actividad actualizada."
        );


        await cargarAgenda();

      } catch (err) {

        console.error(
          "❌ Error cambiando estado:",
          err
        );


        setError(
          err.response
            ?.data
            ?.message ||
          "No fue posible actualizar el estado."
        );

      }

    };


  // ==================================================
  // ELIMINAR
  // ==================================================

  const eliminarActividad =
    async actividad => {

      const confirmar =
        window.confirm(
          `¿Eliminar la actividad "${actividad.titulo}"?`
        );


      if (
        !confirmar
      ) {
        return;
      }


      try {

        setError("");

        const token =
          getToken();


        await axios.delete(

          `${API_URL}/api/agenda-rh/${actividad.id_agenda}`,

          {
            headers: {
              Authorization:
                `Bearer ${token}`
            }
          }

        );


        setMensaje(
          "Actividad eliminada correctamente."
        );


        await cargarAgenda();

      } catch (err) {

        console.error(
          "❌ Error eliminando actividad:",
          err
        );


        setError(
          err.response
            ?.data
            ?.message ||
          "No fue posible eliminar la actividad."
        );

      }

    };


  // ==================================================
  // RENDER
  // ==================================================

  return (
    <div style={styles.page}>

      <div style={styles.container}>

        {/* ============================================
            ENCABEZADO
        ============================================ */}

        <section style={styles.header}>

          <div>

            <button
              type="button"
              style={styles.backButton}
              onClick={
                onBack
              }
            >
              ← Volver
            </button>


            <div style={styles.headerBadge}>
              📅 Recursos Humanos
            </div>


            <h1 style={styles.title}>
              Agenda RH
            </h1>


            <p style={styles.subtitle}>
              Organiza entrevistas,
              reuniones, llamadas,
              seguimientos,
              evaluaciones,
              recordatorios y otras
              actividades de Recursos
              Humanos.
            </p>

          </div>


          <button
            type="button"
            style={styles.newButton}
            onClick={() =>
              nuevaActividad()
            }
          >
            + Nueva actividad
          </button>

        </section>


        {/* ============================================
            MENSAJES
        ============================================ */}

        {error && (
          <div style={styles.errorBox}>
            {error}
          </div>
        )}


        {mensaje && (
          <div style={styles.successBox}>
            {mensaje}
          </div>
        )}


        {/* ============================================
            RESUMEN
        ============================================ */}

        <section style={styles.statsGrid}>

          <StatCard
            icon="📅"
            label="Total"
            value={
              resumen.total
            }
          />

          <StatCard
            icon="⏳"
            label="Pendientes"
            value={
              resumen.pendientes
            }
          />

          <StatCard
            icon="✅"
            label="Realizadas"
            value={
              resumen.realizadas
            }
          />

          <StatCard
            icon="🚫"
            label="Canceladas"
            value={
              resumen.canceladas
            }
          />

        </section>


        {/* ============================================
            CALENDARIO
        ============================================ */}

        <section style={styles.calendarCard}>

          <div style={styles.calendarHeader}>

            <div>

              <div style={styles.calendarSmallTitle}>
                Calendario
              </div>

              <h2 style={styles.calendarTitle}>
                {nombreMes(
                  mesActual
                )}
              </h2>

            </div>


            <div style={styles.calendarControls}>

              <button
                type="button"
                style={styles.todayButton}
                onClick={
                  irHoy
                }
              >
                Hoy
              </button>


              <button
                type="button"
                style={styles.monthButton}
                onClick={
                  mesAnterior
                }
                title="Mes anterior"
              >
                ‹
              </button>


              <button
                type="button"
                style={styles.monthButton}
                onClick={
                  mesSiguiente
                }
                title="Mes siguiente"
              >
                ›
              </button>

            </div>

          </div>


          <div style={styles.calendarScroll}>

            <div style={styles.calendarGrid}>

              {diasSemana.map(
                dia => (
                  <div
                    key={
                      dia
                    }
                    style={styles.weekDay}
                  >
                    {dia}
                  </div>
                )
              )}


              {diasCalendario.map(
                dia => {

                  const hoy =
                    fechaAString(
                      new Date()
                    );


                  const seleccionado =
                    fechaSeleccionada ===
                    dia.fechaTexto;


                  const esHoy =
                    hoy ===
                    dia.fechaTexto;


                  return (

                    <div
                      key={
                        dia.fechaTexto
                      }
                      role="button"
                      tabIndex={0}
                      style={{
                        ...styles.dayCell,

                        ...(
                          !dia.esMesActual
                            ? styles.dayOtherMonth
                            : {}
                        ),

                        ...(
                          seleccionado
                            ? styles.daySelected
                            : {}
                        )
                      }}
                      onClick={() =>
                        seleccionarDia(
                          dia
                        )
                      }
                      onDoubleClick={() =>
                        agregarEnDia(
                          dia
                        )
                      }
                    >

                      <div style={styles.dayTop}>

                        <span
                          style={{
                            ...styles.dayNumber,

                            ...(
                              esHoy
                                ? styles.todayNumber
                                : {}
                            )
                          }}
                        >
                          {
                            dia.fecha
                              .getDate()
                          }
                        </span>


                        {dia.eventos.length >
                          0 && (

                          <span style={styles.dayCount}>
                            {
                              dia.eventos
                                .length
                            }
                          </span>

                        )}

                      </div>


                      <div style={styles.dayEvents}>

                        {dia.eventos
                          .slice(
                            0,
                            3
                          )
                          .map(
                            actividad => {

                              const tipo =
                                obtenerTipo(
                                  actividad
                                    .tipo_actividad
                                );


                              return (

                                <button
                                  type="button"
                                  key={
                                    actividad
                                      .id_agenda
                                  }
                                  title={
                                    actividad.titulo
                                  }
                                  style={{
                                    ...styles.calendarEvent,

                                    ...(
                                      actividad.estado ===
                                      "realizado"
                                        ? styles.calendarEventDone
                                        : {}
                                    ),

                                    ...(
                                      actividad.estado ===
                                      "cancelado"
                                        ? styles.calendarEventCancelled
                                        : {}
                                    )
                                  }}
                                  onClick={
                                    e => {

                                      e.stopPropagation();

                                      editarActividad(
                                        actividad
                                      );

                                    }
                                  }
                                >

                                  <span>
                                    {
                                      tipo.icon
                                    }
                                  </span>


                                  <span style={styles.calendarEventText}>

                                    {actividad
                                      .hora_inicio && (
                                      <>
                                        {formatearHora(
                                          actividad
                                            .hora_inicio
                                        )}{" "}
                                      </>
                                    )}

                                    {
                                      actividad
                                        .titulo
                                    }

                                  </span>

                                </button>

                              );

                            }
                          )}


                        {dia.eventos.length >
                          3 && (

                          <div style={styles.moreEvents}>
                            +
                            {
                              dia.eventos
                                .length -
                              3
                            }{" "}
                            más
                          </div>

                        )}

                      </div>


                      <button
                        type="button"
                        title="Agregar actividad"
                        style={styles.dayAddButton}
                        onClick={
                          e => {

                            e.stopPropagation();

                            agregarEnDia(
                              dia
                            );

                          }
                        }
                      >
                        +
                      </button>

                    </div>

                  );

                }
              )}

            </div>

          </div>


          <div style={styles.calendarHelp}>
            💡 Haz clic en un día para
            seleccionarlo. Usa el botón
            <strong> + </strong>
            dentro del día para registrar
            una actividad.
          </div>

        </section>


        {/* ============================================
            ACTIVIDADES DÍA SELECCIONADO
        ============================================ */}

        <section style={styles.selectedDayCard}>

          <div style={styles.selectedDayHeader}>

            <div>

              <div style={styles.calendarSmallTitle}>
                Día seleccionado
              </div>


              <h3 style={styles.selectedDayTitle}>
                {fechaSeleccionada
                  ? formatearFecha(
                      fechaSeleccionada
                    )
                  : "Selecciona una fecha"}
              </h3>

            </div>


            <button
              type="button"
              style={styles.smallNewButton}
              onClick={() =>
                nuevaActividad(
                  fechaSeleccionada
                )
              }
            >
              + Agregar
            </button>

          </div>


          {actividadesDia.length ===
          0 ? (

            <div style={styles.noDayEvents}>
              No hay actividades registradas
              para este día.
            </div>

          ) : (

            <div style={styles.dayAgendaList}>

              {actividadesDia.map(
                actividad => {

                  const tipo =
                    obtenerTipo(
                      actividad
                        .tipo_actividad
                    );


                  return (

                    <button
                      type="button"
                      key={
                        actividad.id_agenda
                      }
                      style={styles.dayAgendaItem}
                      onClick={() =>
                        editarActividad(
                          actividad
                        )
                      }
                    >

                      <div style={styles.dayAgendaTime}>
                        {formatearHora(
                          actividad.hora_inicio
                        ) ||
                          "Todo el día"}
                      </div>


                      <div style={styles.dayAgendaIcon}>
                        {tipo.icon}
                      </div>


                      <div style={styles.dayAgendaContent}>

                        <strong>
                          {actividad.titulo}
                        </strong>


                        <span style={styles.dayAgendaType}>
                          {tipo.label}

                          {actividad
                            .persona_relacionada
                            ? ` · ${actividad.persona_relacionada}`
                            : ""}
                        </span>

                      </div>


                      <EstadoBadge
                        estado={
                          actividad.estado
                        }
                      />

                    </button>

                  );

                }
              )}

            </div>

          )}

        </section>


        {/* ============================================
            FILTROS
        ============================================ */}

        <section style={styles.filters}>

          <div style={styles.filterGroup}>

            <label style={styles.label}>
              Estado
            </label>


            <select
              value={
                filtroEstado
              }
              onChange={
                e =>
                  setFiltroEstado(
                    e.target.value
                  )
              }
              style={styles.input}
            >

              <option value="todos">
                Todos
              </option>

              <option value="pendiente">
                Pendientes
              </option>

              <option value="realizado">
                Realizadas
              </option>

              <option value="cancelado">
                Canceladas
              </option>

            </select>

          </div>


          <div style={styles.filterGroup}>

            <label style={styles.label}>
              Tipo
            </label>


            <select
              value={
                filtroTipo
              }
              onChange={
                e =>
                  setFiltroTipo(
                    e.target.value
                  )
              }
              style={styles.input}
            >

              <option value="todos">
                Todos
              </option>


              {tiposActividad.map(
                tipo => (
                  <option
                    key={
                      tipo.value
                    }
                    value={
                      tipo.value
                    }
                  >
                    {tipo.icon}{" "}
                    {tipo.label}
                  </option>
                )
              )}

            </select>

          </div>


          <div style={styles.filterGroup}>

            <label style={styles.label}>
              Fecha
            </label>


            <input
              type="date"
              value={
                filtroFecha
              }
              onChange={
                e =>
                  setFiltroFecha(
                    e.target.value
                  )
              }
              style={styles.input}
            />

          </div>


          {(
            filtroFecha ||
            filtroTipo !==
              "todos" ||
            filtroEstado !==
              "todos"
          ) && (

            <button
              type="button"
              style={styles.clearButton}
              onClick={() => {

                setFiltroFecha("");

                setFiltroTipo(
                  "todos"
                );

                setFiltroEstado(
                  "todos"
                );

              }}
            >
              Limpiar filtros
            </button>

          )}

        </section>


        {/* ============================================
            LISTADO GENERAL
        ============================================ */}

        <section style={styles.generalSection}>

          <div style={styles.listHeader}>

            <div>

              <div style={styles.calendarSmallTitle}>
                Actividades
              </div>

              <h2 style={styles.listTitle}>
                Agenda registrada
              </h2>

            </div>


            <span style={styles.resultCount}>
              {
                actividadesFiltradas
                  .length
              }{" "}
              resultado(s)
            </span>

          </div>


          {cargando ? (

            <div style={styles.loading}>
              <strong>
                Cargando agenda...
              </strong>
            </div>

          ) : actividadesFiltradas
              .length === 0 ? (

            <div style={styles.empty}>

              <div style={styles.emptyIcon}>
                📅
              </div>

              <h3 style={styles.emptyTitle}>
                No hay actividades
              </h3>

              <p style={styles.emptyText}>
                Registra una nueva actividad
                para comenzar a organizar tu
                agenda.
              </p>

              <button
                type="button"
                style={styles.newButton}
                onClick={() =>
                  nuevaActividad()
                }
              >
                + Nueva actividad
              </button>

            </div>

          ) : (

            <div style={styles.list}>

              {actividadesFiltradas.map(
                actividad => {

                  const tipo =
                    obtenerTipo(
                      actividad
                        .tipo_actividad
                    );


                  return (

                    <article
                      key={
                        actividad
                          .id_agenda
                      }
                      style={{
                        ...styles.activityCard,

                        ...(
                          actividad.estado ===
                          "realizado"
                            ? styles.activityDone
                            : {}
                        ),

                        ...(
                          actividad.estado ===
                          "cancelado"
                            ? styles.activityCancelled
                            : {}
                        )
                      }}
                    >

                      <div style={styles.activityIcon}>
                        {tipo.icon}
                      </div>


                      <div style={styles.activityContent}>

                        <div style={styles.activityHeader}>

                          <div>

                            <span style={styles.typeLabel}>
                              {tipo.label}
                            </span>


                            <h3 style={styles.activityTitle}>
                              {actividad.titulo}
                            </h3>

                          </div>


                          <EstadoBadge
                            estado={
                              actividad.estado
                            }
                          />

                        </div>


                        <div style={styles.activityInfo}>

                          <span>
                            📅{" "}
                            {formatearFecha(
                              actividad.fecha
                            )}
                          </span>


                          {actividad.hora_inicio && (

                            <span>
                              🕐{" "}
                              {formatearHora(
                                actividad
                                  .hora_inicio
                              )}

                              {actividad.hora_fin
                                ? ` - ${formatearHora(
                                    actividad.hora_fin
                                  )}`
                                : ""}
                            </span>

                          )}


                          {actividad
                            .persona_relacionada && (

                            <span>
                              👤{" "}
                              {
                                actividad
                                  .persona_relacionada
                              }
                            </span>

                          )}


                          {actividad
                            .ubicacion && (

                            <span>
                              📍{" "}
                              {
                                actividad
                                  .ubicacion
                              }
                            </span>

                          )}


                          {Number(
                            actividad
                              .recordatorio_activo
                          ) === 1 && (

                            <span>
                              ⏰ Recordatorio{" "}

                              {actividad
                                .minutos_recordatorio
                                ? `${actividad.minutos_recordatorio} min antes`
                                : "activo"}
                            </span>

                          )}

                        </div>


                        {actividad.descripcion && (

                          <p style={styles.description}>
                            {
                              actividad
                                .descripcion
                            }
                          </p>

                        )}


                        {actividad.enlace && (

                          <a
                            href={
                              actividad.enlace
                            }
                            target="_blank"
                            rel="noopener noreferrer"
                            style={styles.link}
                          >
                            🔗 Abrir enlace
                          </a>

                        )}


                        <div style={styles.actions}>

                          <button
                            type="button"
                            style={styles.editButton}
                            onClick={() =>
                              editarActividad(
                                actividad
                              )
                            }
                          >
                            ✏️ Editar
                          </button>


                          {actividad.estado !==
                            "realizado" && (

                            <button
                              type="button"
                              style={styles.doneButton}
                              onClick={() =>
                                cambiarEstado(
                                  actividad,
                                  "realizado"
                                )
                              }
                            >
                              ✓ Realizada
                            </button>

                          )}


                          {actividad.estado !==
                            "cancelado" && (

                            <button
                              type="button"
                              style={styles.cancelButton}
                              onClick={() =>
                                cambiarEstado(
                                  actividad,
                                  "cancelado"
                                )
                              }
                            >
                              Cancelar
                            </button>

                          )}


                          <button
                            type="button"
                            style={styles.deleteButton}
                            onClick={() =>
                              eliminarActividad(
                                actividad
                              )
                            }
                          >
                            🗑 Eliminar
                          </button>

                        </div>

                      </div>

                    </article>

                  );

                }
              )}

            </div>

          )}

        </section>


        {/* ============================================
            MODAL
        ============================================ */}

        {mostrarFormulario && (

          <div
            style={styles.overlay}
            onClick={
              cerrarFormulario
            }
          >

            <div
              style={styles.modal}
              onClick={
                e =>
                  e.stopPropagation()
              }
            >

              <div style={styles.modalHeader}>

                <div>

                  <span style={styles.modalBadge}>
                    {editando
                      ? "Editar actividad"
                      : "Nueva actividad"}
                  </span>


                  <h2 style={styles.modalTitle}>
                    {editando
                      ? "Modificar actividad"
                      : "Agregar a la agenda"}
                  </h2>

                </div>


                <button
                  type="button"
                  style={styles.closeButton}
                  onClick={
                    cerrarFormulario
                  }
                >
                  ×
                </button>

              </div>


              <form
                onSubmit={
                  guardarActividad
                }
              >

                <div style={styles.formGrid}>

                  <div style={styles.fullField}>

                    <label style={styles.label}>
                      Título *
                    </label>


                    <input
                      type="text"
                      name="titulo"
                      value={
                        formulario.titulo
                      }
                      onChange={
                        cambiar
                      }
                      style={styles.input}
                      placeholder="Ej. Reunión semanal RH"
                    />

                  </div>


                  <div>

                    <label style={styles.label}>
                      Tipo de actividad
                    </label>


                    <select
                      name="tipo_actividad"
                      value={
                        formulario
                          .tipo_actividad
                      }
                      onChange={
                        cambiar
                      }
                      style={styles.input}
                    >

                      {tiposActividad.map(
                        tipo => (
                          <option
                            key={
                              tipo.value
                            }
                            value={
                              tipo.value
                            }
                          >
                            {tipo.icon}{" "}
                            {tipo.label}
                          </option>
                        )
                      )}

                    </select>

                  </div>


                  <div>

                    <label style={styles.label}>
                      Fecha *
                    </label>


                    <input
                      type="date"
                      name="fecha"
                      value={
                        formulario.fecha
                      }
                      onChange={
                        cambiar
                      }
                      style={styles.input}
                    />

                  </div>


                  <div>

                    <label style={styles.label}>
                      Hora de inicio
                    </label>


                    <input
                      type="time"
                      name="hora_inicio"
                      value={
                        formulario
                          .hora_inicio
                      }
                      onChange={
                        cambiar
                      }
                      style={styles.input}
                    />

                  </div>


                  <div>

                    <label style={styles.label}>
                      Hora de término
                    </label>


                    <input
                      type="time"
                      name="hora_fin"
                      value={
                        formulario
                          .hora_fin
                      }
                      onChange={
                        cambiar
                      }
                      style={styles.input}
                    />

                  </div>


                  <div>

                    <label style={styles.label}>
                      Persona relacionada
                    </label>


                    <input
                      type="text"
                      name="persona_relacionada"
                      value={
                        formulario
                          .persona_relacionada
                      }
                      onChange={
                        cambiar
                      }
                      style={styles.input}
                      placeholder="Opcional"
                    />

                  </div>


                  <div>

                    <label style={styles.label}>
                      Ubicación
                    </label>


                    <input
                      type="text"
                      name="ubicacion"
                      value={
                        formulario
                          .ubicacion
                      }
                      onChange={
                        cambiar
                      }
                      style={styles.input}
                      placeholder="Sala, oficina, dirección..."
                    />

                  </div>


                  <div style={styles.fullField}>

                    <label style={styles.label}>
                      Enlace
                    </label>


                    <input
                      type="url"
                      name="enlace"
                      value={
                        formulario.enlace
                      }
                      onChange={
                        cambiar
                      }
                      style={styles.input}
                      placeholder="https://..."
                    />

                  </div>


                  <div style={styles.fullField}>

                    <label style={styles.label}>
                      Descripción / notas
                    </label>


                    <textarea
                      name="descripcion"
                      value={
                        formulario.descripcion
                      }
                      onChange={
                        cambiar
                      }
                      style={styles.textarea}
                      rows={4}
                      placeholder="Detalles importantes de la actividad..."
                    />

                  </div>


                  <div style={styles.reminderBox}>

                    <label style={styles.checkboxRow}>

                      <input
                        type="checkbox"
                        name="recordatorio_activo"
                        checked={
                          Number(
                            formulario
                              .recordatorio_activo
                          ) === 1
                        }
                        onChange={
                          cambiar
                        }
                      />

                      <span>
                        ⏰ Activar recordatorio
                      </span>

                    </label>


                    {Number(
                      formulario
                        .recordatorio_activo
                    ) === 1 && (

                      <select
                        name="minutos_recordatorio"
                        value={
                          formulario
                            .minutos_recordatorio
                        }
                        onChange={
                          cambiar
                        }
                        style={styles.input}
                      >

                        <option value="5">
                          5 minutos antes
                        </option>

                        <option value="10">
                          10 minutos antes
                        </option>

                        <option value="15">
                          15 minutos antes
                        </option>

                        <option value="30">
                          30 minutos antes
                        </option>

                        <option value="60">
                          1 hora antes
                        </option>

                        <option value="120">
                          2 horas antes
                        </option>

                        <option value="1440">
                          1 día antes
                        </option>

                      </select>

                    )}

                  </div>


                  {editando && (

                    <div>

                      <label style={styles.label}>
                        Estado
                      </label>


                      <select
                        name="estado"
                        value={
                          formulario.estado
                        }
                        onChange={
                          cambiar
                        }
                        style={styles.input}
                      >

                        <option value="pendiente">
                          Pendiente
                        </option>

                        <option value="realizado">
                          Realizada
                        </option>

                        <option value="cancelado">
                          Cancelada
                        </option>

                      </select>

                    </div>

                  )}

                </div>


                <div style={styles.modalActions}>

                  <button
                    type="button"
                    style={styles.secondaryButton}
                    onClick={
                      cerrarFormulario
                    }
                  >
                    Cancelar
                  </button>


                  <button
                    type="submit"
                    style={{
                      ...styles.saveButton,

                      ...(
                        guardando
                          ? styles.disabledButton
                          : {}
                      )
                    }}
                    disabled={
                      guardando
                    }
                  >

                    {guardando
                      ? "Guardando..."
                      : editando
                      ? "Guardar cambios"
                      : "Registrar actividad"}

                  </button>

                </div>

              </form>

            </div>

          </div>

        )}

      </div>

    </div>
  );
}


// ==================================================
// ESTADÍSTICA
// ==================================================

function StatCard({
  icon,
  label,
  value
}) {

  return (
    <div style={styles.statCard}>

      <div style={styles.statIcon}>
        {icon}
      </div>

      <div>

        <div style={styles.statValue}>
          {value}
        </div>

        <div style={styles.statLabel}>
          {label}
        </div>

      </div>

    </div>
  );
}


// ==================================================
// ESTADO
// ==================================================

function EstadoBadge({
  estado
}) {

  const config = {

    pendiente: {
      texto: "Pendiente",
      background: "#fff7df",
      color: "#9a6800"
    },

    realizado: {
      texto: "Realizada",
      background: "#e8f8ee",
      color: "#247847"
    },

    cancelado: {
      texto: "Cancelada",
      background: "#fff0f0",
      color: "#a73232"
    }

  };


  const actual =
    config[estado] ||
    config.pendiente;


  return (
    <span
      style={{
        ...styles.statusBadge,
        background:
          actual.background,
        color:
          actual.color
      }}
    >
      {actual.texto}
    </span>
  );
}


// ==================================================
// ESTILOS
// ==================================================

const styles = {

  page: {
    minHeight: "100vh",
    background: "#f4f8fd",
    padding: "30px 20px 60px",
    color: "#17243d",
    fontFamily:
      "Inter, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif"
  },


  container: {
    maxWidth: 1280,
    margin: "0 auto"
  },


  header: {
    display: "flex",
    alignItems: "flex-end",
    justifyContent: "space-between",
    gap: 24,
    background: "#ffffff",
    border: "1px solid #dfe7f3",
    borderRadius: 22,
    padding: "28px 30px",
    boxShadow:
      "0 12px 34px rgba(35, 55, 90, 0.06)"
  },


  backButton: {
    border: "none",
    background: "transparent",
    padding: 0,
    marginBottom: 18,
    color: "#56667e",
    cursor: "pointer",
    fontWeight: 700
  },


  headerBadge: {
    display: "inline-flex",
    padding: "6px 11px",
    borderRadius: 999,
    background: "#edf3ff",
    color: "#315ed1",
    fontSize: 12,
    fontWeight: 800,
    marginBottom: 10
  },


  title: {
    margin: 0,
    fontSize:
      "clamp(28px, 5vw, 40px)"
  },


  subtitle: {
    margin: "10px 0 0",
    color: "#62718a",
    maxWidth: 680,
    lineHeight: 1.6
  },


  newButton: {
    border: "none",
    borderRadius: 13,
    padding: "13px 20px",
    background: "#2764ef",
    color: "#ffffff",
    fontWeight: 800,
    cursor: "pointer",
    whiteSpace: "nowrap"
  },


  smallNewButton: {
    border: "none",
    borderRadius: 11,
    padding: "10px 15px",
    background: "#2764ef",
    color: "#ffffff",
    fontWeight: 800,
    cursor: "pointer"
  },


  errorBox: {
    marginTop: 16,
    padding: "14px 16px",
    borderRadius: 13,
    background: "#fff1f1",
    border:
      "1px solid #efc3c3",
    color: "#a12f2f",
    fontWeight: 700
  },


  successBox: {
    marginTop: 16,
    padding: "14px 16px",
    borderRadius: 13,
    background: "#effcf3",
    border:
      "1px solid #bfe3ca",
    color: "#207246",
    fontWeight: 700
  },


  statsGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(180px, 1fr))",
    gap: 14,
    marginTop: 20
  },


  statCard: {
    background: "#ffffff",
    border:
      "1px solid #e0e7f2",
    borderRadius: 17,
    padding: 18,
    display: "flex",
    alignItems: "center",
    gap: 13
  },


  statIcon: {
    width: 45,
    height: 45,
    borderRadius: 13,
    background: "#eef3ff",
    display: "grid",
    placeItems: "center",
    fontSize: 21
  },


  statValue: {
    fontSize: 23,
    fontWeight: 900
  },


  statLabel: {
    color: "#748199",
    fontSize: 13,
    fontWeight: 700
  },


  // ==================================================
  // CALENDARIO
  // ==================================================

  calendarCard: {
    marginTop: 20,
    background: "#ffffff",
    border:
      "1px solid #dfe7f3",
    borderRadius: 22,
    padding: 22,
    boxShadow:
      "0 8px 25px rgba(35, 55, 90, .05)"
  },


  calendarHeader: {
    display: "flex",
    justifyContent:
      "space-between",
    alignItems: "center",
    gap: 15,
    marginBottom: 18,
    flexWrap: "wrap"
  },


  calendarSmallTitle: {
    fontSize: 11,
    color: "#718098",
    fontWeight: 900,
    textTransform:
      "uppercase",
    letterSpacing: ".06em"
  },


  calendarTitle: {
    margin: "3px 0 0",
    fontSize: 25
  },


  calendarControls: {
    display: "flex",
    gap: 8,
    alignItems: "center"
  },


  todayButton: {
    border:
      "1px solid #cdd8e9",
    background: "#ffffff",
    color: "#385475",
    padding: "9px 14px",
    borderRadius: 10,
    cursor: "pointer",
    fontWeight: 800
  },


  monthButton: {
    width: 40,
    height: 40,
    border:
      "1px solid #d3ddec",
    borderRadius: 11,
    background: "#f7f9fd",
    color: "#36516f",
    cursor: "pointer",
    fontSize: 26,
    lineHeight: 1
  },


  calendarScroll: {
    overflowX: "auto"
  },


  calendarGrid: {
    minWidth: 900,
    display: "grid",
    gridTemplateColumns:
      "repeat(7, minmax(120px, 1fr))",
    borderTop:
      "1px solid #dfe6f0",
    borderLeft:
      "1px solid #dfe6f0"
  },


  weekDay: {
    padding: "10px",
    textAlign: "center",
    fontSize: 12,
    fontWeight: 900,
    color: "#697890",
    background: "#f7f9fc",
    borderRight:
      "1px solid #dfe6f0",
    borderBottom:
      "1px solid #dfe6f0"
  },


  dayCell: {
    position: "relative",
    minHeight: 125,
    padding: 8,
    background: "#ffffff",
    borderRight:
      "1px solid #e1e7f0",
    borderBottom:
      "1px solid #e1e7f0",
    cursor: "pointer",
    transition:
      "background .15s ease"
  },


  dayOtherMonth: {
    background: "#f8fafc",
    color: "#a5afbd"
  },


  daySelected: {
    background: "#eef4ff",
    boxShadow:
      "inset 0 0 0 2px #6993f8"
  },


  dayTop: {
    display: "flex",
    justifyContent:
      "space-between",
    alignItems: "center"
  },


  dayNumber: {
    width: 29,
    height: 29,
    display: "grid",
    placeItems: "center",
    borderRadius: "50%",
    fontWeight: 800,
    fontSize: 13
  },


  todayNumber: {
    background: "#2764ef",
    color: "#ffffff"
  },


  dayCount: {
    minWidth: 20,
    height: 20,
    padding: "0 5px",
    borderRadius: 999,
    display: "grid",
    placeItems: "center",
    background: "#e5edff",
    color: "#315ed1",
    fontSize: 10,
    fontWeight: 900
  },


  dayEvents: {
    marginTop: 5,
    display: "flex",
    flexDirection: "column",
    gap: 3
  },


  calendarEvent: {
    width: "100%",
    border: "none",
    textAlign: "left",
    display: "flex",
    alignItems: "center",
    gap: 4,
    padding: "4px 5px",
    borderRadius: 6,
    background: "#eaf1ff",
    color: "#264eae",
    fontSize: 10,
    cursor: "pointer",
    overflow: "hidden"
  },


  calendarEventDone: {
    background: "#e8f8ee",
    color: "#287347"
  },


  calendarEventCancelled: {
    background: "#fff0f0",
    color: "#9b4b4b",
    textDecoration:
      "line-through",
    opacity: .75
  },


  calendarEventText: {
    overflow: "hidden",
    whiteSpace: "nowrap",
    textOverflow:
      "ellipsis",
    fontWeight: 700
  },


  moreEvents: {
    fontSize: 10,
    color: "#687890",
    paddingLeft: 4,
    fontWeight: 700
  },


  dayAddButton: {
    position: "absolute",
    right: 6,
    bottom: 6,
    width: 24,
    height: 24,
    border: "none",
    borderRadius: "50%",
    background: "#edf3ff",
    color: "#315ed1",
    fontSize: 16,
    fontWeight: 900,
    cursor: "pointer"
  },


  calendarHelp: {
    marginTop: 13,
    padding: "10px 12px",
    borderRadius: 10,
    background: "#f7f9fd",
    color: "#66758d",
    fontSize: 12
  },


  // ==================================================
  // DÍA SELECCIONADO
  // ==================================================

  selectedDayCard: {
    marginTop: 20,
    background: "#ffffff",
    border:
      "1px solid #dfe7f3",
    borderRadius: 18,
    padding: 20
  },


  selectedDayHeader: {
    display: "flex",
    justifyContent:
      "space-between",
    gap: 15,
    alignItems: "center"
  },


  selectedDayTitle: {
    margin: "4px 0 0",
    fontSize: 18,
    textTransform:
      "capitalize"
  },


  noDayEvents: {
    marginTop: 15,
    padding: 16,
    borderRadius: 12,
    background: "#f8fafc",
    color: "#718096",
    textAlign: "center"
  },


  dayAgendaList: {
    display: "flex",
    flexDirection: "column",
    gap: 8,
    marginTop: 15
  },


  dayAgendaItem: {
    width: "100%",
    border:
      "1px solid #e0e7f2",
    borderRadius: 12,
    padding: "11px 13px",
    background: "#ffffff",
    display: "flex",
    alignItems: "center",
    gap: 12,
    cursor: "pointer",
    textAlign: "left"
  },


  dayAgendaTime: {
    width: 85,
    minWidth: 85,
    color: "#52647e",
    fontSize: 12,
    fontWeight: 800
  },


  dayAgendaIcon: {
    width: 34,
    height: 34,
    borderRadius: 10,
    background: "#edf3ff",
    display: "grid",
    placeItems: "center"
  },


  dayAgendaContent: {
    flex: 1,
    display: "flex",
    flexDirection: "column",
    gap: 2
  },


  dayAgendaType: {
    color: "#75839a",
    fontSize: 11
  },


  // ==================================================
  // FILTROS
  // ==================================================

  filters: {
    marginTop: 20,
    padding: 18,
    borderRadius: 17,
    background: "#ffffff",
    border:
      "1px solid #e0e7f2",
    display: "flex",
    alignItems: "flex-end",
    flexWrap: "wrap",
    gap: 13
  },


  filterGroup: {
    minWidth: 180,
    flex: 1
  },


  label: {
    display: "block",
    marginBottom: 6,
    fontSize: 12,
    color: "#68778f",
    fontWeight: 800
  },


  input: {
    width: "100%",
    boxSizing:
      "border-box",
    border:
      "1px solid #cfd9e8",
    borderRadius: 11,
    padding: "11px 12px",
    fontSize: 14,
    outline: "none",
    background: "#ffffff",
    color: "#24334e"
  },


  textarea: {
    width: "100%",
    boxSizing:
      "border-box",
    border:
      "1px solid #cfd9e8",
    borderRadius: 11,
    padding: "11px 12px",
    fontSize: 14,
    resize: "vertical",
    fontFamily: "inherit",
    outline: "none"
  },


  clearButton: {
    border:
      "1px solid #d3dceb",
    borderRadius: 11,
    padding: "11px 15px",
    background: "#ffffff",
    cursor: "pointer",
    color: "#53637c",
    fontWeight: 700
  },


  // ==================================================
  // LISTADO
  // ==================================================

  generalSection: {
    marginTop: 20
  },


  listHeader: {
    display: "flex",
    justifyContent:
      "space-between",
    alignItems: "end",
    gap: 15,
    marginBottom: 12
  },


  listTitle: {
    margin: "3px 0 0",
    fontSize: 22
  },


  resultCount: {
    color: "#718096",
    fontSize: 12,
    fontWeight: 700
  },


  list: {
    display: "flex",
    flexDirection: "column",
    gap: 14
  },


  activityCard: {
    background: "#ffffff",
    border:
      "1px solid #dfe6f1",
    borderRadius: 18,
    padding: 18,
    display: "flex",
    gap: 16,
    boxShadow:
      "0 7px 20px rgba(35, 55, 90, 0.04)"
  },


  activityDone: {
    borderColor:
      "#bee2ca"
  },


  activityCancelled: {
    opacity: .72
  },


  activityIcon: {
    width: 48,
    height: 48,
    minWidth: 48,
    borderRadius: 14,
    background: "#edf3ff",
    display: "grid",
    placeItems: "center",
    fontSize: 22
  },


  activityContent: {
    flex: 1,
    minWidth: 0
  },


  activityHeader: {
    display: "flex",
    justifyContent:
      "space-between",
    alignItems: "flex-start",
    gap: 15
  },


  typeLabel: {
    color: "#728099",
    fontSize: 11,
    textTransform:
      "uppercase",
    fontWeight: 800,
    letterSpacing:
      ".04em"
  },


  activityTitle: {
    margin: "3px 0 0",
    fontSize: 18
  },


  statusBadge: {
    padding: "6px 10px",
    borderRadius: 999,
    fontSize: 11,
    fontWeight: 800,
    whiteSpace: "nowrap"
  },


  activityInfo: {
    display: "flex",
    flexWrap: "wrap",
    gap: "7px 16px",
    marginTop: 12,
    color: "#56677f",
    fontSize: 13
  },


  description: {
    margin: "12px 0 0",
    color: "#64738a",
    lineHeight: 1.55,
    fontSize: 14
  },


  link: {
    display: "inline-flex",
    marginTop: 10,
    color: "#2864e9",
    fontSize: 13,
    fontWeight: 700,
    textDecoration: "none"
  },


  actions: {
    display: "flex",
    flexWrap: "wrap",
    gap: 8,
    marginTop: 15
  },


  editButton: {
    border:
      "1px solid #cdd9ef",
    background: "#f7f9fd",
    color: "#345074",
    borderRadius: 9,
    padding: "8px 11px",
    cursor: "pointer",
    fontWeight: 700
  },


  doneButton: {
    border:
      "1px solid #b8dec5",
    background: "#effbf3",
    color: "#287347",
    borderRadius: 9,
    padding: "8px 11px",
    cursor: "pointer",
    fontWeight: 700
  },


  cancelButton: {
    border:
      "1px solid #ead6a8",
    background: "#fff9e8",
    color: "#85620b",
    borderRadius: 9,
    padding: "8px 11px",
    cursor: "pointer",
    fontWeight: 700
  },


  deleteButton: {
    border:
      "1px solid #edc6c6",
    background: "#fff4f4",
    color: "#a83838",
    borderRadius: 9,
    padding: "8px 11px",
    cursor: "pointer",
    fontWeight: 700
  },


  loading: {
    minHeight: 150,
    borderRadius: 18,
    background: "#ffffff",
    border:
      "1px solid #e1e8f2",
    display: "flex",
    justifyContent:
      "center",
    alignItems: "center",
    gap: 12
  },


  empty: {
    minHeight: 250,
    borderRadius: 20,
    border:
      "1px dashed #cdd8e8",
    background: "#ffffff",
    display: "flex",
    flexDirection: "column",
    justifyContent:
      "center",
    alignItems: "center",
    textAlign: "center",
    padding: 30
  },


  emptyIcon: {
    fontSize: 42
  },


  emptyTitle: {
    margin: "12px 0 4px"
  },


  emptyText: {
    color: "#718096",
    margin: "0 0 17px"
  },


  // ==================================================
  // MODAL
  // ==================================================

  overlay: {
    position: "fixed",
    inset: 0,
    background:
      "rgba(20, 31, 52, .48)",
    zIndex: 1000,
    display: "flex",
    alignItems: "center",
    justifyContent:
      "center",
    padding: 20,
    overflowY: "auto"
  },


  modal: {
    width:
      "min(820px, 100%)",
    maxHeight: "92vh",
    overflowY: "auto",
    background: "#ffffff",
    borderRadius: 22,
    padding: 25,
    boxShadow:
      "0 25px 70px rgba(15, 25, 50, .25)"
  },


  modalHeader: {
    display: "flex",
    alignItems:
      "flex-start",
    justifyContent:
      "space-between",
    gap: 16,
    marginBottom: 22
  },


  modalBadge: {
    color: "#3260d1",
    fontSize: 12,
    fontWeight: 800,
    textTransform:
      "uppercase"
  },


  modalTitle: {
    margin: "5px 0 0",
    fontSize: 26
  },


  closeButton: {
    width: 38,
    height: 38,
    borderRadius: "50%",
    border: "none",
    background: "#eef2f8",
    color: "#57677f",
    fontSize: 23,
    cursor: "pointer"
  },


  formGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(2, minmax(0, 1fr))",
    gap: 15
  },


  fullField: {
    gridColumn:
      "1 / -1"
  },


  reminderBox: {
    gridColumn:
      "1 / -1",
    background: "#f7f9fd",
    border:
      "1px solid #e1e7f0",
    borderRadius: 14,
    padding: 14,
    display: "flex",
    alignItems: "center",
    gap: 15,
    flexWrap: "wrap"
  },


  checkboxRow: {
    display: "flex",
    alignItems: "center",
    gap: 8,
    fontWeight: 700,
    color: "#4d5e77"
  },


  modalActions: {
    display: "flex",
    justifyContent:
      "flex-end",
    gap: 10,
    marginTop: 24,
    paddingTop: 18,
    borderTop:
      "1px solid #e5eaf2"
  },


  secondaryButton: {
    border:
      "1px solid #cfd8e7",
    borderRadius: 11,
    padding: "11px 17px",
    background: "#ffffff",
    color: "#52627b",
    cursor: "pointer",
    fontWeight: 700
  },


  saveButton: {
    border: "none",
    borderRadius: 11,
    padding: "11px 18px",
    background: "#2764ef",
    color: "#ffffff",
    cursor: "pointer",
    fontWeight: 800
  },


  disabledButton: {
    opacity: .55,
    cursor: "not-allowed"
  }

};