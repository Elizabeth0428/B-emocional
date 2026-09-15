// src/views/CalendarView.jsx

import React, { useEffect, useState } from "react";
import { Calendar, dateFnsLocalizer } from "react-big-calendar";

import format from "date-fns/format";
import parse from "date-fns/parse";
import startOfWeek from "date-fns/startOfWeek";
import getDay from "date-fns/getDay";

import { es } from "date-fns/locale";

import "react-big-calendar/lib/css/react-big-calendar.css";

import axios from "axios";

import {
  getCurrentUser,
  getToken
} from "../services/AuthService";


// =====================================================
// CONFIGURACIÓN DEL CALENDARIO
// =====================================================

const locales = {
  es
};

const localizer = dateFnsLocalizer({
  format,
  parse,
  startOfWeek,
  getDay,
  locales
});


// =====================================================
// COMPONENTE
// =====================================================

export default function CalendarView({ onBack }) {

  const user = getCurrentUser();

  const [events, setEvents] = useState([]);

  const [pacientes, setPacientes] = useState([]);

  const [showForm, setShowForm] = useState(false);

  const [showEdit, setShowEdit] = useState(false);

  const [selectedEvent, setSelectedEvent] = useState(null);

  const [view, setView] = useState("month");

  const [date, setDate] = useState(new Date());

  const [loading, setLoading] = useState(false);

  const [loadingCitas, setLoadingCitas] = useState(false);

  const [loadingPacientes, setLoadingPacientes] = useState(false);


  // =====================================================
  // FORMULARIO NUEVA CITA
  // =====================================================

  const [form, setForm] = useState({

    id_paciente: "",

    fecha: "",

    hora: "",

    motivo: "",

    notas: ""

  });


  // =====================================================
  // CARGAR INFORMACIÓN INICIAL
  // =====================================================

  useEffect(() => {

    fetchCitas();

    fetchPacientes();

  }, []);


  // =====================================================
  // CARGAR CITAS
  //
  // IMPORTANTE:
  //
  // Las citas canceladas SÍ pueden seguir existiendo
  // en la base de datos para conservar historial.
  //
  // Pero NO se muestran en el calendario.
  //
  // De esta manera el horario queda libre.
  // =====================================================

  const fetchCitas = async () => {

    try {

      setLoadingCitas(true);

      const token = getToken();

      const res = await axios.get(
        "http://localhost:5000/api/citas",
        {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      );


      const toISODate = (d) => {

        if (typeof d === "string") {

          return d.slice(0, 10);

        }

        return "";

      };


      const toTime = (t) => {

        if (typeof t === "string") {

          return t.slice(0, 8);

        }

        return "00:00:00";

      };


      /*
       * =================================================
       * FILTRO IMPORTANTE
       *
       * Las canceladas no se dibujan.
       *
       * Esto hace que el espacio vuelva a quedar libre.
       * =================================================
       */

      const citasActivas = (res.data || []).filter(
        (c) => c.estado !== "cancelada"
      );


      const eventos = citasActivas.map((c) => {

        const fecha = toISODate(c.fecha);

        const hora = toTime(c.hora);


        const start = new Date(
          `${fecha}T${hora}`
        );


        /*
         * Por defecto una consulta ocupa 1 hora.
         */

        const end = new Date(
          start.getTime() +
          60 * 60 * 1000
        );


        return {

          id: c.id_cita,

          title:
            `${c.paciente || "Paciente"} - ${
              c.motivo || "Consulta"
            }`,

          start,

          end,

          resource: {

            id_cita:
              c.id_cita,

            id_paciente:
              c.id_paciente,

            paciente:
              c.paciente,

            motivo:
              c.motivo,

            estado:
              c.estado || "pendiente",

            notas:
              c.notas,

            fecha:
              fecha,

            hora:
              hora

          }

        };

      });


      setEvents(eventos);


    } catch (err) {

      console.error(
        "❌ Error al cargar citas:",
        err.response?.data ||
        err.message
      );


      alert(
        err.response?.data?.message ||
        "⚠️ No se pudieron cargar las citas."
      );


    } finally {

      setLoadingCitas(false);

    }

  };


  // =====================================================
  // CARGAR PACIENTES
  // =====================================================

  const fetchPacientes = async () => {

    try {

      setLoadingPacientes(true);

      const token = getToken();

      const res = await axios.get(
        "http://localhost:5000/api/pacientes",
        {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      );


      setPacientes(
        res.data || []
      );


    } catch (err) {

      console.error(
        "❌ Error al cargar pacientes:",
        err.response?.data ||
        err.message
      );


      alert(
        err.response?.data?.message ||
        "⚠️ No se pudieron cargar los pacientes."
      );


    } finally {

      setLoadingPacientes(false);

    }

  };


  // =====================================================
  // CAMBIAR FORMULARIO
  // =====================================================

  const handleFormChange = (e) => {

    const {
      name,
      value
    } = e.target;


    setForm((prev) => ({

      ...prev,

      [name]: value

    }));

  };


  // =====================================================
  // CREAR CITA
  //
  // IMPORTANTE:
  //
  // AQUÍ NO SE CREA NINGUNA SESIÓN.
  //
  // La cita solamente agenda la consulta.
  // =====================================================

  const handleCreate = async (e) => {

    e.preventDefault();

    setLoading(true);


    try {

      const token = getToken();


      const payload = {

        id_paciente:
          form.id_paciente,

        fecha:
          form.fecha,

        hora:
          form.hora,

        motivo:
          form.motivo,

        notas:
          form.notas

      };


      console.log(
        "📅 Creando cita:",
        payload
      );


      await axios.post(

        "http://localhost:5000/api/citas",

        payload,

        {
          headers: {

            Authorization:
              `Bearer ${token}`

          }

        }

      );


      alert(
        "✅ Cita agendada correctamente."
      );


      setShowForm(false);


      setForm({

        id_paciente: "",

        fecha: "",

        hora: "",

        motivo: "",

        notas: ""

      });


      await fetchCitas();


    } catch (err) {

      console.error(
        "❌ Error al crear cita:",
        err.response?.data ||
        err.message
      );


      alert(

        err.response?.data?.message ||

        "⚠️ No se pudo crear la cita."

      );


    } finally {

      setLoading(false);

    }

  };


  // =====================================================
  // CAMBIAR ESTADO DE CITA
  // =====================================================

  const handleUpdateEstado = async (estado) => {

    if (!selectedEvent) {

      return;

    }


    try {

      setLoading(true);

      const token = getToken();


      /*
       * El backend actualiza únicamente la cita
       * correspondiente al psicólogo autenticado.
       */

      await axios.put(

        `http://localhost:5000/api/citas/${selectedEvent.id}`,

        {

          fecha:
            selectedEvent.resource.fecha,

          hora:
            selectedEvent.resource.hora,

          motivo:
            selectedEvent.resource.motivo,

          estado,

          notas:
            selectedEvent.resource.notas || ""

        },

        {

          headers: {

            Authorization:
              `Bearer ${token}`

          }

        }

      );


      // =================================================
      // CANCELAR
      //
      // Al volver a cargar las citas:
      //
      // estado = cancelada
      //
      // será filtrada y desaparecerá del calendario.
      // =================================================

      if (estado === "cancelada") {

        alert(
          "❌ Cita cancelada. El horario queda disponible para otra cita."
        );

      }


      if (estado === "apartada") {

        alert(
          "🟢 Cita apartada correctamente."
        );

      }


      if (estado === "pendiente") {

        alert(
          "🟡 Cita marcada como pendiente."
        );

      }


      if (estado === "completada") {

        alert(
          "🔵 Cita marcada como completada."
        );

      }


      setShowEdit(false);

      setSelectedEvent(null);


      await fetchCitas();


    } catch (err) {

      console.error(
        "❌ Error al actualizar cita:",
        err.response?.data ||
        err.message
      );


      alert(

        err.response?.data?.message ||

        "⚠️ No se pudo actualizar la cita."

      );


    } finally {

      setLoading(false);

    }

  };


  // =====================================================
  // ABRIR CITA
  // =====================================================

  const handleSelectEvent = (event) => {

    setSelectedEvent(event);

    setShowEdit(true);

  };


  // =====================================================
  // COLOR DE LAS CITAS
  //
  // 🟢 Apartada
  // 🟡 Pendiente
  // 🔵 Completada
  //
  // ❌ Cancelada NO llega aquí porque se filtra
  //    antes de crear los eventos.
  // =====================================================

  const eventPropGetter = (event) => {

    const estado =
      event.resource?.estado ||
      "pendiente";


    let backgroundColor =
      "#FFB300";


    if (
      estado === "apartada" ||
      estado === "confirmada"
    ) {

      backgroundColor =
        "#43A047";

    }


    if (
      estado === "pendiente"
    ) {

      backgroundColor =
        "#FFB300";

    }


    if (
      estado === "completada"
    ) {

      backgroundColor =
        "#1976D2";

    }


    return {

      style: {

        backgroundColor,

        color: "#fff",

        borderRadius: "6px",

        border: "none",

        padding: "2px 5px"

      }

    };

  };


  // =====================================================
  // CERRAR MODAL DE CITA
  // =====================================================

  const cerrarDetalle = () => {

    setShowEdit(false);

    setSelectedEvent(null);

  };


  // =====================================================
  // RENDER
  // =====================================================

  return (

    <div
      style={{
        height: "80vh",
        padding: 20,
        boxSizing: "border-box"
      }}
    >

      {/* =================================================
          ENCABEZADO
      ================================================= */}

      <div style={headerStyle}>

        <div>

          <h2 style={titleStyle}>
            📅 Agenda de Citas
          </h2>

          <p style={subtitleStyle}>
            Administra las consultas programadas
            de tus pacientes.
          </p>

        </div>


        <button

          type="button"

          onClick={() =>
            setShowForm(true)
          }

          style={newButton}

        >

          ➕ Nueva Cita

        </button>

      </div>


      {/* =================================================
          LEYENDA
      ================================================= */}

      <div style={legendStyle}>

        <div style={legendItem}>

          <span
            style={{
              ...legendDot,
              background: "#43A047"
            }}
          />

          <span>
            Apartada
          </span>

        </div>


        <div style={legendItem}>

          <span
            style={{
              ...legendDot,
              background: "#FFB300"
            }}
          />

          <span>
            Pendiente
          </span>

        </div>


        <div style={legendItem}>

          <span
            style={{
              ...legendDot,
              background: "#1976D2"
            }}
          />

          <span>
            Completada
          </span>

        </div>

      </div>


      {/* =================================================
          INDICADOR DE CARGA
      ================================================= */}

      {loadingCitas && (

        <div style={loadingBox}>

          ⏳ Cargando agenda...

        </div>

      )}


      {/* =================================================
          CALENDARIO
      ================================================= */}

      <Calendar

        localizer={localizer}

        events={events}

        startAccessor="start"

        endAccessor="end"

        views={[
          "month",
          "week",
          "day",
          "agenda"
        ]}

        view={view}

        date={date}

        onView={(newView) =>
          setView(newView)
        }

        onNavigate={(newDate) =>
          setDate(newDate)
        }

        style={{
          height: 500,
          background: "#fff",
          borderRadius: "12px",
          padding: "10px"
        }}

        eventPropGetter={
          eventPropGetter
        }

        onSelectEvent={
          handleSelectEvent
        }

      />


      {/* =================================================
          VOLVER
      ================================================= */}

      <button

        type="button"

        onClick={onBack}

        style={backButton}

      >

        ← Volver

      </button>


      {/* =================================================
          MODAL NUEVA CITA
      ================================================= */}

      {showForm && (

        <div style={modalStyle}>

          <form

            onSubmit={handleCreate}

            style={formStyle}

          >

            <h3>
              ➕ Nueva Cita
            </h3>


            {/* PACIENTE */}

            <label>
              Paciente
            </label>


            <select

              name="id_paciente"

              value={
                form.id_paciente
              }

              onChange={
                handleFormChange
              }

              required

              disabled={
                loadingPacientes
              }

            >

              <option value="">

                {loadingPacientes
                  ? "Cargando pacientes..."
                  : "-- Seleccionar Paciente --"}

              </option>


              {pacientes.map((p) => (

                <option

                  key={
                    p.id_paciente
                  }

                  value={
                    p.id_paciente
                  }

                >

                  {p.nombre}

                </option>

              ))}

            </select>


            {/* PSICÓLOGO */}

            <p
              style={{
                fontSize: "14px",
                color: "#666",
                margin: "4px 0"
              }}
            >

              Psicólogo:{" "}

              <strong>
                {user?.nombre || "Usuario"}
              </strong>

            </p>


            {/* FECHA */}

            <label>
              Fecha
            </label>


            <input

              type="date"

              name="fecha"

              value={
                form.fecha
              }

              onChange={
                handleFormChange
              }

              required

            />


            {/* HORA */}

            <label>
              Hora
            </label>


            <input

              type="time"

              name="hora"

              value={
                form.hora
              }

              onChange={
                handleFormChange
              }

              required

            />


            {/* MOTIVO */}

            <label>
              Motivo de la consulta
            </label>


            <input

              type="text"

              name="motivo"

              placeholder="Motivo de la consulta"

              value={
                form.motivo
              }

              onChange={
                handleFormChange
              }

              required

            />


            {/* NOTAS */}

            <label>
              Notas
            </label>


            <textarea

              name="notas"

              placeholder="Notas adicionales (opcional)"

              value={
                form.notas
              }

              onChange={
                handleFormChange
              }

            />


            {/* BOTONES */}

            <div
              style={{
                display: "flex",
                gap: "10px",
                marginTop: 10
              }}
            >

              <button

                type="submit"

                disabled={
                  loading ||
                  loadingPacientes
                }

                style={{
                  ...btnPrimary,

                  opacity:
                    loading ||
                    loadingPacientes
                      ? 0.6
                      : 1,

                  cursor:
                    loading ||
                    loadingPacientes
                      ? "not-allowed"
                      : "pointer"
                }}

              >

                {loading
                  ? "Guardando..."
                  : "Guardar Cita"}

              </button>


              <button

                type="button"

                onClick={() =>
                  setShowForm(false)
                }

                style={btnCancel}

              >

                Cancelar

              </button>

            </div>

          </form>

        </div>

      )}


      {/* =================================================
          MODAL DETALLE DE CITA
      ================================================= */}

      {showEdit &&
        selectedEvent && (

          <div style={modalStyle}>

            <div style={formStyle}>

              <h3>
                📅 Detalle de la Cita
              </h3>


              {/* =================================================
                  INFORMACIÓN
              ================================================= */}

              <div style={detailBox}>

                <p>

                  <strong>
                    Paciente:
                  </strong>{" "}

                  {
                    selectedEvent
                      .resource
                      .paciente
                  }

                </p>


                <p>

                  <strong>
                    Fecha:
                  </strong>{" "}

                  {
                    selectedEvent
                      .resource
                      .fecha
                  }

                </p>


                <p>

                  <strong>
                    Hora:
                  </strong>{" "}

                  {
                    selectedEvent
                      .resource
                      .hora
                  }

                </p>


                <p>

                  <strong>
                    Motivo:
                  </strong>{" "}

                  {
                    selectedEvent
                      .resource
                      .motivo ||
                    "Consulta"
                  }

                </p>


                <p>

                  <strong>
                    Estado:
                  </strong>{" "}

                  {
                    selectedEvent
                      .resource
                      .estado ||
                    "pendiente"
                  }

                </p>


                {
                  selectedEvent
                    .resource
                    .notas && (

                    <p>

                      <strong>
                        Notas:
                      </strong>{" "}

                      {
                        selectedEvent
                          .resource
                          .notas
                      }

                    </p>

                  )

                }

              </div>


              {/* =================================================
                  ACCIONES
              ================================================= */}

              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  gap: "8px",
                  marginTop: 10
                }}
              >

                {/* =================================================
                    APARTAR
                ================================================= */}

                <button

                  type="button"

                  disabled={loading}

                  onClick={() =>
                    handleUpdateEstado(
                      "apartada"
                    )
                  }

                  style={{
                    ...btnGreen,

                    opacity:
                      loading ? 0.6 : 1
                  }}

                >

                  🟢 Apartar / Confirmar cita

                </button>


                {/* =================================================
                    PENDIENTE
                ================================================= */}

                <button

                  type="button"

                  disabled={loading}

                  onClick={() =>
                    handleUpdateEstado(
                      "pendiente"
                    )
                  }

                  style={{
                    ...btnYellow,

                    opacity:
                      loading ? 0.6 : 1
                  }}

                >

                  🟡 Marcar pendiente

                </button>


                {/* =================================================
                    COMPLETAR
                ================================================= */}

                <button

                  type="button"

                  disabled={loading}

                  onClick={() =>
                    handleUpdateEstado(
                      "completada"
                    )
                  }

                  style={{
                    ...btnBlue,

                    opacity:
                      loading ? 0.6 : 1
                  }}

                >

                  🔵 Marcar completada

                </button>


                {/* =================================================
                    CANCELAR
                ================================================= */}

                <button

                  type="button"

                  disabled={loading}

                  onClick={() =>
                    handleUpdateEstado(
                      "cancelada"
                    )
                  }

                  style={{
                    ...btnRed,

                    opacity:
                      loading ? 0.6 : 1
                  }}

                >

                  ❌ Cancelar cita

                  <small
                    style={{
                      display: "block",
                      marginTop: 3,
                      opacity: 0.9
                    }}
                  >

                    El horario quedará disponible
                    para otra cita.

                  </small>

                </button>

              </div>


              {/* =================================================
                  CERRAR
              ================================================= */}

              <button

                type="button"

                disabled={loading}

                onClick={
                  cerrarDetalle
                }

                style={btnClose}

              >

                Cerrar

              </button>

            </div>

          </div>

        )}

    </div>

  );

}


// =====================================================
// ESTILOS
// =====================================================

const headerStyle = {

  display: "flex",

  justifyContent: "space-between",

  alignItems: "center",

  gap: "20px",

  marginBottom: "10px"

};


const titleStyle = {

  margin: 0,

  color: "#173B68"

};


const subtitleStyle = {

  margin: "5px 0 0",

  color: "#78909c",

  fontSize: "14px"

};


const newButton = {

  padding: "11px 18px",

  borderRadius: "9px",

  border: "none",

  background:
    "linear-gradient(135deg, #43A047, #2E7D32)",

  color: "#fff",

  fontWeight: "700",

  cursor: "pointer",

  whiteSpace: "nowrap"

};


const legendStyle = {

  display: "flex",

  flexWrap: "wrap",

  gap: "18px",

  alignItems: "center",

  marginBottom: "10px",

  padding: "10px 14px",

  background: "#f7faff",

  borderRadius: "10px",

  border: "1px solid #e1ecf7"

};


const legendItem = {

  display: "flex",

  alignItems: "center",

  gap: "6px",

  fontSize: "13px",

  color: "#455a64"

};


const legendDot = {

  width: "11px",

  height: "11px",

  borderRadius: "50%",

  display: "inline-block"

};


const loadingBox = {

  marginBottom: "10px",

  padding: "8px 12px",

  background: "#f5f9ff",

  border: "1px solid #dcecff",

  borderRadius: "8px",

  color: "#1565c0",

  fontSize: "13px"

};


const backButton = {

  marginTop: 20,

  padding: "10px 16px",

  background: "#333",

  color: "white",

  border: "none",

  borderRadius: "8px",

  cursor: "pointer"

};


const modalStyle = {

  position: "fixed",

  top: 0,

  left: 0,

  right: 0,

  bottom: 0,

  background:
    "rgba(0,0,0,0.5)",

  display: "flex",

  justifyContent: "center",

  alignItems: "center",

  zIndex: 2000

};


const formStyle = {

  background: "#fff",

  padding: "24px",

  borderRadius: "14px",

  display: "flex",

  flexDirection: "column",

  gap: "9px",

  width: "360px",

  maxWidth: "90vw",

  maxHeight: "90vh",

  overflowY: "auto",

  boxSizing: "border-box"

};


const detailBox = {

  background: "#f7f9fc",

  border: "1px solid #e1e8ef",

  borderRadius: "10px",

  padding: "10px 14px",

  color: "#455a64"

};


const btnPrimary = {

  flex: 1,

  padding: "10px",

  border: "none",

  borderRadius: "8px",

  background: "#4CAF50",

  color: "white",

  cursor: "pointer",

  fontWeight: "700"

};


const btnCancel = {

  flex: 1,

  padding: "10px",

  border: "none",

  borderRadius: "8px",

  background: "#E53935",

  color: "white",

  cursor: "pointer"

};


const btnGreen = {

  padding: "11px",

  border: "none",

  borderRadius: "8px",

  background: "#43A047",

  color: "#fff",

  cursor: "pointer",

  fontWeight: "700"

};


const btnYellow = {

  padding: "11px",

  border: "none",

  borderRadius: "8px",

  background: "#FFB300",

  color: "#fff",

  cursor: "pointer",

  fontWeight: "700"

};


const btnBlue = {

  padding: "11px",

  border: "none",

  borderRadius: "8px",

  background: "#1976D2",

  color: "#fff",

  cursor: "pointer",

  fontWeight: "700"

};


const btnRed = {

  padding: "11px",

  border: "none",

  borderRadius: "8px",

  background: "#E53935",

  color: "#fff",

  cursor: "pointer",

  fontWeight: "700"

};


const btnClose = {

  marginTop: "15px",

  padding: "9px",

  border: "none",

  borderRadius: "8px",

  background: "#9E9E9E",

  color: "#fff",

  cursor: "pointer"

};