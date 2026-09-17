// src/views/CalendarView.jsx

import React, { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { Calendar, dateFnsLocalizer } from "react-big-calendar";
import format from "date-fns/format";
import parse from "date-fns/parse";
import startOfWeek from "date-fns/startOfWeek";
import getDay from "date-fns/getDay";
import { es } from "date-fns/locale";
import "react-big-calendar/lib/css/react-big-calendar.css";
import axios from "axios";
import { getCurrentUser, getToken } from "../services/AuthService";

const locales = { es };

const localizer = dateFnsLocalizer({
  format,
  parse,
  startOfWeek,
  getDay,
  locales
});

const TIPOS = [
  { value: "consulta", label: "Consulta con paciente" },
  { value: "reunion", label: "Reunión" },
  { value: "supervision", label: "Supervisión" },
  { value: "capacitacion", label: "Capacitación" },
  { value: "administrativo", label: "Actividad administrativa" },
  { value: "personal", label: "Evento personal" },
  { value: "otro", label: "Otro" }
];

const MODALIDADES = [
  { value: "", label: "-- Seleccionar modalidad --" },
  { value: "presencial", label: "Presencial" },
  { value: "videollamada", label: "Videollamada" },
  { value: "otro", label: "Otro" }
];

const formInicial = {
  tipo_evento: "consulta",
  id_paciente: "",
  titulo: "",
  fecha: "",
  hora: "",
  modalidad: "",
  motivo: "",
  notas: ""
};

export default function CalendarView({ onBack }) {
  const user = getCurrentUser();
  const location = useLocation();

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
  const [form, setForm] = useState(formInicial);

  useEffect(() => {
    fetchCitas();
    fetchPacientes();
  }, []);

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const paciente = params.get("paciente");
    const tipo = params.get("tipo");
    const nueva = params.get("nueva");

    if (nueva === "1") {
      setForm({
        ...formInicial,
        tipo_evento: tipo || "consulta",
        id_paciente: paciente || ""
      });
      setShowEdit(false);
      setSelectedEvent(null);
      setShowForm(true);
    }
  }, [location.search]);

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

      const toISODate = (d) =>
        typeof d === "string" ? d.slice(0, 10) : "";

      const toTime = (t) =>
        typeof t === "string" ? t.slice(0, 8) : "00:00:00";

      const citasActivas = (res.data || []).filter(
        (c) => c.estado !== "cancelada"
      );

      const eventos = citasActivas.map((c) => {
        const fecha = toISODate(c.fecha);
        const hora = toTime(c.hora);
        const start = new Date(`${fecha}T${hora}`);
        const end = new Date(start.getTime() + 60 * 60 * 1000);

        const tipo = c.tipo_evento || "consulta";
        const paciente =
          c.paciente_nombre ||
          c.paciente ||
          "";

        const tituloEvento =
          tipo === "consulta"
            ? `${paciente || "Paciente"} - ${c.motivo || "Consulta"}`
            : `${c.titulo || nombreTipo(tipo)}${c.motivo ? ` - ${c.motivo}` : ""}`;

        return {
          id: c.id_cita,
          title: tituloEvento,
          start,
          end,
          resource: {
            id_cita: c.id_cita,
            id_paciente: c.id_paciente,
            paciente,
            paciente_correo: c.paciente_correo,
            paciente_telefono: c.paciente_telefono,
            tipo_evento: tipo,
            titulo: c.titulo,
            modalidad: c.modalidad,
            motivo: c.motivo,
            estado: c.estado || "apartada",
            notas: c.notas,
            fecha,
            hora
          }
        };
      });

      setEvents(eventos);
    } catch (err) {
      console.error("❌ Error al cargar agenda:", err.response?.data || err.message);
      alert(err.response?.data?.message || "⚠️ No se pudo cargar la agenda.");
    } finally {
      setLoadingCitas(false);
    }
  };

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

      setPacientes(res.data || []);
    } catch (err) {
      console.error("❌ Error al cargar pacientes:", err.response?.data || err.message);
      alert(err.response?.data?.message || "⚠️ No se pudieron cargar los pacientes.");
    } finally {
      setLoadingPacientes(false);
    }
  };

  const handleFormChange = (e) => {
    const { name, value } = e.target;

    setForm((prev) => {
      const siguiente = {
        ...prev,
        [name]: value
      };

      if (name === "tipo_evento") {
        if (value === "consulta") {
          siguiente.titulo = "";
        } else {
          siguiente.id_paciente = "";
        }
      }

      return siguiente;
    });
  };

  const abrirNuevoEvento = () => {
    setForm(formInicial);
    setShowForm(true);
  };

  const cerrarNuevoEvento = () => {
    if (loading) return;
    setShowForm(false);
    setForm(formInicial);
  };

  const handleCreate = async (e) => {
    e.preventDefault();

    if (form.tipo_evento === "consulta" && !form.id_paciente) {
      alert("⚠️ Selecciona un paciente para la consulta.");
      return;
    }

    if (form.tipo_evento !== "consulta" && !form.titulo.trim()) {
      alert("⚠️ Escribe un título para el evento.");
      return;
    }

    try {
      setLoading(true);
      const token = getToken();

      const payload = {
        tipo_evento: form.tipo_evento,
        id_paciente:
          form.tipo_evento === "consulta"
            ? form.id_paciente
            : null,
        titulo:
          form.tipo_evento === "consulta"
            ? null
            : form.titulo.trim(),
        fecha: form.fecha,
        hora: form.hora,
        modalidad: form.modalidad || null,
        motivo: form.motivo.trim() || null,
        notas: form.notas.trim() || null
      };

      await axios.post(
        "http://localhost:5000/api/citas",
        payload,
        {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      );

      alert(
        form.tipo_evento === "consulta"
          ? "✅ Cita agendada correctamente."
          : "✅ Evento agendado correctamente."
      );

      setShowForm(false);
      setForm(formInicial);
      await fetchCitas();
    } catch (err) {
      console.error("❌ Error al crear evento:", err.response?.data || err.message);
      alert(err.response?.data?.message || "⚠️ No se pudo guardar el evento.");
    } finally {
      setLoading(false);
    }
  };

  const handleUpdateEstado = async (estado) => {
    if (!selectedEvent) return;

    try {
      setLoading(true);
      const token = getToken();

      await axios.patch(
        `http://localhost:5000/api/citas/${selectedEvent.id}/estado`,
        { estado },
        {
          headers: {
            Authorization: `Bearer ${token}`
          }
        }
      );

      const mensajes = {
        apartada: "🟢 Evento apartado correctamente.",
        pendiente: "🟡 Evento marcado como pendiente.",
        completada: "🔵 Evento marcado como completado.",
        cancelada: "❌ Evento cancelado. El horario quedó disponible."
      };

      alert(mensajes[estado] || "✅ Estado actualizado.");
      setShowEdit(false);
      setSelectedEvent(null);
      await fetchCitas();
    } catch (err) {
      console.error("❌ Error al actualizar estado:", err.response?.data || err.message);
      alert(err.response?.data?.message || "⚠️ No se pudo actualizar el evento.");
    } finally {
      setLoading(false);
    }
  };

  const handleSelectEvent = (event) => {
    setSelectedEvent(event);
    setShowEdit(true);
  };

  const cerrarDetalle = () => {
    setShowEdit(false);
    setSelectedEvent(null);
  };

  const eventPropGetter = (event) => {
    const estado = event.resource?.estado || "apartada";
    let backgroundColor = "#FFB300";

    if (estado === "apartada") backgroundColor = "#43A047";
    if (estado === "pendiente") backgroundColor = "#FFB300";
    if (estado === "completada") backgroundColor = "#1976D2";

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

  const esConsulta = form.tipo_evento === "consulta";

  return (
    <div style={pageStyle}>
      <div style={headerStyle}>
        <div>
          <h2 style={titleStyle}>📅 Agenda</h2>
          <p style={subtitleStyle}>
            Administra consultas, reuniones y actividades de tu agenda profesional.
          </p>
        </div>

        <button
          type="button"
          onClick={abrirNuevoEvento}
          style={newButton}
        >
          ➕ Nuevo evento
        </button>
      </div>

      <div style={legendStyle}>
        <Legend color="#43A047" text="Apartado" />
        <Legend color="#FFB300" text="Pendiente" />
        <Legend color="#1976D2" text="Completado" />
      </div>

      {loadingCitas && (
        <div style={loadingBox}>
          ⏳ Cargando agenda...
        </div>
      )}

      <Calendar
        localizer={localizer}
        events={events}
        startAccessor="start"
        endAccessor="end"
        views={["month", "week", "day", "agenda"]}
        view={view}
        date={date}
        onView={setView}
        onNavigate={setDate}
        style={calendarStyle}
        eventPropGetter={eventPropGetter}
        onSelectEvent={handleSelectEvent}
        messages={{
          today: "Hoy",
          previous: "Atrás",
          next: "Siguiente",
          month: "Mes",
          week: "Semana",
          day: "Día",
          agenda: "Agenda",
          date: "Fecha",
          time: "Hora",
          event: "Evento",
          noEventsInRange: "No hay eventos en este periodo."
        }}
      />

      <button
        type="button"
        onClick={onBack}
        style={backButton}
      >
        ← Volver
      </button>

      {showForm && (
        <div style={modalStyle}>
          <form onSubmit={handleCreate} style={formStyle}>
            <div style={modalHeader}>
              <div>
                <h3 style={modalTitle}>➕ Nuevo evento</h3>
                <p style={modalSubtitle}>
                  Registra una consulta o una actividad en tu agenda.
                </p>
              </div>
            </div>

            <label style={labelStyle}>
              Tipo de evento *
            </label>

            <select
              name="tipo_evento"
              value={form.tipo_evento}
              onChange={handleFormChange}
              required
              style={fieldStyle}
            >
              {TIPOS.map((tipo) => (
                <option key={tipo.value} value={tipo.value}>
                  {tipo.label}
                </option>
              ))}
            </select>

            {esConsulta ? (
              <>
                <label style={labelStyle}>
                  Paciente *
                </label>

                <select
                  name="id_paciente"
                  value={form.id_paciente}
                  onChange={handleFormChange}
                  required
                  disabled={loadingPacientes}
                  style={fieldStyle}
                >
                  <option value="">
                    {loadingPacientes
                      ? "Cargando pacientes..."
                      : "-- Seleccionar paciente --"}
                  </option>

                  {pacientes.map((p) => (
                    <option
                      key={p.id_paciente}
                      value={p.id_paciente}
                    >
                      {p.nombre}
                    </option>
                  ))}
                </select>
              </>
            ) : (
              <>
                <label style={labelStyle}>
                  Título *
                </label>

                <input
                  type="text"
                  name="titulo"
                  value={form.titulo}
                  onChange={handleFormChange}
                  placeholder={placeholderTitulo(form.tipo_evento)}
                  required
                  style={fieldStyle}
                />
              </>
            )}

            <div style={psychologistBox}>
              Psicólogo:{" "}
              <strong>
                {user?.nombre || "Usuario"}
              </strong>
            </div>

            <div style={twoColumns}>
              <div style={fieldGroup}>
                <label style={labelStyle}>
                  Fecha *
                </label>

                <input
                  type="date"
                  name="fecha"
                  value={form.fecha}
                  onChange={handleFormChange}
                  required
                  style={fieldStyle}
                />
              </div>

              <div style={fieldGroup}>
                <label style={labelStyle}>
                  Hora *
                </label>

                <input
                  type="time"
                  name="hora"
                  value={form.hora}
                  onChange={handleFormChange}
                  required
                  style={fieldStyle}
                />
              </div>
            </div>

            <label style={labelStyle}>
              Modalidad
            </label>

            <select
              name="modalidad"
              value={form.modalidad}
              onChange={handleFormChange}
              style={fieldStyle}
            >
              {MODALIDADES.map((modalidad) => (
                <option
                  key={modalidad.value}
                  value={modalidad.value}
                >
                  {modalidad.label}
                </option>
              ))}
            </select>

            <label style={labelStyle}>
              {esConsulta ? "Motivo de la consulta" : "Motivo / descripción"}
            </label>

            <input
              type="text"
              name="motivo"
              placeholder={
                esConsulta
                  ? "Motivo de la consulta"
                  : "Descripción breve del evento"
              }
              value={form.motivo}
              onChange={handleFormChange}
              style={fieldStyle}
            />

            <label style={labelStyle}>
              Notas
            </label>

            <textarea
              name="notas"
              placeholder="Notas adicionales (opcional)"
              value={form.notas}
              onChange={handleFormChange}
              style={textareaStyle}
            />

            <div style={actionsRow}>
              <button
                type="submit"
                disabled={loading || (esConsulta && loadingPacientes)}
                style={{
                  ...btnPrimary,
                  opacity:
                    loading || (esConsulta && loadingPacientes)
                      ? 0.6
                      : 1
                }}
              >
                {loading
                  ? "Guardando..."
                  : esConsulta
                    ? "Guardar cita"
                    : "Guardar evento"}
              </button>

              <button
                type="button"
                onClick={cerrarNuevoEvento}
                disabled={loading}
                style={btnCancel}
              >
                Cancelar
              </button>
            </div>
          </form>
        </div>
      )}

      {showEdit && selectedEvent && (
        <div style={modalStyle}>
          <div style={formStyle}>
            <h3 style={modalTitle}>
              {selectedEvent.resource.tipo_evento === "consulta"
                ? "📅 Detalle de la consulta"
                : "📌 Detalle del evento"}
            </h3>

            <div style={detailBox}>
              <Detail
                label="Tipo"
                value={nombreTipo(selectedEvent.resource.tipo_evento)}
              />

              {selectedEvent.resource.tipo_evento === "consulta" ? (
                <Detail
                  label="Paciente"
                  value={selectedEvent.resource.paciente || "No registrado"}
                />
              ) : (
                <Detail
                  label="Título"
                  value={selectedEvent.resource.titulo || "Sin título"}
                />
              )}

              <Detail
                label="Fecha"
                value={selectedEvent.resource.fecha}
              />

              <Detail
                label="Hora"
                value={selectedEvent.resource.hora}
              />

              <Detail
                label="Modalidad"
                value={nombreModalidad(selectedEvent.resource.modalidad)}
              />

              <Detail
                label={
                  selectedEvent.resource.tipo_evento === "consulta"
                    ? "Motivo"
                    : "Descripción"
                }
                value={selectedEvent.resource.motivo || "No registrada"}
              />

              <Detail
                label="Estado"
                value={selectedEvent.resource.estado || "apartada"}
              />

              {selectedEvent.resource.notas && (
                <Detail
                  label="Notas"
                  value={selectedEvent.resource.notas}
                />
              )}
            </div>

            <div style={stateActions}>
              <button
                type="button"
                disabled={loading}
                onClick={() => handleUpdateEstado("apartada")}
                style={btnGreen}
              >
                🟢 Apartar / Confirmar
              </button>

              <button
                type="button"
                disabled={loading}
                onClick={() => handleUpdateEstado("pendiente")}
                style={btnYellow}
              >
                🟡 Marcar pendiente
              </button>

              <button
                type="button"
                disabled={loading}
                onClick={() => handleUpdateEstado("completada")}
                style={btnBlue}
              >
                🔵 Marcar completado
              </button>

              <button
                type="button"
                disabled={loading}
                onClick={() => handleUpdateEstado("cancelada")}
                style={btnRed}
              >
                ❌ Cancelar
                <small style={smallBlock}>
                  El horario quedará disponible.
                </small>
              </button>
            </div>

            <button
              type="button"
              disabled={loading}
              onClick={cerrarDetalle}
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

function nombreTipo(tipo) {
  const encontrado = TIPOS.find((t) => t.value === tipo);
  return encontrado?.label || "Evento";
}

function nombreModalidad(modalidad) {
  if (modalidad === "presencial") return "Presencial";
  if (modalidad === "videollamada") return "Videollamada";
  if (modalidad === "otro") return "Otro";
  return "No registrada";
}

function placeholderTitulo(tipo) {
  if (tipo === "reunion") return "Ej. Reunión de equipo";
  if (tipo === "supervision") return "Ej. Supervisión clínica";
  if (tipo === "capacitacion") return "Ej. Taller de actualización";
  if (tipo === "administrativo") return "Ej. Elaboración de reportes";
  if (tipo === "personal") return "Ej. Bloqueo personal";
  return "Título del evento";
}

function Legend({ color, text }) {
  return (
    <div style={legendItem}>
      <span
        style={{
          ...legendDot,
          background: color
        }}
      />
      <span>{text}</span>
    </div>
  );
}

function Detail({ label, value }) {
  return (
    <p style={detailLine}>
      <strong>{label}:</strong>{" "}
      <span>{value}</span>
    </p>
  );
}

const pageStyle = {
  height: "80vh",
  padding: 20,
  boxSizing: "border-box"
};

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
  background: "linear-gradient(135deg, #43A047, #2E7D32)",
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

const calendarStyle = {
  height: 500,
  background: "#fff",
  borderRadius: "12px",
  padding: "10px"
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
  inset: 0,
  background: "rgba(0,0,0,0.5)",
  display: "flex",
  justifyContent: "center",
  alignItems: "center",
  zIndex: 2000,
  padding: "18px",
  boxSizing: "border-box"
};

const formStyle = {
  background: "#fff",
  padding: "24px",
  borderRadius: "14px",
  display: "flex",
  flexDirection: "column",
  gap: "9px",
  width: "430px",
  maxWidth: "95vw",
  maxHeight: "92vh",
  overflowY: "auto",
  boxSizing: "border-box",
  boxShadow: "0 18px 55px rgba(0,0,0,0.18)"
};

const modalHeader = {
  marginBottom: "4px"
};

const modalTitle = {
  margin: 0,
  color: "#263238"
};

const modalSubtitle = {
  margin: "5px 0 0",
  color: "#78909c",
  fontSize: "12px"
};

const labelStyle = {
  fontSize: "13px",
  fontWeight: "700",
  color: "#37474f"
};

const fieldStyle = {
  width: "100%",
  minHeight: "39px",
  padding: "8px 10px",
  border: "1px solid #cfd8dc",
  borderRadius: "8px",
  boxSizing: "border-box",
  background: "#fff"
};

const textareaStyle = {
  ...fieldStyle,
  minHeight: "76px",
  resize: "vertical"
};

const psychologistBox = {
  fontSize: "13px",
  color: "#607d8b",
  background: "#f7f9fc",
  borderRadius: "8px",
  padding: "9px 10px",
  margin: "2px 0"
};

const twoColumns = {
  display: "grid",
  gridTemplateColumns: "1fr 1fr",
  gap: "10px"
};

const fieldGroup = {
  display: "flex",
  flexDirection: "column",
  gap: "7px"
};

const actionsRow = {
  display: "flex",
  gap: "10px",
  marginTop: "10px"
};

const detailBox = {
  background: "#f7f9fc",
  border: "1px solid #e1e8ef",
  borderRadius: "10px",
  padding: "10px 14px",
  color: "#455a64"
};

const detailLine = {
  margin: "8px 0",
  lineHeight: "1.45"
};

const stateActions = {
  display: "flex",
  flexDirection: "column",
  gap: "8px",
  marginTop: "10px"
};

const btnPrimary = {
  flex: 1,
  padding: "11px",
  border: "none",
  borderRadius: "8px",
  background: "#4CAF50",
  color: "white",
  cursor: "pointer",
  fontWeight: "700"
};

const btnCancel = {
  flex: 1,
  padding: "11px",
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

const smallBlock = {
  display: "block",
  marginTop: "3px",
  opacity: 0.9
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
