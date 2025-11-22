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
import { getCurrentUser, getToken } from "../services/AuthService";

// 📅 Configuración local
const locales = { es };
const localizer = dateFnsLocalizer({
  format,
  parse,
  startOfWeek,
  getDay,
  locales,
});

export default function CalendarView({ onBack }) {
  const [events, setEvents] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [showEdit, setShowEdit] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [pacientes, setPacientes] = useState([]);

  const user = getCurrentUser();

  const [form, setForm] = useState({
    id_paciente: "",
    fecha: "",
    hora: "",
    motivo: "",
    notas: "",
  });

  const [view, setView] = useState("month");
  const [date, setDate] = useState(new Date());

  useEffect(() => {
    fetchCitas();
    fetchPacientes();
  }, []);

  // ================================
  //   Cargar citas
  // ================================
  const fetchCitas = async () => {
    try {
      const token = getToken();
      const res = await axios.get("http://localhost:5000/api/citas", {
        headers: { Authorization: `Bearer ${token}` },
      });

      const toISODate = (d) => (typeof d === "string" ? d.slice(0, 10) : "");
      const toTime = (t) => (typeof t === "string" ? t.slice(0, 8) : "00:00:00");

      const eventos = res.data.map((c) => {
        const start = new Date(`${toISODate(c.fecha)}T${toTime(c.hora)}`);
        const end = new Date(start.getTime() + 60 * 60 * 1000);

        return {
          id: c.id_cita,
          title: `${c.paciente} - ${c.motivo}`,
          start,
          end,
          resource: {
            id_cita: c.id_cita,
            id_paciente: c.id_paciente, // 👈 ahora siempre está disponible
            paciente: c.paciente,
            motivo: c.motivo,
            estado: c.estado,
            notas: c.notas,
          },
        };
      });

      setEvents(eventos);
    } catch (err) {
      console.error("❌ Error al cargar citas:", err);
    }
  };

  // ================================
  //   Cargar pacientes
  // ================================
  const fetchPacientes = async () => {
    try {
      const token = getToken();
      const res = await axios.get("http://localhost:5000/api/pacientes", {
        headers: { Authorization: `Bearer ${token}` },
      });
      setPacientes(res.data);
    } catch (err) {
      console.error("❌ Error al cargar pacientes:", err);
    }
  };

  // ================================
  //   Crear cita
  // ================================
  const handleCreate = async (e) => {
    e.preventDefault();
    try {
      const token = getToken();
      const payload = { ...form, id_psicologo: user?.id_psicologo };
      await axios.post("http://localhost:5000/api/citas", payload, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setShowForm(false);
      setForm({ id_paciente: "", fecha: "", hora: "", motivo: "", notas: "" });
      fetchCitas();
    } catch (err) {
      console.error("❌ Error al crear cita:", err);
    }
  };

  // ================================
  //   Editar estado de cita
  // ================================
  const handleUpdateEstado = async (estado) => {
    try {
      const token = getToken();
      await axios.put(
  `http://localhost:5000/api/citas/${selectedEvent.resource.id_cita}/estado`,
  { estado },
  { headers: { Authorization: `Bearer ${token}` } }
);

      setShowEdit(false);
      setSelectedEvent(null);
      fetchCitas();
    } catch (err) {
      console.error("❌ Error al actualizar estado:", err);
    }
  };

  // ================================
//   Crear sesión desde cita
// ================================
const handleCrearSesion = async () => {
  try {
    const token = getToken();
    await axios.post(
      "http://localhost:5000/api/sesiones",
      {
        id_cita: selectedEvent.resource.id_cita,
        id_paciente: selectedEvent.resource.id_paciente,
      },
      { headers: { Authorization: `Bearer ${token}` } }
    );

    alert("✅ Sesión creada a partir de la cita");
    setShowEdit(false);
    setSelectedEvent(null);
  } catch (err) {
    console.error("❌ Error al crear sesión desde cita:", err.response?.data || err.message);
    alert("⚠️ No se pudo crear la sesión.");
  }
};


  return (
    <div style={{ height: "80vh", padding: 20 }}>
      <h2>📅 Agenda de Citas</h2>

      <button
        onClick={() => setShowForm(true)}
        style={{
          marginBottom: 10,
          padding: "10px 15px",
          borderRadius: "8px",
          border: "none",
          background: "#4CAF50",
          color: "white",
          cursor: "pointer",
        }}
      >
        ➕ Nueva Cita
      </button>

      <Calendar
        localizer={localizer}
        events={events}
        startAccessor="start"
        endAccessor="end"
        views={["month", "week", "day", "agenda"]}
        view={view}
        date={date}
        onView={(newView) => setView(newView)}
        onNavigate={(newDate) => setDate(newDate)}
        style={{ height: 500, background: "#fff", borderRadius: "8px" }}
        selectable
        onSelectEvent={(event) => {
          setSelectedEvent(event);
          setShowEdit(true);
        }}
        eventPropGetter={(event) => {
          let bg = "#64B5F6";
          if (event.resource.estado === "pendiente") bg = "#FFB300";
          if (event.resource.estado === "completada") bg = "#43A047";
          if (event.resource.estado === "cancelada") bg = "#E53935";
          return { style: { backgroundColor: bg, color: "white" } };
        }}
      />

      <button
        onClick={onBack}
        style={{
          marginTop: 20,
          padding: 10,
          background: "#333",
          color: "white",
          border: "none",
          borderRadius: "8px",
          cursor: "pointer",
        }}
      >
        ← Volver
      </button>

      {/* ================================
          Modal Nueva Cita
      ================================ */}
      {showForm && (
        <div style={modalStyle}>
          <form onSubmit={handleCreate} style={formStyle}>
            <h3>➕ Nueva Cita</h3>

            <select
              value={form.id_paciente}
              onChange={(e) =>
                setForm({ ...form, id_paciente: e.target.value })
              }
              required
            >
              <option value="">-- Seleccionar Paciente --</option>
              {pacientes.map((p) => (
                <option key={p.id_paciente} value={p.id_paciente}>
                  {p.nombre}
                </option>
              ))}
            </select>

            <p style={{ fontSize: "14px", color: "#666" }}>
              Psicólogo: <strong>{user?.nombre}</strong>
            </p>

            <input
              type="date"
              value={form.fecha}
              onChange={(e) => setForm({ ...form, fecha: e.target.value })}
              required
            />
            <input
              type="time"
              value={form.hora}
              onChange={(e) => setForm({ ...form, hora: e.target.value })}
              required
            />
            <input
              type="text"
              placeholder="Motivo"
              value={form.motivo}
              onChange={(e) => setForm({ ...form, motivo: e.target.value })}
              required
            />
            <textarea
              placeholder="Notas (opcional)"
              value={form.notas}
              onChange={(e) => setForm({ ...form, notas: e.target.value })}
            />

            <div style={{ display: "flex", gap: "10px", marginTop: 10 }}>
              <button type="submit" style={btnPrimary}>
                Guardar
              </button>
              <button
                type="button"
                onClick={() => setShowForm(false)}
                style={btnCancel}
              >
                Cancelar
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ================================
          Modal Editar Cita
      ================================ */}
      {showEdit && selectedEvent && (
        <div style={modalStyle}>
          <div style={formStyle}>
            <h3>✏️ Editar Cita</h3>
            <p>
              <strong>Paciente:</strong> {selectedEvent.resource.paciente}
            </p>
            <p>
              <strong>Motivo:</strong> {selectedEvent.resource.motivo}
            </p>
            <p>
              <strong>Estado actual:</strong>{" "}
              {selectedEvent.resource.estado || "pendiente"}
            </p>

            <div style={{ display: "flex", flexDirection: "column", gap: "8px", marginTop: 10 }}>
              <button
                onClick={() => handleUpdateEstado("completada")}
                style={btnPrimary}
              >
                ✅ Marcar Completada
              </button>
              <button
                onClick={() => handleUpdateEstado("cancelada")}
                style={btnCancel}
              >
                ❌ Cancelar
              </button>
              <button
                onClick={handleCrearSesion}
                style={{
                  padding: "10px",
                  border: "none",
                  borderRadius: "8px",
                  background: "#03A9F4",
                  color: "white",
                  cursor: "pointer",
                }}
              >
                📝 Crear Sesión desde esta Cita
              </button>
            </div>

            <button
              onClick={() => setShowEdit(false)}
              style={{
                marginTop: 15,
                padding: "8px",
                border: "none",
                borderRadius: "8px",
                background: "#9E9E9E",
                color: "white",
                cursor: "pointer",
              }}
            >
              Cerrar
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

// 🎨 Estilos
const modalStyle = {
  position: "fixed",
  top: 0,
  left: 0,
  right: 0,
  bottom: 0,
  background: "rgba(0,0,0,0.5)",
  display: "flex",
  justifyContent: "center",
  alignItems: "center",
  zIndex: 2000,
};

const formStyle = {
  background: "#fff",
  padding: 20,
  borderRadius: "10px",
  display: "flex",
  flexDirection: "column",
  gap: "10px",
  width: "320px",
};

const btnPrimary = {
  flex: 1,
  padding: "10px",
  border: "none",
  borderRadius: "8px",
  background: "#4CAF50",
  color: "white",
  cursor: "pointer",
};

const btnCancel = {
  flex: 1,
  padding: "10px",
  border: "none",
  borderRadius: "8px",
  background: "#E53935",
  color: "white",
  cursor: "pointer",
};
