import React, { useState } from "react";
import { getToken, getCurrentUser } from "../services/AuthService";
import HistorialForm from "./HistorialForm.jsx";

const RegistrarPaciente = ({ onBack }) => {
  const user = getCurrentUser();

  const [formData, setFormData] = useState({
    nombre: "",
    sexo: "",
    fecha_nacimiento: "",
    edad: "",
    correo: "",
    telefono: "",
    direccion: "",
    antecedentes: "",
    id_psicologo: user?.id_psicologo || null,
  });

  const [nuevoPaciente, setNuevoPaciente] = useState(null); // ✅ paciente recién creado

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async () => {
    try {
      if (!formData.nombre || !formData.sexo || !formData.fecha_nacimiento) {
        alert("⚠️ Debes llenar al menos nombre, sexo y fecha de nacimiento");
        return;
      }

      const token = getToken();
      const res = await fetch("http://localhost:5000/api/pacientes", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(formData),
      });

      if (!res.ok) throw new Error("Error al registrar paciente");
      const data = await res.json();

      alert("✅ Paciente registrado correctamente");

      // Guardamos al nuevo paciente para abrir el historial clínico
      setNuevoPaciente({
        id_paciente: data.id_paciente,
        nombre: formData.nombre,
      });
    } catch (err) {
      console.error("❌ Error al registrar paciente:", err);
      alert("❌ No se pudo registrar el paciente.");
    }
  };

  // 👉 Si ya registramos paciente → mostramos formulario de historial clínico
  if (nuevoPaciente) {
    return (
      <HistorialForm
        paciente={nuevoPaciente}
        onBack={onBack}
        onSave={() => {
          alert("✅ Historial clínico guardado");
          onBack(); // vuelve al dashboard después de guardar
        }}
      />
    );
  }

  return (
    <div style={styles.container}>
      <h2 style={styles.title}>👤 Registrar nuevo paciente</h2>

      <input
        type="text"
        name="nombre"
        placeholder="Nombre completo"
        value={formData.nombre}
        onChange={handleChange}
        style={styles.input}
      />

      <select
        name="sexo"
        value={formData.sexo}
        onChange={handleChange}
        style={styles.input}
      >
        <option value="">-- Selecciona sexo --</option>
        <option value="M">Masculino</option>
        <option value="F">Femenino</option>
        <option value="X">Otro</option>
      </select>

      <input
        type="date"
        name="fecha_nacimiento"
        placeholder="Fecha de nacimiento"
        value={formData.fecha_nacimiento}
        onChange={handleChange}
        style={styles.input}
      />

      <input
        type="number"
        name="edad"
        placeholder="Edad"
        value={formData.edad}
        onChange={handleChange}
        style={styles.input}
      />

      <input
        type="email"
        name="correo"
        placeholder="Correo electrónico"
        value={formData.correo}
        onChange={handleChange}
        style={styles.input}
      />

      <input
        type="text"
        name="telefono"
        placeholder="Teléfono"
        value={formData.telefono}
        onChange={handleChange}
        style={styles.input}
      />

      <input
        type="text"
        name="direccion"
        placeholder="Dirección"
        value={formData.direccion}
        onChange={handleChange}
        style={styles.input}
      />

      <textarea
        name="antecedentes"
        placeholder="Antecedentes relevantes"
        value={formData.antecedentes}
        onChange={handleChange}
        style={styles.textarea}
      />

      <div style={styles.buttons}>
        <button style={styles.btnSave} onClick={handleSubmit}>
          Registrar paciente
        </button>
        <button style={styles.btnCancel} onClick={onBack}>
          Cancelar
        </button>
      </div>
    </div>
  );
};

// 🎨 Estilos
const styles = {
  container: {
    background: "#fff",
    padding: 20,
    borderRadius: 10,
    boxShadow: "0 4px 15px rgba(0,0,0,0.1)",
    marginTop: 20,
    maxWidth: 600,
    margin: "0 auto",
  },
  title: { textAlign: "center", marginBottom: 20, color: "#0D47A1" },
  input: {
    width: "100%",
    padding: 10,
    marginBottom: 12,
    borderRadius: 6,
    border: "1px solid #ccc",
  },
  textarea: {
    width: "100%",
    padding: 10,
    marginBottom: 12,
    borderRadius: 6,
    border: "1px solid #ccc",
    minHeight: 60,
  },
  buttons: { display: "flex", justifyContent: "center", gap: "20px" },
  btnSave: {
    background: "#4CAF50",
    color: "white",
    padding: "10px 20px",
    border: "none",
    borderRadius: 8,
    cursor: "pointer",
  },
  btnCancel: {
    background: "#F44336",
    color: "white",
    padding: "10px 20px",
    border: "none",
    borderRadius: 8,
    cursor: "pointer",
  },
};

export default RegistrarPaciente;

