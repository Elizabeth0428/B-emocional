import React, { useState } from "react";
import { getToken } from "../services/AuthService";

const HistorialForm = ({ paciente, onBack, onSave }) => {
  const [formData, setFormData] = useState({
    estado_civil: "",
    ocupacion: "",
    escolaridad: "",
    antecedentes_personales: "",
    antecedentes_familiares: "",
    antecedentes_patologicos: "",
    antecedentes_emocionales: "",
    habitos: "",
    alergias: "",
    enfermedades_previas: "",
    medicamentos_actuales: "",
    cirugias: "",
    historia_desarrollo: "",
    evaluacion_inicial: "",
    diagnostico_inicial: "",
    tratamiento_inicial: "",
    notas: "",
  });

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async () => {
    try {
      if (!paciente?.id_paciente) {
        alert("⚠️ No se puede guardar historial sin un paciente válido.");
        return;
      }

      const token = getToken();
      const res = await fetch("http://localhost:5000/api/historial-inicial", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ ...formData, id_paciente: paciente.id_paciente }),
      });

      if (!res.ok) throw new Error("Error al guardar historial");
      const data = await res.json();

      alert("✅ Historial clínico guardado correctamente");

      if (onSave) onSave(data);
      else if (onBack) onBack();
    } catch (err) {
      console.error("❌ Error al guardar historial:", err);
      alert("❌ No se pudo guardar el historial clínico.");
    }
  };

  return (
    <div style={styles.container}>
      <h2 style={styles.title}>🩺 Historial clínico inicial</h2>
      <p>
        <strong>Paciente:</strong>{" "}
        <span style={{ color: "green" }}>{paciente?.nombre || "Desconocido"}</span>
      </p>

      {/* Datos generales */}
      <input
        name="estado_civil"
        placeholder="Estado civil"
        value={formData.estado_civil}
        onChange={handleChange}
        style={styles.input}
      />
      <input
        name="ocupacion"
        placeholder="Ocupación"
        value={formData.ocupacion}
        onChange={handleChange}
        style={styles.input}
      />
      <input
        name="escolaridad"
        placeholder="Escolaridad"
        value={formData.escolaridad}
        onChange={handleChange}
        style={styles.input}
      />

      {/* Antecedentes */}
      <textarea
        name="antecedentes_personales"
        placeholder="Antecedentes personales"
        value={formData.antecedentes_personales}
        onChange={handleChange}
        style={styles.textarea}
      />
      <textarea
        name="antecedentes_familiares"
        placeholder="Antecedentes familiares"
        value={formData.antecedentes_familiares}
        onChange={handleChange}
        style={styles.textarea}
      />
      <textarea
        name="antecedentes_patologicos"
        placeholder="Antecedentes patológicos"
        value={formData.antecedentes_patologicos}
        onChange={handleChange}
        style={styles.textarea}
      />
      <textarea
        name="antecedentes_emocionales"
        placeholder="Antecedentes emocionales"
        value={formData.antecedentes_emocionales}
        onChange={handleChange}
        style={styles.textarea}
      />
      <textarea
        name="habitos"
        placeholder="Hábitos"
        value={formData.habitos}
        onChange={handleChange}
        style={styles.textarea}
      />
      <textarea
        name="alergias"
        placeholder="Alergias"
        value={formData.alergias}
        onChange={handleChange}
        style={styles.textarea}
      />
      <textarea
        name="enfermedades_previas"
        placeholder="Enfermedades previas"
        value={formData.enfermedades_previas}
        onChange={handleChange}
        style={styles.textarea}
      />
      <textarea
        name="medicamentos_actuales"
        placeholder="Medicamentos actuales"
        value={formData.medicamentos_actuales}
        onChange={handleChange}
        style={styles.textarea}
      />
      <textarea
        name="cirugias"
        placeholder="Cirugías"
        value={formData.cirugias}
        onChange={handleChange}
        style={styles.textarea}
      />

      {/* Evaluación */}
      <textarea
        name="historia_desarrollo"
        placeholder="Historia del desarrollo"
        value={formData.historia_desarrollo}
        onChange={handleChange}
        style={styles.textarea}
      />
      <textarea
        name="evaluacion_inicial"
        placeholder="Evaluación inicial"
        value={formData.evaluacion_inicial}
        onChange={handleChange}
        style={styles.textarea}
      />
      <textarea
        name="diagnostico_inicial"
        placeholder="Diagnóstico inicial"
        value={formData.diagnostico_inicial}
        onChange={handleChange}
        style={styles.textarea}
      />
      <textarea
        name="tratamiento_inicial"
        placeholder="Tratamiento inicial"
        value={formData.tratamiento_inicial}
        onChange={handleChange}
        style={styles.textarea}
      />

      {/* Notas */}
      <textarea
        name="notas"
        placeholder="Notas adicionales"
        value={formData.notas}
        onChange={handleChange}
        style={styles.textarea}
      />

      <div style={styles.buttons}>
        <button style={styles.btnSave} onClick={handleSubmit}>
          Guardar historial
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
    padding: 24,
    borderRadius: 12,
    boxShadow: "0 4px 15px rgba(0,0,0,0.1)",
    marginTop: 20,
    maxWidth: 700,
    margin: "0 auto",
  },
  title: { textAlign: "center", color: "#1E3A8A", marginBottom: 20 },
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
    borderRadius: 8,
    border: "1px solid #ccc",
    marginTop: 8,
    marginBottom: 12,
    minHeight: "60px",
  },
  buttons: {
    marginTop: 20,
    display: "flex",
    justifyContent: "center",
    gap: "20px",
  },
  btnSave: {
    backgroundColor: "#16A34A",
    color: "white",
    padding: "10px 20px",
    border: "none",
    borderRadius: 8,
    cursor: "pointer",
    fontWeight: "600",
  },
  btnCancel: {
    backgroundColor: "#DC2626",
    color: "white",
    padding: "10px 20px",
    border: "none",
    borderRadius: 8,
    cursor: "pointer",
    fontWeight: "600",
  },
};

export default HistorialForm;
