// src/components/PatientContext.jsx
import { createContext, useContext, useState, useEffect } from "react";

const PatientContext = createContext();

export const usePatient = () => useContext(PatientContext);

export const PatientProvider = ({ children }) => {
  const [paciente, setPacienteState] = useState(null); // Solo el ID del paciente
  const [respuestas, setRespuestas] = useState({});
  const [emociones, setEmociones] = useState([]);

  // 🔹 Cargar paciente guardado en localStorage (si existe)
  useEffect(() => {
    const saved = localStorage.getItem("paciente");
    if (saved) {
      try {
        const parsed = JSON.parse(saved);
        if (typeof parsed === "number") {
          setPacienteState(parsed);
        } else {
          console.warn("⚠️ Paciente en localStorage no era un número:", parsed);
          localStorage.removeItem("paciente");
        }
      } catch (err) {
        console.error("❌ Error al parsear paciente desde localStorage:", err);
        localStorage.removeItem("paciente");
      }
    }
  }, []);

  // 🔹 Guardar paciente en localStorage cuando cambie
  useEffect(() => {
    if (paciente !== null) {
      localStorage.setItem("paciente", JSON.stringify(paciente));
    } else {
      localStorage.removeItem("paciente");
    }
  }, [paciente]);

  // 🔹 Setter seguro: siempre guardar solo el id_paciente
  const setPaciente = (p) => {
    if (typeof p === "object" && p.id_paciente) {
      setPacienteState(Number(p.id_paciente));
    } else if (typeof p === "number") {
      setPacienteState(p);
    } else {
      console.error("❌ Valor inválido para setPaciente:", p);
    }
  };

  // 🔹 Debug solo en modo desarrollo
  useEffect(() => {
    if (process.env.NODE_ENV === "development") {
      console.log("👤 Paciente ID:", paciente);
      console.log("📝 Respuestas:", respuestas);
      console.log("😊 Emociones:", emociones);
    }
  }, [paciente, respuestas, emociones]);

  return (
    <PatientContext.Provider
      value={{
        paciente,       // ahora siempre será un número
        setPaciente,    // setter seguro
        respuestas,
        setRespuestas,
        emociones,
        setEmociones,
      }}
    >
      {children}
    </PatientContext.Provider>
  );
};
