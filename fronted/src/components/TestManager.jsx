// src/components/TestManager.jsx
import { useState, useEffect } from "react";
import axios from "axios";
import DynamicTest from "./StandardTests/DynamicTest.jsx";
import { getToken } from "../services/AuthService";

// ⭐ API dinámico
const API = import.meta.env.VITE_API_URL;

export default function TestManager({ onFinish, onCancel, pacienteId, idSesion }) {
  const [pruebas, setPruebas] = useState([]);
  const [step, setStep] = useState(0);
  const [loading, setLoading] = useState(true);
  const [respuestas, setRespuestas] = useState({});

  // 🔹 Traer pruebas del backend
  useEffect(() => {
    const fetchPruebas = async () => {
      try {
        const token = getToken();
        const res = await axios.get(`${API}/api/pruebas`, {
          headers: { Authorization: `Bearer ${token}` },
        });

        console.log("Pruebas recibidas del backend:", res.data);
        setPruebas(res.data);
      } catch (err) {
        console.error("❌ Error al obtener pruebas:", err);
        setPruebas([]);
      } finally {
        setLoading(false);
      }
    };
    fetchPruebas();
  }, []);

  // 🔹 Reiniciar cuando cambie paciente o sesión
  useEffect(() => {
    setStep(0);
    setRespuestas({});
  }, [pacienteId, idSesion]);

  // 🔹 Guardar resultados de una prueba
  const handleFinishTest = (pruebaId, result) => {
    setRespuestas((prev) => ({ ...prev, [pruebaId]: result }));

    if (step + 1 < pruebas.length) {
      setStep((prev) => prev + 1);
    } else {
      if (onFinish) {
        onFinish({ ...respuestas, [pruebaId]: result });
      }
    }
  };

  // 🔹 Mientras carga
  if (loading) return <p>Cargando pruebas...</p>;

  // 🔹 Si hay pruebas por aplicar
  if (step < pruebas.length) {
    const prueba = pruebas[step];
    return (
      <div style={{ textAlign: "center" }}>
        <p style={{ fontWeight: "600", marginBottom: 10 }}>
          Progreso: {step + 1} de {pruebas.length}
        </p>

        <h3>{prueba.nombre}</h3>
        <p>{prueba.descripcion}</p>

        <DynamicTest
          idPrueba={prueba.id_prueba}
          idSesion={idSesion}            // ⬅️ se usa ahora en producción
          token={getToken()}
          onFinish={(result) => handleFinishTest(prueba.id_prueba, result)}
        />

        <button
          onClick={() => {
            setStep(0);
            setRespuestas({});
            if (onCancel) onCancel();
          }}
          style={{
            marginTop: "15px",
            padding: "10px 18px",
            borderRadius: "8px",
            backgroundColor: "#E74C3C",
            color: "white",
            border: "none",
            cursor: "pointer",
            fontWeight: "600",
          }}
        >
          Reiniciar pruebas
        </button>
      </div>
    );
  }

  // 🔹 Cuando ya no hay más pruebas
  return (
    <div style={{ textAlign: "center", marginTop: 20 }}>
      <h3>Todas las pruebas han sido completadas</h3>
      <p>Puedes generar el reporte preliminar con los resultados.</p>

      <div style={{ marginTop: 15 }}>
        <button
          onClick={() => onFinish(respuestas)}
          style={{
            marginRight: "10px",
            padding: "12px 20px",
            borderRadius: "8px",
            backgroundColor: "#4CAF50",
            color: "white",
            border: "none",
            cursor: "pointer",
            fontWeight: "600",
          }}
        >
          Generar reporte
        </button>

        <button
          onClick={() => {
            setStep(0);
            setRespuestas({});
            if (onCancel) onCancel();
          }}
          style={{
            padding: "12px 20px",
            borderRadius: "8px",
            backgroundColor: "#E74C3C",
            color: "white",
            border: "none",
            cursor: "pointer",
            fontWeight: "600",
          }}
        >
          Reiniciar pruebas
        </button>
      </div>
    </div>
  );
}
