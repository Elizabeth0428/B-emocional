// src/views/PruebasView.jsx
import React, { useEffect, useState, useRef } from "react";
import axios from "axios";
import DynamicTest from "../components/StandardTests/DynamicTest";
import { getToken } from "../services/AuthService";
import Webcam from "react-webcam";

const API = import.meta.env.VITE_API_URL; // ⭐ PRODUCCIÓN AUTOMÁTICA

export default function PruebasView({ onBack, idPaciente, token: tokenProp }) {
  const [pruebas, setPruebas] = useState([]);
  const [resultados, setResultados] = useState([]);
  const [selectedTest, setSelectedTest] = useState(null);
  const [errorMsg, setErrorMsg] = useState("");

  // 🎥 Estados de grabación
  const [recording, setRecording] = useState(false);
  const [mediaRecorder, setMediaRecorder] = useState(null);
  const [chunks, setChunks] = useState([]);
  const webcamRef = useRef(null);

  // 📌 Cargar pruebas + resultados
  const fetchData = async () => {
    const token = tokenProp || getToken();
    setErrorMsg("");

    if (!idPaciente) {
      setErrorMsg("⚠️ Primero selecciona un paciente antes de continuar.");
      return;
    }

    try {
      const resPruebas = await axios.get(`${API}/api/pruebas`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      setPruebas(Array.isArray(resPruebas.data) ? resPruebas.data : []);

      const resResultados = await axios.get(
        `${API}/api/resultados/${idPaciente}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setResultados(Array.isArray(resResultados.data) ? resResultados.data : []);
    } catch (err) {
      console.error("[PruebasView] Error al obtener datos:", err);
      const status = err?.response?.status;
      if (status === 401 || status === 403) {
        setErrorMsg("No autorizado. Inicia sesión nuevamente.");
      } else {
        setErrorMsg("No se pudieron cargar las pruebas o resultados.");
      }
      setPruebas([]);
      setResultados([]);
    }
  };

  useEffect(() => {
    fetchData();
  }, [idPaciente, tokenProp]);

  // 🎥 Grabación
  const startRecording = () => {
    if (webcamRef.current?.stream) {
      const recorder = new MediaRecorder(webcamRef.current.stream, {
        mimeType: "video/webm",
      });
      setMediaRecorder(recorder);
      setChunks([]);

      recorder.ondataavailable = (e) => {
        if (e.data.size > 0) {
          setChunks((prev) => [...prev, e.data]);
        }
      };

      recorder.onstop = async () => {
        const blob = new Blob(chunks, { type: "video/webm" });
        if (blob.size === 0) return;

        const formData = new FormData();
        formData.append("video", blob, "grabacion.webm");
        formData.append("id_sesion", selectedTest?.idSesion);

        try {
          await axios.post(`${API}/api/videos`, formData, {
            headers: { Authorization: `Bearer ${tokenProp || getToken()}` },
          });
          console.log("✅ Video guardado en backend");
        } catch (error) {
          console.error("❌ Error subiendo video:", error);
        }
      };

      recorder.start();
      setRecording(true);
    } else {
      alert("⚠️ No se detectó la cámara.");
    }
  };

  const stopRecording = () => {
    if (mediaRecorder) {
      mediaRecorder.stop();
      setRecording(false);
    }
  };

  // 📌 Crear sesión antes de prueba
  const iniciarPrueba = async (prueba) => {
    try {
      const token = tokenProp || getToken();
      const resSesion = await axios.post(
        `${API}/api/sesiones`,
        { id_paciente: idPaciente, observaciones: `Prueba: ${prueba.nombre}` },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      const idSesion = resSesion.data.id_sesion;
      console.log("✅ Sesión creada:", idSesion);
      setSelectedTest({ ...prueba, idSesion });
    } catch (err) {
      console.error("❌ Error al crear sesión:", err);
      alert("Error al crear sesión.");
    }
  };

  // 🔹 Vista de prueba seleccionada
  if (selectedTest) {
    return (
      <div style={container}>
        <h2 style={title}>📹 Grabación antes de iniciar la prueba</h2>
        <p style={subtitle}>
          Se grabará al paciente mientras responde la prueba{" "}
          <b>{selectedTest.nombre}</b>.
        </p>

        <Webcam
          ref={webcamRef}
          audio={true}
          style={{
            borderRadius: "12px",
            border: "2px solid #B2DFDB",
            marginBottom: "20px",
            width: "100%",
            maxWidth: "480px",
          }}
        />

        {!recording ? (
          <button style={button} onClick={startRecording}>
            ▶️ Iniciar grabación y prueba
          </button>
        ) : (
          <button
            style={{ ...button, backgroundColor: "#E74C3C" }}
            onClick={stopRecording}
          >
            ⏹️ Detener grabación
          </button>
        )}

        {recording && (
          <DynamicTest
            idPrueba={selectedTest.id_prueba}
            idSesion={selectedTest.idSesion}
            token={tokenProp || getToken()}
            onFinish={async () => {
              stopRecording();
              setSelectedTest(null);

              try {
                const token = tokenProp || getToken();
                const resReporte = await axios.post(
                  `${API}/api/reportes/generar`,
                  { id_sesion: selectedTest.idSesion },
                  { headers: { Authorization: `Bearer ${token}` } }
                );

                console.log("✅ Reporte generado:", resReporte.data);
                alert("Reporte generado correctamente.");
                fetchData();
              } catch (error) {
                console.error("❌ Error al generar reporte:", error);
                alert("Ocurrió un error al generar el reporte.");
              }
            }}
          />
        )}

        <button style={backButton} onClick={() => setSelectedTest(null)}>
          ⬅️ Cancelar
        </button>
      </div>
    );
  }

  // 🔹 Vista normal
  return (
    <div style={container}>
      <h2 style={title}>🧪 Pruebas psicológicas</h2>
      <p style={subtitle}>Selecciona una prueba para comenzar.</p>

      {errorMsg && <div style={errorBox}>{errorMsg}</div>}

      <div style={list}>
        {pruebas.length === 0 && !errorMsg && (
          <p style={{ textAlign: "center", color: "#666" }}>
            No hay pruebas disponibles en el sistema.
          </p>
        )}

        {pruebas.map((prueba) => {
          const realizada = resultados.some(
            (r) => r.id_prueba === prueba.id_prueba
          );

          return (
            <div key={prueba.id_prueba} style={card}>
              <h3>{prueba.nombre}</h3>
              <p>{prueba.descripcion}</p>
              <p>
                <b>Tipo:</b> {prueba.tipo}
              </p>

              {realizada ? (
                <div style={{ marginTop: "10px", color: "green", fontWeight: "600" }}>
                  ✅ Esta prueba ya fue realizada
                </div>
              ) : (
                <button style={button} onClick={() => iniciarPrueba(prueba)}>
                  ▶️ Iniciar prueba
                </button>
              )}
            </div>
          );
        })}
      </div>

      <button style={backButton} onClick={onBack}>
        ⬅️ Volver al Dashboard
      </button>
    </div>
  );
}

// === Estilos ===
const container = {
  maxWidth: "700px",
  margin: "30px auto",
  padding: "25px",
  background: "#fff",
  borderRadius: "16px",
  boxShadow: "0 8px 18px rgba(0,0,0,0.1)",
};

const title = { fontSize: "22px", fontWeight: "700", marginBottom: "10px" };
const subtitle = { fontSize: "15px", color: "#555", marginBottom: "20px" };

const errorBox = {
  background: "#fdecea",
  border: "1px solid #f5c6cb",
  color: "#8a1f2d",
  padding: "10px 12px",
  borderRadius: "8px",
  marginBottom: "16px",
};

const list = {
  display: "flex",
  flexDirection: "column",
  gap: "15px",
  marginBottom: "20px",
};

const card = {
  background: "#f9f9f9",
  padding: "15px",
  borderRadius: "10px",
  boxShadow: "0 2px 6px rgba(0,0,0,0.1)",
};

const button = {
  marginTop: "10px",
  padding: "10px 18px",
  border: "none",
  borderRadius: "8px",
  backgroundColor: "#5C6BC0",
  color: "white",
  fontWeight: "600",
  cursor: "pointer",
};

const backButton = {
  marginTop: "20px",
  padding: "12px 20px",
  border: "none",
  borderRadius: "8px",
  backgroundColor: "#E74C3C",
  color: "white",
  fontWeight: "600",
  cursor: "pointer",
};
