// src/components/FaceScanner.jsx
import React, { useRef, useState } from "react";
import { getToken } from "../services/AuthService";

const FaceScanner = ({ pacienteId, pruebaId }) => {
  const videoRef = useRef(null);
  const mediaRecorderRef = useRef(null);
  const [chunks, setChunks] = useState([]);
  const [recording, setRecording] = useState(false);

  const startRecording = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
      videoRef.current.srcObject = stream;

      const mediaRecorder = new MediaRecorder(stream, { mimeType: "video/webm" });
      mediaRecorderRef.current = mediaRecorder;

      setChunks([]);

      mediaRecorder.ondataavailable = (event) => {
        if (event.data.size > 0) {
          setChunks((prev) => [...prev, event.data]);
        }
      };

      mediaRecorder.start();
      setRecording(true);
    } catch (err) {
      console.error("❌ Error al iniciar cámara:", err);
      alert("No se pudo acceder a la cámara/micrófono.");
    }
  };

  const stopRecording = async () => {
    mediaRecorderRef.current.stop();
    setRecording(false);

    const blob = new Blob(chunks, { type: "video/webm" });
    setChunks([]);

    if (blob.size === 0) {
      console.error("⚠️ Grabación vacía (0 bytes)");
      alert("El archivo no se grabó correctamente.");
      return;
    }

    const file = new File([blob], `video-grabacion-${Date.now()}.webm`, { type: blob.type });

    const formData = new FormData();
    formData.append("file", file); // 👈 siempre "file"
    formData.append("id_paciente", pacienteId);
    formData.append("id_prueba", pruebaId);

    try {
      const token = getToken();
      const API_URL = `http://${window.location.hostname}:5000`; // 👈 dinámico
      const res = await fetch(`${API_URL}/api/videos`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`, // seguridad
        },
        body: formData,
      });

      if (!res.ok) throw new Error("Error al guardar video");
      alert("🎥 Video guardado en el servidor");
    } catch (err) {
      console.error("❌ Error al subir video:", err);
      alert("Error al guardar video en el servidor.");
    }
  };

  return (
    <div style={{ textAlign: "center" }}>
      <video
        ref={videoRef}
        autoPlay
        playsInline
        muted
        style={{
          width: "100%",
          maxWidth: 500,
          borderRadius: "12px",
          border: "2px solid #90CAF9",
          marginBottom: 20,
        }}
      />
      {!recording ? (
        <button onClick={startRecording} style={buttonStyle}>
          ▶️ Iniciar grabación
        </button>
      ) : (
        <button onClick={stopRecording} style={{ ...buttonStyle, backgroundColor: "#E74C3C" }}>
          ⏹️ Detener y guardar
        </button>
      )}
    </div>
  );
};

const buttonStyle = {
  padding: "12px 20px",
  border: "none",
  borderRadius: "8px",
  backgroundColor: "#03A9F4",
  color: "white",
  fontWeight: "600",
  cursor: "pointer",
  boxShadow: "0 4px 10px rgba(0,0,0,0.2)",
};

export default FaceScanner;
