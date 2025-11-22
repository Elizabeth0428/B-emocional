// ✅ src/components/VideoRecorder.jsx
import React, { useRef, useState, useEffect } from "react";
import { getToken } from "../services/AuthService";

function VideoRecorder({ idSesion, tipo = "video", mediaRef, onSaved }) {
  const mediaRecorderRef = useRef(null);
  const chunksRef = useRef([]);
  const [recording, setRecording] = useState(false);
  const [time, setTime] = useState(0);

  // Cronómetro
  useEffect(() => {
    let interval;
    if (recording) {
      interval = setInterval(() => setTime((t) => t + 1), 1000);
    }
    return () => clearInterval(interval);
  }, [recording]);

  // ✅ Iniciar grabación usando el mismo video que se está mostrando
  const startRecording = () => {
    const stream = mediaRef?.current?.srcObject;
    if (!stream) return alert("⚠️ Primero inicia la videollamada.");

    try {
      const recorder = new MediaRecorder(stream, {
        mimeType: "video/webm;codecs=vp8,opus",
      });
      mediaRecorderRef.current = recorder;
      chunksRef.current = [];
      setTime(0);

      recorder.ondataavailable = (e) => {
        if (e.data && e.data.size > 0) {
          chunksRef.current.push(e.data);
        }
      };

      recorder.start(); // sin intervalo (más seguro)
      setRecording(true);
    } catch (err) {
      console.error("❌ Error iniciando grabación:", err);
      alert("No se pudo iniciar la grabación.");
    }
  };

  // ✅ Detener y enviar al backend
  const stopRecording = () => {
    setRecording(false);
    const recorder = mediaRecorderRef.current;
    if (!recorder) return;

    recorder.stop();
    recorder.onstop = async () => {
      const blob = new Blob(chunksRef.current, { type: "video/webm" });
      if (blob.size < 2000) {
        console.warn("⚠️ Archivo muy pequeño / corrupto.");
        return;
      }

      const file = new File([blob], `video-${idSesion}-${Date.now()}.webm`, {
        type: "video/webm",
      });

      const formData = new FormData();
      formData.append("file", file);
      formData.append("id_sesion", idSesion);
      formData.append("tipo", tipo);

      try {
        const res = await fetch(`http://${window.location.hostname}:5000/api/multimedia`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${getToken()}`,
          },
          body: formData,
        });

        if (!res.ok) throw new Error("Error al subir video");
        alert("✅ Video guardado exitosamente");
      } catch (err) {
        console.error("❌ Error guardando video:", err);
        alert("No se pudo guardar el video.");
      }
    };
  };

  return (
    <div style={{ marginTop: "10px", textAlign: "center" }}>
      {!recording ? (
        <button onClick={startRecording} style={btnStart}>🎥 Iniciar Grabación</button>
      ) : (
        <button onClick={stopRecording} style={btnStop}>⛔ Detener</button>
      )}
      {recording && <p style={{ color: "red" }}>⏺ Grabando... {time}s</p>}
    </div>
  );
}

const btnStart = { background: "green", color: "white", padding: "10px", borderRadius: "8px" };
const btnStop = { background: "red", color: "white", padding: "10px", borderRadius: "8px" };

export default VideoRecorder;
