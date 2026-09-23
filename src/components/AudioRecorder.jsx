// src/components/AudioRecorder.jsx
import React, { useState, useRef } from "react";
import { motion } from "framer-motion";
import { FaMicrophone, FaStop } from "react-icons/fa";
import { getToken } from "../services/AuthService";

const AudioRecorder = ({ idSesion }) => {
  const [isRecording, setIsRecording] = useState(false);
  const mediaRecorderRef = useRef(null);
  const audioChunksRef = useRef([]);

  const startRecording = async () => {
    if (!idSesion) {
      alert("⚠️ No hay sesión activa para asociar el audio.");
      return;
    }

    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      alert("⚠️ Tu navegador no soporta grabación de audio.");
      return;
    }

    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      mediaRecorderRef.current = new MediaRecorder(stream, { mimeType: "audio/webm" });
      audioChunksRef.current = [];

      mediaRecorderRef.current.ondataavailable = (e) => {
        if (e.data.size > 0) audioChunksRef.current.push(e.data);
      };

      mediaRecorderRef.current.onstop = async () => {
        const audioBlob = new Blob(audioChunksRef.current, { type: "audio/webm" });
        audioChunksRef.current = [];

        if (audioBlob.size === 0) {
          alert("⚠️ El audio no se grabó correctamente.");
          return;
        }

        const file = new File([audioBlob], `audio-grabacion-${Date.now()}.webm`, { type: audioBlob.type });

        const formData = new FormData();
        formData.append("file", file); // 👈 siempre "file"
        formData.append("id_sesion", idSesion);

        try {
          const token = getToken();
          const API_URL = `https://reflejoyalma.com`; // 👈 dinámico
          const res = await fetch(`${API_URL}/api/audios`, {
            method: "POST",
            headers: { Authorization: `Bearer ${token}` },
            body: formData,
          });

          if (!res.ok) throw new Error("Error al guardar audio");
          alert("🎤 Audio guardado en el servidor!");
        } catch (err) {
          console.error("❌ Error al guardar audio:", err);
          alert("Error al guardar audio.");
        }
      };

      mediaRecorderRef.current.start();
      setIsRecording(true);
    } catch (err) {
      alert("❌ No se pudo acceder al micrófono.");
      console.error(err);
    }
  };

  const stopRecording = () => {
    if (mediaRecorderRef.current) {
      mediaRecorderRef.current.stop();
      setIsRecording(false);
    }
  };

  return (
    <div style={{ marginTop: 20, textAlign: "center" }}>
      {!isRecording ? (
        <motion.button
          onClick={startRecording}
          whileHover={{ scale: 1.1 }}
          whileTap={{ scale: 0.95 }}
          style={buttonStart}
        >
          <FaMicrophone /> Iniciar Grabación
        </motion.button>
      ) : (
        <motion.button
          onClick={stopRecording}
          animate={{ scale: [1, 1.1, 1] }}
          transition={{ repeat: Infinity, duration: 1.2 }}
          style={buttonStop}
        >
          <FaStop /> Detener Grabación
        </motion.button>
      )}
    </div>
  );
};

// 🎨 Estilos
const buttonStart = {
  backgroundColor: "#4CAF50",
  color: "white",
  padding: "14px 26px",
  border: "none",
  borderRadius: "50px",
  fontWeight: "600",
  fontSize: "16px",
  cursor: "pointer",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  gap: "10px",
  boxShadow: "0 4px 12px rgba(76, 175, 80, 0.4)",
};

const buttonStop = {
  backgroundColor: "#E53935",
  color: "white",
  padding: "14px 26px",
  border: "none",
  borderRadius: "50px",
  fontWeight: "600",
  fontSize: "16px",
  cursor: "pointer",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  gap: "10px",
  boxShadow: "0 4px 14px rgba(229, 57, 53, 0.5)",
};

export default AudioRecorder;
