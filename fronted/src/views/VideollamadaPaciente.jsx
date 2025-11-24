// src/views/VideollamadaPaciente.jsx
import React, { useEffect, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import Peer from "peerjs";

// ⭐ URL de API dinámica para producción/dominio/localhost
const API = import.meta.env.VITE_API_URL;

// ⭐ Detectamos si estamos en HTTPS para configurar PeerJS
const isSecure = window.location.protocol === "https:";
const peerPort = isSecure ? 443 : 5000; // Render usa 443, local usa 5000

function VideollamadaPaciente() {
  const { sala } = useParams();
  const localVideoRef = useRef(null);
  const remoteVideoRef = useRef(null);
  const peerRef = useRef(null);
  const currentStreamRef = useRef(null);

  const [conectado, setConectado] = useState(false);

  useEffect(() => {
    const peer = new Peer(undefined, {
      host: window.location.hostname,        // ⭐ Funciona en local y dominio
      port: peerPort,                        // ⭐ Determinado dinámicamente
      path: "/peerjs/myapp",
      secure: isSecure,                      // ⭐ true en HTTPS, false en HTTP
    });

    peerRef.current = peer;

    peer.on("open", (id) => {
      console.log("🙋 Paciente conectado con PeerID:", id);
    });

    return () => {
      if (peerRef.current) peerRef.current.destroy();
    };
  }, [sala]);

  const iniciarSesion = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: true,
        audio: true,
      });
      currentStreamRef.current = stream;

      if (localVideoRef.current) {
        localVideoRef.current.srcObject = stream;
        await localVideoRef.current.play();
      }

      const call = peerRef.current.call(sala, stream);

      call.on("stream", (remoteStream) => {
        if (remoteVideoRef.current) {
          remoteVideoRef.current.srcObject = remoteStream;
          remoteVideoRef.current.play().catch(console.error);
        }
      });

      setConectado(true);
    } catch (err) {
      console.error("⚠️ Error al iniciar cámara:", err);
      alert("No se pudo acceder a cámara/micrófono");
    }
  };

  const finalizarSesion = () => {
    if (currentStreamRef.current) {
      currentStreamRef.current.getTracks().forEach((track) => track.stop());
    }

    if (localVideoRef.current) localVideoRef.current.srcObject = null;
    if (remoteVideoRef.current) remoteVideoRef.current.srcObject = null;

    if (peerRef.current) peerRef.current.disconnect();

    setConectado(false);
    console.log("🛑 Sesión finalizada (paciente)");
  };

  return (
    <div
      style={{
        minHeight: "100vh",
        display: "flex",
        justifyContent: "center",
        alignItems: "center",
        background: "linear-gradient(135deg, #74ebd5 0%, #ACB6E5 100%)",
        fontFamily: "Segoe UI, sans-serif",
      }}
    >
      <div
        style={{
          background: "white",
          borderRadius: "16px",
          padding: "30px",
          width: "80%",
          maxWidth: "900px",
          boxShadow: "0 8px 25px rgba(0,0,0,0.15)",
          textAlign: "center",
        }}
      >
        <h2 style={{ color: "#0D47A1", marginBottom: "10px" }}>
          🙋 Bienvenido a la videollamada
        </h2>
        <p style={{ color: "#555", marginBottom: "20px" }}>Sala: {sala}</p>

        {!conectado ? (
          <button
            onClick={iniciarSesion}
            style={btnStyle("#4CAF50")}
          >
            🚀 Conectarse
          </button>
        ) : (
          <button
            onClick={finalizarSesion}
            style={btnStyle("#f44336")}
          >
            🛑 Finalizar Sesión
          </button>
        )}

        <div
          style={{
            display: "flex",
            justifyContent: "center",
            gap: "20px",
            marginTop: "30px",
          }}
        >
          <video
            ref={localVideoRef}
            muted
            autoPlay
            playsInline
            style={videoCard("#4CAF50")}
          />
          <video
            ref={remoteVideoRef}
            autoPlay
            playsInline
            style={videoCard("#f44336")}
          />
        </div>

        <p style={{ marginTop: "20px", color: "#666" }}>
          El psicólogo está a cargo de grabar la sesión.
        </p>
      </div>
    </div>
  );
}

// === Estilos ===
const btnStyle = (bg) => ({
  padding: "12px 24px",
  backgroundColor: bg,
  border: "none",
  borderRadius: "8px",
  color: "#fff",
  fontWeight: "bold",
  cursor: "pointer",
  transition: "0.3s",
  boxShadow: "0 4px 10px rgba(0,0,0,0.2)",
});

const videoCard = (borderColor) => ({
  width: "320px",
  height: "240px",
  border: `3px solid ${borderColor}`,
  borderRadius: "12px",
  boxShadow: "0 4px 12px rgba(0,0,0,0.15)",
  background: "#000",
});

export default VideollamadaPaciente;
