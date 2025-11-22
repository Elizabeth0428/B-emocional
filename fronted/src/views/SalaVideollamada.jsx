// src/views/SalaVideollamada.jsx
import React, { useEffect, useRef, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import Peer from "peerjs";
import VideoRecorder from "../components/VideoRecorder";
import { getToken } from "../services/AuthService";

function SalaVideollamada() {
  const { sala } = useParams();
  const navigate = useNavigate();

  // Extraemos el idSesion del primer segmento antes del guion
  const [idSesion] = sala.split("-");
  const [connected, setConnected] = useState(false);

  const localVideoRef = useRef(null);
  const remoteVideoRef = useRef(null);
  const peerRef = useRef(null);

  useEffect(() => {
    const peer = new Peer(undefined, {
      host: window.location.hostname,
      port: 5000,
      path: "/peerjs/myapp",
      secure: false,
    });

    peer.on("open", (id) => {
      console.log("📹 Psicólogo creó la sala con ID:", id, "para sesión:", idSesion);
    });

    peer.on("call", (call) => {
      navigator.mediaDevices
        .getUserMedia({ video: true, audio: true })
        .then((stream) => {
          if (localVideoRef.current) {
            localVideoRef.current.srcObject = stream;
            localVideoRef.current.play().catch((err) => console.error("⚠️ Error play local:", err));
          }
          call.answer(stream);
          call.on("stream", (remoteStream) => {
            if (remoteVideoRef.current) {
              remoteVideoRef.current.srcObject = remoteStream;
              remoteVideoRef.current.play().catch((err) => console.error("⚠️ Error play remote:", err));
            }
            setConnected(true);
          });
        })
        .catch((err) => {
          console.error("❌ Error al acceder a la cámara/micrófono:", err);
        });
    });

    peerRef.current = peer;
    return () => peer.destroy();
  }, [sala, idSesion]);

  const iniciarVideollamada = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
      if (localVideoRef.current) {
        localVideoRef.current.srcObject = stream;
        await localVideoRef.current.play();
      }
      console.log("🎥 Cámara iniciada, lista para sesión:", idSesion);
    } catch (err) {
      console.error("❌ Error al iniciar cámara:", err);
      alert("No se pudo acceder a la cámara/micrófono");
    }
  };

  const finalizarSesion = async () => {
    try {
      const res = await fetch(`http://localhost:5000/api/sesiones/${idSesion}/finalizar`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${getToken()}`
        }
      });

      if (!res.ok) throw new Error("Error al finalizar sesión");

      alert("✅ Sesión finalizada correctamente");

      // 🔹 Detener cámara y micrófono
      if (localVideoRef.current?.srcObject) {
        localVideoRef.current.srcObject.getTracks().forEach(track => track.stop());
      }
      if (remoteVideoRef.current?.srcObject) {
        remoteVideoRef.current.srcObject.getTracks().forEach(track => track.stop());
      }

      navigate(-1); // volver a detalle del paciente
    } catch (err) {
      console.error("❌ Error al finalizar sesión:", err);
      alert("❌ No se pudo finalizar la sesión");
    }
  };

  return (
    <div style={{ padding: 20, textAlign: "center", background: "linear-gradient(180deg, #e3f2fd, #bbdefb)", minHeight: "100vh" }}>
      <h2 style={{ color: "#0D47A1" }}>👨‍⚕️ Videollamada - Sala {sala}</h2>

      <button
        onClick={iniciarVideollamada}
        style={{
          padding: "10px 20px",
          marginBottom: "20px",
          backgroundColor: "#03A9F4",
          border: "none",
          borderRadius: "8px",
          color: "#fff",
          fontWeight: "bold",
          cursor: "pointer",
        }}
      >
        🚀 Iniciar Videollamada
      </button>

      <div style={{ display: "flex", justifyContent: "center", gap: "20px", marginTop: "20px" }}>
        <video
          ref={localVideoRef}
          muted
          autoPlay
          playsInline
          style={{ width: "300px", border: "2px solid #4CAF50", borderRadius: "12px" }}
        />
        <video
          ref={remoteVideoRef}
          autoPlay
          playsInline
          style={{ width: "300px", border: "2px solid #f44336", borderRadius: "12px" }}
        />
      </div>
      
<div style={{ marginTop: "30px" }}>
  <h3>🎥 Grabar Sesión</h3>
  {idSesion ? (
    <VideoRecorder idSesion={idSesion} tipo="video" mediaRef={localVideoRef} />
  ) : (
    <p style={{ color: "#888" }}>⚠️ Primero inicia la videollamada para crear la sesión.</p>
  )}

  {!connected && (
    <p style={{ color: "#888", marginTop: "10px" }}>⏳ Esperando conexión con el paciente...</p>
  )}
</div>



      {/* 🔴 Botón de Finalizar Sesión */}
      <button
        onClick={finalizarSesion}
        style={{
          marginTop: "30px",
          padding: "10px 20px",
          backgroundColor: "#E53935",
          border: "none",
          borderRadius: "8px",
          color: "#fff",
          fontWeight: "bold",
          cursor: "pointer",
        }}
      >
        🛑 Finalizar Sesión
      </button>
    </div>
  );
}

export default SalaVideollamada;
