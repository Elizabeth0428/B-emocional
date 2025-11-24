// src/views/SalaVideollamada.jsx
import React, { useEffect, useRef, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import Peer from "peerjs";
import VideoRecorder from "../components/VideoRecorder";
import { getToken } from "../services/AuthService";

const API = import.meta.env.VITE_API_URL; // ⭐ PRODUCCIÓN

function SalaVideollamada() {
  const { sala } = useParams();
  const navigate = useNavigate();

  const [idSesion] = sala.split("-");
  const [connected, setConnected] = useState(false);

  const localVideoRef = useRef(null);
  const remoteVideoRef = useRef(null);
  const peerRef = useRef(null);

  useEffect(() => {
    const peer = new Peer(undefined, {
      host: API.replace("https://", "").replace("http://", ""),
      port: API.startsWith("https") ? 443 : 5000,
      path: "/peerjs/myapp",
      secure: API.startsWith("https"),
    });

    peer.on("open", (id) => {
      console.log("📹 Sala creada:", id, "para sesión:", idSesion);
    });

    peer.on("call", (call) => {
      navigator.mediaDevices
        .getUserMedia({ video: true, audio: true })
        .then((stream) => {
          if (localVideoRef.current) {
            localVideoRef.current.srcObject = stream;
            localVideoRef.current.play().catch((err) => console.error("⚠️ Error local:", err));
          }

          call.answer(stream);

          call.on("stream", (remoteStream) => {
            if (remoteVideoRef.current) {
              remoteVideoRef.current.srcObject = remoteStream;
              remoteVideoRef.current.play().catch((err) => console.error("⚠️ Error remote:", err));
            }
            setConnected(true);
          });
        })
        .catch((err) => {
          console.error("❌ Error cámara/micrófono:", err);
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

      console.log("🎥 Cámara lista para sesión:", idSesion);
    } catch (err) {
      alert("No se pudo acceder a la cámara/micrófono");
      console.error(err);
    }
  };

  const finalizarSesion = async () => {
    try {
      const res = await fetch(`${API}/api/sesiones/${idSesion}/finalizar`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${getToken()}`
        }
      });

      if (!res.ok) throw new Error("Error al finalizar sesión");

      alert("✅ Sesión finalizada correctamente");

      if (localVideoRef.current?.srcObject) {
        localVideoRef.current.srcObject.getTracks().forEach((t) => t.stop());
      }
      if (remoteVideoRef.current?.srcObject) {
        remoteVideoRef.current.srcObject.getTracks().forEach((t) => t.stop());
      }

      navigate(-1);
    } catch (err) {
      console.error("❌ Error finalizando sesión:", err);
      alert("❌ No se pudo finalizar la sesión");
    }
  };

  return (
    <div style={styles.page}>
      <h2 style={styles.title}>👨‍⚕️ Videollamada - Sala {sala}</h2>

      <button onClick={iniciarVideollamada} style={styles.btnPrimary}>
        🚀 Iniciar Videollamada
      </button>

      <div style={styles.videoRow}>
        <video ref={localVideoRef} muted autoPlay playsInline style={styles.localVideo} />
        <video ref={remoteVideoRef} autoPlay playsInline style={styles.remoteVideo} />
      </div>

      <div style={{ marginTop: "30px" }}>
        <h3>🎥 Grabar Sesión</h3>

        {idSesion ? (
          <VideoRecorder idSesion={idSesion} tipo="video" mediaRef={localVideoRef} />
        ) : (
          <p style={{ color: "#888" }}>⚠️ Primero inicia la videollamada para crear la sesión.</p>
        )}

        {!connected && <p style={{ color: "#888", marginTop: "10px" }}>⏳ Esperando conexión...</p>}
      </div>

      <button onClick={finalizarSesion} style={styles.btnDanger}>
        🛑 Finalizar Sesión
      </button>
    </div>
  );
}

const styles = {
  page: {
    padding: 20,
    textAlign: "center",
    background: "linear-gradient(180deg, #e3f2fd, #bbdefb)",
    minHeight: "100vh",
  },
  title: { color: "#0D47A1" },
  videoRow: {
    display: "flex",
    justifyContent: "center",
    gap: "20px",
    marginTop: "20px",
  },
  localVideo: {
    width: "300px",
    border: "2px solid #4CAF50",
    borderRadius: "12px",
  },
  remoteVideo: {
    width: "300px",
    border: "2px solid #f44336",
    borderRadius: "12px",
  },
  btnPrimary: {
    padding: "10px 20px",
    marginBottom: "20px",
    backgroundColor: "#03A9F4",
    border: "none",
    borderRadius: "8px",
    color: "#fff",
    fontWeight: "bold",
    cursor: "pointer",
  },
  btnDanger: {
    marginTop: "30px",
    padding: "10px 20px",
    backgroundColor: "#E53935",
    border: "none",
    borderRadius: "8px",
    color: "#fff",
    fontWeight: "bold",
    cursor: "pointer",
  },
};

export default SalaVideollamada;
