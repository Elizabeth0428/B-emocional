// src/views/VideollamadaPaciente.jsx

import React, { useEffect, useRef, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import Peer from "peerjs";

function VideollamadaPaciente() {
  const { sala } = useParams();
  const navigate = useNavigate();

  const [connected, setConnected] = useState(false);
  const [cameraStarted, setCameraStarted] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [error, setError] = useState("");

  const localVideoRef = useRef(null);
  const remoteVideoRef = useRef(null);
  const peerRef = useRef(null);
  const localStreamRef = useRef(null);
  const callRef = useRef(null);

  // =====================================================
  // INFORMACIÓN DE LA SALA
  // =====================================================

  const salaValida = sala?.startsWith("sala-");
  const partes = sala?.split("-") || [];

  const idSesion = partes[0] === "sala" ? partes[1] : null;
  const idPaciente = partes[0] === "sala" ? partes[2] : null;

  const peerIdSala = salaValida ? `mirrorsoul-${sala}` : null;

  // =====================================================
  // LIMPIAR STREAM
  // =====================================================

  const detenerStream = () => {
    if (localStreamRef.current) {
      localStreamRef.current
        .getTracks()
        .forEach(track => track.stop());

      localStreamRef.current = null;
    }

    if (localVideoRef.current) {
      localVideoRef.current.srcObject = null;
    }
  };

  // =====================================================
  // LIMPIAR LLAMADA
  // =====================================================

  const limpiarLlamada = () => {
    try {
      if (callRef.current) {
        callRef.current.close();
        callRef.current = null;
      }
    } catch (err) {
      console.error("❌ Error al cerrar llamada:", err);
    }
  };

  // =====================================================
  // CONECTAR CON PSICÓLOGO
  // =====================================================

  const conectarConPsicologo = async () => {
    if (!salaValida) {
      setError("El enlace de la videollamada no es válido.");
      return;
    }

    if (connecting || connected) return;

    try {
      setConnecting(true);
      setError("");

      console.log("📹 Paciente entrando a sala:", {
        sala,
        idSesion,
        idPaciente,
        peerIdSala
      });

      // =================================================
      // CÁMARA Y MICRÓFONO
      // =================================================

      const stream =
        await navigator.mediaDevices.getUserMedia({
          video: true,
          audio: true
        });

      localStreamRef.current = stream;

      if (localVideoRef.current) {
        localVideoRef.current.srcObject = stream;

        await localVideoRef.current
          .play()
          .catch(() => {});
      }

      setCameraStarted(true);

      // =================================================
      // PEERJS
      // =================================================

      const peer = new Peer(undefined, {
        host: window.location.hostname,
        port: 5000,
        path: "/peerjs/myapp",
        secure: false
      });

      peerRef.current = peer;

      // =================================================
      // PEER ABIERTO
      // =================================================

      peer.on("open", patientPeerId => {
        console.log(
          "✅ Paciente conectado a PeerJS:",
          patientPeerId
        );

        console.log(
          "📞 Llamando al psicólogo:",
          peerIdSala
        );

        const call = peer.call(
          peerIdSala,
          stream
        );

        if (!call) {
          throw new Error(
            "No fue posible iniciar la llamada."
          );
        }

        callRef.current = call;

        // ===============================================
        // RECIBIR VIDEO DEL PSICÓLOGO
        // ===============================================

        call.on(
          "stream",
          remoteStream => {
            console.log(
              "✅ Psicólogo conectado"
            );

            if (remoteVideoRef.current) {
              remoteVideoRef.current.srcObject =
                remoteStream;

              remoteVideoRef.current
                .play()
                .catch(() => {});
            }

            setConnected(true);
            setConnecting(false);
          }
        );

        // ===============================================
        // CERRAR LLAMADA
        // ===============================================

        call.on("close", () => {
          console.log(
            "📴 El psicólogo terminó la llamada"
          );

          setConnected(false);

          limpiarLlamada();
        });

        // ===============================================
        // ERROR DE LLAMADA
        // ===============================================

        call.on(
          "error",
          callError => {
            console.error(
              "❌ Error en la llamada:",
              callError
            );

            setError(
              "No se pudo establecer la videollamada."
            );

            setConnected(false);
            setConnecting(false);
          }
        );
      });

      // =================================================
      // ERROR PEERJS
      // =================================================

      peer.on(
        "error",
        peerError => {
          console.error(
            "❌ Error PeerJS:",
            peerError
          );

          if (
            peerError.type ===
            "peer-unavailable"
          ) {
            setError(
              "El psicólogo todavía no ha entrado a la sala. Espera a que abra la videollamada."
            );
          } else {
            setError(
              "No se pudo conectar con la sala de videollamada."
            );
          }

          setConnecting(false);
        }
      );

    } catch (err) {
      console.error(
        "❌ Error al entrar a la videollamada:",
        err
      );

      detenerStream();

      setError(
        err.message ||
        "No se pudo acceder a la cámara o micrófono."
      );

      setConnecting(false);
    }
  };

  // =====================================================
  // INICIAR AUTOMÁTICAMENTE
  // =====================================================

  useEffect(() => {
    if (!salaValida) {
      setError(
        "El enlace de videollamada no es válido."
      );

      return;
    }

    conectarConPsicologo();

    return () => {
      console.log(
        "🧹 Cerrando videollamada del paciente"
      );

      limpiarLlamada();
      detenerStream();

      if (peerRef.current) {
        peerRef.current.destroy();
        peerRef.current = null;
      }

      if (remoteVideoRef.current) {
        remoteVideoRef.current.srcObject = null;
      }
    };
  }, [sala]);

  // =====================================================
  // SALIR DE LA VIDEOLLAMADA
  //
  // ESTE BOTÓN ES PARA EL PACIENTE.
  // NO REGRESA AL EXPEDIENTE.
  // =====================================================

  const salirVideollamada = () => {
    limpiarLlamada();
    detenerStream();

    if (peerRef.current) {
      peerRef.current.destroy();
      peerRef.current = null;
    }

    setConnected(false);
    setConnecting(false);

    navigate(-1);
  };

  // =====================================================
  // SALA INVÁLIDA
  // =====================================================

  if (!salaValida) {
    return (
      <div style={page}>
        <div style={invalidCard}>
          <div style={invalidIcon}>
            ⚠️
          </div>

          <h2>
            Enlace inválido
          </h2>

          <p>
            No se pudo identificar la sala
            de videollamada.
          </p>

          <button
            type="button"
            onClick={() => navigate(-1)}
            style={backButton}
          >
            ⬅️ Volver
          </button>
        </div>
      </div>
    );
  }

  // =====================================================
  // INTERFAZ
  // =====================================================

  return (
    <div style={page}>
      <div style={container}>

        {/* =================================================
            ENCABEZADO
        ================================================= */}

        <div style={header}>
          <div style={iconContainer}>
            📹
          </div>

          <h1 style={title}>
            Videollamada
          </h1>

          <p style={subtitle}>
            Conexión segura con tu profesional.
          </p>
        </div>

        {/* =================================================
            INFORMACIÓN
        ================================================= */}

        <div style={infoCard}>

          <div style={infoItem}>
            <span style={infoLabel}>
              SESIÓN
            </span>

            <strong style={infoValue}>
              #{idSesion || "—"}
            </strong>
          </div>

          <div style={infoItem}>
            <span style={infoLabel}>
              PACIENTE
            </span>

            <strong style={infoValue}>
              #{idPaciente || "—"}
            </strong>
          </div>

        </div>

        {/* =================================================
            ESTADO
        ================================================= */}

        <div
          style={{
            ...statusBox,
            background: connected
              ? "#E8F5E9"
              : connecting
                ? "#FFF8E1"
                : error
                  ? "#FFEBEE"
                  : "#EEF4FF",

            color: connected
              ? "#2E7D32"
              : connecting
                ? "#8D6E00"
                : error
                  ? "#C62828"
                  : "#1565C0"
          }}
        >

          <span>
            {connected
              ? "🟢"
              : connecting
                ? "🟡"
                : error
                  ? "🔴"
                  : "🔵"}
          </span>

          <span>
            {connected
              ? "Videollamada conectada"
              : connecting
                ? "Conectando con el psicólogo..."
                : error
                  ? "No se pudo conectar"
                  : "Esperando conexión..."}
          </span>

        </div>

        {/* =================================================
            ERROR
        ================================================= */}

        {error && (
          <div style={errorBox}>

            <strong>
              ⚠️ Atención
            </strong>

            <p style={errorText}>
              {error}
            </p>

            <button
              type="button"
              onClick={() =>
                window.location.reload()
              }
              style={retryButton}
            >
              🔄 Intentar nuevamente
            </button>

          </div>
        )}

        {/* =================================================
            VIDEOS
        ================================================= */}

        <div style={videosGrid}>

          {/* PACIENTE */}

          <div style={videoCard}>

            <h3 style={patientTitle}>
              👤 Tú
            </h3>

            <video
              ref={localVideoRef}
              autoPlay
              muted
              playsInline
              style={video}
            />

          </div>

          {/* PSICÓLOGO */}

          <div style={videoCard}>

            <h3 style={psychologistTitle}>
              🧠 Psicólogo
            </h3>

            <video
              ref={remoteVideoRef}
              autoPlay
              playsInline
              style={video}
            />

          </div>

        </div>

        {/* =================================================
            AYUDA
        ================================================= */}

        <div style={helpBox}>

          <span>
            💡
          </span>

          <p style={helpText}>
            Mantén esta ventana abierta mientras
            realizas la videollamada.
          </p>

        </div>

        {/* =================================================
            SALIR
            ESTE ES EL BOTÓN DEL PACIENTE
        ================================================= */}

        <button
          type="button"
          onClick={salirVideollamada}
          style={backButton}
        >
          ⬅️ Salir de la videollamada
        </button>

      </div>
    </div>
  );
}

// =====================================================
// ESTILOS COMPACTOS
// =====================================================

const page = {
  minHeight: "100vh",
  padding: "18px 20px",
  boxSizing: "border-box",
  background: "linear-gradient(180deg,#E3F2FD,#BBDEFB)",
  fontFamily: "'Segoe UI',sans-serif"
};

const container = {
  width: "100%",
  maxWidth: "1100px",
  margin: "0 auto"
};

const header = {
  textAlign: "center",
  marginBottom: "12px"
};

const iconContainer = {
  width: "52px",
  height: "52px",
  margin: "0 auto 6px",
  borderRadius: "15px",
  background: "linear-gradient(135deg,#E3F2FD,#BBDEFB)",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "27px"
};

const title = {
  margin: 0,
  color: "#0D47A1",
  fontSize: "26px"
};

const subtitle = {
  margin: "4px 0 0",
  color: "#546E7A",
  fontSize: "13px"
};

const infoCard = {
  display: "flex",
  justifyContent: "center",
  gap: "50px",
  margin: "0 auto 12px",
  padding: "10px 15px",
  maxWidth: "450px",
  background: "#fff",
  borderRadius: "12px",
  boxShadow: "0 5px 16px rgba(30,70,120,.08)"
};

const infoItem = {
  textAlign: "center"
};

const infoLabel = {
  display: "block",
  color: "#78909C",
  fontSize: "9px",
  fontWeight: "700",
  letterSpacing: "1px",
  marginBottom: "3px"
};

const infoValue = {
  color: "#1565C0",
  fontSize: "16px"
};

const statusBox = {
  display: "flex",
  width: "fit-content",
  margin: "0 auto 12px",
  alignItems: "center",
  justifyContent: "center",
  gap: "7px",
  padding: "7px 14px",
  borderRadius: "18px",
  fontWeight: "700",
  fontSize: "13px"
};

const errorBox = {
  maxWidth: "700px",
  margin: "0 auto 12px",
  padding: "12px",
  background: "#FFEBEE",
  border: "1px solid #FFCDD2",
  borderRadius: "10px",
  color: "#C62828"
};

const errorText = {
  margin: "5px 0 9px",
  lineHeight: "1.4"
};

const retryButton = {
  border: "none",
  borderRadius: "7px",
  padding: "8px 13px",
  background: "#C62828",
  color: "#fff",
  fontWeight: "700",
  cursor: "pointer"
};

const videosGrid = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit,minmax(320px,1fr))",
  gap: "15px"
};

const videoCard = {
  background: "#fff",
  padding: "10px",
  borderRadius: "15px",
  boxShadow: "0 7px 20px rgba(0,0,0,.10)"
};

const video = {
  width: "100%",
  height: "280px",
  objectFit: "cover",
  background: "#263238",
  border: "2px solid #2196F3",
  borderRadius: "11px"
};

const patientTitle = {
  color: "#2E7D32",
  margin: "3px 0 7px",
  fontSize: "16px"
};

const psychologistTitle = {
  color: "#1565C0",
  margin: "3px 0 7px",
  fontSize: "16px"
};

const helpBox = {
  display: "flex",
  alignItems: "center",
  gap: "8px",
  maxWidth: "700px",
  margin: "12px auto 0",
  padding: "9px 12px",
  background: "#FFF8E1",
  border: "1px solid #FFE082",
  borderRadius: "10px",
  color: "#6D4C41",
  fontSize: "12px"
};

const helpText = {
  margin: 0
};

const backButton = {
  display: "block",
  width: "100%",
  maxWidth: "700px",
  margin: "12px auto 0",
  padding: "10px",
  border: "1px solid #D6E4F0",
  borderRadius: "9px",
  background: "#fff",
  color: "#546E7A",
  fontWeight: "700",
  cursor: "pointer"
};

const invalidCard = {
  background: "#fff",
  padding: "30px",
  borderRadius: "18px",
  textAlign: "center",
  boxShadow: "0 10px 30px rgba(0,0,0,.12)",
  maxWidth: "500px",
  margin: "60px auto"
};

const invalidIcon = {
  fontSize: "40px",
  marginBottom: "8px"
};

export default VideollamadaPaciente;