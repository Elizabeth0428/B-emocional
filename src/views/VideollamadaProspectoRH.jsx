// ==================================================
// src/views/VideollamadaProspectoRH.jsx
// ==================================================

import React, {
  useEffect,
  useRef,
  useState
} from "react";

import {
  useNavigate,
  useParams
} from "react-router-dom";

import Peer from "peerjs";


const API_URL =
  import.meta.env.VITE_API_URL ||
  "https://reflejoyalma.com";


function VideollamadaProspectoRH() {

  const {
    sala
  } = useParams();

  const navigate =
    useNavigate();


  // ==================================================
  // INFORMACIÓN DE SALA
  //
  // rh-ID_PROSPECTO-ID_ENTREVISTA-TIMESTAMP
  // ==================================================

  const partes =
    String(
      sala || ""
    )
      .split("-");


  const salaValida =
    partes[0] === "rh" &&
    partes.length >= 4;


  const idProspecto =
    salaValida
      ? partes[1]
      : null;


  const idEntrevista =
    salaValida
      ? partes[2]
      : null;


  // Debe coincidir exactamente con
  // SalaVideollamadaRH.jsx

  const peerIdSala =
    salaValida
      ? `mirrorsoul-rh-${sala}`
      : null;


  // ==================================================
  // ESTADOS
  // ==================================================

  const [
    conectado,
    setConectado
  ] = useState(false);


  const [
    conectando,
    setConectando
  ] = useState(false);


  const [
    camaraActiva,
    setCamaraActiva
  ] = useState(false);


  const [
    error,
    setError
  ] = useState("");


  const [
    mensaje,
    setMensaje
  ] = useState("");


  // ==================================================
  // REFERENCIAS
  // ==================================================

  const localVideoRef =
    useRef(null);


  const remoteVideoRef =
    useRef(null);


  const localStreamRef =
    useRef(null);


  const peerRef =
    useRef(null);


  const callRef =
    useRef(null);


  // ==================================================
  // CONFIGURACIÓN PEERJS
  // ==================================================

  const obtenerConfiguracionPeer =
    () => {

      try {

        const backend =
          new URL(
            API_URL
          );


        const secure =
          backend.protocol ===
          "https:";


        return {
          host:
            backend.hostname,

          port:
            backend.port
              ? Number(
                  backend.port
                )
              : secure
              ? 443
              : 80,

          path:
            "/peerjs/myapp",

          secure
        };


      } catch {

        const secure =
          window.location.protocol ===
          "https:";


        return {
          host:
            window.location.hostname,

          port:
            secure
              ? 443
              : 5000,

          path:
            "/peerjs/myapp",

          secure
        };

      }

    };


  // ==================================================
  // DETENER STREAM LOCAL
  // ==================================================

  const detenerStream =
    () => {

      if (
        localStreamRef.current
      ) {

        localStreamRef.current
          .getTracks()
          .forEach(
            track =>
              track.stop()
          );


        localStreamRef.current =
          null;

      }


      if (
        localVideoRef.current
      ) {

        localVideoRef.current
          .srcObject =
          null;

      }

    };


  // ==================================================
  // LIMPIAR LLAMADA
  // ==================================================

  const limpiarLlamada =
    () => {

      if (
        callRef.current
      ) {

        try {

          callRef.current
            .close();

        } catch {}


        callRef.current =
          null;

      }


      if (
        remoteVideoRef.current
      ) {

        remoteVideoRef.current
          .srcObject =
          null;

      }

    };


  // ==================================================
  // CONECTAR A RECURSOS HUMANOS
  // ==================================================

  const conectarConRH =
    async () => {

      if (
        !salaValida
      ) {

        setError(
          "El enlace de la videollamada no es válido."
        );

        return;

      }


      if (
        conectando ||
        conectado
      ) {

        return;

      }


      try {

        setConectando(
          true
        );

        setError("");

        setMensaje(
          "Solicitando acceso a cámara y micrófono..."
        );


        console.log(
          "📹 Prospecto entrando a sala RH:",
          {
            sala,
            idProspecto,
            idEntrevista,
            peerIdSala
          }
        );


        // ==================================================
        // CÁMARA Y MICRÓFONO
        // ==================================================

        const stream =
          await navigator
            .mediaDevices
            .getUserMedia({
              video:
                true,

              audio:
                true
            });


        localStreamRef.current =
          stream;


        if (
          localVideoRef.current
        ) {

          localVideoRef.current
            .srcObject =
            stream;


          await localVideoRef.current
            .play()
            .catch(
              () => {}
            );

        }


        setCamaraActiva(
          true
        );


        setMensaje(
          "Conectando con Recursos Humanos..."
        );


        // ==================================================
        // CREAR PEER DEL PROSPECTO
        // ==================================================

        const config =
          obtenerConfiguracionPeer();


        console.log(
          "📡 Configuración PeerJS prospecto RH:",
          config
        );


        const peer =
          new Peer(
            undefined,
            config
          );


        peerRef.current =
          peer;


        // ==================================================
        // PEER ABIERTO
        // ==================================================

        peer.on(
          "open",
          peerId => {

            console.log(
              "✅ Prospecto conectado a PeerJS:",
              peerId
            );


            console.log(
              "📞 Llamando a sala RH:",
              peerIdSala
            );


            const call =
              peer.call(
                peerIdSala,
                stream
              );


            if (!call) {

              setError(
                "No fue posible iniciar la videollamada."
              );

              setConectando(
                false
              );

              return;

            }


            callRef.current =
              call;


            // ==================================================
            // RECIBIR VIDEO DE RH
            // ==================================================

            call.on(
              "stream",
              remoteStream => {

                console.log(
                  "✅ Recursos Humanos conectado."
                );


                if (
                  remoteVideoRef.current
                ) {

                  remoteVideoRef.current
                    .srcObject =
                    remoteStream;


                  remoteVideoRef.current
                    .play()
                    .catch(
                      () => {}
                    );

                }


                setConectado(
                  true
                );


                setConectando(
                  false
                );


                setMensaje(
                  "✅ Videollamada conectada."
                );

              }
            );


            // ==================================================
            // RH TERMINÓ LLAMADA
            // ==================================================

            call.on(
              "close",
              () => {

                console.log(
                  "📴 Recursos Humanos terminó la llamada."
                );


                setConectado(
                  false
                );


                setConectando(
                  false
                );


                setMensaje(
                  "La entrevista por videollamada ha finalizado."
                );


                if (
                  remoteVideoRef.current
                ) {

                  remoteVideoRef.current
                    .srcObject =
                    null;

                }


                callRef.current =
                  null;

              }
            );


            // ==================================================
            // ERROR LLAMADA
            // ==================================================

            call.on(
              "error",
              callError => {

                console.error(
                  "❌ Error llamada RH:",
                  callError
                );


                setConectado(
                  false
                );


                setConectando(
                  false
                );


                setError(
                  "No se pudo establecer la videollamada."
                );

              }
            );

          }
        );


        // ==================================================
        // ERROR PEERJS
        // ==================================================

        peer.on(
          "error",
          peerError => {

            console.error(
              "❌ Error PeerJS prospecto RH:",
              peerError
            );


            if (
              peerError.type ===
              "peer-unavailable"
            ) {

              setError(
                "Recursos Humanos todavía no ha abierto la sala. Espera unos segundos y vuelve a intentarlo."
              );

            } else {

              setError(
                "No se pudo conectar con la sala de videollamada."
              );

            }


            setConectando(
              false
            );

          }
        );


        peer.on(
          "disconnected",
          () => {

            console.warn(
              "⚠️ Prospecto desconectado de PeerJS."
            );

          }
        );


      } catch (
        err
      ) {

        console.error(
          "❌ Error entrando a videollamada RH:",
          err
        );


        detenerStream();


        setConectando(
          false
        );


        if (
          err?.name ===
          "NotAllowedError"
        ) {

          setError(
            "Debes permitir el acceso a la cámara y al micrófono para entrar a la entrevista."
          );

          return;

        }


        setError(
          err.message ||
          "No fue posible acceder a la cámara o al micrófono."
        );

      }

    };


  // ==================================================
  // INICIAR AUTOMÁTICAMENTE
  // ==================================================

  useEffect(() => {

    if (
      !salaValida
    ) {

      setError(
        "El enlace de videollamada no es válido."
      );

      return;

    }


    conectarConRH();


    return () => {

      console.log(
        "🧹 Cerrando videollamada del prospecto RH"
      );


      limpiarLlamada();

      detenerStream();


      if (
        peerRef.current
      ) {

        try {

          peerRef.current
            .destroy();

        } catch {}


        peerRef.current =
          null;

      }

    };


    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    sala
  ]);


  // ==================================================
  // REINTENTAR
  // ==================================================

  const reintentar =
    () => {

      setError("");
      setMensaje("");


      limpiarLlamada();

      detenerStream();


      if (
        peerRef.current
      ) {

        try {

          peerRef.current
            .destroy();

        } catch {}


        peerRef.current =
          null;

      }


      setConectado(
        false
      );


      setConectando(
        false
      );


      setCamaraActiva(
        false
      );


      setTimeout(
        () => {

          conectarConRH();

        },
        300
      );

    };


  // ==================================================
  // SALIR
  // ==================================================

  const salirVideollamada =
    () => {

      const confirmar =
        window.confirm(
          "¿Deseas salir de la entrevista por videollamada?"
        );


      if (!confirmar) {

        return;

      }


      limpiarLlamada();

      detenerStream();


      if (
        peerRef.current
      ) {

        try {

          peerRef.current
            .destroy();

        } catch {}


        peerRef.current =
          null;

      }


      setConectado(
        false
      );


      setConectando(
        false
      );


      setCamaraActiva(
        false
      );


      navigate(
        "/"
      );

    };


  // ==================================================
  // SALA INVÁLIDA
  // ==================================================

  if (
    !salaValida
  ) {

    return (

      <div style={page}>

        <div style={invalidCard}>

          <div style={invalidIcon}>
            ⚠️
          </div>


          <h2 style={invalidTitle}>
            Enlace inválido
          </h2>


          <p style={invalidText}>
            No fue posible identificar
            la sala de entrevista.
          </p>

        </div>

      </div>

    );

  }


  // ==================================================
  // INTERFAZ
  // ==================================================

  return (

    <div style={page}>

      <div style={container}>


        {/* ==================================================
            HEADER
        ================================================== */}

        <div style={header}>

          <div style={logo}>
            🧠
          </div>


          <div>

            <div style={brand}>
              MirrorSoul
            </div>


            <h1 style={title}>
              🎥 Entrevista por videollamada
            </h1>


            <p style={subtitle}>
              Has sido invitado a una
              entrevista con Recursos Humanos.
            </p>

          </div>

        </div>


        {/* ==================================================
            PRIVACIDAD
        ================================================== */}

        <div style={privacyBox}>

          <div style={privacyIcon}>
            🔒
          </div>


          <div>

            <strong>
              Entrevista privada
            </strong>


            <p style={privacyText}>
              Este enlace corresponde únicamente
              a tu proceso de selección.
              No necesitas iniciar sesión.
            </p>

          </div>

        </div>


        {/* ==================================================
            IDENTIFICACIÓN
        ================================================== */}

        <div style={infoGrid}>

          <div style={infoItem}>

            <span style={infoLabel}>
              PROCESO
            </span>

            <strong style={infoValue}>
              #{idProspecto}
            </strong>

          </div>


          <div style={infoItem}>

            <span style={infoLabel}>
              ENTREVISTA
            </span>

            <strong style={infoValue}>
              #{idEntrevista}
            </strong>

          </div>

        </div>


        {/* ==================================================
            ESTADO
        ================================================== */}

        <div
          style={{
            ...statusBox,

            background:
              conectado
                ? "#ECF9EF"
                : conectando
                ? "#FFF7E6"
                : error
                ? "#FFF1F1"
                : "#EEF4FF",

            color:
              conectado
                ? "#27843A"
                : conectando
                ? "#B7791F"
                : error
                ? "#C62828"
                : "#2167D5"
          }}
        >

          <span style={statusIcon}>

            {conectado
              ? "🟢"
              : conectando
              ? "🟡"
              : error
              ? "🔴"
              : "🔵"}

          </span>


          <div>

            <strong>

              {conectado
                ? "Conectado con Recursos Humanos"
                : conectando
                ? "Conectando..."
                : error
                ? "No conectado"
                : "Preparando conexión"}

            </strong>


            {mensaje && (

              <div style={statusMessage}>
                {mensaje}
              </div>

            )}

          </div>

        </div>


        {/* ==================================================
            ERROR
        ================================================== */}

        {error && (

          <div style={errorBox}>

            <div>
              ⚠️ {error}
            </div>


            <button
              type="button"
              onClick={
                reintentar
              }
              style={retryButton}
            >
              🔄 Reintentar conexión
            </button>

          </div>

        )}


        {/* ==================================================
            VIDEOS
        ================================================== */}

        <div style={videosGrid}>


          {/* PROSPECTO */}

          <div style={videoCard}>

            <div style={videoLabel}>
              👤 Tú
            </div>


            <video
              ref={
                localVideoRef
              }
              muted
              autoPlay
              playsInline
              style={video}
            />


            {!camaraActiva && (

              <div style={placeholder}>

                <div style={placeholderIcon}>
                  📷
                </div>

                Preparando tu cámara...

              </div>

            )}

          </div>


          {/* RECURSOS HUMANOS */}

          <div style={videoCard}>

            <div style={videoLabel}>
              🧑‍💼 Recursos Humanos
            </div>


            <video
              ref={
                remoteVideoRef
              }
              autoPlay
              playsInline
              style={video}
            />


            {!conectado && (

              <div style={placeholder}>

                <div style={placeholderIcon}>
                  ⏳
                </div>

                Esperando a Recursos Humanos...

              </div>

            )}

          </div>

        </div>


        {/* ==================================================
            RECOMENDACIONES
        ================================================== */}

        <div style={tipsCard}>

          <h3 style={tipsTitle}>
            💡 Antes de comenzar
          </h3>


          <div style={tipsGrid}>

            <Tip
              icon="🎧"
              text="Utiliza audífonos si es posible."
            />

            <Tip
              icon="📶"
              text="Mantén una conexión estable a internet."
            />

            <Tip
              icon="💡"
              text="Busca un lugar con buena iluminación."
            />

            <Tip
              icon="🔕"
              text="Procura estar en un lugar tranquilo."
            />

          </div>

        </div>


        {/* ==================================================
            SALIR
        ================================================== */}

        <button
          type="button"
          onClick={
            salirVideollamada
          }
          style={exitButton}
        >
          📞 Salir de la entrevista
        </button>


        <footer style={footer}>

          <span>
            🧠 MirrorSoul
          </span>

          <span>
            Entrevista de Recursos Humanos
          </span>

        </footer>

      </div>

    </div>

  );

}


// ==================================================
// TIP
// ==================================================

function Tip({
  icon,
  text
}) {

  return (

    <div style={tip}>

      <span style={tipIcon}>
        {icon}
      </span>

      <span>
        {text}
      </span>

    </div>

  );

}


// ==================================================
// ESTILOS
// ==================================================

const page = {
  minHeight:
    "100vh",

  background:
    "#F6F8FC",

  padding:
    "35px 20px",

  boxSizing:
    "border-box",

  fontFamily:
    "'Segoe UI', Arial, sans-serif",

  color:
    "#263238"
};


const container = {
  maxWidth:
    "1100px",

  margin:
    "0 auto"
};


const header = {
  display:
    "flex",

  alignItems:
    "center",

  gap:
    "15px",

  marginBottom:
    "25px"
};


const logo = {
  width:
    "58px",

  height:
    "58px",

  borderRadius:
    "17px",

  background:
    "#F3E9FF",

  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  fontSize:
    "27px"
};


const brand = {
  color:
    "#7540D5",

  fontWeight:
    "800",

  fontSize:
    "12px",

  textTransform:
    "uppercase",

  letterSpacing:
    "1.2px"
};


const title = {
  margin:
    "3px 0",

  fontSize:
    "28px"
};


const subtitle = {
  margin:
    0,

  color:
    "#78909C"
};


const privacyBox = {
  display:
    "flex",

  gap:
    "13px",

  background:
    "#EEF4FF",

  border:
    "1px solid #D5E3FA",

  padding:
    "15px",

  borderRadius:
    "13px",

  marginBottom:
    "18px"
};


const privacyIcon = {
  fontSize:
    "22px"
};


const privacyText = {
  margin:
    "4px 0 0",

  color:
    "#607D8B",

  fontSize:
    "13px",

  lineHeight:
    1.5
};


const infoGrid = {
  display:
    "grid",

  gridTemplateColumns:
    "repeat(2,minmax(0,1fr))",

  gap:
    "12px",

  marginBottom:
    "18px"
};


const infoItem = {
  background:
    "#FFFFFF",

  border:
    "1px solid #E1E8EF",

  borderRadius:
    "12px",

  padding:
    "14px"
};


const infoLabel = {
  display:
    "block",

  fontSize:
    "10px",

  fontWeight:
    "800",

  color:
    "#90A4AE",

  marginBottom:
    "4px"
};


const infoValue = {
  color:
    "#455A64"
};


const statusBox = {
  display:
    "flex",

  alignItems:
    "center",

  gap:
    "11px",

  padding:
    "14px 16px",

  borderRadius:
    "12px",

  marginBottom:
    "18px"
};


const statusIcon = {
  fontSize:
    "18px"
};


const statusMessage = {
  marginTop:
    "3px",

  fontSize:
    "12px",

  opacity:
    0.85
};


const errorBox = {
  background:
    "#FFF1F1",

  border:
    "1px solid #F0B8B8",

  color:
    "#C62828",

  borderRadius:
    "12px",

  padding:
    "14px",

  marginBottom:
    "18px"
};


const retryButton = {
  border:
    "none",

  background:
    "#C62828",

  color:
    "#FFFFFF",

  borderRadius:
    "8px",

  padding:
    "9px 13px",

  marginTop:
    "10px",

  cursor:
    "pointer",

  fontWeight:
    "700"
};


const videosGrid = {
  display:
    "grid",

  gridTemplateColumns:
    "repeat(auto-fit,minmax(300px,1fr))",

  gap:
    "18px",

  marginBottom:
    "20px"
};


const videoCard = {
  position:
    "relative",

  minHeight:
    "320px",

  background:
    "#111827",

  borderRadius:
    "17px",

  overflow:
    "hidden",

  boxShadow:
    "0 6px 20px rgba(0,0,0,.14)"
};


const videoLabel = {
  position:
    "absolute",

  top:
    "12px",

  left:
    "12px",

  zIndex:
    3,

  background:
    "rgba(0,0,0,.55)",

  color:
    "#FFFFFF",

  padding:
    "7px 10px",

  borderRadius:
    "8px",

  fontSize:
    "12px",

  fontWeight:
    "800"
};


const video = {
  width:
    "100%",

  height:
    "100%",

  minHeight:
    "320px",

  objectFit:
    "cover",

  display:
    "block"
};


const placeholder = {
  position:
    "absolute",

  inset:
    0,

  display:
    "flex",

  flexDirection:
    "column",

  alignItems:
    "center",

  justifyContent:
    "center",

  gap:
    "8px",

  color:
    "#CBD5E1",

  fontSize:
    "14px",

  pointerEvents:
    "none"
};


const placeholderIcon = {
  fontSize:
    "32px"
};


const tipsCard = {
  background:
    "#FFFFFF",

  border:
    "1px solid #E1E8EF",

  borderRadius:
    "15px",

  padding:
    "18px",

  marginBottom:
    "18px"
};


const tipsTitle = {
  margin:
    "0 0 13px",

  fontSize:
    "17px"
};


const tipsGrid = {
  display:
    "grid",

  gridTemplateColumns:
    "repeat(auto-fit,minmax(210px,1fr))",

  gap:
    "10px"
};


const tip = {
  display:
    "flex",

  alignItems:
    "center",

  gap:
    "9px",

  background:
    "#F8FAFC",

  borderRadius:
    "9px",

  padding:
    "10px",

  color:
    "#607D8B",

  fontSize:
    "13px"
};


const tipIcon = {
  fontSize:
    "17px"
};


const exitButton = {
  width:
    "100%",

  border:
    "none",

  background:
    "#C62828",

  color:
    "#FFFFFF",

  padding:
    "13px",

  borderRadius:
    "10px",

  cursor:
    "pointer",

  fontWeight:
    "800",

  fontSize:
    "14px"
};


const footer = {
  display:
    "flex",

  justifyContent:
    "space-between",

  gap:
    "15px",

  flexWrap:
    "wrap",

  marginTop:
    "30px",

  paddingTop:
    "17px",

  borderTop:
    "1px solid #E1E8EF",

  color:
    "#90A4AE",

  fontSize:
    "12px"
};


const invalidCard = {
  maxWidth:
    "520px",

  margin:
    "100px auto",

  background:
    "#FFFFFF",

  border:
    "1px solid #E1E8EF",

  borderRadius:
    "17px",

  padding:
    "35px",

  textAlign:
    "center",

  boxShadow:
    "0 6px 20px rgba(30,60,90,.08)"
};


const invalidIcon = {
  fontSize:
    "45px",

  marginBottom:
    "10px"
};


const invalidTitle = {
  margin:
    "0 0 10px"
};


const invalidText = {
  color:
    "#78909C"
};


export default VideollamadaProspectoRH;