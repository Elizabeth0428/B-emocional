// src/views/SalaVideollamada.jsx

import React, {
  useEffect,
  useRef,
  useState
} from "react";

import {
  useParams,
  useNavigate
} from "react-router-dom";

import Peer from "peerjs";

import VideoRecorder
  from "../components/VideoRecorder";

import {
  getToken
} from "../services/AuthService";


function SalaVideollamada() {

  const params = useParams();

  const navigate =
    useNavigate();


  /* ==================================================
     OBTENER PARÁMETROS

     Primero intentamos obtenerlos desde React Router.

     Si por alguna razón la ruta no los entrega,
     los recuperamos directamente desde window.location.
  ================================================== */

  let sala =
    params.sala || null;

  let idPaciente =
    params.idPaciente || null;


  /* ==================================================
     RECUPERAR DATOS DIRECTAMENTE DE LA URL

     Permite soportar:

     /SalaVideollamada/nueva/4

     /SalaVideollamada/sala-272-4-123456
  ================================================== */

  const pathname =
    window.location.pathname;


  const segmentos =
    pathname
      .split("/")
      .filter(Boolean);


  if (
    !sala &&
    segmentos[0]?.toLowerCase() ===
      "salavideollamada"
  ) {

    if (
      segmentos[1] === "nueva"
    ) {

      sala =
        "nueva";

      idPaciente =
        idPaciente ||
        segmentos[2] ||
        null;

    } else if (
      segmentos[1]
    ) {

      sala =
        segmentos[1];

    }

  }


  /* ==================================================
     MODO INICIAL

     /SalaVideollamada/nueva/:idPaciente

     Todavía no existe una sala real.

     Aquí se crea/reutiliza:

     paciente
       ↓
     sesión
       ↓
     sala
       ↓
     links
       ↓
     sala real
  ================================================== */

  const modoInicial =
    sala === "nueva";


  /* ==================================================
     ESTADOS
  ================================================== */

  const [
    preparando,
    setPreparando
  ] = useState(
    modoInicial
  );


  const [
    errorInicial,
    setErrorInicial
  ] = useState("");


  const [
    connected,
    setConnected
  ] = useState(false);


  const [
    cameraStarted,
    setCameraStarted
  ] = useState(false);


  const [
    finishing,
    setFinishing
  ] = useState(false);


  /* ==================================================
     REFERENCIAS
  ================================================== */

  const localVideoRef =
    useRef(null);


  const remoteVideoRef =
    useRef(null);


  const peerRef =
    useRef(null);


  const localStreamRef =
    useRef(null);


  const callRef =
    useRef(null);


  /* ==================================================
     EXTRAER DATOS DE LA SALA

     Formato:

     sala-ID_SESION-ID_PACIENTE-TIMESTAMP

     Ejemplo:

     sala-272-4-1755781234567
  ================================================== */

  const partes =
  sala?.split("-") || [];

const idSesion =
  partes[0] === "sala"
    ? partes[1]
    : null;

const idPacienteSala =
  partes[0] === "sala"
    ? partes[2]
    : null;

const codigoUnico =
  partes[0] === "sala"
    ? partes.slice(3).join("-")
    : null;


  /* ==================================================
     ID PEER DEL PSICÓLOGO

     Debe coincidir con el ID que usará
     el paciente para llamar.

     Ejemplo:

     sala-272-4-123456

     →

     mirrorsoul-sala-272-4-123456
  ================================================== */

  const peerIdSala =
    sala &&
    sala.startsWith("sala-")
      ? `mirrorsoul-${sala}`
      : null;


  /* ==================================================
     LINK DEL PACIENTE

     Se construye a partir de la misma sala.

     Ejemplo:

     http://localhost:5175/
     videollamada-paciente/
     sala-272-4-123456
  ================================================== */

  const linkPaciente =
    sala &&
    sala.startsWith("sala-")
      ? `${window.location.origin}/videollamada-paciente/${sala}`
      : "";


  /* ==================================================
     DEPURACIÓN
  ================================================== */

  useEffect(() => {

    console.log(
      "🔎 DATOS ACTUALES DE SALA:",
      {
        pathname,
        params,
        sala,
        idPaciente,
        modoInicial,
        idSesion,
        idPacienteSala,
        peerIdSala,
        linkPaciente
      }
    );

  }, [
    pathname,
    params,
    sala,
    idPaciente,
    modoInicial,
    idSesion,
    idPacienteSala,
    peerIdSala,
    linkPaciente
  ]);


  /* ==================================================
     PREPARAR VIDEOLLAMADA

     SOLO EN:

     /SalaVideollamada/nueva/:idPaciente
  ================================================== */

  useEffect(() => {

    if (!modoInicial) {

      return;

    }


    if (!idPaciente) {

      console.error(
        "❌ No se encontró idPaciente:",
        {
          params,
          pathname,
          idPaciente
        }
      );


      setErrorInicial(
        "No se pudo identificar al paciente."
      );


      setPreparando(
        false
      );


      return;

    }


    const prepararSala =
      async () => {

        try {

          const token =
            getToken();


          if (!token) {

            throw new Error(
              "No existe una sesión de usuario válida."
            );

          }


          const API_URL =
            `http://${window.location.hostname}:5000`;


          console.log(
            "📹 Iniciando videollamada para paciente:",
            idPaciente
          );


          console.log(
            "📡 Solicitando sesión y sala al backend..."
          );


          /* ==========================================
             CREAR / RECUPERAR SESIÓN Y SALA
          ========================================== */

          const res =
            await fetch(
              `${API_URL}/api/sesiones/iniciar/${idPaciente}`,
              {

                method:
                  "POST",

                headers: {

                  "Content-Type":
                    "application/json",

                  Authorization:
                    `Bearer ${token}`

                }

              }
            );


          let data = {};


          try {

            data =
              await res.json();

          } catch (jsonError) {

            console.error(
              "❌ El backend no devolvió JSON:",
              jsonError
            );

          }


          console.log(
            "📡 Respuesta iniciar videollamada:",
            data
          );


          if (!res.ok) {

            throw new Error(
              data.message ||
              "No se pudo iniciar la videollamada."
            );

          }


          if (!data.sala) {

            throw new Error(
              "El backend no devolvió una sala válida."
            );

          }


          if (!data.id_sesion) {

            throw new Error(
              "El backend no devolvió el ID de la sesión."
            );

          }


          console.log(
            "✅ Videollamada preparada:",
            {

              idSesion:
                data.id_sesion,

              idPaciente:
                data.id_paciente,

              sala:
                data.sala,

              linkPaciente:
                data.link_paciente,

              linkPsicologo:
                data.link_psicologo

            }
          );


          /* ==========================================
             IR A LA SALA REAL
          ========================================== */

          navigate(
            `/SalaVideollamada/${data.sala}`,
            {
              replace:
                true
            }
          );

        } catch (error) {

          console.error(
            "❌ Error al preparar videollamada:",
            error
          );


          setErrorInicial(
            error.message ||
            "No se pudo preparar la videollamada."
          );


          setPreparando(
            false
          );

        }

      };


    prepararSala();


  }, [
    modoInicial,
    idPaciente,
    navigate
  ]);


  /* ==================================================
     CONECTAR PSICÓLOGO A PEERJS

     SOLO CUANDO EXISTE UNA SALA REAL.
  ================================================== */

  useEffect(() => {

    if (
      modoInicial ||
      !idSesion ||
      !idPacienteSala ||
      !peerIdSala
    ) {

      return;

    }


    console.log(
      "📹 Iniciando sala del psicólogo:",
      {

        sala,

        idSesion,

        idPaciente:
          idPacienteSala,

        codigoUnico,

        peerId:
          peerIdSala

      }
    );


    /* ================================================
       CREAR PEER CON ID FIJO
    ================================================ */

    const peer =
      new Peer(
        peerIdSala,
        {

          host:
            window.location.hostname,

          port:
            5000,

          path:
            "/peerjs/myapp",

          secure:
            false

        }
      );


    peerRef.current =
      peer;


    /* ================================================
       PEER ABIERTO
    ================================================ */

    peer.on(
      "open",
      (peerId) => {

        console.log(
          "✅ Psicólogo conectado a PeerJS"
        );


        console.log(
          "📡 Peer ID:",
          peerId
        );


        console.log(
          "📹 Sala:",
          sala
        );


        console.log(
          "🧠 Sesión:",
          idSesion
        );


        console.log(
          "👤 Paciente:",
          idPacienteSala
        );

      }
    );


    /* ================================================
       PACIENTE LLAMA AL PSICÓLOGO
    ================================================ */

    peer.on(
      "call",
      async (call) => {

        console.log(
          "📞 El paciente está llamando..."
        );


        try {

          let stream =
            localStreamRef.current;


          /* ==========================================
             OBTENER CÁMARA / MICRÓFONO
          ========================================== */

          if (!stream) {

            stream =
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

          }


          /* ==========================================
             MOSTRAR VIDEO LOCAL
          ========================================== */

          if (
            localVideoRef.current
          ) {

            localVideoRef.current
              .srcObject =
              stream;


            await localVideoRef.current
              .play()
              .catch(() => {});

          }


          setCameraStarted(
            true
          );


          /* ==========================================
             GUARDAR LLAMADA
          ========================================== */

          callRef.current =
            call;


          /* ==========================================
             CONTESTAR
          ========================================== */

          call.answer(
            stream
          );


          console.log(
            "📞 Llamada contestada."
          );


          /* ==========================================
             RECIBIR VIDEO PACIENTE
          ========================================== */

          call.on(
            "stream",
            (remoteStream) => {

              console.log(
                "✅ Paciente conectado."
              );


              if (
                remoteVideoRef.current
              ) {

                remoteVideoRef.current
                  .srcObject =
                  remoteStream;


                remoteVideoRef.current
                  .play()
                  .catch(() => {});

              }


              setConnected(
                true
              );

            }
          );


          /* ==========================================
             PACIENTE DESCONECTADO
          ========================================== */

          call.on(
            "close",
            () => {

              console.log(
                "📴 Paciente desconectado."
              );


              setConnected(
                false
              );


              callRef.current =
                null;

            }
          );


          /* ==========================================
             ERROR EN LLAMADA
          ========================================== */

          call.on(
            "error",
            (callError) => {

              console.error(
                "❌ Error en llamada PeerJS:",
                callError
              );


              setConnected(
                false
              );

            }
          );

        } catch (error) {

          console.error(
            "❌ Error al acceder a cámara/micrófono:",
            error
          );


          alert(
            "No se pudo acceder a la cámara/micrófono."
          );

        }

      }
    );


    /* ================================================
       ERROR PEERJS
    ================================================ */

    peer.on(
      "error",
      (error) => {

        console.error(
          "❌ Error PeerJS:",
          error
        );


        if (
          error.type ===
          "unavailable-id"
        ) {

          console.warn(
            "⚠️ El ID de la sala ya está siendo utilizado:",
            peerIdSala
          );

        }


        if (
          error.type ===
          "network"
        ) {

          console.warn(
            "⚠️ Error de red con PeerJS."
          );

        }

      }
    );


    /* ================================================
       DESCONECTADO
    ================================================ */

    peer.on(
      "disconnected",
      () => {

        console.warn(
          "⚠️ Psicólogo desconectado de PeerJS."
        );

      }
    );


    /* ================================================
       LIMPIEZA
    ================================================ */

    return () => {

      console.log(
        "🧹 Cerrando sala del psicólogo..."
      );


      if (
        callRef.current
      ) {

        try {

          callRef.current.close();

        } catch (err) {

          console.error(
            "Error cerrando llamada:",
            err
          );

        }


        callRef.current =
          null;

      }


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
        peerRef.current
      ) {

        try {

          peerRef.current.destroy();

        } catch (err) {

          console.error(
            "Error cerrando PeerJS:",
            err
          );

        }


        peerRef.current =
          null;

      }

    };

  }, [
    sala,
    modoInicial,
    idSesion,
    idPacienteSala,
    codigoUnico,
    peerIdSala
  ]);


  /* ==================================================
     ACTIVAR CÁMARA MANUALMENTE
  ================================================== */

  const iniciarVideollamada =
    async () => {

      try {

        let stream =
          localStreamRef.current;


        if (!stream) {

          stream =
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

        }


        if (
          localVideoRef.current
        ) {

          localVideoRef.current
            .srcObject =
            stream;


          await localVideoRef.current
            .play()
            .catch(() => {});

        }


        setCameraStarted(
          true
        );


        console.log(
          "🎥 Cámara del psicólogo iniciada."
        );

      } catch (error) {

        console.error(
          "❌ Error al iniciar cámara:",
          error
        );


        alert(
          "No se pudo acceder a la cámara/micrófono."
        );

      }

    };


  /* ==================================================
     COPIAR LINK DEL PACIENTE
  ================================================== */

  const copiarLinkPaciente =
    async () => {

      if (!linkPaciente) {

        return;

      }


      try {

        await navigator.clipboard.writeText(
          linkPaciente
        );


        alert(
          "✅ Enlace del paciente copiado."
        );

      } catch (error) {

        console.error(
          "❌ Error al copiar enlace:",
          error
        );


        alert(
          "No fue posible copiar el enlace."
        );

      }

    };


  /* ==================================================
     FINALIZAR SESIÓN
  ================================================== */

  const finalizarSesion =
    async () => {

      if (
        finishing
      ) {

        return;

      }


      const confirmar =
        window.confirm(
          "¿Deseas finalizar esta sesión?"
        );


      if (!confirmar) {

        return;

      }


      try {

        setFinishing(
          true
        );


        const token =
          getToken();


        const API_URL =
          `http://${window.location.hostname}:5000`;


        const res =
          await fetch(
            `${API_URL}/api/sesiones/${idSesion}/finalizar`,
            {

              method:
                "PUT",

              headers: {

                "Content-Type":
                  "application/json",

                Authorization:
                  `Bearer ${token}`

              }

            }
          );


        let data = {};


        try {

          data =
            await res.json();

        } catch {

          data = {};

        }


        if (!res.ok) {

          throw new Error(
            data.message ||
            "Error al finalizar sesión"
          );

        }


        /* ==========================================
           CERRAR LLAMADA
        ========================================== */

        if (
          callRef.current
        ) {

          try {

            callRef.current.close();

          } catch {}

          callRef.current =
            null;

        }


        /* ==========================================
           DETENER STREAM
        ========================================== */

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


        /* ==========================================
           LIMPIAR VIDEO LOCAL
        ========================================== */

        if (
          localVideoRef.current
        ) {

          localVideoRef.current
            .srcObject =
            null;

        }


        /* ==========================================
           LIMPIAR VIDEO REMOTO
        ========================================== */

        if (
          remoteVideoRef.current
        ) {

          remoteVideoRef.current
            .srcObject =
            null;

        }


        /* ==========================================
           CERRAR PEER
        ========================================== */

        if (
          peerRef.current
        ) {

          try {

            peerRef.current.destroy();

          } catch {}

          peerRef.current =
            null;

        }


        setConnected(
          false
        );


        setCameraStarted(
          false
        );


        alert(
          "✅ Sesión finalizada correctamente"
        );


        navigate(
          `/paciente/${idPacienteSala}`
        );

      } catch (error) {

        console.error(
          "❌ Error al finalizar sesión:",
          error
        );


        alert(
          error.message ||
          "❌ No se pudo finalizar la sesión."
        );


        setFinishing(
          false
        );

      }

    };


  /* ==================================================
     PANTALLA DE PREPARACIÓN
  ================================================== */

  if (
    modoInicial &&
    preparando
  ) {

    return (

      <div
        style={preparingPage}
      >

        <div
          style={preparingCard}
        >

          <div
            style={preparingIcon}
          >
            📹
          </div>


          <h2
            style={preparingTitle}
          >
            Preparando videollamada
          </h2>


          <p
            style={preparingText}
          >
            Estamos preparando la sesión clínica
            y generando la sala de videollamada.
          </p>


          <div
            style={preparingStatus}
          >
            ⏳ Un momento...
          </div>

        </div>

      </div>

    );

  }


  /* ==================================================
     ERROR AL PREPARAR
  ================================================== */

  if (
    modoInicial &&
    errorInicial
  ) {

    return (

      <div
        style={preparingPage}
      >

        <div
          style={errorCard}
        >

          <div
            style={errorIcon}
          >
            ⚠️
          </div>


          <h2
            style={errorTitle}
          >
            No se pudo iniciar la videollamada
          </h2>


          <p
            style={errorText}
          >
            {errorInicial}
          </p>


          <button
            type="button"
            onClick={() =>
              navigate(
                `/paciente/${idPaciente}`
              )
            }
            style={backButton}
          >
            ← Volver al expediente
          </button>

        </div>

      </div>

    );

  }


  /* ==================================================
     SALA INVÁLIDA

     Ahora solamente llega aquí si realmente no hay
     una sala válida.
  ================================================== */

  if (
    !sala ||
    sala === "nueva" ||
    !idSesion ||
    !idPacienteSala
  ) {

    return (

      <div
        style={preparingPage}
      >

        <div
          style={errorCard}
        >

          <div
            style={errorIcon}
          >
            ❌
          </div>


          <h2
            style={errorTitle}
          >
            Sala inválida
          </h2>


          <p
            style={errorText}
          >
            No se pudo identificar la sesión
            o el paciente.
          </p>


          <p
            style={{
              ...errorText,
              wordBreak:
                "break-all",
              fontSize:
                "12px"
            }}
          >
            URL:
            <br />
            {pathname}
            <br />
            <br />
            Sala:
            <br />
            {sala || "Sin sala"}
          </p>


          <button
            type="button"
            onClick={() =>
              navigate(-1)
            }
            style={backButton}
          >
            ⬅️ Volver
          </button>

        </div>

      </div>

    );

  }


  /* ==================================================
     INTERFAZ PRINCIPAL
  ================================================== */

  return (

    <div
      style={page}
    >

      <div
        style={container}
      >

        {/* ==========================================
            ENCABEZADO
        ========================================== */}

        <div
          style={header}
        >

          <div
            style={iconContainer}
          >
            📹
          </div>


          <h1
            style={title}
          >
            Videollamada
          </h1>


          <p
            style={subtitle}
          >
            Sesión #{idSesion}
            {" · "}
            Paciente #{idPacienteSala}
          </p>

        </div>


        {/* ==========================================
            ESTADO
        ========================================== */}

        <div
          style={{
            ...statusBox,

            background:
              connected
                ? "#E8F5E9"
                : "#FFF3E0",

            color:
              connected
                ? "#2E7D32"
                : "#EF6C00"
          }}
        >

          <span>
            {connected
              ? "🟢"
              : "🟡"}
          </span>


          {connected
            ? "Paciente conectado"
            : "Esperando al paciente..."
          }

        </div>


        {/* ==========================================
            SALA
        ========================================== */}

        <div
          style={roomInfo}
        >

          <span
            style={roomLabel}
          >
            SALA
          </span>


          <strong
            style={roomValue}
          >
            {sala}
          </strong>

        </div>


        {/* ==========================================
            ENLACE DEL PACIENTE
        ========================================== */}

        <div
          style={patientLinkBox}
        >

          <span
            style={patientLinkLabel}
          >
            🔗 ENLACE PARA EL PACIENTE
          </span>


          <div
            style={patientLinkRow}
          >

            <input
              type="text"
              value={
                linkPaciente
              }
              readOnly
              style={patientLinkInput}
            />


            <button
              type="button"
              onClick={
                copiarLinkPaciente
              }
              style={copyPatientButton}
            >
              📋 Copiar
            </button>

          </div>


          <p
            style={patientLinkHelp}
          >
            Envía este enlace al paciente para que pueda
            ingresar directamente a esta videollamada.
          </p>

        </div>


        {/* ==========================================
            CÁMARA
        ========================================== */}

        {!cameraStarted && (

          <button
            type="button"
            onClick={
              iniciarVideollamada
            }
            style={cameraButton}
          >
            🚀 Activar cámara y micrófono
          </button>

        )}


        {/* ==========================================
            VIDEOS
        ========================================== */}

        <div
          style={videosGrid}
        >

          {/* PSICÓLOGO */}

          <div
            style={videoCard}
          >

            <h3
              style={psychologistTitle}
            >
              👨‍⚕️ Tú
            </h3>


            <video
              ref={
                localVideoRef
              }
              muted
              autoPlay
              playsInline
              style={videoLocal}
            />

          </div>


          {/* PACIENTE */}

          <div
            style={videoCard}
          >

            <h3
              style={patientTitle}
            >
              👤 Paciente
            </h3>


            <video
              ref={
                remoteVideoRef
              }
              autoPlay
              playsInline
              style={videoRemote}
            />

          </div>

        </div>


        {/* ==========================================
            GRABACIÓN
        ========================================== */}

        <div
          style={recordingCard}
        >

          <h3
            style={recordingTitle}
          >
            🎥 Grabar sesión
          </h3>


          <p
            style={recordingText}
          >
            La grabación se asociará automáticamente
            con la sesión #{idSesion}.
          </p>


          <VideoRecorder
            idSesion={
              Number(idSesion)
            }
            tipo="video"
          />

        </div>


        {/* ==========================================
            FINALIZAR
        ========================================== */}

        <button
          type="button"
          onClick={
            finalizarSesion
          }
          disabled={
            finishing
          }
          style={{
            ...finishButton,

            background:
              finishing
                ? "#B0BEC5"
                : "#E53935",

            cursor:
              finishing
                ? "not-allowed"
                : "pointer"
          }}
        >

          {finishing
            ? "⏳ Finalizando..."
            : "🛑 Finalizar sesión"
          }

        </button>

      </div>

    </div>

  );

}


/* =====================================================
   ESTILOS
===================================================== */

const page = {

  minHeight:
    "100vh",

  padding:
    "30px 20px",

  boxSizing:
    "border-box",

  textAlign:
    "center",

  background:
    "linear-gradient(180deg, #E3F2FD, #BBDEFB)",

  fontFamily:
    "'Segoe UI', sans-serif"

};


const container = {

  width:
    "100%",

  maxWidth:
    "1100px",

  margin:
    "0 auto"

};


const header = {

  marginBottom:
    "18px"

};


const iconContainer = {

  width:
    "70px",

  height:
    "70px",

  margin:
    "0 auto 12px",

  borderRadius:
    "20px",

  background:
    "linear-gradient(135deg, #E3F2FD, #BBDEFB)",

  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  fontSize:
    "34px"

};


const title = {

  margin:
    "0 0 6px",

  color:
    "#0D47A1",

  fontSize:
    "30px"

};


const subtitle = {

  margin:
    0,

  color:
    "#546E7A",

  fontSize:
    "14px"

};


const statusBox = {

  display:
    "inline-flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  gap:
    "8px",

  padding:
    "8px 16px",

  borderRadius:
    "20px",

  fontWeight:
    "700",

  marginBottom:
    "18px"

};


const roomInfo = {

  maxWidth:
    "800px",

  margin:
    "0 auto 18px",

  padding:
    "12px 16px",

  background:
    "#ffffff",

  border:
    "1px solid #D6E4F0",

  borderRadius:
    "12px",

  boxShadow:
    "0 6px 18px rgba(30,70,120,.07)"

};


const roomLabel = {

  display:
    "block",

  fontSize:
    "10px",

  fontWeight:
    "800",

  letterSpacing:
    "1.5px",

  color:
    "#90A4AE",

  marginBottom:
    "4px"

};


const roomValue = {

  color:
    "#1565C0",

  fontSize:
    "13px",

  wordBreak:
    "break-all"

};


/* =====================================================
   LINK DEL PACIENTE
===================================================== */

const patientLinkBox = {

  maxWidth:
    "800px",

  margin:
    "0 auto 20px",

  padding:
    "16px",

  background:
    "#F8FAFC",

  border:
    "1px solid #D6E4F0",

  borderRadius:
    "12px",

  textAlign:
    "left",

  boxShadow:
    "0 6px 18px rgba(30,70,120,.07)"

};


const patientLinkLabel = {

  display:
    "block",

  fontSize:
    "11px",

  fontWeight:
    "800",

  letterSpacing:
    "1px",

  color:
    "#607D8B",

  marginBottom:
    "9px"

};


const patientLinkRow = {

  display:
    "flex",

  gap:
    "10px"

};


const patientLinkInput = {

  flex:
    1,

  minWidth:
    0,

  padding:
    "11px",

  border:
    "1px solid #D5DDE5",

  borderRadius:
    "9px",

  fontSize:
    "13px",

  color:
    "#455A64",

  background:
    "#FFFFFF",

  boxSizing:
    "border-box"

};


const copyPatientButton = {

  flexShrink:
    0,

  border:
    "none",

  borderRadius:
    "9px",

  padding:
    "0 16px",

  background:
    "#E3F2FD",

  color:
    "#1565C0",

  fontWeight:
    "700",

  cursor:
    "pointer"

};


const patientLinkHelp = {

  margin:
    "9px 0 0",

  color:
    "#78909C",

  fontSize:
    "12px",

  lineHeight:
    "1.5"

};


const cameraButton = {

  padding:
    "13px 25px",

  marginBottom:
    "25px",

  background:
    "linear-gradient(135deg, #42A5F5, #1976D2)",

  border:
    "none",

  borderRadius:
    "10px",

  color:
    "#fff",

  fontWeight:
    "700",

  cursor:
    "pointer",

  fontSize:
    "15px",

  boxShadow:
    "0 6px 15px rgba(25,118,210,.25)"

};


const videosGrid = {

  display:
    "grid",

  gridTemplateColumns:
    "repeat(auto-fit, minmax(320px, 1fr))",

  gap:
    "25px",

  marginTop:
    "15px"

};


const videoCard = {

  background:
    "#fff",

  padding:
    "15px",

  borderRadius:
    "18px",

  boxShadow:
    "0 10px 25px rgba(0,0,0,.10)"

};


const psychologistTitle = {

  color:
    "#2E7D32"

};


const patientTitle = {

  color:
    "#1565C0"

};


const videoLocal = {

  width:
    "100%",

  maxWidth:
    "500px",

  minHeight:
    "280px",

  objectFit:
    "cover",

  background:
    "#263238",

  border:
    "3px solid #4CAF50",

  borderRadius:
    "14px"

};


const videoRemote = {

  width:
    "100%",

  maxWidth:
    "500px",

  minHeight:
    "280px",

  objectFit:
    "cover",

  background:
    "#263238",

  border:
    "3px solid #2196F3",

  borderRadius:
    "14px"

};


const recordingCard = {

  marginTop:
    "30px",

  background:
    "#fff",

  padding:
    "25px",

  borderRadius:
    "18px",

  boxShadow:
    "0 10px 25px rgba(0,0,0,.10)"

};


const recordingTitle = {

  color:
    "#37474F"

};


const recordingText = {

  color:
    "#78909C",

  fontSize:
    "14px"

};


const finishButton = {

  marginTop:
    "30px",

  padding:
    "13px 30px",

  border:
    "none",

  borderRadius:
    "10px",

  color:
    "#fff",

  fontWeight:
    "700",

  fontSize:
    "15px",

  boxShadow:
    "0 6px 15px rgba(229,57,53,.25)"

};


const preparingPage = {

  minHeight:
    "100vh",

  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  background:
    "linear-gradient(135deg, #E3F2FD, #BBDEFB)",

  fontFamily:
    "'Segoe UI', sans-serif",

  padding:
    "20px"

};


const preparingCard = {

  background:
    "#fff",

  padding:
    "45px",

  borderRadius:
    "22px",

  textAlign:
    "center",

  boxShadow:
    "0 15px 40px rgba(0,0,0,.12)",

  maxWidth:
    "500px",

  width:
    "100%"

};


const preparingIcon = {

  fontSize:
    "50px",

  marginBottom:
    "15px"

};


const preparingTitle = {

  color:
    "#0D47A1",

  margin:
    "0 0 10px"

};


const preparingText = {

  color:
    "#607D8B",

  lineHeight:
    "1.6"

};


const preparingStatus = {

  marginTop:
    "25px",

  color:
    "#1976D2",

  fontWeight:
    "700"

};


const errorCard = {

  background:
    "#fff",

  padding:
    "35px",

  borderRadius:
    "20px",

  boxShadow:
    "0 10px 30px rgba(0,0,0,.12)",

  textAlign:
    "center",

  maxWidth:
    "500px"

};


const errorIcon = {

  fontSize:
    "45px"

};


const errorTitle = {

  color:
    "#C62828"

};


const errorText = {

  color:
    "#607D8B",

  lineHeight:
    "1.5"

};


const backButton = {

  marginTop:
    "15px",

  padding:
    "11px 22px",

  border:
    "none",

  borderRadius:
    "10px",

  background:
    "#1976D2",

  color:
    "#fff",

  fontWeight:
    "700",

  cursor:
    "pointer"

};


export default SalaVideollamada;