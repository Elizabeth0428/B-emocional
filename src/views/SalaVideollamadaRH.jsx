// ==================================================
// src/views/SalaVideollamadaRH.jsx
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

import VideoRecorder
  from "../components/VideoRecorder";

import {
  getToken
} from "../services/AuthService";


const API_URL = import.meta.env.VITE_API_URL || (window.location.protocol === 'https:' ? 'https://reflejoyalma.com' : `http://${window.location.hostname}:5000`);


// ==================================================
// SALA VIDEOLLAMADA RH
//
// Formato:
// rh-ID_PROSPECTO-ID_ENTREVISTA-TIMESTAMP
//
// NO utiliza:
// - id_paciente
// - id_sesion
// - videos_sesion
// ==================================================

function SalaVideollamadaRH() {

  const navigate =
    useNavigate();

  const {
    sala
  } = useParams();


  // ==================================================
  // DATOS DE SALA
  // ==================================================

  const partes =
    String(
      sala || ""
    ).split("-");


  const salaValida =
    partes[0] === "rh" &&
    partes.length >= 4;


  const idProspecto =
    salaValida
      ? Number(
          partes[1]
        )
      : null;


  const idEntrevista =
    salaValida
      ? Number(
          partes[2]
        )
      : null;


  const peerIdSala =
    salaValida
      ? `mirrorsoul-rh-${sala}`
      : null;


  const linkProspecto =
    salaValida
      ? `${window.location.origin}/videollamada-rh/${sala}`
      : "";


  // ==================================================
  // ESTADOS
  // ==================================================

  const [
    prospecto,
    setProspecto
  ] = useState(null);


  const [
    entrevista,
    setEntrevista
  ] = useState(null);


  const [
    cargando,
    setCargando
  ] = useState(true);


  const [
    error,
    setError
  ] = useState("");


  const [
    mensaje,
    setMensaje
  ] = useState("");


  const [
    conectado,
    setConectado
  ] = useState(false);


  const [
    camaraActiva,
    setCamaraActiva
  ] = useState(false);


  const [
    finalizando,
    setFinalizando
  ] = useState(false);


  const [
    streamGrabacion,
    setStreamGrabacion
  ] = useState(null);


  const [
    transcribiendo,
    setTranscribiendo
  ] = useState(false);


  const [
    ultimaGrabacion,
    setUltimaGrabacion
  ] = useState(null);


  const [
    ultimaTranscripcion,
    setUltimaTranscripcion
  ] = useState("");


  // ==================================================
  // REFERENCIAS
  // ==================================================

  const localVideoRef =
    useRef(null);


  const remoteVideoRef =
    useRef(null);


  const peerRef =
    useRef(null);


  const localStreamRef =
    useRef(null);


  const remoteStreamRef =
    useRef(null);


  const audioContextRef =
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
  // CARGAR ENTREVISTA
  // ==================================================

  useEffect(() => {

    if (
      !salaValida ||
      !idProspecto ||
      !idEntrevista
    ) {

      setError(
        "La sala de videollamada RH no es válida."
      );

      setCargando(
        false
      );

      return;

    }


    const cargarDatos =
      async () => {

        try {

          setCargando(
            true
          );

          setError(
            ""
          );


          const token =
            getToken();


          if (!token) {

            throw new Error(
              "Tu sesión no es válida."
            );

          }


          const response =
            await fetch(
              `${API_URL}/api/prospectos/${idProspecto}/entrevistas`,
              {

                method:
                  "GET",

                headers: {

                  Authorization:
                    `Bearer ${token}`,

                  "Content-Type":
                    "application/json"

                }

              }
            );


          const data =
            await response
              .json()
              .catch(
                () => ({})
              );


          if (!response.ok) {

            throw new Error(
              data.message ||
              "No se pudo cargar la entrevista."
            );

          }


          const lista =
            Array.isArray(
              data.entrevistas
            )
              ? data.entrevistas
              : [];


          const encontrada =
            lista.find(
              item =>
                Number(
                  item.id_entrevista
                ) ===
                Number(
                  idEntrevista
                )
            );


          if (!encontrada) {

            throw new Error(
              "No se encontró la entrevista asociada a esta sala."
            );

          }


          if (
            String(
              encontrada.modalidad ||
              ""
            )
              .trim()
              .toLowerCase() !==
            "videollamada"
          ) {

            throw new Error(
              "Esta entrevista no está configurada como videollamada."
            );

          }


          setProspecto(
            data.prospecto ||
            null
          );


          setEntrevista(
            encontrada
          );


          setUltimaTranscripcion(
            encontrada.transcripcion ||
            ""
          );


          if (
            encontrada.grabacion_url
          ) {

            setUltimaGrabacion({

              grabacion_url:
                encontrada.grabacion_url

            });

          }


          console.log(
            "✅ Videollamada RH cargada:",
            {
              sala,
              idProspecto,
              idEntrevista,
              entrevista:
                encontrada
            }
          );


        } catch (
          err
        ) {

          console.error(
            "❌ Error cargando videollamada RH:",
            err
          );


          setError(
            err.message ||
            "No se pudo cargar la videollamada."
          );


        } finally {

          setCargando(
            false
          );

        }

      };


    cargarDatos();


  }, [
    sala,
    salaValida,
    idProspecto,
    idEntrevista
  ]);


  // ==================================================
  // CREAR STREAM COMBINADO
  //
  // Audio:
  // RH + Prospecto
  //
  // Video:
  // Prospecto
  // o RH como respaldo
  // ==================================================

  const crearStreamGrabacion =
    () => {

      const localStream =
        localStreamRef.current;


      const remoteStream =
        remoteStreamRef.current;


      if (!localStream) {

        return null;

      }


      try {

        if (
          audioContextRef.current
        ) {

          audioContextRef.current
            .close()
            .catch(
              () => {}
            );


          audioContextRef.current =
            null;

        }


        const AudioContextClass =
          window.AudioContext ||
          window.webkitAudioContext;


        if (!AudioContextClass) {

          console.warn(
            "⚠️ AudioContext no disponible."
          );


          return localStream;

        }


        const audioContext =
          new AudioContextClass();


        audioContextRef.current =
          audioContext;


        const destination =
          audioContext
            .createMediaStreamDestination();


        // ==============================================
        // AUDIO RH
        // ==============================================

        const audioLocal =
          localStream
            .getAudioTracks();


        if (
          audioLocal.length
        ) {

          const streamAudioLocal =
            new MediaStream(
              audioLocal
            );


          const sourceLocal =
            audioContext
              .createMediaStreamSource(
                streamAudioLocal
              );


          sourceLocal.connect(
            destination
          );

        }


        // ==============================================
        // AUDIO PROSPECTO
        // ==============================================

        if (remoteStream) {

          const audioRemoto =
            remoteStream
              .getAudioTracks();


          if (
            audioRemoto.length
          ) {

            const streamAudioRemoto =
              new MediaStream(
                audioRemoto
              );


            const sourceRemoto =
              audioContext
                .createMediaStreamSource(
                  streamAudioRemoto
                );


            sourceRemoto.connect(
              destination
            );

          }

        }


        // ==============================================
        // VIDEO
        // ==============================================

        const videoTrack =
          remoteStream
            ?.getVideoTracks()?.[0] ||
          localStream
            ?.getVideoTracks()?.[0];


        const tracks = [

          ...destination.stream
            .getAudioTracks()

        ];


        if (videoTrack) {

          tracks.push(
            videoTrack
          );

        }


        const combinado =
          new MediaStream(
            tracks
          );


        console.log(
          "🎥 Stream RH preparado para grabación:",
          {

            audio:
              combinado
                .getAudioTracks()
                .length,

            video:
              combinado
                .getVideoTracks()
                .length

          }
        );


        return combinado;


      } catch (
        err
      ) {

        console.error(
          "❌ Error creando stream combinado RH:",
          err
        );


        return localStream;

      }

    };


  // ==================================================
  // CERRAR AUDIO CONTEXT
  // ==================================================

  const cerrarAudioContext =
    () => {

      if (
        audioContextRef.current
      ) {

        audioContextRef.current
          .close()
          .catch(
            () => {}
          );


        audioContextRef.current =
          null;

      }

    };


  // ==================================================
  // PEER RH
  // ==================================================

  useEffect(() => {

    if (
      cargando ||
      error ||
      !peerIdSala ||
      !entrevista?.id_entrevista
    ) {

      return;

    }


    const config =
      obtenerConfiguracionPeer();


    console.log(
      "📡 Conectando PeerJS RH:",
      {
        sala,
        peerIdSala,
        config
      }
    );


    const peer =
      new Peer(
        peerIdSala,
        config
      );


    peerRef.current =
      peer;


    // ==============================================
    // SALA LISTA
    // ==============================================

    peer.on(
      "open",
      peerId => {

        console.log(
          "✅ Sala RH conectada a PeerJS:",
          peerId
        );


        setMensaje(
          "Sala lista. Puedes enviar el enlace al prospecto."
        );

      }
    );


    // ==============================================
    // PROSPECTO ENTRA
    // ==============================================

    peer.on(
      "call",
      async call => {

        console.log(
          "📞 El prospecto está entrando a la videollamada..."
        );


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
              .catch(
                () => {}
              );

          }


          setCamaraActiva(
            true
          );


          callRef.current =
            call;


          call.answer(
            stream
          );


          // ==============================================
          // STREAM PROSPECTO
          // ==============================================

          call.on(
            "stream",
            remoteStream => {

              console.log(
                "✅ Prospecto conectado."
              );


              remoteStreamRef.current =
                remoteStream;


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


              const combinado =
                crearStreamGrabacion();


              setStreamGrabacion(
                combinado
              );


              setConectado(
                true
              );


              setMensaje(
                "✅ Prospecto conectado. Ya puedes grabar la entrevista."
              );

            }
          );


          // ==============================================
          // PROSPECTO SALE
          // ==============================================

          call.on(
            "close",
            () => {

              console.log(
                "📴 Prospecto desconectado."
              );


              setConectado(
                false
              );


              remoteStreamRef.current =
                null;


              setStreamGrabacion(
                null
              );


              cerrarAudioContext();


              if (
                remoteVideoRef.current
              ) {

                remoteVideoRef.current
                  .srcObject =
                  null;

              }


              callRef.current =
                null;


              setMensaje(
                "El prospecto salió de la videollamada."
              );

            }
          );


          call.on(
            "error",
            callError => {

              console.error(
                "❌ Error en llamada RH:",
                callError
              );


              setConectado(
                false
              );


              setStreamGrabacion(
                null
              );

            }
          );


        } catch (
          err
        ) {

          console.error(
            "❌ Error cámara/micrófono:",
            err
          );


          setMensaje(
            "❌ No se pudo acceder a la cámara o al micrófono."
          );

        }

      }
    );


    // ==============================================
    // ERROR PEER
    // ==============================================

    peer.on(
      "error",
      peerError => {

        console.error(
          "❌ Error PeerJS RH:",
          peerError
        );


        if (
          peerError.type ===
          "unavailable-id"
        ) {

          setMensaje(
            "⚠️ Esta sala ya se encuentra abierta en otra ventana."
          );

          return;

        }


        setMensaje(
          "❌ Ocurrió un problema con la conexión de videollamada."
        );

      }
    );


    peer.on(
      "disconnected",
      () => {

        console.warn(
          "⚠️ PeerJS RH desconectado."
        );

      }
    );


    // ==============================================
    // CLEANUP
    // ==============================================

    return () => {

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


      remoteStreamRef.current =
        null;


      setStreamGrabacion(
        null
      );


      cerrarAudioContext();


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


  }, [
    cargando,
    error,
    peerIdSala,
    sala,
    idEntrevista,
    entrevista?.id_entrevista
  ]);


  // ==================================================
  // ACTIVAR CÁMARA RH
  // ==================================================

  const activarCamara =
    async () => {

      try {

        setMensaje(
          ""
        );


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
            .catch(
              () => {}
            );

        }


        setCamaraActiva(
          true
        );


        setMensaje(
          "✅ Cámara y micrófono activados."
        );


      } catch (
        err
      ) {

        console.error(
          "❌ Error activando cámara:",
          err
        );


        setMensaje(
          "❌ No se pudo acceder a la cámara o al micrófono."
        );

      }

    };


  // ==================================================
  // COPIAR ENLACE
  // ==================================================

  const copiarEnlace =
    async () => {

      try {

        await navigator
          .clipboard
          .writeText(
            linkProspecto
          );


        setMensaje(
          "✅ Enlace copiado. Ya puedes enviarlo al prospecto."
        );


      } catch (
        err
      ) {

        console.error(
          "❌ Error copiando enlace:",
          err
        );


        setMensaje(
          "❌ No fue posible copiar el enlace."
        );

      }

    };


  // ==================================================
  // TRANSCRIBIR GRABACIÓN RH
  // ==================================================

  const transcribirGrabacion =
    async (
      archivoGuardado
    ) => {

      const idVideo =
        Number(

          archivoGuardado?.id_video_rh ||

          archivoGuardado?.id_video ||

          0

        );


      setUltimaGrabacion(
        archivoGuardado ||
        null
      );


      if (!idVideo) {

        setMensaje(
          "⚠️ La grabación se guardó, pero no se recibió su identificador para transcribirla."
        );

        return;

      }


      try {

        setTranscribiendo(
          true
        );


        setMensaje(
          "🎙️ Grabación guardada. Transcribiendo entrevista..."
        );


        const token =
          getToken();


        if (!token) {

          throw new Error(
            "Tu sesión no es válida."
          );

        }


        const response =
          await fetch(
            `${API_URL}/api/archivos-rh/${idVideo}/transcribir`,
            {

              method:
                "POST",

              headers: {

                Authorization:
                  `Bearer ${token}`

              }

            }
          );


        const data =
          await response
            .json()
            .catch(
              () => ({})
            );


        if (!response.ok) {

          throw new Error(
            data.message ||
            data.error ||
            "No se pudo transcribir la entrevista."
          );

        }


        const texto =
          data.transcripcion ||
          "";


        setUltimaTranscripcion(
          texto
        );


        setEntrevista(
          previous => ({

            ...previous,

            grabacion_url:
              archivoGuardado?.grabacion_url ||
              archivoGuardado?.ruta ||
              previous?.grabacion_url ||
              null,

            transcripcion:
              texto ||
              previous?.transcripcion ||
              ""

          })
        );


        setMensaje(
          "✅ Grabación guardada y entrevista transcrita correctamente."
        );


      } catch (
        err
      ) {

        console.error(
          "❌ Error transcribiendo entrevista RH:",
          err
        );


        setMensaje(
          `⚠️ La grabación fue guardada, pero la transcripción falló: ${
            err.message ||
            "Error desconocido"
          }`
        );


      } finally {

        setTranscribiendo(
          false
        );

      }

    };


  // ==================================================
  // URL GRABACIÓN
  // ==================================================

  const obtenerUrlGrabacion =
    () => {

      const ruta =

        ultimaGrabacion?.ruta ||

        ultimaGrabacion?.grabacion_url ||

        entrevista?.grabacion_url ||

        "";


      if (!ruta) {

        return "";

      }


      if (
        String(
          ruta
        ).startsWith(
          "http"
        )
      ) {

        return ruta;

      }


      return (
        `${API_URL}${ruta}`
      );

    };


  // ==================================================
  // FINALIZAR VIDEOLLAMADA
  // ==================================================

  const finalizarVideollamada =
    () => {

      if (
        finalizando
      ) {

        return;

      }


      const confirmar =
        window.confirm(
          "¿Deseas terminar esta videollamada y regresar a las entrevistas del prospecto?"
        );


      if (!confirmar) {

        return;

      }


      try {

        setFinalizando(
          true
        );


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


        remoteStreamRef.current =
          null;


        setStreamGrabacion(
          null
        );


        cerrarAudioContext();


        if (
          localVideoRef.current
        ) {

          localVideoRef.current
            .srcObject =
            null;

        }


        if (
          remoteVideoRef.current
        ) {

          remoteVideoRef.current
            .srcObject =
            null;

        }


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


        setCamaraActiva(
          false
        );


        navigate(
          `/prospecto/${idProspecto}/entrevistas`
        );


      } catch (
        err
      ) {

        console.error(
          "❌ Error finalizando videollamada RH:",
          err
        );


        setMensaje(
          "❌ No se pudo finalizar correctamente la videollamada."
        );


        setFinalizando(
          false
        );

      }

    };


  // ==================================================
  // CARGANDO
  // ==================================================

  if (
    cargando
  ) {

    return (

      <div style={centerPage}>

        <div style={centerCard}>

          <div style={bigIcon}>
            🎥
          </div>

          <h2>
            Preparando videollamada RH
          </h2>

          <p style={mutedText}>
            Estamos cargando la entrevista
            y preparando la sala.
          </p>

          <div style={loadingText}>
            ⏳ Un momento...
          </div>

        </div>

      </div>

    );

  }


  // ==================================================
  // ERROR
  // ==================================================

  if (
    error
  ) {

    return (

      <div style={centerPage}>

        <div style={centerCard}>

          <div style={bigIcon}>
            ⚠️
          </div>

          <h2>
            No se pudo abrir la sala
          </h2>

          <p style={errorText}>
            {error}
          </p>

          <button
            type="button"
            style={backButton}
            onClick={() => {

              if (
                idProspecto
              ) {

                navigate(
                  `/prospecto/${idProspecto}/entrevistas`
                );

              } else {

                navigate(
                  -1
                );

              }

            }}
          >
            ⬅ Volver
          </button>

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


        {/* =============================================
            HEADER
        ============================================= */}

        <div style={header}>

          <button
            type="button"
            style={backButton}
            onClick={() =>
              navigate(
                `/prospecto/${idProspecto}/entrevistas`
              )
            }
          >
            ⬅ Entrevistas
          </button>


          <div>

            <div style={headerLabel}>
              RECURSOS HUMANOS
            </div>

            <h1 style={title}>
              🎥 Videollamada de entrevista
            </h1>

            <p style={subtitle}>
              Entrevista #{idEntrevista}
              {" · "}
              Prospecto #{idProspecto}
            </p>

          </div>

        </div>


        {/* =============================================
            PROSPECTO
        ============================================= */}

        <div style={prospectCard}>

          <div style={prospectIcon}>
            👤
          </div>

          <div>

            <div style={prospectLabel}>
              PROSPECTO
            </div>

            <div style={prospectName}>
              {prospecto?.nombre ||
                "Prospecto"}
            </div>

            <div style={prospectMirror}>
              🆔{" "}
              {prospecto?.id_mirror ||
                "Sin ID MirrorSoul"}
            </div>

          </div>

        </div>


        {/* =============================================
            ESTADO
        ============================================= */}

        <div
          style={{
            ...statusBox,

            background:
              conectado
                ? "#ECF9EF"
                : "#FFF7E6",

            color:
              conectado
                ? "#27843A"
                : "#B7791F"
          }}
        >

          <span>
            {conectado
              ? "🟢"
              : "🟡"}
          </span>

          <strong>
            {conectado
              ? "Prospecto conectado"
              : "Esperando al prospecto"}
          </strong>

        </div>


        {/* =============================================
            SALA
        ============================================= */}

        <div style={roomCard}>

          <div style={roomLabel}>
            SALA RH
          </div>

          <div style={roomValue}>
            {sala}
          </div>

        </div>


        {/* =============================================
            ENLACE
        ============================================= */}

        <div style={linkCard}>

          <div style={linkTitle}>
            🔗 Enlace para el prospecto
          </div>

          <p style={linkDescription}>
            Envía este enlace al prospecto para
            que ingrese a esta entrevista.
          </p>

          <div style={linkRow}>

            <input
              type="text"
              readOnly
              value={
                linkProspecto
              }
              style={linkInput}
            />

            <button
              type="button"
              onClick={
                copiarEnlace
              }
              style={copyButton}
            >
              📋 Copiar
            </button>

          </div>

        </div>


        {/* =============================================
            MENSAJES
        ============================================= */}

        {mensaje && (

          <div
            style={{
              ...messageBox,

              background:
                mensaje.startsWith(
                  "❌"
                )
                  ? "#FFF1F1"
                  : mensaje.startsWith(
                      "⚠️"
                    )
                  ? "#FFF7E6"
                  : "#EEF4FF",

              color:
                mensaje.startsWith(
                  "❌"
                )
                  ? "#C62828"
                  : mensaje.startsWith(
                      "⚠️"
                    )
                  ? "#B7791F"
                  : "#2167D5"
            }}
          >
            {mensaje}
          </div>

        )}


        {/* =============================================
            ACTIVAR CÁMARA
        ============================================= */}

        {!camaraActiva && (

          <button
            type="button"
            onClick={
              activarCamara
            }
            style={cameraButton}
          >
            🚀 Activar cámara y micrófono
          </button>

        )}


        {/* =============================================
            VIDEOS
        ============================================= */}

        <div style={videosGrid}>

          <div style={videoCard}>

            <div style={videoTitle}>
              🧑‍💼 Recursos Humanos
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

              <div style={videoPlaceholder}>
                Cámara no activada
              </div>

            )}

          </div>


          <div style={videoCard}>

            <div style={videoTitle}>
              👤 Prospecto
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

              <div style={videoPlaceholder}>
                Esperando conexión...
              </div>

            )}

          </div>

        </div>


        {/* =============================================
            INFORMACIÓN ENTREVISTA
        ============================================= */}

        <div style={interviewCard}>

          <h3 style={interviewTitle}>
            📋 Información de la entrevista
          </h3>

          <div style={interviewGrid}>

            <Info
              label="Tipo"
              value={
                entrevista?.tipo_entrevista ||
                "Entrevista"
              }
            />

            <Info
              label="Modalidad"
              value="Videollamada"
            />

            <Info
              label="Estatus"
              value={
                entrevista?.estatus ||
                "programada"
              }
            />

            <Info
              label="Resultado"
              value={
                entrevista?.resultado ||
                "pendiente"
              }
            />

          </div>

        </div>


        {/* =============================================
            GRABACIÓN Y TRANSCRIPCIÓN
        ============================================= */}

        <div style={recordingCard}>

          <h3 style={recordingTitle}>
            🎥 Grabación y transcripción
          </h3>

          <p style={recordingDescription}>
            La grabación se guardará directamente
            en la entrevista #{idEntrevista} del
            prospecto.
          </p>


          {!conectado ||
          !streamGrabacion ? (

            <div style={recordingWaiting}>
              ⏳ El botón para grabar se habilitará
              cuando el prospecto esté conectado.
            </div>

          ) : (

            <VideoRecorder

              contexto="rh"

              idProspecto={
                Number(
                  idProspecto
                )
              }

              idEntrevista={
                Number(
                  idEntrevista
                )
              }

              tipo="video"

              stream={
                streamGrabacion
              }

              onSaved={
                transcribirGrabacion
              }

            />

          )}


          {transcribiendo && (

            <div style={transcribingBox}>
              🎙️ Transcribiendo la entrevista...
            </div>

          )}


          {obtenerUrlGrabacion() && (

            <div style={savedBox}>

              <div>

                <strong>
                  🎞️ Grabación guardada
                </strong>

                <div style={savedHelp}>
                  La grabación pertenece a esta
                  entrevista RH.
                </div>

              </div>


              <a
                href={
                  obtenerUrlGrabacion()
                }
                target="_blank"
                rel="noreferrer"
                style={viewButton}
              >
                ▶ Ver grabación
              </a>

            </div>

          )}


          {(ultimaTranscripcion ||
            entrevista?.transcripcion) && (

            <div style={transcriptionCard}>

              <div style={transcriptionTitle}>
                📝 Transcripción
              </div>

              <div style={transcriptionText}>

                {ultimaTranscripcion ||
                  entrevista?.transcripcion}

              </div>

            </div>

          )}

        </div>


        {/* =============================================
            FINALIZAR
        ============================================= */}

        <button
          type="button"
          onClick={
            finalizarVideollamada
          }
          disabled={
            finalizando ||
            transcribiendo
          }
          style={{
            ...finishButton,

            opacity:
              finalizando ||
              transcribiendo
                ? 0.6
                : 1,

            cursor:
              finalizando ||
              transcribiendo
                ? "not-allowed"
                : "pointer"
          }}
        >

          {transcribiendo
            ? "🎙️ Esperando transcripción..."
            : finalizando
            ? "⏳ Finalizando..."
            : "🛑 Terminar videollamada"}

        </button>


        <footer style={footer}>

          <span>
            🧠 MirrorSoul
          </span>

          <span>
            Recursos Humanos · Entrevista #{idEntrevista}
          </span>

        </footer>

      </div>

    </div>

  );

}


// ==================================================
// INFO
// ==================================================

function Info({
  label,
  value
}) {

  return (

    <div style={infoBox}>

      <div style={infoLabel}>
        {label}
      </div>

      <div style={infoValue}>
        {value}
      </div>

    </div>

  );

}


// ==================================================
// ESTILOS
// ==================================================

const page = {
  minHeight: "100vh",
  background: "#F8FAFD",
  padding: "30px 20px",
  boxSizing: "border-box",
  fontFamily:
    "'Segoe UI', Arial, sans-serif",
  color: "#263238"
};


const container = {
  maxWidth: "1180px",
  margin: "0 auto"
};


const header = {
  display: "flex",
  alignItems: "flex-start",
  gap: "18px",
  marginBottom: "24px"
};


const headerLabel = {
  fontSize: "11px",
  fontWeight: "800",
  letterSpacing: "1.3px",
  color: "#7540D5"
};


const title = {
  margin: "5px 0 0",
  fontSize: "30px",
  color: "#263238"
};


const subtitle = {
  margin: "6px 0 0",
  color: "#78909C"
};


const backButton = {
  border: "none",
  background: "#EEF3F8",
  color: "#263238",
  padding: "10px 15px",
  borderRadius: "10px",
  cursor: "pointer",
  fontWeight: "700"
};


const prospectCard = {
  display: "flex",
  gap: "14px",
  alignItems: "center",
  padding: "17px",
  background: "#FFFFFF",
  border:
    "1px solid #E1E8EF",
  borderRadius: "15px",
  marginBottom: "18px"
};


const prospectIcon = {
  width: "48px",
  height: "48px",
  borderRadius: "13px",
  background: "#F3E9FF",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "22px"
};


const prospectLabel = {
  fontSize: "10px",
  fontWeight: "800",
  color: "#90A4AE"
};


const prospectName = {
  fontSize: "18px",
  fontWeight: "800",
  marginTop: "3px"
};


const prospectMirror = {
  color: "#607D8B",
  fontSize: "12px",
  marginTop: "3px"
};


const statusBox = {
  display: "flex",
  alignItems: "center",
  gap: "8px",
  padding: "13px 16px",
  borderRadius: "12px",
  marginBottom: "18px"
};


const roomCard = {
  background: "#FFFFFF",
  border:
    "1px solid #E1E8EF",
  borderRadius: "13px",
  padding: "15px",
  marginBottom: "18px"
};


const roomLabel = {
  fontSize: "10px",
  fontWeight: "800",
  color: "#90A4AE",
  marginBottom: "5px"
};


const roomValue = {
  fontWeight: "700",
  color: "#7540D5",
  wordBreak: "break-all"
};


const linkCard = {
  background: "#F7F1FF",
  border:
    "1px solid #E2D3FA",
  borderRadius: "15px",
  padding: "18px",
  marginBottom: "18px"
};


const linkTitle = {
  fontWeight: "800",
  color: "#7540D5"
};


const linkDescription = {
  color: "#6B7280",
  fontSize: "13px"
};


const linkRow = {
  display: "flex",
  gap: "10px",
  flexWrap: "wrap"
};


const linkInput = {
  flex: "1 1 500px",
  minWidth: 0,
  padding: "11px 12px",
  border:
    "1px solid #D9E2EF",
  borderRadius: "9px",
  background: "#FFFFFF"
};


const copyButton = {
  border: "none",
  background: "#7540D5",
  color: "#FFFFFF",
  padding: "11px 18px",
  borderRadius: "9px",
  cursor: "pointer",
  fontWeight: "800"
};


const messageBox = {
  padding: "12px 14px",
  borderRadius: "10px",
  marginBottom: "18px",
  fontWeight: "600"
};


const cameraButton = {
  width: "100%",
  border: "none",
  background: "#2167D5",
  color: "#FFFFFF",
  padding: "13px 18px",
  borderRadius: "10px",
  cursor: "pointer",
  fontWeight: "800",
  fontSize: "14px",
  marginBottom: "20px"
};


const videosGrid = {
  display: "grid",
  gridTemplateColumns:
    "repeat(auto-fit,minmax(300px,1fr))",
  gap: "18px",
  marginBottom: "22px"
};


const videoCard = {
  position: "relative",
  background: "#101827",
  borderRadius: "16px",
  overflow: "hidden",
  minHeight: "300px",
  boxShadow:
    "0 6px 20px rgba(0,0,0,.12)"
};


const videoTitle = {
  position: "absolute",
  top: "12px",
  left: "12px",
  zIndex: 2,
  background:
    "rgba(0,0,0,.55)",
  color: "#FFFFFF",
  padding: "7px 10px",
  borderRadius: "8px",
  fontSize: "12px",
  fontWeight: "800"
};


const video = {
  width: "100%",
  height: "100%",
  minHeight: "300px",
  objectFit: "cover",
  display: "block"
};


const videoPlaceholder = {
  position: "absolute",
  inset: 0,
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  color: "#CBD5E1",
  fontSize: "14px",
  pointerEvents: "none"
};


const interviewCard = {
  background: "#FFFFFF",
  border:
    "1px solid #E1E8EF",
  borderRadius: "15px",
  padding: "18px",
  marginBottom: "18px"
};


const interviewTitle = {
  margin: "0 0 14px"
};


const interviewGrid = {
  display: "grid",
  gridTemplateColumns:
    "repeat(auto-fit,minmax(180px,1fr))",
  gap: "12px"
};


const infoBox = {
  background: "#F8FAFC",
  padding: "12px",
  borderRadius: "10px"
};


const infoLabel = {
  fontSize: "10px",
  fontWeight: "800",
  color: "#90A4AE",
  textTransform: "uppercase"
};


const infoValue = {
  marginTop: "4px",
  fontWeight: "700",
  color: "#455A64"
};


const recordingCard = {
  background: "#FFFFFF",
  border:
    "1px solid #E1E8EF",
  borderRadius: "15px",
  padding: "18px",
  marginBottom: "20px"
};


const recordingTitle = {
  margin: "0 0 7px",
  color: "#263238"
};


const recordingDescription = {
  margin: "0 0 16px",
  color: "#607D8B",
  fontSize: "13px",
  lineHeight: 1.5
};


const recordingWaiting = {
  padding: "13px",
  borderRadius: "10px",
  background: "#FFF7E6",
  color: "#B7791F",
  fontSize: "13px",
  fontWeight: "700"
};


const transcribingBox = {
  marginTop: "14px",
  padding: "12px",
  borderRadius: "10px",
  background: "#EEF4FF",
  color: "#2167D5",
  fontSize: "13px",
  fontWeight: "700"
};


const savedBox = {
  marginTop: "14px",
  padding: "13px",
  borderRadius: "10px",
  background: "#ECF9EF",
  color: "#27843A",
  display: "flex",
  alignItems: "center",
  justifyContent:
    "space-between",
  gap: "12px",
  flexWrap: "wrap"
};


const savedHelp = {
  marginTop: "4px",
  color: "#607D8B",
  fontSize: "12px"
};


const viewButton = {
  textDecoration: "none",
  background: "#27843A",
  color: "#FFFFFF",
  padding: "9px 12px",
  borderRadius: "8px",
  fontSize: "12px",
  fontWeight: "800"
};


const transcriptionCard = {
  marginTop: "14px",
  padding: "14px",
  borderRadius: "10px",
  background: "#F8FAFC",
  border:
    "1px solid #E1E8EF"
};


const transcriptionTitle = {
  fontWeight: "800",
  color: "#263238"
};


const transcriptionText = {
  marginTop: "9px",
  whiteSpace: "pre-wrap",
  color: "#455A64",
  fontSize: "13px",
  lineHeight: 1.6
};


const finishButton = {
  width: "100%",
  border: "none",
  background: "#C62828",
  color: "#FFFFFF",
  padding: "14px 18px",
  borderRadius: "10px",
  fontWeight: "800",
  fontSize: "14px"
};


const footer = {
  display: "flex",
  justifyContent:
    "space-between",
  gap: "15px",
  flexWrap: "wrap",
  borderTop:
    "1px solid #E1E8EF",
  marginTop: "30px",
  paddingTop: "17px",
  color: "#90A4AE",
  fontSize: "12px"
};


const centerPage = {
  minHeight: "80vh",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  padding: "25px",
  fontFamily:
    "'Segoe UI', Arial, sans-serif"
};


const centerCard = {
  maxWidth: "550px",
  width: "100%",
  background: "#FFFFFF",
  border:
    "1px solid #E1E8EF",
  borderRadius: "18px",
  padding: "35px",
  textAlign: "center",
  boxShadow:
    "0 6px 22px rgba(30,60,90,.08)"
};


const bigIcon = {
  fontSize: "44px",
  marginBottom: "10px"
};


const mutedText = {
  color: "#78909C",
  lineHeight: 1.5
};


const loadingText = {
  marginTop: "18px",
  color: "#7540D5",
  fontWeight: "700"
};


const errorText = {
  color: "#C62828",
  lineHeight: 1.5,
  marginBottom: "20px"
};


export default SalaVideollamadaRH;