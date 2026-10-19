// ==================================================
// src/components/VideoRecorder.jsx
// ==================================================

import React, {
  useEffect,
  useRef,
  useState
} from "react";

import {
  getToken
} from "../services/AuthService";

// ==================================================
// VIDEO / AUDIO RECORDER
// ==================================================

function VideoRecorder({

  // CLÍNICA
  idSesion = null,

  // RH
  idProspecto = null,
  idEntrevista = null,

  // "clinica" | "rh"
  contexto = "clinica",

  // "video" | "audio"
  tipo = "video",

  onSaved,

  // Stream recibido desde videollamada
  stream = null

}) {

  // ==================================================
  // API
  // ==================================================

  const API_URL = import.meta.env.VITE_API_URL || (window.location.protocol === 'https:' ? 'https://reflejoyalma.com' : `http://${window.location.hostname}:5000`);

  const esRH =
    contexto === "rh";

  // ==================================================
  // REFERENCIAS
  // ==================================================

  const mediaRef =
    useRef(null);

  const mediaRecorderRef =
    useRef(null);

  const chunksRef =
    useRef([]);

  const streamRef =
    useRef(null);

  const ownsStreamRef =
    useRef(false);

  // MIME realmente usado por MediaRecorder
  const mimeRef =
    useRef("");

  // ==================================================
  // ESTADOS
  // ==================================================

  const [
    recording,
    setRecording
  ] = useState(false);

  const [
    time,
    setTime
  ] = useState(0);

  const [
    lastSaved,
    setLastSaved
  ] = useState(null);

  const [
    guardando,
    setGuardando
  ] = useState(false);

  const [
    error,
    setError
  ] = useState("");

  // ==================================================
  // CRONÓMETRO
  // ==================================================

  useEffect(() => {

    let interval;

    if (recording) {

      interval =
        setInterval(
          () => {

            setTime(
              previous =>
                previous + 1
            );

          },
          1000
        );

    }

    return () => {

      if (interval) {
        clearInterval(
          interval
        );
      }

    };

  }, [
    recording
  ]);

  // ==================================================
  // STREAM RECIBIDO
  //
  // IMPORTANTE:
  // NO detenemos este stream aquí porque pertenece
  // a SalaVideollamada o SalaVideollamadaRH.
  // ==================================================

  useEffect(() => {

    if (!stream) {
      return;
    }

    streamRef.current =
      stream;

    ownsStreamRef.current =
      false;

    if (
      mediaRef.current &&
      tipo === "video"
    ) {

      mediaRef.current.srcObject =
        stream;

      mediaRef.current
        .play()
        .catch(
          () => {}
        );
    }

  }, [
    stream,
    tipo
  ]);

  // ==================================================
  // CLEANUP
  // ==================================================

  useEffect(() => {

    return () => {

      if (
        mediaRecorderRef.current &&
        mediaRecorderRef.current.state !==
          "inactive"
      ) {

        try {

          mediaRecorderRef.current
            .stop();

        } catch (
          cleanupError
        ) {

          console.error(
            "❌ Error al detener grabador:",
            cleanupError
          );
        }
      }

      // Solo detenemos el stream si este componente
      // fue quien pidió cámara/micrófono.

      if (
        ownsStreamRef.current &&
        streamRef.current
      ) {

        streamRef.current
          .getTracks()
          .forEach(
            track =>
              track.stop()
          );

        streamRef.current =
          null;

        ownsStreamRef.current =
          false;
      }

    };

  }, []);

  // ==================================================
  // VALIDAR CONTEXTO
  // ==================================================

  const validarContexto =
    () => {

      if (esRH) {

        if (
          !idProspecto ||
          !idEntrevista
        ) {

          throw new Error(
            "Falta identificar el prospecto o la entrevista RH."
          );
        }

        return;
      }

      if (!idSesion) {

        throw new Error(
          "Falta identificar la sesión clínica."
        );
      }
    };

  // ==================================================
  // VALIDAR ACCESO A CÁMARA / MICRÓFONO
  // ==================================================

  const validarMediaDevices =
    () => {

      if (
        navigator.mediaDevices &&
        navigator.mediaDevices.getUserMedia
      ) {
        return;
      }

      if (!window.isSecureContext) {

        throw new Error(
          "El micrófono y la cámara requieren una conexión segura HTTPS. Durante el desarrollo abre MirrorSoul desde http://localhost:5175."
        );
      }

      throw new Error(
        "El navegador no permite acceder al micrófono o cámara. Revisa los permisos del sitio."
      );
    };

  // ==================================================
  // OBTENER MIME COMPATIBLE
  // ==================================================

  const obtenerMimeType =
    () => {

      if (
        typeof MediaRecorder ===
        "undefined"
      ) {
        return "";
      }

      const candidatos =
        tipo === "audio"
          ? [
              "audio/webm;codecs=opus",
              "audio/webm",
              "audio/ogg;codecs=opus",
              "audio/ogg"
            ]
          : [
              "video/webm;codecs=vp8,opus",
              "video/webm;codecs=vp9,opus",
              "video/webm"
            ];

      for (
        const mime
        of candidatos
      ) {

        if (
          MediaRecorder
            .isTypeSupported(
              mime
            )
        ) {

          return mime;
        }
      }

      return "";
    };

  // ==================================================
  // OBTENER EXTENSIÓN
  // ==================================================

  const obtenerExtension =
    mimeType => {

      const mime =
        String(
          mimeType ||
          ""
        ).toLowerCase();

      if (
        mime.includes(
          "ogg"
        )
      ) {
        return "ogg";
      }

      if (
        mime.includes(
          "mp4"
        )
      ) {
        return "mp4";
      }

      return "webm";
    };

  // ==================================================
  // SUBIR ARCHIVO
  // ==================================================

  const subirArchivo =
    async (
      file,
      duracion
    ) => {

      validarContexto();

      const token =
        getToken();

      if (!token) {

        throw new Error(
          "Tu sesión no es válida. Inicia sesión nuevamente."
        );
      }

      const formData =
        new FormData();

      formData.append(
        "file",
        file
      );

      formData.append(
        "tipo",
        tipo
      );

      formData.append(
        "descripcion",
        esRH
          ? "Grabación de entrevista RH"
          : "Grabación de sesión"
      );

      formData.append(
        "duracion",
        String(
          duracion ||
          0
        )
      );

      let url;

      // ==================================================
      // RECURSOS HUMANOS
      // ==================================================

      if (esRH) {

        url =
          `${API_URL}/api/archivos-rh/prospecto/${idProspecto}/entrevista/${idEntrevista}`;

      }

      // ==================================================
      // CLÍNICA
      // ==================================================

      else {

        formData.append(
          "id_sesion",
          String(
            idSesion
          )
        );

        url =
          `${API_URL}/api/archivos`;
      }

      console.log(
        "📤 Subiendo grabación:",
        {
          contexto:
            esRH
              ? "rh"
              : "clinica",

          idSesion:
            esRH
              ? null
              : idSesion,

          idProspecto:
            esRH
              ? idProspecto
              : null,

          idEntrevista:
            esRH
              ? idEntrevista
              : null,

          tipo,

          nombre:
            file.name,

          size:
            file.size,

          mime:
            file.type,

          duracion,

          url
        }
      );

      const response =
        await fetch(
          url,
          {
            method:
              "POST",

            headers: {
              Authorization:
                `Bearer ${token}`
            },

            body:
              formData
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
          "Error al subir la grabación"
        );
      }

      return data;
    };

  // ==================================================
  // INICIAR GRABACIÓN
  // ==================================================

  const startRecording =
    async () => {

      if (recording) {
        return;
      }

      try {

        validarContexto();

        setError("");

        let recordingStream =
          streamRef.current;

        // ==================================================
        // SI NO RECIBIMOS STREAM
        //
        // Compatibilidad con uso independiente.
        // ==================================================

        if (!recordingStream) {

          console.log(
            tipo === "audio"
              ? "🎙️ No se recibió stream. Solicitando micrófono..."
              : "📹 No se recibió stream. Solicitando cámara y micrófono..."
          );

          validarMediaDevices();

          const constraints =
            tipo === "audio"
              ? {
                  audio: {
                    echoCancellation:
                      true,

                    noiseSuppression:
                      true,

                    autoGainControl:
                      true
                  },

                  video:
                    false
                }
              : {
                  video:
                    true,

                  audio: {
                    echoCancellation:
                      true,

                    noiseSuppression:
                      true,

                    autoGainControl:
                      true
                  }
                };

          recordingStream =
            await navigator
              .mediaDevices
              .getUserMedia(
                constraints
              );

          streamRef.current =
            recordingStream;

          ownsStreamRef.current =
            true;

          if (
            mediaRef.current &&
            tipo === "video"
          ) {

            mediaRef.current.srcObject =
              recordingStream;

            mediaRef.current
              .play()
              .catch(
                () => {}
              );
          }
        }

        // ==================================================
        // VALIDAR STREAM
        // ==================================================

        if (!recordingStream) {

          throw new Error(
            "No existe un stream disponible para grabar."
          );
        }

        const tracks =
          recordingStream
            .getTracks();

        if (!tracks.length) {

          throw new Error(
            "El stream no contiene pistas de audio o video."
          );
        }

        if (
          tipo === "audio"
        ) {

          const audioTracks =
            recordingStream
              .getAudioTracks();

          if (
            !audioTracks.length
          ) {

            throw new Error(
              "No se encontró una pista de audio disponible."
            );
          }
        }

        console.log(
          "🎥 Stream utilizado para grabación:",
          tracks.map(
            track => ({
              kind:
                track.kind,

              enabled:
                track.enabled,

              readyState:
                track.readyState,

              label:
                track.label
            })
          )
        );

        // ==================================================
        // MIME
        // ==================================================

        const mimeType =
          obtenerMimeType();

        console.log(
          "🎙️ MIME solicitado:",
          mimeType ||
          "automático"
        );

        // ==================================================
        // MEDIA RECORDER
        // ==================================================

        const mediaRecorder =
          mimeType
            ? new MediaRecorder(
                recordingStream,
                {
                  mimeType
                }
              )
            : new MediaRecorder(
                recordingStream
              );

        mediaRecorderRef.current =
          mediaRecorder;

        mimeRef.current =
          mediaRecorder.mimeType ||
          mimeType ||
          (
            tipo === "audio"
              ? "audio/webm"
              : "video/webm"
          );

        console.log(
          "🎙️ MIME real de grabación:",
          mimeRef.current
        );

        chunksRef.current =
          [];

        setTime(0);

        // ==================================================
        // CHUNKS
        // ==================================================

        mediaRecorder.ondataavailable =
          event => {

            if (
              event.data &&
              event.data.size >
                0
            ) {

              chunksRef.current.push(
                event.data
              );
            }
          };

        // ==================================================
        // CUANDO SE DETIENE
        // ==================================================

        mediaRecorder.onstop =
          async () => {

            try {

              setGuardando(
                true
              );

              console.log(
                "🛑 Grabación detenida. Procesando archivo..."
              );

              const mimeFinal =
                mediaRecorder.mimeType ||
                mimeRef.current ||
                (
                  tipo === "audio"
                    ? "audio/webm"
                    : "video/webm"
                );

              const blob =
                new Blob(
                  chunksRef.current,
                  {
                    type:
                      mimeFinal
                  }
                );

              chunksRef.current =
                [];

              if (
                blob.size ===
                0
              ) {

                throw new Error(
                  "La grabación quedó vacía."
                );
              }

              const extension =
                obtenerExtension(
                  blob.type
                );

              const file =
                new File(
                  [
                    blob
                  ],

                  `${tipo}-grabacion-${Date.now()}.${extension}`,

                  {
                    type:
                      blob.type
                  }
                );

              console.log(
                "📦 Archivo generado:",
                {
                  nombre:
                    file.name,

                  size:
                    file.size,

                  type:
                    file.type
                }
              );

              // ==================================================
              // GUARDAR
              // ==================================================

              const data =
                await subirArchivo(
                  file,
                  time
                );

              setLastSaved(
                data
              );

              console.log(
                "✅ Grabación guardada:",
                data
              );

              if (onSaved) {

                await onSaved(
                  data
                );
              }

              alert(
                `✅ ${
                  tipo === "audio"
                    ? "Audio"
                    : "Video"
                } ${
                  esRH
                    ? "de entrevista RH"
                    : "de sesión"
                } guardado correctamente`
              );

              setTime(
                0
              );

            } catch (
              saveError
            ) {

              console.error(
                "❌ Error al guardar multimedia:",
                saveError
              );

              setError(
                saveError.message ||
                "No se pudo guardar la grabación."
              );

              alert(
                saveError.message ||
                "Error al guardar multimedia."
              );

            } finally {

              setGuardando(
                false
              );
            }
          };

        // ==================================================
        // ERROR DEL MEDIARECORDER
        // ==================================================

        mediaRecorder.onerror =
          event => {

            console.error(
              "❌ Error MediaRecorder:",
              event
            );

            setRecording(
              false
            );

            setError(
              "Ocurrió un error durante la grabación."
            );
          };

        // ==================================================
        // INICIAR
        // ==================================================

        mediaRecorder.start(
          1000
        );

        setRecording(
          true
        );

        console.log(
          "🔴 Grabación iniciada:",
          esRH
            ? {
                contexto:
                  "rh",

                idProspecto,

                idEntrevista,

                tipo,

                mime:
                  mimeRef.current
              }
            : {
                contexto:
                  "clinica",

                idSesion,

                tipo,

                mime:
                  mimeRef.current
              }
        );

      } catch (
        startError
      ) {

        console.error(
          "❌ Error al iniciar grabación:",
          startError
        );

        setError(
          startError.message ||
          "No se pudo iniciar la grabación."
        );

        alert(
          startError.message ||
          "No se pudo iniciar la grabación."
        );
      }
    };

  // ==================================================
  // DETENER GRABACIÓN
  //
  // No apagamos la cámara de SalaVideollamada
  // ni de SalaVideollamadaRH.
  // ==================================================

  const stopRecording =
    () => {

      if (
        !mediaRecorderRef.current
      ) {

        return;
      }

      if (
        mediaRecorderRef.current.state ===
        "recording"
      ) {

        console.log(
          "⏹️ Deteniendo grabación..."
        );

        setRecording(
          false
        );

        mediaRecorderRef.current
          .stop();

        if (
          ownsStreamRef.current &&
          streamRef.current
        ) {

          streamRef.current
            .getTracks()
            .forEach(
              track =>
                track.stop()
            );

          streamRef.current =
            null;

          ownsStreamRef.current =
            false;
        }
      }
    };

  // ==================================================
  // FORMATEAR TIEMPO
  // ==================================================

  const formatTime =
    seconds => {

      const min =
        Math.floor(
          seconds / 60
        );

      const sec =
        seconds % 60;

      return (
        `${min}:${String(
          sec
        ).padStart(
          2,
          "0"
        )}`
      );
    };

  // ==================================================
  // RENDER
  // ==================================================

  return (

    <div style={container}>

      {/* =================================================
          TITULO
      ================================================= */}

      <div style={header}>

        <div style={icon}>
          {tipo === "audio"
            ? "🎙️"
            : "🎥"}
        </div>

        <div>

          <div style={title}>

            {esRH
              ? "Grabación de entrevista"
              : "Grabación de sesión"}

          </div>

          <div style={subtitle}>

            {esRH
              ? `Prospecto #${idProspecto || "—"} · Entrevista #${idEntrevista || "—"}`
              : `Sesión clínica #${idSesion || "—"}`}

          </div>

        </div>

      </div>

      {/* =================================================
          VIDEO PREVIEW
      ================================================= */}

      {tipo === "video" && (

        <div style={videoContainer}>

          <video
            ref={
              mediaRef
            }
            autoPlay
            playsInline
            muted
            style={video}
          />

        </div>

      )}

      {/* =================================================
          AUDIO
      ================================================= */}

      {tipo === "audio" && (

        <audio
          ref={
            mediaRef
          }
          controls
          style={{
            width:
              "100%",

            marginBottom:
              "15px"
          }}
        />

      )}

      {/* =================================================
          ESTADO
      ================================================= */}

      {recording && (

        <div style={recordingBox}>

          <span style={recordingDot}>
            ●
          </span>

          Grabando...

          <strong>
            {formatTime(
              time
            )}
          </strong>

        </div>

      )}

      {guardando && (

        <div style={savingBox}>
          ⏳ Guardando grabación...
        </div>

      )}

      {error && (

        <div style={errorBox}>
          ⚠️ {error}
        </div>

      )}

      {/* =================================================
          BOTONES
      ================================================= */}

      <div style={buttons}>

        {!recording ? (

          <button
            type="button"
            onClick={
              startRecording
            }
            disabled={
              guardando
            }
            style={{
              ...startButton,

              opacity:
                guardando
                  ? 0.6
                  : 1,

              cursor:
                guardando
                  ? "not-allowed"
                  : "pointer"
            }}
          >

            ▶️ Grabar{" "}

            {tipo === "audio"
              ? "audio"
              : esRH
              ? "entrevista"
              : "video"}

          </button>

        ) : (

          <button
            type="button"
            onClick={
              stopRecording
            }
            style={
              stopButton
            }
          >

            ⏹️ Detener grabación

          </button>

        )}

      </div>

      {/* =================================================
          ÚLTIMO ARCHIVO
      ================================================= */}

      {lastSaved && (

        <div style={savedBox}>

          <div style={savedTitle}>
            ✅ Grabación guardada
          </div>

          <div style={savedText}>

            {lastSaved.ruta ||
             lastSaved.ruta_archivo ||
             lastSaved.ruta_video ||
             lastSaved.grabacion_url ||
             "Archivo guardado"}

          </div>

          {esRH &&
            lastSaved.id_video_rh && (

            <div style={savedMeta}>

              Grabación RH #

              {lastSaved.id_video_rh}

            </div>

          )}

          {!esRH &&
            lastSaved.id_video && (

            <div style={savedMeta}>

              Archivo clínico #

              {lastSaved.id_video}

            </div>

          )}

        </div>

      )}

    </div>

  );

}

// ==================================================
// ESTILOS
// ==================================================

const container = {

  width:
    "100%",

  boxSizing:
    "border-box",

  background:
    "#FFFFFF",

  border:
    "1px solid #E2E8F0",

  borderRadius:
    "14px",

  padding:
    "18px",

  fontFamily:
    "'Segoe UI', Arial, sans-serif"

};

const header = {

  display:
    "flex",

  alignItems:
    "center",

  gap:
    "11px",

  marginBottom:
    "15px"

};

const icon = {

  width:
    "42px",

  height:
    "42px",

  display:
    "flex",

  justifyContent:
    "center",

  alignItems:
    "center",

  borderRadius:
    "11px",

  background:
    "#F3E9FF",

  fontSize:
    "20px"

};

const title = {

  fontWeight:
    "800",

  color:
    "#263238",

  fontSize:
    "16px"

};

const subtitle = {

  marginTop:
    "3px",

  color:
    "#78909C",

  fontSize:
    "12px"

};

const videoContainer = {

  width:
    "100%",

  overflow:
    "hidden",

  borderRadius:
    "12px",

  background:
    "#111827",

  marginBottom:
    "15px"

};

const video = {

  display:
    "block",

  width:
    "100%",

  maxHeight:
    "360px",

  objectFit:
    "cover",

  background:
    "#111827"

};

const recordingBox = {

  display:
    "flex",

  alignItems:
    "center",

  justifyContent:
    "center",

  gap:
    "8px",

  padding:
    "10px",

  marginBottom:
    "12px",

  background:
    "#FFF1F1",

  color:
    "#C62828",

  borderRadius:
    "9px",

  fontSize:
    "14px"

};

const recordingDot = {

  color:
    "#D32F2F",

  fontSize:
    "20px"

};

const savingBox = {

  padding:
    "10px",

  marginBottom:
    "12px",

  borderRadius:
    "9px",

  background:
    "#FFF8E1",

  color:
    "#A66A00",

  textAlign:
    "center",

  fontSize:
    "13px",

  fontWeight:
    "700"

};

const errorBox = {

  padding:
    "10px",

  marginBottom:
    "12px",

  borderRadius:
    "9px",

  background:
    "#FFF1F1",

  color:
    "#C62828",

  fontSize:
    "13px"

};

const buttons = {

  display:
    "flex",

  justifyContent:
    "center",

  gap:
    "10px"

};

const startButton = {

  border:
    "none",

  borderRadius:
    "9px",

  padding:
    "11px 17px",

  background:
    "#27843A",

  color:
    "#FFFFFF",

  fontWeight:
    "800",

  fontSize:
    "13px",

  cursor:
    "pointer"

};

const stopButton = {

  border:
    "none",

  borderRadius:
    "9px",

  padding:
    "11px 17px",

  background:
    "#C62828",

  color:
    "#FFFFFF",

  fontWeight:
    "800",

  cursor:
    "pointer",

  fontSize:
    "13px"

};

const savedBox = {

  marginTop:
    "15px",

  padding:
    "12px",

  borderRadius:
    "10px",

  background:
    "#ECF9EF",

  border:
    "1px solid #B7E4C7"

};

const savedTitle = {

  color:
    "#27843A",

  fontWeight:
    "800",

  fontSize:
    "13px"

};

const savedText = {

  marginTop:
    "5px",

  color:
    "#455A64",

  fontSize:
    "12px",

  wordBreak:
    "break-all"

};

const savedMeta = {

  marginTop:
    "5px",

  color:
    "#78909C",

  fontSize:
    "11px"

};

export default VideoRecorder;