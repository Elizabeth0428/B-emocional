// src/components/VideoRecorder.jsx

import React, {
  useRef,
  useState,
  useEffect
} from "react";

import { getToken } from "../services/AuthService";


function VideoRecorder({
  idSesion,
  tipo = "video",
  onSaved,
  stream = null
}) {

  const mediaRef =
    useRef(null);

  const mediaRecorderRef =
    useRef(null);

  const chunksRef =
    useRef([]);

  const streamRef =
    useRef(null);

  const [recording, setRecording] =
    useState(false);

  const [time, setTime] =
    useState(0);

  const [lastSaved, setLastSaved] =
    useState(null);


  /* ==================================================
     ⏱ CRONÓMETRO
  ================================================== */

  useEffect(() => {

    let interval;

    if (recording) {

      interval = setInterval(() => {

        setTime(
          previous =>
            previous + 1
        );

      }, 1000);

    }

    return () => {

      if (interval) {

        clearInterval(interval);

      }

    };

  }, [recording]);


  /* ==================================================
     MOSTRAR STREAM RECIBIDO
     
     IMPORTANTE:
     NO detenemos los tracks aquí porque
     pertenecen a SalaVideollamada.
  ================================================== */

  useEffect(() => {

    if (!stream) {

      return;

    }

    streamRef.current =
      stream;


    if (
      mediaRef.current &&
      tipo === "video"
    ) {

      mediaRef.current.srcObject =
        stream;

      mediaRef.current
        .play()
        .catch(() => {});

    }

  }, [
    stream,
    tipo
  ]);


  /* ==================================================
     CLEANUP

     Solo detenemos el MediaRecorder.
     
     NO detenemos la cámara/micrófono
     porque el stream pertenece a
     SalaVideollamada.
  ================================================== */

  useEffect(() => {

    return () => {

      if (
        mediaRecorderRef.current &&
        mediaRecorderRef.current.state !==
          "inactive"
      ) {

        try {

          mediaRecorderRef.current.stop();

        } catch (error) {

          console.error(
            "Error al detener grabador:",
            error
          );

        }

      }

    };

  }, []);


  /* ==================================================
     INICIAR GRABACIÓN
  ================================================== */

  const startRecording =
    async () => {

      try {

        let recordingStream =
          streamRef.current;


        /* ==============================================
           SI NO RECIBIMOS STREAM DE LA VIDEOLLAMADA
           
           Esto mantiene compatibilidad con el componente
           si se utiliza en otro lugar.
        ============================================== */

        if (!recordingStream) {

          console.log(
            "📹 No se recibió stream. Solicitando cámara..."
          );


          const constraints =
            tipo === "audio"
              ? {
                  audio: true
                }
              : {
                  video: true,
                  audio: true
                };


          recordingStream =
            await navigator
              .mediaDevices
              .getUserMedia(
                constraints
              );


          streamRef.current =
            recordingStream;


          if (
            mediaRef.current
          ) {

            mediaRef.current.srcObject =
              recordingStream;

            mediaRef.current
              .play()
              .catch(() => {});

          }

        }


        /* ==============================================
           VALIDAR STREAM
        ============================================== */

        if (!recordingStream) {

          throw new Error(
            "No existe un stream disponible para grabar."
          );

        }


        const tracks =
          recordingStream.getTracks();


        if (
          !tracks.length
        ) {

          throw new Error(
            "El stream no contiene pistas de audio o video."
          );

        }


        console.log(
          "🎥 Stream utilizado para grabación:",
          tracks.map(
            track => ({
              kind: track.kind,
              enabled: track.enabled,
              readyState: track.readyState
            })
          )
        );


        /* ==============================================
           DETERMINAR MIME TYPE COMPATIBLE
        ============================================== */

        let mimeType =
          tipo === "audio"
            ? "audio/webm"
            : "video/webm;codecs=vp8,opus";


        if (
          !MediaRecorder.isTypeSupported(
            mimeType
          )
        ) {

          console.warn(
            "⚠️ MIME type no soportado:",
            mimeType
          );


          if (
            tipo === "audio" &&
            MediaRecorder.isTypeSupported(
              "audio/webm"
            )
          ) {

            mimeType =
              "audio/webm";

          } else if (
            MediaRecorder.isTypeSupported(
              "video/webm"
            )
          ) {

            mimeType =
              "video/webm";

          } else {

            mimeType =
              "";

          }

        }


        /* ==============================================
           CREAR MEDIA RECORDER
        ============================================== */

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


        chunksRef.current =
          [];


        setTime(
          0
        );


        /* ==============================================
           DATOS DISPONIBLES
        ============================================== */

        mediaRecorder.ondataavailable =
          event => {

            if (
              event.data &&
              event.data.size > 0
            ) {

              chunksRef.current.push(
                event.data
              );

            }

          };


        /* ==============================================
           CUANDO TERMINA LA GRABACIÓN
        ============================================== */

        mediaRecorder.onstop =
          async () => {

            try {

              console.log(
                "🛑 Grabación detenida. Procesando archivo..."
              );


              const blob =
                new Blob(
                  chunksRef.current,
                  {
                    type:
                      tipo === "audio"
                        ? "audio/webm"
                        : "video/webm"
                  }
                );


              chunksRef.current =
                [];


              if (
                blob.size === 0
              ) {

                console.error(
                  "⚠️ Grabación vacía (0 bytes)"
                );


                alert(
                  "El archivo no se grabó correctamente."
                );


                return;

              }


              console.log(
                "📦 Archivo generado:",
                {
                  size:
                    blob.size,
                  type:
                    blob.type
                }
              );


              /* ==========================================
                 CREAR ARCHIVO
              ========================================== */

              const file =
                new File(
                  [
                    blob
                  ],
                  `${tipo}-grabacion-${Date.now()}.webm`,
                  {
                    type:
                      blob.type
                  }
                );


              /* ==========================================
                 FORM DATA
              ========================================== */

              const formData =
                new FormData();


              formData.append(
              "file",
              file
              );

              formData.append(
              "id_sesion",
              idSesion
              );

              formData.append(
              "tipo",
              tipo
              );

              formData.append(
              "descripcion",
              "Grabación de sesión"
              );

              formData.append(
              "duracion",
              time
              );

              /* ==========================================
                 SUBIR AL BACKEND
              ========================================== */

              const token =
                getToken();


              const API_URL =
                `http://${window.location.hostname}:5000`;


              console.log(
                "📤 Subiendo grabación:",
                {
                  idSesion,
                  tipo,
                  size:
                    file.size
                }
              );


              const response =
                await fetch(
                  `${API_URL}/api/archivos`,
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


              let data = {};


              try {

                data =
                  await response.json();

              } catch (jsonError) {

                console.error(
                  "❌ El servidor no devolvió JSON:",
                  jsonError
                );

              }


              if (
                !response.ok
              ) {

                throw new Error(
                  data.message ||
                  data.error ||
                  "Error al subir archivo multimedia"
                );

              }


              /* ==========================================
                 GUARDAR RESPUESTA
              ========================================== */

              setLastSaved(
                data
              );


              if (
                onSaved
              ) {

                onSaved(
                  data
                );

              }


              alert(
                `✅ ${
                  tipo === "audio"
                    ? "Audio"
                    : "Video"
                } guardado en el servidor`
              );


              setTime(
                0
              );


            } catch (error) {

              console.error(
                "❌ Error al guardar multimedia:",
                error
              );


              alert(
                "Error al guardar multimedia."
              );

            }

          };


        /* ==============================================
           INICIAR MEDIA RECORDER
        ============================================== */

        mediaRecorder.start(
          1000
        );


        setRecording(
          true
        );


        console.log(
          "🔴 Grabación iniciada"
        );


      } catch (error) {

        console.error(
          "❌ Error al iniciar grabación:",
          error
        );


        alert(
          error.message ||
          "No se pudo iniciar la grabación."
        );

      }

    };


  /* ==================================================
     DETENER GRABACIÓN
     
     IMPORTANTE:
     NO hacemos getTracks().stop()
     
     porque eso apagaría la cámara de
     la videollamada.
  ================================================== */

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


        mediaRecorderRef.current.stop();

      }

    };


  /* ==================================================
     FORMATEAR TIEMPO
  ================================================== */

  const formatTime =
    seconds => {

      const min =
        Math.floor(
          seconds / 60
        );

      const sec =
        seconds % 60;


      return (
        `${min}:${String(sec).padStart(
          2,
          "0"
        )}`
      );

    };


  /* ==================================================
     RENDER
  ================================================== */

  return (

    <div
      style={{
        textAlign:
          "center"
      }}
    >

      {/* =================================================
          VIDEO DE PREVISUALIZACIÓN
      ================================================= */}

      {tipo === "video" && (

        <video
          ref={
            mediaRef
          }
          autoPlay
          playsInline
          muted
          style={{
            width:
              "400px",

            maxWidth:
              "100%",

            borderRadius:
              "10px",

            marginBottom:
              "10px",

            background:
              "#263238"
          }}
        />

      )}


      {/* =================================================
          AUDIO
      ================================================= */}

      {tipo === "audio" && (

        <audio
          ref={
            mediaRef
          }
          autoPlay
          controls
          style={{
            marginBottom:
              "10px"
          }}
        />

      )}


      {/* =================================================
          ESTADO DE GRABACIÓN
      ================================================= */}

      {recording && (

        <p
          style={{
            fontSize:
              "20px",

            fontWeight:
              "bold",

            color:
              "red"
          }}
        >

          ⏺ Grabando...
          {" "}
          {formatTime(
            time
          )}

        </p>

      )}


      {/* =================================================
          BOTONES
      ================================================= */}

      <div
        style={{
          marginTop:
            "10px"
        }}
      >

        {!recording ? (

          <button
            type="button"
            onClick={
              startRecording
            }
            style={{
              background:
                "green",

              color:
                "white",

              padding:
                "10px 18px",

              border:
                "none",

              borderRadius:
                "5px",

              cursor:
                "pointer",

              fontWeight:
                "600"
            }}
          >

            ▶️ Grabar{" "}
            {
              tipo === "audio"
                ? "Audio"
                : "Video"
            }

          </button>

        ) : (

          <button
            type="button"
            onClick={
              stopRecording
            }
            style={{
              background:
                "red",

              color:
                "white",

              padding:
                "10px 18px",

              border:
                "none",

              borderRadius:
                "5px",

              cursor:
                "pointer",

              fontWeight:
                "600"
            }}
          >

            ⏹️ Detener

          </button>

        )}

      </div>


      {/* =================================================
          ÚLTIMO ARCHIVO GUARDADO
      ================================================= */}

      {lastSaved && (

        <div
          style={{
            marginTop:
              "15px",

            fontSize:
              "14px"
          }}
        >

          <p>

            📂 Último guardado:

            {" "}

            <b>
              {
                lastSaved.ruta ||
                "Archivo guardado"
              }
            </b>

            {" "}

            (
            {
              lastSaved.tipo ||
              tipo
            }
            )

          </p>

        </div>

      )}

    </div>

  );

}


export default VideoRecorder;