// src/views/SesionesView.jsx

import React, {
  useEffect,
  useState
} from "react";

import {
  useParams,
  useNavigate
} from "react-router-dom";

import { getToken } from "../services/AuthService";


export default function SesionesView() {

  const { idPaciente } = useParams();

  const navigate = useNavigate();


  // =====================================================
  // ESTADOS PRINCIPALES
  // =====================================================

  const [
    sesiones,
    setSesiones
  ] = useState([]);

  const [
    loading,
    setLoading
  ] = useState(true);

  const [
    error,
    setError
  ] = useState("");


  // =====================================================
  // SESIÓN ABIERTA
  // =====================================================

  const [
    sesionAbierta,
    setSesionAbierta
  ] = useState(null);


  // =====================================================
  // ARCHIVOS MULTIMEDIA POR SESIÓN
  // =====================================================

  const [
    archivosSesion,
    setArchivosSesion
  ] = useState({});

  const [
    cargandoArchivos,
    setCargandoArchivos
  ] = useState(false);


  // =====================================================
  // CANTIDAD DE SESIONES VISIBLES
  // =====================================================

  const [
    sesionesVisibles,
    setSesionesVisibles
  ] = useState(5);


  // =====================================================
  // CARGAR SESIONES
  // =====================================================

  useEffect(() => {

    const fetchSesiones = async () => {

      try {

        const token = getToken();

        const res = await fetch(
          `http://localhost:5000/api/sesiones/paciente/${idPaciente}`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );


        if (!res.ok) {

          throw new Error(
            "No se pudieron obtener las sesiones"
          );

        }


        const data = await res.json();


        setSesiones(
          Array.isArray(data)
            ? data
            : data.sesiones || []
        );


      } catch (err) {

        console.error(
          "❌ Error al obtener sesiones:",
          err
        );


        setError(
          "No fue posible cargar las sesiones del paciente."
        );


      } finally {

        setLoading(false);

      }

    };


    if (idPaciente) {

      fetchSesiones();

    }

  }, [
    idPaciente
  ]);


  // =====================================================
  // ABRIR / CERRAR SESIÓN
  // =====================================================

  const toggleSesion = async (idSesion) => {

    // ---------------------------------------------------
    // CERRAR
    // ---------------------------------------------------

    if (
      sesionAbierta === idSesion
    ) {

      setSesionAbierta(null);

      return;

    }


    // ---------------------------------------------------
    // ABRIR
    // ---------------------------------------------------

    setSesionAbierta(idSesion);


    // ---------------------------------------------------
    // SI YA SE CARGARON ARCHIVOS
    // ---------------------------------------------------

    if (
      Object.prototype.hasOwnProperty.call(
        archivosSesion,
        idSesion
      )
    ) {

      return;

    }


    // ---------------------------------------------------
    // CARGAR MULTIMEDIA
    // ---------------------------------------------------

    try {

      setCargandoArchivos(true);


      const token = getToken();


      const res = await fetch(
        `http://localhost:5000/api/archivos/sesion/${idSesion}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );


      if (!res.ok) {

        throw new Error(
          "No se pudieron obtener las grabaciones de la sesión."
        );

      }


      const data = await res.json();


      console.log(
        "🎥 Archivos multimedia recibidos:",
        data
      );


      setArchivosSesion(
        previous => ({
          ...previous,

          [idSesion]:
            Array.isArray(data)
              ? data
              : [],
        })
      );


    } catch (err) {

      console.error(
        "❌ Error al obtener archivos de la sesión:",
        err
      );


      setArchivosSesion(
        previous => ({
          ...previous,

          [idSesion]: [],
        })
      );


    } finally {

      setCargandoArchivos(false);

    }

  };


  // =====================================================
  // MOSTRAR 5 SESIONES MÁS
  // =====================================================

  const mostrarMasSesiones = () => {

    setSesionesVisibles(
      actual =>
        Math.min(
          actual + 5,
          sesiones.length
        )
    );

  };


  // =====================================================
  // MOSTRAR SOLO LAS PRIMERAS 5
  // =====================================================

  const mostrarMenosSesiones = () => {

    setSesionesVisibles(5);

    setSesionAbierta(null);


    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });

  };


  // =====================================================
  // VOLVER AL EXPEDIENTE
  // =====================================================

  const volverAlExpediente = () => {

    navigate(
      `/paciente/${idPaciente}`
    );

  };


  // =====================================================
  // CARGANDO
  // =====================================================

  if (loading) {

    return (

      <div style={loadingPage}>

        <div style={loadingCard}>

          <div style={loadingIcon}>
            ⏳
          </div>

          <h3 style={loadingTitle}>
            Cargando sesiones...
          </h3>

          <p style={loadingText}>
            Estamos obteniendo el historial de sesiones
            del paciente.
          </p>

        </div>

      </div>

    );

  }


  // =====================================================
  // SESIONES VISIBLES
  // =====================================================

  const sesionesMostradas =
    sesiones.slice(
      0,
      sesionesVisibles
    );


  const hayMasSesiones =
    sesionesVisibles <
    sesiones.length;


  const mostrandoTodas =
    sesionesVisibles >= sesiones.length &&
    sesiones.length > 5;


  // =====================================================
  // RENDER
  // =====================================================

  return (

    <div style={page}>

      <div style={container}>

        {/* =================================================
            ENCABEZADO
        ================================================= */}

        <div style={header}>

          <div>

            <div style={smallLabel}>
              EXPEDIENTE DEL PACIENTE
            </div>

            <h1 style={title}>
              📅 Historial de Sesiones
            </h1>

            <p style={subtitle}>
              Consulta las sesiones clínicas registradas
              para este paciente.
            </p>

          </div>


          <div style={sessionCounter}>

            <span style={counterNumber}>
              {sesiones.length}
            </span>

            <span style={counterLabel}>

              {
                sesiones.length === 1
                  ? "sesión"
                  : "sesiones"
              }

            </span>

          </div>

        </div>


        {/* =================================================
            ERROR
        ================================================= */}

        {error && (

          <div style={errorBox}>

            <span>
              ⚠️
            </span>

            <span>
              {error}
            </span>

          </div>

        )}


        {/* =================================================
            SIN SESIONES
        ================================================= */}

        {!error &&
          sesiones.length === 0 && (

            <div style={emptyBox}>

              <div style={emptyIcon}>
                📅
              </div>

              <h3 style={emptyTitle}>
                No hay sesiones registradas
              </h3>

              <p style={emptyText}>
                Todavía no se han registrado sesiones
                clínicas para este paciente.
              </p>

            </div>

        )}


        {/* =================================================
            LISTA DE SESIONES
        ================================================= */}

        {!error &&
          sesiones.length > 0 && (

            <>

              <div style={sessionsList}>

                {sesionesMostradas.map(
                  (s, index) => {

                    const fecha =
                      s.fecha
                        ? new Date(s.fecha)
                        : null;


                    const abierta =
                      sesionAbierta ===
                      s.id_sesion;


                    const archivos =
                      archivosSesion[
                        s.id_sesion
                      ] || [];


                    return (

                      <div
                        key={s.id_sesion}
                        style={{
                          ...sessionCard,

                          ...(abierta
                            ? sessionCardOpen
                            : {})
                        }}
                      >

                        {/* =================================
                            CABECERA DE SESIÓN
                        ================================= */}

                        <button
                          type="button"
                          onClick={() =>
                            toggleSesion(
                              s.id_sesion
                            )
                          }
                          style={
                            sessionHeaderButton
                          }
                        >

                          <div
                            style={
                              sessionNumber
                            }
                          >
                            {index + 1}
                          </div>


                          <div
                            style={
                              sessionMainInfo
                            }
                          >

                            <div
                              style={
                                sessionLabel
                              }
                            >
                              SESIÓN CLÍNICA
                            </div>


                            <h3
                              style={
                                sessionTitle
                              }
                            >
                              Sesión #{index + 1}
                            </h3>


                            <div
                              style={
                                sessionDate
                              }
                            >

                              📅{" "}

                              {
                                fecha
                                  ? fecha.toLocaleDateString(
                                      "es-MX",
                                      {
                                        day: "2-digit",
                                        month: "long",
                                        year: "numeric",
                                      }
                                    )
                                  : "Fecha no disponible"
                              }

                            </div>

                          </div>


                          <div
                            style={{
                              ...expandButton,

                              ...(abierta
                                ? expandButtonOpen
                                : {})
                            }}
                          >

                            <span>

                              {
                                abierta
                                  ? "Ocultar"
                                  : "Ver detalles"
                              }

                            </span>

                            <span style={arrow}>

                              {
                                abierta
                                  ? "▲"
                                  : "▼"
                              }

                            </span>

                          </div>

                        </button>


                        {/* =================================
                            DETALLES DE SESIÓN
                        ================================= */}

                        {abierta && (

                          <div style={details}>

                            {/* =================================
                                HORA
                            ================================= */}

                            {fecha && (

                              <div
                                style={
                                  detailItem
                                }
                              >

                                <div
                                  style={
                                    detailIcon
                                  }
                                >
                                  🕐
                                </div>

                                <div>

                                  <div
                                    style={
                                      detailLabel
                                    }
                                  >
                                    Hora de la sesión
                                  </div>

                                  <div
                                    style={
                                      detailValue
                                    }
                                  >

                                    {
                                      fecha.toLocaleTimeString(
                                        "es-MX",
                                        {
                                          hour: "2-digit",
                                          minute: "2-digit",
                                        }
                                      )
                                    }

                                  </div>

                                </div>

                              </div>

                            )}


                            {/* =================================
                                ID
                            ================================= */}

                            <div
                              style={
                                detailItem
                              }
                            >

                              <div
                                style={
                                  detailIcon
                                }
                              >
                                🆔
                              </div>

                              <div>

                                <div
                                  style={
                                    detailLabel
                                  }
                                >
                                  Identificador de sesión
                                </div>

                                <div
                                  style={
                                    detailValue
                                  }
                                >
                                  #{s.id_sesion}
                                </div>

                              </div>

                            </div>


                            {/* =================================
                                ESTADO
                            ================================= */}

                            <div
                              style={
                                detailItem
                              }
                            >

                              <div
                                style={
                                  detailIcon
                                }
                              >

                                {
                                  s.estado ===
                                  "finalizada"
                                    ? "✅"
                                    : "🟢"
                                }

                              </div>

                              <div>

                                <div
                                  style={
                                    detailLabel
                                  }
                                >
                                  Estado
                                </div>

                                <div
                                  style={
                                    detailValue
                                  }
                                >

                                  {
                                    s.estado ===
                                    "finalizada"
                                      ? "Finalizada"
                                      : "Activa"
                                  }

                                </div>

                              </div>

                            </div>


                            {/* =================================
                                NOTAS
                            ================================= */}

                            <div
                              style={
                                notesBox
                              }
                            >

                              <div
                                style={
                                  notesTitle
                                }
                              >
                                📝 Notas de la sesión
                              </div>

                              <p
                                style={
                                  notesText
                                }
                              >

                                {
                                  s.notas
                                    ? s.notas
                                    : "Sin notas registradas."
                                }

                              </p>

                            </div>


                            {/* =================================
                                MULTIMEDIA
                            ================================= */}

                            <div
                              style={
                                multimediaBox
                              }
                            >

                              <div
                                style={
                                  multimediaHeader
                                }
                              >

                                <div>

                                  <div
                                    style={
                                      multimediaTitle
                                    }
                                  >
                                    🎥 Grabaciones
                                  </div>

                                  <div
                                    style={
                                      multimediaSubtitle
                                    }
                                  >
                                    Material audiovisual de la sesión
                                  </div>

                                </div>


                                {archivos.length > 0 && (

                                  <span
                                    style={
                                      multimediaCount
                                    }
                                  >

                                    {archivos.length}

                                    {
                                      archivos.length === 1
                                        ? " video"
                                        : " videos"
                                    }

                                  </span>

                                )}

                              </div>


                              {/* =================================
                                  CARGANDO MULTIMEDIA
                              ================================= */}

                              {cargandoArchivos &&
                                sesionAbierta ===
                                  s.id_sesion && (

                                  <div
                                    style={
                                      multimediaLoadingBox
                                    }
                                  >
                                    ⏳ Cargando grabaciones...
                                  </div>

                              )}


                              {/* =================================
                                  SIN ARCHIVOS
                              ================================= */}

                              {!cargandoArchivos &&
                                archivos.length === 0 && (

                                  <div
                                    style={
                                      multimediaEmptyBox
                                    }
                                  >

                                    <span
                                      style={
                                        multimediaEmptyIcon
                                      }
                                    >
                                      🎥
                                    </span>

                                    <span>
                                      No hay grabaciones asociadas
                                      a esta sesión.
                                    </span>

                                  </div>

                              )}


                              {/* =================================
                                  VIDEOS
                              ================================= */}

                              {!cargandoArchivos &&
                                archivos.length > 0 && (

                                  <div
                                    style={
                                      videosList
                                    }
                                  >

                                    {archivos.map(
                                      (archivo) => {

                                        // ---------------------------------
                                        // CONSTRUIR URL
                                        // ---------------------------------

                                        const rutaVideo =
                                          archivo.ruta_video || "";


                                        const videoUrl =
                                          rutaVideo.startsWith("http")
                                            ? rutaVideo
                                            : `http://localhost:5000${rutaVideo}`;


                                        console.log(
                                          "🎥 URL DEL VIDEO EN SESIONES:",
                                          videoUrl
                                        );


                                        return (

                                          <div
                                            key={
                                              archivo.id_video
                                            }
                                            style={
                                              videoWrapper
                                            }
                                          >

                                            {/* =============================
                                                CABECERA VIDEO
                                            ============================= */}

                                            <div
                                              style={
                                                videoHeader
                                              }
                                            >

                                              <div
                                                style={
                                                  videoHeaderInfo
                                                }
                                              >

                                                <div
                                                  style={
                                                    videoName
                                                  }
                                                >
                                                  🎬 Grabación
                                                </div>


                                                <div
                                                  style={
                                                    videoDate
                                                  }
                                                >

                                                  {
                                                    archivo.fecha_subida
                                                      ? new Date(
                                                          archivo.fecha_subida
                                                        ).toLocaleString(
                                                          "es-MX",
                                                          {
                                                            day: "2-digit",
                                                            month: "short",
                                                            year: "numeric",
                                                            hour: "2-digit",
                                                            minute: "2-digit",
                                                          }
                                                        )
                                                      : "Fecha no disponible"
                                                  }

                                                </div>

                                              </div>


                                              <span
                                                style={
                                                  videoType
                                                }
                                              >

                                                {
                                                  archivo.tipo ||
                                                  "video"
                                                }

                                              </span>

                                            </div>


                                            {/* =============================
                                                REPRODUCTOR
                                            ============================= */}

                                            <div
                                              style={
                                                videoPlayerContainer
                                              }
                                            >

                                              <video

                                                key={
                                                  videoUrl
                                                }

                                                controls

                                                crossOrigin="anonymous"

                                                playsInline

                                                preload="metadata"

                                                src={
                                                  videoUrl
                                                }

                                                style={
                                                  videoPlayer
                                                }

                                                onLoadStart={(e) => {

                                                  console.log(
                                                    "📥 Video comenzó a cargar:",
                                                    e.currentTarget.src
                                                  );

                                                }}

                                                onLoadedMetadata={(e) => {

                                                  console.log(
                                                    "✅ Video cargado:",
                                                    e.currentTarget.src
                                                  );


                                                  console.log(
                                                    "🎬 Duración:",
                                                    e.currentTarget.duration
                                                  );


                                                  console.log(
                                                    "📐 Dimensiones:",
                                                    {
                                                      width:
                                                        e.currentTarget.videoWidth,

                                                      height:
                                                        e.currentTarget.videoHeight
                                                    }
                                                  );

                                                }}

                                                onLoadedData={(e) => {

                                                  console.log(
                                                    "📦 Datos del video cargados:",
                                                    e.currentTarget.src
                                                  );

                                                }}

                                                onCanPlay={(e) => {

                                                  console.log(
                                                    "▶️ Video listo para reproducirse:",
                                                    e.currentTarget.src
                                                  );

                                                }}

                                                onCanPlayThrough={(e) => {

                                                  console.log(
                                                    "✅ Video puede reproducirse completamente:",
                                                    e.currentTarget.src
                                                  );

                                                }}

                                                onError={(e) => {

                                                  const video =
                                                    e.currentTarget;


                                                  console.error(
                                                    "❌ ERROR REPRODUCIENDO VIDEO"
                                                  );


                                                  console.error(
                                                    "URL:",
                                                    video.src
                                                  );


                                                  console.error(
                                                    "Código de error:",
                                                    video.error?.code
                                                  );


                                                  console.error(
                                                    "Mensaje:",
                                                    video.error?.message
                                                  );


                                                  console.error(
                                                    "networkState:",
                                                    video.networkState
                                                  );


                                                  console.error(
                                                    "readyState:",
                                                    video.readyState
                                                  );


                                                  console.error(
                                                    "currentSrc:",
                                                    video.currentSrc
                                                  );


                                                  console.error(
                                                    "duración:",
                                                    video.duration
                                                  );

                                                }}

                                              >

                                                <source
                                                  src={
                                                    videoUrl
                                                  }
                                                  type="video/webm"
                                                />

                                                Tu navegador no puede
                                                reproducir este video.

                                              </video>

                                            </div>

                                          </div>

                                        );

                                      }
                                    )}

                                  </div>

                              )}

                            </div>

                          </div>

                        )}

                      </div>

                    );

                  }
                )}

              </div>


              {/* =========================================
                  PAGINACIÓN
              ========================================= */}

              {sesiones.length > 5 && (

                <div
                  style={
                    paginationContainer
                  }
                >

                  {hayMasSesiones && (

                    <button
                      type="button"
                      onClick={
                        mostrarMasSesiones
                      }
                      style={
                        moreButton
                      }
                    >

                      <span
                        style={
                          moreButtonIcon
                        }
                      >
                        ↓
                      </span>

                      <span>
                        Ver 5 sesiones más
                      </span>

                      <span
                        style={
                          remainingText
                        }
                      >

                        (
                        {
                          sesiones.length -
                          sesionesVisibles
                        }
                        {" "}
                        restantes)

                      </span>

                    </button>

                  )}


                  {mostrandoTodas && (

                    <button
                      type="button"
                      onClick={
                        mostrarMenosSesiones
                      }
                      style={
                        lessButton
                      }
                    >

                      <span>
                        ↑
                      </span>

                      <span>
                        Ver menos
                      </span>

                    </button>

                  )}

                </div>

              )}

            </>

        )}


        {/* =================================================
            VOLVER AL EXPEDIENTE
        ================================================= */}

        <div
          style={
            backContainer
          }
        >

          <button
            type="button"
            onClick={
              volverAlExpediente
            }
            style={
              backButton
            }
          >
            ← Volver al expediente
          </button>

        </div>


        {/* =================================================
            PIE
        ================================================= */}

        <div
          style={
            footer
          }
        >

          <span>
            🧠 MirrorSoul
          </span>

          <span>
            Expediente #{idPaciente}
          </span>

        </div>

      </div>

    </div>

  );

}


// =====================================================
// 🎨 ESTILOS
// =====================================================

const page = {
  minHeight: "100vh",
  background:
    "linear-gradient(135deg, #eef6ff 0%, #f8fbff 50%, #e8f3ff 100%)",
  padding: "28px 18px",
  boxSizing: "border-box",
};


const container = {
  width: "100%",
  maxWidth: "1080px",
  margin: "0 auto",
};


const header = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  gap: "18px",
  marginBottom: "22px",
};


const smallLabel = {
  fontSize: "10px",
  fontWeight: "800",
  letterSpacing: "1.8px",
  color: "#5C6BC0",
  marginBottom: "5px",
};


const title = {
  margin: 0,
  color: "#173B70",
  fontSize: "28px",
  fontWeight: "800",
};


const subtitle = {
  margin: "6px 0 0",
  color: "#718096",
  fontSize: "13px",
};


const sessionCounter = {
  minWidth: "82px",
  padding: "11px 14px",
  background: "#ffffff",
  borderRadius: "15px",
  boxShadow:
    "0 7px 20px rgba(30,70,120,0.09)",
  border: "1px solid #E2E8F0",
  display: "flex",
  flexDirection: "column",
  alignItems: "center",
};


const counterNumber = {
  fontSize: "23px",
  fontWeight: "800",
  color: "#3949AB",
};


const counterLabel = {
  fontSize: "11px",
  color: "#718096",
};


const sessionsList = {
  display: "flex",
  flexDirection: "column",
  gap: "12px",
};


const sessionCard = {
  background: "#ffffff",
  borderRadius: "16px",
  border: "1px solid #E2E8F0",
  boxShadow:
    "0 5px 16px rgba(30,70,120,0.06)",
  overflow: "hidden",
};


const sessionCardOpen = {
  boxShadow:
    "0 8px 24px rgba(30,70,120,0.10)",
  border:
    "1px solid #C7D7F5",
};


const sessionHeaderButton = {
  width: "100%",
  display: "flex",
  alignItems: "center",
  gap: "13px",
  border: "none",
  background: "transparent",
  padding: "14px 16px",
  cursor: "pointer",
  textAlign: "left",
};


const sessionNumber = {
  width: "42px",
  height: "42px",
  minWidth: "42px",
  borderRadius: "12px",
  background:
    "linear-gradient(135deg, #5C6BC0, #42A5F5)",
  color: "#ffffff",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "16px",
  fontWeight: "800",
};


const sessionMainInfo = {
  flex: 1,
  minWidth: 0,
};


const sessionLabel = {
  fontSize: "8px",
  fontWeight: "800",
  letterSpacing: "1.3px",
  color: "#94A3B8",
};


const sessionTitle = {
  margin: "2px 0",
  color: "#173B70",
  fontSize: "16px",
  fontWeight: "750",
};


const sessionDate = {
  color: "#718096",
  fontSize: "11px",
};


const expandButton = {
  display: "flex",
  alignItems: "center",
  gap: "6px",
  padding: "8px 11px",
  borderRadius: "9px",
  background: "#EEF4FF",
  color: "#3949AB",
  fontSize: "11px",
  fontWeight: "700",
  whiteSpace: "nowrap",
};


const expandButtonOpen = {
  background: "#E3F2FD",
  color: "#1565C0",
};


const arrow = {
  fontSize: "9px",
};


const details = {
  borderTop: "1px solid #EDF2F7",
  background: "#FAFCFF",
  padding: "14px",
  display: "grid",
  gridTemplateColumns:
    "repeat(3, minmax(0, 1fr))",
  gap: "10px",
};


const detailItem = {
  display: "flex",
  alignItems: "center",
  gap: "9px",
  background: "#ffffff",
  border: "1px solid #E8EEF5",
  borderRadius: "11px",
  padding: "10px 11px",
  minHeight: "54px",
};


const detailIcon = {
  width: "32px",
  height: "32px",
  minWidth: "32px",
  borderRadius: "9px",
  background: "#EEF4FF",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "15px",
};


const detailLabel = {
  fontSize: "8px",
  color: "#94A3B8",
  fontWeight: "700",
  textTransform: "uppercase",
};


const detailValue = {
  marginTop: "2px",
  color: "#334155",
  fontSize: "12px",
  fontWeight: "700",
};


const notesBox = {
  gridColumn: "1 / -1",
  background: "#ffffff",
  border: "1px solid #E8EEF5",
  borderRadius: "11px",
  padding: "12px 13px",
};


const notesTitle = {
  color: "#475569",
  fontSize: "11px",
  fontWeight: "800",
  marginBottom: "5px",
};


const notesText = {
  margin: 0,
  color: "#64748B",
  fontSize: "12px",
  lineHeight: "1.5",
  whiteSpace: "pre-wrap",
};


// =====================================================
// 🎥 MULTIMEDIA
// =====================================================

const multimediaBox = {
  gridColumn: "1 / -1",
  background: "#ffffff",
  border: "1px solid #E1E8F0",
  borderRadius: "12px",
  padding: "12px",
};


const multimediaHeader = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  gap: "10px",
  marginBottom: "8px",
};


const multimediaTitle = {
  color: "#334155",
  fontSize: "12px",
  fontWeight: "800",
};


const multimediaSubtitle = {
  marginTop: "2px",
  color: "#94A3B8",
  fontSize: "10px",
};


const multimediaCount = {
  background: "#EEF4FF",
  color: "#3949AB",
  padding: "4px 8px",
  borderRadius: "7px",
  fontSize: "9px",
  fontWeight: "700",
  whiteSpace: "nowrap",
};


const multimediaLoadingBox = {
  padding: "11px",
  borderRadius: "9px",
  background: "#F8FAFC",
  color: "#64748B",
  fontSize: "11px",
};


const multimediaEmptyBox = {
  display: "flex",
  alignItems: "center",
  gap: "8px",
  padding: "10px",
  borderRadius: "9px",
  background: "#F8FAFC",
  color: "#94A3B8",
  fontSize: "11px",
};


const multimediaEmptyIcon = {
  fontSize: "16px",
};


const videosList = {
  display: "flex",
  flexDirection: "column",
  gap: "8px",
};


const videoWrapper = {
  background: "#F8FAFC",
  border: "1px solid #E2E8F0",
  borderRadius: "10px",
  padding: "9px",
};


const videoHeader = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  gap: "8px",
  marginBottom: "7px",
};


const videoHeaderInfo = {
  minWidth: 0,
};


const videoName = {
  color: "#334155",
  fontSize: "11px",
  fontWeight: "700",
};


const videoDate = {
  marginTop: "2px",
  color: "#94A3B8",
  fontSize: "9px",
};


const videoType = {
  background: "#E3F2FD",
  color: "#1565C0",
  padding: "4px 7px",
  borderRadius: "6px",
  fontSize: "8px",
  fontWeight: "700",
  textTransform: "uppercase",
};


const videoPlayerContainer = {
  width: "100%",
  overflow: "hidden",
  borderRadius: "8px",
  background: "#000",
};


const videoPlayer = {
  width: "100%",
  maxHeight: "360px",
  minHeight: "200px",
  display: "block",
  background: "#000",
};


// =====================================================
// PAGINACIÓN
// =====================================================

const paginationContainer = {
  display: "flex",
  justifyContent: "center",
  alignItems: "center",
  gap: "10px",
  flexWrap: "wrap",
  marginTop: "18px",
};


const moreButton = {
  display: "flex",
  alignItems: "center",
  gap: "7px",
  border: "1px solid #C7D7F5",
  background: "#ffffff",
  color: "#1565C0",
  padding: "10px 16px",
  borderRadius: "11px",
  cursor: "pointer",
  fontWeight: "700",
  fontSize: "11px",
  boxShadow:
    "0 4px 12px rgba(21,101,192,0.07)",
};


const moreButtonIcon = {
  fontSize: "16px",
  fontWeight: "800",
};


const remainingText = {
  color: "#94A3B8",
  fontWeight: "500",
  fontSize: "10px",
};


const lessButton = {
  display: "flex",
  alignItems: "center",
  gap: "6px",
  border: "none",
  background: "#EEF4FF",
  color: "#3949AB",
  padding: "9px 15px",
  borderRadius: "10px",
  cursor: "pointer",
  fontWeight: "700",
  fontSize: "11px",
};


// =====================================================
// SIN SESIONES
// =====================================================

const emptyBox = {
  background: "#ffffff",
  borderRadius: "17px",
  padding: "40px 22px",
  textAlign: "center",
  border: "1px solid #E2E8F0",
  boxShadow:
    "0 7px 20px rgba(30,70,120,0.06)",
};


const emptyIcon = {
  fontSize: "42px",
  marginBottom: "8px",
};


const emptyTitle = {
  margin: "0 0 6px",
  color: "#173B70",
  fontSize: "18px",
};


const emptyText = {
  margin: 0,
  color: "#718096",
  fontSize: "13px",
};


// =====================================================
// ERROR
// =====================================================

const errorBox = {
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  gap: "8px",
  background: "#FFF5F5",
  color: "#C53030",
  border: "1px solid #FED7D7",
  borderRadius: "13px",
  padding: "14px",
  fontSize: "12px",
};


// =====================================================
// VOLVER
// =====================================================

const backContainer = {
  marginTop: "22px",
  display: "flex",
  justifyContent: "center",
};


const backButton = {
  border: "none",
  background: "#E3F2FD",
  color: "#1565C0",
  padding: "10px 19px",
  borderRadius: "11px",
  cursor: "pointer",
  fontWeight: "700",
  fontSize: "12px",
  boxShadow:
    "0 4px 12px rgba(21,101,192,0.08)",
};


// =====================================================
// LOADING
// =====================================================

const loadingPage = {
  minHeight: "100vh",
  display: "flex",
  justifyContent: "center",
  alignItems: "center",
  background:
    "linear-gradient(135deg, #eef6ff, #f8fbff)",
  padding: "20px",
  boxSizing: "border-box",
};


const loadingCard = {
  background: "#ffffff",
  padding: "38px",
  borderRadius: "18px",
  textAlign: "center",
  boxShadow:
    "0 10px 28px rgba(30,70,120,0.09)",
};


const loadingIcon = {
  fontSize: "36px",
  marginBottom: "8px",
};


const loadingTitle = {
  margin: "0 0 7px",
  color: "#173B70",
};


const loadingText = {
  margin: 0,
  color: "#718096",
  fontSize: "13px",
};


// =====================================================
// FOOTER
// =====================================================

const footer = {
  borderTop: "1px solid #E2E8F0",
  marginTop: "28px",
  paddingTop: "15px",
  display: "flex",
  justifyContent: "space-between",
  color: "#94A3B8",
  fontSize: "11px",
};