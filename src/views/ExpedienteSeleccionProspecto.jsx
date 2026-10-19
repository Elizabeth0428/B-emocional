import React, { useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { getToken } from "../services/AuthService";

const API_URL = import.meta.env.VITE_API_URL || (window.location.protocol === 'https:' ? 'https://reflejoyalma.com' : `http://${window.location.hostname}:5000`);

const SECTION_CONFIG = {
  entrevistas: {
    icon: "📅",
    title: "Entrevistas",
    subtitle: "Entrevistas realizadas o programadas durante el proceso.",
    background: "#EEF4FF",
    border: "#C9DAFF",
    accent: "#2167D5"
  },

  pruebas: {
    icon: "🧪",
    title: "Pruebas psicométricas",
    subtitle: "Resultados de las evaluaciones aplicadas durante el proceso.",
    background: "#EAF6FF",
    border: "#BFDFFF",
    accent: "#1677C8"
  },

  seguimiento: {
    icon: "📋",
    title: "Seguimiento",
    subtitle: "Bitácora y evolución del proceso de selección.",
    background: "#ECF8F0",
    border: "#C5E8D0",
    accent: "#2E7D4F"
  },

  documentos: {
    icon: "📁",
    title: "Documentos",
    subtitle: "CV, identificaciones y archivos relacionados con el proceso.",
    background: "#FFF7E2",
    border: "#F2DDA4",
    accent: "#9A6B00"
  },

  observaciones: {
    icon: "🗒️",
    title: "Observaciones de RH",
    subtitle: "Notas registradas por Recursos Humanos.",
    background: "#FFF1E8",
    border: "#F6D4C1",
    accent: "#B85C24"
  },

  ia: {
    icon: "🧠",
    title: "Análisis con IA",
    subtitle: "Síntesis de apoyo para Recursos Humanos.",
    background: "#F4EEFF",
    border: "#D8C7FF",
    accent: "#7540D5"
  },

  decision: {
    icon: "⚖️",
    title: "Decisión final del proceso",
    subtitle: "Cierre y resolución de Recursos Humanos.",
    background: "#EEF2F6",
    border: "#CCD6E0",
    accent: "#334155"
  }
};

export default function ExpedienteSeleccionProspecto() {
  const { idProspecto } = useParams();

  const navigate = useNavigate();

  const [prospecto, setProspecto] =
    useState(null);

  const [entrevistas, setEntrevistas] =
    useState([]);

  const [
    archivosEntrevistas,
    setArchivosEntrevistas
  ] = useState({});

  const [pruebas, setPruebas] =
    useState([]);

  const [documentos, setDocumentos] =
  useState([]);

  const [seguimiento, setSeguimiento] =
    useState([]);

  const [
    observaciones,
    setObservaciones
  ] = useState([]);

  const [reportesIA, setReportesIA] =
    useState([]);

  const [decision, setDecision] =
    useState(null);

  const [abierta, setAbierta] =
    useState(null);

  const [loading, setLoading] =
    useState(true);

  const [error, setError] =
    useState("");

  // ==================================================
  // OBTENER JSON
  // ==================================================

  const obtenerJSON = async (
    url,
    token
  ) => {
    const response =
      await fetch(
        url,
        {
          method: "GET",

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
        `Error ${response.status}`
      );
    }

    return data;
  };

  // ==================================================
  // CARGAR EXPEDIENTE
  // ==================================================

  useEffect(() => {
    if (!idProspecto) {
      setError(
        "No se recibió el identificador del prospecto."
      );

      setLoading(false);

      return;
    }

    const cargarExpediente =
      async () => {
        try {
          setLoading(true);
          setError("");

          const token =
            getToken();

          if (!token) {
            throw new Error(
              "Tu sesión no es válida. Inicia sesión nuevamente."
            );
          }

          // ============================================
          // PROSPECTO
          // ============================================

          const dataProspecto =
            await obtenerJSON(
              `${API_URL}/api/prospectos/${idProspecto}`,
              token
            );

          const persona =
            dataProspecto.prospecto ||
            dataProspecto.data ||
            dataProspecto;

          setProspecto(
            persona
          );

          // ============================================
          // MÓDULOS DEL EXPEDIENTE
          // ============================================

          const resultados =
            await Promise.allSettled([
              obtenerJSON(
                `${API_URL}/api/prospectos/${idProspecto}/entrevistas`,
                token
              ),

              obtenerJSON(
                `${API_URL}/api/prospectos/${idProspecto}/pruebas`,
                token
              ),

              obtenerJSON(
                `${API_URL}/api/prospectos/${idProspecto}/seguimiento`,
                token
              ),
             
              obtenerJSON(
              `${API_URL}/api/prospectos/${idProspecto}/documentos`,
              token
              ),

              obtenerJSON(
                `${API_URL}/api/prospectos/${idProspecto}/observaciones`,
                token
              ),

              obtenerJSON(
                `${API_URL}/api/prospectos/${idProspecto}/reportes-ia`,
                token
              ),

              obtenerJSON(
                `${API_URL}/api/prospectos/${idProspecto}/decision`,
                token
              )
            ]);

          // ============================================
          // ENTREVISTAS
          // ============================================

          if (
            resultados[0].status ===
            "fulfilled"
          ) {
            const data =
              resultados[0].value;

            const listaEntrevistas =
              Array.isArray(
                data.entrevistas
              )
                ? data.entrevistas
                : Array.isArray(
                    data
                  )
                ? data
                : [];

            setEntrevistas(
              listaEntrevistas
            );

            // ==========================================
            // EVIDENCIAS
            // ==========================================

            const resultadosArchivos =
              await Promise.allSettled(
                listaEntrevistas.map(
                  item =>
                    obtenerJSON(
                      `${API_URL}/api/archivos-rh/prospecto/${idProspecto}/entrevista/${item.id_entrevista}`,
                      token
                    )
                )
              );

            const mapa = {};

            resultadosArchivos.forEach(
              (
                resultado,
                index
              ) => {
                const id =
                  listaEntrevistas[
                    index
                  ]?.id_entrevista;

                if (!id) {
                  return;
                }

                if (
                  resultado.status ===
                  "fulfilled"
                ) {
                  const r =
                    resultado.value;

                  mapa[id] =
                    Array.isArray(
                      r.archivos
                    )
                      ? r.archivos
                      : Array.isArray(
                          r.data
                        )
                      ? r.data
                      : r.archivo
                      ? [r.archivo]
                      : r.ruta_video
                      ? [r]
                      : [];
                } else {
                  mapa[id] = [];
                }
              }
            );

            setArchivosEntrevistas(
              mapa
            );
          }

          // ============================================
          // PRUEBAS
          // ============================================

          if (
            resultados[1].status ===
            "fulfilled"
          ) {
            const data =
              resultados[1].value;

            setPruebas(
              Array.isArray(
                data.pruebas
              )
                ? data.pruebas
                : Array.isArray(
                    data
                  )
                ? data
                : []
            );
          }

          // ============================================
          // SEGUIMIENTO
          // ============================================

          if (
            resultados[2].status ===
            "fulfilled"
          ) {
            const data =
              resultados[2].value;

            setSeguimiento(
              Array.isArray(
                data.seguimientos
              )
                ? data.seguimientos
                : Array.isArray(
                    data.seguimiento
                  )
                ? data.seguimiento
                : Array.isArray(
                    data
                  )
                ? data
                : []
            );
          }

             // ============================================
          // DOCUMENTOS
          // ============================================

          if (
            resultados[3].status ===
            "fulfilled"
          ) {
            const data =
              resultados[3].value;

            setDocumentos(
              Array.isArray(
                data.documentos
              )
                ? data.documentos
                : Array.isArray(
                    data
                  )
                ? data
                : []
            );
          }

          // ============================================
          // OBSERVACIONES
          // ============================================

          if (
            resultados[4].status ===
            "fulfilled"
          ) {
            const data =
              resultados[4].value;

            setObservaciones(
              Array.isArray(
                data.observaciones
              )
                ? data.observaciones
                : Array.isArray(
                    data
                  )
                ? data
                : []
            );
          }

          // ============================================
          // IA
          // ============================================

          if (
            resultados[5].status ===
            "fulfilled"
          ) {
            const data =
              resultados[5].value;

            setReportesIA(
              Array.isArray(
                data.reportes
              )
                ? data.reportes
                : Array.isArray(
                    data.reportes_ia
                  )
                ? data.reportes_ia
                : Array.isArray(
                    data
                  )
                ? data
                : []
            );
          }

          // ============================================
          // DECISIÓN
          // ============================================

          if (
            resultados[6].status ===
            "fulfilled"
          ) {
            setDecision(
              resultados[6]
                .value
                .decision ||
              null
            );
          }

        } catch (err) {
          console.error(
            "❌ Error cargando expediente de selección:",
            err
          );

          setError(
            err.message ||
            "No fue posible cargar el expediente de selección."
          );

        } finally {
          setLoading(false);
        }
      };

    cargarExpediente();

  }, [
    idProspecto
  ]);

          

  // ==================================================
  // HELPERS
  // ==================================================

  const formatearFecha =
    fecha => {
      if (!fecha) {
        return "Sin fecha";
      }

      try {
        return new Date(
          fecha
        ).toLocaleString(
          "es-MX",
          {
            dateStyle:
              "medium",

            timeStyle:
              "short"
          }
        );
      } catch {
        return String(
          fecha
        );
      }
    };

  const textoEstado =
    valor =>
      String(
        valor ||
        "Sin registro"
      ).replaceAll(
        "_",
        " "
      );

  const obtenerNombrePrueba =
    prueba =>
      prueba.nombre ||
      prueba.nombre_prueba ||
      prueba.titulo ||
      `Prueba #${prueba.id_prueba || ""}`;

  const obtenerContenidoReporte =
    reporte =>
      reporte.analisis ||
      reporte.contenido ||
      reporte.reporte ||
      reporte.resultado ||
      reporte.texto ||
      "";

  const recortar =
    (
      texto,
      max = 450
    ) => {
      const limpio =
        String(
          texto || ""
        ).trim();

      return limpio.length <=
        max
        ? limpio
        : `${limpio.slice(
            0,
            max
          )}...`;
    };

  const obtenerUrlArchivo =
    ruta => {
      if (!ruta) {
        return "";
      }

      const valor =
        String(
          ruta
        ).trim();

      if (
        /^https?:\/\//i.test(
          valor
        ) ||
        valor.startsWith(
          "blob:"
        )
      ) {
        return valor;
      }

      return (
        `${API_URL}${
          valor.startsWith(
            "/"
          )
            ? ""
            : "/"
        }${valor}`
      );
    };

  // ==================================================
  // RESÚMENES
  // ==================================================

  const entrevistasRealizadas =
    entrevistas.filter(
      item =>
        String(
          item.estatus ||
          ""
        ).toLowerCase() ===
        "realizada"
    ).length;

  const archivosEntrevistasLista =
    Object.values(
      archivosEntrevistas
    ).flat();

  const grabaciones =
    archivosEntrevistasLista
      .length;

  const transcripciones =
    archivosEntrevistasLista
      .filter(
        item =>
          Boolean(
            String(
              item.transcripcion ||
              ""
            ).trim()
          )
      ).length;

  const pruebasCompletadas =
    pruebas.filter(
      item =>
        Boolean(
          item.id_resultado
        ) ||
        String(
          item.estatus ||
          ""
        ).toLowerCase() ===
          "completada"
    ).length;

  const ultimoReporte =
    reportesIA.length
      ? reportesIA[0]
      : null;

  const procesoCerrado =
    [
      "contratado",
      "no_contratado"
    ].includes(
      String(
        prospecto?.estatus ||
        ""
      )
        .trim()
        .toLowerCase()
    );

  const totalElementos =
  entrevistas.length +
  pruebas.length +
  seguimiento.length +
  documentos.length +
  observaciones.length +
  reportesIA.length;

  const resumenSecciones =
    useMemo(
      () => [
        {
          key:
            "entrevistas",

          count:
            entrevistas.length,

          note:
            `${entrevistasRealizadas} realizadas`
        },

        {
          key:
            "pruebas",

          count:
            pruebas.length,

          note:
            `${pruebasCompletadas} completadas`
        },

        {
          key:
            "seguimiento",

          count:
            seguimiento.length,

          note:
            "registros"
        },

        {
        key:
          "documentos", count:
          documentos.length, note:
          documentos.length === 1
          ? "1 documento registrado"
          : `${documentos.length} documentos registrados`
        },

        {
          key:
            "observaciones",

          count:
            observaciones.length,

          note:
            "registros"
        },

        {
          key:
            "ia",

          count:
            reportesIA.length,

          note:
            reportesIA.length
              ? "reporte disponible"
              : "sin reporte"
        },

        {
          key:
            "decision",

          count:
            decision ||
            procesoCerrado
              ? "✓"
              : "—",

          note:
            decision ||
            procesoCerrado
              ? "proceso cerrado"
              : "pendiente"
        }
      ],

      [
        entrevistas.length,
        entrevistasRealizadas,
        pruebas.length,
        pruebasCompletadas,
        seguimiento.length,
        documentos.length,
        observaciones.length,
        reportesIA.length,
        decision,
        procesoCerrado
      ]
    );

  const toggle =
    key => {
      setAbierta(
        actual =>
          actual === key
            ? null
            : key
      );
    };

  // ==================================================
  // LOADING
  // ==================================================

  if (loading) {
    return (
      <div
        style={
          styles.centerPage
        }
      >
        <div
          style={
            styles.centerCard
          }
        >
          <div
            style={
              styles.bigIcon
            }
          >
            📂
          </div>

          <h2>
            Preparando expediente
            de selección
          </h2>

          <p
            style={
              styles.muted
            }
          >
            Estamos reuniendo la
            información registrada
            durante el proceso.
          </p>

          <div
            style={
              styles.loadingText
            }
          >
            ⏳ Cargando expediente...
          </div>
        </div>
      </div>
    );
  }

  // ==================================================
  // ERROR
  // ==================================================

  if (
    error ||
    !prospecto
  ) {
    return (
      <div
        style={
          styles.centerPage
        }
      >
        <div
          style={
            styles.centerCard
          }
        >
          <div
            style={
              styles.bigIcon
            }
          >
            ⚠️
          </div>

          <h2>
            No se pudo abrir
            el expediente
          </h2>

          <p
            style={
              styles.errorText
            }
          >
            {error ||
              "Prospecto no encontrado."}
          </p>

          <button
            type="button"

            onClick={() =>
              navigate(
                `/prospecto/${idProspecto}`
              )
            }

            style={
              styles.secondaryButton
            }
          >
            ⬅ Volver al prospecto
          </button>
        </div>
      </div>
    );
  }

  // ==================================================
  // DATOS PRINCIPALES
  // ==================================================

  const nombre =
    prospecto.nombre ||
    "Prospecto";

  const idMirror =
    prospecto.id_mirror ||
    "Sin ID MirrorSoul";

  const puesto =
    prospecto.puesto ||
    "No registrado";

  const estado =
    textoEstado(
      prospecto.estatus ||
      "prospecto"
    );

  // ==================================================
  // RETURN
  // ==================================================

  return (
    <div style={styles.page}>

      {/* =============================================
          HEADER
      ============================================= */}

      <div
        style={
          styles.topBar
        }
      >
        <button
          type="button"

          onClick={() =>
            navigate(
              `/prospecto/${idProspecto}`
            )
          }

          style={
            styles.secondaryButton
          }
        >
          ⬅ Volver
        </button>

        <div>

          <div
            style={
              styles.eyebrow
            }
          >
            EXPEDIENTE FINAL
            DE SELECCIÓN
          </div>

          <h1
            style={
              styles.title
            }
          >
            📂 {nombre}
          </h1>

          <div
            style={
              styles.mirrorBadge
            }
          >
            🆔 {idMirror}
          </div>

        </div>
      </div>

      {/* =============================================
          RESUMEN SUPERIOR
      ============================================= */}

      <section
        style={
          styles.summaryCard
        }
      >
        <div
          style={
            styles.summaryTop
          }
        >
          <div>

            <div
              style={
                styles.smallLabel
              }
            >
              PUESTO
            </div>

            <div
              style={
                styles.summaryValue
              }
            >
              {puesto}
            </div>

          </div>

          <div>

            <div
              style={
                styles.smallLabel
              }
            >
              ESTADO DEL PROCESO
            </div>

            <div
              style={
                styles.statusBadge
              }
            >
              {estado}
            </div>

          </div>

          <div>

            <div
              style={
                styles.smallLabel
              }
            >
              ELEMENTOS REGISTRADOS
            </div>

            <div
              style={
                styles.summaryValue
              }
            >
              {totalElementos}
            </div>

          </div>
        </div>

        <div
          style={
            styles.summaryHint
          }
        >
          Selecciona una sección
          para desplegar su contenido.
          Solo una permanece abierta
          a la vez.
        </div>
      </section>

      {/* =============================================
          ACORDEONES
      ============================================= */}

      <div
        style={
          styles.accordionList
        }
      >

        {resumenSecciones.map(
          item => {
            const config =
              SECTION_CONFIG[
                item.key
              ];

            const abiertaAhora =
              abierta ===
              item.key;

            return (
              <section
                key={
                  item.key
                }

                style={{
                  ...styles.accordionCard,

                  borderColor:
                    config.border,

                  background:
                    config.background
                }}
              >

                {/* ===================================
                    CABECERA
                =================================== */}

                <button
                  type="button"

                  onClick={() =>
                    toggle(
                      item.key
                    )
                  }

                  style={
                    styles.accordionHeader
                  }
                >

                  <div
                    style={{
                      ...styles.accordionIcon,

                      color:
                        config.accent,

                      background:
                        "#FFFFFF"
                    }}
                  >
                    {config.icon}
                  </div>

                  <div
                    style={
                      styles.accordionHeaderText
                    }
                  >

                    <div
                      style={
                        styles.accordionTitle
                      }
                    >
                      {config.title}
                    </div>

                    <div
                      style={
                        styles.accordionSubtitle
                      }
                    >
                      {config.subtitle}
                    </div>

                  </div>

                  <div
                    style={
                      styles.accordionMeta
                    }
                  >

                    <div
                      style={{
                        ...styles.countPill,

                        color:
                          config.accent,

                        borderColor:
                          config.border
                      }}
                    >
                      {item.count}
                    </div>

                    <div
                      style={
                        styles.accordionNote
                      }
                    >
                      {item.note}
                    </div>

                  </div>

                  <div
                    style={{
                      ...styles.chevron,

                      color:
                        config.accent,

                      transform:
                        abiertaAhora
                          ? "rotate(180deg)"
                          : "rotate(0deg)"
                    }}
                  >
                    ▼
                  </div>

                </button>

                {/* ===================================
                    CONTENIDO
                =================================== */}

                {abiertaAhora && (

                  <div
                    style={
                      styles.accordionBody
                    }
                  >

                    {item.key ===
                      "entrevistas" && (

                      <EntrevistasSection
                        entrevistas={
                          entrevistas
                        }

                        archivosEntrevistas={
                          archivosEntrevistas
                        }

                        formatearFecha={
                          formatearFecha
                        }

                        textoEstado={
                          textoEstado
                        }

                        obtenerUrlArchivo={
                          obtenerUrlArchivo
                        }

                        navigate={
                          navigate
                        }

                        idProspecto={
                          idProspecto
                        }
                      />

                    )}

                    {item.key ===
                      "pruebas" && (

                      <PruebasSection
                        pruebas={
                          pruebas
                        }

                        obtenerNombrePrueba={
                          obtenerNombrePrueba
                        }

                        textoEstado={
                          textoEstado
                        }

                        recortar={
                          recortar
                        }

                        navigate={
                          navigate
                        }

                        idProspecto={
                          idProspecto
                        }
                      />

                    )}

                    {item.key ===
                      "seguimiento" && (

                      <SeguimientoSection
                        seguimiento={
                          seguimiento
                        }

                        formatearFecha={
                          formatearFecha
                        }

                        recortar={
                          recortar
                        }

                        navigate={
                          navigate
                        }

                        idProspecto={
                          idProspecto
                        }
                      />

                    )}

                   {item.key ===
                   "documentos" && (

                  <DocumentosSection
                  documentos={
                  documentos
                  }

                  formatearFecha={
                  formatearFecha
                  }

                  navigate={
                  navigate
                   }

                  idProspecto={
                  idProspecto
                    }
                  />

                  )}

                    {item.key ===
                      "observaciones" && (

                      <ObservacionesSection
                        observaciones={
                          observaciones
                        }

                        formatearFecha={
                          formatearFecha
                        }

                        recortar={
                          recortar
                        }

                        navigate={
                          navigate
                        }

                        idProspecto={
                          idProspecto
                        }
                      />

                    )}

                    {item.key ===
                      "ia" && (

                      <IASection
                        ultimoReporte={
                          ultimoReporte
                        }

                        obtenerContenidoReporte={
                          obtenerContenidoReporte
                        }

                        formatearFecha={
                          formatearFecha
                        }

                        recortar={
                          recortar
                        }

                        navigate={
                          navigate
                        }

                        idProspecto={
                          idProspecto
                        }
                      />

                    )}

                    {item.key ===
                      "decision" && (

                      <DecisionSection
                        decision={
                          decision
                        }

                        procesoCerrado={
                          procesoCerrado
                        }

                        prospecto={
                          prospecto
                        }

                        estado={
                          estado
                        }

                        textoEstado={
                          textoEstado
                        }

                        navigate={
                          navigate
                        }

                        idProspecto={
                          idProspecto
                        }
                      />

                    )}

                  </div>

                )}

              </section>
            );
          }
        )}

      </div>

      {/* =============================================
          FOOTER
      ============================================= */}

      <footer
        style={
          styles.footer
        }
      >

        <span>
          🧠 MirrorSoul
        </span>

        <span>
          Expediente final ·
          {" "}
          {idMirror}
        </span>

      </footer>

    </div>
  );
}

// ==================================================
// ENTREVISTAS
// ==================================================

function EntrevistasSection({
  entrevistas,
  archivosEntrevistas,
  formatearFecha,
  textoEstado,
  obtenerUrlArchivo,
  navigate,
  idProspecto
}) {

  if (
    !entrevistas.length
  ) {
    return (
      <EmptyText
        text="No existen entrevistas registradas."
      />
    );
  }

  return (
    <>

      <div
        style={
          styles.stack
        }
      >

        {entrevistas.map(
          item => {

            const archivos =
              archivosEntrevistas[
                item.id_entrevista
              ] || [];

            return (

              <article
                key={
                  item.id_entrevista
                }

                style={
                  styles.detailCard
                }
              >

                <div
                  style={
                    styles.detailTop
                  }
                >

                  <div>

                    <strong
                      style={
                        styles.detailTitle
                      }
                    >
                      {item.tipo_entrevista ||
                        "Entrevista"}
                    </strong>

                    <div
                      style={
                        styles.itemMeta
                      }
                    >
                      {item.modalidad ===
                      "videollamada"
                        ? "🎥 Videollamada"
                        : "🏢 Presencial"}

                      {" · "}

                      {formatearFecha(
                        item.fecha_entrevista
                      )}
                    </div>

                  </div>

                  <span
                    style={
                      styles.miniBadge
                    }
                  >
                    {textoEstado(
                      item.estatus
                    )}
                  </span>

                </div>

                {item.motivo && (

                  <InfoBlock
                    label="Motivo"
                    value={
                      item.motivo
                    }
                  />

                )}

                {(item.observaciones ||
                  item.observacion) && (

                  <InfoBlock
                    label="Observaciones"
                    value={
                      item.observaciones ||
                      item.observacion
                    }
                  />

                )}

                <div
                  style={
                    styles.subheading
                  }
                >
                  EVIDENCIAS
                </div>

                {!archivos.length ? (

                  <div
                    style={
                      styles.softEmpty
                    }
                  >
                    No hay grabaciones
                    o transcripciones
                    asociadas a esta
                    entrevista.
                  </div>

                ) : (

                  <div
                    style={
                      styles.stackSmall
                    }
                  >

                    {archivos.map(
                      (
                        archivo,
                        index
                      ) => {

                        const tipo =
                          String(
                            archivo.tipo ||
                            (
                              item.modalidad ===
                              "videollamada"
                                ? "video"
                                : "audio"
                            )
                          )
                            .toLowerCase();

                        const esAudio =
                          tipo ===
                          "audio";

                        const ruta =
                        obtenerUrlArchivo(
                        archivo.ruta_video ||
                        archivo.ruta_archivo ||
                        archivo.ruta ||
                        archivo.url ||
                        archivo.grabacion_url
                        );

                        const transcripcion =
                          String(
                            archivo.transcripcion ||
                            ""
                          ).trim();

                        return (

                          <div
                            key={
                              archivo.id_video_rh ||
                              archivo.id_archivo ||
                              `${item.id_entrevista}-${index}`
                            }

                            style={
                              styles.evidenceCard
                            }
                          >

                            <div
                              style={
                                styles.detailTop
                              }
                            >

                              <strong>
                                {esAudio
                                  ? "🎙️ Grabación de audio"
                                  : "🎥 Grabación de video"}
                              </strong>

                              <span
                                style={
                                  styles.evidenceBadge
                                }
                              >
                                {transcripcion
                                  ? "✅ Transcrita"
                                  : "— Sin transcripción"}
                              </span>

                            </div>

                            {ruta ? (

                              <div
                                style={
                                  styles.mediaBox
                                }
                              >

                                {esAudio ? (

                                <AudioProtegido
                                url={ruta}
                                style={
                                styles.audioPlayer
                                }
                                 />

                                ) : (

                                  <video
                                    controls
                                    preload="metadata"
                                    src={ruta}
                                    style={
                                      styles.videoPlayer
                                    }
                                  />

                                )}

                              </div>

                            ) : (

                              <div
                                style={
                                  styles.softEmpty
                                }
                              >
                                La evidencia está
                                registrada, pero no
                                contiene una ruta
                                disponible.
                              </div>

                            )}

                            <div
                              style={
                                styles.transcriptionBox
                              }
                            >

                              <div
                                style={
                                  styles.subheading
                                }
                              >
                                📝 Transcripción
                              </div>

                              <div
                                style={
                                  styles.transcriptionText
                                }
                              >
                                {transcripcion ||
                                  "Todavía no hay una transcripción disponible para esta grabación."}
                              </div>

                            </div>

                          </div>

                        );

                      }
                    )}

                  </div>

                )}

              </article>

            );

          }
        )}

      </div>

      <ModuleButton
        text="Abrir módulo de entrevistas"

        onClick={() =>
          navigate(
            `/prospecto/${idProspecto}/entrevistas`
          )
        }
      />

    </>
  );
}

// ==================================================
// PRUEBAS
// ==================================================

function PruebasSection({
  pruebas,
  obtenerNombrePrueba,
  textoEstado,
  recortar,
  navigate,
  idProspecto
}) {

  if (
    !pruebas.length
  ) {
    return (
      <EmptyText
        text="No hay pruebas psicométricas registradas."
      />
    );
  }

  return (
    <>

      <div
        style={
          styles.stack
        }
      >

        {pruebas.map(
          (
            item,
            index
          ) => (

            <article
              key={
                item.id_habilitacion ||
                item.id_resultado ||
                item.id_prueba ||
                index
              }

              style={
                styles.detailCard
              }
            >

              <div
                style={
                  styles.detailTop
                }
              >

                <div>

                  <strong
                    style={
                      styles.detailTitle
                    }
                  >
                    {obtenerNombrePrueba(
                      item
                    )}
                  </strong>

                  <div
                    style={
                      styles.itemMeta
                    }
                  >
                    {item.categoria ||
                      "Evaluación psicométrica"}

                    {item.version
                      ? ` · ${item.version}`
                      : ""}
                  </div>

                </div>

                <span
                  style={
                    styles.miniBadge
                  }
                >
                  {textoEstado(
                    item.estatus ||
                    (
                      item.id_resultado
                        ? "completada"
                        : "pendiente"
                    )
                  )}
                </span>

              </div>

              <ResultadoPruebaPsicometrica
                item={
                  item
                }

                recortar={
                  recortar
                }
              />

            </article>

          )
        )}

      </div>

      <ModuleButton
        text="Abrir módulo de pruebas"

        onClick={() =>
          navigate(
            `/prospecto/${idProspecto}/pruebas`
          )
        }
      />

    </>
  );
}

// ==================================================
// RESULTADO DE PRUEBA
// ==================================================

function ResultadoPruebaPsicometrica({
  item,
  recortar
}) {

  const nombre =
    String(
      item?.nombre ||
      item?.nombre_prueba ||
      ""
    )
      .trim()
      .toLowerCase();

  const version =
    String(
      item?.version ||
      ""
    )
      .trim()
      .toLowerCase();

  const esRaven =
    Number(
      item?.id_prueba_rh
    ) === 3 ||
    nombre.includes(
      "raven"
    ) ||
    version.includes(
      "raven-spm"
    );

  const esORVIS =
    nombre.includes(
      "orvis"
    ) ||
    version.includes(
      "orvis-92"
    );

  const esIPIP =
    nombre.includes(
      "ipip-50"
    ) ||
    version.includes(
      "ipip-bffm-50"
    );

  const lineas =
    String(
      item?.resultado_texto ||
      ""
    )
      .split("\n")
      .map(
        linea =>
          linea.trim()
      )
      .filter(Boolean);

  // ==================================================
  // RAVEN SPM
  // ==================================================

  if (esRaven) {

    const obtenerValor =
      (prefijo) => {

        const linea =
          lineas.find(
            texto =>
              texto
                .toLowerCase()
                .startsWith(
                  prefijo.toLowerCase()
                )
          );

        if (!linea) {
          return null;
        }

        const partes =
          linea.split(":");

        return partes
          .slice(1)
          .join(":")
          .trim();
      };

    const obtenerSerie =
      (serie) => {

        const valor =
          obtenerValor(
            `Serie ${serie}`
          );

        if (!valor) {
          return null;
        }

        const match =
          valor.match(
            /(\d+(?:\.\d+)?)\s*\/\s*12/
          );

        if (!match) {
          return null;
        }

        return Number(
          match[1]
        );
      };

    const serieA =
      obtenerSerie("A");

    const serieB =
      obtenerSerie("B");

    const serieC =
      obtenerSerie("C");

    const serieD =
      obtenerSerie("D");

    const serieE =
      obtenerSerie("E");

    const puntajeTexto =
      obtenerValor(
        "Puntaje bruto total"
      );

    const banda =
      obtenerValor(
        "Banda percentilar"
      );

    const rango =
      obtenerValor(
        "Rango"
      );

    const clasificacion =
      obtenerValor(
        "Clasificación"
      );

    const puntaje =
      item?.puntaje_total !==
        null &&
      item?.puntaje_total !==
        undefined
        ? Number(
            item.puntaje_total
          )
        : Number(
            String(
              puntajeTexto || ""
            )
              .split("/")[0]
          );

    const interpretacion =
      String(
        item?.interpretacion ||
        ""
      ).trim();

    return (
      <>

        {/* ==========================================
            ENCABEZADO DEL RESULTADO
        ========================================== */}

        <div
          style={
            styles.testIntro
          }
        >

          <strong>
            Resultado psicométrico
            Raven SPM
          </strong>

          <span>
            Evaluación de razonamiento
            no verbal mediante matrices
            progresivas.
          </span>

        </div>

        {/* ==========================================
            RESUMEN PRINCIPAL
        ========================================== */}

        <div
          style={{
            display:
              "grid",

            gridTemplateColumns:
              "repeat(auto-fit, minmax(160px, 1fr))",

            gap:
              "12px",

            marginBottom:
              "18px"
          }}
        >

          <div
            style={{
              padding:
                "16px",

              borderRadius:
                "12px",

              background:
                "#F8FAFC",

              border:
                "1px solid #E2E8F0"
            }}
          >
            <div
              style={{
                fontSize:
                  "11px",

                fontWeight:
                  "800",

                color:
                  "#64748B",

                marginBottom:
                  "6px"
              }}
            >
              PUNTAJE BRUTO
            </div>

            <div
              style={{
                fontSize:
                  "23px",

                fontWeight:
                  "800",

                color:
                  "#0F172A"
              }}
            >
              {Number.isFinite(
                puntaje
              )
                ? `${puntaje} / 60`
                : "No disponible"}
            </div>
          </div>

          <div
            style={{
              padding:
                "16px",

              borderRadius:
                "12px",

              background:
                "#F8FAFC",

              border:
                "1px solid #E2E8F0"
            }}
          >
            <div
              style={{
                fontSize:
                  "11px",

                fontWeight:
                  "800",

                color:
                  "#64748B",

                marginBottom:
                  "6px"
              }}
            >
              BANDA PERCENTILAR
            </div>

            <div
              style={{
                fontSize:
                  "19px",

                fontWeight:
                  "800",

                color:
                  "#2167D5"
              }}
            >
              {banda ||
                "No disponible"}
            </div>
          </div>

          <div
            style={{
              padding:
                "16px",

              borderRadius:
                "12px",

              background:
                "#F8FAFC",

              border:
                "1px solid #E2E8F0"
            }}
          >
            <div
              style={{
                fontSize:
                  "11px",

                fontWeight:
                  "800",

                color:
                  "#64748B",

                marginBottom:
                  "6px"
              }}
            >
              RANGO
            </div>

            <div
              style={{
                fontSize:
                  "23px",

                fontWeight:
                  "800",

                color:
                  "#0F172A"
              }}
            >
              {rango ||
                "No disponible"}
            </div>
          </div>

          <div
            style={{
              padding:
                "16px",

              borderRadius:
                "12px",

              background:
                "#EEF4FF",

              border:
                "1px solid #C9DAFF"
            }}
          >
            <div
              style={{
                fontSize:
                  "11px",

                fontWeight:
                  "800",

                color:
                  "#64748B",

                marginBottom:
                  "6px"
              }}
            >
              CLASIFICACIÓN
            </div>

            <div
              style={{
                fontSize:
                  "18px",

                fontWeight:
                  "800",

                color:
                  "#2167D5"
              }}
            >
              {clasificacion ||
                "No disponible"}
            </div>
          </div>

        </div>

        {/* ==========================================
            RESULTADOS POR SERIE
        ========================================== */}

        <div
          style={{
            margin:
              "20px 0 10px",

            fontSize:
              "13px",

            fontWeight:
              "800",

            color:
              "#334155",

            letterSpacing:
              ".4px"
          }}
        >
          RESULTADOS POR SERIE
        </div>

        <div
          style={
            styles.dimensionList
          }
        >

          {serieA !== null && (

            <DimensionBar
              name="Serie A"
              value={serieA}
              max={12}
              label={
                `${serieA} / 12`
              }
            />

          )}

          {serieB !== null && (

            <DimensionBar
              name="Serie B"
              value={serieB}
              max={12}
              label={
                `${serieB} / 12`
              }
            />

          )}

          {serieC !== null && (

            <DimensionBar
              name="Serie C"
              value={serieC}
              max={12}
              label={
                `${serieC} / 12`
              }
            />

          )}

          {serieD !== null && (

            <DimensionBar
              name="Serie D"
              value={serieD}
              max={12}
              label={
                `${serieD} / 12`
              }
            />

          )}

          {serieE !== null && (

            <DimensionBar
              name="Serie E"
              value={serieE}
              max={12}
              label={
                `${serieE} / 12`
              }
            />

          )}

        </div>

        {/* ==========================================
            RESULTADO FINAL
        ========================================== */}

        {(rango ||
          clasificacion) && (

          <div
            style={{
              marginTop:
                "20px",

              padding:
                "18px",

              borderRadius:
                "14px",

              background:
                "#ECF8F0",

              border:
                "1px solid #C5E8D0"
            }}
          >

            <div
              style={{
                fontSize:
                  "11px",

                fontWeight:
                  "800",

                color:
                  "#64748B",

                marginBottom:
                  "6px"
              }}
            >
              RESULTADO PSICOMÉTRICO
            </div>

            <div
              style={{
                fontSize:
                  "21px",

                fontWeight:
                  "800",

                color:
                  "#2E7D4F"
              }}
            >
              {rango
                ? `Rango ${rango}`
                : "Rango no disponible"}

              {clasificacion
                ? ` — ${clasificacion}`
                : ""}
            </div>

            {banda && (

              <div
                style={{
                  marginTop:
                    "7px",

                  color:
                    "#475569",

                  fontSize:
                    "14px"
                }}
              >
                Banda percentilar:{" "}
                <strong>
                  {banda}
                </strong>
              </div>

            )}

          </div>

        )}

        {/* ==========================================
            INTERPRETACIÓN
        ========================================== */}

        {interpretacion && (

          <InfoBlock
            label="Interpretación del resultado"

            value={
              interpretacion
            }
          />

        )}

        {/* ==========================================
            INTERPRETACIÓN LABORAL
        ========================================== */}

        {item.interpretacion_laboral && (

          <InfoBlock
            label="Consideración para Recursos Humanos"

            value={
              recortar(
                item.interpretacion_laboral,
                800
              )
            }
          />

        )}

      </>
    );
  }

  // ==================================================
  // ORVIS
  // ==================================================

  if (esORVIS) {

    const dimensiones =
      lineas
        .map(
          linea => {

            const match =
              linea.match(
                /^(.+?):\s*suma\s*([\d.]+)\/([\d.]+)\s*\|\s*promedio\s*([\d.]+)\/5(?:\s*\|\s*(\d+)\s*reactivos)?$/i
              );

            if (!match) {
              return null;
            }

            return {
              nombre:
                match[1],

              suma:
                match[2],

              maximo:
                match[3],

              promedio:
                match[4],

              reactivos:
                match[5]
            };
          }
        )
        .filter(Boolean)
        .sort(
          (
            a,
            b
          ) =>
            Number(
              b.promedio
            ) -
            Number(
              a.promedio
            )
        );

    return (
      <>

        <div
          style={
            styles.testIntro
          }
        >

          <strong>
            Perfil de intereses
            vocacionales
          </strong>

          <span>
            Los resultados se presentan
            por dimensión. No existe una
            calificación global ORVIS.
          </span>

        </div>

        {dimensiones.length ? (

          <div
            style={
              styles.dimensionList
            }
          >

            {dimensiones.map(
              dimension => (

                <DimensionBar
                  key={
                    dimension.nombre
                  }

                  name={
                    dimension.nombre
                  }

                  value={
                    Number(
                      dimension.promedio
                    )
                  }

                  max={5}

                  label={
                    `${dimension.promedio} / 5`
                  }

                  meta={
                    `Suma ${dimension.suma}/${dimension.maximo}${
                      dimension.reactivos
                        ? ` · ${dimension.reactivos} reactivos`
                        : ""
                    }`
                  }
                />

              )
            )}

          </div>

        ) : (

          <InfoBlock
            label="Resultado ORVIS"

            value={
              item.resultado_texto ||
              "Resultado registrado."
            }
          />

        )}

        {item.interpretacion_laboral && (

          <InfoBlock
            label="Interpretación laboral"

            value={
              recortar(
                item.interpretacion_laboral,
                600
              )
            }
          />

        )}

      </>
    );
  }

  // ==================================================
  // IPIP-50
  // ==================================================

  if (esIPIP) {

    const dimensiones =
      lineas
        .map(
          linea => {

            const match =
              linea.match(
                /^(.+?):\s*([\d.]+)\/50$/i
              );

            if (!match) {
              return null;
            }

            return {
              nombre:
                match[1],

              puntaje:
                match[2]
            };
          }
        )
        .filter(Boolean)
        .sort(
          (
            a,
            b
          ) =>
            Number(
              b.puntaje
            ) -
            Number(
              a.puntaje
            )
        );

    return (
      <>

        <div
          style={
            styles.testIntro
          }
        >

          <strong>
            Perfil de personalidad
            por dimensiones
          </strong>

          <span>
            El total técnico acumulado
            no representa una calificación
            global de personalidad.
          </span>

        </div>

        {dimensiones.length ? (

          <div
            style={
              styles.dimensionList
            }
          >

            {dimensiones.map(
              dimension => (

                <DimensionBar
                  key={
                    dimension.nombre
                  }

                  name={
                    dimension.nombre
                  }

                  value={
                    Number(
                      dimension.puntaje
                    )
                  }

                  max={50}

                  label={
                    `${dimension.puntaje} / 50`
                  }
                />

              )
            )}

          </div>

        ) : item.resultado_texto ? (

          <InfoBlock
            label="Resultado"

            value={
              item.resultado_texto
            }
          />

        ) : null}

        {item.interpretacion_laboral && (

          <InfoBlock
            label="Interpretación laboral"

            value={
              recortar(
                item.interpretacion_laboral,
                600
              )
            }
          />

        )}

      </>
    );
  }

  // ==================================================
  // OTRAS PRUEBAS
  // ==================================================

  return (
    <>

      {item.puntaje_total !==
        null &&
        item.puntaje_total !==
        undefined && (

        <InfoBlock
          label="Puntaje"
          value={
            item.puntaje_total
          }
        />

      )}

      {item.interpretacion && (

        <InfoBlock
          label="Interpretación"

          value={
            recortar(
              item.interpretacion,
              600
            )
          }
        />

      )}

      {item.interpretacion_laboral && (

        <InfoBlock
          label="Interpretación laboral"

          value={
            recortar(
              item.interpretacion_laboral,
              400
            )
          }
        />

      )}

    </>
  );
}

// ==================================================
// BARRA DE DIMENSIÓN
// ==================================================

function DimensionBar({
  name,
  value,
  max,
  label,
  meta
}) {

  const porcentaje =
    Math.max(
      0,
      Math.min(
        100,
        (
          value /
          max
        ) *
        100
      )
    );

  return (
    <div
      style={
        styles.dimensionRow
      }
    >

      <div
        style={
          styles.dimensionTop
        }
      >

        <strong>
          {name}
        </strong>

        <span
          style={
            styles.dimensionValue
          }
        >
          {label}
        </span>

      </div>

      <div
        style={
          styles.barTrack
        }
      >

        <div
          style={{
            ...styles.barFill,

            width:
              `${porcentaje}%`
          }}
        />

      </div>

      {meta && (

        <div
          style={
            styles.dimensionMeta
          }
        >
          {meta}
        </div>

      )}

    </div>
  );
}

// ==================================================
// SEGUIMIENTO
// ==================================================

function SeguimientoSection({
  seguimiento,
  formatearFecha,
  recortar,
  navigate,
  idProspecto
}) {

  if (
    !seguimiento.length
  ) {
    return (
      <EmptyText
        text="No existen registros de seguimiento."
      />
    );
  }

  return (
    <>

      <div
        style={
          styles.timeline
        }
      >

        {seguimiento.map(
          (
            item,
            index
          ) => (

            <div
              key={
                item.id_seguimiento ||
                index
              }

              style={
                styles.timelineItem
              }
            >

              <div
                style={
                  styles.timelineDot
                }
              />

              <div
                style={
                  styles.timelineContent
                }
              >

                <div
                  style={
                    styles.detailTop
                  }
                >

                  <strong>
                    {item.titulo ||
                      item.tipo ||
                      "Seguimiento"}
                  </strong>

                  <span
                    style={
                      styles.itemMeta
                    }
                  >
                    {formatearFecha(
                      item.fecha ||
                      item.fecha_registro ||
                      item.creado_en
                    )}
                  </span>

                </div>

                <div
                  style={
                    styles.timelineText
                  }
                >
                  {recortar(
                    item.descripcion ||
                    item.observacion ||
                    item.notas ||
                    item.comentario ||
                    "",
                    500
                  )}
                </div>

              </div>

            </div>

          )
        )}

      </div>

      <ModuleButton
        text="Abrir seguimiento"

        onClick={() =>
          navigate(
            `/prospecto/${idProspecto}/seguimiento`
          )
        }
      />

    </>
  );
}


// ==================================================
// DOCUMENTOS
// ==================================================

function DocumentosSection({
  documentos,
  formatearFecha,
  navigate,
  idProspecto
}) {

  const [abriendoId, setAbriendoId] =
    useState(null);

  const [
    errorDocumentos,
    setErrorDocumentos
  ] = useState("");

  const tipos = {
    cv: {
      label: "Currículum / CV",
      icon: "📄"
    },

    identificacion: {
      label: "Identificación",
      icon: "🪪"
    },

    constancia: {
      label: "Constancia",
      icon: "📋"
    },

    certificado: {
      label: "Certificado",
      icon: "🎓"
    },

    comprobante: {
      label: "Comprobante",
      icon: "🧾"
    },

    otro: {
      label: "Otro documento",
      icon: "📎"
    }
  };

  const obtenerTipo =
    valor =>
      tipos[valor] || {
        label:
          valor ||
          "Documento",

        icon:
          "📎"
      };

  const formatearMime =
    mime => {

      const mapa = {
        "application/pdf":
          "PDF",

        "image/jpeg":
          "Imagen JPG",

        "image/png":
          "Imagen PNG",

        "application/msword":
          "Documento Word",

        "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
          "Documento Word"
      };

      return (
        mapa[mime] ||
        mime ||
        "Archivo"
      );
    };

  // ================================================
  // OBTENER ARCHIVO PROTEGIDO
  // ================================================

  const obtenerArchivo =
    async documento => {

      try {

        setAbriendoId(
          documento.id_documento
        );

        setErrorDocumentos("");

        const token =
          getToken();

        if (!token) {

          throw new Error(
            "Tu sesión no es válida. Inicia sesión nuevamente."
          );

        }

        const response =
          await fetch(
            `${API_URL}/api/prospectos/${idProspecto}/documentos/${documento.id_documento}/archivo`,
            {
              headers: {
                Authorization:
                  `Bearer ${token}`
              }
            }
          );

        if (!response.ok) {

          const data =
            await response
              .json()
              .catch(
                () => ({})
              );

          throw new Error(
            data.message ||
            "No fue posible abrir el documento."
          );

        }

        return await response.blob();

      } finally {

        setAbriendoId(null);

      }
    };

  // ================================================
  // VER
  // ================================================

  const abrirDocumento =
    async documento => {

      try {

        const blob =
          await obtenerArchivo(
            documento
          );

        const url =
          URL.createObjectURL(
            blob
          );

        window.open(
          url,
          "_blank",
          "noopener,noreferrer"
        );

        setTimeout(
          () => {

            URL.revokeObjectURL(
              url
            );

          },
          60000
        );

      } catch (err) {

        console.error(
          "❌ Error abriendo documento desde expediente:",
          err
        );

        setErrorDocumentos(
          err.message ||
          "No fue posible abrir el documento."
        );

      }
    };

  // ================================================
  // DESCARGAR
  // ================================================

  const descargarDocumento =
    async documento => {

      try {

        const blob =
          await obtenerArchivo(
            documento
          );

        const url =
          URL.createObjectURL(
            blob
          );

        const link =
          document.createElement(
            "a"
          );

        link.href =
          url;

        link.download =
          documento.nombre_original ||
          "documento";

        document.body.appendChild(
          link
        );

        link.click();

        link.remove();

        URL.revokeObjectURL(
          url
        );

      } catch (err) {

        console.error(
          "❌ Error descargando documento desde expediente:",
          err
        );

        setErrorDocumentos(
          err.message ||
          "No fue posible descargar el documento."
        );

      }
    };

  // ================================================
  // VISTA
  // ================================================

  return (
    <>

      {errorDocumentos && (

        <div
          style={
            styles.documentError
          }
        >
          ⚠️ {errorDocumentos}
        </div>

      )}

      {!documentos.length ? (

        <EmptyText
          text="No hay documentos registrados para este prospecto."
        />

      ) : (

        <div
          style={
            styles.documentList
          }
        >

          {documentos.map(
            documento => {

              const tipo =
                obtenerTipo(
                  documento.tipo_documento
                );

              const ocupado =
                abriendoId ===
                documento.id_documento;

              return (

                <article
                  key={
                    documento.id_documento
                  }

                  style={
                    styles.documentRow
                  }
                >

                  <div
                    style={
                      styles.documentFileIcon
                    }
                  >
                    {tipo.icon}
                  </div>

                  <div
                    style={
                      styles.documentInfo
                    }
                  >

                    <div
                      style={
                        styles.documentName
                      }
                    >
                      {documento.nombre_original ||
                        "Documento"}
                    </div>

                    <div
                      style={
                        styles.documentBadges
                      }
                    >

                      <span
                        style={
                          styles.documentTypeBadge
                        }
                      >
                        {tipo.label}
                      </span>

                      <span
                        style={
                          styles.documentMimeBadge
                        }
                      >
                        {formatearMime(
                          documento.mime_type
                        )}
                      </span>

                    </div>

                    {documento.descripcion && (

                      <div
                        style={
                          styles.documentDescription
                        }
                      >
                        {documento.descripcion}
                      </div>

                    )}

                    <div
                      style={
                        styles.documentDate
                      }
                    >
                      📅{" "}
                      {formatearFecha(
                        documento.fecha_subida
                      )}
                    </div>

                  </div>

                  <div
                    style={
                      styles.documentActions
                    }
                  >

                    <button
                      type="button"

                      disabled={
                        ocupado
                      }

                      style={{
                        ...styles.documentViewButton,

                        opacity:
                          ocupado
                            ? 0.6
                            : 1
                      }}

                      onClick={() =>
                        abrirDocumento(
                          documento
                        )
                      }
                    >
                      {ocupado
                        ? "⏳"
                        : "👁️"}{" "}
                      Ver
                    </button>

                    <button
                      type="button"

                      disabled={
                        ocupado
                      }

                      style={{
                        ...styles.documentDownloadButton,

                        opacity:
                          ocupado
                            ? 0.6
                            : 1
                      }}

                      onClick={() =>
                        descargarDocumento(
                          documento
                        )
                      }
                    >
                      ⬇️ Descargar
                    </button>

                  </div>

                </article>

              );

            }
          )}

        </div>

      )}

      <div
        style={
          styles.documentNotice
        }
      >
        🔐 Estos archivos forman parte
        del expediente interno de selección
        y deben ser consultados únicamente
        por personal autorizado.
      </div>

      <ModuleButton
        text="Abrir módulo de documentos"

        onClick={() =>
          navigate(
            `/prospecto/${idProspecto}/documentos`
          )
        }
      />

    </>
  );
}

// ==================================================
// OBSERVACIONES
// ==================================================

function ObservacionesSection({
  observaciones,
  formatearFecha,
  recortar,
  navigate,
  idProspecto
}) {

  if (
    !observaciones.length
  ) {
    return (
      <EmptyText
        text="No existen observaciones registradas."
      />
    );
  }

  return (
    <>

      <div
        style={
          styles.stackSmall
        }
      >

        {observaciones.map(
          (
            item,
            index
          ) => (

            <article
              key={
                item.id_observacion ||
                index
              }

              style={
                styles.noteCard
              }
            >

              <div
                style={
                  styles.detailTop
                }
              >

                <strong>
                  {item.titulo ||
                    textoSeguro(
                      item.tipo
                    ) ||
                    "Observación"}
                </strong>

                <span
                  style={
                    styles.itemMeta
                  }
                >
                  {formatearFecha(
                    item.fecha ||
                    item.fecha_registro ||
                    item.creado_en
                  )}
                </span>

              </div>

              <div
                style={
                  styles.noteText
                }
              >
                {recortar(
                  item.observacion ||
                  item.descripcion ||
                  "",
                  700
                )}
              </div>

            </article>

          )
        )}

      </div>

      <ModuleButton
        text="Abrir observaciones"

        onClick={() =>
          navigate(
            `/prospecto/${idProspecto}/observaciones`
          )
        }
      />

    </>
  );
}

// ==================================================
// IA
// ==================================================

function IASection({
  ultimoReporte,
  obtenerContenidoReporte,
  formatearFecha,
  recortar,
  navigate,
  idProspecto
}) {

  return (
    <>

      {ultimoReporte ? (

        <div
          style={
            styles.aiReportBox
          }
        >

          <div
            style={
              styles.detailTop
            }
          >

            <strong>
              Último reporte generado
            </strong>

            <span
              style={
                styles.itemMeta
              }
            >
              {formatearFecha(
                ultimoReporte.fecha ||
                ultimoReporte.fecha_reporte ||
                ultimoReporte.creado_en
              )}
            </span>

          </div>

          <div
            style={
              styles.aiText
            }
          >
            {recortar(
              obtenerContenidoReporte(
                ultimoReporte
              ),
              1800
            ) ||
              "El reporte existe, pero no se encontró contenido textual para mostrar."}
          </div>

        </div>

      ) : (

        <EmptyText
          text="Todavía no se ha generado un reporte IA para este prospecto."
        />

      )}

      <div
        style={
          styles.aiNotice
        }
      >
        ⚠️ El reporte IA es una
        herramienta de apoyo.
        La decisión final corresponde
        a Recursos Humanos.
      </div>

      <ModuleButton
        text="Abrir reporte IA"

        purple

        onClick={() =>
          navigate(
            `/prospecto/${idProspecto}/reporte-ia`
          )
        }
      />

    </>
  );
}

// ==================================================
// DECISIÓN FINAL
// ==================================================

function DecisionSection({
  decision,
  procesoCerrado,
  prospecto,
  estado,
  textoEstado,
  navigate,
  idProspecto
}) {

  if (decision) {

  return (
    <div>

      <div
        style={
          styles.decisionSaved
        }
      >

        <div
          style={
            styles.decisionLabel
          }
        >
          DECISIÓN REGISTRADA
        </div>

        <div
          style={
            styles.decisionResult
          }
        >
          {textoEstado(
            decision.decision ||
            prospecto.estatus
          )}
        </div>

        {decision.motivo && (
          <InfoBlock
            label="Motivo"
            value={
              decision.motivo
            }
          />
        )}

        {decision.observaciones && (
          <InfoBlock
            label="Observaciones finales"
            value={
              decision.observaciones
            }
          />
        )}

      </div>

      <div
        style={
          styles.decisionQuestion
        }
      >
        ¿Deseas modificar la decisión?
      </div>

      <div
        style={
          styles.decisionButtons
        }
      >

        <button
          type="button"
          style={
            styles.hireButton
          }
          onClick={() =>
            navigate(
              `/prospecto/${idProspecto}/decision?resultado=contratar`
            )
          }
        >
          ✅ Contratar

          <span
            style={
              styles.buttonSubtext
            }
          >
            Registrar o actualizar
            como contratación
          </span>
        </button>

        <button
          type="button"
          style={
            styles.rejectButton
          }
          onClick={() =>
            navigate(
              `/prospecto/${idProspecto}/decision?resultado=no_contratar`
            )
          }
        >
          ❌ No contratar

          <span
            style={
              styles.buttonSubtext
            }
          >
            Registrar o actualizar
            como no contratación
          </span>
        </button>

      </div>

    </div>
  );
}
  // ==================================================
  // PROCESO CERRADO SIN OBJETO DECISIÓN
  // ==================================================

  if (procesoCerrado) {

    return (
      <div
        style={
          styles.decisionSaved
        }
      >

        <div
          style={
            styles.decisionLabel
          }
        >
          PROCESO CERRADO
        </div>

        <div
          style={
            styles.decisionResult
          }
        >
          {estado}
        </div>

      </div>
    );
  }

  // ==================================================
  // DECISIÓN PENDIENTE
  // ==================================================

  return (
    <div>

      <div
        style={
          styles.decisionIntro
        }
      >

        <div>

          <strong>
            Antes de registrar
            la decisión final
          </strong>

          <p
            style={
              styles.decisionText
            }
          >
            Revisa entrevistas,
            pruebas psicométricas,
            seguimiento, documentos,
            observaciones y análisis IA.
            La decisión final corresponde
            a Recursos Humanos.
          </p>

        </div>

      </div>

      <div
        style={
          styles.decisionQuestion
        }
      >
        ¿Qué desea registrar
        Recursos Humanos?
      </div>

      <div
        style={
          styles.decisionButtons
        }
      >

        {/* ===========================================
            CONTRATAR
        =========================================== */}

        <button
          type="button"

          style={
            styles.hireButton
          }

          onClick={() =>
            navigate(
              `/prospecto/${idProspecto}/decision?resultado=contratar`
            )
          }
        >

          ✅ Contratar

          <span
            style={
              styles.buttonSubtext
            }
          >
            Continuar con la
            conversión a empleado
          </span>

        </button>

        {/* ===========================================
            NO CONTRATAR
        =========================================== */}

        <button
          type="button"

          style={
            styles.rejectButton
          }

          onClick={() =>
            navigate(
              `/prospecto/${idProspecto}/decision?resultado=no_contratar`
            )
          }
        >

          ❌ No contratar

          <span
            style={
              styles.buttonSubtext
            }
          >
            Registrar motivo y
            cerrar el proceso
          </span>

        </button>

      </div>

      <div
        style={
          styles.decisionFooter
        }
      >
        💡 Si RH decide contratar,
        MirrorSoul conserva el vínculo
        con el historial del proceso
        de selección.
      </div>

    </div>
  );
}

// ==================================================
// TEXTO SEGURO
// ==================================================

function textoSeguro(
  valor
) {

  if (!valor) {
    return "";
  }

  return String(
    valor
  ).replaceAll(
    "_",
    " "
  );
}

// ==================================================
// INFO BLOCK
// ==================================================

function InfoBlock({
  label,
  value
}) {

  return (
    <div
      style={
        styles.infoBlock
      }
    >

      <div
        style={
          styles.infoLabel
        }
      >
        {label}
      </div>

      <div
        style={
          styles.infoValue
        }
      >
        {value}
      </div>

    </div>
  );
}

// ==================================================
// EMPTY
// ==================================================

function EmptyText({
  text
}) {

  return (
    <div
      style={
        styles.emptyBox
      }
    >
      {text}
    </div>
  );
}

// ==================================================
// BOTÓN DE MÓDULO
// ==================================================

function ModuleButton({
  text,
  onClick,
  purple = false
}) {

  return (
    <button
      type="button"

      onClick={
        onClick
      }

      style={{
        ...styles.moduleButton,

        background:
          purple
            ? "#7540D5"
            : "#2167D5"
      }}
    >

      {text}

      <span>
        →
      </span>

    </button>
  );
}

function AudioProtegido({
  url,
  style
}) {
  const [src, setSrc] =
    React.useState("");

  const [error, setError] =
    React.useState("");

  React.useEffect(() => {
    let objectUrl = "";
    let activo = true;

    const cargarAudio =
      async () => {
        try {
          setError("");

          const token =
            getToken();

          if (!token) {
            throw new Error(
              "No hay una sesión válida."
            );
          }

          const response =
            await fetch(
              url,
              {
                headers: {
                  Authorization:
                    `Bearer ${token}`
                }
              }
            );

          if (!response.ok) {
            throw new Error(
              `No se pudo cargar el audio (${response.status}).`
            );
          }

          const blob =
            await response.blob();

          console.log(
            "🎧 Audio cargado:",
            {
              size: blob.size,
              type: blob.type,
              url
            }
          );

          if (!blob.size) {
            throw new Error(
              "El archivo de audio está vacío."
            );
          }

          objectUrl =
            URL.createObjectURL(
              blob
            );

          if (activo) {
            setSrc(
              objectUrl
            );
          }

        } catch (err) {
          console.error(
            "❌ Error cargando audio:",
            err
          );

          if (activo) {
            setError(
              err.message ||
              "No se pudo reproducir el audio."
            );
          }
        }
      };

    if (url) {
      cargarAudio();
    }

    return () => {
      activo = false;

      if (objectUrl) {
        URL.revokeObjectURL(
          objectUrl
        );
      }
    };
  }, [
    url
  ]);

  if (error) {
    return (
      <div
        style={{
          padding: "10px",
          background: "#FFF1F1",
          color: "#C62828",
          borderRadius: "9px",
          fontSize: "13px"
        }}
      >
        ⚠️ {error}
      </div>
    );
  }

  if (!src) {
    return (
      <div
        style={{
          padding: "10px",
          background: "#F8FAFC",
          color: "#64748B",
          borderRadius: "9px",
          fontSize: "13px"
        }}
      >
        ⏳ Cargando audio...
      </div>
    );
  }

  return (
    <audio
      controls
      preload="metadata"
      src={src}
      style={style}
    />
  );
}

// ==================================================
// ESTILOS
// ==================================================

const styles = {

  page: { maxWidth: 1220, margin: "0 auto", padding: "30px 24px 60px", boxSizing: "border-box", fontFamily: "'Segoe UI', Arial, sans-serif", color: "#263238" },
  topBar: { display: "flex", alignItems: "center", gap: 20, marginBottom: 24 },
  eyebrow: { color: "#7540D5", fontSize: 11, fontWeight: 900, letterSpacing: "1.3px", marginBottom: 5 },
  title: { margin: 0, fontSize: 30, color: "#263238" },
  mirrorBadge: { display: "inline-block", marginTop: 8, padding: "6px 11px", borderRadius: 8, background: "#E8F1FF", color: "#1565C0", fontSize: 13, fontWeight: 800 },
  secondaryButton: { border: "1px solid #8FD3FF", background: "#DFF4FF", color: "#0F5F8F", borderRadius: 10, padding: "10px 15px", cursor: "pointer", fontWeight: 700 },

  // ==================================================
  // RESUMEN
  // ==================================================

  summaryCard: { background: "linear-gradient(135deg,#F7F1FF,#FFFFFF)", border: "1px solid #E2D3FA", borderRadius: 20, padding: 24, marginBottom: 20, boxShadow: "0 7px 22px rgba(117,64,213,.08)" },
  summaryTop: { display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(190px,1fr))", gap: 18 },
  smallLabel: { fontSize: 10, color: "#90A4AE", fontWeight: 900, letterSpacing: 1 },
  summaryValue: { marginTop: 5, fontSize: 17, fontWeight: 800 },
  statusBadge: { marginTop: 5, display: "inline-block", background: "#EEF4FF", color: "#2167D5", padding: "7px 12px", borderRadius: 20, fontWeight: 800, textTransform: "capitalize" },
  summaryHint: { marginTop: 18, paddingTop: 14, borderTop: "1px solid #E9E1F8", color: "#6B7280", fontSize: 13 },

  // ==================================================
  // ACORDEÓN
  // ==================================================

  accordionList: { display: "flex", flexDirection: "column", gap: 12 },
  accordionCard: { border: "1px solid", borderRadius: 16, overflow: "hidden", boxShadow: "0 3px 12px rgba(30,60,90,.04)" },
  accordionHeader: { width: "100%", border: "none", background: "transparent", padding: "16px 18px", display: "flex", alignItems: "center", gap: 14, cursor: "pointer", textAlign: "left" },
  accordionIcon: { minWidth: 44, width: 44, height: 44, borderRadius: 12, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 21, boxShadow: "0 2px 7px rgba(0,0,0,.05)" },
  accordionHeaderText: { flex: 1, minWidth: 0 },
  accordionTitle: { fontSize: 17, fontWeight: 900, color: "#263238" },
  accordionSubtitle: { marginTop: 3, color: "#6B7A86", fontSize: 12 },
  accordionMeta: { minWidth: 120, textAlign: "right" },
  countPill: { display: "inline-flex", alignItems: "center", justifyContent: "center", minWidth: 34, height: 30, padding: "0 10px", borderRadius: 16, border: "1px solid", background: "#FFFFFF", fontWeight: 900 },
  accordionNote: { marginTop: 4, color: "#7B8790", fontSize: 10 },
  chevron: { fontSize: 15, transition: "transform .2s ease" },
  accordionBody: { background: "#FFFFFF", borderTop: "1px solid rgba(0,0,0,.06)", padding: 18 },

  // ==================================================
  // GENERALES
  // ==================================================

  stack: { display: "flex", flexDirection: "column", gap: 14 },
  stackSmall: { display: "flex", flexDirection: "column", gap: 10 },
  detailCard: { border: "1px solid #E7EDF3", borderRadius: 14, padding: 16, background: "#FCFDFE" },
  detailTop: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 14, flexWrap: "wrap" },
  detailTitle: { fontSize: 16 },
  itemMeta: { marginTop: 4, color: "#78909C", fontSize: 11 },
  miniBadge: { background: "#EEF4FF", color: "#2167D5", padding: "6px 10px", borderRadius: 16, fontSize: 11, fontWeight: 800, textTransform: "capitalize" },
  infoBlock: { marginTop: 12, padding: 13, borderRadius: 10, background: "#F8FAFC", border: "1px solid #EEF2F5" },
  infoLabel: { fontSize: 10, color: "#90A4AE", fontWeight: 900, textTransform: "uppercase", marginBottom: 6 },
  infoValue: { color: "#37474F", lineHeight: 1.55, whiteSpace: "pre-wrap" },
  subheading: { marginTop: 14, marginBottom: 8, fontSize: 11, fontWeight: 900, color: "#607D8B", textTransform: "uppercase", letterSpacing: ".5px" },
  softEmpty: { padding: 12, background: "#F8FAFC", borderRadius: 10, color: "#78909C", fontSize: 12 },
  emptyBox: { padding: 18, borderRadius: 10, background: "#F8FAFC", color: "#78909C", textAlign: "center" },

  // ==================================================
  // EVIDENCIA
  // ==================================================

  evidenceCard: { border: "1px solid #E7EDF3", borderRadius: 12, padding: 13, background: "#FFFFFF" },
  evidenceBadge: { background: "#F1F5F9", color: "#607D8B", borderRadius: 16, padding: "5px 9px", fontSize: 10, fontWeight: 800 },
  mediaBox: { marginTop: 12 },
  audioPlayer: { width: "100%" },
  videoPlayer: { width: "100%", maxHeight: 360, borderRadius: 10, background: "#000" },
  transcriptionBox: { marginTop: 12, padding: 12, borderRadius: 10, background: "#F8FAFC" },
  transcriptionText: { color: "#455A64", lineHeight: 1.6, whiteSpace: "pre-wrap" },

  // ==================================================
  // PRUEBAS
  // ==================================================

  testIntro: { marginTop: 12, marginBottom: 12, display: "flex", flexDirection: "column", gap: 4, color: "#455A64", fontSize: 12 },
  dimensionList: { display: "flex", flexDirection: "column", gap: 10, marginTop: 12 },
  dimensionRow: { padding: 12, border: "1px solid #E5EDF5", borderRadius: 11, background: "#FFFFFF" },
  dimensionTop: { display: "flex", justifyContent: "space-between", gap: 12, marginBottom: 8 },
  dimensionValue: { color: "#1677C8", fontWeight: 900 },
  barTrack: { height: 8, background: "#EAF2F8", borderRadius: 8, overflow: "hidden" },
  barFill: { height: "100%", background: "linear-gradient(90deg,#4DA3E6,#2167D5)", borderRadius: 8 },
  dimensionMeta: { marginTop: 6, color: "#78909C", fontSize: 10 },

  // ==================================================
  // SEGUIMIENTO
  // ==================================================

  timeline: { display: "flex", flexDirection: "column", gap: 0 },
  timelineItem: { display: "grid", gridTemplateColumns: "18px 1fr", gap: 12, position: "relative" },
  timelineDot: { width: 10, height: 10, borderRadius: "50%", background: "#2E7D4F", marginTop: 8, boxShadow: "0 0 0 4px #E6F4EB" },
  timelineContent: { paddingBottom: 16, borderBottom: "1px solid #EDF2F5" },
  timelineText: { marginTop: 8, color: "#455A64", lineHeight: 1.55 },

  // ==================================================
  // DOCUMENTOS
  // ==================================================

  documentList: { display: "flex", flexDirection: "column", gap: 12 },
  documentRow: { display: "flex", alignItems: "center", gap: 14, padding: 15, background: "#FFFDF8", border: "1px solid #F1E1B7", borderRadius: 13, flexWrap: "wrap" },
  documentFileIcon: { width: 46, height: 46, minWidth: 46, borderRadius: 11, background: "#FFF5D8", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 22 },
  documentInfo: { flex: 1, minWidth: 220 },
  documentName: { fontWeight: 900, color: "#263238", wordBreak: "break-word" },
  documentBadges: { display: "flex", flexWrap: "wrap", gap: 6, marginTop: 6 },
  documentTypeBadge: { display: "inline-block", padding: "4px 8px", borderRadius: 10, background: "#FFF0C7", color: "#8A6200", fontSize: 11, fontWeight: 800 },
  documentMimeBadge: { display: "inline-block", padding: "4px 8px", borderRadius: 10, background: "#E8F3FF", color: "#2167D5", fontSize: 11, fontWeight: 800 },
  documentDescription: { marginTop: 7, color: "#546E7A", fontSize: 13, lineHeight: 1.45 },
  documentDate: { marginTop: 7, color: "#90A4AE", fontSize: 11 },
  documentActions: { display: "flex", gap: 7, flexWrap: "wrap" },
  documentViewButton: { border: "none", borderRadius: 8, padding: "9px 11px", background: "#E8F1FF", color: "#2167D5", fontWeight: 800, cursor: "pointer", fontSize: 12 },
  documentDownloadButton: { border: "none", borderRadius: 8, padding: "9px 11px", background: "#E8F5E9", color: "#2E7D32", fontWeight: 800, cursor: "pointer", fontSize: 12 },
  documentNotice: { marginTop: 14, padding: 12, borderRadius: 10, background: "#FFF9E8", border: "1px solid #F2DDA4", color: "#79631F", fontSize: 11, lineHeight: 1.5 },
  documentError: { marginBottom: 12, padding: 12, borderRadius: 10, background: "#FFEBEE", color: "#C62828", border: "1px solid #FFCDD2", fontSize: 12 },

  // ==================================================
  // OBSERVACIONES
  // ==================================================

  noteCard: { borderLeft: "4px solid #E8955D", background: "#FFFDFC", borderRadius: 10, padding: 14, borderTop: "1px solid #F4E5DA", borderRight: "1px solid #F4E5DA", borderBottom: "1px solid #F4E5DA" },
  noteText: { marginTop: 10, lineHeight: 1.6, color: "#455A64" },

  // ==================================================
  // IA
  // ==================================================

  aiReportBox: { background: "#FBF9FF", border: "1px solid #E5DBFA", borderRadius: 13, padding: 16 },
  aiText: { marginTop: 12, whiteSpace: "pre-wrap", lineHeight: 1.65, color: "#4B5563" },
  aiNotice: { marginTop: 12, padding: 12, borderRadius: 10, background: "#F7F2FF", color: "#6941C6", fontSize: 12 },

  // ==================================================
  // DECISIÓN FINAL
  // ==================================================

  decisionSaved: { padding: 18, borderRadius: 13, background: "#F8FAFC", border: "1px solid #DDE5EC" },
  decisionLabel: { fontSize: 10, fontWeight: 900, color: "#64748B", letterSpacing: 1 },
  decisionResult: { marginTop: 7, fontSize: 24, fontWeight: 900, textTransform: "capitalize" },
  decisionIntro: { padding: 16, borderRadius: 12, background: "#F8FAFC", border: "1px solid #DDE5EC" },
  decisionText: { margin: "6px 0 0", color: "#64748B", lineHeight: 1.55 },
  decisionQuestion: { marginTop: 18, marginBottom: 12, fontWeight: 900, fontSize: 16 },
  decisionButtons: { display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(230px,1fr))", gap: 12 },
  hireButton: { border: "none", borderRadius: 12, padding: "15px 16px", background: "#2E7D4F", color: "#FFFFFF", fontWeight: 900, cursor: "pointer", textAlign: "left", display: "flex", flexDirection: "column", gap: 5 },
  rejectButton: { border: "none", borderRadius: 12, padding: "15px 16px", background: "#C62828", color: "#FFFFFF", fontWeight: 900, cursor: "pointer", textAlign: "left", display: "flex", flexDirection: "column", gap: 5 },
  buttonSubtext: { fontSize: 11, fontWeight: 500, opacity: 0.9 },
  decisionFooter: { marginTop: 14, color: "#64748B", fontSize: 11, lineHeight: 1.5 },

  // ==================================================
  // BOTONES
  // ==================================================

  moduleButton: { width: "100%", marginTop: 14, border: "none", color: "#FFFFFF", borderRadius: 10, padding: "11px 14px", cursor: "pointer", fontWeight: 800, display: "flex", justifyContent: "space-between", alignItems: "center" },

  // ==================================================
  // FOOTER
  // ==================================================

  footer: { marginTop: 24, paddingTop: 16, borderTop: "1px solid #E6ECF2", display: "flex", justifyContent: "space-between", gap: 12, color: "#90A4AE", fontSize: 11, flexWrap: "wrap" },

  // ==================================================
  // LOADING / ERROR
  // ==================================================

  centerPage: { minHeight: "60vh", display: "flex", alignItems: "center", justifyContent: "center", padding: 24, fontFamily: "'Segoe UI', Arial, sans-serif" },
  centerCard: { width: "100%", maxWidth: 520, background: "#FFFFFF", border: "1px solid #E5EAF0", borderRadius: 18, padding: 30, textAlign: "center", boxShadow: "0 8px 28px rgba(30,60,90,.08)" },
  bigIcon: { fontSize: 46 },
  muted: { color: "#78909C" },
  loadingText: { marginTop: 14, color: "#2167D5", fontWeight: 800 },
  errorText: { color: "#C62828" }
};