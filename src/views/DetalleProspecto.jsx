import React, { useEffect, useState } from "react";
import { getToken } from "../services/AuthService";
import { useNavigate, useParams } from "react-router-dom";

const API_URL = import.meta.env.VITE_API_URL || (window.location.protocol === 'https:' ? 'https://reflejoyalma.com' : `http://${window.location.hostname}:5000`);

// ==================================================
// DETALLE / EXPEDIENTE DEL PROSPECTO
// ==================================================

export default function DetalleProspecto({
  idProspecto: idProp,
  prospecto: prop,
  onBack
}) {
  const navigate = useNavigate();
  const { idProspecto: idRuta } = useParams();

  const idProspecto =
    idProp ||
    idRuta ||
    prop?.id_prospecto ||
    prop?.id;

  const [prospecto, setProspecto] = useState(prop || null);
  const [loading, setLoading] = useState(!prop);
  const [error, setError] = useState("");
  const [ayudaPaso, setAyudaPaso] = useState(null);

  const [progreso, setProgreso] = useState({
    entrevistas: 0,
    pruebas: 0,
    seguimiento: 0,
    ia: 0,
    decision: false
  });

  // ==================================================
  // CARGAR PROSPECTO
  // ==================================================

  useEffect(() => {
    if (prop) {
      setProspecto(prop);
      setLoading(false);
      return;
    }

    if (!idProspecto) {
      setLoading(false);
      setError("No se recibió el identificador del prospecto.");
      return;
    }

    const obtener = async () => {
      try {
        setLoading(true);
        setError("");

        const token = getToken();

        if (!token) {
          navigate("/login", { replace: true });
          return;
        }

        const response = await fetch(
          `${API_URL}/api/prospectos/${idProspecto}`,
          {
            method: "GET",
            headers: {
              Authorization: `Bearer ${token}`,
              "Content-Type": "application/json"
            }
          }
        );

        const data = await response.json().catch(() => ({}));

        if (response.status === 401) {
          navigate("/login", { replace: true });
          return;
        }

        if (!response.ok) {
          throw new Error(
            data.message ||
            "No se pudo obtener el expediente del prospecto."
          );
        }

        setProspecto(
          data.prospecto ||
          data.data ||
          data
        );
      } catch (err) {
        console.error(
          "❌ Error al obtener expediente:",
          err
        );

        setError(
          err.message ||
          "No se pudo cargar el expediente."
        );
      } finally {
        setLoading(false);
      }
    };

    obtener();
  }, [idProspecto, prop, navigate]);

  // ==================================================
  // CARGAR PROGRESO DEL PROCESO
  // ==================================================

  useEffect(() => {
    if (!idProspecto) return;

    let activo = true;

    const obtenerModulo = async (ruta, token) => {
      const response = await fetch(
        `${API_URL}/api/prospectos/${idProspecto}${ruta}`,
        {
          method: "GET",
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json"
          }
        }
      );

      if (!response.ok) {
        throw new Error(`Error ${response.status}`);
      }

      return response.json().catch(() => ({}));
    };

    const cantidad = (resultado, claves = []) => {
      if (resultado.status !== "fulfilled") return 0;

      const data = resultado.value;

      if (Array.isArray(data)) return data.length;

      for (const clave of claves) {
        if (Array.isArray(data?.[clave])) {
          return data[clave].length;
        }
      }

      return 0;
    };

    const cargarProgreso = async () => {
      const token = getToken();

      if (!token) return;

      const resultados = await Promise.allSettled([
        obtenerModulo("/entrevistas", token),
        obtenerModulo("/pruebas", token),
        obtenerModulo("/seguimiento", token),
        obtenerModulo("/reportes-ia", token),
        obtenerModulo("/decision", token)
      ]);

      if (!activo) return;

      const decisionData =
        resultados[4].status === "fulfilled"
          ? resultados[4].value
          : null;

      const tieneDecision = Boolean(
        decisionData?.decision ||
        decisionData?.data?.decision ||
        decisionData?.resultado ||
        decisionData?.estatus_final
      );

      setProgreso({
        entrevistas: cantidad(
          resultados[0],
          ["entrevistas", "data"]
        ),

        pruebas: cantidad(
          resultados[1],
          ["pruebas", "data"]
        ),

        seguimiento: cantidad(
          resultados[2],
          ["seguimientos", "seguimiento", "data"]
        ),

        ia: cantidad(
          resultados[3],
          ["reportes", "reportes_ia", "data"]
        ),

        decision: tieneDecision
      });
    };

    cargarProgreso();

    return () => {
      activo = false;
    };
  }, [idProspecto]);

  // ==================================================
  // NAVEGACIÓN
  // ==================================================

  const volver = () => {
    if (onBack) {
      onBack();
      return;
    }

    navigate("/prospectos");
  };

  const irA = ruta => {
    navigate(
      `/prospecto/${idProspecto}${ruta}`
    );
  };

  // ==================================================
  // ESTADO DEL PROCESO
  // ==================================================

  const obtenerEstado = () => {
    const estadoActual = String(
      prospecto?.estatus ||
      prospecto?.estado ||
      "prospecto"
    )
      .trim()
      .toLowerCase();

    const estados = {
      prospecto: {
        texto: "Prospecto",
        fondo: "#FFF7E6",
        color: "#B7791F"
      },

      en_proceso: {
        texto: "En proceso de selección",
        fondo: "#EEF4FF",
        color: "#2167D5"
      },

      evaluacion: {
        texto: "En evaluación",
        fondo: "#F3E9FF",
        color: "#7540D5"
      },

      aprobado: {
        texto: "Aprobado",
        fondo: "#ECF9EF",
        color: "#3BAE55"
      },

      contratado: {
        texto: "Contratado",
        fondo: "#E8F8ED",
        color: "#27843A"
      },

      no_contratado: {
        texto: "No contratado",
        fondo: "#FFF1F1",
        color: "#C62828"
      }
    };

    return estados[estadoActual] || estados.prospecto;
  };

  // ==================================================
  // LOADING
  // ==================================================

  if (loading) {
    return (
      <div style={loadingContainer}>
        <div style={loadingIcon}>
          ⏳
        </div>

        <h3>
          Cargando expediente...
        </h3>

        <p>
          Estamos obteniendo la información del prospecto.
        </p>
      </div>
    );
  }

  // ==================================================
  // ERROR
  // ==================================================

  if (!prospecto) {
    return (
      <div style={errorContainer}>
        <div style={errorIcon}>
          ⚠️
        </div>

        <h2>
          No se pudo cargar el expediente
        </h2>

        <p>
          {error ||
            "No fue posible obtener la información del expediente."}
        </p>

        <button
          type="button"
          onClick={volver}
          style={backButton}
        >
          ⬅ Volver a prospectos
        </button>
      </div>
    );
  }

  // ==================================================
  // DATOS
  // ==================================================

  const estado = obtenerEstado();

  const nombre =
    prospecto.nombre ||
    "Prospecto sin nombre";

  const idMirror =
    prospecto.id_mirror ||
    "No asignado";

  const sexoCodigo = String(
    prospecto.sexo ||
    prospecto.genero ||
    ""
  )
    .trim()
    .toUpperCase();

  const sexo =
    sexoCodigo === "F"
      ? "Femenino"
      : sexoCodigo === "M"
      ? "Masculino"
      : "No especificado";

  const edad =
    prospecto.edad ??
    "No especificada";

  const correo =
    prospecto.correo ||
    "No registrado";

  const telefono =
    prospecto.telefono ||
    "No registrado";

  const direccion =
    prospecto.direccion ||
    "No registrada";

  const puesto =
    prospecto.puesto ||
    prospecto.puesto_aspira ||
    prospecto.puesto_al_que_aspira ||
    "No registrado";

  const area =
    prospecto.area ||
    prospecto.area_puesto ||
    "No registrada";

  const fechaRegistro =
    prospecto.fecha_registro
      ? new Date(
          prospecto.fecha_registro
        ).toLocaleDateString("es-MX")
      : "No disponible";

  const estadoCodigo = String(
    prospecto.estatus ||
    prospecto.estado ||
    ""
  )
    .trim()
    .toLowerCase();

  const procesoCerrado = [
    "contratado",
    "no_contratado"
  ].includes(estadoCodigo);

  // ==================================================
  // RUTA / MAPA DEL PROCESO
  // ==================================================

  const pasosProceso = [
    {
      id: "datos",
      icon: "👤",
      title: "Datos",
      completed: true,
      help:
        "Revisa los datos generales del prospecto y la vacante a la que aspira.",
      next:
        "Después continúa con Entrevistas."
    },

    {
      id: "entrevistas",
      icon: "📅",
      title: "Entrevistas",
      completed:
        progreso.entrevistas > 0,
      help:
        "Registra entrevistas presenciales o por videollamada. Las grabaciones y transcripciones quedan vinculadas al expediente.",
      next:
        "Después continúa con Pruebas.",
      route:
        "/entrevistas"
    },

    {
      id: "pruebas",
      icon: "🧪",
      title: "Pruebas",
      completed:
        progreso.pruebas > 0,
      help:
        "Asigna y revisa las pruebas psicométricas. Sus resultados forman parte de la evaluación del prospecto.",
      next:
        "Después continúa con Seguimiento.",
      route:
        "/pruebas"
    },

    {
      id: "seguimiento",
      icon: "📋",
      title: "Seguimiento",
      completed:
        progreso.seguimiento > 0,
      help:
        "Registra avances, contactos, pendientes y eventos importantes del proceso.",
      next:
        "Después continúa con Análisis IA.",
      route:
        "/seguimiento"
    },

    {
      id: "ia",
      icon: "🧠",
      title: "Análisis IA",
      completed:
        progreso.ia > 0,
      help:
        "Genera una síntesis de apoyo usando la información recopilada. La IA no decide si se contrata al prospecto.",
      next:
        "Después continúa con Decisión final.",
      route:
        "/reporte-ia"
    },

    {
      id: "decision",
      icon: "⚖️",
      title: "Decisión final",
      completed:
        progreso.decision ||
        procesoCerrado,
      help:
        "RH revisa el expediente completo y registra si el prospecto será contratado o no contratado.",
      next:
        "Esta es la última etapa.",
      route:
        "/expediente-seleccion"
    }
  ];

  const primerPendiente =
    procesoCerrado
      ? null
      : pasosProceso.find(
          paso =>
            !paso.completed
        )?.id;

  const abrirPaso = paso => {
    if (paso.id === "datos") {
      window.scrollTo({
        top: 0,
        behavior: "smooth"
      });

      return;
    }

    if (paso.route) {
      irA(paso.route);
    }
  };

  // ==================================================
  // MÓDULOS COMPACTOS
  // ==================================================

  const modulos = [
    {
      icon: "📅",
      title: "Entrevistas",
      text: "Gestionar entrevistas",
      color: "#2167D5",
      soft: "#EEF4FF",
      route: "/entrevistas",
      help:
        "Aquí registras y administras las entrevistas del prospecto. Pueden ser presenciales o por videollamada y pueden incluir grabaciones y transcripciones."
    },

    {
      icon: "🧪",
      title: "Pruebas psicométricas",
      text: "Administrar pruebas",
      color: "#7540D5",
      soft: "#F3E9FF",
      route: "/pruebas",
      help:
        "Aquí habilitas y consultas las pruebas psicométricas asignadas al prospecto. Sus resultados sirven como apoyo para el proceso de selección."
    },

    {
      icon: "📋",
      title: "Seguimiento",
      text: "Ver seguimiento",
      color: "#1677C8",
      soft: "#EAF6FF",
      route: "/seguimiento",
      help:
        "Aquí registras avances, contactos, pendientes y eventos importantes que ocurren durante el proceso de selección."
    },

    {
      icon: "📁",
      title: "Documentos",
      text: "Gestionar documentos",
      color: "#B7791F",
      soft: "#FFF7E6",
      route: "/documentos",
      help:
        "Aquí puedes guardar y consultar documentos relacionados con el prospecto y su proceso de selección."
    },

    {
      icon: "📝",
      title: "Observaciones de RH",
      text: "Registrar observaciones",
      color: "#27843A",
      soft: "#ECF9EF",
      route: "/observaciones",
      help:
        "Aquí Recursos Humanos registra observaciones relevantes sobre conducta, experiencia, competencias, documentación, referencias u otros aspectos del proceso."
    },

    {
      icon: "🧠",
      title: "Análisis con IA",
      text: "Abrir análisis IA",
      color: "#7540D5",
      soft: "#F3E9FF",
      route: "/reporte-ia",
      help:
        "Aquí MirrorSoul integra entrevistas, pruebas, seguimiento, observaciones y demás información disponible para generar un análisis de apoyo. La IA no toma la decisión final de contratación."
    }
  ];

  // ==================================================
  // RETURN
  // ==================================================

  return (
    <div style={page}>

      {/* HEADER */}

      <div style={header}>
        <button
          type="button"
          onClick={volver}
          style={backButton}
        >
          ⬅ Volver
        </button>

        <div style={headerInfo}>
          <div style={headerLabel}>
            EXPEDIENTE DEL PROSPECTO
          </div>

          <h1 style={title}>
            👤 {nombre}
          </h1>

          <div style={mirrorId}>
            🆔 {idMirror}
          </div>
        </div>
      </div>

      {/* ESTADO */}

      <div style={statusContainer}>
        <div>
          <div style={statusLabel}>
            ESTADO DEL PROCESO
          </div>

          <strong
            style={{
              ...statusBadge,
              background:
                estado.fondo,
              color:
                estado.color
            }}
          >
            {estado.texto}
          </strong>
        </div>

        <div style={statusInfo}>
          <div style={statusInfoIcon}>
            📋
          </div>

          <div>
            <strong>
              Proceso de selección
            </strong>

            <p style={statusInfoText}>
              {procesoCerrado
                ? "El proceso de selección ya cuenta con un resultado final."
                : "Completa las etapas y consulta la ruta para saber qué sigue."}
            </p>
          </div>
        </div>
      </div>

      {/* INFORMACIÓN PERSONAL */}

      <section style={section}>
        <SectionHeader
          icon="👤"
          title="Información personal"
          description="Información registrada del prospecto."
        />

        <div style={infoGrid}>
          <InfoItem
            icon="👤"
            label="Nombre"
            value={nombre}
          />

          <InfoItem
            icon="⚧"
            label="Sexo"
            value={sexo}
          />

          <InfoItem
            icon="🎂"
            label="Edad"
            value={
              edad !==
              "No especificada"
                ? `${edad} años`
                : edad
            }
          />

          <InfoItem
            icon="📧"
            label="Correo"
            value={correo}
          />

          <InfoItem
            icon="📞"
            label="Teléfono"
            value={telefono}
          />

          <InfoItem
            icon="📍"
            label="Dirección"
            value={direccion}
          />
        </div>
      </section>

      {/* INFORMACIÓN DEL PUESTO */}

      <section style={section}>
        <SectionHeader
          icon="💼"
          title="Información del puesto"
          description="Datos relacionados con la vacante a la que aspira."
        />

        <div style={infoGrid}>
          <InfoItem
            icon="💼"
            label="Puesto al que aspira"
            value={puesto}
          />

          <InfoItem
            icon="🏢"
            label="Área"
            value={area}
          />

          <InfoItem
            icon="📅"
            label="Fecha de registro"
            value={fechaRegistro}
          />

          <InfoItem
            icon="📌"
            label="Estado del proceso"
            value={estado.texto}
          />
        </div>
      </section>

      {/* ==================================================
          RUTA DEL PROCESO
      ================================================== */}

      <section style={section}>
        <SectionHeader
          icon="🧭"
          title="Ruta del proceso de selección"
          description="Consulta qué ya se realizó, qué sigue y para qué sirve cada etapa."
        />

        <div style={guideCard}>

          <div style={guideLegend}>
            <span>
              ✅ Completado
            </span>

            <span>
              🔵 Continúa aquí
            </span>

            <span>
              ⚪ Pendiente
            </span>
          </div>

          <div style={guideSteps}>
            {pasosProceso.map(
              (
                paso,
                index
              ) => {
                const actual =
                  paso.id ===
                  primerPendiente;

                const status =
                  paso.completed
                    ? "completed"
                    : actual
                    ? "current"
                    : "pending";

                return (
                  <React.Fragment
                    key={paso.id}
                  >
                    <div
                      style={{
                        ...guideStep,
                        ...(status ===
                        "completed"
                          ? guideStepCompleted
                          : status ===
                            "current"
                          ? guideStepCurrent
                          : guideStepPending)
                      }}
                      onClick={() =>
                        abrirPaso(paso)
                      }
                    >
                      <span
                        style={
                          guideState
                        }
                      >
                        {status ===
                        "completed"
                          ? "✓"
                          : status ===
                            "current"
                          ? "●"
                          : "○"}
                      </span>

                      <button
                        type="button"
                        style={
                          helpButton
                        }
                        onClick={
                          e => {
                            e.stopPropagation();

                            setAyudaPaso(
                              ayudaPaso ===
                              paso.id
                                ? null
                                : paso.id
                            );
                          }
                        }
                      >
                        ?
                      </button>

                      <div style={guideIcon}>
                        {paso.icon}
                      </div>

                      <div style={guideTitle}>
                        {paso.title}
                      </div>

                      {status ===
                        "current" && (
                        <div
                          style={
                            currentText
                          }
                        >
                          CONTINÚA AQUÍ
                        </div>
                      )}
                    </div>

                    {index <
                      pasosProceso.length -
                        1 && (
                      <div
                        style={
                          guideArrow
                        }
                      >
                        →
                      </div>
                    )}
                  </React.Fragment>
                );
              }
            )}
          </div>

          {ayudaPaso && (
            <GuideHelp
              paso={
                pasosProceso.find(
                  p =>
                    p.id ===
                    ayudaPaso
                )
              }
              onClose={() =>
                setAyudaPaso(null)
              }
            />
          )}
        </div>
      </section>

      {/* ==================================================
          MÓDULOS DEL PROCESO
      ================================================== */}

      <section style={section}>
        <SectionHeader
          icon="🧩"
          title="Proceso de selección"
          description="Accede rápidamente a cada herramienta del expediente."
        />

        <div style={modulesGrid}>
          {modulos.map(
            modulo => (
              <ModuleCard
                key={
                  modulo.title
                }
                {...modulo}
                onClick={() =>
                  irA(
                    modulo.route
                  )
                }
              />
            )
          )}
        </div>
      </section>

      {/* ==================================================
          EXPEDIENTE FINAL
      ================================================== */}

      <section style={section}>
        <div style={finalInfoCard}>

          <div style={finalInfoIcon}>
            📂
          </div>

          <div style={finalInfoContent}>
            <h2 style={finalInfoTitle}>
              Expediente final del proceso
            </h2>

            <p style={finalInfoText}>
              La información generada durante cada etapa
              se conserva y se integra en un solo expediente
              para que Recursos Humanos pueda revisar el
              proceso completo antes de tomar una decisión.
            </p>

            <div style={finalInfoGrid}>
              <FinalItem
                icon="📅"
                text="Entrevistas"
              />

              <FinalItem
                icon="🎥"
                text="Grabaciones"
              />

              <FinalItem
                icon="📝"
                text="Transcripciones"
              />

              <FinalItem
                icon="🧪"
                text="Pruebas psicométricas"
              />

              <FinalItem
                icon="📋"
                text="Seguimiento"
              />

              <FinalItem
                icon="📁"
                text="Documentos"
              />

              <FinalItem
                icon="🗒️"
                text="Observaciones"
              />

              <FinalItem
                icon="🧠"
                text="Análisis IA"
              />
            </div>

            <div style={finalNotice}>
              <span style={finalNoticeIcon}>
                ⚖️
              </span>

              <span>
                La decisión de contratar o no contratar
                se realizará únicamente dentro del
                expediente de selección.
              </span>
            </div>

            <button
              type="button"
              onClick={() =>
                irA(
                  "/expediente-seleccion"
                )
              }
              style={finalButton}
            >
              <span>
                📂 Abrir expediente de selección
              </span>

              <span>
                →
              </span>
            </button>
          </div>
        </div>
      </section>

      <footer style={footer}>
        <span>
          🧠 MirrorSoul
        </span>

        <span>
          Expediente del prospecto #{idProspecto}
        </span>
      </footer>
    </div>
  );
}

// ==================================================
// HEADER DE SECCIÓN
// ==================================================

function SectionHeader({
  icon,
  title,
  description
}) {
  return (
    <div style={sectionHeader}>
      <div style={sectionHeaderIcon}>
        {icon}
      </div>

      <div>
        <h2 style={sectionTitle}>
          {title}
        </h2>

        <p style={sectionDescription}>
          {description}
        </p>
      </div>
    </div>
  );
}

// ==================================================
// INFO ITEM
// ==================================================

function InfoItem({
  icon,
  label,
  value
}) {
  return (
    <div style={infoItem}>
      <div style={infoIcon}>
        {icon}
      </div>

      <div style={infoContent}>
        <div style={infoLabel}>
          {label}
        </div>

        <div style={infoValue}>
          {value}
        </div>
      </div>
    </div>
  );
}

// ==================================================
// MÓDULO COMPACTO
// ==================================================

function ModuleCard({
  icon,
  title,
  text,
  color,
  soft,
  onClick,
  help
}) {
  const [
    mostrarAyuda,
    setMostrarAyuda
  ] = useState(false);

  const alternarAyuda = e => {
    e.preventDefault();
    e.stopPropagation();

    setMostrarAyuda(
      actual => !actual
    );
  };

  return (
    <button
      type="button"
      style={{
        ...moduleCard,
        position: "relative",
        overflow:
          mostrarAyuda
            ? "visible"
            : "hidden",
        zIndex:
          mostrarAyuda
            ? 30
            : 1
      }}
      onClick={onClick}
    >

      {help && (
        <span
          role="button"
          tabIndex={0}
          title="¿Para qué sirve?"
          style={{
            ...moduleHelpButton,
            ...(mostrarAyuda
              ? moduleHelpButtonActive
              : {})
          }}
          onClick={
            alternarAyuda
          }
          onKeyDown={e => {
            if (
              e.key === "Enter" ||
              e.key === " "
            ) {
              alternarAyuda(e);
            }
          }}
        >
          ?
        </span>
      )}

      {mostrarAyuda && (
        <div
          style={moduleHelpPopover}
          onClick={e => {
            e.preventDefault();
            e.stopPropagation();
          }}
        >
          <div
            style={
              moduleHelpArrow
            }
          />

          <div
            style={
              moduleHelpHeader
            }
          >
            <span
              style={
                moduleHelpIcon
              }
            >
              ❓
            </span>

            <strong
              style={
                moduleHelpTitle
              }
            >
              {title}
            </strong>

            <span
              role="button"
              tabIndex={0}
              style={
                moduleHelpClose
              }
              onClick={
                alternarAyuda
              }
              onKeyDown={e => {
                if (
                  e.key === "Enter" ||
                  e.key === " "
                ) {
                  alternarAyuda(e);
                }
              }}
            >
              ×
            </span>
          </div>

          <p
            style={
              moduleHelpText
            }
          >
            {help}
          </p>
        </div>
      )}

      <div
        style={{
          ...moduleIconBox,
          background: soft
        }}
      >
        <span
          style={{
            ...moduleIconStrip,
            background: color
          }}
        />

        <span style={moduleEmoji}>
          {icon}
        </span>
      </div>

      <div style={moduleContent}>
        <strong style={moduleTitle}>
          {title}
        </strong>

        <span style={moduleText}>
          {text}
        </span>
      </div>

      <div
        style={{
          ...moduleArrow,
          color
        }}
      >
        →
      </div>
    </button>
  );
}

// ==================================================
// AYUDA
// ==================================================

function GuideHelp({
  paso,
  onClose
}) {
  if (!paso) return null;

  return (
    <div style={guideHelpBox}>
      <div style={guideHelpTop}>
        <strong>
          {paso.icon}{" "}
          {paso.title}
        </strong>

        <button
          type="button"
          style={guideHelpClose}
          onClick={onClose}
        >
          ×
        </button>
      </div>

      <div style={guideHelpText}>
        {paso.help}
      </div>

      <div style={guideNextText}>
        <strong>
          Siguiente:
        </strong>{" "}
        {paso.next}
      </div>
    </div>
  );
}

// ==================================================
// FINAL ITEM
// ==================================================

function FinalItem({
  icon,
  text
}) {
  return (
    <div style={finalItem}>
      <span style={finalItemIcon}>
        {icon}
      </span>

      <span>
        {text}
      </span>
    </div>
  );
}

// ==================================================
// ESTILOS GENERALES
// ==================================================

const page = {
  minHeight: "100vh",
  padding: 30,
  maxWidth: 1200,
  margin: "0 auto",
  boxSizing: "border-box",
  fontFamily:
    "'Segoe UI', Arial, sans-serif",
  color: "#263238",
  background: "#F8FAFD"
};

const header = {
  display: "flex",
  alignItems: "center",
  gap: 25,
  marginBottom: 25
};

const headerInfo = {
  flex: 1
};

const backButton = {
  border: "none",
  background: "#EEF3F8",
  color: "#263238",
  padding: "10px 16px",
  borderRadius: 10,
  cursor: "pointer",
  fontWeight: 600,
  fontSize: 14
};

const headerLabel = {
  color: "#607D8B",
  fontSize: 12,
  fontWeight: 700,
  letterSpacing: "1.2px",
  marginBottom: 5
};

const title = {
  margin: 0,
  color: "#263238",
  fontSize: 30,
  fontWeight: 700
};

const mirrorId = {
  marginTop: 7,
  display: "inline-block",
  background: "#E8F1FF",
  color: "#1565C0",
  padding: "6px 12px",
  borderRadius: 8,
  fontSize: 13,
  fontWeight: 700
};

// ==================================================
// ESTADO
// ==================================================

const statusContainer = {
  background: "#FFFFFF",
  border: "1px solid #E1E8EF",
  borderRadius: 18,
  padding: 20,
  marginBottom: 30,
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  gap: 20,
  flexWrap: "wrap",
  boxShadow:
    "0 5px 18px rgba(30,60,90,.05)"
};

const statusLabel = {
  color: "#90A4AE",
  fontSize: 11,
  fontWeight: 800,
  letterSpacing: 1,
  marginBottom: 8
};

const statusBadge = {
  display: "inline-block",
  padding: "8px 14px",
  borderRadius: 20,
  fontSize: 13,
  fontWeight: 800
};

const statusInfo = {
  display: "flex",
  alignItems: "center",
  gap: 12,
  maxWidth: 550
};

const statusInfoIcon = {
  minWidth: 46,
  width: 46,
  height: 46,
  borderRadius: 12,
  background: "#EEF4FF",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: 21
};

const statusInfoText = {
  margin: "5px 0 0",
  color: "#78909C",
  fontSize: 13,
  lineHeight: 1.5
};

// ==================================================
// SECCIONES
// ==================================================

const section = {
  marginBottom: 35
};

const sectionHeader = {
  display: "flex",
  alignItems: "flex-start",
  gap: 12,
  marginBottom: 18
};

const sectionHeaderIcon = {
  fontSize: 25
};

const sectionTitle = {
  margin: 0,
  fontSize: 21,
  color: "#263238"
};

const sectionDescription = {
  margin: "5px 0 0",
  color: "#78909C",
  fontSize: 14,
  lineHeight: 1.5
};

// ==================================================
// INFORMACIÓN
// ==================================================

const infoGrid = {
  display: "grid",
  gridTemplateColumns:
    "repeat(auto-fit,minmax(250px,1fr))",
  gap: 15
};

const infoItem = {
  display: "flex",
  alignItems: "center",
  gap: 12,
  background: "#FFFFFF",
  border: "1px solid #E1E8EF",
  padding: 16,
  borderRadius: 14,
  boxShadow:
    "0 4px 12px rgba(30,60,90,.04)"
};

const infoIcon = {
  minWidth: 40,
  width: 40,
  height: 40,
  borderRadius: 11,
  background: "#EEF4FF",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: 18
};

const infoContent = {
  minWidth: 0
};

const infoLabel = {
  color: "#90A4AE",
  fontSize: 12,
  marginBottom: 4
};

const infoValue = {
  color: "#263238",
  fontWeight: 600,
  fontSize: 14,
  wordBreak: "break-word"
};

// ==================================================
// GUÍA
// ==================================================

const guideCard = {
  background: "#FFFFFF",
  border: "1px solid #E1E8EF",
  borderRadius: 18,
  padding: 18,
  boxShadow:
    "0 5px 18px rgba(30,60,90,.05)"
};

const guideLegend = {
  display: "flex",
  gap: 16,
  flexWrap: "wrap",
  color: "#78909C",
  fontSize: 12,
  marginBottom: 16
};

const guideSteps = {
  display: "flex",
  alignItems: "stretch",
  gap: 8,
  overflowX: "auto",
  paddingBottom: 5
};

const guideStep = {
  position: "relative",
  minWidth: 120,
  minHeight: 92,
  flex: "1 1 0",
  borderRadius: 14,
  border: "1px solid",
  padding: "15px 10px 11px",
  textAlign: "center",
  cursor: "pointer",
  boxSizing: "border-box"
};

const guideStepCompleted = {
  background: "#ECF9EF",
  borderColor: "#BFE6C8",
  color: "#27843A"
};

const guideStepCurrent = {
  background: "#EEF4FF",
  borderColor: "#8EB5FF",
  color: "#2167D5",
  boxShadow:
    "0 5px 14px rgba(33,103,213,.12)"
};

const guideStepPending = {
  background: "#F8FAFC",
  borderColor: "#DDE5ED",
  color: "#78909C"
};

const guideState = {
  position: "absolute",
  top: 8,
  left: 10,
  fontWeight: 900
};

const helpButton = {
  position: "absolute",
  right: 8,
  top: 7,
  width: 23,
  height: 23,
  borderRadius: "50%",
  border:
    "1px solid #CBD5E1",
  background: "#FFFFFF",
  color: "#52677A",
  fontWeight: 900,
  cursor: "pointer"
};

const guideIcon = {
  fontSize: 23,
  marginBottom: 5
};

const guideTitle = {
  fontSize: 13,
  fontWeight: 800
};

const currentText = {
  marginTop: 7,
  fontSize: 9,
  fontWeight: 900,
  letterSpacing: ".8px"
};

const guideArrow = {
  alignSelf: "center",
  color: "#AAB7C4",
  fontSize: 18,
  fontWeight: 900
};

const guideHelpBox = {
  marginTop: 15,
  padding: 14,
  borderRadius: 12,
  border:
    "1px solid #DDE5ED",
  background: "#F8FAFC"
};

const guideHelpTop = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  marginBottom: 7
};

const guideHelpClose = {
  border: "none",
  background: "transparent",
  fontSize: 20,
  cursor: "pointer",
  color: "#78909C"
};

const guideHelpText = {
  fontSize: 13,
  color: "#607D8B",
  lineHeight: 1.5
};

const guideNextText = {
  marginTop: 7,
  fontSize: 12,
  color: "#334155"
};

// ==================================================
// MÓDULOS COMPACTOS
// ==================================================

const modulesGrid = {
  display: "grid",
  gridTemplateColumns:
    "repeat(auto-fit,minmax(340px,1fr))",
  gap: 14
};

const moduleCard = {
  width: "100%",
  minHeight: 78,
  border:
    "1px solid #DDE5ED",
  background:
    "linear-gradient(180deg,#FFFFFF,#F9FBFD)",
  borderRadius: 14,
  padding: 0,
  display: "grid",
  gridTemplateColumns:
    "74px minmax(0,1fr) 45px",
  alignItems: "stretch",
  overflow: "hidden",
  cursor: "pointer",
  textAlign: "left",
  boxShadow:
    "0 4px 12px rgba(30,60,90,.05)"
};

const moduleIconBox = {
  position: "relative",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  minHeight: 78,
  overflow: "hidden"
};

const moduleIconStrip = {
  position: "absolute",
  left: 0,
  top: 0,
  bottom: 0,
  width: 7
};

const moduleEmoji = {
  fontSize: 28
};

const moduleContent = {
  minWidth: 0,
  padding: "14px 10px",
  display: "flex",
  flexDirection: "column",
  justifyContent: "center"
};

const moduleTitle = {
  fontSize: 15,
  color: "#263238",
  marginBottom: 4
};

const moduleText = {
  fontSize: 12,
  color: "#78909C"
};

const moduleArrow = {
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: 21,
  fontWeight: 900
};

const moduleHelpButton = {
  position: "absolute",
  top: 8,
  right: 8,
  width: 25,
  height: 25,
  borderRadius: "50%",
  border:
    "1px solid #D5E2F4",
  background: "#F1F6FD",
  color: "#2167D5",
  fontSize: 14,
  fontWeight: 900,
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  cursor: "help",
  zIndex: 10
};

const moduleHelpButtonActive = {
  background: "#2167D5",
  color: "#FFFFFF",
  borderColor: "#2167D5"
};

const moduleHelpPopover = {
  position: "absolute",
  top: 42,
  right: 8,
  width: 290,
  maxWidth:
    "calc(100% - 16px)",
  background: "#FFFFFF",
  border:
    "1px solid #D7E3F3",
  borderRadius: 13,
  padding: "14px 15px",
  boxShadow:
    "0 14px 34px rgba(30,60,100,.18)",
  zIndex: 50,
  textAlign: "left",
  boxSizing: "border-box",
  cursor: "default"
};

const moduleHelpArrow = {
  position: "absolute",
  top: -6,
  right: 13,
  width: 11,
  height: 11,
  background: "#FFFFFF",
  borderLeft:
    "1px solid #D7E3F3",
  borderTop:
    "1px solid #D7E3F3",
  transform: "rotate(45deg)"
};

const moduleHelpHeader = {
  display: "grid",
  gridTemplateColumns:
    "28px 1fr 25px",
  gap: 8,
  alignItems: "center",
  marginBottom: 8
};

const moduleHelpIcon = {
  width: 28,
  height: 28,
  borderRadius: 8,
  background: "#EEF4FF",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: 14
};

const moduleHelpTitle = {
  color: "#172B4D",
  fontSize: 14,
  lineHeight: 1.3
};

const moduleHelpClose = {
  width: 25,
  height: 25,
  borderRadius: "50%",
  background: "#F1F5F9",
  color: "#64748B",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: 18,
  fontWeight: 800,
  cursor: "pointer",
  lineHeight: 1
};

const moduleHelpText = {
  margin: 0,
  color: "#52657C",
  fontSize: 13,
  lineHeight: 1.55,
  fontWeight: 500
};

// ==================================================
// EXPEDIENTE FINAL
// ==================================================

const finalInfoCard = {
  display: "flex",
  alignItems: "flex-start",
  gap: 18,
  background:
    "linear-gradient(135deg,#F7F1FF,#FFFFFF)",
  border:
    "1px solid #E2D3FA",
  borderRadius: 20,
  padding: 25,
  boxShadow:
    "0 7px 22px rgba(117,64,213,.08)"
};

const finalInfoIcon = {
  minWidth: 60,
  width: 60,
  height: 60,
  borderRadius: 16,
  background: "#E9DDFB",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: 28
};

const finalInfoContent = {
  flex: 1,
  minWidth: 0
};

const finalInfoTitle = {
  margin: 0,
  color: "#263238",
  fontSize: 21
};

const finalInfoText = {
  margin: "7px 0 18px",
  color: "#64748B",
  fontSize: 14,
  lineHeight: 1.6
};

const finalInfoGrid = {
  display: "grid",
  gridTemplateColumns:
    "repeat(auto-fit,minmax(180px,1fr))",
  gap: 10,
  marginBottom: 18
};

const finalItem = {
  display: "flex",
  alignItems: "center",
  gap: 9,
  padding: "10px 12px",
  background: "#FFFFFF",
  borderRadius: 9,
  border:
    "1px solid #EEF1F5",
  color: "#475569",
  fontSize: 13
};

const finalItemIcon = {
  fontSize: 17
};

const finalNotice = {
  display: "flex",
  alignItems: "center",
  gap: 10,
  background: "#FFF9E8",
  border:
    "1px solid #F3E2A5",
  borderRadius: 10,
  padding: 12,
  marginBottom: 16,
  color: "#6B5A16",
  fontSize: 13,
  lineHeight: 1.5
};

const finalNoticeIcon = {
  fontSize: 19
};

const finalButton = {
  width: "100%",
  border: "none",
  background: "#263238",
  color: "#FFFFFF",
  padding: "13px 16px",
  borderRadius: 10,
  cursor: "pointer",
  fontWeight: 800,
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center"
};

// ==================================================
// FOOTER / ESTADOS
// ==================================================

const footer = {
  borderTop:
    "1px solid #E5E9EF",
  marginTop: 35,
  paddingTop: 18,
  display: "flex",
  justifyContent: "space-between",
  gap: 15,
  flexWrap: "wrap",
  color: "#90A4AE",
  fontSize: 12
};

const loadingContainer = {
  textAlign: "center",
  padding: "80px 20px",
  color: "#607D8B"
};

const loadingIcon = {
  fontSize: 40,
  marginBottom: 10
};

const errorContainer = {
  maxWidth: 600,
  margin: "80px auto",
  textAlign: "center",
  background: "#FFFFFF",
  padding: 40,
  borderRadius: 16,
  boxShadow:
    "0 5px 20px rgba(0,0,0,.08)"
};

const errorIcon = {
  fontSize: 45,
  marginBottom: 10
};

export {
  DetalleProspecto
};