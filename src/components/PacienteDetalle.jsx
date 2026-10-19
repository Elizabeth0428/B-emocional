// src/views/PacienteDetalle.jsx

import { useEffect, useState } from "react";
import { getToken } from "../services/AuthService";
import { useNavigate, useParams } from "react-router-dom";

export default function PacienteDetalle({
  idPaciente: idPacienteProp
}) {
  const [paciente, setPaciente] = useState(null);
  const [loading, setLoading] = useState(true);
  const [mostrarGuia, setMostrarGuia] = useState(false);

  const navigate = useNavigate();

  // =====================================================
  // ID DEL PACIENTE
  // =====================================================

  const {
    idPaciente: idPacienteRuta
  } = useParams();

  const idPaciente =
    idPacienteProp ||
    idPacienteRuta;

  // =====================================================
  // PROTEGER ESTA PANTALLA
  // =====================================================

  useEffect(() => {
    const token = getToken();

    if (!token) {
      navigate(
        "/login",
        {
          replace: true
        }
      );
    }
  }, [navigate]);

  // =====================================================
  // GUÍA DEL EXPEDIENTE
  // SOLO SE MUESTRA AUTOMÁTICAMENTE 2 VECES
  // =====================================================

  useEffect(() => {
    if (!idPaciente) return;

    const key =
      `mirrorsoul_expediente_guia_${idPaciente}`;

    const visitas =
      Number(
        localStorage.getItem(key) ||
        0
      );

    if (visitas < 2) {
      setMostrarGuia(true);
    }

    localStorage.setItem(
      key,
      String(visitas + 1)
    );
  }, [idPaciente]);

  // =====================================================
  // OBTENER PACIENTE
  // =====================================================

  useEffect(() => {
    const obtenerPaciente =
      async () => {
        try {
          setLoading(true);

          const token =
            getToken();

          if (!token) {
            navigate(
              "/login",
              {
                replace: true
              }
            );

            return;
          }

          const res =
            await fetch(
              `https://reflejoyalma.com/api/pacientes/${idPaciente}`,
              {
                headers: {
                  Authorization:
                    `Bearer ${token}`
                }
              }
            );

          if (
            res.status === 401
          ) {
            sessionStorage.removeItem(
              "token"
            );

            sessionStorage.removeItem(
              "user"
            );

            navigate(
              "/login",
              {
                replace: true
              }
            );

            return;
          }

          if (!res.ok) {
            throw new Error(
              "No se pudo obtener el paciente"
            );
          }

          const data =
            await res.json();

          setPaciente(data);

        } catch (error) {
          console.error(
            "❌ Error al obtener paciente:",
            error
          );

          setPaciente(null);

        } finally {
          setLoading(false);
        }
      };

    if (idPaciente) {
      obtenerPaciente();
    } else {
      setLoading(false);
    }

  }, [
    idPaciente,
    navigate
  ]);

  // =====================================================
  // BOTÓN VOLVER
  // =====================================================

  const volver = () => {
    navigate(
      "/dashboard",
      {
        replace: true
      }
    );
  };

  // =====================================================
  // CARGANDO
  // =====================================================

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
          Estamos obteniendo la información del paciente.
        </p>
      </div>
    );
  }

  // =====================================================
  // PACIENTE NO ENCONTRADO
  // =====================================================

  if (!paciente) {
    return (
      <div style={errorContainer}>
        <div style={errorIcon}>
          ⚠️
        </div>

        <h2>
          Paciente no encontrado
        </h2>

        <p>
          No fue posible cargar la información del expediente.
        </p>

        <button
          type="button"
          onClick={volver}
          style={backButton}
        >
          ⬅ Volver al inicio
        </button>
      </div>
    );
  }

  // =====================================================
  // NAVEGAR A MÓDULO DEL PACIENTE
  // =====================================================

  const irA = ruta => {
    navigate(
      `/paciente/${idPaciente}${ruta}`
    );
  };

  // =====================================================
  // RENDER
  // =====================================================

  return (
    <div style={page}>

      {/* =================================================
          ENCABEZADO
      ================================================= */}

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
            EXPEDIENTE DEL PACIENTE
          </div>

          <h1 style={title}>
            👤 {paciente.nombre}
          </h1>

          <div style={mirrorId}>
            🆔 {paciente.id_mirror}
          </div>
        </div>

        <button
          type="button"
          style={helpTopButton}
          onClick={() =>
            setMostrarGuia(true)
          }
        >
          ❓ ¿Cómo usar este expediente?
        </button>
      </div>

      {/* =================================================
          INFORMACIÓN DEL PACIENTE
      ================================================= */}

      <section style={patientCard}>
        <div style={patientHeader}>
          <div style={patientAvatar}>
            {paciente.nombre
              ?.charAt(0)
              ?.toUpperCase() ||
              "P"}
          </div>

          <div>
            <h2 style={patientName}>
              {paciente.nombre}
            </h2>

            <p style={patientSubtitle}>
              Expediente clínico MirrorSoul
            </p>
          </div>
        </div>

        <div style={patientInfoGrid}>
          <InfoItem
            icon="⚧"
            label="Sexo"
            value={
              paciente.sexo === "F"
                ? "Femenino"
                : paciente.sexo === "M"
                ? "Masculino"
                : "No especificado"
            }
          />

          <InfoItem
            icon="🎂"
            label="Edad"
            value={
              paciente.edad
                ? `${paciente.edad} años`
                : "No especificada"
            }
          />

          <InfoItem
            icon="📧"
            label="Correo"
            value={
              paciente.correo ||
              "No registrado"
            }
          />

          <InfoItem
            icon="📞"
            label="Teléfono"
            value={
              paciente.telefono ||
              "No registrado"
            }
          />
        </div>
      </section>

      {/* =================================================
          INFORMACIÓN CLÍNICA
      ================================================= */}

      <section style={section}>
        <div style={sectionHeader}>
          <div style={sectionHeaderContent}>
            <span style={sectionIcon}>
              📋
            </span>

            <div>
              <h2 style={sectionTitle}>
                Información clínica
              </h2>

              <p style={sectionDescription}>
                Consulta y administra la información clínica del paciente.
              </p>
            </div>
          </div>
        </div>

        <div style={modulesGrid}>

          <ModuleCard
            icon="📋"
            title="Historial clínico inicial"
            description="Consulta la información clínica inicial registrada del paciente."
            help="Aquí se registra la información clínica inicial del paciente: antecedentes, motivo de consulta y otros datos importantes para comenzar el proceso clínico. Normalmente se completa al inicio."
            onClick={() =>
              irA("/historial")
            }
          />

          <ModuleCard
            icon="📑"
            title="Seguimiento clínico"
            description="Consulta la evolución, diagnóstico, tratamiento y observaciones."
            help="Aquí registras la evolución del paciente durante el proceso: cambios, observaciones, diagnóstico, tratamiento y otros datos de seguimiento."
            onClick={() =>
              irA("/seguimiento")
            }
          />

          <ModuleCard
            icon="🧪"
            title="Resultados de pruebas"
            description="Consulta los resultados e interpretaciones de las pruebas realizadas."
            help="Aquí puedes consultar los resultados de las pruebas psicológicas que ya fueron contestadas y registradas para este paciente."
            onClick={() =>
              irA("/resultados")
            }
          />

          <ModuleCard
            icon="📅"
            title="Sesiones"
            description="Consulta las sesiones clínicas y el material asociado."
            help="Aquí se administran las consultas clínicas del paciente. Cada sesión puede contener seguimiento, notas, pruebas, grabaciones y material relacionado."
            onClick={() =>
              irA("/sesiones")
            }
          />

        </div>
      </section>

      {/* =================================================
          HERRAMIENTAS CLÍNICAS
      ================================================= */}

      <section style={section}>
        <div style={sectionHeader}>
          <div style={sectionHeaderContent}>
            <span style={sectionIcon}>
              🧠
            </span>

            <div>
              <h2 style={sectionTitle}>
                Herramientas clínicas
              </h2>

              <p style={sectionDescription}>
                Accede a las herramientas disponibles para este paciente.
              </p>
            </div>
          </div>
        </div>

        <div style={toolsGrid}>

          <ToolCard
            icon="🧪"
            title="Pruebas psicológicas"
            description="Habilita pruebas y administra los accesos para el paciente."
            button="Administrar pruebas"
            help="Aquí habilitas las pruebas psicológicas que debe contestar el paciente. Después podrás consultar sus resultados dentro del expediente."
            onClick={() =>
              irA("/pruebas")
            }
          />

          <ToolCard
            icon="🧠"
            title="Preanálisis IA"
            description="Consulta los preanálisis clínicos generados a partir de las sesiones."
            button="Ver preanálisis"
            help="Aquí MirrorSoul integra la información de la sesión, seguimiento, pruebas, notas y grabaciones disponibles para generar un preanálisis clínico de apoyo. El resultado debe ser revisado por el profesional."
            onClick={() =>
              irA("/reportes-ia")
            }
          />

          <ToolCard
            icon="📞"
            title="Videollamada"
            description="Genera una sala de videollamada para realizar una sesión con el paciente."
            button="Abrir videollamada"
            help="Aquí puedes abrir una sala de videollamada cuando la consulta con el paciente se realizará a distancia."
            onClick={() =>
              navigate(
                `/SalaVideollamada/nueva/${idPaciente}`
              )
            }
          />

        </div>
      </section>

      {/* =================================================
          PIE
      ================================================= */}

      <div style={footer}>
        <span>
          🧠 MirrorSoul
        </span>

        <span>
          Expediente #{paciente.id_paciente}
        </span>
      </div>

      {/* =================================================
          GUÍA GENERAL DEL EXPEDIENTE
      ================================================= */}

      {mostrarGuia && (
        <div
          style={overlay}
          onClick={() =>
            setMostrarGuia(false)
          }
        >
          <div
            style={guideModal}
            onClick={e =>
              e.stopPropagation()
            }
          >
            <button
              type="button"
              style={closeButton}
              onClick={() =>
                setMostrarGuia(false)
              }
            >
              ×
            </button>

            <div style={guideIcon}>
              🧭
            </div>

            <h2 style={guideTitle}>
              ¿Cómo usar el expediente de {paciente.nombre}?
            </h2>

            <p style={guideDescription}>
              El expediente concentra la información general
              del paciente. El trabajo de cada consulta se
              desarrolla principalmente dentro de una sesión clínica.
            </p>

            <div style={guideRoute}>

              <GuideStep
                number="1"
                icon="📋"
                title="Historial inicial"
                text="Registra la información base, antecedentes y motivo de consulta del paciente."
              />

              <GuideArrow />

              <GuideStep
                number="2"
                icon="🩺"
                title="Iniciar o continuar sesión"
                text="La sesión es el espacio principal de trabajo de cada consulta clínica."
              />

              <GuideArrow />

              <GuideStep
                number="3"
                icon="📝"
                title="Trabajo de la sesión"
                text="Durante la sesión puedes registrar seguimiento, notas, pruebas y grabaciones cuando sean necesarias."
              />

              <GuideArrow />

              <GuideStep
                number="4"
                icon="🧠"
                title="Preanálisis IA"
                text="Al terminar la consulta, MirrorSoul integra la información disponible para generar un preanálisis clínico de apoyo."
              />

              <GuideArrow />

              <GuideStep
                number="5"
                icon="✅"
                title="Finalizar sesión"
                text="Después de revisar el preanálisis se realiza el cierre definitivo de la sesión."
              />

              <GuideArrow />

              <GuideStep
                number="6"
                icon="📅"
                title="Próxima cita"
                text="Una vez finalizada la sesión, puedes programar la siguiente cita si el proceso lo requiere."
              />

            </div>

            <div style={guideNotice}>
              💡 El historial inicial pertenece al expediente.
              Después, el trabajo clínico gira principalmente
              alrededor de cada sesión. Las pruebas, notas,
              grabaciones y videollamadas se utilizan según
              las necesidades de cada consulta.
            </div>

            <button
              type="button"
              style={understoodButton}
              onClick={() =>
                setMostrarGuia(false)
              }
            >
              Entendido ✓
            </button>
          </div>
        </div>
      )}

    </div>
  );
}

// =====================================================
// INFORMACIÓN
// =====================================================

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

      <div>
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

// =====================================================
// MÓDULO CLÍNICO
// =====================================================

function ModuleCard({
  icon,
  title,
  description,
  onClick,
  help
}) {
  const [
    mostrarAyuda,
    setMostrarAyuda
  ] = useState(false);

  const alternarAyuda =
    e => {
      e.preventDefault();
      e.stopPropagation();

      setMostrarAyuda(
        actual =>
          !actual
      );
    };

  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        ...moduleCard,
        zIndex:
          mostrarAyuda
            ? 30
            : 1
      }}
    >

      {help && (
        <span
          role="button"
          tabIndex={0}
          title="¿Para qué sirve?"
          style={{
            ...cardHelp,
            ...(mostrarAyuda
              ? cardHelpActive
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
        <HelpPopover
          title={title}
          text={help}
          onClose={
            alternarAyuda
          }
        />
      )}

      <div style={moduleIcon}>
        {icon}
      </div>

      <div style={moduleContent}>
        <h3 style={moduleTitle}>
          {title}
        </h3>

        <p style={moduleDescription}>
          {description}
        </p>

        <div style={moduleAction}>
          Consultar →
        </div>
      </div>
    </button>
  );
}

// =====================================================
// HERRAMIENTA
// =====================================================

function ToolCard({
  icon,
  title,
  description,
  button,
  onClick,
  help
}) {
  const [
    mostrarAyuda,
    setMostrarAyuda
  ] = useState(false);

  const alternarAyuda =
    e => {
      e.preventDefault();
      e.stopPropagation();

      setMostrarAyuda(
        actual =>
          !actual
      );
    };

  return (
    <div
      style={{
        ...toolCard,
        zIndex:
          mostrarAyuda
            ? 30
            : 1
      }}
    >

      {help && (
        <button
          type="button"
          style={{
            ...cardHelp,
            ...(mostrarAyuda
              ? cardHelpActive
              : {})
          }}
          title="¿Para qué sirve?"
          onClick={
            alternarAyuda
          }
        >
          ?
        </button>
      )}

      {mostrarAyuda && (
        <HelpPopover
          title={title}
          text={help}
          onClose={
            alternarAyuda
          }
        />
      )}

      <div style={toolTop}>
        <div style={toolIcon}>
          {icon}
        </div>

        <div>
          <h3 style={toolTitle}>
            {title}
          </h3>
        </div>
      </div>

      <p style={toolDescription}>
        {description}
      </p>

      <button
        type="button"
        onClick={onClick}
        style={toolButton}
      >
        {button}

        <span>
          →
        </span>
      </button>
    </div>
  );
}

// =====================================================
// AYUDA PEQUEÑA
// =====================================================

function HelpPopover({
  title,
  text,
  onClose
}) {
  return (
    <div
      style={helpPopover}
      onClick={e => {
        e.preventDefault();
        e.stopPropagation();
      }}
    >
      <div
        style={helpPopoverArrow}
      />

      <div
        style={helpPopoverHeader}
      >
        <span
          style={helpPopoverIcon}
        >
          ❓
        </span>

        <strong
          style={helpPopoverTitle}
        >
          {title}
        </strong>

        <button
          type="button"
          style={helpPopoverClose}
          onClick={onClose}
        >
          ×
        </button>
      </div>

      <p style={helpPopoverText}>
        {text}
      </p>
    </div>
  );
}

// =====================================================
// COMPONENTES GUÍA
// =====================================================

function GuideStep({
  number,
  icon,
  title,
  text
}) {
  return (
    <div style={guideStep}>
      <div style={guideNumber}>
        {number}
      </div>

      <div style={guideStepIcon}>
        {icon}
      </div>

      <div>
        <div style={guideStepTitle}>
          {title}
        </div>

        <div style={guideStepText}>
          {text}
        </div>
      </div>
    </div>
  );
}

function GuideArrow() {
  return (
    <div style={guideArrow}>
      ↓
    </div>
  );
}

// =====================================================
// ESTILOS
// =====================================================

const page = {
  minHeight: "100vh",
  padding: "30px",
  maxWidth: "1200px",
  margin: "0 auto",
  boxSizing: "border-box",
  fontFamily:
    "'Segoe UI', Arial, sans-serif"
};

const header = {
  display: "flex",
  alignItems: "center",
  gap: "25px",
  marginBottom: "25px"
};

const headerInfo = {
  flex: 1
};

const backButton = {
  border: "none",
  background: "#eef3f8",
  color: "#263238",
  padding: "10px 16px",
  borderRadius: "10px",
  cursor: "pointer",
  fontWeight: "600",
  fontSize: "14px",
  transition: "0.2s"
};

const helpTopButton = {
  border: "1px solid #c9daf4",
  background: "#ffffff",
  color: "#2167d5",
  borderRadius: "999px",
  padding: "10px 16px",
  cursor: "pointer",
  fontSize: "13px",
  fontWeight: "800",
  boxShadow:
    "0 4px 12px rgba(40,80,140,.07)",
  flexShrink: 0
};

const headerLabel = {
  color: "#607d8b",
  fontSize: "12px",
  fontWeight: "700",
  letterSpacing: "1.2px",
  marginBottom: "5px"
};

const title = {
  margin: 0,
  color: "#263238",
  fontSize: "30px",
  fontWeight: "700"
};

const mirrorId = {
  marginTop: "6px",
  display: "inline-block",
  background: "#e8f1ff",
  color: "#1565c0",
  padding: "6px 12px",
  borderRadius: "8px",
  fontSize: "13px",
  fontWeight: "700"
};

const patientCard = {
  background: "#ffffff",
  border: "1px solid #e2e8f0",
  borderRadius: "18px",
  padding: "25px",
  marginBottom: "30px",
  boxShadow:
    "0 6px 20px rgba(30,60,90,.07)"
};

const patientHeader = {
  display: "flex",
  alignItems: "center",
  gap: "15px",
  marginBottom: "25px"
};

const patientAvatar = {
  width: "58px",
  height: "58px",
  borderRadius: "50%",
  background:
    "linear-gradient(135deg,#3f51b5,#2196f3)",
  color: "#fff",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "23px",
  fontWeight: "700"
};

const patientName = {
  margin: 0,
  color: "#263238",
  fontSize: "22px"
};

const patientSubtitle = {
  margin: "4px 0 0",
  color: "#78909c",
  fontSize: "14px"
};

const patientInfoGrid = {
  display: "grid",
  gridTemplateColumns:
    "repeat(auto-fit,minmax(220px,1fr))",
  gap: "15px"
};

const infoItem = {
  display: "flex",
  alignItems: "center",
  gap: "12px",
  background: "#f8fafc",
  padding: "14px",
  borderRadius: "12px"
};

const infoIcon = {
  width: "38px",
  height: "38px",
  borderRadius: "10px",
  background: "#e8f1ff",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "18px"
};

const infoLabel = {
  color: "#78909c",
  fontSize: "12px",
  marginBottom: "3px"
};

const infoValue = {
  color: "#263238",
  fontWeight: "600",
  fontSize: "14px",
  wordBreak: "break-word"
};

const section = {
  marginBottom: "35px"
};

const sectionHeader = {
  marginBottom: "18px"
};

const sectionHeaderContent = {
  display: "flex",
  alignItems: "flex-start"
};

const sectionIcon = {
  fontSize: "25px",
  marginRight: "10px"
};

const sectionTitle = {
  display: "inline",
  margin: 0,
  color: "#263238",
  fontSize: "21px"
};

const sectionDescription = {
  margin: "7px 0 0",
  color: "#78909c",
  fontSize: "14px"
};

const modulesGrid = {
  display: "grid",
  gridTemplateColumns:
    "repeat(2,minmax(0,1fr))",
  gap: "18px"
};

const moduleCard = {
  display: "flex",
  alignItems: "flex-start",
  gap: "18px",
  textAlign: "left",
  width: "100%",
  padding: "22px",
  background: "#ffffff",
  border: "1px solid #e1e8ef",
  borderRadius: "16px",
  cursor: "pointer",
  boxShadow:
    "0 4px 14px rgba(30,60,90,.05)",
  transition: "all .2s",
  position: "relative"
};

const moduleIcon = {
  minWidth: "52px",
  height: "52px",
  borderRadius: "14px",
  background: "#eef4ff",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "25px"
};

const moduleContent = {
  flex: 1
};

const moduleTitle = {
  margin: "0 0 7px",
  color: "#263238",
  fontSize: "17px"
};

const moduleDescription = {
  margin: 0,
  color: "#78909c",
  lineHeight: "1.5",
  fontSize: "14px"
};

const moduleAction = {
  marginTop: "13px",
  color: "#3f51b5",
  fontWeight: "700",
  fontSize: "13px"
};

const toolsGrid = {
  display: "grid",
  gridTemplateColumns:
    "repeat(3,minmax(0,1fr))",
  gap: "18px"
};

const toolCard = {
  background: "#ffffff",
  border: "1px solid #e1e8ef",
  borderRadius: "16px",
  padding: "22px",
  boxShadow:
    "0 4px 14px rgba(30,60,90,.05)",
  position: "relative"
};

const toolTop = {
  display: "flex",
  alignItems: "center",
  gap: "12px"
};

const toolIcon = {
  width: "48px",
  height: "48px",
  borderRadius: "13px",
  background: "#eef4ff",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "23px"
};

const toolTitle = {
  margin: "0 0 7px",
  color: "#263238",
  fontSize: "19px",
  fontWeight: "700",
  fontFamily:
    "'Segoe UI', Arial, sans-serif"
};

const toolDescription = {
  color: "#78909c",
  fontSize: "16px",
  lineHeight: "1.55",
  minHeight: "60px",
  margin: "15px 0",
  fontFamily:
    "'Segoe UI', Arial, sans-serif"
};

const toolButton = {
  width: "100%",
  display: "flex",
  justifyContent:
    "space-between",
  alignItems: "center",
  border: "none",
  borderRadius: "9px",
  padding: "11px 14px",
  background: "#3f51b5",
  color: "#ffffff",
  fontWeight: "700",
  fontSize: "15px",
  cursor: "pointer"
};

const cardHelp = {
  position: "absolute",
  top: "12px",
  right: "12px",
  width: "29px",
  height: "29px",
  borderRadius: "50%",
  border: "1px solid #d5e2f4",
  background: "#f1f6fd",
  color: "#2167d5",
  fontSize: "15px",
  fontWeight: "900",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  cursor: "help",
  zIndex: 5
};

const cardHelpActive = {
  background: "#2167d5",
  color: "#ffffff",
  border:
    "1px solid #2167d5",
  boxShadow:
    "0 4px 12px rgba(33,103,213,.22)"
};

// =====================================================
// POPOVER PEQUEÑO
// =====================================================

const helpPopover = {
  position: "absolute",
  top: "49px",
  right: "12px",
  width: "285px",
  maxWidth:
    "calc(100% - 24px)",
  padding: "15px 16px",
  background: "#ffffff",
  border:
    "1px solid #d7e3f3",
  borderRadius: "14px",
  boxShadow:
    "0 14px 34px rgba(30,60,100,.18)",
  zIndex: 50,
  textAlign: "left",
  boxSizing: "border-box",
  cursor: "default"
};

const helpPopoverArrow = {
  position: "absolute",
  top: "-7px",
  right: "15px",
  width: "12px",
  height: "12px",
  background: "#ffffff",
  borderLeft:
    "1px solid #d7e3f3",
  borderTop:
    "1px solid #d7e3f3",
  transform: "rotate(45deg)"
};

const helpPopoverHeader = {
  display: "grid",
  gridTemplateColumns:
    "30px 1fr 27px",
  gap: "8px",
  alignItems: "center",
  marginBottom: "9px"
};

const helpPopoverIcon = {
  width: "30px",
  height: "30px",
  borderRadius: "8px",
  background: "#eef4ff",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "14px"
};

const helpPopoverTitle = {
  color: "#172b4d",
  fontSize: "15px",
  lineHeight: "1.3"
};

const helpPopoverClose = {
  width: "27px",
  height: "27px",
  border: "none",
  borderRadius: "50%",
  background: "#f1f5f9",
  color: "#64748b",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontWeight: "800",
  fontSize: "18px",
  cursor: "pointer",
  lineHeight: 1
};

const helpPopoverText = {
  margin: 0,
  color: "#52657c",
  fontSize: "14px",
  lineHeight: "1.6",
  fontWeight: "500"
};

const footer = {
  borderTop:
    "1px solid #e5e9ef",
  marginTop: "35px",
  paddingTop: "18px",
  display: "flex",
  justifyContent:
    "space-between",
  color: "#90a4ae",
  fontSize: "12px"
};

const loadingContainer = {
  textAlign: "center",
  padding: "80px 20px",
  color: "#607d8b"
};

const loadingIcon = {
  fontSize: "40px",
  marginBottom: "10px"
};

const errorContainer = {
  maxWidth: "600px",
  margin: "80px auto",
  textAlign: "center",
  background: "#ffffff",
  padding: "40px",
  borderRadius: "16px",
  boxShadow:
    "0 5px 20px rgba(0,0,0,.08)"
};

const errorIcon = {
  fontSize: "45px",
  marginBottom: "10px"
};

// =====================================================
// MODAL SOLO PARA GUÍA GENERAL
// =====================================================

const overlay = {
  position: "fixed",
  inset: 0,
  background:
    "rgba(18,35,61,.48)",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  padding: "20px",
  zIndex: 9999,
  backdropFilter:
    "blur(3px)"
};

const guideModal = {
  width: "100%",
  maxWidth: "720px",
  maxHeight: "90vh",
  overflowY: "auto",
  background: "#ffffff",
  borderRadius: "24px",
  padding: "30px",
  position: "relative",
  boxShadow:
    "0 24px 80px rgba(20,50,90,.25)",
  boxSizing: "border-box"
};

const closeButton = {
  position: "absolute",
  top: "14px",
  right: "16px",
  width: "34px",
  height: "34px",
  border: "none",
  borderRadius: "50%",
  background: "#f1f5f9",
  color: "#64748b",
  fontSize: "23px",
  cursor: "pointer"
};

const guideIcon = {
  width: "58px",
  height: "58px",
  borderRadius: "16px",
  background: "#eaf1ff",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "27px",
  marginBottom: "14px"
};

const guideTitle = {
  margin: "0 0 8px",
  color: "#172b4d",
  fontSize: "24px"
};

const guideDescription = {
  color: "#667085",
  fontSize: "14px",
  lineHeight: "1.6",
  margin: "0 0 24px"
};

const guideRoute = {
  display: "flex",
  flexDirection: "column",
  gap: "4px"
};

const guideStep = {
  display: "grid",
  gridTemplateColumns:
    "34px 48px 1fr",
  gap: "12px",
  alignItems: "center",
  background: "#fbfcfe",
  border:
    "1px solid #e5ebf3",
  borderRadius: "14px",
  padding: "13px 14px"
};

const guideNumber = {
  width: "30px",
  height: "30px",
  borderRadius: "50%",
  background: "#2167d5",
  color: "#ffffff",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontWeight: "900",
  fontSize: "12px"
};

const guideStepIcon = {
  width: "44px",
  height: "44px",
  borderRadius: "12px",
  background: "#eef4ff",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "22px"
};

const guideStepTitle = {
  color: "#344054",
  fontSize: "14px",
  fontWeight: "900",
  marginBottom: "3px"
};

const guideStepText = {
  color: "#667085",
  fontSize: "12px",
  lineHeight: "1.45"
};

const guideArrow = {
  color: "#90a4ae",
  textAlign: "center",
  fontSize: "17px",
  height: "20px"
};

const guideNotice = {
  marginTop: "18px",
  padding: "12px 14px",
  background: "#fff9e8",
  border:
    "1px solid #f6d98b",
  borderRadius: "12px",
  color: "#7a5a10",
  fontSize: "11px",
  lineHeight: "1.5"
};

const understoodButton = {
  width: "100%",
  marginTop: "20px",
  padding: "12px 18px",
  border: "none",
  borderRadius: "12px",
  background:
    "linear-gradient(135deg,#2167d5,#5795f2)",
  color: "#ffffff",
  cursor: "pointer",
  fontSize: "13px",
  fontWeight: "900"
};