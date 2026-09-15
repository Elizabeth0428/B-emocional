import { useEffect, useState } from "react";
import { getToken } from "../services/AuthService";
import { useNavigate, useParams } from "react-router-dom";

export default function PacienteDetalle({ idPaciente: idPacienteProp, onBack }) {

  const [paciente, setPaciente] = useState(null);
  const [loading, setLoading] = useState(true);

  const navigate = useNavigate();

  // =====================================================
  // ID DEL PACIENTE
  // =====================================================
  // Si viene como prop lo usamos.
  // Si viene desde React Router usamos useParams().
  // =====================================================

  const { idPaciente: idPacienteRuta } = useParams();

  const idPaciente =
    idPacienteProp || idPacienteRuta;


  // =====================================================
  // OBTENER PACIENTE
  // =====================================================

  useEffect(() => {

    const obtenerPaciente = async () => {

      try {

        const token = getToken();

        const res = await fetch(
          `http://localhost:5000/api/pacientes/${idPaciente}`,
          {
            headers: {
              Authorization: `Bearer ${token}`,
            },
          }
        );

        if (!res.ok) {
          throw new Error(
            "No se pudo obtener el paciente"
          );
        }

        const data = await res.json();

        setPaciente(data);

      } catch (error) {

        console.error(
          "❌ Error al obtener paciente:",
          error
        );

      } finally {

        setLoading(false);

      }

    };

    if (idPaciente) {
      obtenerPaciente();
    } else {
      setLoading(false);
    }

  }, [idPaciente]);


  // =====================================================
  // BOTÓN VOLVER
  // =====================================================

   const volver = () => {

  navigate("/pacientes");

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
          No fue posible cargar la información
          del expediente.
        </p>

        <button
          type="button"
          onClick={volver}
          style={backButton}
        >
          ⬅ Volver a pacientes
        </button>

      </div>
    );

  }


  // =====================================================
  // NAVEGAR A MÓDULO DEL PACIENTE
  // =====================================================

  const irA = (ruta) => {

    /*
      ANTES:
      /historial/5

      AHORA:
      /paciente/5/historial

      Esto coincide exactamente con las rutas
      definidas en MainApp.jsx.
    */

    navigate(
      `/paciente/${idPaciente}${ruta}`
    );

  };


  // =====================================================
  // RENDER
  // =====================================================

  return (

    <div style={page}>

      {/* ==================================================
          ENCABEZADO
      ================================================== */}

      <div style={header}>

        <button
          type="button"
          onClick={volver}
          style={backButton}
        >
          ⬅ Volver
        </button>

        <div>

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

      </div>


      {/* ==================================================
          INFORMACIÓN DEL PACIENTE
      ================================================== */}

      <section style={patientCard}>

        <div style={patientHeader}>

          <div style={patientAvatar}>
            {paciente.nombre
              ?.charAt(0)
              ?.toUpperCase() || "P"}
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


      {/* ==================================================
          INFORMACIÓN CLÍNICA
      ================================================== */}

      <section style={section}>

        <div style={sectionHeader}>

          <div>

            <span style={sectionIcon}>
              📋
            </span>

            <div>

              <h2 style={sectionTitle}>
                Información clínica
              </h2>

              <p style={sectionDescription}>
                Consulta y administra la información
                clínica del paciente.
              </p>

            </div>

          </div>

        </div>


        <div style={modulesGrid}>

          {/* ==================================================
              HISTORIAL
          ================================================== */}

          <ModuleCard
            icon="📋"
            title="Historial clínico inicial"
            description="Consulta la información clínica inicial registrada del paciente."
            onClick={() =>
              irA("/historial")
            }
          />


          {/* ==================================================
              SEGUIMIENTO
          ================================================== */}

          <ModuleCard
            icon="📑"
            title="Seguimiento clínico"
            description="Consulta la evolución, diagnóstico, tratamiento y observaciones."
            onClick={() =>
              irA("/seguimiento")
            }
          />


          {/* ==================================================
              RESULTADOS
          ================================================== */}

          <ModuleCard
            icon="🧪"
            title="Resultados de pruebas"
            description="Consulta los resultados e interpretaciones de las pruebas realizadas."
            onClick={() =>
              irA("/resultados")
            }
          />


          {/* ==================================================
              SESIONES
          ================================================== */}

          <ModuleCard
            icon="📅"
            title="Sesiones"
            description="Consulta las sesiones clínicas y el material asociado."
            onClick={() =>
              irA("/sesiones")
            }
          />

        </div>

      </section>


      {/* ==================================================
          HERRAMIENTAS CLÍNICAS
      ================================================== */}

      <section style={section}>

        <div style={sectionHeader}>

          <div>

            <span style={sectionIcon}>
              🧠
            </span>

            <div>

              <h2 style={sectionTitle}>
                Herramientas clínicas
              </h2>

              <p style={sectionDescription}>
                Accede a las herramientas disponibles
                para este paciente.
              </p>

            </div>

          </div>

        </div>


        <div style={toolsGrid}>

          {/* ==================================================
              PRUEBAS
          ================================================== */}

          <ToolCard
            icon="🧪"
            title="Pruebas psicológicas"
            description="Habilita pruebas y administra los accesos para el paciente."
            button="Administrar pruebas"
            onClick={() =>
              irA("/pruebas")
            }
          />


          {/* ==================================================
              IA
          ================================================== */}

          <ToolCard
            icon="🧠"
            title="Reportes automáticos con IA"
            description="Genera y consulta los reportes clínicos automáticos de las sesiones."
            button="Abrir reportes IA"
            onClick={() =>
              irA("/reportes-ia")
            }
          />


          {/* ==================================================
              VIDEOLLAMADA
          ================================================== */}

       <ToolCard
  icon="📞"
  title="Videollamada"
  description="Genera una sala de videollamada para realizar una sesión con el paciente."
  button="Abrir videollamada"
  onClick={() =>
    navigate(`/SalaVideollamada/nueva/${idPaciente}`)
  }
/>

        </div>

      </section>


      {/* ==================================================
          PIE
      ================================================== */}

      <div style={footer}>

        <span>
          🧠 MirrorSoul
        </span>

        <span>
          Expediente #{paciente.id_paciente}
        </span>

      </div>

    </div>

  );

}


/* =====================================================
   COMPONENTE INFORMACIÓN
===================================================== */

function InfoItem({
  icon,
  label,
  value,
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


/* =====================================================
   COMPONENTE MÓDULO CLÍNICO
===================================================== */

function ModuleCard({
  icon,
  title,
  description,
  onClick,
}) {

  return (

    <button
      type="button"
      onClick={onClick}
      style={moduleCard}
    >

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


/* =====================================================
   COMPONENTE HERRAMIENTA
===================================================== */

function ToolCard({
  icon,
  title,
  description,
  button,
  onClick,
}) {

  return (

    <div style={toolCard}>

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


/* =====================================================
   ESTILOS
===================================================== */

const page = {

  minHeight: "100vh",

  padding: "30px",

  maxWidth: "1200px",

  margin: "0 auto",

  boxSizing: "border-box",

};


const header = {

  display: "flex",

  alignItems: "center",

  gap: "25px",

  marginBottom: "25px",

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

  transition: "0.2s",

};


const headerLabel = {

  color: "#607d8b",

  fontSize: "12px",

  fontWeight: "700",

  letterSpacing: "1.2px",

  marginBottom: "5px",

};


const title = {

  margin: 0,

  color: "#263238",

  fontSize: "30px",

  fontWeight: "700",

};


const mirrorId = {

  marginTop: "6px",

  display: "inline-block",

  background: "#e8f1ff",

  color: "#1565c0",

  padding: "6px 12px",

  borderRadius: "8px",

  fontSize: "13px",

  fontWeight: "700",

};


const patientCard = {

  background: "#ffffff",

  border: "1px solid #e2e8f0",

  borderRadius: "18px",

  padding: "25px",

  marginBottom: "30px",

  boxShadow:
    "0 6px 20px rgba(30, 60, 90, 0.07)",

};


const patientHeader = {

  display: "flex",

  alignItems: "center",

  gap: "15px",

  marginBottom: "25px",

};


const patientAvatar = {

  width: "58px",

  height: "58px",

  borderRadius: "50%",

  background:
    "linear-gradient(135deg, #3f51b5, #2196f3)",

  color: "#fff",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  fontSize: "23px",

  fontWeight: "700",

};


const patientName = {

  margin: 0,

  color: "#263238",

  fontSize: "22px",

};


const patientSubtitle = {

  margin: "4px 0 0",

  color: "#78909c",

  fontSize: "14px",

};


const patientInfoGrid = {

  display: "grid",

  gridTemplateColumns:
    "repeat(auto-fit, minmax(220px, 1fr))",

  gap: "15px",

};


const infoItem = {

  display: "flex",

  alignItems: "center",

  gap: "12px",

  background: "#f8fafc",

  padding: "14px",

  borderRadius: "12px",

};


const infoIcon = {

  width: "38px",

  height: "38px",

  borderRadius: "10px",

  background: "#e8f1ff",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  fontSize: "18px",

};


const infoLabel = {

  color: "#78909c",

  fontSize: "12px",

  marginBottom: "3px",

};


const infoValue = {

  color: "#263238",

  fontWeight: "600",

  fontSize: "14px",

  wordBreak: "break-word",

};


const section = {

  marginBottom: "35px",

};


const sectionHeader = {

  marginBottom: "18px",

};


const sectionIcon = {

  fontSize: "25px",

  marginRight: "10px",

};


const sectionTitle = {

  display: "inline",

  margin: 0,

  color: "#263238",

  fontSize: "21px",

};


const sectionDescription = {

  margin: "7px 0 0 36px",

  color: "#78909c",

  fontSize: "14px",

};


const modulesGrid = {

  display: "grid",

  gridTemplateColumns:
    "repeat(2, minmax(0, 1fr))",

  gap: "18px",

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
    "0 4px 14px rgba(30, 60, 90, 0.05)",

  transition: "all 0.2s",

};


const moduleIcon = {

  minWidth: "52px",

  height: "52px",

  borderRadius: "14px",

  background: "#eef4ff",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  fontSize: "25px",

};


const moduleContent = {

  flex: 1,

};


const moduleTitle = {

  margin: "0 0 7px",

  color: "#263238",

  fontSize: "17px",

};


const moduleDescription = {

  margin: 0,

  color: "#78909c",

  lineHeight: "1.5",

  fontSize: "13px",

};


const moduleAction = {

  marginTop: "13px",

  color: "#3f51b5",

  fontWeight: "700",

  fontSize: "13px",

};


const toolsGrid = {

  display: "grid",

  gridTemplateColumns:
    "repeat(3, minmax(0, 1fr))",

  gap: "18px",

};


const toolCard = {

  background: "#ffffff",

  border: "1px solid #e1e8ef",

  borderRadius: "16px",

  padding: "22px",

  boxShadow:
    "0 4px 14px rgba(30, 60, 90, 0.05)",

};


const toolTop = {

  display: "flex",

  alignItems: "center",

  gap: "12px",

};


const toolIcon = {

  width: "48px",

  height: "48px",

  borderRadius: "13px",

  background: "#eef4ff",

  display: "flex",

  alignItems: "center",

  justifyContent: "center",

  fontSize: "23px",

};


const toolTitle = {

  margin: 0,

  color: "#263238",

  fontSize: "16px",

};


const toolDescription = {

  color: "#78909c",

  fontSize: "13px",

  lineHeight: "1.5",

  minHeight: "60px",

  margin: "15px 0",

};


const toolButton = {

  width: "100%",

  display: "flex",

  justifyContent: "space-between",

  alignItems: "center",

  border: "none",

  borderRadius: "9px",

  padding: "10px 13px",

  background: "#3f51b5",

  color: "#ffffff",

  fontWeight: "600",

  cursor: "pointer",

};


const footer = {

  borderTop: "1px solid #e5e9ef",

  marginTop: "35px",

  paddingTop: "18px",

  display: "flex",

  justifyContent: "space-between",

  color: "#90a4ae",

  fontSize: "12px",

};


const loadingContainer = {

  textAlign: "center",

  padding: "80px 20px",

  color: "#607d8b",

};


const loadingIcon = {

  fontSize: "40px",

  marginBottom: "10px",

};


const errorContainer = {

  maxWidth: "600px",

  margin: "80px auto",

  textAlign: "center",

  background: "#ffffff",

  padding: "40px",

  borderRadius: "16px",

  boxShadow:
    "0 5px 20px rgba(0,0,0,0.08)",

};


const errorIcon = {

  fontSize: "45px",

  marginBottom: "10px",

};