// src/views/Dashboard.jsx
import React, { useEffect, useState } from "react";
import { getCurrentUser } from "../services/AuthService";
import Avatar from "../components/Avatar.jsx";

const Dashboard = ({ onNavigate }) => {
  const user = getCurrentUser();

  // =====================================================
  // EMOJIS DINÁMICOS
  // =====================================================

  const emojis = [
    "😀",
    "😎",
    "🤓",
    "🧠",
    "😄",
    "😊",
    "🙌",
    "🌈",
    "🌟",
    "💡",
    "🎯",
  ];

  const [emoji, setEmoji] = useState("😀");

  useEffect(() => {
    const interval = setInterval(() => {
      const randomEmoji =
        emojis[Math.floor(Math.random() * emojis.length)];

      setEmoji(randomEmoji);
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  const handleHoverEmoji = () => {
    const randomEmoji =
      emojis[Math.floor(Math.random() * emojis.length)];

    setEmoji(randomEmoji);
  };

  return (
    <div style={page}>

      {/* =====================================================
          CONTENIDO PRINCIPAL
      ===================================================== */}
      <main style={mainContent}>

        {/* Decoración */}
        <div style={decorCircleOne}></div>
        <div style={decorCircleTwo}></div>
        <div style={decorCircleThree}></div>


        {/* =================================================
            PRESENTACIÓN
        ================================================= */}
        <section style={welcomeSection}>

          <div style={welcomeText}>

            <h1 style={title}>
              ¡Hola,{" "}
              <span
                style={name}
                onMouseEnter={handleHoverEmoji}
              >
                {user?.nombre || "Usuario"}
              </span>
              !{" "}
              <span>{emoji}</span>
            </h1>

            <p style={subtitle}>
              🌱 Selecciona una opción para continuar
              <br />
              con tu trabajo clínico.
            </p>

          </div>


          {/* =================================================
              DOCTORA
              
              IMPORTANTE:
              La burbuja de la doctora ya pertenece a Avatar.jsx.
              Aquí NO agregamos ninguna burbuja adicional.
          ================================================= */}
          <div style={avatarContainer}>
            <Avatar />
          </div>

        </section>


        {/* =================================================
            TARJETAS PRINCIPALES
        ================================================= */}
        <section style={cardsContainer}>

          {/* ===============================================
              ADMINISTRADOR
          =============================================== */}
          {user?.role === 1 && (
            <>
              <DashboardCard
                icon="➕"
                title="Registrar psicólogo"
                description="Añade un nuevo psicólogo al sistema"
                accent="purple"
                onClick={() =>
                  onNavigate("registerPsychologist")
                }
              />

              <DashboardCard
                icon="👥"
                title="Ver psicólogos"
                description="Consulta y gestiona los psicólogos"
                accent="blue"
                onClick={() =>
                  onNavigate("psychologistView")
                }
              />
            </>
          )}


          {/* ===============================================
              PSICÓLOGO
          =============================================== */}
          {user?.role === 2 && (
            <>
              <DashboardCard
                icon="➕"
                title="Registrar paciente"
                description="Añade un nuevo paciente al sistema"
                accent="purple"
                onClick={() =>
                  onNavigate("registrarPaciente")
                }
              />

              <DashboardCard
                icon="👥"
                title={
                  <>
                    Ver pacientes
                    <br />
                    <span style={{ fontSize: "15px" }}>
                      (expedientes clínicos)
                    </span>
                  </>
                }
                description="Consulta y gestiona los expedientes clínicos"
                accent="blue"
                onClick={() =>
                  onNavigate("pacientes")
                }
              />

              <DashboardCard
                icon="📅"
                title="Citas"
                description="Gestiona citas y agendamientos"
                accent="green"
                onClick={() =>
                  onNavigate("citas")
                }
              />
            </>
          )}

        </section>


        {/* =================================================
            PIE DE PÁGINA
        ================================================= */}
        <footer style={footer}>
          © 2025{" "}
          <span style={footerBrand}>
            MirrorSoul
          </span>
          . Todos los derechos reservados.
        </footer>

      </main>

    </div>
  );
};


/* ============================================================
   COMPONENTE TARJETA
============================================================ */

const DashboardCard = ({
  icon,
  title,
  description,
  accent,
  onClick,
}) => {

  const accentColors = {
    purple: {
      border: "#8B4DE8",
      iconBackground: "#F3E9FF",
      iconColor: "#7B3FE4",
      title: "#7540D5",
    },

    blue: {
      border: "#4A7FF5",
      iconBackground: "#EAF1FF",
      iconColor: "#2167DD",
      title: "#2167DD",
    },

    green: {
      border: "#54C96B",
      iconBackground: "#ECF9EF",
      iconColor: "#3BAE55",
      title: "#3BAE55",
    },
  };

  const colors =
    accentColors[accent] || accentColors.blue;

  return (
    <button
      style={{
        ...card,
        borderBottom: `4px solid ${colors.border}`,
      }}
      onClick={onClick}
      onMouseEnter={(e) => {
        e.currentTarget.style.transform =
          "translateY(-6px)";

        e.currentTarget.style.boxShadow =
          "0 15px 30px rgba(40,80,140,0.14)";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.transform =
          "translateY(0)";

        e.currentTarget.style.boxShadow =
          "0 8px 20px rgba(40,80,140,0.08)";
      }}
    >

      {/* Icono */}
      <div
        style={{
          ...cardIcon,
          background: colors.iconBackground,
          color: colors.iconColor,
        }}
      >
        {icon}
      </div>

      {/* Título */}
      <div
        style={{
          ...cardTitle,
          color: colors.title,
        }}
      >
        {title}
      </div>

      {/* Descripción */}
      <div style={cardDescription}>
        {description}
      </div>

    </button>
  );
};


/* ============================================================
   ESTILOS GENERALES
============================================================ */

const page = {
  minHeight: "100%",
  width: "100%",
  background: "#F4F9FE",
  fontFamily: "'Segoe UI', Arial, sans-serif",
  color: "#1A2B4B",
  overflow: "hidden",
};


/* ============================================================
   CONTENIDO
============================================================ */

const mainContent = {
  minHeight: "calc(100vh - 86px)",
  position: "relative",
  padding: "55px 7%",
  boxSizing: "border-box",
  overflow: "hidden",
};


/* ============================================================
   DECORACIONES
============================================================ */

const decorCircleOne = {
  position: "absolute",
  width: "350px",
  height: "350px",
  borderRadius: "50%",
  background: "rgba(100,170,255,0.08)",
  right: "-130px",
  bottom: "-150px",
  pointerEvents: "none",
};

const decorCircleTwo = {
  position: "absolute",
  width: "150px",
  height: "150px",
  borderRadius: "50%",
  background: "rgba(100,170,255,0.08)",
  right: "20px",
  top: "80px",
  pointerEvents: "none",
};

const decorCircleThree = {
  position: "absolute",
  width: "10px",
  height: "10px",
  borderRadius: "50%",
  background: "rgba(60,120,220,0.20)",
  right: "150px",
  top: "100px",
  boxShadow:
    "30px 20px 0 rgba(60,120,220,0.15), 60px -15px 0 rgba(60,120,220,0.12)",
  pointerEvents: "none",
};


/* ============================================================
   BIENVENIDA
============================================================ */

const welcomeSection = {
  maxWidth: "1150px",
  margin: "0 auto 42px",
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  position: "relative",
  zIndex: 2,
};

const welcomeText = {
  flex: "1",
};

const title = {
  margin: "0 0 12px",
  fontSize: "40px",
  fontWeight: "800",
  color: "#172B4D",
  letterSpacing: "-1px",
};

const name = {
  color: "#2167D5",
  cursor: "pointer",
};

const subtitle = {
  margin: "0",
  fontSize: "17px",
  lineHeight: "1.6",
  color: "#596B82",
};


/* ============================================================
   AVATAR
============================================================ */

const avatarContainer = {
  width: "350px",
  height: "170px",

  display: "flex",
  justifyContent: "center",
  alignItems: "center",

  background: "transparent",

  position: "relative",

  overflow: "visible",

  boxSizing: "border-box",

  transform: "translateY(-15px)",
};

/* ============================================================
   TARJETAS
============================================================ */

const cardsContainer = {
  maxWidth: "1150px",
  margin: "0 auto",
  padding: "38px",
  background: "rgba(255,255,255,0.90)",
  borderRadius: "20px",
  boxShadow: "0 8px 24px rgba(40,80,140,0.08)",
  display: "grid",
  gridTemplateColumns: "repeat(3, 1fr)",
  gap: "28px",
  position: "relative",
  zIndex: 3,
  boxSizing: "border-box",
};

const card = {
  minHeight: "245px",
  background: "#FFFFFF",
  border: "1px solid #E4EAF2",
  borderRadius: "16px",
  padding: "28px 22px 24px",
  cursor: "pointer",
  display: "flex",
  flexDirection: "column",
  justifyContent: "center",
  alignItems: "center",
  textAlign: "center",
  transition: "all 0.25s ease",
  boxShadow: "0 8px 20px rgba(40,80,140,0.08)",
  fontFamily: "'Segoe UI', Arial, sans-serif",
};

const cardIcon = {
  width: "64px",
  height: "64px",
  borderRadius: "50%",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  fontSize: "29px",
  marginBottom: "18px",
};

const cardTitle = {
  fontSize: "18px",
  fontWeight: "800",
  marginBottom: "12px",
  lineHeight: "1.3",
};

const cardDescription = {
  fontSize: "14px",
  lineHeight: "1.5",
  color: "#718096",
  maxWidth: "210px",
};


/* ============================================================
   PIE DE PÁGINA
============================================================ */

const footer = {
  maxWidth: "1150px",
  margin: "38px auto 0",
  paddingTop: "20px",
  borderTop: "1px solid #DCE5F0",
  textAlign: "center",
  fontSize: "12px",
  color: "#64748B",
  position: "relative",
  zIndex: 2,
};

const footerBrand = {
  color: "#2167D5",
  fontWeight: "700",
};


/* ============================================================
   EXPORT
============================================================ */

export default Dashboard;