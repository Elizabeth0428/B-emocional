// 📁 src/views/Dashboard.jsx
import React, { useEffect, useState } from "react";
import { logout, getCurrentUser } from "../services/AuthService";
import Avatar from "../components/Avatar.jsx";
import "./Dashboard.css";

const Dashboard = ({ onNavigate }) => {
  const user = getCurrentUser();
  const [showSettings, setShowSettings] = useState(false);

  const emojis = ["💙", "✨", "🙂", "😊", "🤗"];
  const [emoji, setEmoji] = useState("💙");

  useEffect(() => {
    const interval = setInterval(() => {
      setEmoji(emojis[Math.floor(Math.random() * emojis.length)]);
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  const handleLogout = () => {
    logout();
    onNavigate("login");
  };

  return (
    <div className="dashboard-wrapper">

      {/* ✅ NAVBAR SUPERIOR */}
      <header className="dashboard-navbar">
        <h3 className="navbar-title">MirrorSoul</h3>

        <div className="settings">
          <button className="settings-btn" onClick={() => setShowSettings(!showSettings)}>⚙️</button>
          {showSettings && (
            <div className="settings-menu">
              <button onClick={() => onNavigate("cambiarPassword")}>🔑 Cambiar contraseña</button>
              <button className="logout-btn" onClick={handleLogout}>🚪 Cerrar sesión</button>
            </div>
          )}
        </div>
      </header>

      {/* ✅ CONTENIDO PRINCIPAL */}
      <div className="dashboard-content">
        <Avatar />

        <div className="dashboard-panel">
         <h2 className="greeting">
  {emoji}{" "}
  {user?.role === 1 
    ? `Bienvenida Admin ${user?.nombre || "Usuario"}`
    : `Bienvenida Doc. ${user?.nombre || "Usuario"}`}
</h2>


          <p className="sub-text">Selecciona una opción para continuar con tu trabajo clínico.</p>

          <div className="dashboard-buttons">

            {/* ✅ OPCIONES PARA ADMINISTRADOR (role = 1) */}
            {user?.role === 1 && (
              <>
                <button onClick={() => onNavigate("registerPsychologist")}>
                  <img src="/icons/registrar.png" alt="Registrar Psicólogo" className="icon-btn" />
                  Registrar psicólogo
                </button>

                <button onClick={() => onNavigate("psychologistView")}>
                  <img src="/icons/pacientes.png" alt="Ver Psicólogos" className="icon-btn" />
                  Ver psicólogos
                </button>

                <button onClick={() => onNavigate("backup")}>
                  <img src="/icons/backup.png" alt="Backup" className="icon-btn" />
                  Backup de datos
                </button>
              </>
            )}

            {/* ✅ OPCIONES PARA PSICÓLOGO (role = 2) */}
            {user?.role === 2 && (
              <>
                <button onClick={() => onNavigate("registrarPaciente")}>
                  <img src="/icons/registrar.png" alt="Registrar" className="icon-btn" />
                  Registrar paciente
                </button>

                <button onClick={() => onNavigate("pacientes")}>
                  <img src="/icons/pacientes.png" alt="Pacientes" className="icon-btn" />
                  Ver pacientes
                </button>

                <button onClick={() => onNavigate("citas")}>
                  <img src="/icons/citas.png" alt="Citas" className="icon-btn" />
                  Citas
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
