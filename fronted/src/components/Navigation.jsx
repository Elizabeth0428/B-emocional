// src/components/Navigation.jsx
import React from "react";
import logo from "../assets/logoMirrorsoul.png"; // asegúrate que esta ruta es correcta

const Navigation = ({ onNavigate }) => {
  return (
    <header className="nav-header">
      <div className="nav-logo" onClick={() => onNavigate("dashboard")}>
        <img src={logo} alt="MirrorSoul" />
        <span>MirrorSoul</span>
      </div>

      <nav className="nav-menu">
        <button onClick={() => onNavigate("dashboard")}>Inicio</button>
        <button onClick={() => onNavigate("citas")}>Citas</button>
        <button onClick={() => onNavigate("pacientes")}>Pacientes</button>
        <button onClick={() => onNavigate("perfil")}>Perfil</button>
      </nav>
    </header>
  );
};

export default Navigation;
