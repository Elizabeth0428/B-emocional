// src/layouts/MainLayout.jsx

import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { logout } from "../services/AuthService";

export default function MainLayout({ children, onNavigate }) {
  const navigate = useNavigate();
  const [menuOpen, setMenuOpen] = useState(false);

  // =====================================================
  // CAMBIAR CONTRASEÑA
  // =====================================================

  const handleChangePassword = () => {
    setMenuOpen(false);

    if (onNavigate) {
      onNavigate("cambiarPassword");
    }
  };

  // =====================================================
  // CERRAR SESIÓN
  // =====================================================

  const handleLogout = () => {
    setMenuOpen(false);

    logout();

    if (onNavigate) {
      onNavigate("landing");
    } else {
      navigate("/");
    }

    window.location.reload();
  };

  return (
    <div style={layout}>

      {/* =====================================================
          ÚNICA BARRA SUPERIOR
      ===================================================== */}
      <header style={topBar}>

        {/* =================================================
            IZQUIERDA
        ================================================= */}
        <div style={brandArea}>

          {/* LOGO ANIMADO */}
          <img
            src="/logo.png"
            alt="MirrorSoul"
            style={logoImage}
          />

        </div>


        {/* =================================================
            DERECHA
        ================================================= */}
        <div style={headerRight}>

          {/* =================================================
              BOTÓN AJUSTES
          ================================================= */}
          <div style={settingsWrapper}>

            <button
              style={settingsButton}
              onClick={() => setMenuOpen(!menuOpen)}
            >
              ⚙️ Ajustes
            </button>


            {/* =================================================
                MENÚ DE AJUSTES
            ================================================= */}
            {menuOpen && (
              <div style={settingsMenu}>

                <button
                  style={menuItem}
                  onClick={handleChangePassword}
                >
                  🔑 Cambiar contraseña
                </button>

                <button
                  style={{
                    ...menuItem,
                    ...logoutItem,
                  }}
                  onClick={handleLogout}
                >
                  🚪 Cerrar sesión
                </button>

              </div>
            )}

          </div>


          {/* =================================================
              ESTADO
          ================================================= */}
          <div style={status}>
            <span style={statusDot}></span>
            Sistema activo
          </div>

        </div>

      </header>


      {/* =====================================================
          CONTENIDO
      ===================================================== */}
      <main style={content}>
        {children}
      </main>

    </div>
  );
}


/* ============================================================
   CONTENEDOR PRINCIPAL
============================================================ */

const layout = {
  minHeight: "100vh",
  width: "100%",

  background:
    "linear-gradient(135deg, #EAF4FF 0%, #F4F9FF 50%, #E8F3FF 100%)",

  color: "#1F2937",
};


/* ============================================================
   BARRA SUPERIOR
============================================================ */

const topBar = {
  width: "100%",
  height: "86px",

  padding: "0 30px",

  boxSizing: "border-box",

  background:
    "linear-gradient(135deg, #4A90E2 0%, #357ABD 100%)",

  color: "#FFFFFF",

  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",

  boxShadow:
    "0 5px 18px rgba(53,122,189,0.25)",

  position: "relative",

  zIndex: 1000,
};


/* ============================================================
   ÁREA DEL LOGO
============================================================ */

const brandArea = {
  display: "flex",
  alignItems: "center",
  gap: "14px",

  height: "100%",

  flexShrink: 0,
};


/* ============================================================
   LOGO
============================================================ */

const logoImage = {
  width: "250px",
  height: "250px",

  objectFit: "contain",

  display: "block",

  flexShrink: 0,

  borderRadius: "14px",

  filter:
    "drop-shadow(0 4px 8px rgba(0,0,0,0.18))",

  animation:
    "mirrorSoulLogoFloat 3.5s ease-in-out infinite",
};



/* ============================================================
   DERECHA
============================================================ */

const headerRight = {
  display: "flex",

  alignItems: "center",

  gap: "14px",
};


/* ============================================================
   CONTENEDOR AJUSTES
============================================================ */

const settingsWrapper = {
  position: "relative",
};


/* ============================================================
   BOTÓN AJUSTES
============================================================ */

const settingsButton = {
  background:
    "rgba(255,255,255,0.14)",

  border:
    "1px solid rgba(255,255,255,0.25)",

  color: "#FFFFFF",

  padding: "9px 16px",

  borderRadius: "10px",

  cursor: "pointer",

  fontSize: "14px",

  fontWeight: "600",

  whiteSpace: "nowrap",

  boxShadow: "none",
};


/* ============================================================
   MENÚ DE AJUSTES
============================================================ */

const settingsMenu = {
  position: "absolute",

  top: "calc(100% + 10px)",

  right: "0",

  width: "210px",

  background: "#FFFFFF",

  borderRadius: "12px",

  padding: "8px",

  boxShadow:
    "0 12px 30px rgba(30,70,120,0.20)",

  border:
    "1px solid #E3ECF7",

  zIndex: 2000,
};


/* ============================================================
   OPCIONES DEL MENÚ
============================================================ */

const menuItem = {
  width: "100%",

  padding: "11px 12px",

  background: "transparent",

  border: "none",

  borderRadius: "8px",

  color: "#263B5A",

  cursor: "pointer",

  fontSize: "14px",

  fontWeight: "600",

  textAlign: "left",

  boxShadow: "none",

  transition: "background 0.2s ease",
};


const logoutItem = {
  color: "#D64545",

  marginTop: "3px",
};


/* ============================================================
   ESTADO
============================================================ */

const status = {
  display: "flex",

  alignItems: "center",

  gap: "8px",

  padding: "9px 14px",

  borderRadius: "20px",

  background:
    "rgba(255,255,255,0.13)",

  border:
    "1px solid rgba(255,255,255,0.15)",

  fontSize: "13px",

  fontWeight: "600",

  whiteSpace: "nowrap",
};


const statusDot = {
  width: "8px",

  height: "8px",

  borderRadius: "50%",

  background: "#6FCF97",

  boxShadow:
    "0 0 0 4px rgba(111,207,151,0.18)",
};


/* ============================================================
   CONTENIDO
============================================================ */

const content = {
  width: "100%",

  minHeight:
    "calc(100vh - 86px)",

  boxSizing: "border-box",

  overflowY: "auto",
};


/* ============================================================
   ANIMACIÓN DEL LOGO
============================================================ */

/*
  Se agrega directamente al documento.
  No necesitas crear otro archivo CSS.
*/

if (
  typeof document !== "undefined" &&
  !document.getElementById("mirrorsoul-logo-animation")
) {
  const style = document.createElement("style");

  style.id = "mirrorsoul-logo-animation";

  style.innerHTML = `
    @keyframes mirrorSoulLogoFloat {
      0% {
        transform: translateY(0px) rotate(0deg) scale(1);
      }

      25% {
        transform: translateY(-4px) rotate(2deg) scale(1.03);
      }

      50% {
        transform: translateY(-7px) rotate(0deg) scale(1.06);
      }

      75% {
        transform: translateY(-4px) rotate(-2deg) scale(1.03);
      }

      100% {
        transform: translateY(0px) rotate(0deg) scale(1);
      }
    }
  `;

  document.head.appendChild(style);
}