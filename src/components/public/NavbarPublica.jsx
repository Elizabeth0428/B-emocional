
import React, {
  useEffect,
  useState,
} from "react";

import {
  useLocation,
  useNavigate,
} from "react-router-dom";

import LogoMirrorSoul from "./LogoMirrorSoul";

import "./NavbarPublica.css";

// ============================================================
// CONFIGURACIÓN DEL TEMA PÚBLICO
// ============================================================

const TEMA_STORAGE_KEY = "mirrorsoul_tema_publico";

// ============================================================
// OBTENER TEMA GUARDADO
// ============================================================

function obtenerTemaInicial() {
  try {
    const guardado = localStorage.getItem(
      TEMA_STORAGE_KEY
    );

    return guardado === "oscuro"
      ? "oscuro"
      : "claro";
  } catch {
    return "claro";
  }
}

// ============================================================
// NAVBAR PÚBLICA MIRRORSOUL
// ============================================================

function NavbarPublica() {
  const navigate = useNavigate();
  const location = useLocation();

  // ==========================================================
  // ESTADOS
  // ==========================================================

  const [menuAbierto, setMenuAbierto] =
    useState(false);

  const [tema, setTema] =
    useState(obtenerTemaInicial);

  const oscuro = tema === "oscuro";

  // ==========================================================
  // APLICAR Y GUARDAR TEMA
  // ==========================================================

  useEffect(() => {
    document.documentElement.setAttribute(
      "data-ms-theme",
      tema
    );

    document.documentElement.style.colorScheme =
      oscuro ? "dark" : "light";

    try {
      localStorage.setItem(
        TEMA_STORAGE_KEY,
        tema
      );
    } catch {
      // La página continúa funcionando
      // aunque el almacenamiento esté bloqueado.
    }
  }, [tema, oscuro]);

  // ==========================================================
  // CERRAR MENÚ AL CAMBIAR DE RUTA
  // ==========================================================

  useEffect(() => {
    setMenuAbierto(false);
  }, [location.pathname]);

  // ==========================================================
  // NAVEGAR A SECCIÓN CON HASH
  // ==========================================================

  useEffect(() => {
    if (
      location.pathname !== "/" ||
      !location.hash
    ) {
      return;
    }

    let id = "";

    try {
      id = decodeURIComponent(
        location.hash.substring(1)
      );
    } catch {
      return;
    }

    const raf = requestAnimationFrame(() => {
      document
        .getElementById(id)
        ?.scrollIntoView({
          behavior: "smooth",
          block: "start",
        });
    });

    return () => cancelAnimationFrame(raf);
  }, [
    location.pathname,
    location.hash,
  ]);

  // ==========================================================
  // NAVEGACIÓN POR SECCIONES
  // ==========================================================

  const irASeccion = (id) => {
    setMenuAbierto(false);

    // Si estamos en otra página, regresar al inicio
    // y después desplazarnos a la sección.

    if (location.pathname !== "/") {
      navigate(`/#${id}`);
      return;
    }

    const elemento =
      document.getElementById(id);

    if (elemento) {
      elemento.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }

    // Actualizar la dirección sin recargar la página.
    // No usar navigate aquí para evitar
    // desplazamientos duplicados.

    if (window.location.hash !== `#${id}`) {
      window.history.replaceState(
        window.history.state,
        "",
        `/#${id}`
      );
    }
  };

  // ==========================================================
  // NAVEGACIÓN A OTRAS PÁGINAS
  // ==========================================================

  const irARuta = (ruta) => {
    setMenuAbierto(false);
    navigate(ruta);
  };

  // ==========================================================
  // CAMBIAR MODO CLARO / OSCURO
  // ==========================================================

  const cambiarTema = () => {
    setTema((actual) =>
      actual === "claro"
        ? "oscuro"
        : "claro"
    );
  };

  // ==========================================================
  // ELEMENTOS DE NAVEGACIÓN
  // ==========================================================

  const enlaces = [
    {
      texto: "MirrorSoul",
      seccion: "que-es",
    },
    {
      texto: "Soluciones",
      seccion: "soluciones",
    },
    {
      texto: "Beneficios",
      seccion: "beneficios",
    },
    {
      texto: "Planes",
      ruta: "/planes",
    },
    {
      texto: "Otros servicios",
      seccion: "servicios",
    },
  ];

  const manejarEnlace = (enlace) => {
    if (enlace.ruta) {
      irARuta(enlace.ruta);
    } else {
      irASeccion(enlace.seccion);
    }
  };

  // ==========================================================
  // RENDER
  // ==========================================================

  return (
    <header className="ms-public-navbar">

      <div className="ms-navbar-container">

        {/* ================================================== */}
        {/* LOGO Y NOMBRE MIRRORSOUL */}
        {/* ================================================== */}

        <button
          type="button"
          className="ms-navbar-brand"
          onClick={() =>
            irASeccion("inicio")
          }
          aria-label="Ir al inicio de MirrorSoul"
        >
          <span className="ms-navbar-logo">
            <LogoMirrorSoul
              width={76}
              height={66}
              background={false}
            />
          </span>

          <span className="ms-navbar-brand-name">
            <strong>
              MirrorSoul
            </strong>

            <small>
              Plataforma inteligente
            </small>
          </span>
        </button>

        {/* ================================================== */}
        {/* NAVEGACIÓN DESKTOP */}
        {/* ================================================== */}

        <nav
          className="ms-navbar-links"
          aria-label="Navegación principal"
        >
          {enlaces.map((enlace) => (
            <button
              key={enlace.texto}
              type="button"
              onClick={() =>
                manejarEnlace(enlace)
              }
            >
              {enlace.texto}
            </button>
          ))}
        </nav>

        {/* ================================================== */}
        {/* ACCIONES DESKTOP */}
        {/* ================================================== */}

        <div className="ms-navbar-actions">

          {/* SELECTOR DE APARIENCIA */}

          <button
            type="button"
            className="ms-theme-toggle"
            onClick={cambiarTema}
            aria-label={
              oscuro
                ? "Activar modo claro"
                : "Activar modo oscuro"
            }
            aria-pressed={oscuro}
            title={
              oscuro
                ? "Cambiar a modo claro"
                : "Cambiar a modo oscuro"
            }
          >
            <span aria-hidden="true">
              {oscuro ? "☀️" : "🌙"}
            </span>

            <span>
              {oscuro ? "Claro" : "Oscuro"}
            </span>
          </button>

          {/* INICIAR SESIÓN */}

          <button
            type="button"
            className="ms-navbar-login"
            onClick={() =>
              irARuta("/login")
            }
          >
            Iniciar sesión
          </button>

          {/* COMENZAR */}

          <button
            type="button"
            className="ms-navbar-primary"
            onClick={() =>
              irARuta("/planes")
            }
          >
            Comenzar
          </button>

        </div>

        {/* ================================================== */}
        {/* CONTROLES PARA CELULARES */}
        {/* ================================================== */}

        <div className="ms-navbar-mobile-controls">

          {/* SELECTOR MÓVIL */}

          <button
            type="button"
            className="ms-theme-toggle ms-theme-mobile"
            onClick={cambiarTema}
            aria-label={
              oscuro
                ? "Activar modo claro"
                : "Activar modo oscuro"
            }
            aria-pressed={oscuro}
          >
            <span aria-hidden="true">
              {oscuro ? "☀️" : "🌙"}
            </span>
          </button>

          {/* ABRIR / CERRAR MENÚ */}

          <button
            type="button"
            className="ms-navbar-menu-button"
            onClick={() =>
              setMenuAbierto((actual) => !actual)
            }
            aria-label={
              menuAbierto
                ? "Cerrar menú"
                : "Abrir menú"
            }
            aria-expanded={menuAbierto}
            aria-controls="ms-menu-movil"
          >
            {menuAbierto ? "✕" : "☰"}
          </button>

        </div>

      </div>

      {/* ==================================================== */}
      {/* MENÚ RESPONSIVE */}
      {/* ==================================================== */}

      {menuAbierto && (
        <div
          id="ms-menu-movil"
          className="ms-navbar-mobile-menu"
        >

          {/* ENLACES */}

          {enlaces.map((enlace) => (
            <button
              key={enlace.texto}
              type="button"
              onClick={() =>
                manejarEnlace(enlace)
              }
            >
              {enlace.texto}
            </button>
          ))}

          {/* ACCIONES MÓVILES */}

          <div className="ms-mobile-actions">

            <button
              type="button"
              className="ms-navbar-login"
              onClick={() =>
                irARuta("/login")
              }
            >
              Iniciar sesión
            </button>

            <button
              type="button"
              className="ms-navbar-primary"
              onClick={() =>
                irARuta("/planes")
              }
            >
              Comenzar
            </button>

          </div>

        </div>
      )}

    </header>
  );
}

export default NavbarPublica;
