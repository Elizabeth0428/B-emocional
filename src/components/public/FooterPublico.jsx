
import React from "react";

import {
  useLocation,
  useNavigate,
} from "react-router-dom";

import LogoMirrorSoul from "./LogoMirrorSoul";

// ============================================================
// MIRRORSOUL - FOOTER PÚBLICO
// Compatible con modo claro y oscuro
// ============================================================

function FooterPublico() {
  const navigate = useNavigate();
  const location = useLocation();

  // ==========================================================
  // NAVEGACIÓN A SECCIONES
  // ==========================================================

  const irASeccion = (id) => {
    const ruta = `/#${id}`;

    if (location.pathname !== "/") {
      navigate(ruta);
      return;
    }

    const elemento = document.getElementById(id);

    if (elemento) {
      elemento.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }

    if (window.location.hash !== `#${id}`) {
      window.history.replaceState(
        window.history.state,
        "",
        ruta
      );
    }
  };

  // ==========================================================
  // NAVEGACIÓN A PÁGINAS
  // ==========================================================

  const irARuta = (ruta) => {
    navigate(ruta);
  };

  // ==========================================================
  // ENLACES
  // ==========================================================

  const enlacesMirrorSoul = [
    {
      texto: "¿Qué es MirrorSoul?",
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
  ];

  const enlacesServicios = [
    "Equipo de cómputo",
    "Punto de venta",
    "Videovigilancia",
    "Soporte y mantenimiento",
  ];

  const enlacesContacto = [
    "Solicitar información",
    "Solicitar cotización",
    "Solicitar demostración",
  ];

  // ==========================================================
  // RENDER
  // ==========================================================

  return (
    <>
      <footer className="ms-footer">

        {/* ================================================ */}
        {/* DECORACIONES */}
        {/* ================================================ */}

        <div
          className="ms-footer-glow ms-footer-glow-left"
          aria-hidden="true"
        />

        <div
          className="ms-footer-glow ms-footer-glow-right"
          aria-hidden="true"
        />

        <div className="ms-footer-container">

          {/* ============================================== */}
          {/* COLUMNAS */}
          {/* ============================================== */}

          <div className="ms-footer-grid">

            {/* ============================================ */}
            {/* COLUMNA 1 - IDENTIDAD */}
            {/* ============================================ */}

            <div className="ms-footer-brand-column">

              <button
                type="button"
                className="ms-footer-logo"
                onClick={() => irASeccion("inicio")}
                aria-label="Volver al inicio de MirrorSoul"
              >
                <LogoMirrorSoul
                  width={118}
                  height={76}
                  background={false}
                  padding={0}
                />
              </button>

              <div className="ms-footer-brand-name">
                MirrorSoul
              </div>

              <p className="ms-footer-brand-text">
                Tecnología para comprender,
                acompañar y transformar la
                gestión del bienestar dentro de
                organizaciones y entornos
                profesionales.
              </p>

            </div>

            {/* ============================================ */}
            {/* COLUMNA 2 - MIRRORSOUL */}
            {/* ============================================ */}

            <div className="ms-footer-column">

              <h4 className="ms-footer-column-title">
                MirrorSoul
              </h4>

              <nav aria-label="Enlaces de MirrorSoul">
                {enlacesMirrorSoul.map((enlace) => (
                  <button
                    type="button"
                    key={enlace.texto}
                    className="ms-footer-link"
                    onClick={() => {
                      if (enlace.ruta) {
                        irARuta(enlace.ruta);
                      } else {
                        irASeccion(enlace.seccion);
                      }
                    }}
                  >
                    {enlace.texto}
                  </button>
                ))}
              </nav>

            </div>

            {/* ============================================ */}
            {/* COLUMNA 3 - SERVICIOS */}
            {/* ============================================ */}

            <div className="ms-footer-column">

              <h4 className="ms-footer-column-title">
                Servicios
              </h4>

              <nav aria-label="Servicios tecnológicos">
                {enlacesServicios.map((servicio) => (
                  <button
                    type="button"
                    key={servicio}
                    className="ms-footer-link"
                    onClick={() => irASeccion("servicios")}
                  >
                    {servicio}
                  </button>
                ))}
              </nav>

            </div>

            {/* ============================================ */}
            {/* COLUMNA 4 - CONTACTO */}
            {/* ============================================ */}

            <div className="ms-footer-column">

              <h4 className="ms-footer-column-title">
                Contacto
              </h4>

              <nav aria-label="Contacto y acceso">
                {enlacesContacto.map((opcion) => (
                  <button
                    type="button"
                    key={opcion}
                    className="ms-footer-link"
                    onClick={() => irARuta("/contacto")}
                  >
                    {opcion}
                  </button>
                ))}
              </nav>

              <button
                type="button"
                className="ms-footer-login"
                onClick={() => irARuta("/login")}
              >
                Iniciar sesión
                <span aria-hidden="true">→</span>
              </button>

            </div>

          </div>

          {/* ============================================== */}
          {/* BARRA INFERIOR */}
          {/* ============================================== */}

          <div className="ms-footer-bottom">

            <span className="ms-footer-copyright">
              © {new Date().getFullYear()} MirrorSoul.
              Todos los derechos reservados.
            </span>

            <span className="ms-footer-bottom-message">
              Tecnología y bienestar conectados.
            </span>

          </div>

        </div>

      </footer>

      {/* ================================================== */}
      {/* ESTILOS MODO CLARO Y OSCURO */}
      {/* ================================================== */}

      <style>{`

        /* ================================================
           1. VARIABLES - MODO CLARO
           ================================================ */

        :root,
        :root[data-ms-theme="claro"] {
          --footer-bg: linear-gradient(
            180deg,
            #edf5ff 0%,
            #e5f0fc 100%
          );

          --footer-title: #142842;
          --footer-text: #405874;
          --footer-muted: #61748a;

          --footer-border: #d0e0f0;

          --footer-link-hover: #1768ba;
          --footer-link-hover-bg:
            rgba(37, 99, 235, 0.07);

          --footer-login-bg: #ffffff;
          --footer-login-border: #cbdff3;
          --footer-login-text: #1768ba;

          --footer-glow-left:
            rgba(58, 165, 255, 0.13);

          --footer-glow-right:
            rgba(145, 121, 255, 0.11);
        }

        /* ================================================
           2. VARIABLES - MODO OSCURO
           ================================================ */

        :root[data-ms-theme="oscuro"] {
          --footer-bg: linear-gradient(
            180deg,
            #06111d 0%,
            #040d17 100%
          );

          --footer-title: #ffffff;
          --footer-text: #c2d1e3;
          --footer-muted: #9caec4;

          --footer-border:
            rgba(255, 255, 255, 0.10);

          --footer-link-hover: #72e9ff;
          --footer-link-hover-bg:
            rgba(114, 233, 255, 0.07);

          --footer-login-bg:
            rgba(255, 255, 255, 0.04);

          --footer-login-border:
            rgba(255, 255, 255, 0.14);

          --footer-login-text: #72e9ff;

          --footer-glow-left:
            rgba(77, 214, 255, 0.09);

          --footer-glow-right:
            rgba(145, 121, 255, 0.09);
        }

        /* ================================================
           3. CONTENEDOR GENERAL
           ================================================ */

        .ms-footer {
          position: relative;

          width: 100%;
          overflow: hidden;

          padding: 85px 28px 30px;

          background: var(--footer-bg);

          border-top:
            1px solid var(--footer-border);

          color: var(--footer-title);

          font-family: inherit;

          transition:
            background 0.3s ease,
            color 0.3s ease,
            border-color 0.3s ease;
        }

        .ms-footer-container {
          position: relative;
          z-index: 2;

          max-width: 1380px;
          margin: 0 auto;
        }

        /* ================================================
           4. DECORACIONES
           ================================================ */

        .ms-footer-glow {
          position: absolute;

          border-radius: 50%;

          filter: blur(110px);

          pointer-events: none;
        }

        .ms-footer-glow-left {
          width: 340px;
          height: 340px;

          top: -120px;
          left: -100px;

          background: var(--footer-glow-left);
        }

        .ms-footer-glow-right {
          width: 360px;
          height: 360px;

          right: -90px;
          bottom: -100px;

          background: var(--footer-glow-right);
        }

        /* ================================================
           5. CUATRO COLUMNAS
           ================================================ */

        .ms-footer-grid {
          display: grid;

          grid-template-columns:
            minmax(0, 1.3fr)
            repeat(3, minmax(0, 1fr));

          gap: 42px;

          align-items: start;
        }

        .ms-footer-column,
        .ms-footer-brand-column {
          min-width: 0;
        }

        .ms-footer-brand-column {
          max-width: 430px;
        }

        /* ================================================
           6. LOGO SIN FONDO DUPLICADO
           ================================================ */

        .ms-footer-logo {
          display: inline-flex;

          align-items: center;
          justify-content: center;

          padding: 0;
          margin: 0 0 14px;

          background: transparent;

          border: none;
          border-radius: 0;
          box-shadow: none;

          cursor: pointer;
        }

        .ms-footer-logo img {
          display: block;
          max-width: 100%;
          height: 100%;
          object-fit: contain;
        }

        .ms-footer-brand-name {
          margin-bottom: 15px;

          color: var(--footer-title);

          font-size: 25px;
          font-weight: 900;

          letter-spacing: -0.7px;
        }

        /* ================================================
           7. TEXTO DE PRESENTACIÓN
           ================================================ */

        .ms-footer .ms-footer-brand-text {
          margin: 0;

          color: var(--footer-text) !important;

          font-size: 16px !important;
          line-height: 1.85 !important;

          font-weight: 500;
        }

        /* ================================================
           8. TÍTULOS DE COLUMNAS
           ================================================ */

        .ms-footer .ms-footer-column-title {
          margin: 0 0 23px;

          color: var(--footer-title) !important;

          font-size: 22px !important;
          font-weight: 900;

          line-height: 1.25 !important;
        }

        /* ================================================
           9. ENLACES
           ================================================ */

        .ms-footer-link {
          display: block;

          width: 100%;

          padding: 7px 10px;
          margin: 0 0 7px -10px;

          border: none;
          border-radius: 9px;

          background: transparent;
          color: var(--footer-text);

          font-family: inherit;
          font-size: 16px;
          font-weight: 600;

          line-height: 1.6;
          text-align: left;

          cursor: pointer;

          transition:
            background 0.2s ease,
            color 0.2s ease,
            transform 0.2s ease;
        }

        .ms-footer-link:hover {
          color: var(--footer-link-hover);
          background: var(--footer-link-hover-bg);

          transform: translateX(3px);
        }

        /* ================================================
           10. INICIAR SESIÓN
           ================================================ */

        .ms-footer-login {
          display: inline-flex;

          align-items: center;
          justify-content: center;

          gap: 12px;

          margin-top: 14px;
          padding: 13px 18px;

          min-height: 47px;

          border: 1px solid var(--footer-login-border);
          border-radius: 13px;

          background: var(--footer-login-bg);

          color: var(--footer-login-text);

          font-family: inherit;
          font-size: 15px;
          font-weight: 900;

          cursor: pointer;

          transition:
            background 0.2s ease,
            transform 0.2s ease,
            border-color 0.2s ease;
        }

        .ms-footer-login:hover {
          background: var(--footer-link-hover-bg);
          transform: translateY(-2px);
        }

        .ms-footer-login span {
          font-size: 20px;
        }

        /* ================================================
           11. BARRA INFERIOR
           ================================================ */

        .ms-footer-bottom {
          display: flex;

          align-items: center;
          justify-content: space-between;

          flex-wrap: wrap;

          gap: 15px;

          margin-top: 60px;
          padding-top: 25px;

          border-top:
            1px solid var(--footer-border);
        }

        .ms-footer-copyright,
        .ms-footer-bottom-message {
          color: var(--footer-muted);

          font-size: 13px;
          font-weight: 500;

          line-height: 1.6;
        }

        /* ================================================
           12. ACCESIBILIDAD
           ================================================ */

        .ms-footer button:focus-visible {
          outline: 3px solid #3b82f6;
          outline-offset: 4px;
        }

        /* ================================================
           13. TABLET
           ================================================ */

        @media (max-width: 1024px) {
          .ms-footer {
            padding: 70px 25px 30px;
          }

          .ms-footer-grid {
            grid-template-columns:
              repeat(2, minmax(0, 1fr));

            gap: 40px 30px;
          }

          .ms-footer-brand-column {
            max-width: 100%;
          }
        }

        /* ================================================
           14. CELULARES
           ================================================ */

        @media (max-width: 600px) {
          .ms-footer {
            padding: 55px 20px 25px;
          }

          .ms-footer-grid {
            grid-template-columns: 1fr;

            gap: 35px;
          }

          .ms-footer-brand-name {
            font-size: 23px;
          }

          .ms-footer .ms-footer-column-title {
            margin-bottom: 15px;

            font-size: 20px !important;
          }

          .ms-footer-link {
            font-size: 15px;
            margin-bottom: 4px;
          }

          .ms-footer-bottom {
            flex-direction: column;
            align-items: flex-start;

            gap: 8px;

            margin-top: 45px;
            padding-top: 20px;
          }

          .ms-footer-copyright,
          .ms-footer-bottom-message {
            font-size: 12px;
          }
        }

        /* ================================================
           15. MOVIMIENTO REDUCIDO
           ================================================ */

        @media (prefers-reduced-motion: reduce) {
          .ms-footer *,
          .ms-footer *::before,
          .ms-footer *::after {
            animation: none !important;
            transition: none !important;
          }
        }

      `}</style>
    </>
  );
}

export default FooterPublico;
