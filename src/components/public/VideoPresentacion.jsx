
import React from "react";
import LogoMirrorSoul from "./LogoMirrorSoul";

// ============================================================
// MIRRORSOUL - VIDEO DE PRESENTACIÓN
// MODO CLARO Y OSCURO
// ============================================================

// ============================================================
// 1. ÁREAS DE LA PLATAFORMA
// ============================================================

const caracteristicas = [
  {
    icono: "🏢",
    titulo: "Recursos Humanos",
  },
  {
    icono: "🏥",
    titulo: "Clínica",
  },
  {
    icono: "🧠",
    titulo: "Evaluaciones",
  },
  {
    icono: "🤖",
    titulo: "Inteligencia artificial",
  },
  {
    icono: "🤝",
    titulo: "Canalización",
  },
  {
    icono: "📊",
    titulo: "Reportes",
  },
];

// ============================================================
// 2. COMPONENTE PRINCIPAL
// ============================================================

function VideoPresentacion() {
  return (
    <>
      <section className="ms-video-section">

        <div className="ms-video-container">

          {/* ============================================== */}
          {/* ENCABEZADO */}
          {/* ============================================== */}

          <div className="ms-video-heading">

            <span className="ms-video-eyebrow">
              CONOCE MIRRORSOUL
            </span>

            <h2 className="ms-video-main-title">
              Descubre cómo funciona la plataforma
              en un solo recorrido.
            </h2>

            <p className="ms-video-description">
              MirrorSoul integra diferentes procesos
              dentro de un mismo entorno. Desde la
              gestión y evaluación hasta el análisis,
              seguimiento y atención profesional.
            </p>

          </div>

          {/* ============================================== */}
          {/* TARJETA PRINCIPAL DEL VIDEO */}
          {/* ============================================== */}

          <div className="ms-video-card">

            <div
              className="ms-video-glow"
              aria-hidden="true"
            />

            {/* ============================================ */}
            {/* CABECERA DE LA TARJETA */}
            {/* ============================================ */}

            <div className="ms-video-header">

              <div className="ms-video-brand">

                <div className="ms-video-logo">

                  <LogoMirrorSoul
                    width={58}
                    height={46}
                    background={false}
                    padding={0}
                  />

                </div>

                <div className="ms-video-brand-info">

                  <strong className="ms-video-brand-title">
                    MirrorSoul
                  </strong>

                  <span className="ms-video-brand-subtitle">
                    Video de presentación
                  </span>

                </div>

              </div>

              <span className="ms-video-duration">
                Próximamente
              </span>

            </div>

            {/* ============================================ */}
            {/* ÁREA RESERVADA PARA EL VIDEO */}
            {/* ============================================ */}

            <div className="ms-video-area">

              <div className="ms-video-area-glow" />

              <div className="ms-video-content">

                {/* INDICADOR DECORATIVO */}

                <div
                  className="ms-video-play"
                  aria-hidden="true"
                >
                  <span>▶</span>
                </div>

                <span className="ms-video-available-label">
                  PRESENTACIÓN OFICIAL
                </span>

                <h3 className="ms-video-content-title">
                  Conoce MirrorSoul en acción
                </h3>

                <p className="ms-video-content-text">
                  Próximamente podrás conocer
                  los principales módulos,
                  procesos y beneficios de
                  MirrorSoul a través de
                  nuestra presentación oficial.
                </p>

                <span className="ms-video-soon">
                  Video disponible próximamente
                </span>

              </div>

            </div>

            {/* ============================================ */}
            {/* CARACTERÍSTICAS */}
            {/* ============================================ */}

            <div className="ms-video-features">

              {caracteristicas.map((item) => (

                <div
                  key={item.titulo}
                  className="ms-video-feature"
                >

                  <span
                    className="ms-video-feature-icon"
                    aria-hidden="true"
                  >
                    {item.icono}
                  </span>

                  <span className="ms-video-feature-text">
                    {item.titulo}
                  </span>

                </div>

              ))}

            </div>

          </div>

          {/* ============================================== */}
          {/* TEXTO DE APOYO */}
          {/* ============================================== */}

          <div className="ms-video-bottom">

            <span className="ms-video-bottom-label">
              UNA VISIÓN COMPLETA
            </span>

            <h3 className="ms-video-bottom-title">
              Todo el ecosistema MirrorSoul,
              conectado en una sola experiencia.
            </h3>

            <p className="ms-video-bottom-description">
              El video podrá mostrar la experiencia
              real dentro de la plataforma, ayudando
              a que empresas y profesionales
              comprendan rápidamente cómo funciona
              y qué valor puede aportar.
            </p>

          </div>

        </div>

      </section>

      {/* ================================================== */}
      {/* ESTILOS DEL COMPONENTE */}
      {/* ================================================== */}

      <style>{`

        /* ================================================
           3. VARIABLES - MODO CLARO
           ================================================ */

        :root,
        :root[data-ms-theme="claro"] {
          --vid-title: #142842;
          --vid-text: #526782;
          --vid-muted: #60738b;

          --vid-accent: #1768ba;

          --vid-card-bg: linear-gradient(
            145deg,
            #ffffff 0%,
            #f4f9ff 100%
          );

          --vid-card-border: #dce7f5;

          --vid-area-bg: radial-gradient(
            circle at center,
            #e4f2ff 0%,
            #f6faff 65%,
            #ffffff 100%
          );

          --vid-area-border: #dce8f6;

          --vid-play-bg: linear-gradient(
            135deg,
            #d9f4ff,
            #e5e6ff
          );

          --vid-play-border: #cce2fa;
          --vid-play-color: #206bb8;

          --vid-badge-bg: #eaf4ff;
          --vid-badge-border: #d2e6fa;

          --vid-feature-bg: #f1f7ff;
          --vid-feature-border: #e0eaf6;

          --vid-icon-bg: #e5f2ff;

          --vid-shadow:
            0 25px 65px rgba(28, 63, 107, 0.10);
        }

        /* ================================================
           4. VARIABLES - MODO OSCURO
           ================================================ */

        :root[data-ms-theme="oscuro"] {
          --vid-title: #ffffff;
          --vid-text: #c0d0e4;
          --vid-muted: #aec1d7;

          --vid-accent: #78e7ff;

          --vid-card-bg: linear-gradient(
            145deg,
            #182c40 0%,
            #0c1a2b 100%
          );

          --vid-card-border:
            rgba(255,255,255,0.09);

          --vid-area-bg: radial-gradient(
            circle at center,
            rgba(92,123,255,0.17),
            #08121f 68%
          );

          --vid-area-border:
            rgba(255,255,255,0.08);

          --vid-play-bg: linear-gradient(
            135deg,
            rgba(99,229,255,0.16),
            rgba(142,125,255,0.18)
          );

          --vid-play-border:
            rgba(108,230,255,0.19);

          --vid-play-color: #ffffff;

          --vid-badge-bg:
            rgba(255,255,255,0.06);

          --vid-badge-border:
            rgba(255,255,255,0.10);

          --vid-feature-bg:
            rgba(255,255,255,0.045);

          --vid-feature-border:
            rgba(255,255,255,0.08);

          --vid-icon-bg:
            rgba(108,230,255,0.08);

          --vid-shadow:
            0 35px 80px rgba(0,0,0,0.24);
        }

        /* ================================================
           5. SECCIÓN
           ================================================ */

        .ms-video-section {
          position: relative;

          width: 100%;
          padding: 110px 28px;

          background: transparent;
          color: var(--vid-title);
        }

        .ms-video-container {
          width: 100%;
          max-width: 1180px;
          margin: 0 auto;
        }

        /* ================================================
           6. ENCABEZADO
           ================================================ */

        .ms-video-heading {
          max-width: 850px;
          margin: 0 auto 50px;

          text-align: center;
        }

        .ms-video-eyebrow {
          display: inline-block;
          margin-bottom: 15px;

          color: var(--vid-accent);

          font-size: 13px;
          font-weight: 900;
          letter-spacing: 1.8px;
        }

        .mirrorsoul-public-page
        .ms-video-main-title {
          margin: 0;

          color: var(--vid-title) !important;

          font-size:
            clamp(2.2rem, 3vw, 3.5rem) !important;

          line-height: 1.1 !important;
          letter-spacing: -1.3px;

          font-weight: 900;
        }

        .mirrorsoul-public-page
        .ms-video-description {
          max-width: 750px;
          margin: 22px auto 0;

          color: var(--vid-text) !important;

          font-size:
            clamp(1.05rem, 1.13vw, 1.2rem) !important;

          line-height: 1.75 !important;
          font-weight: 500;
        }

        /* ================================================
           7. TARJETA PRINCIPAL
           ================================================ */

        .ms-video-card {
          position: relative;
          overflow: hidden;

          padding: 22px;

          border-radius: 28px;
          border: 1px solid var(--vid-card-border);

          background: var(--vid-card-bg);

          box-shadow: var(--vid-shadow);

          color: var(--vid-title);

          transition:
            background 0.3s ease,
            color 0.3s ease,
            border-color 0.3s ease;
        }

        .ms-video-glow {
          position: absolute;

          width: 420px;
          height: 420px;

          right: -160px;
          top: -160px;

          border-radius: 50%;

          background:
            rgba(104,226,255,0.07);

          filter: blur(100px);

          pointer-events: none;
        }

        /* ================================================
           8. CABECERA DEL VIDEO
           ================================================ */

        .ms-video-header {
          position: relative;
          z-index: 2;

          display: flex;
          align-items: center;
          justify-content: space-between;

          gap: 15px;
          margin-bottom: 18px;
        }

        .ms-video-brand {
          display: flex;
          align-items: center;

          gap: 11px;
          min-width: 0;
        }

        .ms-video-logo {
          display: flex;
          align-items: center;
          justify-content: center;

          flex-shrink: 0;

          width: 58px;
          height: 46px;

          background: transparent;
          border: none;
          box-shadow: none;
        }

        .ms-video-brand-info {
          min-width: 0;
        }

        .ms-video-brand-title {
          display: block;

          color: var(--vid-title);

          font-size: 15px;
          font-weight: 900;
        }

        .ms-video-brand-subtitle {
          display: block;
          margin-top: 4px;

          color: var(--vid-muted);

          font-size: 12px;
          font-weight: 600;
        }

        .ms-video-duration {
          display: inline-flex;
          align-items: center;
          justify-content: center;

          padding: 8px 12px;

          border-radius: 9px;

          background: var(--vid-badge-bg);
          border: 1px solid var(--vid-badge-border);

          color: var(--vid-text);

          font-size: 11px;
          font-weight: 800;

          white-space: nowrap;
        }

        /* ================================================
           9. ÁREA CENTRAL DEL VIDEO
           ================================================ */

        .ms-video-area {
          position: relative;
          overflow: hidden;

          display: flex;
          align-items: center;
          justify-content: center;

          width: 100%;
          min-height: 440px;

          border-radius: 20px;

          background: var(--vid-area-bg);
          border: 1px solid var(--vid-area-border);

          transition:
            background 0.3s ease,
            border-color 0.3s ease;
        }

        .ms-video-area-glow {
          position: absolute;

          width: 320px;
          height: 320px;

          left: 50%;
          top: 50%;

          transform: translate(-50%, -50%);

          border-radius: 50%;

          background:
            rgba(95,170,255,0.10);

          filter: blur(65px);

          pointer-events: none;
        }

        .ms-video-content {
          position: relative;
          z-index: 2;

          width: 100%;
          max-width: 550px;

          padding: 35px 25px;

          text-align: center;
        }

        /* ================================================
           10. ICONO DE REPRODUCCIÓN DECORATIVO
           ================================================ */

        .ms-video-play {
          display: flex;
          align-items: center;
          justify-content: center;

          width: 78px;
          height: 78px;

          margin: 0 auto 24px;

          border-radius: 50%;

          background: var(--vid-play-bg);
          border: 1px solid var(--vid-play-border);

          color: var(--vid-play-color);

          box-shadow:
            0 12px 35px rgba(91,203,255,0.10);
        }

        .ms-video-play span {
          margin-left: 4px;

          font-size: 27px;
          line-height: 1;
        }

        /* ================================================
           11. CONTENIDO CENTRAL
           ================================================ */

        .ms-video-available-label {
          display: block;

          margin-bottom: 13px;

          color: var(--vid-accent);

          font-size: 12px;
          font-weight: 900;

          letter-spacing: 1.5px;
        }

        .mirrorsoul-public-page
        .ms-video-content-title {
          margin: 0;

          color: var(--vid-title) !important;

          font-size: 28px !important;
          font-weight: 900;

          line-height: 1.3 !important;
          letter-spacing: -0.5px;
        }

        .mirrorsoul-public-page
        .ms-video-content-text {
          max-width: 460px;

          margin: 16px auto 0;

          color: var(--vid-text) !important;

          font-size: 16px !important;
          line-height: 1.75 !important;
        }

        .ms-video-soon {
          display: inline-flex;
          align-items: center;
          justify-content: center;

          margin-top: 23px;
          padding: 10px 16px;

          border-radius: 999px;

          background: var(--vid-badge-bg);
          border: 1px solid var(--vid-badge-border);

          color: var(--vid-accent);

          font-size: 12px;
          font-weight: 800;
        }

        /* ================================================
           12. CARACTERÍSTICAS
           ================================================ */

        .ms-video-features {
          display: grid;

          grid-template-columns:
            repeat(6, minmax(0, 1fr));

          gap: 10px;
          margin-top: 18px;
        }

        .ms-video-feature {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;

          gap: 9px;
          min-width: 0;
          min-height: 90px;

          padding: 13px 9px;

          border-radius: 13px;

          background: var(--vid-feature-bg);
          border: 1px solid var(--vid-feature-border);

          transition:
            background 0.3s ease,
            border-color 0.3s ease;
        }

        .ms-video-feature-icon {
          display: flex;
          align-items: center;
          justify-content: center;

          width: 34px;
          height: 34px;

          border-radius: 10px;

          background: var(--vid-icon-bg);

          font-size: 19px;
        }

        .ms-video-feature-text {
          color: var(--vid-text);

          font-size: 12px;
          font-weight: 800;

          line-height: 1.4;
          text-align: center;
        }

        /* ================================================
           13. MENSAJE FINAL
           ================================================ */

        .ms-video-bottom {
          max-width: 800px;

          margin: 60px auto 0;

          text-align: center;
        }

        .ms-video-bottom-label {
          display: block;

          margin-bottom: 13px;

          color: var(--vid-accent);

          font-size: 12px;
          font-weight: 900;

          letter-spacing: 1.5px;
        }

        .mirrorsoul-public-page
        .ms-video-bottom-title {
          margin: 0;

          color: var(--vid-title) !important;

          font-size:
            clamp(1.9rem, 2.4vw, 2.8rem) !important;

          line-height: 1.2 !important;
          font-weight: 900;

          letter-spacing: -0.7px;
        }

        .mirrorsoul-public-page
        .ms-video-bottom-description {
          max-width: 700px;

          margin: 17px auto 0;

          color: var(--vid-text) !important;

          font-size: 17px !important;
          line-height: 1.75 !important;
        }

        /* ================================================
           14. TABLET
           ================================================ */

        @media (max-width: 1024px) {
          .ms-video-section {
            padding: 85px 25px;
          }

          .ms-video-features {
            grid-template-columns:
              repeat(3, minmax(0, 1fr));
          }

          .ms-video-area {
            min-height: 380px;
          }
        }

        /* ================================================
           15. CELULARES
           ================================================ */

        @media (max-width: 600px) {
          .ms-video-section {
            padding: 65px 18px;
          }

          .ms-video-heading {
            margin-bottom: 35px;
          }

          .ms-video-card {
            padding: 14px;
            border-radius: 20px;
          }

          .ms-video-header {
            gap: 10px;
          }

          .ms-video-logo {
            width: 46px;
            height: 42px;
          }

          .ms-video-logo > div {
            max-width: 46px;
            max-height: 42px;
          }

          .ms-video-brand-title {
            font-size: 13px;
          }

          .ms-video-brand-subtitle {
            font-size: 10px;
          }

          .ms-video-duration {
            padding: 6px 8px;
            font-size: 10px;
          }

          .ms-video-area {
            min-height: 340px;
            border-radius: 15px;
          }

          .ms-video-content {
            padding: 25px 15px;
          }

          .ms-video-play {
            width: 65px;
            height: 65px;
          }

          .mirrorsoul-public-page
          .ms-video-content-title {
            font-size: 23px !important;
          }

          .mirrorsoul-public-page
          .ms-video-content-text {
            font-size: 15px !important;
          }

          .ms-video-features {
            grid-template-columns:
              repeat(2, minmax(0, 1fr));

            gap: 9px;
          }

          .ms-video-feature {
            min-height: 83px;
            padding: 11px 7px;
          }

          .ms-video-feature-text {
            font-size: 11px;
          }

          .ms-video-bottom {
            margin-top: 45px;
          }

          .mirrorsoul-public-page
          .ms-video-main-title {
            font-size:
              clamp(2rem, 7vw, 2.7rem) !important;
          }
        }

        /* ================================================
           16. ACCESIBILIDAD
           ================================================ */

        @media (prefers-reduced-motion: reduce) {
          .ms-video-section *,
          .ms-video-section *::before,
          .ms-video-section *::after {
            animation: none !important;
            transition: none !important;
          }
        }

      `}</style>
    </>
  );
}

export default VideoPresentacion;
