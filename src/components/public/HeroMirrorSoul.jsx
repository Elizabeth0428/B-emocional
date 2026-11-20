
import React from "react";
import { useNavigate } from "react-router-dom";
import LogoMirrorSoul from "./LogoMirrorSoul";

// ============================================================
// HERO MIRRORSOUL
// Compatible con data-ms-theme="claro" y "oscuro"
// ============================================================

const caracteristicas = [
  {
    titulo: "Todo conectado",
    descripcion: "Gestión, evaluación y seguimiento.",
  },
  {
    titulo: "Procesos inteligentes",
    descripcion: "Automatización e IA aplicada.",
  },
  {
    titulo: "Información útil",
    descripcion: "Datos para mejores decisiones.",
  },
];

const modulos = [
  {
    icono: "👥",
    etiqueta: "PERSONAS",
    titulo: "Gestión centralizada",
  },
  {
    icono: "🧠",
    etiqueta: "BIENESTAR",
    titulo: "Seguimiento integral",
  },
  {
    icono: "🤖",
    etiqueta: "INTELIGENCIA",
    titulo: "IA aplicada",
  },
  {
    icono: "📊",
    etiqueta: "RESULTADOS",
    titulo: "Información clara",
  },
];

const etapas = [
  "Detecta",
  "Evalúa",
  "Analiza",
  "Acompaña",
];

function HeroMirrorSoul() {
  const navigate = useNavigate();

  // ==========================================================
  // NAVEGACIÓN
  // ==========================================================

  const irASeccion = (id) => {
    document
      .getElementById(id)
      ?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
  };

  return (
    <>
      <section className="ms-hero">

        {/* ================================================ */}
        {/* DECORACIONES */}
        {/* ================================================ */}

        <div className="ms-hero-glow ms-hero-glow-left" />
        <div className="ms-hero-glow ms-hero-glow-right" />

        <div className="ms-hero-container">

          {/* ============================================== */}
          {/* COLUMNA IZQUIERDA */}
          {/* ============================================== */}

          <div className="ms-hero-content">

            {/* ETIQUETA */}

            <div className="ms-hero-badge">
              <span className="ms-hero-badge-dot" />

              Tecnología, bienestar e
              inteligencia artificial
            </div>

            {/* TÍTULO */}

            <h1 className="ms-hero-title">
              Una nueva forma de comprender,
              acompañar y transformar el
              bienestar dentro de las
              organizaciones.
            </h1>

            {/* DESCRIPCIÓN */}

            <p className="ms-hero-description">
              MirrorSoul integra gestión,
              evaluación, seguimiento,
              atención profesional e
              inteligencia artificial en una
              sola plataforma, permitiendo
              conectar personas, procesos y
              decisiones de forma más inteligente.
            </p>

            {/* ============================================ */}
            {/* BOTONES */}
            {/* ============================================ */}

            <div className="ms-hero-buttons">

              <button
                type="button"
                className="ms-hero-primary"
                onClick={() =>
                  irASeccion("que-es")
                }
              >
                Conocer MirrorSoul
                <span aria-hidden="true">→</span>
              </button>

              <button
                type="button"
                className="ms-hero-secondary"
                onClick={() =>
                  navigate("/planes")
                }
              >
                Ver planes
              </button>

            </div>

            {/* ============================================ */}
            {/* CARACTERÍSTICAS */}
            {/* ============================================ */}

            <div className="ms-hero-metrics">
              {caracteristicas.map((item) => (
                <div
                  className="ms-hero-metric"
                  key={item.titulo}
                >
                  <span
                    className="ms-hero-metric-icon"
                    aria-hidden="true"
                  >
                    ✓
                  </span>

                  <div>
                    <strong className="ms-hero-metric-title">
                      {item.titulo}
                    </strong>

                    <span className="ms-hero-metric-description">
                      {item.descripcion}
                    </span>
                  </div>
                </div>
              ))}
            </div>

          </div>

          {/* ============================================== */}
          {/* COLUMNA DERECHA - PANEL MIRRORSOUL */}
          {/* ============================================== */}

          <div className="ms-hero-visual">

            <div className="ms-hero-visual-glow" />

            <div className="ms-hero-dashboard">

              {/* ========================================== */}
              {/* CABECERA */}
              {/* ========================================== */}

              <div className="ms-hero-dashboard-header">

                <div className="ms-hero-dashboard-brand">

                  <div className="ms-hero-dashboard-logo">
                    <LogoMirrorSoul
                      width={48}
                      height={48}
                      background={false}
                      padding={0}
                    />
                  </div>

                  <div>
                    <div className="ms-hero-dashboard-brand-title">
                      MirrorSoul
                    </div>

                    <div className="ms-hero-dashboard-brand-subtitle">
                      Plataforma inteligente
                    </div>
                  </div>

                </div>

                <div className="ms-hero-status">
                  <span className="ms-hero-status-dot" />
                  Activo
                </div>

              </div>

              {/* ========================================== */}
              {/* CUATRO MÓDULOS */}
              {/* ========================================== */}

              <div className="ms-hero-dashboard-grid">
                {modulos.map((modulo) => (
                  <div
                    className="ms-hero-module"
                    key={modulo.etiqueta}
                  >
                    <div className="ms-hero-module-icon">
                      {modulo.icono}
                    </div>

                    <div className="ms-hero-module-info">

                      <span className="ms-hero-module-label">
                        {modulo.etiqueta}
                      </span>

                      <strong className="ms-hero-module-title">
                        {modulo.titulo}
                      </strong>

                    </div>
                  </div>
                ))}
              </div>

              {/* ========================================== */}
              {/* PANEL DE VISIÓN GENERAL */}
              {/* ========================================== */}

              <div className="ms-hero-process-panel">

                <div className="ms-hero-process-header">

                  <div>
                    <span className="ms-hero-process-eyebrow">
                      VISIÓN GENERAL
                    </span>

                    <h3 className="ms-hero-process-title">
                      Conecta cada etapa del proceso
                    </h3>
                  </div>

                  <span className="ms-hero-process-badge">
                    MirrorSoul
                  </span>

                </div>

                {/* FLUJO */}

                <div className="ms-hero-process-flow">
                  {etapas.map((etapa, index) => (
                    <React.Fragment key={etapa}>

                      {index > 0 && (
                        <span
                          className="ms-hero-flow-line"
                          aria-hidden="true"
                        />
                      )}

                      <div className="ms-hero-flow-item">
                        <span className="ms-hero-flow-number">
                          {String(index + 1).padStart(2, "0")}
                        </span>

                        <span className="ms-hero-flow-text">
                          {etapa}
                        </span>
                      </div>

                    </React.Fragment>
                  ))}
                </div>

              </div>

              {/* ========================================== */}
              {/* PIE DEL PANEL */}
              {/* ========================================== */}

              <div className="ms-hero-dashboard-footer">

                <span>
                  Gestión inteligente para
                  organizaciones y profesionales.
                </span>

                <span
                  className="ms-hero-footer-arrow"
                  aria-hidden="true"
                >
                  ↗
                </span>

              </div>

            </div>
          </div>

        </div>
      </section>

      {/* ================================================== */}
      {/* ESTILOS DEL HERO */}
      {/* ================================================== */}

      <style>{`

        /* ================================================
           1. VARIABLES - MODO CLARO
           ================================================ */

        :root,
        :root[data-ms-theme="claro"] {
          --hero-title: #132844;
          --hero-text: #52677f;
          --hero-muted: #64748b;

          --hero-badge-bg: #eaf5ff;
          --hero-badge-text: #1762a6;
          --hero-badge-border: #cce6ff;

          --hero-secondary-bg: #ffffff;
          --hero-secondary-text: #17375a;

          --hero-metric-bg: #e8f4ff;
          --hero-metric-color: #1670ce;

          --hero-dashboard-bg: linear-gradient(
            145deg,
            #ffffff 0%,
            #f4f9ff 100%
          );

          --hero-dashboard-border: #d8e6f5;
          --hero-dashboard-title: #142b47;
          --hero-dashboard-text: #566b83;

          --hero-module-bg: #edf5ff;
          --hero-module-border: #dce8f6;
          --hero-icon-bg: #dfeeff;

          --hero-panel-bg: #eaf3ff;
          --hero-panel-border: #d4e5f7;

          --hero-number-bg: #dceeff;
          --hero-number-text: #1766b1;

          --hero-shadow:
            0 24px 65px rgba(25, 62, 110, 0.13);
        }

        /* ================================================
           2. VARIABLES - MODO OSCURO
           ================================================ */

        :root[data-ms-theme="oscuro"] {
          --hero-title: #ffffff;
          --hero-text: #c0d0e4;
          --hero-muted: #9eb1c9;

          --hero-badge-bg: rgba(85,224,255,0.06);
          --hero-badge-text: #9fe9fa;
          --hero-badge-border: rgba(109,229,255,0.17);

          --hero-secondary-bg: rgba(255,255,255,0.045);
          --hero-secondary-text: #ffffff;

          --hero-metric-bg: rgba(84,223,255,0.08);
          --hero-metric-color: #78e9ff;

          --hero-dashboard-bg: linear-gradient(
            145deg,
            #1e2e42 0%,
            #101c2d 100%
          );

          --hero-dashboard-border: rgba(255,255,255,0.10);
          --hero-dashboard-title: #ffffff;
          --hero-dashboard-text: #b7c7da;

          --hero-module-bg: rgba(255,255,255,0.045);
          --hero-module-border: rgba(255,255,255,0.08);
          --hero-icon-bg: rgba(255,255,255,0.065);

          --hero-panel-bg: rgba(65,105,150,0.14);
          --hero-panel-border: rgba(112,222,255,0.10);

          --hero-number-bg: rgba(97,229,255,0.09);
          --hero-number-text: #76eaff;

          --hero-shadow:
            0 35px 80px rgba(0,0,0,0.30);
        }

        /* ================================================
           3. SECCIÓN PRINCIPAL
           ================================================ */

        .ms-hero {
          position: relative;
          width: 100%;
          min-height: calc(100vh - 84px);

          display: flex;
          align-items: center;

          padding: 80px 28px 90px;

          overflow: hidden;

          background: transparent;
          color: var(--hero-title);
        }

        .ms-hero-glow {
          position: absolute;
          width: 480px;
          height: 480px;
          border-radius: 50%;
          filter: blur(115px);
          pointer-events: none;
          opacity: 0.5;
        }

        .ms-hero-glow-left {
          top: -180px;
          left: -170px;
          background: rgba(76,151,255,0.20);
        }

        .ms-hero-glow-right {
          right: -180px;
          bottom: -160px;
          background: rgba(74,218,255,0.15);
        }

        .ms-hero-container {
          position: relative;
          z-index: 2;

          width: 100%;
          max-width: 1380px;
          margin: 0 auto;

          display: grid;
          grid-template-columns:
            minmax(0,1.05fr)
            minmax(0,0.95fr);

          align-items: center;
          gap: clamp(28px,4vw,65px);
        }

        .ms-hero-content {
          min-width: 0;
          max-width: 710px;
        }

        /* ================================================
           4. ETIQUETA
           ================================================ */

        .ms-hero-badge {
          display: inline-flex;
          align-items: center;
          gap: 9px;

          padding: 9px 15px;
          margin-bottom: 25px;

          border-radius: 999px;
          border: 1px solid var(--hero-badge-border);
          background: var(--hero-badge-bg);

          color: var(--hero-badge-text);

          font-size: 12px;
          font-weight: 800;
          letter-spacing: 0.8px;
          text-transform: uppercase;
        }

        .ms-hero-badge-dot {
          width: 8px;
          height: 8px;
          flex-shrink: 0;

          border-radius: 50%;
          background: #26b8eb;
        }

        /* ================================================
           5. TÍTULO Y DESCRIPCIÓN
           ================================================ */

        .mirrorsoul-public-page
        .ms-hero .ms-hero-title {
          margin: 0;
          max-width: 740px;

          color: var(--hero-title) !important;

          font-size:
            clamp(2.4rem,3.15vw,3.9rem) !important;

          line-height: 1.08 !important;
          letter-spacing: -1.4px;
          font-weight: 900;
          text-wrap: balance;
        }

        .mirrorsoul-public-page
        .ms-hero .ms-hero-description {
          margin: 27px 0 0;

          max-width: 660px;

          color: var(--hero-text) !important;

          font-size:
            clamp(1.04rem,1.12vw,1.2rem) !important;

          line-height: 1.75 !important;
          font-weight: 500;
        }

        /* ================================================
           6. BOTONES
           ================================================ */

        .ms-hero-buttons {
          display: flex;
          flex-wrap: wrap;
          gap: 14px;
          margin-top: 34px;
        }

        .ms-hero-primary,
        .ms-hero-secondary {
          min-height: 56px;
          padding: 15px 23px;

          display: inline-flex;
          align-items: center;
          justify-content: center;

          gap: 12px;

          border-radius: 13px;
          font-family: inherit;
          font-size: 16px;
          font-weight: 900;

          cursor: pointer;

          transition:
            transform 0.2s ease,
            box-shadow 0.2s ease;
        }

        .ms-hero-primary {
          border: none;

          background: linear-gradient(
            135deg,
            #55d7f4,
            #8478ff
          );

          color: #071828;

          box-shadow:
            0 13px 30px rgba(77,153,255,0.16);
        }

        .ms-hero-primary span {
          font-size: 23px;
          line-height: 1;
        }

        .ms-hero-secondary {
          border: 1px solid var(--hero-dashboard-border);
          background: var(--hero-secondary-bg);
          color: var(--hero-secondary-text);
        }

        .ms-hero-primary:hover,
        .ms-hero-secondary:hover {
          transform: translateY(-3px);
        }

        .ms-hero-primary:focus-visible,
        .ms-hero-secondary:focus-visible {
          outline: 3px solid #2563eb;
          outline-offset: 3px;
        }

        /* ================================================
           7. CARACTERÍSTICAS
           ================================================ */

        .ms-hero-metrics {
          display: grid;
          grid-template-columns: repeat(3,minmax(0,1fr));
          gap: 15px;
          margin-top: 43px;
        }

        .ms-hero-metric {
          display: flex;
          align-items: flex-start;
          gap: 10px;
          min-width: 0;
        }

        .ms-hero-metric-icon {
          display: flex;
          align-items: center;
          justify-content: center;

          flex-shrink: 0;

          width: 28px;
          height: 28px;

          border-radius: 9px;

          background: var(--hero-metric-bg);
          color: var(--hero-metric-color);

          font-size: 15px;
          font-weight: 900;
        }

        .ms-hero-metric-title {
          display: block;

          margin-bottom: 5px;

          color: var(--hero-title);

          font-size: 13px;
          line-height: 1.35;
          font-weight: 900;
        }

        .ms-hero-metric-description {
          display: block;

          color: var(--hero-muted);

          font-size: 11px;
          line-height: 1.55;
        }

        /* ================================================
           8. PANEL VISUAL
           ================================================ */

        .ms-hero-visual {
          position: relative;

          display: flex;
          align-items: center;
          justify-content: center;

          min-width: 0;
        }

        .ms-hero-visual-glow {
          position: absolute;
          width: 90%;
          height: 85%;

          border-radius: 50%;
          background: rgba(97,147,255,0.16);

          filter: blur(85px);
          pointer-events: none;
        }

        .ms-hero-dashboard {
          position: relative;
          z-index: 2;

          width: 100%;
          max-width: 620px;

          padding: 25px;
          border-radius: 28px;

          border: 1px solid var(--hero-dashboard-border);
          background: var(--hero-dashboard-bg);
          box-shadow: var(--hero-shadow);

          color: var(--hero-dashboard-title);

          transition:
            background 0.3s ease,
            border-color 0.3s ease,
            color 0.3s ease;
        }

        /* ================================================
           9. CABECERA DEL PANEL
           ================================================ */

        .ms-hero-dashboard-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 12px;
          margin-bottom: 23px;
        }

        .ms-hero-dashboard-brand {
          display: flex;
          align-items: center;
          gap: 11px;
          min-width: 0;
        }

        .ms-hero-dashboard-logo {
          display: flex;
          align-items: center;
          justify-content: center;
          flex-shrink: 0;

          width: 52px;
          height: 52px;

          background: transparent;
          border: none;
          box-shadow: none;
        }

        .ms-hero-dashboard-brand-title {
          color: var(--hero-dashboard-title);
          font-size: 16px;
          font-weight: 900;
        }

        .ms-hero-dashboard-brand-subtitle {
          margin-top: 3px;
          color: var(--hero-dashboard-text);
          font-size: 11px;
        }

        .ms-hero-status {
          display: flex;
          align-items: center;
          gap: 7px;

          color: var(--hero-dashboard-text);
          font-size: 11px;
          font-weight: 800;
        }

        .ms-hero-status-dot {
          width: 9px;
          height: 9px;

          border-radius: 50%;
          background: #22c97f;
          box-shadow:
            0 0 10px rgba(34,201,127,0.28);
        }

        /* ================================================
           10. MÓDULOS SUPERIORES
           ================================================ */

        .ms-hero-dashboard-grid {
          display: grid;
          grid-template-columns: repeat(2,minmax(0,1fr));

          gap: 12px;
          margin-bottom: 17px;
        }

        .ms-hero-module {
          display: flex;
          align-items: center;
          gap: 12px;

          min-width: 0;

          padding: 14px;

          border: 1px solid var(--hero-module-border);
          border-radius: 16px;

          background: var(--hero-module-bg);
        }

        .ms-hero-module-icon {
          width: 40px;
          height: 40px;

          flex-shrink: 0;

          display: flex;
          align-items: center;
          justify-content: center;

          border-radius: 12px;

          background: var(--hero-icon-bg);

          font-size: 19px;
        }

        .ms-hero-module-info {
          min-width: 0;
        }

        .ms-hero-module-label {
          display: block;

          color: var(--hero-dashboard-text);

          font-size: 10px;
          font-weight: 800;
          letter-spacing: 0.5px;
        }

        .ms-hero-module-title {
          display: block;

          margin-top: 5px;

          color: var(--hero-dashboard-title);

          font-size: 12px;
          line-height: 1.4;
          font-weight: 900;
        }

        /* ================================================
           11. PANEL CENTRAL
           ================================================ */

        .ms-hero-process-panel {
          padding: 18px;

          border-radius: 18px;

          border: 1px solid var(--hero-panel-border);
          background: var(--hero-panel-bg);
        }

        .ms-hero-process-header {
          display: flex;
          align-items: center;
          justify-content: space-between;

          gap: 10px;
          margin-bottom: 25px;
        }

        .ms-hero-process-eyebrow {
          color: var(--hero-metric-color);

          font-size: 10px;
          font-weight: 900;
          letter-spacing: 1px;
        }

        .ms-hero-process-panel
        .ms-hero-process-title {
          margin: 6px 0 0;

          color: var(--hero-dashboard-title) !important;

          font-size: 16px !important;
          line-height: 1.35 !important;
          font-weight: 900;
        }

        .ms-hero-process-badge {
          padding: 7px 10px;
          border-radius: 9px;

          background: var(--hero-module-bg);
          border: 1px solid var(--hero-module-border);

          color: var(--hero-dashboard-text);

          font-size: 10px;
          font-weight: 800;

          white-space: nowrap;
        }

        /* ================================================
           12. FLUJO DE PROCESOS
           ================================================ */

        .ms-hero-process-flow {
          display: flex;
          align-items: flex-start;
          justify-content: space-between;
          width: 100%;
        }

        .ms-hero-flow-item {
          display: flex;
          flex-direction: column;
          align-items: center;

          gap: 8px;
          flex-shrink: 0;
        }

        .ms-hero-flow-number {
          width: 34px;
          height: 34px;

          display: flex;
          align-items: center;
          justify-content: center;

          border-radius: 11px;
          background: var(--hero-number-bg);
          color: var(--hero-number-text);

          font-size: 11px;
          font-weight: 900;
        }

        .ms-hero-flow-text {
          color: var(--hero-dashboard-text);

          font-size: 10px;
          font-weight: 800;
        }

        .ms-hero-flow-line {
          height: 1px;
          flex: 1;

          margin: 17px 8px 0;

          background: var(--hero-dashboard-border);
        }

        /* ================================================
           13. PIE DEL PANEL
           ================================================ */

        .ms-hero-dashboard-footer {
          display: flex;
          align-items: center;
          justify-content: space-between;

          gap: 15px;
          margin-top: 16px;
          padding: 12px 3px 2px;

          color: var(--hero-dashboard-text);

          font-size: 10px;
          line-height: 1.5;
        }

        .ms-hero-footer-arrow {
          color: var(--hero-metric-color);
          font-size: 19px;
        }

        /* ================================================
           14. TABLET
           ================================================ */

        @media (max-width: 1100px) {
          .ms-hero-container {
            gap: 32px;
          }

          .ms-hero {
            padding: 65px 22px 75px;
          }

          .ms-hero-metrics {
            gap: 10px;
          }

          .ms-hero-dashboard {
            padding: 18px;
          }
        }

        /* ================================================
           15. PANTALLAS PEQUEÑAS
           ================================================ */

        @media (max-width: 900px) {
          .ms-hero-container {
            grid-template-columns: 1fr;
            gap: 48px;
          }

          .ms-hero-content {
            max-width: 100%;
          }

          .ms-hero-visual {
            width: 100%;
          }

          .ms-hero-dashboard {
            max-width: 700px;
          }
        }

        /* ================================================
           16. CELULARES
           ================================================ */

        @media (max-width: 600px) {
          .ms-hero {
            padding: 52px 18px 65px;
          }

          .ms-hero-badge {
            font-size: 10px;
            letter-spacing: 0.3px;
            line-height: 1.4;
          }

          .mirrorsoul-public-page
          .ms-hero .ms-hero-title {
            font-size:
              clamp(2.05rem,7.5vw,2.85rem) !important;
          }

          .ms-hero-buttons {
            flex-direction: column;
          }

          .ms-hero-primary,
          .ms-hero-secondary {
            width: 100%;
          }

          .ms-hero-metrics {
            grid-template-columns: 1fr;
            gap: 18px;
          }

          .ms-hero-dashboard {
            padding: 15px;
            border-radius: 20px;
          }

          .ms-hero-dashboard-grid {
            gap: 8px;
          }

          .ms-hero-module {
            padding: 10px;
            gap: 8px;
          }

          .ms-hero-module-icon {
            width: 32px;
            height: 32px;
            font-size: 16px;
          }

          .ms-hero-module-title {
            font-size: 11px;
          }

          .ms-hero-process-panel {
            padding: 12px;
          }

          .ms-hero-process-badge {
            display: none;
          }

          .ms-hero-flow-line {
            margin-left: 3px;
            margin-right: 3px;
          }

          .ms-hero-flow-text {
            font-size: 9px;
          }
        }

        /* ================================================
           17. ACCESIBILIDAD
           ================================================ */

        @media (prefers-reduced-motion: reduce) {
          .ms-hero *,
          .ms-hero *::before,
          .ms-hero *::after {
            transition: none !important;
            animation: none !important;
          }
        }

      `}</style>
    </>
  );
}

export default HeroMirrorSoul;
