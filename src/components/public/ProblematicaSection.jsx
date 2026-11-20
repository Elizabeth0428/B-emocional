
import React from "react";
import LogoMirrorSoul from "./LogoMirrorSoul";

// ============================================================
// MIRRORSOUL - LA PROBLEMÁTICA
// Compatible con modo claro y oscuro
// ============================================================

// ============================================================
// PROBLEMAS IDENTIFICADOS
// ============================================================

const problemas = [
  {
    icono: "📂",
    titulo: "Información dispersa",
    texto:
      "Datos importantes repartidos entre hojas de cálculo, archivos, mensajes, correos y diferentes sistemas.",
  },
  {
    icono: "⏱️",
    titulo: "Falta de seguimiento",
    texto:
      "Evaluaciones, casos o procesos que se inician, pero pierden continuidad con el paso del tiempo.",
  },
  {
    icono: "🔁",
    titulo: "Procesos manuales",
    texto:
      "Tareas repetitivas que consumen tiempo y aumentan el riesgo de errores, duplicidad o pérdida de información.",
  },
  {
    icono: "📉",
    titulo: "Poca visibilidad",
    texto:
      "Dificultad para saber qué está ocurriendo realmente, qué requiere atención y qué acciones ya se realizaron.",
  },
  {
    icono: "🧠",
    titulo: "Detección tardía",
    texto:
      "Señales emocionales, laborales o clínicas que pueden pasar desapercibidas hasta convertirse en un problema mayor.",
  },
  {
    icono: "🤝",
    titulo: "Áreas desconectadas",
    texto:
      "RH, profesionales, administradores y usuarios trabajando con información separada y sin un flujo común.",
  },
];

// ============================================================
// BARRAS ILUSTRATIVAS DEL PROBLEMA
//
// Los porcentajes son decorativos, no estadísticas reales.
// ============================================================

const indicadores = [
  {
    titulo: "Evaluaciones",
    porcentaje: 78,
  },
  {
    titulo: "Seguimiento",
    porcentaje: 38,
  },
  {
    titulo: "Información conectada",
    porcentaje: 28,
  },
  {
    titulo: "Capacidad de respuesta",
    porcentaje: 42,
  },
];

// ============================================================
// COMPONENTE PRINCIPAL
// ============================================================

function ProblematicaSection() {
  return (
    <>
      <section className="ms-problematica">

        <div className="ms-problematica-container">

          {/* ============================================== */}
          {/* ENCABEZADO */}
          {/* ============================================== */}

          <div className="ms-problematica-heading">

            <span className="ms-problematica-eyebrow">
              LA PROBLEMÁTICA
            </span>

            <h2 className="ms-problematica-title">
              Cuando la información no está
              conectada, también se pierde
              la capacidad de actuar a tiempo.
            </h2>

            <p className="ms-problematica-description">
              Muchas organizaciones cuentan con
              información, evaluaciones y procesos,
              pero siguen trabajando con herramientas
              separadas que dificultan el seguimiento,
              la prevención y la toma de decisiones.
            </p>

          </div>

          {/* ============================================== */}
          {/* SEIS TARJETAS DE PROBLEMAS */}
          {/* ============================================== */}

          <div className="ms-problematica-grid">

            {problemas.map((problema) => (
              <article
                key={problema.titulo}
                className="ms-problematica-card"
              >

                <div
                  className="ms-problematica-icon"
                  aria-hidden="true"
                >
                  {problema.icono}
                </div>

                <h3 className="ms-problematica-card-title">
                  {problema.titulo}
                </h3>

                <p className="ms-problematica-card-text">
                  {problema.texto}
                </p>

              </article>
            ))}

          </div>

          {/* ============================================== */}
          {/* BLOQUE DE IMPACTO */}
          {/* ============================================== */}

          <div className="ms-problematica-impact">

            <div
              className="ms-problematica-impact-glow"
              aria-hidden="true"
            />

            {/* ============================================ */}
            {/* EXPLICACIÓN */}
            {/* ============================================ */}

            <div className="ms-problematica-impact-content">

              <span className="ms-problematica-impact-eyebrow">
                EL RESULTADO
              </span>

              <h3 className="ms-problematica-impact-title">
                Mucha información, pero poca
                capacidad de convertirla en
                acciones claras.
              </h3>

              <p className="ms-problematica-impact-text">
                Cuando cada área trabaja por separado,
                el seguimiento se vuelve más difícil,
                la información pierde valor y detectar
                una necesidad a tiempo puede
                convertirse en un reto.
              </p>

            </div>

            {/* ============================================ */}
            {/* PANEL DE INDICADORES */}
            {/* ============================================ */}

            <div className="ms-problematica-visual">

              <div className="ms-problematica-visual-heading">
                <span>VISIÓN DEL PROBLEMA</span>

                <span className="ms-problematica-visual-decoration">
                  ◉
                </span>
              </div>

              {indicadores.map((indicador) => (
                <div
                  key={indicador.titulo}
                  className="ms-problematica-visual-row"
                >

                  <span className="ms-problematica-visual-label">
                    {indicador.titulo}
                  </span>

                  <div className="ms-problematica-visual-line">
                    <div
                      className="ms-problematica-visual-progress"
                      style={{
                        width: `${indicador.porcentaje}%`,
                      }}
                    />
                  </div>

                </div>
              ))}

              {/* ========================================== */}
              {/* ALERTA */}
              {/* ========================================== */}

              <div className="ms-problematica-alert">

                <span
                  className="ms-problematica-alert-icon"
                  aria-hidden="true"
                >
                  !
                </span>

                <div className="ms-problematica-alert-content">

                  <strong className="ms-problematica-alert-title">
                    El problema no siempre es
                    tener pocos datos.
                  </strong>

                  <span className="ms-problematica-alert-text">
                    El problema es no poder conectarlos,
                    interpretarlos y darles continuidad.
                  </span>

                </div>

              </div>

            </div>

          </div>

          {/* ============================================== */}
          {/* TRANSICIÓN HACIA LA SOLUCIÓN */}
          {/* ============================================== */}

          <div className="ms-problematica-transition">

            <div className="ms-problematica-transition-brand">

              <LogoMirrorSoul
                width={92}
                height={72}
                background={false}
                padding={0}
              />

            </div>

            <div className="ms-problematica-transition-content">

              <span className="ms-problematica-transition-label">
                AQUÍ ENTRA MIRRORSOUL
              </span>

              <h3 className="ms-problematica-transition-title">
                Una plataforma diseñada para
                conectar cada etapa del proceso.
              </h3>

              <p className="ms-problematica-transition-text">
                Detectar, evaluar, analizar,
                acompañar y dar seguimiento dentro
                de un mismo entorno.
              </p>

            </div>

          </div>

        </div>

      </section>

      {/* ================================================== */}
      {/* ESTILOS MODO CLARO Y OSCURO */}
      {/* ================================================== */}

      <style>{`

        /* ================================================
           1. VARIABLES MODO CLARO
           ================================================ */

        :root,
        :root[data-ms-theme="claro"] {
          --prob-title: #142842;
          --prob-text: #526782;
          --prob-muted: #566b82;

          --prob-eyebrow: #ad492f;

          --prob-card-bg: #ffffff;
          --prob-card-border: #dce7f5;

          --prob-icon-bg: #fff0e8;
          --prob-icon-border: #f6d7c8;

          --prob-impact-bg: linear-gradient(
            145deg,
            #fff5f0 0%,
            #ffffff 100%
          );

          --prob-impact-border: #f2d7c8;

          --prob-visual-bg: #ffffff;
          --prob-visual-border: #eadcd5;

          --prob-track-bg: #e7edf5;

          --prob-alert-bg: #fff1e9;
          --prob-alert-border: #f3d2c3;
          --prob-alert-text: #7c4638;

          --prob-transition-bg: #eaf4ff;
          --prob-transition-border: #d4e6f7;

          --prob-transition-accent: #1768ba;

          --prob-shadow:
            0 18px 50px rgba(27, 61, 104, 0.09);
        }

        /* ================================================
           2. VARIABLES MODO OSCURO
           ================================================ */

        :root[data-ms-theme="oscuro"] {
          --prob-title: #ffffff;
          --prob-text: #c4d2e2;
          --prob-muted: #b7c6d8;

          --prob-eyebrow: #ffad8e;

          --prob-card-bg: #142437;
          --prob-card-border: rgba(
            255,255,255,0.10
          );

          --prob-icon-bg: rgba(
            255,158,126,0.12
          );

          --prob-icon-border: rgba(
            255,158,126,0.18
          );

          --prob-impact-bg: linear-gradient(
            145deg,
            #281e29 0%,
            #111e2d 100%
          );

          --prob-impact-border: rgba(
            255,150,120,0.15
          );

          --prob-visual-bg: rgba(
            6,15,24,0.65
          );

          --prob-visual-border: rgba(
            255,255,255,0.10
          );

          --prob-track-bg: rgba(
            255,255,255,0.12
          );

          --prob-alert-bg: rgba(
            255,153,120,0.09
          );

          --prob-alert-border: rgba(
            255,153,120,0.17
          );

          --prob-alert-text: #e6c2b5;

          --prob-transition-bg: rgba(
            65,133,170,0.08
          );

          --prob-transition-border: rgba(
            106,225,255,0.10
          );

          --prob-transition-accent: #70e7ff;

          --prob-shadow:
            0 20px 55px rgba(0,0,0,0.20);
        }

        /* ================================================
           3. SECCIÓN PRINCIPAL
           ================================================ */

        .ms-problematica {
          position: relative;

          width: 100%;

          padding: 110px 28px;

          background: transparent;

          color: var(--prob-title);
        }

        .ms-problematica-container {
          width: 100%;
          max-width: 1280px;
          margin: 0 auto;
        }

        /* ================================================
           4. ENCABEZADO
           ================================================ */

        .ms-problematica-heading {
          max-width: 900px;
          margin-bottom: 55px;
        }

        .ms-problematica-eyebrow {
          display: inline-block;

          margin-bottom: 17px;

          color: var(--prob-eyebrow);

          font-size: 13px;
          font-weight: 900;
          letter-spacing: 1.8px;
        }

        .mirrorsoul-public-page
        .ms-problematica-title {
          margin: 0;

          color: var(--prob-title) !important;

          font-size:
            clamp(2.25rem,3.2vw,3.7rem) !important;

          line-height: 1.1 !important;
          letter-spacing: -1.3px;

          font-weight: 900;
        }

        .mirrorsoul-public-page
        .ms-problematica-description {
          margin: 24px 0 0;

          max-width: 850px;

          color: var(--prob-text) !important;

          font-size:
            clamp(1.05rem,1.14vw,1.23rem) !important;

          line-height: 1.75 !important;

          font-weight: 500;
        }

        /* ================================================
           5. GRID DE PROBLEMAS
           ================================================ */

        .ms-problematica-grid {
          display: grid;

          grid-template-columns:
            repeat(3,minmax(0,1fr));

          gap: 20px;
        }

        /* ================================================
           6. TARJETAS
           ================================================ */

        .mirrorsoul-public-page
        .ms-problematica-card {
          min-width: 0;
          min-height: 230px;

          padding: 30px;

          border-radius: 22px;

          background: var(--prob-card-bg) !important;

          border: 1px solid var(--prob-card-border);

          box-shadow: var(--prob-shadow);

          color: var(--prob-title);

          transition:
            background 0.3s ease,
            color 0.3s ease,
            transform 0.2s ease;
        }

        .ms-problematica-card:hover {
          transform: translateY(-4px);
        }

        .ms-problematica-icon {
          display: flex;

          align-items: center;
          justify-content: center;

          width: 56px;
          height: 56px;

          margin-bottom: 20px;

          border-radius: 16px;

          background: var(--prob-icon-bg);
          border: 1px solid var(--prob-icon-border);

          font-size: 25px;
        }

        .mirrorsoul-public-page
        .ms-problematica-card-title {
          margin: 0;

          color: var(--prob-title) !important;

          font-size: 21px !important;
          font-weight: 900;

          line-height: 1.3 !important;
          letter-spacing: -0.2px;
        }

        .mirrorsoul-public-page
        .ms-problematica-card-text {
          margin: 13px 0 0;

          color: var(--prob-text) !important;

          font-size: 16px !important;
          line-height: 1.7 !important;

          font-weight: 500;
        }

        /* ================================================
           7. BLOQUE DE IMPACTO
           ================================================ */

        .ms-problematica-impact {
          position: relative;
          overflow: hidden;

          display: grid;

          grid-template-columns:
            minmax(0,1fr)
            minmax(0,0.95fr);

          align-items: center;

          gap: 45px;

          margin-top: 45px;
          padding: 43px;

          border-radius: 28px;

          background: var(--prob-impact-bg);

          border: 1px solid var(--prob-impact-border);

          box-shadow: var(--prob-shadow);
        }

        .ms-problematica-impact-glow {
          position: absolute;

          width: 300px;
          height: 300px;

          top: -140px;
          left: -100px;

          border-radius: 50%;

          background: rgba(
            255,110,90,0.08
          );

          filter: blur(85px);

          pointer-events: none;
        }

        .ms-problematica-impact-content {
          position: relative;
          z-index: 2;

          min-width: 0;
        }

        .ms-problematica-impact-eyebrow {
          display: block;

          margin-bottom: 15px;

          color: var(--prob-eyebrow);

          font-size: 13px;
          font-weight: 900;
          letter-spacing: 1.5px;
        }

        .mirrorsoul-public-page
        .ms-problematica-impact-title {
          margin: 0;

          color: var(--prob-title) !important;

          font-size:
            clamp(1.9rem,2.4vw,2.65rem) !important;

          line-height: 1.2 !important;
          letter-spacing: -0.8px;

          font-weight: 900;
        }

        .mirrorsoul-public-page
        .ms-problematica-impact-text {
          margin: 20px 0 0;

          color: var(--prob-text) !important;

          font-size: 17px !important;
          line-height: 1.8 !important;
        }

        /* ================================================
           8. PANEL VISUAL
           ================================================ */

        .ms-problematica-visual {
          position: relative;
          z-index: 2;

          min-width: 0;

          padding: 27px;

          border-radius: 20px;

          background: var(--prob-visual-bg);

          border: 1px solid var(--prob-visual-border);
        }

        .ms-problematica-visual-heading {
          display: flex;
          justify-content: space-between;
          align-items: center;

          gap: 10px;
          margin-bottom: 25px;

          color: var(--prob-title);

          font-size: 12px;
          font-weight: 900;
          letter-spacing: 1px;
        }

        .ms-problematica-visual-decoration {
          color: var(--prob-eyebrow);

          font-size: 16px;
        }

        .ms-problematica-visual-row {
          display: grid;

          grid-template-columns:
            145px minmax(0,1fr);

          gap: 12px;

          align-items: center;

          margin-bottom: 20px;
        }

        .ms-problematica-visual-label {
          color: var(--prob-muted);

          font-size: 13px;
          font-weight: 700;

          line-height: 1.45;
        }

        .ms-problematica-visual-line {
          width: 100%;
          height: 9px;

          overflow: hidden;

          border-radius: 999px;

          background: var(--prob-track-bg);
        }

        .ms-problematica-visual-progress {
          height: 100%;

          border-radius: 999px;

          background: linear-gradient(
            90deg,
            #e77f63,
            #f6b17d
          );
        }

        /* ================================================
           9. ALERTA
           ================================================ */

        .ms-problematica-alert {
          display: flex;
          align-items: flex-start;

          gap: 13px;

          margin-top: 27px;
          padding: 18px;

          border-radius: 16px;

          background: var(--prob-alert-bg);

          border: 1px solid var(--prob-alert-border);
        }

        .ms-problematica-alert-icon {
          display: flex;

          align-items: center;
          justify-content: center;

          flex-shrink: 0;

          width: 34px;
          height: 34px;

          border-radius: 10px;

          background: var(--prob-icon-bg);

          color: var(--prob-eyebrow);

          font-size: 17px;
          font-weight: 900;
        }

        .ms-problematica-alert-content {
          min-width: 0;
        }

        .ms-problematica-alert-title {
          display: block;

          margin-bottom: 6px;

          color: var(--prob-title);

          font-size: 14px;
          font-weight: 900;

          line-height: 1.45;
        }

        .ms-problematica-alert-text {
          display: block;

          color: var(--prob-alert-text);

          font-size: 13px;
          line-height: 1.65;

          font-weight: 500;
        }

        /* ================================================
           10. TRANSICIÓN HACIA MIRRORSOUL
           ================================================ */

        .ms-problematica-transition {
          display: flex;

          align-items: center;
          justify-content: center;

          gap: 22px;

          max-width: 850px;

          margin: 65px auto 0;
          padding: 25px;

          border-radius: 20px;

          background: var(--prob-transition-bg);

          border: 1px solid var(--prob-transition-border);
        }

        .ms-problematica-transition-brand {
          display: flex;

          align-items: center;
          justify-content: center;

          flex-shrink: 0;

          width: 100px;
          height: 82px;

          background: transparent;

          border: none;
          box-shadow: none;
        }

        .ms-problematica-transition-content {
          min-width: 0;
        }

        .ms-problematica-transition-label {
          display: block;

          margin-bottom: 9px;

          color: var(--prob-transition-accent);

          font-size: 13px;
          font-weight: 900;

          letter-spacing: 1.5px;
        }

        .mirrorsoul-public-page
        .ms-problematica-transition-title {
          margin: 0;

          color: var(--prob-title) !important;

          font-size: 24px !important;

          line-height: 1.3 !important;

          font-weight: 900;
          letter-spacing: -0.5px;
        }

        .mirrorsoul-public-page
        .ms-problematica-transition-text {
          margin: 11px 0 0;

          color: var(--prob-text) !important;

          font-size: 16px !important;
          line-height: 1.65 !important;
        }

        /* ================================================
           11. TABLET
           ================================================ */

        @media (max-width: 1100px) {
          .ms-problematica {
            padding: 85px 25px;
          }

          .ms-problematica-grid {
            grid-template-columns:
              repeat(2,minmax(0,1fr));
          }

          .ms-problematica-impact {
            gap: 25px;
            padding: 30px;
          }
        }

        /* ================================================
           12. PANTALLAS MEDIANAS
           ================================================ */

        @media (max-width: 850px) {
          .ms-problematica-impact {
            grid-template-columns: 1fr;
          }

          .ms-problematica-heading {
            margin-bottom: 40px;
          }

          .ms-problematica-visual {
            width: 100%;
          }
        }

        /* ================================================
           13. CELULARES
           ================================================ */

        @media (max-width: 600px) {
          .ms-problematica {
            padding: 65px 18px;
          }

          .ms-problematica-grid {
            grid-template-columns: 1fr;
            gap: 15px;
          }

          .mirrorsoul-public-page
          .ms-problematica-card {
            min-height: auto;
            padding: 26px;
          }

          .ms-problematica-impact {
            margin-top: 30px;

            padding: 24px 18px;

            border-radius: 21px;
            gap: 30px;
          }

          .ms-problematica-visual {
            padding: 18px;
          }

          .ms-problematica-visual-row {
            grid-template-columns: 1fr;
            gap: 7px;
            margin-bottom: 17px;
          }

          .ms-problematica-alert {
            padding: 14px;
          }

          .ms-problematica-transition {
            align-items: flex-start;

            margin-top: 45px;

            padding: 18px;
            gap: 12px;
          }

          .ms-problematica-transition-brand {
            width: 58px;
            height: 58px;
          }

          .ms-problematica-transition-brand > div {
            max-width: 58px;
            max-height: 58px;
          }

          .mirrorsoul-public-page
          .ms-problematica-transition-title {
            font-size: 18px !important;
          }

          .mirrorsoul-public-page
          .ms-problematica-title {
            font-size:
              clamp(2rem,7vw,2.7rem) !important;
          }
        }

        /* ================================================
           14. MOVIMIENTO REDUCIDO
           ================================================ */

        @media (prefers-reduced-motion: reduce) {
          .ms-problematica *,
          .ms-problematica *::before,
          .ms-problematica *::after {
            animation: none !important;
            transition: none !important;
          }
        }

      `}</style>
    </>
  );
}

export default ProblematicaSection;
