
import React from "react";
import LogoMirrorSoul from "./LogoMirrorSoul";

// ============================================================
// MIRRORSOUL - BENEFICIOS
// DISEÑO ADAPTABLE A MODO CLARO Y OSCURO
// ============================================================

// ============================================================
// 1. BENEFICIOS
// ============================================================

const beneficios = [
  {
    icono: "🧩",
    titulo: "Información centralizada",
    texto:
      "Reúne información, evaluaciones, seguimiento y procesos en un mismo entorno para evitar datos dispersos.",
  },
  {
    icono: "⏱️",
    titulo: "Menos trabajo manual",
    texto:
      "Automatiza tareas repetitivas y reduce procesos que normalmente dependen de hojas de cálculo, correos o seguimiento manual.",
  },
  {
    icono: "🔎",
    titulo: "Detección más oportuna",
    texto:
      "Facilita identificar señales, necesidades o situaciones que requieren atención antes de que se conviertan en problemas mayores.",
  },
  {
    icono: "🔄",
    titulo: "Seguimiento continuo",
    texto:
      "Permite mantener continuidad desde la evaluación inicial hasta la atención, canalización y seguimiento posterior.",
  },
  {
    icono: "📊",
    titulo: "Mejores decisiones",
    texto:
      "Convierte datos y resultados en información estructurada para facilitar la interpretación y la toma de decisiones.",
  },
  {
    icono: "🤖",
    titulo: "Tecnología e IA",
    texto:
      "Integra inteligencia artificial y automatización como herramientas de apoyo para analizar información y optimizar procesos.",
  },
  {
    icono: "🤝",
    titulo: "Procesos conectados",
    texto:
      "Ayuda a que RH, profesionales, administradores y usuarios trabajen dentro de un flujo común.",
  },
  {
    icono: "📈",
    titulo: "Escalabilidad",
    texto:
      "La plataforma puede adaptarse a distintos tamaños de organización, áreas de trabajo y número de usuarios.",
  },
];

// ============================================================
// 2. PUNTOS DE VALOR
// ============================================================

const puntosValor = [
  "Detectar necesidades",
  "Organizar información",
  "Dar seguimiento",
  "Facilitar decisiones",
];

// ============================================================
// 3. TARJETAS VISUALES
// ============================================================

const indicadores = [
  {
    icono: "📂",
    titulo: "Información",
    descripcion: "Centralizada",
  },
  {
    icono: "🔄",
    titulo: "Procesos",
    descripcion: "Conectados",
  },
  {
    icono: "📊",
    titulo: "Resultados",
    descripcion: "Más claros",
  },
  {
    icono: "⚡",
    titulo: "Respuesta",
    descripcion: "Más rápida",
  },
];

// ============================================================
// 4. COMPONENTE PRINCIPAL
// ============================================================

function BeneficiosSection() {
  return (
    <>
      <section className="ms-beneficios">
        <div className="ms-beneficios-container">

          {/* ============================================== */}
          {/* ENCABEZADO */}
          {/* ============================================== */}

          <div className="ms-beneficios-heading">
            <span className="ms-beneficios-eyebrow">
              BENEFICIOS
            </span>

            <h2 className="ms-beneficios-title">
              Más control, mejor seguimiento y
              decisiones con información más clara.
            </h2>

            <p className="ms-beneficios-description">
              MirrorSoul busca reducir la
              fragmentación de procesos y ayudar
              a que cada etapa tenga continuidad
              dentro de una misma plataforma.
            </p>
          </div>

          {/* ============================================== */}
          {/* OCHO TARJETAS DE BENEFICIOS */}
          {/* ============================================== */}

          <div className="ms-beneficios-grid">
            {beneficios.map((beneficio, index) => (
              <article
                key={beneficio.titulo}
                className="ms-beneficios-card"
              >
                <div className="ms-beneficios-card-header">
                  <div
                    className="ms-beneficios-icon"
                    aria-hidden="true"
                  >
                    {beneficio.icono}
                  </div>

                  <span className="ms-beneficios-number">
                    {String(index + 1).padStart(2, "0")}
                  </span>
                </div>

                <h3 className="ms-beneficios-card-title">
                  {beneficio.titulo}
                </h3>

                <p className="ms-beneficios-card-text">
                  {beneficio.texto}
                </p>
              </article>
            ))}
          </div>

          {/* ============================================== */}
          {/* BLOQUE DE VALOR */}
          {/* ============================================== */}

          <div className="ms-beneficios-value">

            {/* ============================================ */}
            {/* COLUMNA IZQUIERDA */}
            {/* ============================================ */}

            <div className="ms-beneficios-value-content">
              <span className="ms-beneficios-value-eyebrow">
                EL OBJETIVO
              </span>

              <h3 className="ms-beneficios-value-title">
                Que la tecnología ayude a actuar,
                no solo a almacenar información.
              </h3>

              <p className="ms-beneficios-value-text">
                MirrorSoul busca que cada dato
                tenga continuidad dentro de un
                proceso y que cada proceso pueda
                convertirse en una acción concreta.
              </p>

              <div className="ms-beneficios-points">
                {puntosValor.map((punto) => (
                  <div
                    key={punto}
                    className="ms-beneficios-point"
                  >
                    <span
                      className="ms-beneficios-check"
                      aria-hidden="true"
                    >
                      ✓
                    </span>

                    <span className="ms-beneficios-point-label">
                      {punto}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* ============================================ */}
            {/* COLUMNA DERECHA - PANEL VISUAL */}
            {/* ============================================ */}

            <div className="ms-beneficios-visual">

              {/* CABECERA DEL PANEL */}

              <div className="ms-beneficios-visual-top">
                <div className="ms-beneficios-visual-brand">
                  <LogoMirrorSoul
                    width={76}
                    height={62}
                    background={false}
                    padding={0}
                  />

                  <div>
                    <strong className="ms-beneficios-brand-title">
                      MirrorSoul
                    </strong>

                    <span className="ms-beneficios-brand-subtitle">
                      Plataforma inteligente
                    </span>
                  </div>
                </div>

                <span className="ms-beneficios-status">
                  <span
                    className="ms-beneficios-status-dot"
                    aria-hidden="true"
                  />
                  Sistema conectado
                </span>
              </div>

              {/* CUATRO TARJETAS */}

              <div className="ms-beneficios-visual-grid">
                {indicadores.map((item) => (
                  <div
                    key={item.titulo}
                    className="ms-beneficios-metric"
                  >
                    <span
                      className="ms-beneficios-metric-icon"
                      aria-hidden="true"
                    >
                      {item.icono}
                    </span>

                    <div className="ms-beneficios-metric-content">
                      <strong className="ms-beneficios-metric-title">
                        {item.titulo}
                      </strong>

                      <span className="ms-beneficios-metric-text">
                        {item.descripcion}
                      </span>
                    </div>
                  </div>
                ))}
              </div>

              {/* BARRA VISUAL DEL FLUJO */}

              <div className="ms-beneficios-visual-bottom">
                <div className="ms-beneficios-progress-header">
                  <span>Flujo integrado</span>
                  <span>Vista ilustrativa</span>
                </div>

                <div className="ms-beneficios-progress-track">
                  <div className="ms-beneficios-progress-bar" />
                </div>
              </div>

            </div>
          </div>

          {/* ============================================== */}
          {/* MENSAJE FINAL */}
          {/* ============================================== */}

          <div className="ms-beneficios-cta">
            <span className="ms-beneficios-cta-eyebrow">
              UNA PLATAFORMA, DIFERENTES NECESIDADES
            </span>

            <h3 className="ms-beneficios-cta-title">
              MirrorSoul puede adaptarse al entorno
              de cada organización.
            </h3>

            <p className="ms-beneficios-cta-text">
              Empresas, clínicas, profesionales e
              instituciones pueden utilizar las
              herramientas que mejor se adapten
              a su operación.
            </p>
          </div>

        </div>
      </section>

      {/* ================================================== */}
      {/* ESTILOS DEL COMPONENTE */}
      {/* ================================================== */}

      <style>{`

        /* ================================================
           5. VARIABLES - MODO CLARO
           ================================================ */

        :root,
        :root[data-ms-theme="claro"] {
          --ben-title: #142842;
          --ben-text: #50657d;
          --ben-muted: #62748a;

          --ben-accent: #176c91;
          --ben-accent-bg: #e6f8f2;

          --ben-card-bg: #ffffff;
          --ben-card-border: #dae6f3;

          --ben-icon-bg: #e8f7ff;
          --ben-icon-border: #d2e9f8;

          --ben-value-bg: linear-gradient(
            145deg,
            #f1fbf8 0%,
            #ffffff 100%
          );

          --ben-value-border: #d4eae2;

          --ben-check-bg: #dff7ed;
          --ben-check-text: #167a57;

          --ben-visual-bg: #ffffff;
          --ben-visual-border: #dce8f3;

          --ben-metric-bg: #f0f7ff;
          --ben-metric-border: #dfebf8;

          --ben-status-bg: #e5f8ed;
          --ben-status-text: #176744;

          --ben-track: #e4ecf4;

          --ben-cta-bg: linear-gradient(
            135deg,
            #e9f5ff 0%,
            #f5fbff 100%
          );

          --ben-cta-border: #d2e5f7;

          --ben-shadow:
            0 16px 45px rgba(25, 60, 100, 0.08);
        }

        /* ================================================
           6. VARIABLES - MODO OSCURO
           ================================================ */

        :root[data-ms-theme="oscuro"] {
          --ben-title: #ffffff;
          --ben-text: #c3d3e5;
          --ben-muted: #afc2d7;

          --ben-accent: #7ce8c1;
          --ben-accent-bg: rgba(124,232,193,0.10);

          --ben-card-bg: #142437;
          --ben-card-border: rgba(255,255,255,0.09);

          --ben-icon-bg: rgba(103,226,194,0.08);
          --ben-icon-border: rgba(103,226,194,0.15);

          --ben-value-bg: linear-gradient(
            145deg,
            #17312f 0%,
            #101e2e 100%
          );

          --ben-value-border: rgba(124,232,193,0.15);

          --ben-check-bg: rgba(124,232,193,0.11);
          --ben-check-text: #7ce8c1;

          --ben-visual-bg: rgba(6,18,30,0.70);
          --ben-visual-border: rgba(255,255,255,0.10);

          --ben-metric-bg: rgba(255,255,255,0.05);
          --ben-metric-border: rgba(255,255,255,0.08);

          --ben-status-bg: rgba(35,196,125,0.11);
          --ben-status-text: #8ff0b9;

          --ben-track: rgba(255,255,255,0.12);

          --ben-cta-bg: linear-gradient(
            135deg,
            #142d40 0%,
            #101f30 100%
          );

          --ben-cta-border: rgba(124,232,193,0.12);

          --ben-shadow:
            0 18px 50px rgba(0,0,0,0.20);
        }

        /* ================================================
           7. SECCIÓN
           ================================================ */

        .ms-beneficios {
          position: relative;
          width: 100%;

          padding: 110px 28px;

          background: transparent;
          color: var(--ben-title);
        }

        .ms-beneficios-container {
          width: 100%;
          max-width: 1280px;
          margin: 0 auto;
        }

        /* ================================================
           8. ENCABEZADO
           ================================================ */

        .ms-beneficios-heading {
          max-width: 830px;
          margin-bottom: 55px;
        }

        .ms-beneficios-eyebrow {
          display: inline-block;

          margin-bottom: 15px;

          color: var(--ben-accent);

          font-size: 13px;
          font-weight: 900;
          letter-spacing: 1.8px;
        }

        .mirrorsoul-public-page
        .ms-beneficios-title {
          margin: 0;

          color: var(--ben-title) !important;

          font-size:
            clamp(2.2rem,3vw,3.5rem) !important;

          line-height: 1.1 !important;
          letter-spacing: -1.3px;
          font-weight: 900;
        }

        .mirrorsoul-public-page
        .ms-beneficios-description {
          margin: 24px 0 0;

          color: var(--ben-text) !important;

          font-size:
            clamp(1.05rem,1.13vw,1.2rem) !important;

          line-height: 1.75 !important;
          font-weight: 500;
        }

        /* ================================================
           9. GRID DE BENEFICIOS
           ================================================ */

        .ms-beneficios-grid {
          display: grid;

          grid-template-columns:
            repeat(4,minmax(0,1fr));

          gap: 17px;
        }

        /* ================================================
           10. TARJETAS DE BENEFICIOS
           ================================================ */

        .mirrorsoul-public-page
        .ms-beneficios-card {
          min-width: 0;
          min-height: 240px;

          padding: 26px;

          border-radius: 21px;

          background: var(--ben-card-bg) !important;

          border: 1px solid var(--ben-card-border);

          color: var(--ben-title);

          box-shadow: var(--ben-shadow);

          transition:
            background 0.3s ease,
            color 0.3s ease,
            border-color 0.3s ease,
            transform 0.2s ease;
        }

        .ms-beneficios-card:hover {
          transform: translateY(-4px);
        }

        .ms-beneficios-card-header {
          display: flex;
          align-items: center;
          justify-content: space-between;

          gap: 12px;
          margin-bottom: 22px;
        }

        .ms-beneficios-icon {
          display: flex;
          align-items: center;
          justify-content: center;

          width: 56px;
          height: 56px;

          border-radius: 16px;

          background: var(--ben-icon-bg);
          border: 1px solid var(--ben-icon-border);

          font-size: 25px;
        }

        .ms-beneficios-number {
          color: var(--ben-muted);

          font-size: 13px;
          font-weight: 900;
          letter-spacing: 1px;
        }

        .mirrorsoul-public-page
        .ms-beneficios-card-title {
          margin: 0;

          color: var(--ben-title) !important;

          font-size: 21px !important;
          line-height: 1.35 !important;
          font-weight: 900;
        }

        .mirrorsoul-public-page
        .ms-beneficios-card-text {
          margin: 14px 0 0;

          color: var(--ben-text) !important;

          font-size: 16px !important;
          line-height: 1.7 !important;
          font-weight: 500;
        }

        /* ================================================
           11. BLOQUE DE VALOR
           ================================================ */

        .ms-beneficios-value {
          display: grid;

          grid-template-columns:
            minmax(0,1fr)
            minmax(0,0.95fr);

          align-items: center;
          gap: 45px;

          margin-top: 45px;
          padding: 42px;

          border-radius: 28px;

          background: var(--ben-value-bg);
          border: 1px solid var(--ben-value-border);

          box-shadow: var(--ben-shadow);

          transition:
            background 0.3s ease,
            border-color 0.3s ease;
        }

        .ms-beneficios-value-content {
          min-width: 0;
        }

        .ms-beneficios-value-eyebrow {
          display: block;

          margin-bottom: 15px;

          color: var(--ben-accent);

          font-size: 13px;
          font-weight: 900;
          letter-spacing: 1.5px;
        }

        .mirrorsoul-public-page
        .ms-beneficios-value-title {
          margin: 0;

          color: var(--ben-title) !important;

          font-size:
            clamp(1.9rem,2.5vw,2.8rem) !important;

          line-height: 1.2 !important;
          font-weight: 900;
          letter-spacing: -0.8px;
        }

        .mirrorsoul-public-page
        .ms-beneficios-value-text {
          margin: 20px 0 0;

          color: var(--ben-text) !important;

          font-size: 17px !important;
          line-height: 1.75 !important;
        }

        /* ================================================
           12. PUNTOS DE VALOR
           ================================================ */

        .ms-beneficios-points {
          display: grid;
          grid-template-columns:
            repeat(2,minmax(0,1fr));

          gap: 16px 18px;
          margin-top: 30px;
        }

        .ms-beneficios-point {
          display: flex;
          align-items: center;
          gap: 10px;
          min-width: 0;
        }

        .ms-beneficios-check {
          display: flex;
          align-items: center;
          justify-content: center;

          flex-shrink: 0;

          width: 31px;
          height: 31px;

          border-radius: 10px;

          background: var(--ben-check-bg);
          color: var(--ben-check-text);

          font-size: 16px;
          font-weight: 900;
        }

        .ms-beneficios-point-label {
          color: var(--ben-title);

          font-size: 15px;
          font-weight: 800;
          line-height: 1.5;
        }

        /* ================================================
           13. PANEL VISUAL
           ================================================ */

        .ms-beneficios-visual {
          min-width: 0;

          padding: 24px;

          border-radius: 23px;

          background: var(--ben-visual-bg);
          border: 1px solid var(--ben-visual-border);

          box-shadow: var(--ben-shadow);

          transition:
            background 0.3s ease,
            border-color 0.3s ease;
        }

        /* ================================================
           14. CABECERA VISUAL
           ================================================ */

        .ms-beneficios-visual-top {
          display: flex;
          align-items: center;
          justify-content: space-between;
          flex-wrap: wrap;

          gap: 14px;
          margin-bottom: 25px;
        }

        .ms-beneficios-visual-brand {
          display: flex;
          align-items: center;
          gap: 12px;
        }

        .ms-beneficios-brand-title {
          display: block;

          color: var(--ben-title);

          font-size: 16px;
          font-weight: 900;
        }

        .ms-beneficios-brand-subtitle {
          display: block;

          margin-top: 4px;

          color: var(--ben-muted);

          font-size: 11px;
          font-weight: 600;
        }

        .ms-beneficios-status {
          display: inline-flex;
          align-items: center;

          gap: 7px;

          padding: 8px 11px;

          border-radius: 999px;

          background: var(--ben-status-bg);
          color: var(--ben-status-text);

          font-size: 11px;
          font-weight: 800;
          white-space: nowrap;
        }

        .ms-beneficios-status-dot {
          width: 8px;
          height: 8px;

          border-radius: 50%;

          background: #25c87b;
        }

        /* ================================================
           15. CUATRO TARJETAS DEL PANEL
           ================================================ */

        .ms-beneficios-visual-grid {
          display: grid;

          grid-template-columns:
            repeat(2,minmax(0,1fr));

          gap: 12px;
        }

        .ms-beneficios-metric {
          display: flex;
          align-items: center;

          gap: 12px;
          min-width: 0;

          padding: 16px;

          border-radius: 15px;

          background: var(--ben-metric-bg);
          border: 1px solid var(--ben-metric-border);
        }

        .ms-beneficios-metric-icon {
          display: flex;
          align-items: center;
          justify-content: center;

          flex-shrink: 0;

          width: 40px;
          height: 40px;

          border-radius: 12px;

          background: var(--ben-icon-bg);

          font-size: 20px;
        }

        .ms-beneficios-metric-content {
          min-width: 0;
        }

        .ms-beneficios-metric-title {
          display: block;

          color: var(--ben-title);

          font-size: 14px;
          font-weight: 900;
          line-height: 1.4;
        }

        .ms-beneficios-metric-text {
          display: block;

          margin-top: 4px;

          color: var(--ben-muted);

          font-size: 12px;
          line-height: 1.45;
        }

        /* ================================================
           16. BARRA DE FLUJO
           ================================================ */

        .ms-beneficios-visual-bottom {
          margin-top: 22px;
          padding-top: 20px;

          border-top: 1px solid var(--ben-visual-border);
        }

        .ms-beneficios-progress-header {
          display: flex;
          align-items: center;
          justify-content: space-between;

          gap: 12px;
          margin-bottom: 12px;

          color: var(--ben-text);

          font-size: 12px;
          font-weight: 800;
        }

        .ms-beneficios-progress-track {
          width: 100%;
          height: 10px;

          border-radius: 999px;
          overflow: hidden;

          background: var(--ben-track);
        }

        .ms-beneficios-progress-bar {
          width: 100%;
          height: 100%;

          border-radius: 999px;

          background: linear-gradient(
            90deg,
            #28c49d,
            #45d4eb,
            #6d8aff
          );
        }

        /* ================================================
           17. BLOQUE FINAL
           ================================================ */

        .ms-beneficios-cta {
          max-width: 100%;

          margin-top: 45px;
          padding: 45px;

          border-radius: 26px;

          background: var(--ben-cta-bg);
          border: 1px solid var(--ben-cta-border);

          text-align: center;

          box-shadow: var(--ben-shadow);
        }

        .ms-beneficios-cta-eyebrow {
          display: block;

          margin-bottom: 15px;

          color: var(--ben-accent);

          font-size: 12px;
          font-weight: 900;
          letter-spacing: 1.5px;
        }

        .mirrorsoul-public-page
        .ms-beneficios-cta-title {
          max-width: 850px;
          margin: 0 auto;

          color: var(--ben-title) !important;

          font-size:
            clamp(1.9rem,2.4vw,2.8rem) !important;

          line-height: 1.2 !important;
          font-weight: 900;
        }

        .mirrorsoul-public-page
        .ms-beneficios-cta-text {
          max-width: 760px;

          margin: 20px auto 0;

          color: var(--ben-text) !important;

          font-size: 17px !important;
          line-height: 1.75 !important;
        }

        /* ================================================
           18. TABLET
           ================================================ */

        @media (max-width: 1100px) {
          .ms-beneficios {
            padding: 85px 25px;
          }

          .ms-beneficios-grid {
            grid-template-columns:
              repeat(2,minmax(0,1fr));
          }

          .ms-beneficios-value {
            gap: 25px;
            padding: 30px;
          }
        }

        /* ================================================
           19. PANTALLAS MEDIANAS
           ================================================ */

        @media (max-width: 850px) {
          .ms-beneficios-value {
            grid-template-columns: 1fr;
          }

          .ms-beneficios-visual {
            width: 100%;
          }
        }

        /* ================================================
           20. CELULARES
           ================================================ */

        @media (max-width: 600px) {
          .ms-beneficios {
            padding: 65px 18px;
          }

          .ms-beneficios-heading {
            margin-bottom: 40px;
          }

          .ms-beneficios-grid {
            grid-template-columns: 1fr;
            gap: 15px;
          }

          .mirrorsoul-public-page
          .ms-beneficios-card {
            min-height: auto;
            padding: 25px;
          }

          .ms-beneficios-value {
            margin-top: 30px;
            padding: 25px 18px;

            border-radius: 21px;
            gap: 30px;
          }

          .ms-beneficios-points {
            grid-template-columns: 1fr;
            gap: 12px;
          }

          .ms-beneficios-visual {
            padding: 17px;
          }

          .ms-beneficios-visual-grid {
            grid-template-columns: 1fr;
          }

          .ms-beneficios-metric {
            padding: 12px;
          }

          .ms-beneficios-cta {
            margin-top: 30px;
            padding: 30px 20px;
          }

          .mirrorsoul-public-page
          .ms-beneficios-title {
            font-size:
              clamp(2rem,7vw,2.7rem) !important;
          }
        }

        /* ================================================
           21. MOVIMIENTO REDUCIDO
           ================================================ */

        @media (prefers-reduced-motion: reduce) {
          .ms-beneficios *,
          .ms-beneficios *::before,
          .ms-beneficios *::after {
            animation: none !important;
            transition: none !important;
          }
        }

      `}</style>
    </>
  );
}

export default BeneficiosSection;
