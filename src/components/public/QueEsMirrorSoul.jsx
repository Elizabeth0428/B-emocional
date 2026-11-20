
import React from "react";
import LogoMirrorSoul from "./LogoMirrorSoul";

// ============================================================
// MIRRORSOUL - ¿QUÉ ES?
// Compatible con modo claro y oscuro
// ============================================================

const beneficios = [
  {
    icono: "🧠",
    titulo: "Comprender mejor",
    texto:
      "Centraliza evaluaciones, resultados, seguimiento e información relevante para entender mejor lo que ocurre con cada persona.",
  },
  {
    icono: "🔄",
    titulo: "Dar continuidad",
    texto:
      "Evita que los procesos se pierdan. MirrorSoul conecta evaluación, seguimiento, canalización y atención profesional.",
  },
  {
    icono: "🤖",
    titulo: "Usar tecnología a favor",
    texto:
      "Integra automatización e inteligencia artificial como apoyo para analizar información y mejorar procesos.",
  },
  {
    icono: "📊",
    titulo: "Tomar mejores decisiones",
    texto:
      "Transforma información dispersa en datos organizados, reportes y resultados más fáciles de interpretar.",
  },
];

// ============================================================
// ENTORNOS DE LA PLATAFORMA
// ============================================================

const entornos = [
  {
    icono: "🏢",
    titulo: "Empresas y RH",
    texto:
      "Gestión del talento, selección, evaluación, seguimiento, bienestar y canalización dentro de la organización.",
    items: [
      "Gestión de empleados",
      "Selección de candidatos",
      "Pruebas psicométricas",
      "Evaluaciones",
      "NOM-035",
      "Seguimiento",
      "Canalización",
    ],
  },
  {
    icono: "🏥",
    titulo: "Clínicas",
    texto:
      "Gestión de pacientes, sesiones, historial, pruebas, reportes y seguimiento clínico.",
    items: [
      "Pacientes",
      "Sesiones",
      "Historial clínico",
      "Evaluaciones",
      "Reportes",
    ],
  },
  {
    icono: "🧠",
    titulo: "Profesionales",
    texto:
      "Herramientas para profesionales independientes que buscan organizar, evaluar y dar seguimiento a su práctica.",
    items: [
      "Pacientes",
      "Evaluaciones",
      "Seguimiento",
      "Reportes",
    ],
  },
  {
    icono: "🎓",
    titulo: "Educativo",
    texto:
      "Evaluación, acompañamiento y seguimiento dentro de instituciones educativas.",
    items: [
      "Evaluaciones",
      "Usuarios",
      "Seguimiento",
      "Reportes",
    ],
  },
];

// ============================================================
// COMPONENTE DE PASOS
// ============================================================

function Step({ numero, titulo, texto }) {
  return (
    <div className="ms-que-step">
      <div className="ms-que-step-number">
        {numero}
      </div>

      <div className="ms-que-step-content">
        <h3 className="ms-que-step-title">
          {titulo}
        </h3>

        <p className="ms-que-step-text">
          {texto}
        </p>
      </div>
    </div>
  );
}

// ============================================================
// COMPONENTE PRINCIPAL
// ============================================================

function QueEsMirrorSoul() {
  return (
    <>
      <section className="ms-que-section">
        <div className="ms-que-container">

          {/* ============================================== */}
          {/* BLOQUE PRINCIPAL */}
          {/* ============================================== */}

          <div className="ms-que-main-grid">

            {/* ============================================ */}
            {/* TARJETA PRINCIPAL */}
            {/* ============================================ */}

            <div className="ms-que-main-card">

              <div className="ms-que-brand-row">

                <div className="ms-que-logo">
                  <LogoMirrorSoul
                    width={86}
                    height={70}
                    padding={0}
                    background={false}
                  />
                </div>

                <span className="ms-que-eyebrow">
                  MIRRORSOUL PLATFORM
                </span>

              </div>

              <h2 className="ms-que-main-title">
                Mucho más que almacenar
                información.
              </h2>

              <p className="ms-que-main-description">
                MirrorSoul busca conectar cada
                etapa de un proceso: desde la
                identificación de una necesidad
                hasta su evaluación, análisis,
                seguimiento y atención.
              </p>

              {/* ========================================== */}
              {/* ETAPAS DEL PROCESO */}
              {/* ========================================== */}

              <div className="ms-que-steps">

                <Step
                  numero="01"
                  titulo="Detectar"
                  texto="Identificar señales, necesidades o áreas que requieren atención."
                />

                <Step
                  numero="02"
                  titulo="Evaluar"
                  texto="Aplicar herramientas y evaluaciones según cada contexto."
                />

                <Step
                  numero="03"
                  titulo="Analizar"
                  texto="Organizar resultados y convertirlos en información útil."
                />

                <Step
                  numero="04"
                  titulo="Dar seguimiento"
                  texto="Mantener continuidad y acompañamiento en cada caso."
                />

              </div>
            </div>

            {/* ============================================ */}
            {/* CUATRO TARJETAS DE BENEFICIOS */}
            {/* ============================================ */}

            <div className="ms-que-benefits-grid">
              {beneficios.map((item) => (
                <article
                  key={item.titulo}
                  className="ms-que-benefit-card"
                >

                  <div
                    className="ms-que-icon-box"
                    aria-hidden="true"
                  >
                    {item.icono}
                  </div>

                  <h3 className="ms-que-card-title">
                    {item.titulo}
                  </h3>

                  <p className="ms-que-card-text">
                    {item.texto}
                  </p>

                </article>
              ))}
            </div>

          </div>

          {/* ============================================== */}
          {/* ENTORNOS */}
          {/* ============================================== */}

          <div className="ms-que-environments">

            <span className="ms-que-section-eyebrow">
              UNA SOLA PLATAFORMA
            </span>

            <h2 className="ms-que-section-title">
              Diseñada para adaptarse a
              distintos entornos.
            </h2>

            <p className="ms-que-section-description">
              MirrorSoul integra diferentes
              herramientas dentro de una misma
              plataforma y adapta su
              funcionamiento según las
              necesidades de cada organización.
            </p>

            {/* ============================================ */}
            {/* TARJETAS DE ENTORNOS */}
            {/* ============================================ */}

            <div className="ms-que-environment-grid">

              {entornos.map((entorno) => (
                <article
                  key={entorno.titulo}
                  className="ms-que-environment-card"
                >

                  <div className="ms-que-environment-header">

                    <div
                      className="ms-que-environment-icon"
                      aria-hidden="true"
                    >
                      {entorno.icono}
                    </div>

                    <h3 className="ms-que-environment-title">
                      {entorno.titulo}
                    </h3>

                  </div>

                  <p className="ms-que-environment-text">
                    {entorno.texto}
                  </p>

                  {/* ====================================== */}
                  {/* ETIQUETAS DE SERVICIOS */}
                  {/* ====================================== */}

                  <div className="ms-que-tags">
                    {entorno.items.map((item) => (
                      <span
                        key={item}
                        className="ms-que-tag"
                      >
                        {item}
                      </span>
                    ))}
                  </div>

                </article>
              ))}

            </div>
          </div>

        </div>
      </section>

      {/* ================================================== */}
      {/* ESTILOS DEL COMPONENTE */}
      {/* ================================================== */}

      <style>{`

        /* ================================================
           VARIABLES - MODO CLARO
           ================================================ */

        :root,
        :root[data-ms-theme="claro"] {
          --que-bg: transparent;

          --que-card-bg: #ffffff;
          --que-main-bg:
            linear-gradient(
              145deg,
              #ffffff 0%,
              #f4f9ff 100%
            );

          --que-title: #142842;
          --que-text: #526782;
          --que-muted: #64748b;

          --que-border: #dce7f5;

          --que-accent: #1768ba;
          --que-accent-bg: #eaf4ff;
          --que-accent-border: #cfe4fa;

          --que-icon-bg: #eaf4ff;

          --que-tag-bg: #eef5ff;
          --que-tag-text: #315779;

          --que-shadow:
            0 18px 45px rgba(28, 63, 105, 0.09);
        }

        /* ================================================
           VARIABLES - MODO OSCURO
           ================================================ */

        :root[data-ms-theme="oscuro"] {
          --que-bg: transparent;

          --que-card-bg: #112030;
          --que-main-bg:
            linear-gradient(
              145deg,
              #12273b 0%,
              #0c1b2b 100%
            );

          --que-title: #ffffff;
          --que-text: #c0d0e4;
          --que-muted: #a9bed5;

          --que-border:
            rgba(255,255,255,0.09);

          --que-accent: #61eaff;
          --que-accent-bg:
            rgba(73,205,240,0.08);
          --que-accent-border:
            rgba(73,205,240,0.16);

          --que-icon-bg:
            rgba(100,210,240,0.07);

          --que-tag-bg:
            rgba(255,255,255,0.05);
          --que-tag-text: #c9d9eb;

          --que-shadow:
            0 18px 45px rgba(0,0,0,0.18);
        }

        /* ================================================
           SECCIÓN Y CONTENEDOR
           ================================================ */

        .ms-que-section {
          position: relative;
          width: 100%;

          padding: 100px 42px;

          background: var(--que-bg);
          color: var(--que-title);
        }

        .ms-que-container {
          width: 100%;
          max-width: 1600px;
          margin: 0 auto;
        }

        /* ================================================
           BLOQUE PRINCIPAL
           ================================================ */

        .ms-que-main-grid {
          display: grid;

          grid-template-columns:
            minmax(0,1.1fr)
            minmax(0,0.95fr);

          gap: 32px;
          align-items: stretch;
        }

        .ms-que-main-card {
          padding: 46px 40px;

          border-radius: 30px;

          background: var(--que-main-bg);
          border: 1px solid var(--que-border);

          color: var(--que-title);

          box-shadow: var(--que-shadow);

          min-width: 0;
        }

        /* ================================================
           LOGO
           ================================================ */

        .ms-que-brand-row {
          display: flex;
          align-items: center;
          flex-wrap: wrap;
          gap: 15px;

          margin-bottom: 25px;
        }

        .ms-que-logo {
          display: flex;
          align-items: center;
          justify-content: center;

          flex-shrink: 0;

          width: 86px;
          height: 70px;

          padding: 0;

          background: transparent;
          border: none;
          box-shadow: none;
        }

        .ms-que-eyebrow {
          display: inline-flex;
          align-items: center;

          min-height: 36px;
          padding: 8px 16px;

          border-radius: 10px;

          background: var(--que-accent-bg);
          border: 1px solid var(--que-accent-border);

          color: var(--que-accent);

          font-size: 13px;
          font-weight: 900;
          letter-spacing: 1.4px;
        }

        /* ================================================
           TÍTULO Y DESCRIPCIÓN PRINCIPAL
           ================================================ */

        .mirrorsoul-public-page
        .ms-que-main-title {
          margin: 0;

          color: var(--que-title) !important;

          font-size:
            clamp(2.2rem,3.1vw,3.6rem) !important;

          line-height: 1.08 !important;
          font-weight: 900;

          letter-spacing: -1.4px;
        }

        .mirrorsoul-public-page
        .ms-que-main-description {
          max-width: 850px;

          margin: 24px 0 34px;

          color: var(--que-text) !important;

          font-size:
            clamp(1.05rem,1.12vw,1.2rem) !important;

          line-height: 1.75 !important;
          font-weight: 500;
        }

        /* ================================================
           PASOS
           ================================================ */

        .ms-que-steps {
          display: grid;
          gap: 22px;
        }

        .ms-que-step {
          display: flex;
          align-items: flex-start;
          gap: 18px;
        }

        .ms-que-step-number {
          display: flex;
          align-items: center;
          justify-content: center;

          width: 56px;
          height: 56px;

          flex-shrink: 0;

          border-radius: 16px;

          background: var(--que-accent-bg);
          border: 1px solid var(--que-accent-border);

          color: var(--que-accent);

          font-size: 15px;
          font-weight: 900;
        }

        .ms-que-step-content {
          min-width: 0;
        }

        .mirrorsoul-public-page
        .ms-que-step-title {
          margin: 2px 0 5px;

          color: var(--que-title) !important;

          font-size: 20px !important;
          font-weight: 900;
          line-height: 1.3 !important;
        }

        .mirrorsoul-public-page
        .ms-que-step-text {
          margin: 0;

          color: var(--que-text) !important;

          font-size: 16px !important;
          line-height: 1.65 !important;
        }

        /* ================================================
           CUATRO TARJETAS DE BENEFICIOS
           ================================================ */

        .ms-que-benefits-grid {
          display: grid;
          grid-template-columns:
            repeat(2,minmax(0,1fr));

          gap: 22px;
        }

        .mirrorsoul-public-page
        .ms-que-benefit-card {
          min-width: 0;
          min-height: 245px;

          padding: 30px;

          border-radius: 24px;

          background: var(--que-card-bg) !important;
          border: 1px solid var(--que-border);

          color: var(--que-title);

          box-shadow: var(--que-shadow);

          transition:
            background 0.3s ease,
            color 0.3s ease,
            transform 0.2s ease;
        }

        .ms-que-benefit-card:hover {
          transform: translateY(-3px);
        }

        .ms-que-icon-box {
          display: flex;
          align-items: center;
          justify-content: center;

          width: 58px;
          height: 58px;

          border-radius: 16px;

          background: var(--que-icon-bg);

          font-size: 25px;
        }

        .mirrorsoul-public-page
        .ms-que-card-title {
          margin: 24px 0 12px;

          color: var(--que-title) !important;

          font-size: 22px !important;
          font-weight: 900;

          line-height: 1.3 !important;
        }

        .mirrorsoul-public-page
        .ms-que-card-text {
          margin: 0;

          color: var(--que-text) !important;

          font-size: 16px !important;
          line-height: 1.7 !important;
        }

        /* ================================================
           SEGUNDA SECCIÓN - ENTORNOS
           ================================================ */

        .ms-que-environments {
          margin-top: 105px;
        }

        .ms-que-section-eyebrow {
          display: block;

          margin-bottom: 15px;

          color: var(--que-accent);

          font-size: 13px;
          font-weight: 900;
          letter-spacing: 1.7px;
        }

        .mirrorsoul-public-page
        .ms-que-section-title {
          margin: 0;

          color: var(--que-title) !important;

          font-size:
            clamp(2.25rem,3vw,3.5rem) !important;

          line-height: 1.1 !important;

          font-weight: 900;
          letter-spacing: -1.4px;
        }

        .mirrorsoul-public-page
        .ms-que-section-description {
          max-width: 850px;

          margin: 19px 0 0;

          color: var(--que-text) !important;

          font-size:
            clamp(1.05rem,1.12vw,1.2rem) !important;

          line-height: 1.75 !important;
        }

        /* ================================================
           CUATRO TARJETAS DE ENTORNOS
           ================================================ */

        .ms-que-environment-grid {
          display: grid;

          grid-template-columns:
            repeat(4,minmax(0,1fr));

          gap: 20px;
          margin-top: 38px;
        }

        .mirrorsoul-public-page
        .ms-que-environment-card {
          display: flex;
          flex-direction: column;

          min-width: 0;
          min-height: 330px;

          padding: 30px;

          border-radius: 23px;

          background: var(--que-card-bg) !important;
          border: 1px solid var(--que-border);

          color: var(--que-title);

          box-shadow: var(--que-shadow);

          transition:
            background 0.3s ease,
            color 0.3s ease,
            transform 0.2s ease;
        }

        .ms-que-environment-card:hover {
          transform: translateY(-3px);
        }

        .ms-que-environment-header {
          display: flex;
          align-items: center;
          gap: 15px;
        }

        .ms-que-environment-icon {
          display: flex;
          align-items: center;
          justify-content: center;

          flex-shrink: 0;

          width: 55px;
          height: 55px;

          border-radius: 15px;

          background: var(--que-icon-bg);

          font-size: 24px;
        }

        .mirrorsoul-public-page
        .ms-que-environment-title {
          margin: 0;

          color: var(--que-title) !important;

          font-size: 21px !important;
          font-weight: 900;

          line-height: 1.3 !important;
        }

        .mirrorsoul-public-page
        .ms-que-environment-text {
          margin: 19px 0 0;

          color: var(--que-text) !important;

          font-size: 16px !important;
          line-height: 1.7 !important;
        }

        /* ================================================
           ETIQUETAS
           ================================================ */

        .ms-que-tags {
          display: flex;
          flex-wrap: wrap;

          gap: 8px;

          margin-top: auto;
          padding-top: 24px;
        }

        .ms-que-tag {
          display: inline-flex;
          align-items: center;

          padding: 7px 10px;

          border-radius: 8px;

          background: var(--que-tag-bg);
          border: 1px solid var(--que-border);

          color: var(--que-tag-text);

          font-size: 13px;
          font-weight: 700;

          line-height: 1.4;
        }

        /* ================================================
           TABLET
           ================================================ */

        @media (max-width: 1150px) {
          .ms-que-section {
            padding: 85px 28px;
          }

          .ms-que-main-grid {
            grid-template-columns: 1fr;
          }

          .ms-que-environment-grid {
            grid-template-columns:
              repeat(2,minmax(0,1fr));
          }

          .ms-que-benefit-card {
            min-height: 210px;
          }
        }

        /* ================================================
           CELULARES
           ================================================ */

        @media (max-width: 650px) {
          .ms-que-section {
            padding: 65px 18px;
          }

          .ms-que-main-grid {
            gap: 22px;
          }

          .ms-que-main-card {
            padding: 27px 22px;
            border-radius: 22px;
          }

          .ms-que-benefits-grid,
          .ms-que-environment-grid {
            grid-template-columns: 1fr;
            gap: 15px;
          }

          .mirrorsoul-public-page
          .ms-que-benefit-card,
          .mirrorsoul-public-page
          .ms-que-environment-card {
            min-height: auto;
            padding: 25px;
          }

          .ms-que-environments {
            margin-top: 75px;
          }

          .ms-que-step {
            gap: 13px;
          }

          .ms-que-step-number {
            width: 45px;
            height: 45px;
            border-radius: 12px;
          }

          .ms-que-environment-header {
            gap: 12px;
          }

          .ms-que-environment-icon {
            width: 48px;
            height: 48px;
          }

          .mirrorsoul-public-page
          .ms-que-main-title,
          .mirrorsoul-public-page
          .ms-que-section-title {
            font-size:
              clamp(2rem,7vw,2.7rem) !important;
          }
        }

        /* ================================================
           ACCESIBILIDAD
           ================================================ */

        @media (prefers-reduced-motion: reduce) {
          .ms-que-section *,
          .ms-que-section *::before,
          .ms-que-section *::after {
            animation: none !important;
            transition: none !important;
          }
        }

      `}</style>
    </>
  );
}

export default QueEsMirrorSoul;
