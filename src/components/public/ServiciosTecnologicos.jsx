
import React from "react";
import { useNavigate } from "react-router-dom";
import LogoMirrorSoul from "./LogoMirrorSoul";

// ============================================================
// MIRRORSOUL - SERVICIOS TECNOLÓGICOS
// DISEÑO MODO CLARO Y OSCURO
// ============================================================

// ============================================================
// 1. SERVICIOS
// ============================================================

const servicios = [
  {
    icono: "💻",
    titulo: "Venta de equipo de cómputo",
    texto:
      "Equipos de escritorio, laptops, estaciones de trabajo y soluciones según las necesidades de cada empresa.",
    detalles: [
      "Laptops",
      "PC de escritorio",
      "Estaciones de trabajo",
      "Periféricos",
    ],
  },
  {
    icono: "🧾",
    titulo: "Punto de venta",
    texto:
      "Implementación de sistemas y licencias para punto de venta, configuración e integración para comercios y empresas.",
    detalles: [
      "Licencias",
      "Configuración",
      "Instalación",
      "Soporte",
    ],
  },
  {
    icono: "📹",
    titulo: "Videovigilancia",
    texto:
      "Instalación y configuración de cámaras de seguridad para oficinas, comercios y espacios empresariales.",
    detalles: [
      "Cámaras",
      "DVR / NVR",
      "Monitoreo",
      "Configuración",
    ],
  },
  {
    icono: "🌐",
    titulo: "Redes y conectividad",
    texto:
      "Diseño, instalación y configuración de infraestructura de red para mejorar la conectividad de la organización.",
    detalles: [
      "Cableado",
      "Switches",
      "WiFi",
      "Configuración",
    ],
  },
  {
    icono: "☎️",
    titulo: "Telefonía y comunicaciones",
    texto:
      "Soluciones de telefonía IP y comunicaciones empresariales para mejorar la operación y conectividad interna.",
    detalles: [
      "Telefonía IP",
      "Conmutadores",
      "Extensiones",
      "Configuración SIP",
    ],
  },
  {
    icono: "🛠️",
    titulo: "Soporte técnico",
    texto:
      "Atención y solución de incidencias de hardware, software, redes y sistemas dentro de la organización.",
    detalles: [
      "Diagnóstico",
      "Soporte",
      "Configuración",
      "Resolución de fallas",
    ],
  },
  {
    icono: "🔧",
    titulo: "Mantenimiento",
    texto:
      "Mantenimiento preventivo y correctivo para equipos de cómputo, infraestructura y sistemas tecnológicos.",
    detalles: [
      "Preventivo",
      "Correctivo",
      "Optimización",
      "Revisión",
    ],
  },
  {
    icono: "⚙️",
    titulo: "Implementación tecnológica",
    texto:
      "Integración y configuración de soluciones completas según las necesidades operativas de cada empresa.",
    detalles: [
      "Implementación",
      "Integración",
      "Configuración",
      "Acompañamiento",
    ],
  },
];

// ============================================================
// 2. VENTAJAS
// ============================================================

const ventajas = [
  "Atención personalizada",
  "Soluciones a la medida",
  "Implementación y soporte",
  "Acompañamiento técnico",
];

// ============================================================
// 3. ÁREAS VISUALES
// ============================================================

const areas = [
  {
    icono: "💻",
    titulo: "Equipos",
  },
  {
    icono: "📹",
    titulo: "Seguridad",
  },
  {
    icono: "🌐",
    titulo: "Redes",
  },
  {
    icono: "🛠️",
    titulo: "Soporte",
  },
];

// ============================================================
// 4. COMPONENTE PRINCIPAL
// ============================================================

function ServiciosTecnologicos() {
  const navigate = useNavigate();

  return (
    <>
      <section className="ms-servicios">

        <div className="ms-servicios-container">

          {/* ============================================== */}
          {/* ENCABEZADO */}
          {/* ============================================== */}

          <div className="ms-servicios-heading">

            <span className="ms-servicios-eyebrow">
              OTROS SERVICIOS
            </span>

            <h2 className="ms-servicios-title">
              Tecnología para tu empresa,
              más allá de MirrorSoul.
            </h2>

            <p className="ms-servicios-description">
              Además de nuestra plataforma,
              ofrecemos soluciones tecnológicas
              para ayudar a empresas y negocios
              a mejorar su infraestructura,
              operación y soporte.
            </p>

          </div>

          {/* ============================================== */}
          {/* BLOQUE PRINCIPAL */}
          {/* ============================================== */}

          <div className="ms-servicios-intro">

            {/* ============================================ */}
            {/* INFORMACIÓN */}
            {/* ============================================ */}

            <div className="ms-servicios-intro-content">

              <span className="ms-servicios-intro-eyebrow">
                SOLUCIONES EMPRESARIALES
              </span>

              <h3 className="ms-servicios-intro-title">
                Un solo proveedor para diferentes
                necesidades tecnológicas.
              </h3>

              <p className="ms-servicios-intro-text">
                Podemos acompañar a tu organización
                desde la adquisición de equipo hasta
                la instalación, configuración,
                mantenimiento y soporte de la
                infraestructura tecnológica.
              </p>

              {/* ========================================== */}
              {/* VENTAJAS */}
              {/* ========================================== */}

              <div className="ms-servicios-points">

                {ventajas.map((ventaja) => (
                  <div
                    key={ventaja}
                    className="ms-servicios-point"
                  >
                    <span
                      className="ms-servicios-check"
                      aria-hidden="true"
                    >
                      ✓
                    </span>

                    <span>
                      {ventaja}
                    </span>
                  </div>
                ))}

              </div>

            </div>

            {/* ============================================ */}
            {/* PANEL VISUAL */}
            {/* ============================================ */}

            <div className="ms-servicios-visual">

              <div className="ms-servicios-visual-center">

                <div className="ms-servicios-visual-logo">
                  <LogoMirrorSoul
                    width={112}
                    height={78}
                    background={false}
                    padding={0}
                  />
                </div>

                <strong className="ms-servicios-visual-title">
                  Soluciones
                </strong>

                <span className="ms-servicios-visual-text">
                  Tecnología empresarial
                </span>

              </div>

              {/* ========================================== */}
              {/* CUATRO ÁREAS */}
              {/* ========================================== */}

              <div className="ms-servicios-visual-grid">

                {areas.map((area) => (
                  <div
                    key={area.titulo}
                    className="ms-servicios-visual-item"
                  >
                    <span
                      className="ms-servicios-visual-icon"
                      aria-hidden="true"
                    >
                      {area.icono}
                    </span>

                    <span className="ms-servicios-visual-item-name">
                      {area.titulo}
                    </span>
                  </div>
                ))}

              </div>

            </div>

          </div>

          {/* ============================================== */}
          {/* OCHO TARJETAS DE SERVICIOS */}
          {/* ============================================== */}

          <div className="ms-servicios-grid">

            {servicios.map((servicio, index) => (

              <article
                key={servicio.titulo}
                className="ms-servicios-card"
              >

                {/* ======================================== */}
                {/* ICONO Y NÚMERO */}
                {/* ======================================== */}

                <div className="ms-servicios-card-top">

                  <div
                    className="ms-servicios-icon-box"
                    aria-hidden="true"
                  >
                    {servicio.icono}
                  </div>

                  <span className="ms-servicios-number">
                    {String(index + 1).padStart(
                      2,
                      "0"
                    )}
                  </span>

                </div>

                {/* ======================================== */}
                {/* TÍTULO */}
                {/* ======================================== */}

                <h3 className="ms-servicios-card-title">
                  {servicio.titulo}
                </h3>

                {/* ======================================== */}
                {/* DESCRIPCIÓN */}
                {/* ======================================== */}

                <p className="ms-servicios-card-text">
                  {servicio.texto}
                </p>

                {/* ======================================== */}
                {/* ETIQUETAS */}
                {/* ======================================== */}

                <div className="ms-servicios-tags">

                  {servicio.detalles.map((detalle) => (
                    <span
                      key={detalle}
                      className="ms-servicios-tag"
                    >
                      {detalle}
                    </span>
                  ))}

                </div>

              </article>
            ))}

          </div>

          {/* ============================================== */}
          {/* SOLUCIONES PERSONALIZADAS */}
          {/* ============================================== */}

          <div className="ms-servicios-custom">

            <div className="ms-servicios-custom-content">

              <span className="ms-servicios-custom-eyebrow">
                SOLUCIONES PERSONALIZADAS
              </span>

              <h3 className="ms-servicios-custom-title">
                ¿Tu empresa necesita algo diferente?
              </h3>

              <p className="ms-servicios-custom-text">
                Podemos analizar tus necesidades
                y diseñar una solución que combine
                equipamiento, infraestructura,
                software, instalación y soporte.
              </p>

            </div>

            {/* ============================================ */}
            {/* BOTÓN DE CONTACTO */}
            {/* ============================================ */}

            <button
              type="button"
              className="ms-servicios-contact-button"
              onClick={() => navigate("/contacto")}
            >
              Solicitar cotización

              <span aria-hidden="true">
                →
              </span>
            </button>

          </div>

          {/* ============================================== */}
          {/* ACLARACIÓN DE CONTRATACIÓN */}
          {/* ============================================== */}

          <div className="ms-servicios-note">

            <span
              className="ms-servicios-note-icon"
              aria-hidden="true"
            >
              i
            </span>

            <p className="ms-servicios-note-text">
              Estos servicios tecnológicos son
              adicionales a los planes de
              MirrorSoul y pueden contratarse
              de forma independiente o como
              parte de una solución empresarial
              personalizada.
            </p>

          </div>

        </div>

      </section>

      {/* ================================================== */}
      {/* ESTILOS DEL COMPONENTE */}
      {/* ================================================== */}

      <style>{`

        /* ================================================
           5. VARIABLES MODO CLARO
           ================================================ */

        :root,
        :root[data-ms-theme="claro"] {
          --srv-title: #142842;
          --srv-text: #526782;
          --srv-muted: #60738b;

          --srv-accent: #9a5a14;
          --srv-accent-bg: #fff4df;

          --srv-card-bg: #ffffff;
          --srv-card-border: #dce7f5;

          --srv-intro-bg: linear-gradient(
            145deg,
            #fffaf1 0%,
            #ffffff 100%
          );

          --srv-intro-border: #f0e3cf;

          --srv-icon-bg: #fff4df;
          --srv-icon-border: #f2e3c8;

          --srv-check-bg: #e7f6ed;
          --srv-check-color: #17734e;

          --srv-visual-bg: #ffffff;
          --srv-visual-border: #e7dfd4;

          --srv-center-bg: linear-gradient(
            145deg,
            #fff0d8,
            #eef5ff
          );

          --srv-center-border: #ecdcbc;

          --srv-item-bg: #f4f8ff;
          --srv-item-border: #dfebf8;

          --srv-tag-bg: #fff6e8;
          --srv-tag-border: #efe0c9;
          --srv-tag-text: #795527;

          --srv-custom-bg: linear-gradient(
            135deg,
            #fff4df,
            #f7fbff
          );

          --srv-custom-border: #ecdcc6;

          --srv-note-bg: #edf5ff;
          --srv-note-border: #d6e6f8;

          --srv-shadow:
            0 18px 48px rgba(31, 63, 103, 0.09);
        }

        /* ================================================
           6. VARIABLES MODO OSCURO
           ================================================ */

        :root[data-ms-theme="oscuro"] {
          --srv-title: #ffffff;
          --srv-text: #cad6e6;
          --srv-muted: #b8c9db;

          --srv-accent: #f4bd72;
          --srv-accent-bg: rgba(244,189,114,0.09);

          --srv-card-bg: #152437;
          --srv-card-border: rgba(255,255,255,0.10);

          --srv-intro-bg: linear-gradient(
            145deg,
            #27231f 0%,
            #101e30 100%
          );

          --srv-intro-border:
            rgba(244,189,114,0.16);

          --srv-icon-bg:
            rgba(244,189,114,0.09);

          --srv-icon-border:
            rgba(244,189,114,0.17);

          --srv-check-bg:
            rgba(102,225,171,0.10);

          --srv-check-color: #83f0c0;

          --srv-visual-bg:
            rgba(5,15,27,0.58);

          --srv-visual-border:
            rgba(255,255,255,0.10);

          --srv-center-bg: linear-gradient(
            145deg,
            rgba(244,189,114,0.10),
            rgba(97,150,255,0.09)
          );

          --srv-center-border:
            rgba(244,189,114,0.17);

          --srv-item-bg:
            rgba(255,255,255,0.055);

          --srv-item-border:
            rgba(255,255,255,0.09);

          --srv-tag-bg:
            rgba(244,189,114,0.07);

          --srv-tag-border:
            rgba(244,189,114,0.13);

          --srv-tag-text: #e8d4b6;

          --srv-custom-bg: linear-gradient(
            135deg,
            #302820,
            #122336
          );

          --srv-custom-border:
            rgba(244,189,114,0.14);

          --srv-note-bg:
            rgba(97,161,255,0.07);

          --srv-note-border:
            rgba(116,175,255,0.12);

          --srv-shadow:
            0 18px 48px rgba(0,0,0,0.20);
        }

        /* ================================================
           7. SECCIÓN PRINCIPAL
           ================================================ */

        .ms-servicios {
          position: relative;
          width: 100%;
          padding: 110px 28px;

          background: transparent;
          color: var(--srv-title);
        }

        .ms-servicios-container {
          width: 100%;
          max-width: 1280px;
          margin: 0 auto;
        }

        /* ================================================
           8. ENCABEZADO
           ================================================ */

        .ms-servicios-heading {
          max-width: 850px;
          margin-bottom: 55px;
        }

        .ms-servicios-eyebrow {
          display: inline-block;
          margin-bottom: 15px;

          color: var(--srv-accent);

          font-size: 13px;
          font-weight: 900;
          letter-spacing: 1.8px;
        }

        .mirrorsoul-public-page
        .ms-servicios-title {
          margin: 0;

          color: var(--srv-title) !important;

          font-size:
            clamp(2.25rem,3vw,3.5rem) !important;

          line-height: 1.1 !important;
          letter-spacing: -1.3px;
          font-weight: 900;
        }

        .mirrorsoul-public-page
        .ms-servicios-description {
          margin: 24px 0 0;
          max-width: 760px;

          color: var(--srv-text) !important;

          font-size:
            clamp(1.05rem,1.13vw,1.22rem) !important;

          line-height: 1.75 !important;
          font-weight: 500;
        }

        /* ================================================
           9. BLOQUE PRINCIPAL
           ================================================ */

        .ms-servicios-intro {
          display: grid;

          grid-template-columns:
            minmax(0,1fr)
            minmax(0,0.85fr);

          gap: 50px;
          align-items: center;

          padding: 38px;
          margin-bottom: 35px;

          border-radius: 27px;

          background: var(--srv-intro-bg);
          border: 1px solid var(--srv-intro-border);

          box-shadow: var(--srv-shadow);

          transition:
            background 0.3s ease,
            border-color 0.3s ease;
        }

        .ms-servicios-intro-content {
          min-width: 0;
        }

        .ms-servicios-intro-eyebrow {
          display: block;
          margin-bottom: 12px;

          color: var(--srv-accent);

          font-size: 13px;
          font-weight: 900;
          letter-spacing: 1.5px;
        }

        .mirrorsoul-public-page
        .ms-servicios-intro-title {
          margin: 0;

          color: var(--srv-title) !important;

          font-size:
            clamp(1.9rem,2.4vw,2.8rem) !important;

          line-height: 1.2 !important;
          font-weight: 900;
          letter-spacing: -0.8px;
        }

        .mirrorsoul-public-page
        .ms-servicios-intro-text {
          margin: 20px 0 0;

          color: var(--srv-text) !important;

          font-size: 17px !important;
          line-height: 1.75 !important;
        }

        /* ================================================
           10. VENTAJAS
           ================================================ */

        .ms-servicios-points {
          display: grid;
          grid-template-columns:
            repeat(2,minmax(0,1fr));

          gap: 13px 18px;
          margin-top: 28px;
        }

        .ms-servicios-point {
          display: flex;
          align-items: center;

          gap: 10px;

          min-width: 0;

          color: var(--srv-title);

          font-size: 15px;
          font-weight: 700;
          line-height: 1.5;
        }

        .ms-servicios-check {
          display: flex;
          align-items: center;
          justify-content: center;

          flex-shrink: 0;

          width: 31px;
          height: 31px;

          border-radius: 10px;

          background: var(--srv-check-bg);
          color: var(--srv-check-color);

          font-size: 16px;
          font-weight: 900;
        }

        /* ================================================
           11. PANEL VISUAL
           ================================================ */

        .ms-servicios-visual {
          min-width: 0;
          padding: 27px;

          border-radius: 23px;

          background: var(--srv-visual-bg);
          border: 1px solid var(--srv-visual-border);

          box-shadow: var(--srv-shadow);
        }

        .ms-servicios-visual-center {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;

          min-height: 195px;

          padding: 20px;

          margin-bottom: 22px;

          border-radius: 20px;

          background: var(--srv-center-bg);
          border: 1px solid var(--srv-center-border);
        }

        .ms-servicios-visual-logo {
          display: flex;
          align-items: center;
          justify-content: center;

          width: 112px;
          height: 78px;

          background: transparent;
          border: none;
          box-shadow: none;
        }

        .ms-servicios-visual-title {
          display: block;
          margin-top: 12px;

          color: var(--srv-title);

          font-size: 21px;
          font-weight: 900;
        }

        .ms-servicios-visual-text {
          display: block;
          margin-top: 6px;

          color: var(--srv-text);

          font-size: 14px;
          font-weight: 600;
        }

        /* ================================================
           12. CUATRO ÁREAS VISUALES
           ================================================ */

        .ms-servicios-visual-grid {
          display: grid;
          grid-template-columns:
            repeat(2,minmax(0,1fr));

          gap: 12px;
        }

        .ms-servicios-visual-item {
          display: flex;
          align-items: center;

          gap: 12px;
          min-width: 0;

          padding: 16px;

          border-radius: 15px;

          background: var(--srv-item-bg);
          border: 1px solid var(--srv-item-border);
        }

        .ms-servicios-visual-icon {
          display: flex;
          align-items: center;
          justify-content: center;

          flex-shrink: 0;

          width: 40px;
          height: 40px;

          border-radius: 12px;

          background: var(--srv-icon-bg);

          font-size: 21px;
        }

        .ms-servicios-visual-item-name {
          color: var(--srv-title);

          font-size: 14px;
          font-weight: 800;
        }

        /* ================================================
           13. GRID DE SERVICIOS
           ================================================ */

        .ms-servicios-grid {
          display: grid;

          grid-template-columns:
            repeat(4,minmax(0,1fr));

          gap: 18px;
        }

        /* ================================================
           14. TARJETAS
           ================================================ */

        .mirrorsoul-public-page
        .ms-servicios-card {
          display: flex;
          flex-direction: column;

          min-width: 0;
          min-height: 330px;

          padding: 26px;

          border-radius: 22px;

          background: var(--srv-card-bg) !important;
          border: 1px solid var(--srv-card-border);

          color: var(--srv-title);

          box-shadow: var(--srv-shadow);

          transition:
            background 0.3s ease,
            color 0.3s ease,
            transform 0.2s ease;
        }

        .ms-servicios-card:hover {
          transform: translateY(-4px);
        }

        .ms-servicios-card-top {
          display: flex;
          align-items: center;
          justify-content: space-between;

          gap: 12px;
          margin-bottom: 22px;
        }

        .ms-servicios-icon-box {
          display: flex;
          align-items: center;
          justify-content: center;

          width: 56px;
          height: 56px;

          border-radius: 16px;

          background: var(--srv-icon-bg);
          border: 1px solid var(--srv-icon-border);

          font-size: 25px;
        }

        .ms-servicios-number {
          color: var(--srv-muted);

          font-size: 13px;
          font-weight: 900;
          letter-spacing: 1px;
        }

        .mirrorsoul-public-page
        .ms-servicios-card-title {
          margin: 0;

          color: var(--srv-title) !important;

          font-size: 21px !important;
          line-height: 1.35 !important;
          font-weight: 900;
        }

        .mirrorsoul-public-page
        .ms-servicios-card-text {
          margin: 14px 0 0;

          color: var(--srv-text) !important;

          font-size: 16px !important;
          line-height: 1.7 !important;
          font-weight: 500;

          flex: 1;
        }

        /* ================================================
           15. ETIQUETAS
           ================================================ */

        .ms-servicios-tags {
          display: flex;
          flex-wrap: wrap;

          gap: 8px;
          margin-top: 24px;
        }

        .ms-servicios-tag {
          display: inline-flex;
          align-items: center;

          padding: 7px 10px;

          border-radius: 8px;

          background: var(--srv-tag-bg);
          border: 1px solid var(--srv-tag-border);

          color: var(--srv-tag-text);

          font-size: 12px;
          line-height: 1.45;
          font-weight: 700;
        }

        /* ================================================
           16. SOLUCIONES PERSONALIZADAS
           ================================================ */

        .ms-servicios-custom {
          display: flex;
          align-items: center;
          justify-content: space-between;

          gap: 35px;

          margin-top: 45px;
          padding: 38px;

          border-radius: 26px;

          background: var(--srv-custom-bg);
          border: 1px solid var(--srv-custom-border);

          box-shadow: var(--srv-shadow);
        }

        .ms-servicios-custom-content {
          min-width: 0;
          max-width: 750px;
        }

        .ms-servicios-custom-eyebrow {
          display: block;

          margin-bottom: 14px;

          color: var(--srv-accent);

          font-size: 13px;
          font-weight: 900;
          letter-spacing: 1.5px;
        }

        .mirrorsoul-public-page
        .ms-servicios-custom-title {
          margin: 0;

          color: var(--srv-title) !important;

          font-size:
            clamp(1.9rem,2.4vw,2.7rem) !important;

          line-height: 1.2 !important;
          font-weight: 900;
        }

        .mirrorsoul-public-page
        .ms-servicios-custom-text {
          margin: 18px 0 0;

          color: var(--srv-text) !important;

          font-size: 17px !important;
          line-height: 1.75 !important;
        }

        /* ================================================
           17. BOTÓN SOLICITAR COTIZACIÓN
           ================================================ */

        .ms-servicios-contact-button {
          display: inline-flex;
          align-items: center;
          justify-content: center;

          flex-shrink: 0;
          gap: 12px;

          min-height: 53px;
          padding: 15px 23px;

          border: none;
          border-radius: 13px;

          background: linear-gradient(
            135deg,
            #f4bd72,
            #ed9665
          );

          color: #33210e;

          font-family: inherit;
          font-size: 15px;
          font-weight: 900;

          cursor: pointer;

          box-shadow:
            0 12px 25px rgba(210,131,70,0.16);

          transition:
            transform 0.2s ease,
            box-shadow 0.2s ease;
        }

        .ms-servicios-contact-button:hover {
          transform: translateY(-3px);

          box-shadow:
            0 15px 30px rgba(210,131,70,0.24);
        }

        .ms-servicios-contact-button span {
          font-size: 22px;
          line-height: 1;
        }

        .ms-servicios-contact-button:focus-visible {
          outline: 3px solid #2563eb;
          outline-offset: 3px;
        }

        /* ================================================
           18. NOTA FINAL
           ================================================ */

        .ms-servicios-note {
          display: flex;
          align-items: flex-start;

          gap: 14px;

          max-width: 100%;

          margin-top: 32px;
          padding: 20px 24px;

          border-radius: 16px;

          background: var(--srv-note-bg);
          border: 1px solid var(--srv-note-border);
        }

        .ms-servicios-note-icon {
          display: flex;
          align-items: center;
          justify-content: center;

          flex-shrink: 0;

          width: 28px;
          height: 28px;

          border-radius: 50%;

          background: var(--srv-icon-bg);
          border: 1px solid var(--srv-icon-border);

          color: var(--srv-accent);

          font-size: 15px;
          font-weight: 900;
        }

        .mirrorsoul-public-page
        .ms-servicios-note-text {
          margin: 0;

          color: var(--srv-text) !important;

          font-size: 15px !important;
          line-height: 1.7 !important;
        }

        /* ================================================
           19. TABLET
           ================================================ */

        @media (max-width: 1150px) {
          .ms-servicios {
            padding: 85px 25px;
          }

          .ms-servicios-grid {
            grid-template-columns:
              repeat(2,minmax(0,1fr));
          }

          .ms-servicios-intro {
            gap: 28px;
            padding: 30px;
          }
        }

        /* ================================================
           20. PANTALLAS MEDIANAS
           ================================================ */

        @media (max-width: 850px) {
          .ms-servicios-intro {
            grid-template-columns: 1fr;
          }

          .ms-servicios-custom {
            flex-direction: column;
            align-items: stretch;
          }

          .ms-servicios-contact-button {
            align-self: flex-start;
          }
        }

        /* ================================================
           21. CELULARES
           ================================================ */

        @media (max-width: 600px) {
          .ms-servicios {
            padding: 65px 18px;
          }

          .ms-servicios-heading {
            margin-bottom: 40px;
          }

          .ms-servicios-intro {
            padding: 25px 18px;
            border-radius: 21px;
          }

          .ms-servicios-points {
            grid-template-columns: 1fr;
          }

          .ms-servicios-visual {
            padding: 18px;
          }

          .ms-servicios-visual-item {
            padding: 12px;
            gap: 8px;
          }

          .ms-servicios-visual-icon {
            width: 33px;
            height: 33px;
            font-size: 17px;
          }

          .ms-servicios-grid {
            grid-template-columns: 1fr;
            gap: 16px;
          }

          .mirrorsoul-public-page
          .ms-servicios-card {
            min-height: auto;
            padding: 25px;
          }

          .ms-servicios-custom {
            margin-top: 30px;
            padding: 27px 20px;
            gap: 25px;
          }

          .ms-servicios-contact-button {
            width: 100%;
          }

          .ms-servicios-note {
            padding: 17px;
          }

          .mirrorsoul-public-page
          .ms-servicios-title {
            font-size:
              clamp(2rem,7vw,2.7rem) !important;
          }
        }

        /* ================================================
           22. MOVIMIENTO REDUCIDO
           ================================================ */

        @media (prefers-reduced-motion: reduce) {
          .ms-servicios *,
          .ms-servicios *::before,
          .ms-servicios *::after {
            animation: none !important;
            transition: none !important;
          }
        }

      `}</style>
    </>
  );
}

export default ServiciosTecnologicos;
