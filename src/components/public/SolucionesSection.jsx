
import React from "react";
import LogoMirrorSoul from "./LogoMirrorSoul";

// ============================================================
// MIRRORSOUL - SOLUCIONES
// MODO CLARO Y OSCURO
// ============================================================

// ============================================================
// SOLUCIONES DE LA PLATAFORMA
// ============================================================

const soluciones = [
  {
    icono: "🏢",
    titulo: "Recursos Humanos",
    texto:
      "Gestión de empleados, selección de candidatos, pruebas psicométricas, evaluaciones, seguimiento, canalización y bienestar laboral.",
    detalles: [
      "Gestión de empleados",
      "Selección de candidatos",
      "Pruebas psicométricas",
      "NOM-035",
      "Evaluaciones",
      "Seguimiento",
      "Canalización",
    ],
  },
  {
    icono: "🏥",
    titulo: "Gestión clínica",
    texto:
      "Centraliza pacientes, sesiones, historial clínico, pruebas, reportes y seguimiento profesional dentro de un mismo entorno.",
    detalles: [
      "Pacientes",
      "Sesiones",
      "Historial clínico",
      "Pruebas",
      "Reportes",
    ],
  },
  {
    icono: "🧠",
    titulo: "Evaluaciones",
    texto:
      "Permite aplicar evaluaciones, organizar resultados y dar continuidad a los procesos según el contexto de cada persona.",
    detalles: [
      "Aplicación de pruebas",
      "Resultados",
      "Interpretación",
      "Seguimiento",
      "Historial",
    ],
  },
  {
    icono: "🤖",
    titulo: "Inteligencia artificial",
    texto:
      "Utiliza inteligencia artificial como herramienta de apoyo para organizar información, generar análisis y facilitar la interpretación de resultados.",
    detalles: [
      "Análisis de información",
      "Preevaluaciones",
      "Reportes",
      "Apoyo profesional",
      "Automatización",
    ],
  },
  {
    icono: "🔄",
    titulo: "Seguimiento y continuidad",
    texto:
      "Conecta cada etapa del proceso para evitar que los casos queden aislados o sin seguimiento.",
    detalles: [
      "Recordatorios",
      "Seguimientos",
      "Estados",
      "Historial",
      "Continuidad",
    ],
  },
  {
    icono: "🤝",
    titulo: "Canalización profesional",
    texto:
      "Facilita la conexión entre una necesidad detectada y profesionales disponibles, permitiendo dar seguimiento a todo el proceso.",
    detalles: [
      "Detección",
      "Opciones profesionales",
      "Selección",
      "Aceptación",
      "Seguimiento",
    ],
  },
  {
    icono: "📊",
    titulo: "Reportes y análisis",
    texto:
      "Convierte datos dispersos en información organizada que puede facilitar la toma de decisiones y el seguimiento de resultados.",
    detalles: [
      "Indicadores",
      "Resultados",
      "Historial",
      "Reportes",
      "Información estructurada",
    ],
  },
  {
    icono: "⚙️",
    titulo: "Automatización",
    texto:
      "Reduce tareas manuales mediante flujos conectados, notificaciones y procesos automáticos dentro de la plataforma.",
    detalles: [
      "Notificaciones",
      "Procesos automáticos",
      "Flujos",
      "Estados",
      "Alertas",
    ],
  },
];

// ============================================================
// ETAPAS DEL PROCESO
// ============================================================

const etapas = [
  {
    numero: "01",
    titulo: "Detecta",
    texto: "Identifica una necesidad.",
  },
  {
    numero: "02",
    titulo: "Evalúa",
    texto: "Obtiene información.",
  },
  {
    numero: "03",
    titulo: "Analiza",
    texto: "Organiza resultados.",
  },
  {
    numero: "04",
    titulo: "Canaliza",
    texto: "Conecta con atención.",
  },
  {
    numero: "05",
    titulo: "Da seguimiento",
    texto: "Mantiene continuidad.",
  },
];

// ============================================================
// ÁREAS CONECTADAS
// ============================================================

const areas = [
  "RH",
  "Clínica",
  "IA",
  "Evaluación",
  "Seguimiento",
  "Reportes",
];

// ============================================================
// COMPONENTE PRINCIPAL
// ============================================================

function SolucionesSection() {
  return (
    <>
      <section className="ms-soluciones">

        <div className="ms-soluciones-container">

          {/* ============================================== */}
          {/* ENCABEZADO */}
          {/* ============================================== */}

          <div className="ms-soluciones-heading">

            <span className="ms-soluciones-eyebrow">
              LA SOLUCIÓN
            </span>

            <h2 className="ms-soluciones-title">
              MirrorSoul conecta herramientas,
              información y seguimiento en una
              sola plataforma.
            </h2>

            <p className="ms-soluciones-description">
              En lugar de trabajar con procesos
              separados, MirrorSoul permite integrar
              diferentes etapas dentro de un mismo
              flujo, facilitando la gestión, la
              evaluación y la continuidad.
            </p>

          </div>

          {/* ============================================== */}
          {/* FLUJO PRINCIPAL */}
          {/* ============================================== */}

          <div className="ms-soluciones-flow-card">

            {/* ============================================ */}
            {/* CABECERA DEL FLUJO */}
            {/* ============================================ */}

            <div className="ms-soluciones-flow-header">

              <div className="ms-soluciones-flow-brand">

                <div className="ms-soluciones-logo">
                  <LogoMirrorSoul
                    width={84}
                    height={68}
                    background={false}
                    padding={0}
                  />
                </div>

                <div className="ms-soluciones-flow-heading">

                  <span className="ms-soluciones-flow-eyebrow">
                    UN PROCESO CONECTADO
                  </span>

                  <h3 className="ms-soluciones-flow-title">
                    De la detección a la acción.
                  </h3>

                </div>

              </div>

              <span className="ms-soluciones-flow-badge">
                MirrorSoul
              </span>

            </div>

            {/* ============================================ */}
            {/* CINCO ETAPAS */}
            {/* ============================================ */}

            <div className="ms-soluciones-flow">

              {etapas.map((etapa, index) => (
                <React.Fragment key={etapa.numero}>

                  {index > 0 && (
                    <div
                      className="ms-soluciones-flow-line"
                      aria-hidden="true"
                    />
                  )}

                  <div className="ms-soluciones-flow-item">

                    <div className="ms-soluciones-flow-number">
                      {etapa.numero}
                    </div>

                    <strong className="ms-soluciones-flow-item-title">
                      {etapa.titulo}
                    </strong>

                    <span className="ms-soluciones-flow-text">
                      {etapa.texto}
                    </span>

                  </div>

                </React.Fragment>
              ))}

            </div>

          </div>

          {/* ============================================== */}
          {/* TARJETAS DE SOLUCIONES */}
          {/* ============================================== */}

          <div className="ms-soluciones-grid">

            {soluciones.map((solucion, index) => (

              <article
                className="ms-soluciones-card"
                key={solucion.titulo}
              >

                {/* ======================================== */}
                {/* ICONO Y NÚMERO */}
                {/* ======================================== */}

                <div className="ms-soluciones-card-top">

                  <div
                    className="ms-soluciones-icon"
                    aria-hidden="true"
                  >
                    {solucion.icono}
                  </div>

                  <span className="ms-soluciones-card-number">
                    {String(index + 1).padStart(
                      2,
                      "0"
                    )}
                  </span>

                </div>

                {/* ======================================== */}
                {/* TÍTULO */}
                {/* ======================================== */}

                <h3 className="ms-soluciones-card-title">
                  {solucion.titulo}
                </h3>

                {/* ======================================== */}
                {/* DESCRIPCIÓN */}
                {/* ======================================== */}

                <p className="ms-soluciones-card-text">
                  {solucion.texto}
                </p>

                {/* ======================================== */}
                {/* ETIQUETAS */}
                {/* ======================================== */}

                <div className="ms-soluciones-tags">

                  {solucion.detalles.map((detalle) => (

                    <span
                      className="ms-soluciones-tag"
                      key={detalle}
                    >
                      {detalle}
                    </span>

                  ))}

                </div>

              </article>

            ))}

          </div>

          {/* ============================================== */}
          {/* BLOQUE DIFERENCIAL */}
          {/* ============================================== */}

          <div className="ms-soluciones-integration">

            {/* ============================================ */}
            {/* EXPLICACIÓN */}
            {/* ============================================ */}

            <div className="ms-soluciones-integration-content">

              <span className="ms-soluciones-integration-eyebrow">
                EL VALOR DE LA INTEGRACIÓN
              </span>

              <h3 className="ms-soluciones-integration-title">
                No se trata únicamente de
                agregar funciones.
              </h3>

              <p className="ms-soluciones-integration-text">
                El verdadero valor está en que
                cada herramienta pueda compartir
                información con el resto del
                proceso y permitir que la
                organización tenga una visión
                más completa.
              </p>

            </div>

            {/* ============================================ */}
            {/* VISUAL DE INTEGRACIÓN */}
            {/* ============================================ */}

            <div className="ms-soluciones-integration-visual">

              <div className="ms-soluciones-center-circle">

                <div className="ms-soluciones-center-logo">
                  <LogoMirrorSoul
                    width={100}
                    height={74}
                    background={false}
                    padding={0}
                  />
                </div>

                <strong className="ms-soluciones-center-title">
                  MirrorSoul
                </strong>

              </div>

              {/* ========================================== */}
              {/* ÁREAS CONECTADAS */}
              {/* ========================================== */}

              <div className="ms-soluciones-connection-grid">

                {areas.map((area) => (

                  <span
                    className="ms-soluciones-connection"
                    key={area}
                  >
                    {area}
                  </span>

                ))}

              </div>

            </div>

          </div>

        </div>

      </section>

      {/* ================================================== */}
      {/* ESTILOS DEL COMPONENTE */}
      {/* ================================================== */}

      <style>{`

        /* ================================================
           1. VARIABLES - MODO CLARO
           ================================================ */

        :root,
        :root[data-ms-theme="claro"] {
          --sol-title: #142842;
          --sol-text: #50657f;
          --sol-muted: #60738a;

          --sol-accent: #1769ba;
          --sol-accent-soft: #eaf4ff;

          --sol-card: #ffffff;
          --sol-card-border: #dce7f5;

          --sol-flow-bg:
            linear-gradient(
              145deg,
              #ffffff 0%,
              #f1f7ff 100%
            );

          --sol-flow-border: #d7e6f7;

          --sol-number-bg:
            linear-gradient(
              135deg,
              #e7f5ff,
              #edf0ff
            );

          --sol-number-border: #d5e7fa;

          --sol-tag-bg: #eef5ff;
          --sol-tag-border: #dce7f5;
          --sol-tag-text: #345a7c;

          --sol-icon-bg: #eaf4ff;
          --sol-icon-border: #d4e8fb;

          --sol-integration-bg:
            linear-gradient(
              145deg,
              #eaf4ff 0%,
              #ffffff 100%
            );

          --sol-visual-bg: #ffffff;
          --sol-visual-border: #dce7f5;

          --sol-circle-bg:
            linear-gradient(
              145deg,
              #e3f5ff,
              #edeaff
            );

          --sol-circle-border: #cfe4fa;

          --sol-connection-bg: #eef5ff;
          --sol-connection-text: #345a7c;

          --sol-shadow:
            0 20px 55px rgba(28, 63, 110, 0.09);
        }

        /* ================================================
           2. VARIABLES - MODO OSCURO
           ================================================ */

        :root[data-ms-theme="oscuro"] {
          --sol-title: #ffffff;
          --sol-text: #c0d0e4;
          --sol-muted: #afc2d8;

          --sol-accent: #76eaff;
          --sol-accent-soft:
            rgba(101,229,255,0.08);

          --sol-card: #142438;
          --sol-card-border:
            rgba(255,255,255,0.09);

          --sol-flow-bg:
            linear-gradient(
              145deg,
              #17293d 0%,
              #0d1b2b 100%
            );

          --sol-flow-border:
            rgba(255,255,255,0.09);

          --sol-number-bg:
            linear-gradient(
              135deg,
              rgba(102,230,255,0.10),
              rgba(142,125,255,0.11)
            );

          --sol-number-border:
            rgba(104,229,255,0.14);

          --sol-tag-bg:
            rgba(255,255,255,0.055);

          --sol-tag-border:
            rgba(255,255,255,0.10);

          --sol-tag-text: #cad9ea;

          --sol-icon-bg:
            rgba(101,229,255,0.07);

          --sol-icon-border:
            rgba(101,229,255,0.14);

          --sol-integration-bg:
            linear-gradient(
              145deg,
              #172b40 0%,
              #0b1a2a 100%
            );

          --sol-visual-bg:
            rgba(4,13,22,0.46);

          --sol-visual-border:
            rgba(255,255,255,0.09);

          --sol-circle-bg:
            linear-gradient(
              145deg,
              rgba(97,229,255,0.08),
              rgba(143,125,255,0.10)
            );

          --sol-circle-border:
            rgba(104,230,255,0.15);

          --sol-connection-bg:
            rgba(255,255,255,0.06);

          --sol-connection-text: #c8daed;

          --sol-shadow:
            0 20px 55px rgba(0,0,0,0.20);
        }

        /* ================================================
           3. SECCIÓN PRINCIPAL
           ================================================ */

        .ms-soluciones {
          position: relative;

          width: 100%;

          padding: 110px 28px;

          background: transparent;

          color: var(--sol-title);
        }

        .ms-soluciones-container {
          width: 100%;

          max-width: 1280px;

          margin: 0 auto;
        }

        /* ================================================
           4. ENCABEZADO
           ================================================ */

        .ms-soluciones-heading {
          max-width: 950px;

          margin-bottom: 55px;
        }

        .ms-soluciones-eyebrow {
          display: inline-block;

          margin-bottom: 15px;

          color: var(--sol-accent);

          font-size: 13px;
          font-weight: 900;

          letter-spacing: 1.8px;
        }

        .mirrorsoul-public-page
        .ms-soluciones-title {
          margin: 0;

          color: var(--sol-title) !important;

          font-size:
            clamp(2.25rem,3vw,3.5rem) !important;

          line-height: 1.1 !important;

          letter-spacing: -1.3px;

          font-weight: 900;
        }

        .mirrorsoul-public-page
        .ms-soluciones-description {
          max-width: 850px;

          margin: 24px 0 0;

          color: var(--sol-text) !important;

          font-size:
            clamp(1.05rem,1.13vw,1.22rem) !important;

          line-height: 1.75 !important;

          font-weight: 500;
        }

        /* ================================================
           5. TARJETA DEL FLUJO
           ================================================ */

        .ms-soluciones-flow-card {
          padding: 30px;

          margin-bottom: 28px;

          border-radius: 25px;

          background: var(--sol-flow-bg);

          border: 1px solid var(--sol-flow-border);

          box-shadow: var(--sol-shadow);

          transition:
            background 0.3s ease,
            border-color 0.3s ease;
        }

        /* ================================================
           6. CABECERA DEL FLUJO
           ================================================ */

        .ms-soluciones-flow-header {
          display: flex;

          align-items: center;

          justify-content: space-between;

          gap: 20px;

          margin-bottom: 32px;
        }

        .ms-soluciones-flow-brand {
          display: flex;

          align-items: center;

          gap: 17px;

          min-width: 0;
        }

        .ms-soluciones-logo {
          display: flex;

          align-items: center;

          justify-content: center;

          flex-shrink: 0;

          width: 84px;
          height: 68px;

          background: transparent;

          border: none;
          box-shadow: none;
        }

        .ms-soluciones-flow-heading {
          min-width: 0;
        }

        .ms-soluciones-flow-eyebrow {
          display: block;

          margin-bottom: 8px;

          color: var(--sol-accent);

          font-size: 11px;
          font-weight: 900;

          letter-spacing: 1.4px;
        }

        .mirrorsoul-public-page
        .ms-soluciones-flow-title {
          margin: 0;

          color: var(--sol-title) !important;

          font-size: 25px !important;

          font-weight: 900;

          line-height: 1.3 !important;
        }

        .ms-soluciones-flow-badge {
          padding: 9px 13px;

          border-radius: 10px;

          background: var(--sol-accent-soft);

          border: 1px solid var(--sol-number-border);

          color: var(--sol-accent);

          font-size: 12px;
          font-weight: 900;
        }

        /* ================================================
           7. ETAPAS DEL PROCESO
           ================================================ */

        .ms-soluciones-flow {
          display: flex;

          align-items: flex-start;

          justify-content: space-between;

          width: 100%;
        }

        .ms-soluciones-flow-item {
          display: flex;

          flex-direction: column;

          align-items: center;

          text-align: center;

          width: 145px;

          flex-shrink: 0;
        }

        .ms-soluciones-flow-number {
          display: flex;

          align-items: center;

          justify-content: center;

          width: 44px;
          height: 44px;

          margin-bottom: 13px;

          border-radius: 14px;

          background: var(--sol-number-bg);

          border: 1px solid var(--sol-number-border);

          color: var(--sol-accent);

          font-size: 13px;
          font-weight: 900;
        }

        .ms-soluciones-flow-item-title {
          color: var(--sol-title);

          font-size: 15px;

          line-height: 1.4;

          font-weight: 900;
        }

        .ms-soluciones-flow-text {
          display: block;

          margin-top: 5px;

          color: var(--sol-muted);

          font-size: 12px;

          line-height: 1.5;
        }

        .ms-soluciones-flow-line {
          flex: 1;

          height: 2px;

          margin: 21px 6px 0;

          background: var(--sol-number-border);
        }

        /* ================================================
           8. CUADRÍCULA DE SOLUCIONES
           ================================================ */

        .ms-soluciones-grid {
          display: grid;

          grid-template-columns:
            repeat(4,minmax(0,1fr));

          gap: 18px;
        }

        /* ================================================
           9. TARJETAS
           ================================================ */

        .mirrorsoul-public-page
        .ms-soluciones-card {
          display: flex;

          flex-direction: column;

          min-width: 0;

          min-height: 340px;

          padding: 25px;

          border-radius: 22px;

          background: var(--sol-card) !important;

          border: 1px solid var(--sol-card-border);

          color: var(--sol-title);

          box-shadow: var(--sol-shadow);

          transition:
            background 0.3s ease,
            color 0.3s ease,
            transform 0.2s ease;
        }

        .ms-soluciones-card:hover {
          transform: translateY(-4px);
        }

        .ms-soluciones-card-top {
          display: flex;

          align-items: center;

          justify-content: space-between;

          margin-bottom: 22px;
        }

        .ms-soluciones-icon {
          display: flex;

          align-items: center;

          justify-content: center;

          width: 55px;
          height: 55px;

          border-radius: 16px;

          background: var(--sol-icon-bg);

          border: 1px solid var(--sol-icon-border);

          font-size: 25px;
        }

        .ms-soluciones-card-number {
          color: var(--sol-muted);

          font-size: 13px;

          font-weight: 900;

          letter-spacing: 1px;
        }

        .mirrorsoul-public-page
        .ms-soluciones-card-title {
          margin: 0;

          color: var(--sol-title) !important;

          font-size: 22px !important;

          font-weight: 900;

          line-height: 1.35 !important;
        }

        .mirrorsoul-public-page
        .ms-soluciones-card-text {
          margin: 15px 0 0;

          color: var(--sol-text) !important;

          font-size: 16px !important;

          line-height: 1.7 !important;

          font-weight: 500;

          flex: 1;
        }

        /* ================================================
           10. ETIQUETAS
           ================================================ */

        .ms-soluciones-tags {
          display: flex;

          flex-wrap: wrap;

          gap: 8px;

          margin-top: 22px;
        }

        .ms-soluciones-tag {
          display: inline-flex;

          align-items: center;

          padding: 7px 10px;

          border-radius: 8px;

          background: var(--sol-tag-bg);

          border: 1px solid var(--sol-tag-border);

          color: var(--sol-tag-text);

          font-size: 12px;

          line-height: 1.35;

          font-weight: 700;
        }

        /* ================================================
           11. BLOQUE DE INTEGRACIÓN
           ================================================ */

        .ms-soluciones-integration {
          display: grid;

          grid-template-columns:
            minmax(0,1fr)
            minmax(0,0.9fr);

          align-items: center;

          gap: 45px;

          margin-top: 45px;

          padding: 38px;

          border-radius: 26px;

          background: var(--sol-integration-bg);

          border: 1px solid var(--sol-flow-border);

          box-shadow: var(--sol-shadow);
        }

        .ms-soluciones-integration-content {
          min-width: 0;
          max-width: 590px;
        }

        .ms-soluciones-integration-eyebrow {
          display: block;

          margin-bottom: 13px;

          color: var(--sol-accent);

          font-size: 12px;

          font-weight: 900;

          letter-spacing: 1.5px;
        }

        .mirrorsoul-public-page
        .ms-soluciones-integration-title {
          margin: 0;

          color: var(--sol-title) !important;

          font-size:
            clamp(1.9rem,2.4vw,2.8rem) !important;

          line-height: 1.2 !important;

          font-weight: 900;

          letter-spacing: -0.8px;
        }

        .mirrorsoul-public-page
        .ms-soluciones-integration-text {
          margin: 20px 0 0;

          color: var(--sol-text) !important;

          font-size: 17px !important;

          line-height: 1.75 !important;
        }

        /* ================================================
           12. PANEL VISUAL
           ================================================ */

        .ms-soluciones-integration-visual {
          position: relative;

          padding: 27px;

          border-radius: 22px;

          background: var(--sol-visual-bg);

          border: 1px solid var(--sol-visual-border);

          min-width: 0;
        }

        /* ================================================
           13. LOGO CENTRAL
           ================================================ */

        .ms-soluciones-center-circle {
          display: flex;

          flex-direction: column;

          align-items: center;

          justify-content: center;

          width: 160px;
          height: 160px;

          margin: 0 auto 24px;

          border-radius: 50%;

          background: var(--sol-circle-bg);

          border: 1px solid var(--sol-circle-border);
        }

        .ms-soluciones-center-logo {
          display: flex;

          align-items: center;

          justify-content: center;

          width: 105px;
          height: 80px;

          background: transparent;

          border: none;

          box-shadow: none;
        }

        .ms-soluciones-center-title {
          color: var(--sol-title);

          font-size: 15px;

          font-weight: 900;
        }

        /* ================================================
           14. ÁREAS CONECTADAS
           ================================================ */

        .ms-soluciones-connection-grid {
          display: grid;

          grid-template-columns:
            repeat(3,minmax(0,1fr));

          gap: 9px;
        }

        .ms-soluciones-connection {
          display: flex;

          align-items: center;

          justify-content: center;

          min-height: 40px;

          padding: 9px 6px;

          text-align: center;

          border-radius: 10px;

          background: var(--sol-connection-bg);

          border: 1px solid var(--sol-tag-border);

          color: var(--sol-connection-text);

          font-size: 12px;

          font-weight: 800;
        }

        /* ================================================
           15. TABLET
           ================================================ */

        @media (max-width: 1150px) {
          .ms-soluciones {
            padding: 85px 25px;
          }

          .ms-soluciones-grid {
            grid-template-columns:
              repeat(2,minmax(0,1fr));
          }

          .ms-soluciones-flow-item {
            width: 118px;
          }

          .ms-soluciones-integration {
            gap: 25px;
          }
        }

        /* ================================================
           16. PANTALLAS MEDIANAS
           ================================================ */

        @media (max-width: 850px) {
          .ms-soluciones-flow {
            flex-wrap: wrap;

            justify-content: center;

            gap: 20px;
          }

          .ms-soluciones-flow-item {
            width: 130px;
          }

          .ms-soluciones-flow-line {
            display: none;
          }

          .ms-soluciones-integration {
            grid-template-columns: 1fr;
          }

          .ms-soluciones-integration-visual {
            width: 100%;
          }
        }

        /* ================================================
           17. CELULARES
           ================================================ */

        @media (max-width: 600px) {
          .ms-soluciones {
            padding: 65px 18px;
          }

          .ms-soluciones-heading {
            margin-bottom: 40px;
          }

          .ms-soluciones-flow-card {
            padding: 22px 17px;

            border-radius: 21px;
          }

          .ms-soluciones-flow-header {
            align-items: flex-start;

            gap: 12px;
          }

          .ms-soluciones-flow-brand {
            gap: 10px;
          }

          .ms-soluciones-logo {
            width: 54px;
            height: 54px;
          }

          .ms-soluciones-logo > div {
            max-width: 54px;
            max-height: 54px;
          }

          .mirrorsoul-public-page
          .ms-soluciones-flow-title {
            font-size: 19px !important;
          }

          .ms-soluciones-flow-badge {
            display: none;
          }

          .ms-soluciones-flow {
            display: grid;

            grid-template-columns:
              repeat(2,minmax(0,1fr));

            gap: 22px 12px;
          }

          .ms-soluciones-flow-item {
            width: 100%;
          }

          .ms-soluciones-grid {
            grid-template-columns: 1fr;

            gap: 16px;
          }

          .mirrorsoul-public-page
          .ms-soluciones-card {
            min-height: auto;

            padding: 26px;
          }

          .ms-soluciones-integration {
            grid-template-columns: 1fr;

            margin-top: 30px;

            padding: 26px 20px;

            gap: 30px;
          }

          .ms-soluciones-integration-visual {
            padding: 18px;
          }

          .ms-soluciones-center-circle {
            width: 145px;
            height: 145px;
          }

          .ms-soluciones-connection {
            font-size: 11px;
          }

          .mirrorsoul-public-page
          .ms-soluciones-title {
            font-size:
              clamp(2rem,7vw,2.7rem) !important;
          }
        }

        /* ================================================
           18. ACCESIBILIDAD
           ================================================ */

        @media (prefers-reduced-motion: reduce) {
          .ms-soluciones *,
          .ms-soluciones *::before,
          .ms-soluciones *::after {
            animation: none !important;
            transition: none !important;
          }
        }

      `}</style>
    </>
  );
}

export default SolucionesSection;
