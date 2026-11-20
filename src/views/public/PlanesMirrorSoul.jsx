
import React, {
  useEffect,
  useState,
} from "react";

import { useNavigate } from "react-router-dom";

import LogoMirrorSoul from "../../components/public/LogoMirrorSoul";

// ============================================================
// MIRRORSOUL - PLANES PÚBLICOS
// MODO CLARO Y OSCURO
// ============================================================

// ============================================================
// 1. OBTENER TEMA GUARDADO
// ============================================================

const TEMA_KEY = "mirrorsoul_tema_publico";

function obtenerTemaInicial() {
  try {
    const tema = localStorage.getItem(TEMA_KEY);

    return tema === "oscuro"
      ? "oscuro"
      : "claro";
  } catch {
    return "claro";
  }
}

// ============================================================
// 2. CONFIGURACIÓN DE PLANES
// ============================================================

const planes = [
  {
    nombre: "Independiente",
    slug: "independiente",

    descripcion:
      "Para profesionales que desean utilizar MirrorSoul de forma individual.",

    licencias: "1 licencia",

    incluye: [
      "1 usuario profesional",
      "Gestión de pacientes",
      "Historial clínico",
      "Evaluaciones",
      "Sesiones",
      "Seguimiento",
      "Reportes",
      "Herramientas de IA",
    ],

    destacado: false,
  },

  {
    nombre: "Clínica",
    slug: "clinica",

    descripcion:
      "Para clínicas y consultorios que necesitan administrar profesionales y pacientes.",

    licencias: "5 licencias",

    incluye: [
      "Administrador de clínica",
      "5 licencias incluidas",
      "Gestión de psicólogos",
      "Gestión de pacientes",
      "Sesiones",
      "Historial clínico",
      "Evaluaciones",
      "Reportes",
      "Herramientas de IA",
    ],

    destacado: true,
  },

  {
    nombre: "Recursos Humanos",
    slug: "rh",

    descripcion:
      "Para organizaciones que desean integrar bienestar, evaluación y seguimiento de empleados.",

    licencias: "5 licencias",

    incluye: [
      "Administrador RH",
      "5 licencias incluidas",
      "Gestión de empleados",
      "Gestión de prospectos",
      "Selección de candidatos",
      "Pruebas psicométricas",
      "Evaluaciones",
      "NOM-035",
      "Seguimiento",
      "Canalización profesional",
      "Reportes",
    ],

    destacado: false,
  },

  {
    nombre: "Educativo",
    slug: "educativo",

    descripcion:
      "Para instituciones que requieren herramientas de evaluación y seguimiento.",

    licencias: "5 licencias",

    incluye: [
      "Administrador educativo",
      "5 licencias incluidas",
      "Gestión de usuarios",
      "Evaluaciones",
      "Seguimiento",
      "Reportes",
      "Herramientas de apoyo",
    ],

    destacado: false,
  },
];

// ============================================================
// 3. COMPONENTE PRINCIPAL
// ============================================================

function PlanesMirrorSoul() {
  const navigate = useNavigate();

  // ==========================================================
  // ESTADOS
  // ==========================================================

  const [facturacion, setFacturacion] =
    useState("mensual");

  const [tema, setTema] =
    useState(obtenerTemaInicial);

  const oscuro = tema === "oscuro";

  const etiquetaPeriodo =
    facturacion === "mensual"
      ? "por mes"
      : "por año";

  // ==========================================================
  // APLICAR Y GUARDAR APARIENCIA
  // ==========================================================

  useEffect(() => {
    document.documentElement.setAttribute(
      "data-ms-theme",
      tema
    );

    document.documentElement.style.colorScheme =
      oscuro ? "dark" : "light";

    try {
      localStorage.setItem(TEMA_KEY, tema);
    } catch {
      // Continuar aunque localStorage esté bloqueado.
    }
  }, [tema, oscuro]);

  // ==========================================================
  // CAMBIAR TEMA
  // ==========================================================

  const cambiarTema = () => {
    setTema((actual) =>
      actual === "claro"
        ? "oscuro"
        : "claro"
    );
  };

  // ==========================================================
  // ELEGIR PLAN
  // Conservamos exactamente la ruta del proyecto.
  // ==========================================================

  const elegirPlan = (slug) => {
    navigate(
      `/registro-plan?plan=${encodeURIComponent(
        slug
      )}&periodo=${encodeURIComponent(
        facturacion
      )}`
    );
  };

  // ==========================================================
  // RENDER
  // ==========================================================

  return (
    <section className="ms-planes-page">

      {/* ==================================================== */}
      {/* DECORACIONES */}
      {/* ==================================================== */}

      <div
        className="ms-planes-glow ms-planes-glow-left"
        aria-hidden="true"
      />

      <div
        className="ms-planes-glow ms-planes-glow-right"
        aria-hidden="true"
      />

      <div className="ms-planes-container">

        {/* ================================================== */}
        {/* BOTONES SUPERIORES */}
        {/* ================================================== */}

        <div className="ms-planes-toolbar">

          {/* REGRESAR */}

          <button
            type="button"
            className="ms-planes-back"
            onClick={() => navigate("/")}
          >
            <span aria-hidden="true">
              ←
            </span>

            Regresar
          </button>

          {/* SELECTOR DE APARIENCIA */}

          <button
            type="button"
            className="ms-planes-theme"
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

            <span>
              {oscuro
                ? "Modo claro"
                : "Modo oscuro"}
            </span>
          </button>

        </div>

        {/* ================================================== */}
        {/* ENCABEZADO */}
        {/* ================================================== */}

        <div className="ms-planes-header">

          <div className="ms-planes-header-content">

            <span className="ms-planes-eyebrow">
              PLANES MIRRORSOUL
            </span>

            <h1 className="ms-planes-title">
              Elige el plan que mejor
              se adapta a tu entorno.
            </h1>

            <p className="ms-planes-description">
              Puedes iniciar con una
              configuración individual o
              elegir un plan para clínica,
              Recursos Humanos o sector
              educativo.
            </p>

          </div>

          {/* LOGO SIN RECUADRO NEGRO */}

          <div className="ms-planes-header-logo">

            <LogoMirrorSoul
              width={150}
              height={110}
              background={false}
              padding={0}
            />

          </div>

        </div>

        {/* ================================================== */}
        {/* SELECCIÓN DE FACTURACIÓN */}
        {/* ================================================== */}

        <div className="ms-planes-billing">

          <span className="ms-planes-billing-label">
            Facturación
          </span>

          <div
            className="ms-planes-billing-switch"
            role="group"
            aria-label="Seleccionar período de facturación"
          >

            <button
              type="button"
              className={
                facturacion === "mensual"
                  ? "ms-planes-billing-button active"
                  : "ms-planes-billing-button"
              }
              onClick={() =>
                setFacturacion("mensual")
              }
              aria-pressed={
                facturacion === "mensual"
              }
            >
              Mensual
            </button>

            <button
              type="button"
              className={
                facturacion === "anual"
                  ? "ms-planes-billing-button active"
                  : "ms-planes-billing-button"
              }
              onClick={() =>
                setFacturacion("anual")
              }
              aria-pressed={
                facturacion === "anual"
              }
            >
              Anual
            </button>

          </div>

        </div>

        {/* ================================================== */}
        {/* CUATRO PLANES */}
        {/* ================================================== */}

        <div className="ms-planes-grid">

          {planes.map((plan) => (

            <article
              key={plan.slug}
              className={
                plan.destacado
                  ? "ms-plan-card ms-plan-card-featured"
                  : "ms-plan-card"
              }
            >

              {/* ========================================== */}
              {/* LOGO Y DISTINTIVO */}
              {/* ========================================== */}

              <div className="ms-plan-card-top">

                <div className="ms-plan-card-logo">

                  <LogoMirrorSoul
                    width={78}
                    height={61}
                    background={false}
                    padding={0}
                  />

                </div>

                {plan.destacado && (
                  <span className="ms-plan-featured-tag">
                    Destacado
                  </span>
                )}

              </div>

              {/* ========================================== */}
              {/* TÍTULO */}
              {/* ========================================== */}

              <h2 className="ms-plan-card-title">
                {plan.nombre}
              </h2>

              {/* ========================================== */}
              {/* DESCRIPCIÓN */}
              {/* ========================================== */}

              <p className="ms-plan-card-description">
                {plan.descripcion}
              </p>

              {/* ========================================== */}
              {/* PRECIO */}
              {/* ========================================== */}

              <div className="ms-plan-price-box">

                <strong className="ms-plan-price-title">
                  Precio por definir
                </strong>

                <span className="ms-plan-price-period">
                  {etiquetaPeriodo}
                </span>

                <span className="ms-plan-price-note">
                  Configuración en proceso
                </span>

              </div>

              {/* ========================================== */}
              {/* LICENCIAS */}
              {/* ========================================== */}

              <div className="ms-plan-license-box">

                <div
                  className="ms-plan-license-icon"
                  aria-hidden="true"
                >
                  👤
                </div>

                <div>

                  <strong className="ms-plan-license-title">
                    {plan.licencias}
                  </strong>

                  <span className="ms-plan-license-text">
                    incluidas en el plan
                  </span>

                </div>

              </div>

              {/* ========================================== */}
              {/* CARACTERÍSTICAS */}
              {/* ========================================== */}

              <div className="ms-plan-includes-title">
                Incluye:
              </div>

              <div className="ms-plan-features">

                {plan.incluye.map((item) => (

                  <div
                    key={item}
                    className="ms-plan-feature"
                  >

                    <span
                      className="ms-plan-check"
                      aria-hidden="true"
                    >
                      ✓
                    </span>

                    <span>
                      {item}
                    </span>

                  </div>

                ))}

              </div>

              {/* ========================================== */}
              {/* ELEGIR PLAN */}
              {/* ========================================== */}

              <button
                type="button"
                className={
                  plan.destacado
                    ? "ms-plan-cta ms-plan-cta-featured"
                    : "ms-plan-cta"
                }
                onClick={() =>
                  elegirPlan(plan.slug)
                }
              >
                Elegir plan

                <span aria-hidden="true">
                  →
                </span>
              </button>

            </article>

          ))}

        </div>

      </div>

      {/* ==================================================== */}
      {/* ESTILOS COMPLETOS */}
      {/* ==================================================== */}

      <style>{`

        /* ================================================
           1. VARIABLES - MODO CLARO
           ================================================ */

        :root,
        :root[data-ms-theme="claro"] {
          --plan-bg: linear-gradient(
            180deg,
            #f8fbff 0%,
            #edf5ff 55%,
            #ffffff 100%
          );

          --plan-title: #142842;
          --plan-text: #526782;
          --plan-muted: #60758e;

          --plan-accent: #1768ba;

          --plan-card-bg: linear-gradient(
            145deg,
            #ffffff 0%,
            #f8fbff 100%
          );

          --plan-card-border: #d9e6f5;
          --plan-card-featured-border: #8bc5f9;

          --plan-box-bg: #edf5ff;
          --plan-box-border: #dce8f7;

          --plan-button-bg: #ffffff;
          --plan-button-border: #ccdef1;

          --plan-switch-bg: #e8f1fd;
          --plan-switch-text: #526782;

          --plan-tag-bg: #e6f3ff;
          --plan-tag-text: #1768ba;

          --plan-check-bg: #e2f4ff;
          --plan-check-color: #1768ba;

          --plan-shadow:
            0 18px 48px rgba(28, 63, 109, 0.09);
        }

        /* ================================================
           2. VARIABLES - MODO OSCURO
           ================================================ */

        :root[data-ms-theme="oscuro"] {
          --plan-bg: linear-gradient(
            180deg,
            #06111d 0%,
            #081727 45%,
            #06111d 100%
          );

          --plan-title: #ffffff;
          --plan-text: #c3d3e5;
          --plan-muted: #a7bdd4;

          --plan-accent: #72e9ff;

          --plan-card-bg: linear-gradient(
            145deg,
            #142438 0%,
            #0b192a 100%
          );

          --plan-card-border:
            rgba(255,255,255,0.10);

          --plan-card-featured-border:
            rgba(103,226,255,0.38);

          --plan-box-bg:
            rgba(255,255,255,0.045);

          --plan-box-border:
            rgba(255,255,255,0.09);

          --plan-button-bg:
            rgba(255,255,255,0.045);

          --plan-button-border:
            rgba(255,255,255,0.14);

          --plan-switch-bg:
            rgba(255,255,255,0.07);

          --plan-switch-text: #cad8e9;

          --plan-tag-bg:
            rgba(97,230,255,0.10);

          --plan-tag-text: #72e9ff;

          --plan-check-bg:
            rgba(97,230,255,0.12);

          --plan-check-color: #72e9ff;

          --plan-shadow:
            0 20px 55px rgba(0,0,0,0.24);
        }

        /* ================================================
           3. PÁGINA PRINCIPAL
           ================================================ */

        .ms-planes-page {
          position: relative;
          isolation: isolate;

          min-height: 100vh;
          width: 100%;

          overflow: hidden;

          padding: 42px 28px 100px;

          background: var(--plan-bg);
          color: var(--plan-title);

          font-family:
            "Inter",
            "Segoe UI",
            Arial,
            sans-serif;

          transition:
            background 0.3s ease,
            color 0.3s ease;
        }

        .ms-planes-page,
        .ms-planes-page * {
          box-sizing: border-box;
        }

        .ms-planes-container {
          position: relative;
          z-index: 2;

          max-width: 1500px;
          margin: 0 auto;
        }

        /* ================================================
           4. DECORACIONES
           ================================================ */

        .ms-planes-glow {
          position: absolute;
          z-index: 0;

          width: 420px;
          height: 420px;

          border-radius: 50%;

          filter: blur(110px);

          pointer-events: none;
        }

        .ms-planes-glow-left {
          top: -80px;
          left: -110px;

          background:
            rgba(76,214,255,0.10);
        }

        .ms-planes-glow-right {
          bottom: -120px;
          right: -90px;

          background:
            rgba(143,121,255,0.11);
        }

        /* ================================================
           5. BARRA SUPERIOR
           ================================================ */

        .ms-planes-toolbar {
          display: flex;
          align-items: center;
          justify-content: space-between;

          gap: 15px;
          margin-bottom: 35px;
        }

        .ms-planes-back,
        .ms-planes-theme {
          display: inline-flex;
          align-items: center;
          justify-content: center;

          gap: 9px;

          min-height: 46px;
          padding: 11px 17px;

          border-radius: 13px;
          border: 1px solid var(--plan-button-border);

          background: var(--plan-button-bg);
          color: var(--plan-title);

          font-family: inherit;
          font-size: 14px;
          font-weight: 800;

          cursor: pointer;

          transition:
            background 0.2s ease,
            color 0.2s ease,
            transform 0.2s ease;
        }

        .ms-planes-back:hover,
        .ms-planes-theme:hover {
          transform: translateY(-2px);
        }

        .ms-planes-back span {
          color: var(--plan-accent);
          font-size: 20px;
          line-height: 1;
        }

        /* ================================================
           6. ENCABEZADO
           ================================================ */

        .ms-planes-header {
          display: flex;
          align-items: center;
          justify-content: space-between;

          flex-wrap: wrap;
          gap: 24px;

          margin-bottom: 36px;
        }

        .ms-planes-header-content {
          flex: 1;
          min-width: 250px;
        }

        .ms-planes-eyebrow {
          display: inline-block;

          margin-bottom: 15px;

          color: var(--plan-accent);

          font-size: 14px;
          font-weight: 900;
          letter-spacing: 1.8px;
        }

        .ms-planes-title {
          max-width: 800px;
          margin: 0;

          color: var(--plan-title) !important;

          font-size:
            clamp(2.3rem,4vw,3.5rem) !important;

          line-height: 1.08 !important;
          letter-spacing: -1.4px;

          font-weight: 900;
        }

        .ms-planes-description {
          max-width: 790px;

          margin: 20px 0 0;

          color: var(--plan-text) !important;

          font-size:
            clamp(1.05rem,1.2vw,1.18rem) !important;

          line-height: 1.75 !important;
        }

        /* ================================================
           7. LOGO PRINCIPAL
           ================================================ */

        .ms-planes-header-logo {
          display: flex;
          align-items: center;
          justify-content: center;

          flex-shrink: 0;

          background: transparent;
          border: none;
          box-shadow: none;
        }

        /* ================================================
           8. SELECCIÓN MENSUAL / ANUAL
           ================================================ */

        .ms-planes-billing {
          display: flex;
          align-items: center;
          flex-wrap: wrap;

          gap: 15px;
          margin-bottom: 34px;
        }

        .ms-planes-billing-label {
          color: var(--plan-title);

          font-size: 16px;
          font-weight: 900;
        }

        .ms-planes-billing-switch {
          display: inline-flex;
          gap: 6px;

          padding: 6px;

          border-radius: 14px;

          background: var(--plan-switch-bg);
          border: 1px solid var(--plan-box-border);
        }

        .ms-planes-billing-button {
          padding: 11px 20px;

          border: none;
          border-radius: 10px;

          background: transparent;
          color: var(--plan-switch-text);

          font-family: inherit;
          font-size: 15px;
          font-weight: 800;

          cursor: pointer;
        }

        .ms-planes-billing-button.active {
          background: linear-gradient(
            135deg,
            #61e6ff,
            #8e7cff
          );

          color: #07111f;

          box-shadow:
            0 5px 15px rgba(51,124,212,0.14);
        }

        /* ================================================
           9. CUADRÍCULA DE PLANES
           ================================================ */

        .ms-planes-grid {
          display: grid;

          grid-template-columns:
            repeat(4,minmax(0,1fr));

          gap: 22px;
          align-items: stretch;
        }

        /* ================================================
           10. TARJETAS PRINCIPALES
           ================================================ */

        .ms-plan-card {
          position: relative;

          display: flex;
          flex-direction: column;

          min-width: 0;
          padding: 25px;

          border-radius: 25px;

          background: var(--plan-card-bg);

          border: 1px solid var(--plan-card-border);

          box-shadow: var(--plan-shadow);

          color: var(--plan-title);

          transition:
            background 0.3s ease,
            border-color 0.3s ease,
            color 0.3s ease,
            transform 0.2s ease;
        }

        .ms-plan-card:hover {
          transform: translateY(-4px);
        }

        .ms-plan-card-featured {
          border-color: var(--plan-card-featured-border);
          box-shadow: var(--plan-shadow);
        }

        /* ================================================
           11. LOGO Y ETIQUETA DESTACADA
           ================================================ */

        .ms-plan-card-top {
          display: flex;
          align-items: center;
          justify-content: space-between;

          gap: 10px;

          min-height: 65px;
          margin-bottom: 12px;
        }

        .ms-plan-card-logo {
          display: flex;
          align-items: center;
          justify-content: center;

          width: 78px;
          height: 61px;

          flex-shrink: 0;

          background: transparent;
          border: none;
          box-shadow: none;
        }

        .ms-plan-featured-tag {
          display: inline-flex;
          align-items: center;

          padding: 8px 10px;

          border-radius: 999px;

          background: var(--plan-tag-bg);
          color: var(--plan-tag-text);

          border: 1px solid var(--plan-box-border);

          font-size: 11px;
          font-weight: 900;

          white-space: nowrap;
        }

        /* ================================================
           12. NOMBRE Y DESCRIPCIÓN
           ================================================ */

        .ms-plan-card-title {
          margin: 0 0 14px;

          color: var(--plan-title) !important;

          font-size: 25px !important;
          font-weight: 900;

          line-height: 1.25 !important;
        }

        .ms-plan-card-description {
          margin: 0;

          color: var(--plan-text) !important;

          font-size: 16px !important;
          line-height: 1.7 !important;

          min-height: 115px;
        }

        /* ================================================
           13. PRECIO
           ================================================ */

        .ms-plan-price-box {
          margin: 24px 0 18px;
          padding: 19px;

          border-radius: 17px;

          background: var(--plan-box-bg);
          border: 1px solid var(--plan-box-border);
        }

        .ms-plan-price-title {
          display: block;

          margin-bottom: 8px;

          color: var(--plan-title);

          font-size: 19px;
          font-weight: 900;
        }

        .ms-plan-price-period {
          display: block;

          margin-bottom: 7px;

          color: var(--plan-accent);

          font-size: 15px;
          font-weight: 800;
        }

        .ms-plan-price-note {
          display: block;

          color: var(--plan-muted);

          font-size: 13px;
          font-weight: 700;
        }

        /* ================================================
           14. LICENCIAS
           ================================================ */

        .ms-plan-license-box {
          display: flex;
          align-items: center;

          gap: 13px;

          margin-bottom: 27px;
          padding: 15px;

          border-radius: 17px;

          background: var(--plan-box-bg);
          border: 1px solid var(--plan-box-border);
        }

        .ms-plan-license-icon {
          display: flex;
          align-items: center;
          justify-content: center;

          flex-shrink: 0;

          width: 41px;
          height: 41px;

          border-radius: 12px;

          background: var(--plan-tag-bg);
          font-size: 20px;
        }

        .ms-plan-license-title {
          display: block;

          color: var(--plan-title);

          font-size: 17px;
          font-weight: 900;
        }

        .ms-plan-license-text {
          display: block;

          margin-top: 4px;

          color: var(--plan-muted);

          font-size: 13px;
          font-weight: 700;
        }

        /* ================================================
           15. CARACTERÍSTICAS DEL PLAN
           ================================================ */

        .ms-plan-includes-title {
          margin-bottom: 17px;

          color: var(--plan-title);

          font-size: 18px;
          font-weight: 900;
        }

        .ms-plan-features {
          display: grid;
          gap: 12px;

          margin-bottom: 28px;
        }

        .ms-plan-feature {
          display: flex;
          align-items: flex-start;

          gap: 11px;

          color: var(--plan-text);

          font-size: 15px;
          line-height: 1.5;
          font-weight: 600;
        }

        .ms-plan-check {
          display: inline-flex;
          align-items: center;
          justify-content: center;

          flex-shrink: 0;

          width: 24px;
          height: 24px;

          border-radius: 8px;

          background: var(--plan-check-bg);
          color: var(--plan-check-color);

          font-weight: 900;
          font-size: 14px;
        }

        /* ================================================
           16. BOTONES ELEGIR PLAN
           ================================================ */

        .ms-plan-cta {
          display: flex;
          align-items: center;
          justify-content: center;

          gap: 11px;

          width: 100%;
          min-height: 55px;

          margin-top: auto;
          padding: 12px 17px;

          border-radius: 14px;

          border: 1px solid var(--plan-button-border);

          background: var(--plan-button-bg);
          color: var(--plan-title);

          font-family: inherit;
          font-size: 16px;
          font-weight: 900;

          cursor: pointer;

          transition:
            transform 0.2s ease,
            background 0.2s ease,
            box-shadow 0.2s ease;
        }

        .ms-plan-cta:hover {
          transform: translateY(-2px);
          box-shadow: var(--plan-shadow);
        }

        .ms-plan-cta-featured {
          border: none;

          background: linear-gradient(
            135deg,
            #61e6ff,
            #8e7cff
          );

          color: #07111f;
        }

        .ms-plan-cta span {
          font-size: 22px;
          line-height: 1;
        }

        /* ================================================
           17. ACCESIBILIDAD
           ================================================ */

        .ms-planes-page button:focus-visible {
          outline: 3px solid #2563eb;
          outline-offset: 3px;
        }

        /* ================================================
           18. PANTALLAS MEDIANAS
           ================================================ */

        @media (max-width: 1250px) {
          .ms-planes-grid {
            grid-template-columns:
              repeat(2,minmax(0,1fr));
          }

          .ms-plan-card-description {
            min-height: auto;
          }
        }

        /* ================================================
           19. TABLET
           ================================================ */

        @media (max-width: 850px) {
          .ms-planes-page {
            padding: 30px 22px 75px;
          }

          .ms-planes-header {
            align-items: flex-start;
          }

          .ms-planes-header-logo {
            margin: 0 auto;
          }
        }

        /* ================================================
           20. CELULARES
           ================================================ */

        @media (max-width: 650px) {
          .ms-planes-page {
            padding: 22px 17px 65px;
          }

          .ms-planes-toolbar {
            margin-bottom: 30px;
          }

          .ms-planes-back,
          .ms-planes-theme {
            padding: 10px 12px;
            font-size: 13px;
          }

          .ms-planes-header {
            gap: 16px;
            margin-bottom: 28px;
          }

          .ms-planes-header-logo {
            order: -1;
            width: 100%;
          }

          .ms-planes-title {
            font-size:
              clamp(2rem,7vw,2.7rem) !important;
          }

          .ms-planes-billing {
            flex-direction: column;
            align-items: flex-start;
          }

          .ms-planes-grid {
            grid-template-columns: 1fr;
            gap: 22px;
          }

          .ms-plan-card {
            padding: 23px;
            border-radius: 21px;
          }

          .ms-plan-card-description {
            min-height: auto;
          }

          .ms-plan-card-title {
            font-size: 23px !important;
          }

          .ms-plan-feature {
            font-size: 15px;
          }
        }

        /* ================================================
           21. MOVIMIENTO REDUCIDO
           ================================================ */

        @media (prefers-reduced-motion: reduce) {
          .ms-planes-page *,
          .ms-planes-page *::before,
          .ms-planes-page *::after {
            transition: none !important;
            animation: none !important;
          }
        }

      `}</style>
    </section>
  );
}

export default PlanesMirrorSoul;
