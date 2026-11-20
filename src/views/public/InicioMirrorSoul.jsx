
import React from "react";

import NavbarPublica from "../../components/public/NavbarPublica";
import HeroMirrorSoul from "../../components/public/HeroMirrorSoul";
import QueEsMirrorSoul from "../../components/public/QueEsMirrorSoul";
import ProblematicaSection from "../../components/public/ProblematicaSection";
import SolucionesSection from "../../components/public/SolucionesSection";
import VideoPresentacion from "../../components/public/VideoPresentacion";
import BeneficiosSection from "../../components/public/BeneficiosSection";
import ServiciosTecnologicos from "../../components/public/ServiciosTecnologicos";
import FooterPublico from "../../components/public/FooterPublico";

import "./InicioMirrorSoul.css";

// ============================================================
// DECORACIONES DE LAS SECCIONES
// ============================================================

function SectionDecorations({
  left = "✦",
  right = "🧠",
  bottom = "◇",
}) {
  return (
    <div
      className="section-background-icons"
      aria-hidden="true"
    >
      <span
        className="
          section-bg-icon
          section-bg-icon-left
        "
      >
        {left}
      </span>

      <span
        className="
          section-bg-icon
          section-bg-icon-right
        "
      >
        {right}
      </span>

      <span
        className="
          section-bg-icon
          section-bg-icon-bottom
        "
      >
        {bottom}
      </span>

      <span className="section-bg-dot section-bg-dot-1" />
      <span className="section-bg-dot section-bg-dot-2" />
      <span className="section-bg-dot section-bg-dot-3" />
    </div>
  );
}

// ============================================================
// PÁGINA PÚBLICA MIRRORSOUL
// ============================================================

function InicioMirrorSoul() {
  return (
    <div className="mirrorsoul-public-page">

      <div className="public-content-layer">

        {/* ================================================ */}
        {/* NAVEGACIÓN */}
        {/* ================================================ */}

        <NavbarPublica />

        <main className="public-main">

          {/* ============================================== */}
          {/* INICIO */}
          {/* ============================================== */}

          <section
            id="inicio"
            className="public-section"
          >
            <SectionDecorations
              left="✦"
              right="🤖"
              bottom="○"
            />

            <HeroMirrorSoul />
          </section>

          {/* ============================================== */}
          {/* QUÉ ES MIRRORSOUL */}
          {/* ============================================== */}

          <section
            id="que-es"
            className="public-section"
          >
            <SectionDecorations
              left="🧠"
              right="📊"
              bottom="✧"
            />

            <QueEsMirrorSoul />
          </section>

          {/* ============================================== */}
          {/* PROBLEMÁTICA */}
          {/* ============================================== */}

          <section
            id="problematica"
            className="public-section"
          >
            <SectionDecorations
              left="⚠"
              right="◇"
              bottom="✦"
            />

            <ProblematicaSection />
          </section>

          {/* ============================================== */}
          {/* SOLUCIONES */}
          {/* ============================================== */}

          <section
            id="soluciones"
            className="public-section"
          >
            <SectionDecorations
              left="🤖"
              right="🧠"
              bottom="+"
            />

            <SolucionesSection />
          </section>

          {/* ============================================== */}
          {/* VIDEO DE PRESENTACIÓN */}
          {/* ============================================== */}

          <section
            id="video"
            className="public-section"
          >
            <SectionDecorations
              left="▶"
              right="✧"
              bottom="○"
            />

            <VideoPresentacion />
          </section>

          {/* ============================================== */}
          {/* BENEFICIOS */}
          {/* ============================================== */}

          <section
            id="beneficios"
            className="public-section"
          >
            <SectionDecorations
              left="✓"
              right="📈"
              bottom="✦"
            />

            <BeneficiosSection />
          </section>

          {/* ============================================== */}
          {/* OTROS SERVICIOS */}
          {/* ============================================== */}

          <section
            id="servicios"
            className="public-section"
          >
            <SectionDecorations
              left="💻"
              right="⚙️"
              bottom="🌐"
            />

            <ServiciosTecnologicos />
          </section>

        </main>

        {/* ================================================ */}
        {/* FOOTER */}
        {/* ================================================ */}

        <FooterPublico />

      </div>
    </div>
  );
}

export default InicioMirrorSoul;
