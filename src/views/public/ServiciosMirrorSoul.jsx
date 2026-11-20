import React from "react";
import { useNavigate } from "react-router-dom";

import NavbarPublica
  from "../../components/public/NavbarPublica";

import FooterPublico
  from "../../components/public/FooterPublico";

function ServiciosMirrorSoul() {
  const navigate =
    useNavigate();

  const servicios = [
    {
      icono: "💻",
      titulo: "Equipo de cómputo",
      descripcion:
        "Venta y suministro de equipos para oficinas, negocios y empresas.",
      items: [
        "Laptops",
        "Computadoras de escritorio",
        "Estaciones de trabajo",
        "Monitores",
        "Periféricos",
        "Accesorios",
      ],
    },

    {
      icono: "🧾",
      titulo: "Punto de venta",
      descripcion:
        "Soluciones para comercios y negocios que necesitan controlar su operación y ventas.",
      items: [
        "Licencias de punto de venta",
        "Instalación",
        "Configuración",
        "Impresoras",
        "Lectores",
        "Soporte",
      ],
    },

    {
      icono: "📹",
      titulo: "Cámaras y videovigilancia",
      descripcion:
        "Instalación y configuración de sistemas de seguridad para diferentes espacios.",
      items: [
        "Cámaras IP",
        "Cámaras analógicas",
        "DVR / NVR",
        "Acceso remoto",
        "Configuración",
        "Monitoreo",
      ],
    },

    {
      icono: "🌐",
      titulo: "Redes y conectividad",
      descripcion:
        "Implementación de infraestructura para mantener conectados equipos, usuarios y servicios.",
      items: [
        "Cableado estructurado",
        "Switches",
        "Routers",
        "WiFi",
        "Configuración de red",
        "Diagnóstico",
      ],
    },

    {
      icono: "☎️",
      titulo: "Telefonía empresarial",
      descripcion:
        "Configuración e implementación de soluciones de comunicación para empresas.",
      items: [
        "Telefonía IP",
        "Conmutadores",
        "Extensiones",
        "SIP",
        "Configuración",
        "Soporte",
      ],
    },

    {
      icono: "🛠️",
      titulo: "Soporte técnico",
      descripcion:
        "Atención y solución de problemas tecnológicos dentro de la organización.",
      items: [
        "Hardware",
        "Software",
        "Redes",
        "Configuración",
        "Diagnóstico",
        "Atención de incidencias",
      ],
    },

    {
      icono: "🔧",
      titulo: "Mantenimiento",
      descripcion:
        "Servicios preventivos y correctivos para mantener equipos e infraestructura en mejores condiciones.",
      items: [
        "Mantenimiento preventivo",
        "Mantenimiento correctivo",
        "Limpieza",
        "Optimización",
        "Revisión",
        "Diagnóstico",
      ],
    },

    {
      icono: "⚙️",
      titulo: "Implementación de soluciones",
      descripcion:
        "Diseño y puesta en marcha de soluciones adaptadas a las necesidades de cada empresa.",
      items: [
        "Planeación",
        "Instalación",
        "Configuración",
        "Integración",
        "Capacitación",
        "Acompañamiento",
      ],
    },
  ];

  return (
    <div style={styles.page}>
      <NavbarPublica />

      <main>
        {/* ============================= */}
        {/* HERO */}
        {/* ============================= */}

        <section style={styles.hero}>
          <div style={styles.heroGlowOne} />
          <div style={styles.heroGlowTwo} />

          <div style={styles.heroContent}>
            <span style={styles.eyebrow}>
              SERVICIOS TECNOLÓGICOS
            </span>

            <h1 style={styles.title}>
              Tecnología para que tu empresa
              pueda seguir avanzando.
            </h1>

            <p style={styles.description}>
              Además de MirrorSoul, ofrecemos
              soluciones tecnológicas para
              empresas, negocios y organizaciones
              que requieren infraestructura,
              equipamiento, soporte e implementación.
            </p>

            <div style={styles.heroActions}>
              <button
                type="button"
                style={styles.primaryButton}
                onClick={() =>
                  navigate("/contacto")
                }
              >
                Solicitar cotización
                <span>
                  →
                </span>
              </button>

              <button
                type="button"
                style={styles.secondaryButton}
                onClick={() =>
                  navigate("/")
                }
              >
                ← Volver a MirrorSoul
              </button>
            </div>
          </div>
        </section>

        {/* ============================= */}
        {/* INTRODUCCIÓN */}
        {/* ============================= */}

        <section style={styles.introSection}>
          <div style={styles.container}>
            <div style={styles.introGrid}>
              <div>
                <span style={styles.sectionEyebrow}>
                  SOLUCIONES PARA EMPRESAS
                </span>

                <h2 style={styles.sectionTitle}>
                  Desde el equipo hasta la
                  implementación.
                </h2>

                <p style={styles.sectionText}>
                  Podemos ayudarte a resolver
                  diferentes necesidades tecnológicas
                  dentro de una misma propuesta,
                  evitando trabajar con múltiples
                  proveedores para cada servicio.
                </p>
              </div>

              <div style={styles.introCard}>
                <div style={styles.introRow}>
                  <span style={styles.introIcon}>
                    ✓
                  </span>

                  <div>
                    <strong style={styles.introTitle}>
                      Diagnóstico
                    </strong>

                    <span style={styles.introText}>
                      Identificamos la necesidad
                      antes de implementar.
                    </span>
                  </div>
                </div>

                <div style={styles.introRow}>
                  <span style={styles.introIcon}>
                    ✓
                  </span>

                  <div>
                    <strong style={styles.introTitle}>
                      Implementación
                    </strong>

                    <span style={styles.introText}>
                      Instalamos y configuramos
                      la solución.
                    </span>
                  </div>
                </div>

                <div style={styles.introRow}>
                  <span style={styles.introIcon}>
                    ✓
                  </span>

                  <div>
                    <strong style={styles.introTitle}>
                      Soporte
                    </strong>

                    <span style={styles.introText}>
                      Podemos dar continuidad
                      después de la implementación.
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ============================= */}
        {/* SERVICIOS */}
        {/* ============================= */}

        <section style={styles.servicesSection}>
          <div style={styles.container}>
            <div style={styles.sectionHeading}>
              <span style={styles.sectionEyebrow}>
                NUESTROS SERVICIOS
              </span>

              <h2 style={styles.sectionTitle}>
                Soluciones para diferentes
                necesidades tecnológicas.
              </h2>

              <p style={styles.sectionText}>
                Cada servicio puede contratarse
                de forma independiente o combinarse
                dentro de una solución personalizada.
              </p>
            </div>

            <div style={styles.grid}>
              {servicios.map(
                (
                  servicio,
                  index
                ) => (
                  <article
                    key={index}
                    style={styles.card}
                  >
                    <div style={styles.cardTop}>
                      <div style={styles.iconBox}>
                        {servicio.icono}
                      </div>

                      <span style={styles.number}>
                        {String(index + 1).padStart(
                          2,
                          "0"
                        )}
                      </span>
                    </div>

                    <h3 style={styles.cardTitle}>
                      {servicio.titulo}
                    </h3>

                    <p style={styles.cardDescription}>
                      {servicio.descripcion}
                    </p>

                    <div style={styles.divider} />

                    <div style={styles.items}>
                      {servicio.items.map(
                        (
                          item,
                          itemIndex
                        ) => (
                          <div
                            key={itemIndex}
                            style={styles.item}
                          >
                            <span style={styles.check}>
                              ✓
                            </span>

                            <span>
                              {item}
                            </span>
                          </div>
                        )
                      )}
                    </div>
                  </article>
                )
              )}
            </div>
          </div>
        </section>

        {/* ============================= */}
        {/* PROCESO */}
        {/* ============================= */}

        <section style={styles.processSection}>
          <div style={styles.container}>
            <div style={styles.processCard}>
              <div style={styles.processHeading}>
                <span style={styles.sectionEyebrow}>
                  ¿CÓMO TRABAJAMOS?
                </span>

                <h2 style={styles.processTitle}>
                  Una solución diseñada alrededor
                  de la necesidad de tu empresa.
                </h2>
              </div>

              <div style={styles.processGrid}>
                <div style={styles.processItem}>
                  <span style={styles.processNumber}>
                    01
                  </span>

                  <strong style={styles.processItemTitle}>
                    Escuchamos
                  </strong>

                  <p style={styles.processText}>
                    Conocemos la necesidad,
                    infraestructura y objetivo.
                  </p>
                </div>

                <div style={styles.processLine} />

                <div style={styles.processItem}>
                  <span style={styles.processNumber}>
                    02
                  </span>

                  <strong style={styles.processItemTitle}>
                    Proponemos
                  </strong>

                  <p style={styles.processText}>
                    Diseñamos una solución
                    adecuada al entorno.
                  </p>
                </div>

                <div style={styles.processLine} />

                <div style={styles.processItem}>
                  <span style={styles.processNumber}>
                    03
                  </span>

                  <strong style={styles.processItemTitle}>
                    Implementamos
                  </strong>

                  <p style={styles.processText}>
                    Instalamos, configuramos
                    y dejamos operativa la solución.
                  </p>
                </div>

                <div style={styles.processLine} />

                <div style={styles.processItem}>
                  <span style={styles.processNumber}>
                    04
                  </span>

                  <strong style={styles.processItemTitle}>
                    Acompañamos
                  </strong>

                  <p style={styles.processText}>
                    Podemos continuar con soporte
                    y mantenimiento.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ============================= */}
        {/* COMBINACIÓN CON MIRRORSOUL */}
        {/* ============================= */}

        <section style={styles.combineSection}>
          <div style={styles.container}>
            <div style={styles.combineCard}>
              <div style={styles.combineContent}>
                <span style={styles.combineEyebrow}>
                  SOLUCIÓN INTEGRAL
                </span>

                <h2 style={styles.combineTitle}>
                  También podemos combinar
                  tecnología y MirrorSoul.
                </h2>

                <p style={styles.combineText}>
                  Una empresa puede contratar
                  MirrorSoul y complementar la
                  implementación con equipamiento,
                  infraestructura, redes, seguridad
                  o soporte tecnológico.
                </p>

                <div style={styles.combineTags}>
                  <span style={styles.tag}>
                    MirrorSoul
                  </span>

                  <span style={styles.plus}>
                    +
                  </span>

                  <span style={styles.tag}>
                    Equipamiento
                  </span>

                  <span style={styles.plus}>
                    +
                  </span>

                  <span style={styles.tag}>
                    Implementación
                  </span>

                  <span style={styles.plus}>
                    +
                  </span>

                  <span style={styles.tag}>
                    Soporte
                  </span>
                </div>
              </div>

              <div style={styles.combineVisual}>
                <div style={styles.centerCircle}>
                  <div style={styles.centerLogo}>
                    M
                  </div>

                  <strong style={styles.centerTitle}>
                    Solución empresarial
                  </strong>
                </div>

                <div style={styles.solutionGrid}>
                  <div style={styles.solutionBox}>
                    💻
                    <span>
                      Equipo
                    </span>
                  </div>

                  <div style={styles.solutionBox}>
                    🌐
                    <span>
                      Red
                    </span>
                  </div>

                  <div style={styles.solutionBox}>
                    📹
                    <span>
                      Seguridad
                    </span>
                  </div>

                  <div style={styles.solutionBox}>
                    🛠️
                    <span>
                      Soporte
                    </span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ============================= */}
        {/* CTA */}
        {/* ============================= */}

        <section style={styles.ctaSection}>
          <div style={styles.container}>
            <div style={styles.cta}>
              <span style={styles.ctaEyebrow}>
                ¿TIENES UN PROYECTO?
              </span>

              <h2 style={styles.ctaTitle}>
                Cuéntanos qué necesitas.
              </h2>

              <p style={styles.ctaText}>
                Podemos preparar una propuesta
                de acuerdo con la infraestructura,
                servicios y alcance de tu proyecto.
              </p>

              <button
                type="button"
                style={styles.ctaButton}
                onClick={() =>
                  navigate("/contacto")
                }
              >
                Solicitar cotización
                <span>
                  →
                </span>
              </button>
            </div>
          </div>
        </section>
      </main>

      <FooterPublico />
    </div>
  );
}

const styles = {
  page: {
    minHeight: "100vh",

    background:
      "linear-gradient(180deg,#07111f,#091624)",

    color: "#ffffff",

    fontFamily:
      "'Inter','Segoe UI',Arial,sans-serif",
  },

  hero: {
    position: "relative",

    overflow: "hidden",

    padding:
      "115px 28px 100px",

    background:
      "radial-gradient(circle at 50% 0%,rgba(244,189,114,.10),transparent 38%),linear-gradient(180deg,#07111f,#091522)",
  },

  heroGlowOne: {
    position: "absolute",

    width: "420px",
    height: "420px",

    borderRadius: "50%",

    left: "-160px",
    top: "-180px",

    background:
      "rgba(244,189,114,.06)",

    filter:
      "blur(110px)",
  },

  heroGlowTwo: {
    position: "absolute",

    width: "420px",
    height: "420px",

    borderRadius: "50%",

    right: "-160px",
    bottom: "-190px",

    background:
      "rgba(143,125,255,.07)",

    filter:
      "blur(115px)",
  },

  heroContent: {
    position: "relative",

    zIndex: 2,

    maxWidth: "880px",

    margin: "0 auto",

    textAlign: "center",
  },

  eyebrow: {
    display: "inline-block",

    marginBottom: "16px",

    color: "#f4bd72",

    fontSize: "10px",

    fontWeight: "900",

    letterSpacing:
      "1.8px",
  },

  title: {
    margin: 0,

    color: "#ffffff",

    fontSize:
      "clamp(42px,5vw,66px)",

    lineHeight: 1.04,

    fontWeight: "900",

    letterSpacing:
      "-2px",
  },

  description: {
    maxWidth: "760px",

    margin:
      "24px auto 0",

    color:
      "rgba(255,255,255,.56)",

    fontSize: "16px",

    lineHeight: 1.75,
  },

  heroActions: {
    display: "flex",

    justifyContent: "center",

    flexWrap: "wrap",

    gap: "12px",

    marginTop: "32px",
  },

  primaryButton: {
    padding:
      "14px 20px",

    border: "none",

    borderRadius: "11px",

    background:
      "linear-gradient(135deg,#f5bd73,#9d84ff)",

    color: "#07111f",

    fontWeight: "900",

    cursor: "pointer",

    display: "flex",

    alignItems: "center",

    gap: "9px",
  },

  secondaryButton: {
    padding:
      "13px 18px",

    borderRadius: "11px",

    border:
      "1px solid rgba(255,255,255,.09)",

    background:
      "rgba(255,255,255,.03)",

    color: "#ffffff",

    fontWeight: "800",

    cursor: "pointer",
  },

  container: {
    maxWidth: "1280px",

    margin: "0 auto",
  },

  introSection: {
    padding:
      "95px 28px 40px",
  },

  introGrid: {
    display: "grid",

    gridTemplateColumns:
      "1fr .8fr",

    gap: "60px",

    alignItems: "center",
  },

  sectionEyebrow: {
    display: "block",

    marginBottom: "11px",

    color:
      "rgba(244,189,114,.74)",

    fontSize: "9px",

    fontWeight: "900",

    letterSpacing:
      "1.5px",
  },

  sectionTitle: {
    margin: 0,

    color: "#ffffff",

    fontSize:
      "clamp(32px,4vw,49px)",

    lineHeight: 1.1,

    fontWeight: "900",

    letterSpacing:
      "-1.2px",
  },

  sectionText: {
    maxWidth: "700px",

    margin:
      "16px 0 0",

    color:
      "rgba(255,255,255,.47)",

    fontSize: "13px",

    lineHeight: 1.75,
  },

  introCard: {
    padding: "24px",

    borderRadius: "20px",

    background:
      "rgba(255,255,255,.025)",

    border:
      "1px solid rgba(255,255,255,.055)",
  },

  introRow: {
    display: "flex",

    alignItems: "center",

    gap: "12px",

    padding:
      "13px 0",

    borderBottom:
      "1px solid rgba(255,255,255,.045)",
  },

  introIcon: {
    width: "32px",
    height: "32px",

    flexShrink: 0,

    display: "flex",

    alignItems: "center",

    justifyContent: "center",

    borderRadius: "10px",

    background:
      "rgba(244,189,114,.06)",

    color: "#f4bd72",

    fontSize: "10px",

    fontWeight: "900",
  },

  introTitle: {
    display: "block",

    color: "#ffffff",

    fontSize: "11px",

    fontWeight: "900",
  },

  introText: {
    display: "block",

    marginTop: "3px",

    color:
      "rgba(255,255,255,.36)",

    fontSize: "9px",
  },

  servicesSection: {
    padding:
      "70px 28px 100px",
  },

  sectionHeading: {
    maxWidth: "800px",

    marginBottom: "45px",
  },

  grid: {
    display: "grid",

    gridTemplateColumns:
      "repeat(4,1fr)",

    gap: "17px",
  },

  card: {
    minHeight: "380px",

    padding: "24px",

    display: "flex",

    flexDirection: "column",

    borderRadius: "21px",

    background:
      "linear-gradient(145deg,rgba(255,255,255,.027),rgba(255,255,255,.015))",

    border:
      "1px solid rgba(255,255,255,.06)",
  },

  cardTop: {
    display: "flex",

    alignItems: "center",

    justifyContent:
      "space-between",

    marginBottom: "18px",
  },

  iconBox: {
    width: "47px",
    height: "47px",

    display: "flex",

    alignItems: "center",

    justifyContent: "center",

    borderRadius: "14px",

    background:
      "rgba(244,189,114,.06)",

    border:
      "1px solid rgba(244,189,114,.08)",

    fontSize: "21px",
  },

  number: {
    color:
      "rgba(255,255,255,.17)",

    fontSize: "10px",

    fontWeight: "900",
  },

  cardTitle: {
    margin: 0,

    color: "#ffffff",

    fontSize: "17px",

    fontWeight: "900",

    lineHeight: 1.3,
  },

  cardDescription: {
    margin:
      "10px 0 0",

    color:
      "rgba(255,255,255,.44)",

    fontSize: "11px",

    lineHeight: 1.65,
  },

  divider: {
    height: "1px",

    margin:
      "18px 0",

    background:
      "rgba(255,255,255,.05)",
  },

  items: {
    display: "grid",

    gap: "8px",

    marginTop: "auto",
  },

  item: {
    display: "flex",

    alignItems: "center",

    gap: "8px",

    color:
      "rgba(255,255,255,.50)",

    fontSize: "9px",
  },

  check: {
    width: "18px",
    height: "18px",

    flexShrink: 0,

    display: "flex",

    alignItems: "center",

    justifyContent: "center",

    borderRadius: "6px",

    background:
      "rgba(244,189,114,.05)",

    color: "#f4bd72",

    fontSize: "7px",

    fontWeight: "900",
  },

  processSection: {
    padding:
      "0 28px 100px",
  },

  processCard: {
    padding: "38px",

    borderRadius: "27px",

    background:
      "linear-gradient(145deg,rgba(35,29,23,.92),rgba(8,18,29,.98))",

    border:
      "1px solid rgba(244,189,114,.08)",
  },

  processHeading: {
    maxWidth: "680px",

    marginBottom: "38px",
  },

  processTitle: {
    margin: 0,

    color: "#ffffff",

    fontSize: "31px",

    lineHeight: 1.2,

    fontWeight: "900",

    letterSpacing:
      "-.8px",
  },

  processGrid: {
    display: "flex",

    alignItems: "center",
  },

  processItem: {
    width: "190px",

    flexShrink: 0,

    textAlign: "center",
  },

  processNumber: {
    width: "42px",
    height: "42px",

    margin:
      "0 auto 12px",

    display: "flex",

    alignItems: "center",

    justifyContent: "center",

    borderRadius: "13px",

    background:
      "rgba(244,189,114,.07)",

    border:
      "1px solid rgba(244,189,114,.10)",

    color: "#f4bd72",

    fontSize: "9px",

    fontWeight: "900",
  },

  processItemTitle: {
    display: "block",

    color: "#ffffff",

    fontSize: "12px",

    fontWeight: "900",
  },

  processText: {
    margin:
      "6px 0 0",

    color:
      "rgba(255,255,255,.37)",

    fontSize: "9px",

    lineHeight: 1.5,
  },

  processLine: {
    flex: 1,

    height: "1px",

    margin:
      "0 10px 44px",

    background:
      "linear-gradient(90deg,rgba(244,189,114,.14),rgba(143,125,255,.14))",
  },

  combineSection: {
    padding:
      "0 28px 100px",
  },

  combineCard: {
    padding: "40px",

    display: "grid",

    gridTemplateColumns:
      "1fr .8fr",

    gap: "55px",

    alignItems: "center",

    borderRadius: "28px",

    background:
      "linear-gradient(145deg,rgba(18,35,52,.96),rgba(7,17,28,.99))",

    border:
      "1px solid rgba(255,255,255,.07)",
  },

  combineContent: {
    maxWidth: "620px",
  },

  combineEyebrow: {
    display: "block",

    marginBottom: "10px",

    color: "#72e9ff",

    fontSize: "9px",

    fontWeight: "900",

    letterSpacing:
      "1.5px",
  },

  combineTitle: {
    margin: 0,

    color: "#ffffff",

    fontSize: "31px",

    lineHeight: 1.2,

    fontWeight: "900",

    letterSpacing:
      "-.8px",
  },

  combineText: {
    margin:
      "16px 0 0",

    color:
      "rgba(255,255,255,.48)",

    fontSize: "13px",

    lineHeight: 1.7,
  },

  combineTags: {
    display: "flex",

    flexWrap: "wrap",

    alignItems: "center",

    gap: "8px",

    marginTop: "24px",
  },

  tag: {
    padding:
      "8px 10px",

    borderRadius: "9px",

    background:
      "rgba(255,255,255,.035)",

    border:
      "1px solid rgba(255,255,255,.055)",

    color:
      "rgba(255,255,255,.60)",

    fontSize: "9px",

    fontWeight: "800",
  },

  plus: {
    color:
      "rgba(255,255,255,.22)",

    fontWeight: "900",
  },

  combineVisual: {
    padding: "24px",

    borderRadius: "20px",

    background:
      "rgba(4,13,22,.50)",

    border:
      "1px solid rgba(255,255,255,.05)",
  },

  centerCircle: {
    width: "145px",
    height: "145px",

    margin:
      "0 auto 22px",

    borderRadius: "50%",

    display: "flex",

    flexDirection: "column",

    alignItems: "center",

    justifyContent: "center",

    background:
      "linear-gradient(145deg,rgba(102,229,255,.08),rgba(244,189,114,.07))",

    border:
      "1px solid rgba(102,229,255,.08)",
  },

  centerLogo: {
    width: "45px",
    height: "45px",

    display: "flex",

    alignItems: "center",

    justifyContent: "center",

    borderRadius: "14px",

    background:
      "linear-gradient(135deg,#65e5ff,#f4bd72)",

    color: "#07111f",

    fontWeight: "900",

    marginBottom: "8px",
  },

  centerTitle: {
    color: "#ffffff",

    fontSize: "10px",

    fontWeight: "900",
  },

  solutionGrid: {
    display: "grid",

    gridTemplateColumns:
      "repeat(4,1fr)",

    gap: "8px",
  },

  solutionBox: {
    minHeight: "68px",

    display: "flex",

    flexDirection: "column",

    alignItems: "center",

    justifyContent: "center",

    gap: "5px",

    borderRadius: "11px",

    background:
      "rgba(255,255,255,.027)",

    border:
      "1px solid rgba(255,255,255,.05)",

    color:
      "rgba(255,255,255,.52)",

    fontSize: "16px",
  },

  ctaSection: {
    padding:
      "0 28px 110px",
  },

  cta: {
    maxWidth: "820px",

    margin: "0 auto",

    padding: "45px",

    textAlign: "center",

    borderRadius: "27px",

    background:
      "linear-gradient(135deg,rgba(244,189,114,.07),rgba(143,125,255,.06))",

    border:
      "1px solid rgba(244,189,114,.08)",
  },

  ctaEyebrow: {
    color:
      "rgba(244,189,114,.75)",

    fontSize: "9px",

    fontWeight: "900",

    letterSpacing:
      "1.5px",
  },

  ctaTitle: {
    margin:
      "9px 0 0",

    color: "#ffffff",

    fontSize: "32px",

    fontWeight: "900",
  },

  ctaText: {
    maxWidth: "600px",

    margin:
      "13px auto 0",

    color:
      "rgba(255,255,255,.46)",

    fontSize: "12px",

    lineHeight: 1.7,
  },

  ctaButton: {
    marginTop: "23px",

    border: "none",

    padding:
      "14px 20px",

    borderRadius: "11px",

    background:
      "linear-gradient(135deg,#f4bd72,#9c84ff)",

    color: "#07111f",

    fontWeight: "900",

    cursor: "pointer",

    display: "inline-flex",

    alignItems: "center",

    gap: "9px",
  },
};

export default ServiciosMirrorSoul;