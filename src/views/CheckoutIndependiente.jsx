// src/views/CheckoutIndependiente.jsx

import React, { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";

const API_URL =
  import.meta.env.VITE_API_URL ||
  `${import.meta.env.VITE_API_URL || window.location.origin}`;

const PLAN_INDEPENDIENTE_ID = 4;

const CheckoutIndependiente = () => {
  const navigate = useNavigate();

  const [registro, setRegistro] = useState(null);
  const [periodo, setPeriodo] = useState("mensual");
  const [loading, setLoading] = useState(false);
  const [consultando, setConsultando] = useState(false);
  const [error, setError] = useState("");
  const [pago, setPago] = useState(null);

  useEffect(() => {
    try {
      const guardado =
        sessionStorage.getItem(
          "registro_independiente"
        );

      if (!guardado) {
        return;
      }

      setRegistro(
        JSON.parse(guardado)
      );

    } catch (err) {
      console.error(
        "❌ Error leyendo registro independiente:",
        err
      );
    }
  }, []);

  const perfil =
    registro?.perfil_independiente ||
    registro?.organizacion?.perfil_independiente ||
    "";

  const esClinica =
    perfil === "clinica";

  const esRH =
    perfil === "rh";

  const idUsuario =
    Number(
      registro?.usuario?.id_usuario ||
      registro?.id_usuario
    ) || null;

  const idOrganizacion =
    Number(
      registro?.organizacion?.id_organizacion ||
      registro?.usuario?.id_organizacion ||
      registro?.id_organizacion
    ) || null;

  const fondo = useMemo(
    () => {
      if (esClinica) {
        return "radial-gradient(circle at 15% 20%,rgba(105,170,255,.23),transparent 34%),radial-gradient(circle at 85% 10%,rgba(176,132,255,.18),transparent 30%),linear-gradient(135deg,#F8FBFF 0%,#EEF5FF 48%,#F7F1FF 100%)";
      }

      if (esRH) {
        return "radial-gradient(circle at 15% 20%,rgba(45,93,154,.18),transparent 34%),radial-gradient(circle at 85% 10%,rgba(93,75,180,.16),transparent 30%),linear-gradient(135deg,#F7FAFD 0%,#EDF3F8 48%,#F3F0FA 100%)";
      }

      return "linear-gradient(135deg,#F9FBFF,#F3F6FB)";
    },
    [esClinica, esRH]
  );

  const crearCheckout = async () => {
    try {
      setLoading(true);
      setError("");

      if (
        !idUsuario ||
        !idOrganizacion
      ) {
        throw new Error(
          "No se encontraron los datos del registro. Regresa y crea tu cuenta nuevamente."
        );
      }

      const response =
        await fetch(
          `${API_URL}/api/checkout`,
          {
            method: "POST",
            headers: {
              "Content-Type":
                "application/json"
            },
            body: JSON.stringify({
              id_usuario:
                idUsuario,
              id_organizacion:
                idOrganizacion,
              id_plan:
                PLAN_INDEPENDIENTE_ID,
              periodo
            })
          }
        );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data?.message ||
          "No se pudo generar el checkout."
        );
      }

      const pagoCreado =
        data?.pago ||
        data;

      setPago(
        pagoCreado
      );

      sessionStorage.setItem(
        "checkout_independiente",
        JSON.stringify(
          pagoCreado
        )
      );

    } catch (err) {
      console.error(
        "❌ Error creando checkout:",
        err
      );

      setError(
        err.message ||
        "No se pudo iniciar el pago."
      );

    } finally {
      setLoading(false);
    }
  };

  const obtenerIdPago = () =>
    Number(
      pago?.id_pago ||
      pago?.pago?.id_pago ||
      pago?.checkout?.id_pago
    ) || null;

  const consultarEstado = async () => {
    const idPago =
      obtenerIdPago();

    if (!idPago) {
      setError(
        "No se encontró el ID del pago."
      );
      return;
    }

    try {
      setConsultando(true);
      setError("");

      const response =
        await fetch(
          `${API_URL}/api/checkout/${idPago}`
        );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data?.message ||
          "No se pudo consultar el pago."
        );
      }

      const actualizado =
        data?.pago ||
        data;

      setPago(
        actualizado
      );

      sessionStorage.setItem(
        "checkout_independiente",
        JSON.stringify(
          actualizado
        )
      );

    } catch (err) {
      console.error(
        "❌ Error consultando checkout:",
        err
      );

      setError(
        err.message ||
        "No se pudo consultar el estado."
      );

    } finally {
      setConsultando(false);
    }
  };

  const estadoPago =
    String(
      pago?.estado ||
      pago?.pago?.estado ||
      ""
    )
      .trim()
      .toLowerCase();

  const aprobado =
    [
      "approved",
      "aprobado",
      "pagado"
    ].includes(
      estadoPago
    );

  if (!registro) {
    return (
      <div
        style={{
          ...styles.page,
          background: fondo
        }}
      >
        <div style={styles.emptyCard}>
          <img
            src="/logo.png"
            alt="MirrorSoul"
            style={styles.logoLarge}
          />

          <div style={styles.emptyIcon}>
            ⚠️
          </div>

          <h1 style={styles.emptyTitle}>
            No encontramos tu registro
          </h1>

          <p style={styles.emptyText}>
            Para continuar al checkout primero
            necesitas crear tu cuenta independiente.
          </p>

          <button
            type="button"
            style={styles.primaryButton}
            onClick={() =>
              navigate(
                "/independiente/registro"
              )
            }
          >
            Ir al registro
          </button>
        </div>
      </div>
    );
  }

  return (
    <div
      style={{
        ...styles.page,
        background: fondo
      }}
    >
      <DecorativeBackground
        perfil={perfil}
      />

      <div style={styles.shell}>
        <header style={styles.header}>
          <button
            type="button"
            style={styles.backButton}
            onClick={() =>
              navigate(
                "/independiente/registro"
              )
            }
          >
            ← Volver
          </button>

          <div style={styles.logoWrap}>
            <img
              src="/logo.png"
              alt="MirrorSoul"
              style={styles.logo}
            />
          </div>

          <button
            type="button"
            style={styles.loginButton}
            onClick={() =>
              navigate("/")
            }
          >
            Iniciar sesión
          </button>
        </header>

        <div style={styles.progress}>
          <div style={styles.progressLine}>
            <div style={styles.progressFill} />
          </div>

          <div style={styles.progressLabels}>
            <span style={styles.progressDone}>
              01. Perfil
            </span>

            <span style={styles.progressDone}>
              02. Cuenta
            </span>

            <span style={styles.progressActive}>
              03. Activación
            </span>
          </div>
        </div>

        <main style={styles.content}>
          <section style={styles.hero}>
            <div style={styles.profileBadge}>
              {esClinica
                ? "🧠 Psicología / Clínica"
                : "👥 Recursos Humanos"}
            </div>

            <h1 style={styles.title}>
              Activa tu espacio profesional
            </h1>

            <p style={styles.subtitle}>
              Revisa tu información y continúa
              con la activación de tu plan
              independiente.
            </p>
          </section>

          <div style={styles.checkoutGrid}>
            <section style={styles.card}>
              <div style={styles.cardEyebrow}>
                TU CUENTA
              </div>

              <h2 style={styles.cardTitle}>
                Resumen del registro
              </h2>

              <div style={styles.infoList}>
                <InfoRow
                  label="Titular"
                  value={
                    registro?.nombre ||
                    registro?.usuario?.nombre ||
                    "—"
                  }
                />

                <InfoRow
                  label="Correo"
                  value={
                    registro?.correo ||
                    registro?.usuario?.correo ||
                    "—"
                  }
                />

                <InfoRow
                  label="Espacio"
                  value={
                    registro?.nombre_practica ||
                    registro?.organizacion?.nombre_comercial ||
                    registro?.organizacion?.nombre ||
                    "—"
                  }
                />

                <InfoRow
                  label="Perfil"
                  value={
                    esClinica
                      ? "Psicología / Clínica"
                      : "Recursos Humanos"
                  }
                />
              </div>

              <div style={styles.secureBox}>
                <span>🔐</span>

                <div>
                  <strong>
                    Tu cuenta está protegida
                  </strong>

                  <p style={styles.secureText}>
                    La activación se asociará
                    únicamente a esta organización.
                  </p>
                </div>
              </div>
            </section>

            <section style={styles.planCard}>
              <div style={styles.planTop}>
                <div>
                  <div style={styles.cardEyebrow}>
                    PLAN SELECCIONADO
                  </div>

                  <h2 style={styles.planTitle}>
                    Independiente
                  </h2>
                </div>

                <div style={styles.planIcon}>
                  {esClinica
                    ? "🧠"
                    : "👥"}
                </div>
              </div>

              <div style={styles.planFeatures}>
                <Feature text="1 licencia profesional" />
                <Feature text="Cuenta independiente" />
                <Feature text="Acceso según tu perfil" />
                <Feature text="Sin administrador adicional" />
              </div>

              {!pago && (
                <>
                  <div style={styles.periodTitle}>
                    Periodicidad
                  </div>

                  <div style={styles.periodGrid}>
                    <button
                      type="button"
                      style={{
                        ...styles.periodButton,
                        ...(periodo === "mensual"
                          ? styles.periodSelected
                          : {})
                      }}
                      onClick={() =>
                        setPeriodo(
                          "mensual"
                        )
                      }
                    >
                      <span style={styles.periodMain}>
                        Mensual
                      </span>

                      <span style={styles.periodSub}>
                        Renovación cada mes
                      </span>
                    </button>

                    <button
                      type="button"
                      style={{
                        ...styles.periodButton,
                        ...(periodo === "anual"
                          ? styles.periodSelected
                          : {})
                      }}
                      onClick={() =>
                        setPeriodo(
                          "anual"
                        )
                      }
                    >
                      <span style={styles.periodMain}>
                        Anual
                      </span>

                      <span style={styles.periodSub}>
                        Renovación cada año
                      </span>
                    </button>
                  </div>

                  {error && (
                    <div style={styles.errorBox}>
                      ⚠️ {error}
                    </div>
                  )}

                  <button
                    type="button"
                    disabled={loading}
                    style={{
                      ...styles.primaryButton,
                      opacity:
                        loading
                          ? .65
                          : 1,
                      cursor:
                        loading
                          ? "not-allowed"
                          : "pointer"
                    }}
                    onClick={
                      crearCheckout
                    }
                  >
                    {loading
                      ? "Generando activación..."
                      : "Continuar con la activación →"}
                  </button>
                </>
              )}

              {pago && (
                <div style={styles.paymentBox}>
                  <div
                    style={{
                      ...styles.statusIcon,
                      ...(aprobado
                        ? styles.statusIconApproved
                        : {})
                    }}
                  >
                    {aprobado
                      ? "✓"
                      : "⏳"}
                  </div>

                  <div style={styles.paymentEyebrow}>
                    {aprobado
                      ? "PAGO CONFIRMADO"
                      : "ACTIVACIÓN PENDIENTE"}
                  </div>

                  <h3 style={styles.paymentTitle}>
                    {aprobado
                      ? "Tu cuenta ya está activa"
                      : "Tu solicitud fue creada"}
                  </h3>

                  <p style={styles.paymentText}>
                    {aprobado
                      ? "La activación fue confirmada. Ya puedes iniciar sesión con tu correo y contraseña."
                      : "Por ahora el pago se aprueba manualmente desde Administración Comercial. Puedes consultar el estado desde aquí."}
                  </p>

                  <div style={styles.paymentDetails}>
                    <InfoRow
                      label="ID de pago"
                      value={
                        obtenerIdPago() ||
                        "—"
                      }
                    />

                    <InfoRow
                      label="Estado"
                      value={
                        estadoPago ||
                        "pendiente"
                      }
                    />

                    <InfoRow
                      label="Periodo"
                      value={periodo}
                    />
                  </div>

                  {error && (
                    <div style={styles.errorBox}>
                      ⚠️ {error}
                    </div>
                  )}

                  {aprobado ? (
                    <button
                      type="button"
                      style={styles.primaryButton}
                      onClick={() =>
                        navigate("/")
                      }
                    >
                      Iniciar sesión →
                    </button>
                  ) : (
                    <button
                      type="button"
                      disabled={consultando}
                      style={{
                        ...styles.secondaryButton,
                        opacity:
                          consultando
                            ? .65
                            : 1
                      }}
                      onClick={
                        consultarEstado
                      }
                    >
                      {consultando
                        ? "Consultando..."
                        : "Actualizar estado"}
                    </button>
                  )}
                </div>
              )}
            </section>
          </div>
        </main>
      </div>
    </div>
  );
};

const DecorativeBackground = ({
  perfil
}) => {
  const clinica =
    perfil === "clinica";

  const elementos =
    clinica
      ? [
          { icon: "🧠", top: "17%", left: "4%", delay: 0 },
          { icon: "😊", top: "31%", right: "5%", delay: .7 },
          { icon: "❤️", bottom: "16%", left: "7%", delay: 1.2 },
          { icon: "✨", bottom: "12%", right: "8%", delay: .4 }
        ]
      : [
          { icon: "👥", top: "17%", left: "4%", delay: 0 },
          { icon: "📊", top: "31%", right: "5%", delay: .7 },
          { icon: "💼", bottom: "16%", left: "7%", delay: 1.2 },
          { icon: "✅", bottom: "12%", right: "8%", delay: .4 }
        ];

  return (
    <>
      {elementos.map(
        (
          item,
          index
        ) => (
          <motion.div
            key={`${item.icon}-${index}`}
            style={{
              ...styles.floatIcon,
              top: item.top,
              bottom: item.bottom,
              left: item.left,
              right: item.right
            }}
            animate={{
              y: [
                0,
                -12,
                0
              ],
              rotate: [
                -3,
                3,
                -3
              ],
              opacity: [
                .38,
                .7,
                .38
              ]
            }}
            transition={{
              duration:
                5 + index * .5,
              delay:
                item.delay,
              repeat:
                Infinity,
              ease:
                "easeInOut"
            }}
          >
            {item.icon}
          </motion.div>
        )
      )}
    </>
  );
};

const InfoRow = ({
  label,
  value
}) => (
  <div style={styles.infoRow}>
    <span style={styles.infoLabel}>
      {label}
    </span>

    <strong style={styles.infoValue}>
      {value}
    </strong>
  </div>
);

const Feature = ({
  text
}) => (
  <div style={styles.feature}>
    <span style={styles.check}>
      ✓
    </span>

    <span>{text}</span>
  </div>
);

const styles = {
  page: {
    minHeight: "100vh",
    position: "relative",
    overflow: "hidden",
    fontFamily:
      "'Inter','Segoe UI',Arial,sans-serif",
    color: "#17243B",
    transition: "background .5s ease"
  },

  shell: {
    width:
      "min(1160px,calc(100% - 40px))",
    margin: "0 auto",
    position: "relative",
    zIndex: 2,
    paddingBottom: 60
  },

  header: {
    minHeight: 118,
    display: "grid",
    gridTemplateColumns:
      "1fr auto 1fr",
    alignItems: "center",
    borderBottom:
      "1px solid rgba(215,224,236,.78)"
  },

  logoWrap: {
    justifySelf: "center",
    minWidth: 250,
    minHeight: 92,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    borderRadius: 20,
    padding: "6px 18px",
    background:
      "rgba(255,255,255,.65)",
    border:
      "1px solid rgba(255,255,255,.9)",
    boxShadow:
      "0 12px 34px rgba(45,70,115,.10)",
    backdropFilter: "blur(14px)"
  },

  logo: {
    width: 230,
    maxWidth: "42vw",
    height: 82,
    objectFit: "contain",
    filter:
      "drop-shadow(0 8px 16px rgba(40,70,120,.16))"
  },

  logoLarge: {
    width: 230,
    maxWidth: "70%",
    objectFit: "contain",
    marginBottom: 20
  },

  backButton: {
    justifySelf: "start",
    border: "none",
    background: "transparent",
    color: "#516079",
    fontSize: 14,
    fontWeight: 700,
    cursor: "pointer"
  },

  loginButton: {
    justifySelf: "end",
    border:
      "1px solid rgba(216,224,235,.95)",
    background:
      "rgba(255,255,255,.82)",
    color: "#34465F",
    borderRadius: 9,
    padding: "10px 16px",
    fontSize: 13,
    fontWeight: 700,
    cursor: "pointer",
    backdropFilter: "blur(10px)"
  },

  progress: {
    width: "min(650px,100%)",
    margin: "30px auto 0"
  },

  progressLine: {
    height: 3,
    background: "#E1E7F0",
    borderRadius: 20,
    overflow: "hidden"
  },

  progressFill: {
    width: "100%",
    height: "100%",
    background:
      "linear-gradient(90deg,#3E76E3,#6D5AD7)"
  },

  progressLabels: {
    display: "flex",
    justifyContent: "space-between",
    marginTop: 9,
    fontSize: 10,
    fontWeight: 850,
    letterSpacing: ".06em"
  },

  progressDone: {
    color: "#6F80A0"
  },

  progressActive: {
    color: "#416DD2"
  },

  content: {
    width: "min(980px,100%)",
    margin: "48px auto 0"
  },

  hero: {
    textAlign: "center",
    maxWidth: 650,
    margin: "0 auto 30px"
  },

  profileBadge: {
    display: "inline-block",
    padding: "8px 14px",
    borderRadius: 30,
    background:
      "rgba(255,255,255,.72)",
    border:
      "1px solid rgba(255,255,255,.92)",
    color: "#426DCC",
    fontSize: 12,
    fontWeight: 800,
    boxShadow:
      "0 8px 24px rgba(40,65,110,.08)",
    backdropFilter: "blur(10px)"
  },

  title: {
    margin: "16px 0 8px",
    fontSize:
      "clamp(32px,5vw,46px)",
    color: "#203653",
    letterSpacing: "-1.3px"
  },

  subtitle: {
    maxWidth: 570,
    margin: "0 auto",
    color: "#718097",
    fontSize: 14,
    lineHeight: 1.65
  },

  checkoutGrid: {
    display: "grid",
    gridTemplateColumns:
      "minmax(0,.9fr) minmax(0,1.1fr)",
    gap: 22,
    alignItems: "start"
  },

  card: {
    background:
      "rgba(255,255,255,.86)",
    border:
      "1px solid rgba(255,255,255,.92)",
    borderRadius: 22,
    padding: 28,
    boxShadow:
      "0 20px 55px rgba(25,45,80,.08)",
    backdropFilter: "blur(16px)"
  },

  planCard: {
    background:
      "rgba(255,255,255,.92)",
    border:
      "1px solid rgba(255,255,255,.95)",
    borderRadius: 22,
    padding: 30,
    boxShadow:
      "0 22px 60px rgba(25,45,80,.11)",
    backdropFilter: "blur(18px)"
  },

  cardEyebrow: {
    color: "#72829A",
    fontSize: 10,
    fontWeight: 900,
    letterSpacing: ".12em",
    marginBottom: 8
  },

  cardTitle: {
    margin: "0 0 22px",
    color: "#263B59",
    fontSize: 22
  },

  infoList: {
    display: "grid"
  },

  infoRow: {
    display: "flex",
    justifyContent:
      "space-between",
    gap: 15,
    padding: "13px 0",
    borderBottom:
      "1px solid #EDF1F5"
  },

  infoLabel: {
    color: "#8793A5",
    fontSize: 12
  },

  infoValue: {
    color: "#40516A",
    fontSize: 12,
    textAlign: "right",
    wordBreak: "break-word"
  },

  secureBox: {
    display: "flex",
    gap: 11,
    marginTop: 22,
    padding: 14,
    borderRadius: 11,
    background: "#F4F7FB",
    color: "#455871",
    fontSize: 12
  },

  secureText: {
    margin: "4px 0 0",
    color: "#7C899B",
    fontSize: 11,
    lineHeight: 1.5
  },

  planTop: {
    display: "flex",
    justifyContent:
      "space-between",
    alignItems: "center"
  },

  planTitle: {
    margin: 0,
    color: "#223854",
    fontSize: 28
  },

  planIcon: {
    width: 55,
    height: 55,
    borderRadius: 15,
    background: "#EEF4FF",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: 26
  },

  planFeatures: {
    display: "grid",
    gap: 10,
    margin: "24px 0"
  },

  feature: {
    display: "flex",
    alignItems: "center",
    gap: 9,
    color: "#51627A",
    fontSize: 12
  },

  check: {
    width: 20,
    height: 20,
    borderRadius: "50%",
    background: "#EDF4FF",
    color: "#4476D6",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: 10,
    fontWeight: 900
  },

  periodTitle: {
    marginBottom: 10,
    color: "#364A66",
    fontSize: 12,
    fontWeight: 800
  },

  periodGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(2,minmax(0,1fr))",
    gap: 10
  },

  periodButton: {
    border: "1px solid #DFE5EE",
    borderRadius: 12,
    padding: 14,
    background: "#FFF",
    cursor: "pointer",
    textAlign: "left"
  },

  periodSelected: {
    border:
      "2px solid #4D7DE0",
    background: "#F5F9FF",
    boxShadow:
      "0 8px 20px rgba(60,100,190,.10)"
  },

  periodMain: {
    display: "block",
    color: "#344862",
    fontSize: 13,
    fontWeight: 850
  },

  periodSub: {
    display: "block",
    marginTop: 4,
    color: "#8A96A7",
    fontSize: 10
  },

  primaryButton: {
    width: "100%",
    marginTop: 20,
    border: "none",
    borderRadius: 10,
    padding: "14px 18px",
    background:
      "linear-gradient(135deg,#3F76E3,#6958D4)",
    color: "#FFF",
    fontSize: 13,
    fontWeight: 850,
    cursor: "pointer",
    boxShadow:
      "0 9px 24px rgba(69,94,190,.20)"
  },

  secondaryButton: {
    width: "100%",
    marginTop: 18,
    border: "1px solid #D8E0EC",
    borderRadius: 10,
    padding: "13px 18px",
    background: "#FFF",
    color: "#46617F",
    fontSize: 12,
    fontWeight: 800,
    cursor: "pointer"
  },

  errorBox: {
    marginTop: 14,
    padding: 12,
    borderRadius: 10,
    background: "#FFF1F1",
    color: "#AC3E3E",
    fontSize: 12
  },

  paymentBox: {
    marginTop: 25,
    paddingTop: 24,
    borderTop:
      "1px solid #EDF1F5",
    textAlign: "center"
  },

  statusIcon: {
    width: 58,
    height: 58,
    margin: "0 auto 12px",
    borderRadius: "50%",
    background: "#FFF5DE",
    color: "#A97718",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: 25
  },

  statusIconApproved: {
    background: "#E9F8EE",
    color: "#319755"
  },

  paymentEyebrow: {
    color: "#7B8799",
    fontSize: 9,
    fontWeight: 900,
    letterSpacing: ".12em"
  },

  paymentTitle: {
    color: "#293E5C",
    fontSize: 21,
    margin: "8px 0"
  },

  paymentText: {
    color: "#7A879A",
    fontSize: 12,
    lineHeight: 1.6
  },

  paymentDetails: {
    marginTop: 15,
    padding:
      "0 12px",
    background: "#F8FAFC",
    borderRadius: 10
  },

  floatIcon: {
    position: "fixed",
    zIndex: 0,
    width: 60,
    height: 60,
    borderRadius: "50%",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    background:
      "rgba(255,255,255,.52)",
    border:
      "1px solid rgba(255,255,255,.84)",
    boxShadow:
      "0 12px 32px rgba(40,65,110,.09)",
    backdropFilter:
      "blur(10px)",
    fontSize: 25,
    pointerEvents: "none"
  },

  emptyCard: {
    width:
      "min(520px,calc(100% - 40px))",
    margin: "70px auto",
    padding: 35,
    borderRadius: 22,
    background:
      "rgba(255,255,255,.92)",
    textAlign: "center",
    boxShadow:
      "0 20px 55px rgba(25,45,80,.09)"
  },

  emptyIcon: {
    fontSize: 35
  },

  emptyTitle: {
    color: "#263B59",
    fontSize: 26
  },

  emptyText: {
    color: "#7A8799",
    fontSize: 13,
    lineHeight: 1.6
  }
};

export default CheckoutIndependiente;
