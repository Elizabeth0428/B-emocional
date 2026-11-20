// src/views/RegisterUsuarioIndependiente.jsx

import React, { useState } from "react";
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";

const API_URL =
  import.meta.env.VITE_API_URL ||
  `http://${window.location.hostname}:5000`;

const RegisterUsuarioIndependiente = () => {
  const navigate = useNavigate();

  const [paso, setPaso] = useState(1);

  const [form, setForm] = useState({
    perfil_independiente: "",
    nombre: "",
    nombre_practica: "",
    correo: "",
    telefono: "",
    password: "",
    confirmar_password: "",
    rfc: "",
    direccion: ""
  });

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [registroExitoso, setRegistroExitoso] = useState(null);
  const [mostrarPassword, setMostrarPassword] = useState(false);

  const esClinica =
    form.perfil_independiente === "clinica";

  const esRH =
    form.perfil_independiente === "rh";

  const fondoActual =
    esClinica
      ? "radial-gradient(circle at 15% 20%,rgba(108,171,255,.22),transparent 34%), radial-gradient(circle at 85% 15%,rgba(175,131,255,.18),transparent 30%), linear-gradient(135deg,#F7FBFF 0%,#EEF5FF 48%,#F7F2FF 100%)"
      : esRH
        ? "radial-gradient(circle at 15% 20%,rgba(45,93,154,.18),transparent 34%), radial-gradient(circle at 85% 15%,rgba(93,75,180,.16),transparent 30%), linear-gradient(135deg,#F7FAFD 0%,#EDF3F8 48%,#F3F0FA 100%)"
        : "radial-gradient(circle at 15% 20%,rgba(83,126,227,.12),transparent 34%), radial-gradient(circle at 85% 15%,rgba(120,94,210,.10),transparent 30%), linear-gradient(135deg,#FBFCFF 0%,#F3F6FB 50%,#F8F7FC 100%)";

  // ==================================================
  // CAMBIAR FORMULARIO
  // ==================================================

  const handleChange = e => {
    const { name, value } = e.target;

    setForm(actual => ({
      ...actual,
      [name]: value
    }));

    if (error) {
      setError("");
    }
  };

  // ==================================================
  // ELEGIR PERFIL
  // ==================================================

  const elegirPerfil = perfil => {
    setForm(actual => ({
      ...actual,
      perfil_independiente: perfil
    }));

    setError("");
    setPaso(2);

    window.scrollTo({
      top: 0,
      behavior: "smooth"
    });
  };

  // ==================================================
  // VOLVER AL PASO 1
  // ==================================================

  const volverPerfil = () => {
    setPaso(1);
    setError("");

    window.scrollTo({
      top: 0,
      behavior: "smooth"
    });
  };

  // ==================================================
  // REGISTRAR
  // ==================================================

  const handleSubmit = async e => {
    e.preventDefault();

    try {
      setLoading(true);
      setError("");

      if (!form.perfil_independiente) {
        throw new Error(
          "Selecciona el tipo de perfil independiente."
        );
      }

      if (
        !form.nombre.trim() ||
        !form.nombre_practica.trim() ||
        !form.correo.trim() ||
        !form.password
      ) {
        throw new Error(
          "Completa todos los campos obligatorios."
        );
      }

      if (form.password.length < 6) {
        throw new Error(
          "La contraseña debe tener al menos 6 caracteres."
        );
      }

      if (
        form.password !==
        form.confirmar_password
      ) {
        throw new Error(
          "Las contraseñas no coinciden."
        );
      }

      const payload = {
        perfil_independiente:
          form.perfil_independiente,

        nombre:
          form.nombre.trim(),

        nombre_practica:
          form.nombre_practica.trim(),

        correo:
          form.correo
            .trim()
            .toLowerCase(),

        telefono:
          form.telefono.trim() ||
          null,

        password:
          form.password,

        rfc:
          form.rfc
            .trim()
            .toUpperCase() ||
          null,

        direccion:
          form.direccion.trim() ||
          null
      };

      const response = await fetch(
        `${API_URL}/api/usuario-independiente`,
        {
          method: "POST",
          headers: {
            "Content-Type":
              "application/json"
          },
          body: JSON.stringify(
            payload
          )
        }
      );

      const data =
        await response.json();

      if (!response.ok) {
        throw new Error(
          data?.message ||
          "No se pudo crear la cuenta."
        );
      }

      const datosRegistro = {
        ...data,
        perfil_independiente:
          form.perfil_independiente,
        correo:
          form.correo,
        nombre:
          form.nombre,
        nombre_practica:
          form.nombre_practica
      };

      sessionStorage.setItem(
        "registro_independiente",
        JSON.stringify(
          datosRegistro
        )
      );

      setRegistroExitoso(
        datosRegistro
      );

    } catch (err) {
      console.error(
        "❌ Error registrando independiente:",
        err
      );

      setError(
        err.message ||
        "No se pudo registrar la cuenta."
      );

    } finally {
      setLoading(false);
    }
  };

  // ==================================================
  // REGISTRO EXITOSO
  // ==================================================

  if (registroExitoso) {
    return (
      <div style={{ ...styles.page, background: fondoActual }}>
        <DecorativeBackground perfil={form.perfil_independiente} />

        <div style={styles.successCard}>
          <div style={styles.successIcon}>
            ✓
          </div>

          <div style={styles.successEyebrow}>
            REGISTRO COMPLETADO
          </div>

          <h1 style={styles.successTitle}>
            Tu espacio está listo
          </h1>

          <p style={styles.successText}>
            Ya creamos tu cuenta independiente.
            Ahora solo falta activar tu plan.
          </p>

          <div style={styles.successSummary}>
            <SummaryItem
              labelText="Perfil"
              value={
                form.perfil_independiente ===
                "clinica"
                  ? "Psicología / Clínica"
                  : "Recursos Humanos"
              }
            />

            <SummaryItem
              labelText="Titular"
              value={form.nombre}
            />

            <SummaryItem
              labelText="Espacio"
              value={
                form.nombre_practica
              }
            />

            <SummaryItem
              labelText="Estado"
              value="Pendiente de pago"
            />
          </div>

          <div style={styles.checkoutNotice}>
            <div style={styles.noticeIcon}>
              💳
            </div>

            <div>
              <strong>
                Siguiente paso: activar tu plan
              </strong>

              <p style={styles.noticeText}>
                Continúa al checkout para
                completar la activación de tu
                cuenta independiente.
              </p>
            </div>
          </div>

          <button
            type="button"
            style={styles.mainButton}
            onClick={() =>
              navigate(
                "/independiente/checkout"
              )
            }
          >
            Continuar con mi plan →
          </button>

          <button
            type="button"
            style={styles.textButton}
            onClick={() =>
              navigate("/")
            }
          >
            Volver al inicio
          </button>
        </div>
      </div>
    );
  }

  // ==================================================
  // VISTA
  // ==================================================

  return (
    <div
      style={{
        ...styles.page,
        background: fondoActual
      }}
    >
      <div style={styles.topGlow} />
      <div style={styles.bottomGlow} />

      <DecorativeBackground
        perfil={
          paso === 2
            ? form.perfil_independiente
            : ""
        }
      />

      <div style={styles.shell}>
        {/* HEADER */}

        <header style={styles.header}>
          <button
            type="button"
            style={styles.backButton}
            onClick={() => {
              if (paso === 2) {
                volverPerfil();
              } else {
                navigate("/");
              }
            }}
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

        {/* PROGRESO */}

        <div style={styles.progress}>
          <div style={styles.progressLine}>
            <div
              style={{
                ...styles.progressFill,
                width:
                  paso === 1
                    ? "50%"
                    : "100%"
              }}
            />
          </div>

          <div style={styles.progressLabels}>
            <span
              style={
                paso >= 1
                  ? styles.progressActive
                  : styles.progressInactive
              }
            >
              01. Perfil
            </span>

            <span
              style={
                paso >= 2
                  ? styles.progressActive
                  : styles.progressInactive
              }
            >
              02. Cuenta
            </span>
          </div>
        </div>

        {/* ==================================================
            PASO 1
        ================================================== */}

        {paso === 1 && (
          <main style={styles.content}>
            <div style={styles.hero}>
              <span style={styles.planLabel}>
                PLAN INDEPENDIENTE
              </span>

              <h1 style={styles.heroTitle}>
                Tu espacio profesional,
                <br />
                a tu manera.
              </h1>

              <p style={styles.heroText}>
                Elige cómo trabajarás dentro
                de MirrorSoul. Esta selección
                definirá las herramientas que
                tendrás disponibles.
              </p>
            </div>

            <div style={styles.profileGrid}>
              {/* CLÍNICA */}

              <button
                type="button"
                style={styles.profileCard}
                onClick={() =>
                  elegirPerfil(
                    "clinica"
                  )
                }
              >
                <div
                  style={{
                    ...styles.profileAccent,
                    background:
                      "linear-gradient(135deg,#386FE8,#61A4FF)"
                  }}
                />

                <div style={styles.profileTop}>
                  <div
                    style={{
                      ...styles.profileIcon,
                      background:
                        "#EEF5FF"
                    }}
                  >
                    🧠
                  </div>

                  <div style={styles.profileArrow}>
                    →
                  </div>
                </div>

                <div style={styles.profileCategory}>
                  ÁREA CLÍNICA
                </div>

                <h2 style={styles.profileName}>
                  Psicología
                  <br />
                  y Clínica
                </h2>

                <p style={styles.profileText}>
                  Para profesionales que
                  trabajan directamente con
                  pacientes y procesos
                  terapéuticos.
                </p>

                <div style={styles.divider} />

                <div style={styles.moduleList}>
                  <Module text="Pacientes y expedientes" />
                  <Module text="Sesiones y seguimiento" />
                  <Module text="Evaluaciones psicológicas" />
                  <Module text="Resultados e IA clínica" />
                  <Module text="Agenda profesional" />
                </div>

                <div style={styles.cardFooter}>
                  Elegir Psicología / Clínica
                  <span>→</span>
                </div>
              </button>

              {/* RH */}

              <button
                type="button"
                style={styles.profileCard}
                onClick={() =>
                  elegirPerfil(
                    "rh"
                  )
                }
              >
                <div
                  style={{
                    ...styles.profileAccent,
                    background:
                      "linear-gradient(135deg,#6757D9,#9278F2)"
                  }}
                />

                <div style={styles.profileTop}>
                  <div
                    style={{
                      ...styles.profileIcon,
                      background:
                        "#F2EFFF"
                    }}
                  >
                    👥
                  </div>

                  <div style={styles.profileArrow}>
                    →
                  </div>
                </div>

                <div style={styles.profileCategory}>
                  RECURSOS HUMANOS
                </div>

                <h2 style={styles.profileName}>
                  Gestión
                  <br />
                  de talento
                </h2>

                <p style={styles.profileText}>
                  Para profesionales que
                  gestionan selección,
                  empleados y bienestar
                  laboral.
                </p>

                <div style={styles.divider} />

                <div style={styles.moduleList}>
                  <Module text="Prospectos y selección" />
                  <Module text="Empleados y seguimiento" />
                  <Module text="Evaluaciones RH" />
                  <Module text="NOM-035" />
                  <Module text="Canalización y bienestar" />
                </div>

                <div style={styles.cardFooter}>
                  Elegir Recursos Humanos
                  <span>→</span>
                </div>
              </button>
            </div>

            <div style={styles.bottomMessage}>
              <span>🔐</span>

              <span>
                Tu cuenta será independiente.
                No necesitas administrador ni
                matrícula.
              </span>
            </div>
          </main>
        )}

        {/* ==================================================
            PASO 2
        ================================================== */}

        {paso === 2 && (
          <main style={styles.formContent}>
            <div style={styles.formIntro}>
              <button
                type="button"
                style={styles.changeProfile}
                onClick={
                  volverPerfil
                }
              >
                ← Cambiar área
              </button>

              <div style={styles.selectedBadge}>
                {form.perfil_independiente ===
                "clinica"
                  ? "🧠 Psicología / Clínica"
                  : "👥 Recursos Humanos"}
              </div>

              <h1 style={styles.formMainTitle}>
                {esClinica
                  ? "Crea tu espacio clínico"
                  : "Crea tu espacio de RH"}
              </h1>

              <p style={styles.formMainText}>
                {esClinica
                  ? "Configura tu cuenta para trabajar con pacientes, sesiones y evaluaciones."
                  : "Configura tu cuenta para gestionar talento, empleados y evaluaciones RH."}
              </p>
            </div>

            <div style={styles.formCard}>
              {error && (
                <div style={styles.errorBox}>
                  <span>⚠️</span>
                  {error}
                </div>
              )}

              <form onSubmit={handleSubmit}>
                <div style={styles.section}>
                  <div style={styles.sectionTitle}>
                    Información profesional
                  </div>

                  <div style={styles.formGrid}>
                    <Field
                      labelText="Nombre completo"
                      required
                    >
                      <input
                        type="text"
                        name="nombre"
                        value={form.nombre}
                        onChange={
                          handleChange
                        }
                        placeholder="Tu nombre completo"
                        style={styles.input}
                        required
                      />
                    </Field>

                    <Field
                      labelText={
                        form.perfil_independiente ===
                        "rh"
                          ? "Nombre de tu consultoría"
                          : "Nombre de tu práctica"
                      }
                      required
                    >
                      <input
                        type="text"
                        name="nombre_practica"
                        value={
                          form.nombre_practica
                        }
                        onChange={
                          handleChange
                        }
                        placeholder={
                          form.perfil_independiente ===
                          "rh"
                            ? "Ej. Consultoría Talento MX"
                            : "Ej. Consultorio Psicología Integral"
                        }
                        style={styles.input}
                        required
                      />
                    </Field>

                    <Field labelText="Teléfono">
                      <input
                        type="tel"
                        name="telefono"
                        value={form.telefono}
                        onChange={
                          handleChange
                        }
                        placeholder="55 1234 5678"
                        style={styles.input}
                      />
                    </Field>

                    <Field labelText="RFC">
                      <input
                        type="text"
                        name="rfc"
                        value={form.rfc}
                        onChange={
                          handleChange
                        }
                        placeholder="Opcional"
                        style={styles.input}
                      />
                    </Field>

                    <Field
                      labelText={
                        form.perfil_independiente ===
                        "rh"
                          ? "Dirección de oficina"
                          : "Dirección del consultorio"
                      }
                      full
                    >
                      <input
                        type="text"
                        name="direccion"
                        value={form.direccion}
                        onChange={
                          handleChange
                        }
                        placeholder={
                          form.perfil_independiente ===
                          "rh"
                            ? "Dirección de tu oficina o consultoría"
                            : "Dirección de tu consultorio"
                        }
                        style={styles.input}
                      />
                    </Field>
                  </div>
                </div>

                <div style={styles.sectionDivider} />

                <div style={styles.section}>
                  <div style={styles.sectionTitle}>
                    Datos de acceso
                  </div>

                  <div style={styles.formGrid}>
                    <Field
                      labelText="Correo electrónico"
                      required
                    >
                      <input
                        type="email"
                        name="correo"
                        value={form.correo}
                        onChange={
                          handleChange
                        }
                        placeholder="correo@ejemplo.com"
                        style={styles.input}
                        required
                      />
                    </Field>

                    <div />

                    <Field
                      labelText="Contraseña"
                      required
                    >
                      <div style={styles.passwordBox}>
                        <input
                          type={
                            mostrarPassword
                              ? "text"
                              : "password"
                          }
                          name="password"
                          value={form.password}
                          onChange={
                            handleChange
                          }
                          placeholder="Mínimo 6 caracteres"
                          style={styles.passwordInput}
                          minLength={6}
                          required
                        />

                        <button
                          type="button"
                          style={styles.eyeButton}
                          onClick={() =>
                            setMostrarPassword(
                              actual =>
                                !actual
                            )
                          }
                        >
                          {mostrarPassword
                            ? "Ocultar"
                            : "Ver"}
                        </button>
                      </div>
                    </Field>

                    <Field
                      labelText="Confirmar contraseña"
                      required
                    >
                      <input
                        type={
                          mostrarPassword
                            ? "text"
                            : "password"
                        }
                        name="confirmar_password"
                        value={
                          form.confirmar_password
                        }
                        onChange={
                          handleChange
                        }
                        placeholder="Confirma tu contraseña"
                        style={styles.input}
                        minLength={6}
                        required
                      />
                    </Field>
                  </div>
                </div>

                <div style={styles.securityNotice}>
                  <div style={styles.securityIcon}>
                    🔐
                  </div>

                  <div>
                    <strong>
                      Tu acceso será personal
                    </strong>

                    <p style={styles.securityText}>
                      Iniciarás sesión usando
                      este correo y contraseña.
                    </p>
                  </div>
                </div>

                <button
                  type="submit"
                  disabled={loading}
                  style={{
                    ...styles.mainButton,
                    opacity:
                      loading
                        ? 0.65
                        : 1,
                    cursor:
                      loading
                        ? "not-allowed"
                        : "pointer"
                  }}
                >
                  {loading
                    ? "Creando tu cuenta..."
                    : "Continuar con mi plan →"}
                </button>
              </form>
            </div>
          </main>
        )}
      </div>
    </div>
  );
};

// ==================================================
// COMPONENTES
// ==================================================

const DecorativeBackground = ({
  perfil
}) => {
  const clinica =
    perfil === "clinica";

  const rh =
    perfil === "rh";

  if (
    !clinica &&
    !rh
  ) {
    return null;
  }

  const elementos =
    clinica
      ? [
          { icon: "🧠", top: "15%", left: "5%", size: "lg", delay: 0 },
          { icon: "😊", top: "31%", right: "6%", size: "md", delay: .5 },
          { icon: "❤️", bottom: "18%", left: "8%", size: "sm", delay: 1 },
          { icon: "😌", bottom: "13%", right: "10%", size: "md", delay: 1.5 },
          { icon: "✨", top: "63%", left: "4%", size: "sm", delay: .8 },
          { icon: "🌿", top: "12%", right: "12%", size: "sm", delay: 1.2 }
        ]
      : [
          { icon: "👥", top: "15%", left: "5%", size: "lg", delay: 0 },
          { icon: "📊", top: "31%", right: "6%", size: "md", delay: .5 },
          { icon: "💼", bottom: "18%", left: "8%", size: "sm", delay: 1 },
          { icon: "✅", bottom: "13%", right: "10%", size: "md", delay: 1.5 },
          { icon: "📋", top: "63%", left: "4%", size: "sm", delay: .8 },
          { icon: "🤝", top: "12%", right: "12%", size: "sm", delay: 1.2 }
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
              ...(item.size === "lg"
                ? styles.floatLarge
                : item.size === "md"
                  ? styles.floatMedium
                  : styles.floatSmall),
              top: item.top,
              bottom: item.bottom,
              left: item.left,
              right: item.right
            }}
            initial={{
              opacity: 0,
              scale: .8
            }}
            animate={{
              opacity: [
                .42,
                .78,
                .42
              ],
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
              scale: [
                1,
                1.05,
                1
              ]
            }}
            transition={{
              duration:
                5 + index * .4,
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

const Field = ({
  labelText,
  required,
  full,
  children
}) => (
  <label
    style={{
      ...styles.field,
      ...(full
        ? styles.fullField
        : {})
    }}
  >
    <span style={styles.fieldLabel}>
      {labelText}

      {required && (
        <span style={styles.required}>
          *
        </span>
      )}
    </span>

    {children}
  </label>
);

const Module = ({
  text
}) => (
  <div style={styles.module}>
    <span style={styles.check}>
      ✓
    </span>

    <span>
      {text}
    </span>
  </div>
);

const SummaryItem = ({
  labelText,
  value
}) => (
  <div style={styles.summaryItem}>
    <span style={styles.summaryLabel}>
      {labelText}
    </span>

    <strong style={styles.summaryValue}>
      {value || "—"}
    </strong>
  </div>
);

// ==================================================
// ESTILOS
// ==================================================

const styles = {
  page: {
    minHeight: "100vh",
    position: "relative",
    overflow: "hidden",
    transition: "background .55s ease",
    background:
      "linear-gradient(135deg,#FBFCFF 0%,#F3F6FB 50%,#F8F7FC 100%)",
    fontFamily:
      "'Inter','Segoe UI',Arial,sans-serif",
    color: "#17243B"
  },

  topGlow: {
    position: "fixed",
    width: 520,
    height: 520,
    borderRadius: "50%",
    background:
      "rgba(72,117,226,.07)",
    filter: "blur(100px)",
    top: -250,
    left: -180,
    pointerEvents: "none"
  },

  bottomGlow: {
    position: "fixed",
    width: 500,
    height: 500,
    borderRadius: "50%",
    background:
      "rgba(106,80,210,.06)",
    filter: "blur(100px)",
    bottom: -260,
    right: -180,
    pointerEvents: "none"
  },

  shell: {
    width: "min(1160px,calc(100% - 40px))",
    margin: "0 auto",
    paddingBottom: 60,
    position: "relative",
    zIndex: 1
  },

  header: {
    minHeight: 118,
    display: "grid",
    gridTemplateColumns: "1fr auto 1fr",
    alignItems: "center",
    borderBottom:
      "1px solid rgba(216,224,236,.8)"
  },

  logoWrap: {
    justifySelf: "center",
    minWidth: 250,
    minHeight: 92,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    padding: "6px 18px",
    borderRadius: 20,
    background: "rgba(255,255,255,.62)",
    border: "1px solid rgba(255,255,255,.88)",
    boxShadow: "0 12px 34px rgba(45,70,115,.10)",
    backdropFilter: "blur(14px)"
  },

  logo: {
    width: 230,
    maxWidth: "42vw",
    height: 82,
    objectFit: "contain",
    display: "block",
    filter: "drop-shadow(0 8px 16px rgba(40,70,120,.16))"
  },

  backButton: {
    justifySelf: "start",
    border: "none",
    background: "transparent",
    color: "#516079",
    fontSize: 14,
    fontWeight: 700,
    cursor: "pointer",
    padding: "10px 0"
  },

  loginButton: {
    justifySelf: "end",
    border: "1px solid #DDE4EF",
    background: "#FFF",
    color: "#34465F",
    borderRadius: 9,
    padding: "9px 15px",
    fontSize: 13,
    fontWeight: 700,
    cursor: "pointer"
  },

  progress: {
    width: "min(520px,100%)",
    margin: "30px auto 0"
  },

  progressLine: {
    height: 3,
    borderRadius: 10,
    background: "#E5EAF2",
    overflow: "hidden"
  },

  progressFill: {
    height: "100%",
    background:
      "linear-gradient(90deg,#3F76E3,#725DD8)",
    transition: "width .3s ease"
  },

  progressLabels: {
    display: "flex",
    justifyContent: "space-between",
    marginTop: 9,
    fontSize: 11,
    fontWeight: 800,
    letterSpacing: ".06em"
  },

  progressActive: {
    color: "#416DD2"
  },

  progressInactive: {
    color: "#A0AABA"
  },

  content: {
    maxWidth: 1000,
    margin: "55px auto 0"
  },

  hero: {
    textAlign: "center",
    maxWidth: 660,
    margin: "0 auto 38px"
  },

  planLabel: {
    display: "inline-block",
    color: "#4C73CF",
    fontWeight: 900,
    letterSpacing: ".12em",
    fontSize: 11,
    marginBottom: 14
  },

  heroTitle: {
    margin: 0,
    fontSize:
      "clamp(34px,5vw,52px)",
    lineHeight: 1.08,
    letterSpacing: "-1.7px",
    color: "#1D3152",
    fontWeight: 800
  },

  heroText: {
    maxWidth: 590,
    margin: "18px auto 0",
    color: "#718097",
    fontSize: 15,
    lineHeight: 1.7
  },

  profileGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit,minmax(320px,1fr))",
    gap: 22
  },

  profileCard: {
    position: "relative",
    overflow: "hidden",
    display: "flex",
    flexDirection: "column",
    minHeight: 500,
    border:
      "1px solid #E1E7F0",
    borderRadius: 20,
    padding: 30,
    background: "#FFF",
    textAlign: "left",
    cursor: "pointer",
    boxShadow:
      "0 15px 40px rgba(25,45,80,.06)"
  },

  profileAccent: {
    position: "absolute",
    top: 0,
    left: 0,
    width: "100%",
    height: 5
  },

  profileTop: {
    display: "flex",
    justifyContent:
      "space-between",
    alignItems: "center",
    marginBottom: 24
  },

  profileIcon: {
    width: 58,
    height: 58,
    borderRadius: 15,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: 27
  },

  profileArrow: {
    color: "#9AA6B8",
    fontSize: 22
  },

  profileCategory: {
    color: "#74849B",
    fontSize: 10,
    fontWeight: 900,
    letterSpacing: ".13em",
    marginBottom: 10
  },

  profileName: {
    margin: 0,
    color: "#203551",
    fontSize: 29,
    lineHeight: 1.12,
    letterSpacing: "-.7px"
  },

  profileText: {
    color: "#78879A",
    fontSize: 14,
    lineHeight: 1.65,
    minHeight: 68,
    margin:
      "16px 0 22px"
  },

  divider: {
    height: 1,
    background: "#EDF1F5",
    marginBottom: 21
  },

  moduleList: {
    display: "grid",
    gap: 12
  },

  module: {
    display: "flex",
    alignItems: "center",
    gap: 9,
    color: "#4B5E77",
    fontSize: 13
  },

  check: {
    width: 20,
    height: 20,
    flexShrink: 0,
    borderRadius: "50%",
    background: "#EFF5FF",
    color: "#4779DB",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: 11,
    fontWeight: 900
  },

  cardFooter: {
    display: "flex",
    justifyContent:
      "space-between",
    alignItems: "center",
    marginTop: "auto",
    paddingTop: 28,
    color: "#366BD4",
    fontWeight: 800,
    fontSize: 13
  },

  bottomMessage: {
    display: "flex",
    justifyContent: "center",
    gap: 8,
    color: "#7A8799",
    fontSize: 12,
    marginTop: 25
  },

  formContent: {
    width: "min(820px,100%)",
    margin: "45px auto 0"
  },

  formIntro: {
    textAlign: "center",
    marginBottom: 25
  },

  changeProfile: {
    border: "none",
    background: "transparent",
    color: "#64758D",
    fontWeight: 700,
    cursor: "pointer",
    marginBottom: 18
  },

  selectedBadge: {
    display: "inline-block",
    background: "#EEF4FF",
    color: "#3C6DCE",
    borderRadius: 30,
    padding: "8px 14px",
    fontSize: 12,
    fontWeight: 800,
    marginBottom: 15
  },

  formMainTitle: {
    margin: 0,
    color: "#203653",
    fontSize: 36,
    letterSpacing: "-1px"
  },

  formMainText: {
    margin:
      "10px 0 0",
    color: "#7A8799",
    fontSize: 14
  },

  formCard: {
    background: "rgba(255,255,255,.88)",
    border:
      "1px solid rgba(255,255,255,.92)",
    borderRadius: 24,
    padding: 34,
    boxShadow:
      "0 22px 60px rgba(25,45,80,.10)",
    backdropFilter: "blur(18px)"
  },

  errorBox: {
    display: "flex",
    gap: 8,
    padding: 13,
    marginBottom: 22,
    borderRadius: 10,
    background: "#FFF1F1",
    color: "#AD3A3A",
    fontSize: 13
  },

  section: {
    display: "block"
  },

  sectionTitle: {
    color: "#253B59",
    fontSize: 15,
    fontWeight: 800,
    marginBottom: 18
  },

  sectionDivider: {
    height: 1,
    background: "#EEF1F5",
    margin: "28px 0"
  },

  formGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(2,minmax(0,1fr))",
    gap: 17
  },

  field: {
    display: "block"
  },

  fullField: {
    gridColumn: "1 / -1"
  },

  fieldLabel: {
    display: "block",
    marginBottom: 7,
    color: "#55667D",
    fontWeight: 750,
    fontSize: 12
  },

  required: {
    color: "#5579D9",
    marginLeft: 3
  },

  input: {
    width: "100%",
    boxSizing: "border-box",
    border:
      "1px solid #DCE3ED",
    borderRadius: 9,
    padding: "12px 13px",
    background: "#FCFDFE",
    color: "#31425A",
    fontSize: 13,
    outline: "none"
  },

  passwordBox: {
    display: "flex",
    border:
      "1px solid #DCE3ED",
    borderRadius: 9,
    overflow: "hidden",
    background: "#FCFDFE"
  },

  passwordInput: {
    flex: 1,
    minWidth: 0,
    border: "none",
    outline: "none",
    background: "transparent",
    padding: "12px 13px",
    color: "#31425A",
    fontSize: 13
  },

  eyeButton: {
    border: "none",
    borderLeft:
      "1px solid #E7EBF2",
    background: "#FFF",
    padding: "0 13px",
    color: "#5F7088",
    fontSize: 11,
    fontWeight: 700,
    cursor: "pointer"
  },

  securityNotice: {
    display: "flex",
    gap: 12,
    alignItems: "flex-start",
    marginTop: 28,
    padding: 15,
    borderRadius: 11,
    background: "#F5F8FC",
    color: "#435671"
  },

  securityIcon: {
    width: 34,
    height: 34,
    borderRadius: 9,
    background: "#EAF1FB",
    display: "flex",
    alignItems: "center",
    justifyContent: "center"
  },

  securityText: {
    margin:
      "4px 0 0",
    color: "#7A8799",
    fontSize: 11
  },

  mainButton: {
    width: "100%",
    marginTop: 22,
    border: "none",
    borderRadius: 10,
    padding: "14px 18px",
    background:
      "linear-gradient(135deg,#3F76E3,#6958D4)",
    color: "#FFF",
    fontSize: 14,
    fontWeight: 800,
    cursor: "pointer",
    boxShadow:
      "0 8px 22px rgba(69,94,190,.20)"
  },

  textButton: {
    marginTop: 13,
    border: "none",
    background: "transparent",
    color: "#67778E",
    fontWeight: 700,
    cursor: "pointer"
  },

  successCard: {
    width: "min(620px,calc(100% - 40px))",
    margin: "70px auto",
    position: "relative",
    zIndex: 2,
    background: "rgba(255,255,255,.90)",
    border:
      "1px solid #E1E7F0",
    borderRadius: 22,
    padding: 38,
    textAlign: "center",
    boxShadow:
      "0 18px 50px rgba(25,45,80,.08)"
  },

  successIcon: {
    width: 68,
    height: 68,
    margin:
      "0 auto 16px",
    borderRadius: "50%",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    background: "#EAF8EF",
    color: "#35A05A",
    fontSize: 28,
    fontWeight: 900
  },

  successEyebrow: {
    color: "#42955B",
    fontSize: 10,
    fontWeight: 900,
    letterSpacing: ".12em"
  },

  successTitle: {
    margin:
      "10px 0 8px",
    color: "#263B59",
    fontSize: 30
  },

  successText: {
    margin: 0,
    color: "#78869A",
    fontSize: 14
  },

  successSummary: {
    display: "grid",
    gridTemplateColumns:
      "repeat(2,minmax(0,1fr))",
    gap: 10,
    margin: "25px 0"
  },

  summaryItem: {
    background: "#F7F9FC",
    borderRadius: 10,
    padding: 13,
    textAlign: "left"
  },

  summaryLabel: {
    display: "block",
    color: "#909AAC",
    fontSize: 9,
    fontWeight: 850,
    textTransform: "uppercase",
    letterSpacing: ".05em"
  },

  summaryValue: {
    display: "block",
    marginTop: 5,
    color: "#40526B",
    fontSize: 12
  },

  checkoutNotice: {
    display: "flex",
    gap: 12,
    textAlign: "left",
    padding: 15,
    borderRadius: 11,
    background: "#FFF9EC",
    border:
      "1px solid #F2E1B6",
    color: "#665A3D"
  },

  noticeIcon: {
    fontSize: 22
  },

  floatLarge: {
    position: "fixed",
    zIndex: 0,
    width: 82,
    height: 82,
    borderRadius: "50%",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: 34,
    background: "rgba(255,255,255,.58)",
    border: "1px solid rgba(255,255,255,.88)",
    boxShadow: "0 16px 42px rgba(40,65,110,.11)",
    backdropFilter: "blur(12px)",
    pointerEvents: "none"
  },

  floatMedium: {
    position: "fixed",
    zIndex: 0,
    width: 62,
    height: 62,
    borderRadius: "50%",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: 27,
    background: "rgba(255,255,255,.52)",
    border: "1px solid rgba(255,255,255,.82)",
    boxShadow: "0 12px 34px rgba(40,65,110,.09)",
    backdropFilter: "blur(10px)",
    pointerEvents: "none"
  },

  floatSmall: {
    position: "fixed",
    zIndex: 0,
    width: 48,
    height: 48,
    borderRadius: "50%",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontSize: 21,
    background: "rgba(255,255,255,.46)",
    border: "1px solid rgba(255,255,255,.78)",
    boxShadow: "0 9px 26px rgba(40,65,110,.08)",
    backdropFilter: "blur(9px)",
    pointerEvents: "none"
  },

  noticeText: {
    margin:
      "5px 0 0",
    color: "#847654",
    fontSize: 11,
    lineHeight: 1.5
  }
};

export default RegisterUsuarioIndependiente;