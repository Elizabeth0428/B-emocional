import React, {
  useState,
} from "react";

import {
  useNavigate,
} from "react-router-dom";

import NavbarPublica
  from "../../components/public/NavbarPublica";

import FooterPublico
  from "../../components/public/FooterPublico";

function ContactoMirrorSoul() {
  const navigate =
    useNavigate();

  const [
    form,
    setForm
  ] =
    useState({
      nombre: "",
      empresa: "",
      correo: "",
      telefono: "",
      tipo_consulta:
        "informacion",
      mensaje: "",
    });

  const [
    enviado,
    setEnviado
  ] =
    useState(
      false
    );

  const [
    error,
    setError
  ] =
    useState(
      ""
    );

  // ==================================================
  // CAMBIOS
  // ==================================================

  const handleChange =
    e => {

      const {
        name,
        value,
      } =
        e.target;

      setForm(
        prev => ({
          ...prev,

          [name]:
            value,
        })
      );

      if (error) {
        setError(
          ""
        );
      }
    };

  // ==================================================
  // ENVIAR
  // ==================================================

  const handleSubmit =
    e => {

      e.preventDefault();

      if (
        !form.nombre.trim()
      ) {
        setError(
          "Ingresa tu nombre."
        );

        return;
      }

      if (
        !form.correo.trim()
      ) {
        setError(
          "Ingresa tu correo electrónico."
        );

        return;
      }

      if (
        !form.mensaje.trim()
      ) {
        setError(
          "Cuéntanos brevemente qué necesitas."
        );

        return;
      }

      /*
        Después conectamos aquí:

        POST /api/contacto

        También podemos enviar:
        - correo
        - notificación al administrador
        - guardar prospecto comercial
      */

      console.log(
        "Contacto MirrorSoul:",
        form
      );

      setEnviado(
        true
      );
    };

  return (
    <div style={styles.page}>
      <NavbarPublica />

      <main>
        {/* ============================= */}
        {/* HERO */}
        {/* ============================= */}

        <section style={styles.hero}>
          <div style={styles.heroGlow} />

          <div style={styles.heroContent}>
            <span style={styles.eyebrow}>
              CONTACTO
            </span>

            <h1 style={styles.title}>
              Hablemos de lo que tu
              organización necesita.
            </h1>

            <p style={styles.description}>
              Ya sea que quieras conocer
              MirrorSoul, solicitar una
              demostración, cotizar un plan
              o buscar una solución
              tecnológica, podemos ayudarte.
            </p>
          </div>
        </section>

        {/* ============================= */}
        {/* CONTENIDO */}
        {/* ============================= */}

        <section style={styles.section}>
          <div style={styles.container}>
            <div style={styles.layout}>
              {/* ============================= */}
              {/* INFORMACIÓN */}
              {/* ============================= */}

              <div style={styles.infoColumn}>
                <span style={styles.infoEyebrow}>
                  ¿EN QUÉ PODEMOS AYUDARTE?
                </span>

                <h2 style={styles.infoTitle}>
                  Soluciones adaptadas a
                  diferentes necesidades.
                </h2>

                <p style={styles.infoText}>
                  Cuéntanos qué estás
                  buscando y podremos
                  orientarte sobre la
                  solución más adecuada.
                </p>

                <div style={styles.options}>
                  <div style={styles.optionCard}>
                    <span style={styles.optionIcon}>
                      💙
                    </span>

                    <div>
                      <strong style={styles.optionTitle}>
                        Conocer MirrorSoul
                      </strong>

                      <span style={styles.optionText}>
                        Información sobre la
                        plataforma y sus
                        funcionalidades.
                      </span>
                    </div>
                  </div>

                  <div style={styles.optionCard}>
                    <span style={styles.optionIcon}>
                      🎥
                    </span>

                    <div>
                      <strong style={styles.optionTitle}>
                        Solicitar demostración
                      </strong>

                      <span style={styles.optionText}>
                        Conoce cómo funciona
                        MirrorSoul en una
                        presentación.
                      </span>
                    </div>
                  </div>

                  <div style={styles.optionCard}>
                    <span style={styles.optionIcon}>
                      📦
                    </span>

                    <div>
                      <strong style={styles.optionTitle}>
                        Cotizar un plan
                      </strong>

                      <span style={styles.optionText}>
                        Recibe información
                        sobre paquetes,
                        licencias y opciones.
                      </span>
                    </div>
                  </div>

                  <div style={styles.optionCard}>
                    <span style={styles.optionIcon}>
                      💻
                    </span>

                    <div>
                      <strong style={styles.optionTitle}>
                        Servicios tecnológicos
                      </strong>

                      <span style={styles.optionText}>
                        Equipo, cámaras,
                        redes, soporte,
                        mantenimiento y más.
                      </span>
                    </div>
                  </div>
                </div>

                <div style={styles.backBlock}>
                  <button
                    type="button"
                    style={styles.backButton}
                    onClick={() =>
                      navigate("/")
                    }
                  >
                    ← Volver a MirrorSoul
                  </button>
                </div>
              </div>

              {/* ============================= */}
              {/* FORMULARIO */}
              {/* ============================= */}

              <div style={styles.formCard}>
                {!enviado ? (
                  <>
                    <div style={styles.formHeader}>
                      <span style={styles.formEyebrow}>
                        ESCRÍBENOS
                      </span>

                      <h2 style={styles.formTitle}>
                        Solicita información
                      </h2>

                      <p style={styles.formText}>
                        Completa tus datos y
                        dinos cómo podemos
                        ayudarte.
                      </p>
                    </div>

                    <form
                      onSubmit={
                        handleSubmit
                      }
                    >
                      <div style={styles.field}>
                        <label style={styles.label}>
                          Nombre
                        </label>

                        <input
                          type="text"
                          name="nombre"
                          value={
                            form.nombre
                          }
                          onChange={
                            handleChange
                          }
                          placeholder="Tu nombre"
                          style={styles.input}
                        />
                      </div>

                      <div style={styles.field}>
                        <label style={styles.label}>
                          Empresa u organización
                        </label>

                        <input
                          type="text"
                          name="empresa"
                          value={
                            form.empresa
                          }
                          onChange={
                            handleChange
                          }
                          placeholder="Opcional"
                          style={styles.input}
                        />
                      </div>

                      <div style={styles.twoColumns}>
                        <div style={styles.field}>
                          <label style={styles.label}>
                            Correo
                          </label>

                          <input
                            type="email"
                            name="correo"
                            value={
                              form.correo
                            }
                            onChange={
                              handleChange
                            }
                            placeholder="correo@empresa.com"
                            style={styles.input}
                          />
                        </div>

                        <div style={styles.field}>
                          <label style={styles.label}>
                            Teléfono
                          </label>

                          <input
                            type="tel"
                            name="telefono"
                            value={
                              form.telefono
                            }
                            onChange={
                              handleChange
                            }
                            placeholder="55 0000 0000"
                            style={styles.input}
                          />
                        </div>
                      </div>

                      <div style={styles.field}>
                        <label style={styles.label}>
                          ¿Qué necesitas?
                        </label>

                        <select
                          name="tipo_consulta"
                          value={
                            form
                              .tipo_consulta
                          }
                          onChange={
                            handleChange
                          }
                          style={styles.input}
                        >
                          <option value="informacion">
                            Información sobre MirrorSoul
                          </option>

                          <option value="demo">
                            Solicitar demostración
                          </option>

                          <option value="planes">
                            Planes y paquetes
                          </option>

                          <option value="servicios">
                            Servicios tecnológicos
                          </option>

                          <option value="cotizacion">
                            Cotización personalizada
                          </option>

                          <option value="otro">
                            Otro
                          </option>
                        </select>
                      </div>

                      <div style={styles.field}>
                        <label style={styles.label}>
                          Mensaje
                        </label>

                        <textarea
                          name="mensaje"
                          value={
                            form.mensaje
                          }
                          onChange={
                            handleChange
                          }
                          placeholder="Cuéntanos brevemente qué necesitas..."
                          style={styles.textarea}
                        />
                      </div>

                      {error && (
                        <div style={styles.errorBox}>
                          {error}
                        </div>
                      )}

                      <button
                        type="submit"
                        style={styles.submitButton}
                      >
                        Enviar solicitud
                        <span>
                          →
                        </span>
                      </button>
                    </form>
                  </>
                ) : (
                  <div style={styles.success}>
                    <div style={styles.successIcon}>
                      ✓
                    </div>

                    <span style={styles.successEyebrow}>
                      SOLICITUD RECIBIDA
                    </span>

                    <h2 style={styles.successTitle}>
                      Gracias por contactarnos.
                    </h2>

                    <p style={styles.successText}>
                      La información fue
                      preparada correctamente.
                      Cuando conectemos el
                      formulario al backend,
                      aquí se enviará tu
                      solicitud al equipo.
                    </p>

                    <button
                      type="button"
                      style={styles.submitButton}
                      onClick={() => {
                        setForm({
                          nombre: "",
                          empresa: "",
                          correo: "",
                          telefono: "",
                          tipo_consulta:
                            "informacion",
                          mensaje: "",
                        });

                        setEnviado(
                          false
                        );
                      }}
                    >
                      Enviar otra solicitud
                    </button>
                  </div>
                )}
              </div>
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
    minHeight:
      "100vh",

    background:
      "linear-gradient(180deg,#07111f,#091624)",

    color:
      "#ffffff",

    fontFamily:
      "'Inter','Segoe UI',Arial,sans-serif",
  },

  hero: {
    position:
      "relative",

    overflow:
      "hidden",

    padding:
      "110px 28px 70px",

    background:
      "radial-gradient(circle at 50% 0%,rgba(92,119,255,.12),transparent 42%)",
  },

  heroGlow: {
    position:
      "absolute",

    width:
      "500px",

    height:
      "500px",

    borderRadius:
      "50%",

    left:
      "50%",

    top:
      "-330px",

    transform:
      "translateX(-50%)",

    background:
      "rgba(99,229,255,.07)",

    filter:
      "blur(120px)",
  },

  heroContent: {
    position:
      "relative",

    zIndex: 2,

    maxWidth:
      "820px",

    margin:
      "0 auto",

    textAlign:
      "center",
  },

  eyebrow: {
    display:
      "inline-block",

    marginBottom:
      "15px",

    color:
      "#71e9ff",

    fontSize:
      "10px",

    fontWeight:
      "900",

    letterSpacing:
      "1.8px",
  },

  title: {
    margin: 0,

    color:
      "#ffffff",

    fontSize:
      "clamp(40px,5vw,62px)",

    lineHeight:
      1.06,

    fontWeight:
      "900",

    letterSpacing:
      "-1.8px",
  },

  description: {
    maxWidth:
      "700px",

    margin:
      "22px auto 0",

    color:
      "rgba(255,255,255,.55)",

    fontSize:
      "16px",

    lineHeight:
      1.75,
  },

  section: {
    padding:
      "45px 28px 110px",
  },

  container: {
    maxWidth:
      "1180px",

    margin:
      "0 auto",
  },

  layout: {
    display:
      "grid",

    gridTemplateColumns:
      ".9fr 1.1fr",

    gap:
      "40px",

    alignItems:
      "start",
  },

  infoColumn: {
    padding:
      "20px 0",
  },

  infoEyebrow: {
    display:
      "block",

    marginBottom:
      "10px",

    color:
      "rgba(113,233,255,.72)",

    fontSize:
      "9px",

    fontWeight:
      "900",

    letterSpacing:
      "1.5px",
  },

  infoTitle: {
    margin: 0,

    maxWidth:
      "520px",

    color:
      "#ffffff",

    fontSize:
      "34px",

    lineHeight:
      1.15,

    fontWeight:
      "900",

    letterSpacing:
      "-.8px",
  },

  infoText: {
    margin:
      "15px 0 0",

    maxWidth:
      "500px",

    color:
      "rgba(255,255,255,.46)",

    fontSize:
      "13px",

    lineHeight:
      1.7,
  },

  options: {
    display:
      "grid",

    gap:
      "11px",

    marginTop:
      "28px",
  },

  optionCard: {
    display:
      "flex",

    alignItems:
      "flex-start",

    gap:
      "12px",

    padding:
      "15px",

    borderRadius:
      "14px",

    background:
      "rgba(255,255,255,.025)",

    border:
      "1px solid rgba(255,255,255,.05)",
  },

  optionIcon: {
    width:
      "38px",

    height:
      "38px",

    flexShrink:
      0,

    display:
      "flex",

    alignItems:
      "center",

    justifyContent:
      "center",

    borderRadius:
      "11px",

    background:
      "rgba(102,229,255,.05)",

    fontSize:
      "17px",
  },

  optionTitle: {
    display:
      "block",

    color:
      "#ffffff",

    fontSize:
      "11px",

    fontWeight:
      "900",
  },

  optionText: {
    display:
      "block",

    marginTop:
      "4px",

    color:
      "rgba(255,255,255,.38)",

    fontSize:
      "9px",

    lineHeight:
      1.55,
  },

  backBlock: {
    marginTop:
      "25px",
  },

  backButton: {
    padding:
      "11px 15px",

    borderRadius:
      "10px",

    border:
      "1px solid rgba(255,255,255,.08)",

    background:
      "rgba(255,255,255,.025)",

    color:
      "#ffffff",

    fontWeight:
      "800",

    cursor:
      "pointer",
  },

  formCard: {
    padding:
      "34px",

    borderRadius:
      "25px",

    background:
      "linear-gradient(145deg,rgba(17,33,50,.96),rgba(8,18,29,.98))",

    border:
      "1px solid rgba(255,255,255,.07)",

    boxShadow:
      "0 25px 65px rgba(0,0,0,.15)",
  },

  formHeader: {
    marginBottom:
      "28px",
  },

  formEyebrow: {
    color:
      "#71e9ff",

    fontSize:
      "9px",

    fontWeight:
      "900",

    letterSpacing:
      "1.4px",
  },

  formTitle: {
    margin:
      "8px 0 0",

    color:
      "#ffffff",

    fontSize:
      "27px",

    fontWeight:
      "900",
  },

  formText: {
    margin:
      "9px 0 0",

    color:
      "rgba(255,255,255,.42)",

    fontSize:
      "11px",

    lineHeight:
      1.6,
  },

  field: {
    marginBottom:
      "17px",
  },

  twoColumns: {
    display:
      "grid",

    gridTemplateColumns:
      "1fr 1fr",

    gap:
      "14px",
  },

  label: {
    display:
      "block",

    marginBottom:
      "7px",

    color:
      "rgba(255,255,255,.62)",

    fontSize:
      "9px",

    fontWeight:
      "800",
  },

  input: {
    width:
      "100%",

    boxSizing:
      "border-box",

    padding:
      "13px 14px",

    borderRadius:
      "11px",

    border:
      "1px solid rgba(255,255,255,.08)",

    background:
      "rgba(255,255,255,.035)",

    color:
      "#ffffff",

    outline:
      "none",

    fontSize:
      "11px",
  },

  textarea: {
    width:
      "100%",

    minHeight:
      "135px",

    resize:
      "vertical",

    boxSizing:
      "border-box",

    padding:
      "13px 14px",

    borderRadius:
      "11px",

    border:
      "1px solid rgba(255,255,255,.08)",

    background:
      "rgba(255,255,255,.035)",

    color:
      "#ffffff",

    outline:
      "none",

    fontFamily:
      "inherit",

    fontSize:
      "11px",

    lineHeight:
      1.6,
  },

  errorBox: {
    marginBottom:
      "14px",

    padding:
      "11px",

    borderRadius:
      "9px",

    background:
      "rgba(255,90,90,.07)",

    border:
      "1px solid rgba(255,90,90,.11)",

    color:
      "#ffaaaa",

    fontSize:
      "9px",

    fontWeight:
      "700",
  },

  submitButton: {
    width:
      "100%",

    border:
      "none",

    padding:
      "14px 18px",

    borderRadius:
      "11px",

    background:
      "linear-gradient(135deg,#65e5ff,#927eff)",

    color:
      "#07111f",

    fontWeight:
      "900",

    cursor:
      "pointer",

    display:
      "flex",

    alignItems:
      "center",

    justifyContent:
      "center",

    gap:
      "9px",
  },

  success: {
    minHeight:
      "470px",

    display:
      "flex",

    flexDirection:
      "column",

    alignItems:
      "center",

    justifyContent:
      "center",

    textAlign:
      "center",
  },

  successIcon: {
    width:
      "65px",

    height:
      "65px",

    display:
      "flex",

    alignItems:
      "center",

    justifyContent:
      "center",

    borderRadius:
      "20px",

    background:
      "rgba(112,231,181,.08)",

    border:
      "1px solid rgba(112,231,181,.12)",

    color:
      "#70e7b5",

    fontSize:
      "25px",

    fontWeight:
      "900",

    marginBottom:
      "20px",
  },

  successEyebrow: {
    color:
      "#70e7b5",

    fontSize:
      "9px",

    fontWeight:
      "900",

    letterSpacing:
      "1.4px",
  },

  successTitle: {
    margin:
      "9px 0 0",

    color:
      "#ffffff",

    fontSize:
      "28px",

    fontWeight:
      "900",
  },

  successText: {
    maxWidth:
      "430px",

    margin:
      "13px auto 25px",

    color:
      "rgba(255,255,255,.43)",

    fontSize:
      "11px",

    lineHeight:
      1.7,
  },
};

export default ContactoMirrorSoul;