import React, { useEffect, useMemo, useState } from "react";
import axios from "axios";
import { useParams } from "react-router-dom";

const API_URL =
  import.meta.env.VITE_API_URL ||
  `http://${window.location.hostname}:5000`;

const money = valor => {
  if (
    valor === null ||
    valor === undefined ||
    valor === ""
  ) {
    return null;
  }

  const numero = Number(valor);

  if (Number.isNaN(numero)) {
    return valor;
  }

  return numero.toLocaleString("es-MX", {
    style: "currency",
    currency: "MXN"
  });
};

const textoModalidad = opcion => {
  const modalidades = [];

  if (
    Number(
      opcion?.modalidad_presencial
    ) === 1
  ) {
    modalidades.push("Presencial");
  }

  if (
    Number(
      opcion?.modalidad_videollamada
    ) === 1
  ) {
    modalidades.push("Videollamada");
  }

  return modalidades.length
    ? modalidades.join(" / ")
    : null;
};

const obtenerInicial = nombre =>
  String(nombre || "P")
    .trim()
    .charAt(0)
    .toUpperCase();


// ==================================================
// FOTO PROFESIONAL
// ==================================================

const obtenerFotoProfesional =
  foto => {

    if (!foto) {
      return "";
    }

    const valor =
      String(
        foto
      ).trim();

    if (!valor) {
      return "";
    }

    if (
      valor.startsWith(
        "http://"
      ) ||
      valor.startsWith(
        "https://"
      )
    ) {
      return valor;
    }

    return `${API_URL}${valor}`;
  };



// ==================================================
// COMPARTIR / CONTACTAR PROFESIONAL
// ==================================================

const normalizarTelefonoWhatsApp = telefono => {
  const digitos = String(telefono || "").replace(/\D/g, "");

  if (!digitos) return "";

  if (digitos.length === 10) {
    return `52${digitos}`;
  }

  return digitos;
};

const construirTextoProfesional = opcion => {
  if (!opcion) return "";

  const modalidad = textoModalidad(opcion);
  const ubicacion = [
    opcion.municipio,
    opcion.estado
  ].filter(Boolean).join(", ");

  return [
    "Mi profesional seleccionado en MirrorSoul:",
    "",
    `Nombre: ${opcion.nombre || "Profesional"}`,
    opcion.especialidad ? `Especialidad: ${opcion.especialidad}` : null,
    opcion.telefono ? `Teléfono: ${opcion.telefono}` : null,
    opcion.correo ? `Correo: ${opcion.correo}` : null,
    modalidad ? `Modalidad: ${modalidad}` : null,
    money(opcion.precio_presencial)
      ? `Precio presencial: ${money(opcion.precio_presencial)}`
      : null,
    money(opcion.precio_videollamada)
      ? `Precio videollamada: ${money(opcion.precio_videollamada)}`
      : null,
    ubicacion ? `Ubicación: ${ubicacion}` : null,
    opcion.direccion ? `Dirección: ${opcion.direccion}` : null,
    opcion.disponibilidad ? `Disponibilidad: ${opcion.disponibilidad}` : null
  ].filter(Boolean).join("\n");
};

export default function CanalizacionPublica() {
  const { token } =
    useParams();

  const [
    canalizacion,
    setCanalizacion
  ] = useState(null);

  const [
    opciones,
    setOpciones
  ] = useState([]);

  const [
    seleccionada,
    setSeleccionada
  ] = useState(null);

  const [
    cargando,
    setCargando
  ] = useState(true);

  const [
    guardando,
    setGuardando
  ] = useState(false);

  const [
    error,
    setError
  ] = useState("");

  const [
    mensaje,
    setMensaje
  ] = useState("");

  const opcionElegida =
    useMemo(
      () =>
        opciones.find(
          opcion =>
            Number(
              opcion.seleccionado
            ) === 1
        ) || null,
      [opciones]
    );

  const cargarCanalizacion =
    async () => {
      if (!token) {
        setError(
          "El enlace de canalización no es válido."
        );

        setCargando(false);

        return;
      }

      try {
        setCargando(true);
        setError("");

        const { data } =
          await axios.get(
            `${API_URL}/api/empleados/canalizacion-publica/${token}`
          );

        setCanalizacion(
          data?.canalizacion ||
          null
        );

        const lista =
          Array.isArray(
            data?.opciones
          )
            ? data.opciones
            : [];

        setOpciones(
          lista
        );

        const elegida =
          lista.find(
            item =>
              Number(
                item.seleccionado
              ) === 1
          );

        if (elegida) {
          setSeleccionada(
            Number(
              elegida.id_opcion
            )
          );
        }

      } catch (err) {
        console.error(
          "❌ Error cargando canalización pública:",
          err
        );

        setError(
          err.response?.data?.message ||
          "No fue posible abrir las opciones de canalización."
        );

      } finally {
        setCargando(false);
      }
    };

  useEffect(
    () => {
      cargarCanalizacion();
    },
    [token]
  );

  const seleccionar =
    idOpcion => {
      if (
        !canalizacion
          ?.puede_seleccionar
      ) {
        return;
      }

      setSeleccionada(
        Number(
          idOpcion
        )
      );

      setError("");
      setMensaje("");
    };

  const confirmarSeleccion =
    async () => {
      if (!seleccionada) {
        setError(
          "Selecciona una opción antes de continuar."
        );

        return;
      }

      const opcion =
        opciones.find(
          item =>
            Number(
              item.id_opcion
            ) ===
            Number(
              seleccionada
            )
        );

      const confirmar =
        window.confirm(
          `¿Confirmas que deseas seleccionar a ${opcion?.nombre || "este profesional"}?`
        );

      if (!confirmar) {
        return;
      }

      try {
        setGuardando(true);
        setError("");
        setMensaje("");

        const { data } =
          await axios.post(
            `${API_URL}/api/empleados/canalizacion-publica/${token}/seleccionar`,
            {
              id_opcion:
                Number(
                  seleccionada
                )
            }
          );

        setMensaje(
          data?.message ||
          "Tu selección fue registrada correctamente."
        );

        await cargarCanalizacion();

      } catch (err) {
        console.error(
          "❌ Error registrando selección:",
          err
        );

        setError(
          err.response?.data?.message ||
          "No fue posible registrar tu selección."
        );

      } finally {
        setGuardando(false);
      }
    };


  const compartirPorWhatsApp = () => {
    if (!opcionElegida) return;

    const texto = construirTextoProfesional(opcionElegida);

    window.open(
      `https://wa.me/?text=${encodeURIComponent(texto)}`,
      "_blank",
      "noopener,noreferrer"
    );
  };

  const enviarAMiCorreo = () => {
    if (!opcionElegida) return;

    const asunto = "Mi profesional seleccionado en MirrorSoul";
    const cuerpo = construirTextoProfesional(opcionElegida);

    window.location.href =
      `mailto:?subject=${encodeURIComponent(asunto)}&body=${encodeURIComponent(cuerpo)}`;
  };

  const copiarInformacion = async () => {
    if (!opcionElegida) return;

    const texto = construirTextoProfesional(opcionElegida);

    try {
      await navigator.clipboard.writeText(texto);
      setMensaje("Información del profesional copiada al portapapeles.");
    } catch {
      window.prompt(
        "Copia la información del profesional:",
        texto
      );
    }
  };

  const contactarPorWhatsApp = () => {
    if (!opcionElegida?.telefono) return;

    const telefono =
      normalizarTelefonoWhatsApp(opcionElegida.telefono);

    if (!telefono) return;

    const mensaje =
      `Hola ${opcionElegida.nombre || ""}. Te contacto porque te seleccioné como profesional de apoyo mediante MirrorSoul.`;

    window.open(
      `https://wa.me/${telefono}?text=${encodeURIComponent(mensaje)}`,
      "_blank",
      "noopener,noreferrer"
    );
  };

  const contactarPorCorreo = () => {
    if (!opcionElegida?.correo) return;

    const asunto =
      "Contacto desde canalización MirrorSoul";

    const cuerpo =
      `Hola ${opcionElegida.nombre || ""}.\n\nTe contacto porque te seleccioné como profesional de apoyo mediante MirrorSoul.`;

    window.location.href =
      `mailto:${opcionElegida.correo}?subject=${encodeURIComponent(asunto)}&body=${encodeURIComponent(cuerpo)}`;
  };

  if (cargando) {
    return (
      <div style={styles.page}>
        <div style={styles.loadingCard}>
          <div style={styles.spinner} />
          <strong>
            Cargando opciones...
          </strong>
        </div>
      </div>
    );
  }

  if (error && !canalizacion) {
    return (
      <div style={styles.page}>
        <div style={styles.messageCard}>
          <div style={styles.errorIcon}>
            !
          </div>

          <h2 style={styles.messageTitle}>
            No fue posible abrir la canalización
          </h2>

          <p style={styles.messageText}>
            {error}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div style={styles.page}>
      <main style={styles.container}>

        <section style={styles.hero}>
          <div style={styles.heroBadge}>
            MirrorSoul · Canalización
          </div>

          <h1 style={styles.title}>
            Opciones de apoyo profesional
          </h1>

          <p style={styles.subtitle}>
            Hola{" "}
            <strong>
              {canalizacion
                ?.empleado_nombre ||
                "empleado"}
            </strong>
            . Recursos Humanos ha puesto a tu disposición las siguientes opciones para que elijas la que mejor se adapte a ti.
          </p>

          {canalizacion
            ?.id_mirror && (
            <span style={styles.mirrorId}>
              ID Mirror:{" "}
              {canalizacion.id_mirror}
            </span>
          )}
        </section>

        <section style={styles.notice}>
          <strong>
            Tu elección es personal
          </strong>

          <span>
            Revisa las opciones disponibles antes de seleccionar. Una vez confirmada tu elección, Recursos Humanos recibirá únicamente la confirmación administrativa de la opción seleccionada.
          </span>
        </section>

        {error && (
          <div style={styles.errorBox}>
            {error}
          </div>
        )}

        {mensaje && (
          <div style={styles.successBox}>
            {mensaje}
          </div>
        )}

        {opcionElegida ? (
          <section style={styles.selectedSummary}>
            <div style={styles.successCircle}>
              ✓
            </div>

            <div style={styles.selectedContent}>
              <span style={styles.smallLabel}>
                Selección registrada
              </span>

              <h2 style={styles.selectedName}>
                {opcionElegida.nombre}
              </h2>

              <p style={styles.selectedMeta}>
                {opcionElegida.especialidad ||
                  "Profesional de apoyo"}
              </p>

              <div style={styles.selectedContactGrid}>
                {opcionElegida.telefono && (
                  <div style={styles.contactDataCard}>
                    <span style={styles.infoLabel}>
                      Teléfono
                    </span>

                    <strong>
                      {opcionElegida.telefono}
                    </strong>
                  </div>
                )}

                {opcionElegida.correo && (
                  <div style={styles.contactDataCard}>
                    <span style={styles.infoLabel}>
                      Correo
                    </span>

                    <strong style={styles.breakText}>
                      {opcionElegida.correo}
                    </strong>
                  </div>
                )}

                {textoModalidad(opcionElegida) && (
                  <div style={styles.contactDataCard}>
                    <span style={styles.infoLabel}>
                      Modalidad
                    </span>

                    <strong>
                      {textoModalidad(opcionElegida)}
                    </strong>
                  </div>
                )}

                {money(
                  opcionElegida.precio_presencial
                ) && (
                  <div style={styles.contactDataCard}>
                    <span style={styles.infoLabel}>
                      Precio presencial
                    </span>

                    <strong>
                      {money(
                        opcionElegida.precio_presencial
                      )}
                    </strong>
                  </div>
                )}

                {money(
                  opcionElegida.precio_videollamada
                ) && (
                  <div style={styles.contactDataCard}>
                    <span style={styles.infoLabel}>
                      Precio videollamada
                    </span>

                    <strong>
                      {money(
                        opcionElegida.precio_videollamada
                      )}
                    </strong>
                  </div>
                )}

                {(opcionElegida.municipio ||
                  opcionElegida.estado) && (
                  <div style={styles.contactDataCard}>
                    <span style={styles.infoLabel}>
                      Ubicación
                    </span>

                    <strong>
                      {[
                        opcionElegida.municipio,
                        opcionElegida.estado
                      ]
                        .filter(Boolean)
                        .join(", ")}
                    </strong>
                  </div>
                )}
              </div>

              {opcionElegida.direccion && (
                <div style={styles.selectedAddress}>
                  <span style={styles.infoLabel}>
                    Dirección
                  </span>

                  <strong>
                    {opcionElegida.direccion}
                  </strong>
                </div>
              )}

              <p style={styles.selectedNote}>
                Tu elección ya fue registrada y permanecerá disponible cuando vuelvas a abrir este mismo enlace.
              </p>

              {(opcionElegida.telefono ||
                opcionElegida.correo) && (
                <div style={styles.contactSection}>
                  <strong style={styles.actionTitle}>
                    Contactar al profesional
                  </strong>

                  <div style={styles.actionButtons}>
                    {opcionElegida.telefono && (
                      <button
                        type="button"
                        style={styles.whatsappButton}
                        onClick={contactarPorWhatsApp}
                      >
                        💬 Contactar por WhatsApp
                      </button>
                    )}

                    {opcionElegida.correo && (
                      <button
                        type="button"
                        style={styles.emailButton}
                        onClick={contactarPorCorreo}
                      >
                        ✉️ Enviar correo
                      </button>
                    )}
                  </div>
                </div>
              )}

              <div style={styles.saveSection}>
                <strong style={styles.actionTitle}>
                  Guardar o compartir mi selección
                </strong>

                <span style={styles.saveHelp}>
                  Puedes enviarte estos datos por WhatsApp, abrir un correo nuevo o copiarlos.
                </span>

                <div style={styles.actionButtons}>
                  <button
                    type="button"
                    style={styles.whatsappOutlineButton}
                    onClick={compartirPorWhatsApp}
                  >
                    💬 Compartir por WhatsApp
                  </button>

                  <button
                    type="button"
                    style={styles.secondaryActionButton}
                    onClick={enviarAMiCorreo}
                  >
                    ✉️ Enviar a mi correo
                  </button>

                  <button
                    type="button"
                    style={styles.secondaryActionButton}
                    onClick={copiarInformacion}
                  >
                    📋 Copiar información
                  </button>
                </div>
              </div>
            </div>
          </section>

        ) : !opciones.length ? (
          <section style={styles.emptyCard}>
            <strong>
              Aún no hay opciones disponibles
            </strong>

            <span>
              Recursos Humanos todavía no ha enviado profesionales para esta canalización.
            </span>
          </section>

        ) : (
          <>
            <div style={styles.sectionHeader}>
              <div>
                <h2 style={styles.sectionTitle}>
                  Elige una opción
                </h2>

                <p style={styles.sectionSubtitle}>
                  Selecciona una tarjeta para revisar y confirmar tu elección.
                </p>
              </div>

              <span style={styles.countBadge}>
                {opciones.length} opción(es)
              </span>
            </div>

            <section style={styles.grid}>
              {opciones.map(
                opcion => {
                  const activa =
                    Number(
                      seleccionada
                    ) ===
                    Number(
                      opcion.id_opcion
                    );

                  const modalidad =
                    textoModalidad(
                      opcion
                    );

                  const foto =
                    obtenerFotoProfesional(
                      opcion.foto_url
                    );

                  return (
                    <button
                      key={
                        opcion.id_opcion
                      }
                      type="button"
                      style={{
                        ...styles.card,
                        ...(activa
                          ? styles.cardActive
                          : {})
                      }}
                      onClick={() =>
                        seleccionar(
                          opcion.id_opcion
                        )
                      }
                    >
                      <div style={styles.cardTop}>

                        {/* ======================================
                            FOTO PROFESIONAL
                        ====================================== */}

                        <div style={styles.avatar}>
                          {foto ? (
                            <img
                              src={foto}
                              alt={
                                opcion.nombre ||
                                "Foto profesional"
                              }
                              style={
                                styles.avatarImage
                              }
                              onError={
                                e => {
                                  e.currentTarget.style.display =
                                    "none";

                                  const padre =
                                    e.currentTarget.parentElement;

                                  if (padre) {
                                    padre.textContent =
                                      obtenerInicial(
                                        opcion.nombre
                                      );
                                  }
                                }
                              }
                            />
                          ) : (
                            obtenerInicial(
                              opcion.nombre
                            )
                          )}
                        </div>

                        <div style={styles.cardHeading}>
                          <strong style={styles.professionalName}>
                            {opcion.nombre}
                          </strong>

                          <span style={styles.typeBadge}>
                            {opcion.tipo_profesional ===
                            "mirrorsoul"
                              ? "MirrorSoul"
                              : "Profesional externo"}
                          </span>
                        </div>

                        <div
                          style={{
                            ...styles.radio,
                            ...(activa
                              ? styles.radioActive
                              : {})
                          }}
                        >
                          {activa
                            ? "✓"
                            : ""}
                        </div>
                      </div>

                      <div style={styles.cardBody}>
                        <div style={styles.infoRow}>
                          <span style={styles.infoLabel}>
                            Especialidad
                          </span>

                          <strong>
                            {opcion.especialidad ||
                              "No especificada"}
                          </strong>
                        </div>

                        {opcion
                          .anos_experiencia !==
                          null &&
                          opcion
                            .anos_experiencia !==
                            undefined && (
                            <div style={styles.infoRow}>
                              <span style={styles.infoLabel}>
                                Experiencia
                              </span>

                              <strong>
                                {opcion.anos_experiencia} año(s)
                              </strong>
                            </div>
                          )}

                        {opcion.cedula_profesional && (
                          <div style={styles.infoRow}>
                            <span style={styles.infoLabel}>
                              Cédula profesional
                            </span>

                            <strong>
                              {opcion.cedula_profesional}
                            </strong>
                          </div>
                        )}

                        {!!opcion
                          .areas_atencion
                          ?.length && (
                          <div style={styles.areasSection}>
                            <span style={styles.infoLabel}>
                              Áreas de atención
                            </span>

                            <div style={styles.areasWrap}>
                              {opcion
                                .areas_atencion
                                .map(
                                  area => (
                                    <span
                                      key={area}
                                      style={
                                        styles.areaChip
                                      }
                                    >
                                      {area}
                                    </span>
                                  )
                                )}
                            </div>
                          </div>
                        )}

                        {modalidad && (
                          <div style={styles.infoRow}>
                            <span style={styles.infoLabel}>
                              Modalidad
                            </span>

                            <strong>
                              {modalidad}
                            </strong>
                          </div>
                        )}

                        {(opcion.municipio ||
                          opcion.estado) && (
                          <div style={styles.infoRow}>
                            <span style={styles.infoLabel}>
                              Ubicación
                            </span>

                            <strong>
                              {[
                                opcion.municipio,
                                opcion.estado
                              ]
                                .filter(Boolean)
                                .join(", ")}
                            </strong>
                          </div>
                        )}

                        {(money(
                          opcion.precio_presencial
                        ) ||
                          money(
                            opcion.precio_videollamada
                          )) && (
                          <div style={styles.priceBox}>
                            {money(
                              opcion.precio_presencial
                            ) && (
                              <span>
                                Presencial:{" "}
                                <strong>
                                  {money(
                                    opcion.precio_presencial
                                  )}
                                </strong>
                              </span>
                            )}

                            {money(
                              opcion.precio_videollamada
                            ) && (
                              <span>
                                Videollamada:{" "}
                                <strong>
                                  {money(
                                    opcion.precio_videollamada
                                  )}
                                </strong>
                              </span>
                            )}
                          </div>
                        )}

                        {opcion.descripcion && (
                          <p style={styles.description}>
                            {opcion.descripcion}
                          </p>
                        )}

                        {opcion.disponibilidad && (
                          <div style={styles.infoRow}>
                            <span style={styles.infoLabel}>
                              Disponibilidad
                            </span>

                            <strong>
                              {opcion.disponibilidad}
                            </strong>
                          </div>
                        )}
                      </div>

                      <div style={styles.cardFooter}>
                        {activa
                          ? "Seleccionado"
                          : "Seleccionar esta opción"}
                      </div>
                    </button>
                  );
                }
              )}
            </section>

            <div style={styles.confirmBar}>
              <div>
                <strong>
                  {seleccionada
                    ? "Opción seleccionada"
                    : "Selecciona un profesional"}
                </strong>

                <span>
                  {seleccionada
                    ? "Confirma para registrar tu elección."
                    : "Puedes revisar todas las opciones antes de decidir."}
                </span>
              </div>

              <button
                type="button"
                style={{
                  ...styles.confirmButton,
                  ...(!seleccionada ||
                  guardando
                    ? styles.confirmButtonDisabled
                    : {})
                }}
                disabled={
                  !seleccionada ||
                  guardando
                }
                onClick={
                  confirmarSeleccion
                }
              >
                {guardando
                  ? "Guardando..."
                  : "Confirmar selección"}
              </button>
            </div>
          </>
        )}

        <footer style={styles.footer}>
          <strong>
            MirrorSoul
          </strong>

          <span>
            Canalización administrativa de Recursos Humanos.
          </span>
        </footer>
      </main>
    </div>
  );
}

const styles = {
  page: {
    minHeight: "100vh",
    background:
      "linear-gradient(180deg, #f5f8ff 0%, #eef3fb 100%)",
    padding: "28px 16px 50px",
    fontFamily:
      "Inter, system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    color: "#15213b"
  },

  container: {
    width: "100%",
    maxWidth: 1120,
    margin: "0 auto"
  },

  hero: {
    background: "#ffffff",
    border: "1px solid #dfe7f4",
    borderRadius: 22,
    padding: "30px",
    boxShadow:
      "0 12px 34px rgba(31, 50, 90, 0.06)"
  },

  heroBadge: {
    display: "inline-flex",
    padding: "7px 12px",
    borderRadius: 999,
    background: "#edf3ff",
    color: "#2456d6",
    fontSize: 13,
    fontWeight: 800,
    marginBottom: 14
  },

  title: {
    margin: 0,
    fontSize: "clamp(28px, 5vw, 42px)",
    lineHeight: 1.1,
    color: "#12203a"
  },

  subtitle: {
    margin: "14px 0 0",
    maxWidth: 760,
    fontSize: 16,
    lineHeight: 1.7,
    color: "#52617a"
  },

  mirrorId: {
    display: "inline-flex",
    marginTop: 16,
    color: "#6a7890",
    fontSize: 13,
    fontWeight: 700
  },

  notice: {
    display: "flex",
    flexDirection: "column",
    gap: 5,
    marginTop: 16,
    padding: "16px 18px",
    borderRadius: 16,
    border: "1px solid #dbe7ff",
    background: "#f8fbff",
    color: "#425372",
    fontSize: 14,
    lineHeight: 1.55
  },

  errorBox: {
    marginTop: 16,
    padding: "14px 16px",
    borderRadius: 14,
    border: "1px solid #f2c3c3",
    background: "#fff5f5",
    color: "#a22424",
    fontWeight: 700
  },

  successBox: {
    marginTop: 16,
    padding: "14px 16px",
    borderRadius: 14,
    border: "1px solid #bfe5cb",
    background: "#f3fff7",
    color: "#1c7040",
    fontWeight: 700
  },

  sectionHeader: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "flex-end",
    gap: 16,
    marginTop: 28,
    marginBottom: 14
  },

  sectionTitle: {
    margin: 0,
    fontSize: 22,
    color: "#17243d"
  },

  sectionSubtitle: {
    margin: "5px 0 0",
    color: "#697791",
    fontSize: 14
  },

  countBadge: {
    flexShrink: 0,
    padding: "7px 11px",
    borderRadius: 999,
    background: "#e8efff",
    color: "#2456d6",
    fontWeight: 800,
    fontSize: 13
  },

  grid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(260px, 1fr))",
    gap: 16
  },

  card: {
    border: "1px solid #dce4f2",
    background: "#ffffff",
    borderRadius: 18,
    padding: 0,
    textAlign: "left",
    overflow: "hidden",
    cursor: "pointer",
    color: "#17243d",
    boxShadow:
      "0 8px 22px rgba(31, 50, 90, 0.05)",
    transition:
      "transform .15s ease, border-color .15s ease, box-shadow .15s ease"
  },

  cardActive: {
    border: "2px solid #2764ef",
    boxShadow:
      "0 10px 28px rgba(39, 100, 239, 0.14)"
  },

  cardTop: {
    display: "flex",
    alignItems: "center",
    gap: 12,
    padding: "18px 18px 14px"
  },

  avatar: {
    width: 58,
    height: 58,
    minWidth: 58,
    borderRadius: "50%",
    display: "grid",
    placeItems: "center",
    background: "#e5edff",
    color: "#2854cd",
    fontSize: 19,
    fontWeight: 900,
    overflow: "hidden",
    border: "2px solid #edf2ff"
  },

  avatarImage: {
    width: "100%",
    height: "100%",
    objectFit: "cover",
    display: "block",
    borderRadius: "50%"
  },

  cardHeading: {
    minWidth: 0,
    flex: 1,
    display: "flex",
    flexDirection: "column",
    gap: 4
  },

  professionalName: {
    fontSize: 17,
    lineHeight: 1.25
  },

  typeBadge: {
    color: "#6d7a92",
    fontSize: 12,
    fontWeight: 700
  },

  radio: {
    width: 28,
    height: 28,
    borderRadius: 9,
    display: "grid",
    placeItems: "center",
    border: "2px solid #b9c5d8",
    background: "#fff",
    color: "#fff",
    fontWeight: 900
  },

  radioActive: {
    borderColor: "#2764ef",
    background: "#2764ef"
  },

  cardBody: {
    display: "flex",
    flexDirection: "column",
    gap: 10,
    padding: "0 18px 16px"
  },

  infoRow: {
    display: "flex",
    flexDirection: "column",
    gap: 2
  },

  infoLabel: {
    color: "#7a879d",
    fontSize: 11,
    textTransform: "uppercase",
    letterSpacing: ".04em",
    fontWeight: 800
  },

  areasSection: {
    display: "flex",
    flexDirection: "column",
    gap: 7
  },

  areasWrap: {
    display: "flex",
    flexWrap: "wrap",
    gap: 6
  },

  areaChip: {
    display: "inline-flex",
    padding: "5px 9px",
    borderRadius: 999,
    background: "#edf3ff",
    border: "1px solid #d4e1ff",
    color: "#2456d6",
    fontSize: 11,
    fontWeight: 700
  },

  priceBox: {
    display: "flex",
    flexDirection: "column",
    gap: 4,
    padding: 10,
    borderRadius: 12,
    background: "#f7f9fd",
    color: "#4b5b75",
    fontSize: 13
  },

  description: {
    margin: 0,
    paddingTop: 4,
    color: "#5c6b83",
    fontSize: 13,
    lineHeight: 1.5
  },

  cardFooter: {
    padding: "12px 18px",
    borderTop: "1px solid #edf1f7",
    color: "#2764ef",
    fontWeight: 800,
    fontSize: 13
  },

  confirmBar: {
    position: "sticky",
    bottom: 16,
    zIndex: 5,
    marginTop: 22,
    padding: "16px 18px",
    borderRadius: 18,
    display: "flex",
    alignItems: "center",
    justifyContent: "space-between",
    gap: 18,
    background: "rgba(255,255,255,.96)",
    border: "1px solid #dbe3ef",
    boxShadow:
      "0 14px 34px rgba(28, 45, 78, .12)",
    backdropFilter: "blur(10px)"
  },

  confirmButton: {
    border: 0,
    borderRadius: 12,
    padding: "13px 20px",
    background: "#2764ef",
    color: "#fff",
    fontWeight: 900,
    cursor: "pointer",
    whiteSpace: "nowrap"
  },

  confirmButtonDisabled: {
    opacity: 0.5,
    cursor: "not-allowed"
  },

  selectedSummary: {
    marginTop: 24,
    display: "flex",
    gap: 18,
    alignItems: "flex-start",
    background: "#ffffff",
    border: "1px solid #cae6d5",
    borderRadius: 20,
    padding: 24
  },

  successCircle: {
    width: 48,
    height: 48,
    minWidth: 48,
    borderRadius: "50%",
    display: "grid",
    placeItems: "center",
    background: "#e6f7ed",
    color: "#21804c",
    fontWeight: 900,
    fontSize: 21
  },

  smallLabel: {
    color: "#21804c",
    fontSize: 12,
    fontWeight: 900,
    textTransform: "uppercase",
    letterSpacing: ".04em"
  },

  selectedName: {
    margin: "5px 0 3px",
    fontSize: 22
  },

  selectedMeta: {
    margin: 0,
    color: "#53627a"
  },

  selectedNote: {
    margin: "12px 0 0",
    color: "#66758c",
    lineHeight: 1.5,
    fontSize: 14
  },


  selectedContent: {
    flex: 1,
    minWidth: 0
  },

  selectedContactGrid: {
    display: "grid",
    gridTemplateColumns:
      "repeat(auto-fit, minmax(190px, 1fr))",
    gap: 10,
    marginTop: 18
  },

  contactDataCard: {
    display: "flex",
    flexDirection: "column",
    gap: 4,
    padding: "12px 14px",
    borderRadius: 12,
    background: "#f7fafc",
    border: "1px solid #e4eaf2",
    color: "#33435d"
  },

  selectedAddress: {
    display: "flex",
    flexDirection: "column",
    gap: 4,
    marginTop: 10,
    padding: "12px 14px",
    borderRadius: 12,
    background: "#f7fafc",
    border: "1px solid #e4eaf2",
    color: "#33435d"
  },

  breakText: {
    overflowWrap: "anywhere"
  },

  contactSection: {
    marginTop: 18,
    paddingTop: 18,
    borderTop: "1px solid #e4eaf2"
  },

  saveSection: {
    marginTop: 18,
    padding: 16,
    borderRadius: 14,
    background: "#f7f9fd",
    border: "1px solid #e0e7f1"
  },

  actionTitle: {
    display: "block",
    marginBottom: 8,
    color: "#22334e"
  },

  saveHelp: {
    display: "block",
    marginBottom: 12,
    color: "#66758c",
    lineHeight: 1.5,
    fontSize: 13
  },

  actionButtons: {
    display: "flex",
    flexWrap: "wrap",
    gap: 10
  },

  whatsappButton: {
    border: 0,
    borderRadius: 11,
    padding: "11px 15px",
    background: "#1f9d55",
    color: "#ffffff",
    fontWeight: 800,
    cursor: "pointer"
  },

  emailButton: {
    border: 0,
    borderRadius: 11,
    padding: "11px 15px",
    background: "#2764ef",
    color: "#ffffff",
    fontWeight: 800,
    cursor: "pointer"
  },

  whatsappOutlineButton: {
    border: "1px solid #7fd3a0",
    borderRadius: 11,
    padding: "11px 15px",
    background: "#f1fff6",
    color: "#177642",
    fontWeight: 800,
    cursor: "pointer"
  },

  secondaryActionButton: {
    border: "1px solid #cfd8e6",
    borderRadius: 11,
    padding: "11px 15px",
    background: "#ffffff",
    color: "#33435d",
    fontWeight: 800,
    cursor: "pointer"
  },

  emptyCard: {
    marginTop: 24,
    padding: 28,
    borderRadius: 18,
    border: "1px dashed #cbd5e5",
    background: "#ffffff",
    display: "flex",
    flexDirection: "column",
    gap: 6,
    color: "#66758c"
  },

  footer: {
    marginTop: 34,
    display: "flex",
    justifyContent: "space-between",
    gap: 16,
    borderTop: "1px solid #dce4ef",
    paddingTop: 18,
    color: "#7c899d",
    fontSize: 12
  },

  loadingCard: {
    width: "min(420px, calc(100% - 32px))",
    margin: "15vh auto 0",
    background: "#fff",
    borderRadius: 18,
    padding: 28,
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    gap: 14,
    border: "1px solid #e0e7f1"
  },

  spinner: {
    width: 24,
    height: 24,
    borderRadius: "50%",
    border: "3px solid #dce5f7",
    borderTopColor: "#2764ef"
  },

  messageCard: {
    width: "min(520px, calc(100% - 32px))",
    margin: "12vh auto 0",
    padding: 30,
    borderRadius: 20,
    background: "#fff",
    border: "1px solid #e2e8f1",
    textAlign: "center"
  },

  errorIcon: {
    width: 48,
    height: 48,
    margin: "0 auto 14px",
    borderRadius: "50%",
    display: "grid",
    placeItems: "center",
    background: "#fff0f0",
    color: "#b02d2d",
    fontWeight: 900,
    fontSize: 22
  },

  messageTitle: {
    margin: 0
  },

  messageText: {
    color: "#68778e",
    lineHeight: 1.6
  }
};