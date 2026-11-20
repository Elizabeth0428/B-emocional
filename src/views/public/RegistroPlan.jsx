
import React, {
  useMemo,
  useState,
} from "react";

import {
  useLocation,
  useNavigate,
} from "react-router-dom";

import NavbarPublica from "../../components/public/NavbarPublica";
import FooterPublico from "../../components/public/FooterPublico";

// ============================================================
// MIRRORSOUL - REGISTRO DE CONTRATACIÓN
// MODO CLARO / OSCURO
// ============================================================

function RegistroPlan() {
  const navigate = useNavigate();
  const location = useLocation();

  // ==========================================================
  // 1. LEER PLAN DESDE LA URL
  // ==========================================================

  const params = useMemo(
    () => new URLSearchParams(location.search),
    [location.search]
  );

  const tipoPlan = params.get("plan") || "";

  const idPlan = Number(params.get("id")) || null;

  const periodo =
    params.get("periodo") === "anual"
      ? "anual"
      : "mensual";

  // ==========================================================
  // 2. NOMBRE DEL PLAN
  // ==========================================================

  const nombrePlan =
    {
      independiente: "Independiente",
      clinica: "Clínica",
      rh: "Recursos Humanos",
      educativo: "Educativo",
    }[tipoPlan] || "MirrorSoul";

  // ==========================================================
  // 3. ESTADO DEL FORMULARIO
  // ==========================================================

  const [form, setForm] = useState({
    nombre_organizacion: "",
    nombre_responsable: "",
    correo: "",
    telefono: "",
    tipo_organizacion: tipoPlan,
    periodo_facturacion: periodo,
    numero_usuarios: "",
    requiere_factura: false,
    rfc: "",
    observaciones: "",
  });

  const [cargando, setCargando] = useState(false);
  const [error, setError] = useState("");

  // ==========================================================
  // 4. ACTUALIZAR CAMPOS
  // ==========================================================

  const handleChange = (e) => {
    const {
      name,
      value,
      type,
      checked,
    } = e.target;

    let nuevoValor =
      type === "checkbox" ? checked : value;

    if (name === "rfc") {
      nuevoValor = String(value)
        .toUpperCase()
        .replace(/\s+/g, "");
    }

    setForm((prev) => ({
      ...prev,
      [name]: nuevoValor,

      ...(name === "requiere_factura" && !checked
        ? { rfc: "" }
        : {}),
    }));

    if (error) {
      setError("");
    }
  };

  // ==========================================================
  // 5. VALIDACIÓN
  // ==========================================================

  const validar = () => {
    if (
      tipoPlan &&
      ![
        "independiente",
        "clinica",
        "rh",
        "educativo",
      ].includes(tipoPlan)
    ) {
      return "El plan seleccionado no es válido.";
    }

    if (!tipoPlan) {
      return "Selecciona un plan antes de continuar.";
    }

    if (
      tipoPlan !== "independiente" &&
      !form.nombre_organizacion.trim()
    ) {
      return "Ingresa el nombre de la organización.";
    }

    if (!form.nombre_responsable.trim()) {
      return "Ingresa el nombre del responsable.";
    }

    if (!form.correo.trim()) {
      return "Ingresa un correo electrónico.";
    }

    const correoValido =
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
        form.correo.trim()
      );

    if (!correoValido) {
      return "Ingresa un correo electrónico válido.";
    }

    if (!form.telefono.trim()) {
      return "Ingresa un teléfono de contacto.";
    }

    if (form.requiere_factura) {
      if (!form.rfc.trim()) {
        return "Ingresa el RFC para solicitar factura.";
      }

      const rfcValido =
        /^[A-ZÑ&]{3,4}\d{6}[A-Z0-9]{3}$/i.test(
          form.rfc.trim()
        );

      if (!rfcValido) {
        return "Ingresa un RFC válido.";
      }
    }

    return null;
  };

  // ==========================================================
  // 6. CONTINUAR AL CHECKOUT
  // ==========================================================

  const continuar = (e) => {
    e.preventDefault();

    if (cargando) {
      return;
    }

    const validacion = validar();

    if (validacion) {
      setError(validacion);
      return;
    }

    setCargando(true);

    const datos = {
      ...form,

      nombre_organizacion:
        form.nombre_organizacion.trim(),

      nombre_responsable:
        form.nombre_responsable.trim(),

      correo: form.correo.trim(),

      telefono: form.telefono.trim(),

      rfc: form.rfc.trim(),

      id_plan: idPlan,
      tipo_plan: tipoPlan,
      tipo_organizacion: tipoPlan,
      periodo_facturacion: periodo,
    };

    try {
      // Guardamos exactamente la clave que
      // utiliza el proceso de contratación.

      sessionStorage.setItem(
        "mirrorsoul_plan_registro",
        JSON.stringify(datos)
      );

      // Mantener la ruta original del checkout.

      const query = new URLSearchParams({
        plan: tipoPlan,
        periodo,
      });

      if (idPlan) {
        query.set("id", String(idPlan));
      }

      navigate(`/checkout?${query.toString()}`);
    } catch {
      setCargando(false);

      setError(
        "No fue posible conservar los datos. " +
        "Verifica que el navegador permita " +
        "el almacenamiento de sesión."
      );
    }
  };

  // ==========================================================
  // 7. CAMPOS REUTILIZABLES
  // ==========================================================

  const campo = ({
    nombre,
    etiqueta,
    tipo = "text",
    placeholder = "",
    requerido = false,
    autoComplete,
    maxLength,
  }) => (
    <div className="ms-reg-field" key={nombre}>
      <label
        className="ms-reg-label"
        htmlFor={`ms-reg-${nombre}`}
      >
        {etiqueta}
        {requerido && (
          <span className="ms-reg-required"> *</span>
        )}
      </label>

      <input
        id={`ms-reg-${nombre}`}
        type={tipo}
        name={nombre}
        value={form[nombre]}
        onChange={handleChange}
        placeholder={placeholder}
        autoComplete={autoComplete}
        maxLength={maxLength}
        required={requerido}
        min={tipo === "number" ? 1 : undefined}
        className="ms-reg-input"
      />
    </div>
  );

  // ==========================================================
  // 8. COMPONENTE
  // ==========================================================

  return (
    <div className="ms-reg-page">
      <NavbarPublica />

      <main>

        {/* ================================================== */}
        {/* ENCABEZADO */}
        {/* ================================================== */}

        <section className="ms-reg-hero">
          <div className="ms-reg-hero-content">

            <span className="ms-reg-eyebrow">
              CONTRATACIÓN MIRRORSOUL
            </span>

            <h1 className="ms-reg-title">
              Comencemos con tus datos.
            </h1>

            <p className="ms-reg-description">
              Estás por iniciar el proceso
              para contratar el plan{" "}
              <strong className="ms-reg-highlight">
                {nombrePlan}
              </strong>.
            </p>

          </div>
        </section>

        {/* ================================================== */}
        {/* FORMULARIO Y RESUMEN */}
        {/* ================================================== */}

        <section className="ms-reg-form-section">
          <div className="ms-reg-container">

            <div className="ms-reg-layout">

              {/* ========================================== */}
              {/* FORMULARIO */}
              {/* ========================================== */}

              <form
                className="ms-reg-form-card"
                onSubmit={continuar}
              >
                <div className="ms-reg-form-header">

                  <span className="ms-reg-card-eyebrow">
                    DATOS PRINCIPALES
                  </span>

                  <h2 className="ms-reg-form-title">
                    Información de contacto
                  </h2>

                  <p className="ms-reg-form-description">
                    Estos datos se utilizarán para
                    preparar tu cuenta y continuar
                    con la contratación.
                  </p>

                </div>

                {/* ======================================== */}
                {/* NOMBRE DE ORGANIZACIÓN */}
                {/* ======================================== */}

                {tipoPlan !== "independiente" &&
                  campo({
                    nombre: "nombre_organizacion",
                    etiqueta: "Nombre de la organización",
                    placeholder:
                      "Ej. Clínica Bienestar Integral",
                    requerido: true,
                    autoComplete: "organization",
                  })}

                {/* ======================================== */}
                {/* RESPONSABLE */}
                {/* ======================================== */}

                {campo({
                  nombre: "nombre_responsable",
                  etiqueta: "Nombre del responsable",
                  placeholder: "Nombre completo",
                  requerido: true,
                  autoComplete: "name",
                })}

                {/* ======================================== */}
                {/* CORREO Y TELÉFONO */}
                {/* ======================================== */}

                <div className="ms-reg-two-columns">

                  {campo({
                    nombre: "correo",
                    etiqueta: "Correo electrónico",
                    tipo: "email",
                    placeholder: "correo@empresa.com",
                    requerido: true,
                    autoComplete: "email",
                  })}

                  {campo({
                    nombre: "telefono",
                    etiqueta: "Teléfono",
                    tipo: "tel",
                    placeholder: "55 0000 0000",
                    requerido: true,
                    autoComplete: "tel",
                  })}

                </div>

                {/* ======================================== */}
                {/* TIPO DE SOLUCIÓN Y USUARIOS */}
                {/* ======================================== */}

                <div className="ms-reg-two-columns">

                  <div className="ms-reg-field">

                    <label
                      className="ms-reg-label"
                      htmlFor="ms-reg-tipo"
                    >
                      Tipo de solución
                    </label>

                    <input
                      id="ms-reg-tipo"
                      type="text"
                      value={nombrePlan}
                      readOnly
                      className="ms-reg-input ms-reg-input-readonly"
                    />

                  </div>

                  {campo({
                    nombre: "numero_usuarios",
                    etiqueta: "Usuarios aproximados",
                    tipo: "number",
                    placeholder: "Ej. 5",
                  })}

                </div>

                {/* ======================================== */}
                {/* FACTURACIÓN */}
                {/* ======================================== */}

                <div className="ms-reg-invoice">

                  <label className="ms-reg-invoice-option">

                    <input
                      type="checkbox"
                      name="requiere_factura"
                      checked={form.requiere_factura}
                      onChange={handleChange}
                      className="ms-reg-checkbox"
                    />

                    <span>
                      <strong className="ms-reg-invoice-title">
                        Requiero factura
                      </strong>

                      <span className="ms-reg-invoice-text">
                        Activa esta opción si necesitas
                        factura por la contratación.
                      </span>
                    </span>

                  </label>

                  {form.requiere_factura && (
                    <div className="ms-reg-invoice-fields">

                      {campo({
                        nombre: "rfc",
                        etiqueta: "RFC",
                        placeholder: "Ej. ABC123456XYZ",
                        requerido: true,
                        maxLength: 13,
                      })}

                      <span className="ms-reg-helper">
                        El RFC se utilizará para
                        los datos de facturación.
                      </span>

                    </div>
                  )}

                </div>

                {/* ======================================== */}
                {/* OBSERVACIONES */}
                {/* ======================================== */}

                <div className="ms-reg-field">

                  <label
                    className="ms-reg-label"
                    htmlFor="ms-reg-observaciones"
                  >
                    ¿Hay algo que debamos saber?
                  </label>

                  <textarea
                    id="ms-reg-observaciones"
                    name="observaciones"
                    value={form.observaciones}
                    onChange={handleChange}
                    placeholder={
                      "Puedes contarnos brevemente " +
                      "qué necesitas..."
                    }
                    className="ms-reg-textarea"
                  />

                </div>

                {/* ======================================== */}
                {/* MENSAJE DE ERROR */}
                {/* ======================================== */}

                {error && (
                  <div
                    className="ms-reg-error"
                    role="alert"
                  >
                    {error}
                  </div>
                )}

                {/* ======================================== */}
                {/* ACCIONES */}
                {/* ======================================== */}

                <div className="ms-reg-actions">

                  <button
                    type="button"
                    className="ms-reg-back"
                    onClick={() => navigate("/planes")}
                  >
                    ← Regresar
                  </button>

                  <button
                    type="submit"
                    className="ms-reg-continue"
                    disabled={cargando}
                  >
                    {cargando
                      ? "Continuando..."
                      : "Continuar al pago"}

                    {!cargando && (
                      <span aria-hidden="true">
                        →
                      </span>
                    )}
                  </button>

                </div>

              </form>

              {/* ========================================== */}
              {/* RESUMEN LATERAL */}
              {/* ========================================== */}

              <aside className="ms-reg-summary">

                <span className="ms-reg-card-eyebrow">
                  TU SELECCIÓN
                </span>

                <h2 className="ms-reg-summary-title">
                  Plan {nombrePlan}
                </h2>

                <p className="ms-reg-summary-description">
                  Antes de realizar cualquier pago
                  podrás revisar todos los detalles
                  de tu contratación.
                </p>

                <div className="ms-reg-divider" />

                <div className="ms-reg-summary-row">
                  <span>Plan</span>
                  <strong>{nombrePlan}</strong>
                </div>

                <div className="ms-reg-summary-row">
                  <span>Modalidad</span>
                  <strong>Suscripción</strong>
                </div>

                <div className="ms-reg-summary-row">
                  <span>Periodo</span>
                  <strong>
                    {periodo === "anual"
                      ? "Anual"
                      : "Mensual"}
                  </strong>
                </div>

                <div className="ms-reg-summary-row">
                  <span>Factura</span>
                  <strong>
                    {form.requiere_factura
                      ? "Sí"
                      : "No"}
                  </strong>
                </div>

                {form.requiere_factura && (
                  <div className="ms-reg-summary-row">
                    <span>RFC</span>

                    <strong>
                      {form.rfc || "Pendiente"}
                    </strong>
                  </div>
                )}

                <div className="ms-reg-summary-row">
                  <span>Precio</span>

                  <strong className="ms-reg-pending">
                    Por definir
                  </strong>
                </div>

                <div className="ms-reg-divider" />

                {/* ======================================== */}
                {/* SEGURIDAD */}
                {/* ======================================== */}

                <div className="ms-reg-security">

                  <span
                    className="ms-reg-security-icon"
                    aria-hidden="true"
                  >
                    🔒
                  </span>

                  <div>
                    <strong>
                      Proceso seguro
                    </strong>

                    <span>
                      No se realizará ningún cargo
                      en esta pantalla.
                    </span>
                  </div>

                </div>

                {/* ======================================== */}
                {/* INDICADOR DE PROGRESO */}
                {/* ======================================== */}

                <div className="ms-reg-steps">

                  <div className="ms-reg-step">
                    <span className="ms-reg-step-active">
                      1
                    </span>
                    <span>Datos</span>
                  </div>

                  <div className="ms-reg-step-line" />

                  <div className="ms-reg-step">
                    <span className="ms-reg-step-pending">
                      2
                    </span>
                    <span>Resumen</span>
                  </div>

                  <div className="ms-reg-step-line" />

                  <div className="ms-reg-step">
                    <span className="ms-reg-step-pending">
                      3
                    </span>
                    <span>Pago</span>
                  </div>

                </div>

              </aside>

            </div>
          </div>
        </section>

      </main>

      <FooterPublico />

      {/* ==================================================== */}
      {/* ESTILOS COMPLETOS */}
      {/* ==================================================== */}

      <style>{`

        /* ================================================
           1. MODO CLARO
           ================================================ */

        :root,
        :root[data-ms-theme="claro"] {
          --reg-bg: linear-gradient(
            180deg,
            #f8fbff,
            #edf5ff 60%,
            #ffffff
          );

          --reg-title: #142842;
          --reg-text: #506580;
          --reg-muted: #62748a;
          --reg-accent: #1768ba;

          --reg-card: #ffffff;
          --reg-border: #d9e6f4;

          --reg-input-bg: #f8fbff;
          --reg-input-border: #cedff0;
          --reg-input-text: #142842;
          --reg-placeholder: #788ba2;

          --reg-soft-bg: #edf5ff;
          --reg-soft-border: #d8e7f6;

          --reg-divider: #dce7f3;

          --reg-security-bg: #e8f6ff;

          --reg-error-bg: #fff1f0;
          --reg-error-border: #f3c7c2;
          --reg-error-text: #a32f2b;

          --reg-shadow:
            0 22px 55px rgba(30, 70, 120, 0.09);
        }

        /* ================================================
           2. MODO OSCURO
           ================================================ */

        :root[data-ms-theme="oscuro"] {
          --reg-bg: linear-gradient(
            180deg,
            #07111f,
            #091624 60%,
            #07111f
          );

          --reg-title: #ffffff;
          --reg-text: #c4d3e5;
          --reg-muted: #a9bdd3;
          --reg-accent: #72e9ff;

          --reg-card: #122236;
          --reg-border: rgba(255,255,255,0.11);

          --reg-input-bg: #0b1a2b;
          --reg-input-border: rgba(255,255,255,0.16);
          --reg-input-text: #ffffff;
          --reg-placeholder: #92a8c0;

          --reg-soft-bg: #192d43;
          --reg-soft-border: rgba(255,255,255,0.12);

          --reg-divider: rgba(255,255,255,0.12);

          --reg-security-bg: #193347;

          --reg-error-bg: #351f29;
          --reg-error-border: #79404b;
          --reg-error-text: #ffb5b5;

          --reg-shadow:
            0 25px 70px rgba(0,0,0,0.22);
        }

        /* ================================================
           3. PÁGINA PRINCIPAL
           ================================================ */

        .ms-reg-page {
          min-height: 100vh;
          width: 100%;

          background: var(--reg-bg);
          color: var(--reg-title);

          font-family:
            "Inter",
            "Segoe UI",
            Arial,
            sans-serif;

          transition:
            background 0.3s ease,
            color 0.3s ease;
        }

        .ms-reg-page,
        .ms-reg-page * {
          box-sizing: border-box;
        }

        /* ================================================
           4. ENCABEZADO
           ================================================ */

        .ms-reg-hero {
          padding: 75px 28px 45px;

          text-align: center;

          background:
            radial-gradient(
              circle at 50% 0%,
              rgba(94,149,255,0.09),
              transparent 55%
            );
        }

        .ms-reg-hero-content {
          max-width: 850px;
          margin: 0 auto;
        }

        .ms-reg-eyebrow {
          display: inline-block;

          margin-bottom: 15px;

          color: var(--reg-accent);

          font-size: 13px;
          font-weight: 900;
          letter-spacing: 1.8px;
        }

        .ms-reg-page .ms-reg-title {
          margin: 0;

          color: var(--reg-title) !important;

          font-size:
            clamp(2.4rem,4vw,3.7rem) !important;

          line-height: 1.1 !important;
          font-weight: 900;
          letter-spacing: -1.4px;
        }

        .ms-reg-page .ms-reg-description {
          max-width: 680px;

          margin: 22px auto 0;

          color: var(--reg-text) !important;

          font-size: 18px !important;
          line-height: 1.75 !important;
        }

        .ms-reg-highlight {
          color: var(--reg-accent);
          font-weight: 900;
        }

        /* ================================================
           5. CONTENEDOR
           ================================================ */

        .ms-reg-form-section {
          padding: 25px 28px 100px;
        }

        .ms-reg-container {
          max-width: 1180px;
          margin: 0 auto;
        }

        .ms-reg-layout {
          display: grid;

          grid-template-columns:
            minmax(0,1fr)
            minmax(290px,360px);

          align-items: start;
          gap: 25px;
        }

        /* ================================================
           6. TARJETAS
           ================================================ */

        .ms-reg-form-card,
        .ms-reg-summary {
          min-width: 0;

          padding: 34px;

          border-radius: 24px;
          border: 1px solid var(--reg-border);

          background: var(--reg-card);
          box-shadow: var(--reg-shadow);

          color: var(--reg-title);

          transition:
            background 0.3s ease,
            border-color 0.3s ease,
            color 0.3s ease;
        }

        .ms-reg-summary {
          position: sticky;
          top: 100px;

          padding: 27px;
        }

        /* ================================================
           7. TÍTULOS DE TARJETA
           ================================================ */

        .ms-reg-form-header {
          margin-bottom: 30px;
        }

        .ms-reg-card-eyebrow {
          display: block;

          color: var(--reg-accent);

          font-size: 12px;
          font-weight: 900;
          letter-spacing: 1.5px;
        }

        .ms-reg-page .ms-reg-form-title {
          margin: 10px 0 0;

          color: var(--reg-title) !important;

          font-size: 29px !important;
          font-weight: 900;
        }

        .ms-reg-page .ms-reg-form-description,
        .ms-reg-page .ms-reg-summary-description {
          margin: 13px 0 0;

          color: var(--reg-text) !important;

          font-size: 15px !important;
          line-height: 1.7 !important;
        }

        /* ================================================
           8. CAMPOS
           ================================================ */

        .ms-reg-field {
          min-width: 0;
          margin-bottom: 20px;
        }

        .ms-reg-label {
          display: block;

          margin-bottom: 9px;

          color: var(--reg-title);

          font-size: 14px;
          font-weight: 800;
        }

        .ms-reg-required {
          color: #dc5555;
        }

        .ms-reg-two-columns {
          display: grid;
          grid-template-columns: repeat(2,minmax(0,1fr));

          gap: 17px;
        }

        .ms-reg-input,
        .ms-reg-textarea {
          display: block;

          width: 100%;

          padding: 14px 15px;

          border: 1px solid var(--reg-input-border);
          border-radius: 12px;

          background: var(--reg-input-bg);
          color: var(--reg-input-text);

          font-family: inherit;
          font-size: 15px;
          line-height: 1.5;

          outline: none;

          transition:
            background 0.2s ease,
            border-color 0.2s ease,
            box-shadow 0.2s ease;
        }

        .ms-reg-input::placeholder,
        .ms-reg-textarea::placeholder {
          color: var(--reg-placeholder);
          opacity: 1;
        }

        .ms-reg-input:focus,
        .ms-reg-textarea:focus {
          border-color: #448de6;

          box-shadow:
            0 0 0 3px rgba(68,141,230,0.12);
        }

        .ms-reg-input-readonly {
          color: var(--reg-muted);
          cursor: default;
        }

        .ms-reg-textarea {
          min-height: 125px;
          resize: vertical;
        }

        /* ================================================
           9. FACTURACIÓN
           ================================================ */

        .ms-reg-invoice {
          margin-bottom: 22px;
          padding: 20px;

          border-radius: 16px;

          background: var(--reg-soft-bg);
          border: 1px solid var(--reg-soft-border);
        }

        .ms-reg-invoice-option {
          display: flex;
          align-items: flex-start;
          gap: 13px;

          cursor: pointer;
        }

        .ms-reg-checkbox {
          flex-shrink: 0;

          width: 19px;
          height: 19px;
          margin-top: 3px;

          accent-color: #2563eb;
          cursor: pointer;
        }

        .ms-reg-invoice-title {
          display: block;

          color: var(--reg-title);

          font-size: 16px;
          font-weight: 900;
        }

        .ms-reg-invoice-text {
          display: block;
          margin-top: 6px;

          color: var(--reg-text);

          font-size: 14px;
          line-height: 1.6;
        }

        .ms-reg-invoice-fields {
          margin-top: 20px;
          padding-top: 19px;

          border-top: 1px solid var(--reg-soft-border);
        }

        .ms-reg-helper {
          display: block;

          margin-top: 8px;

          color: var(--reg-muted);

          font-size: 13px;
          line-height: 1.6;
        }

        /* ================================================
           10. ERROR
           ================================================ */

        .ms-reg-error {
          margin-top: 10px;
          padding: 14px 16px;

          border-radius: 12px;

          background: var(--reg-error-bg);
          border: 1px solid var(--reg-error-border);

          color: var(--reg-error-text);

          font-size: 14px;
          font-weight: 700;
          line-height: 1.5;
        }

        /* ================================================
           11. BOTONES
           ================================================ */

        .ms-reg-actions {
          display: flex;
          justify-content: space-between;
          align-items: center;

          gap: 14px;
          margin-top: 30px;
        }

        .ms-reg-back,
        .ms-reg-continue {
          display: inline-flex;
          align-items: center;
          justify-content: center;

          gap: 10px;

          min-height: 51px;
          padding: 13px 20px;

          border-radius: 12px;

          font-family: inherit;
          font-size: 15px;
          font-weight: 900;

          cursor: pointer;

          transition:
            transform 0.2s ease,
            background 0.2s ease;
        }

        .ms-reg-back {
          border: 1px solid var(--reg-border);

          background: var(--reg-soft-bg);
          color: var(--reg-title);
        }

        .ms-reg-continue {
          border: none;

          background: linear-gradient(
            135deg,
            #65e5ff,
            #917eff
          );

          color: #07111f;
        }

        .ms-reg-back:hover,
        .ms-reg-continue:hover:not(:disabled) {
          transform: translateY(-2px);
        }

        .ms-reg-continue:disabled {
          opacity: 0.65;
          cursor: wait;
        }

        .ms-reg-page button:focus-visible {
          outline: 3px solid #2563eb;
          outline-offset: 3px;
        }

        /* ================================================
           12. RESUMEN
           ================================================ */

        .ms-reg-page .ms-reg-summary-title {
          margin: 12px 0 0;

          color: var(--reg-title) !important;

          font-size: 26px !important;
          font-weight: 900;
        }

        .ms-reg-divider {
          height: 1px;
          margin: 24px 0;

          background: var(--reg-divider);
        }

        .ms-reg-summary-row {
          display: flex;
          align-items: flex-start;
          justify-content: space-between;

          gap: 12px;
          margin-bottom: 17px;
        }

        .ms-reg-summary-row > span {
          color: var(--reg-text);

          font-size: 14px;
          line-height: 1.5;
        }

        .ms-reg-summary-row > strong {
          color: var(--reg-title);

          font-size: 14px;
          line-height: 1.5;
          font-weight: 900;

          text-align: right;
          overflow-wrap: anywhere;
        }

        .ms-reg-summary-row .ms-reg-pending {
          color: var(--reg-accent);
        }

        /* ================================================
           13. SEGURIDAD
           ================================================ */

        .ms-reg-security {
          display: flex;
          align-items: flex-start;
          gap: 12px;
        }

        .ms-reg-security-icon {
          display: flex;
          align-items: center;
          justify-content: center;

          flex-shrink: 0;

          width: 43px;
          height: 43px;

          border-radius: 12px;
          background: var(--reg-security-bg);

          font-size: 20px;
        }

        .ms-reg-security strong {
          display: block;

          color: var(--reg-title);

          font-size: 14px;
          font-weight: 900;
        }

        .ms-reg-security div > span {
          display: block;

          margin-top: 6px;

          color: var(--reg-text);

          font-size: 13px;
          line-height: 1.55;
        }

        /* ================================================
           14. PASOS DE CONTRATACIÓN
           ================================================ */

        .ms-reg-steps {
          display: flex;
          align-items: center;
          justify-content: space-between;

          margin-top: 32px;
        }

        .ms-reg-step {
          display: flex;
          flex-direction: column;
          align-items: center;

          gap: 9px;

          color: var(--reg-text);

          font-size: 12px;
          font-weight: 700;
        }

        .ms-reg-step-active,
        .ms-reg-step-pending {
          display: flex;
          align-items: center;
          justify-content: center;

          width: 34px;
          height: 34px;

          border-radius: 11px;

          font-size: 13px;
          font-weight: 900;
        }

        .ms-reg-step-active {
          background: linear-gradient(
            135deg,
            #65e5ff,
            #917eff
          );

          color: #07111f;
        }

        .ms-reg-step-pending {
          background: var(--reg-soft-bg);

          border: 1px solid var(--reg-soft-border);
          color: var(--reg-muted);
        }

        .ms-reg-step-line {
          flex: 1;
          height: 1px;

          margin: 0 9px 23px;
          background: var(--reg-divider);
        }

        /* ================================================
           15. TABLET
           ================================================ */

        @media (max-width: 950px) {
          .ms-reg-layout {
            grid-template-columns: 1fr;
          }

          .ms-reg-summary {
            position: static;
          }
        }

        /* ================================================
           16. CELULARES
           ================================================ */

        @media (max-width: 600px) {
          .ms-reg-hero {
            padding: 55px 20px 30px;
          }

          .ms-reg-form-section {
            padding: 20px 16px 70px;
          }

          .ms-reg-form-card,
          .ms-reg-summary {
            padding: 24px 19px;
            border-radius: 20px;
          }

          .ms-reg-two-columns {
            grid-template-columns: 1fr;
            gap: 0;
          }

          .ms-reg-page .ms-reg-title {
            font-size:
              clamp(2.1rem,7vw,2.9rem) !important;
          }

          .ms-reg-page .ms-reg-form-title {
            font-size: 25px !important;
          }

          .ms-reg-page .ms-reg-description {
            font-size: 16px !important;
          }

          .ms-reg-actions {
            flex-direction: column-reverse;
            align-items: stretch;
          }

          .ms-reg-back,
          .ms-reg-continue {
            width: 100%;
          }
        }

        /* ================================================
           17. MOVIMIENTO REDUCIDO
           ================================================ */

        @media (prefers-reduced-motion: reduce) {
          .ms-reg-page *,
          .ms-reg-page *::before,
          .ms-reg-page *::after {
            animation: none !important;
            transition: none !important;
          }
        }

      `}</style>
    </div>
  );
}

export default RegistroPlan;
