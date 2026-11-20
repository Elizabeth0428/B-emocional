import React from "react";

function PlanCard({
  plan,
  onSelect,
}) {
  const precioVisible =
    plan?.precio !== null &&
    plan?.precio !== undefined;

  return (
    <article
      style={{
        ...styles.card,

        ...(plan?.destacado
          ? styles.cardDestacado
          : {}),
      }}
    >
      {/* ============================= */}
      {/* ETIQUETA */}
      {/* ============================= */}

      <div style={styles.topRow}>
        <span
          style={{
            ...styles.tag,

            ...(plan?.destacado
              ? styles.tagDestacada
              : {}),
          }}
        >
          {plan?.etiqueta ||
            "MirrorSoul"}
        </span>

        {plan?.destacado && (
          <span style={styles.recommended}>
            Recomendado
          </span>
        )}
      </div>

      {/* ============================= */}
      {/* NOMBRE */}
      {/* ============================= */}

      <h3 style={styles.title}>
        {plan?.nombre ||
          "Plan MirrorSoul"}
      </h3>

      <p style={styles.description}>
        {plan?.descripcion ||
          "Solución adaptable a tus necesidades."}
      </p>

      {/* ============================= */}
      {/* PRECIO */}
      {/* ============================= */}

      <div style={styles.priceBox}>
        {precioVisible ? (
          <>
            <div style={styles.priceRow}>
              <span style={styles.currency}>
                $
              </span>

              <span style={styles.price}>
                {Number(
                  plan.precio
                ).toLocaleString(
                  "es-MX"
                )}
              </span>
            </div>

            <span style={styles.period}>
              MXN / {plan?.periodo || "mes"}
            </span>
          </>
        ) : (
          <>
            <span style={styles.pendingPrice}>
              Precio por definir
            </span>

            <span style={styles.period}>
              Configuración en proceso
            </span>
          </>
        )}
      </div>

      {/* ============================= */}
      {/* LICENCIAS */}
      {/* ============================= */}

      <div style={styles.licenseBox}>
        <div style={styles.licenseIcon}>
          👤
        </div>

        <div>
          <strong style={styles.licenseTitle}>
            {plan?.licencias === 1
              ? "1 licencia"
              : `${plan?.licencias || 0} licencias`}
          </strong>

          <span style={styles.licenseText}>
            incluidas en el plan
          </span>
        </div>
      </div>

      {/* ============================= */}
      {/* CARACTERÍSTICAS */}
      {/* ============================= */}

      <div style={styles.features}>
        <span style={styles.featuresTitle}>
          Incluye:
        </span>

        {(plan?.caracteristicas || [])
          .map(
            (
              item,
              index
            ) => (
              <div
                key={index}
                style={styles.feature}
              >
                <span style={styles.check}>
                  ✓
                </span>

                <span style={styles.featureText}>
                  {item}
                </span>
              </div>
            )
          )}
      </div>

      {/* ============================= */}
      {/* BOTÓN */}
      {/* ============================= */}

      <button
        type="button"
        style={{
          ...styles.button,

          ...(plan?.destacado
            ? styles.buttonDestacado
            : {}),
        }}
        onClick={onSelect}
      >
        Elegir plan
        <span style={styles.arrow}>
          →
        </span>
      </button>

      {/* ============================= */}
      {/* NOTA */}
      {/* ============================= */}

      <span style={styles.note}>
        Podrás revisar los detalles antes
        de continuar con la contratación.
      </span>
    </article>
  );
}

const styles = {
  card: {
    position: "relative",

    display: "flex",

    flexDirection:
      "column",

    minHeight: "600px",

    padding: "26px",

    borderRadius:
      "24px",

    background:
      "linear-gradient(145deg,rgba(17,31,48,.95),rgba(8,18,30,.98))",

    border:
      "1px solid rgba(255,255,255,.07)",

    boxShadow:
      "0 22px 55px rgba(0,0,0,.15)",
  },

  cardDestacado: {
    border:
      "1px solid rgba(102,229,255,.28)",

    boxShadow:
      "0 26px 65px rgba(79,193,255,.10)",

    transform:
      "translateY(-8px)",
  },

  topRow: {
    display: "flex",

    alignItems: "center",

    justifyContent:
      "space-between",

    gap: "10px",

    minHeight: "28px",
  },

  tag: {
    display: "inline-flex",

    alignItems: "center",

    padding:
      "6px 9px",

    borderRadius:
      "8px",

    background:
      "rgba(255,255,255,.035)",

    border:
      "1px solid rgba(255,255,255,.055)",

    color:
      "rgba(255,255,255,.50)",

    fontSize: "9px",

    fontWeight: "900",

    letterSpacing:
      ".6px",

    textTransform:
      "uppercase",
  },

  tagDestacada: {
    background:
      "rgba(102,229,255,.07)",

    border:
      "1px solid rgba(102,229,255,.11)",

    color: "#76eaff",
  },

  recommended: {
    padding:
      "6px 9px",

    borderRadius:
      "8px",

    background:
      "linear-gradient(135deg,rgba(100,229,255,.10),rgba(143,125,255,.12))",

    color: "#89eaff",

    fontSize: "8px",

    fontWeight: "900",
  },

  title: {
    margin:
      "22px 0 0",

    color: "#ffffff",

    fontSize: "26px",

    lineHeight: 1.15,

    fontWeight: "900",

    letterSpacing:
      "-.7px",
  },

  description: {
    margin:
      "12px 0 0",

    minHeight: "64px",

    color:
      "rgba(255,255,255,.48)",

    fontSize: "12px",

    lineHeight: 1.7,
  },

  priceBox: {
    marginTop: "24px",

    padding:
      "18px",

    minHeight: "84px",

    display: "flex",

    flexDirection:
      "column",

    justifyContent:
      "center",

    borderRadius:
      "16px",

    background:
      "rgba(255,255,255,.025)",

    border:
      "1px solid rgba(255,255,255,.05)",
  },

  priceRow: {
    display: "flex",

    alignItems:
      "flex-start",

    gap: "4px",
  },

  currency: {
    marginTop: "5px",

    color:
      "rgba(255,255,255,.58)",

    fontSize: "14px",

    fontWeight: "900",
  },

  price: {
    color: "#ffffff",

    fontSize: "36px",

    lineHeight: 1,

    fontWeight: "900",

    letterSpacing:
      "-1px",
  },

  pendingPrice: {
    color: "#ffffff",

    fontSize: "19px",

    fontWeight: "900",
  },

  period: {
    display: "block",

    marginTop: "6px",

    color:
      "rgba(255,255,255,.33)",

    fontSize: "8px",

    fontWeight: "700",
  },

  licenseBox: {
    display: "flex",

    alignItems: "center",

    gap: "11px",

    marginTop: "15px",

    padding:
      "13px 14px",

    borderRadius:
      "13px",

    background:
      "rgba(102,229,255,.035)",

    border:
      "1px solid rgba(102,229,255,.055)",
  },

  licenseIcon: {
    width: "35px",
    height: "35px",

    display: "flex",

    alignItems: "center",

    justifyContent:
      "center",

    flexShrink: 0,

    borderRadius:
      "11px",

    background:
      "rgba(102,229,255,.055)",

    fontSize: "16px",
  },

  licenseTitle: {
    display: "block",

    color: "#ffffff",

    fontSize: "11px",

    fontWeight: "900",
  },

  licenseText: {
    display: "block",

    marginTop: "2px",

    color:
      "rgba(255,255,255,.35)",

    fontSize: "8px",
  },

  features: {
    marginTop: "24px",

    flex: 1,
  },

  featuresTitle: {
    display: "block",

    marginBottom:
      "11px",

    color:
      "rgba(255,255,255,.64)",

    fontSize: "10px",

    fontWeight: "900",
  },

  feature: {
    display: "flex",

    alignItems:
      "flex-start",

    gap: "8px",

    marginBottom:
      "9px",
  },

  check: {
    width: "19px",
    height: "19px",

    flexShrink: 0,

    display: "flex",

    alignItems: "center",

    justifyContent:
      "center",

    borderRadius:
      "6px",

    background:
      "rgba(118,234,255,.06)",

    color: "#76eaff",

    fontSize: "8px",

    fontWeight: "900",
  },

  featureText: {
    paddingTop: "2px",

    color:
      "rgba(255,255,255,.52)",

    fontSize: "10px",

    lineHeight: 1.45,
  },

  button: {
    width: "100%",

    marginTop: "23px",

    padding:
      "13px 16px",

    display: "flex",

    alignItems: "center",

    justifyContent:
      "center",

    gap: "9px",

    borderRadius:
      "11px",

    border:
      "1px solid rgba(255,255,255,.09)",

    background:
      "rgba(255,255,255,.035)",

    color: "#ffffff",

    fontSize: "11px",

    fontWeight: "900",

    cursor: "pointer",
  },

  buttonDestacado: {
    border: "none",

    background:
      "linear-gradient(135deg,#65e5ff,#927eff)",

    color: "#07111f",

    boxShadow:
      "0 12px 30px rgba(88,205,255,.11)",
  },

  arrow: {
    fontSize: "16px",
  },

  note: {
    display: "block",

    marginTop: "10px",

    textAlign: "center",

    color:
      "rgba(255,255,255,.25)",

    fontSize: "7px",

    lineHeight: 1.5,
  },
};

export default PlanCard;