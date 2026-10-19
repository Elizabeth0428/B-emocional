// src/components/WorkflowGuide.jsx
import React from "react";

export default function WorkflowGuide({
  title = "Tu ruta de trabajo",
  description = "Sigue estos pasos para avanzar.",
  steps = [],
  onStepClick
}) {
  return (
    <section style={styles.wrapper}>
      <div style={styles.header}>
        <div>
          <div style={styles.eyebrow}>🧭 GUÍA DE NAVEGACIÓN</div>
          <h2 style={styles.title}>{title}</h2>
          <p style={styles.description}>{description}</p>
        </div>

        <div style={styles.legend}>
          <span>✅ Completado</span>
          <span>🔵 Recomendado</span>
          <span>⚪ Pendiente</span>
        </div>
      </div>

      <div style={styles.steps}>
        {steps.map((step, index) => {
          const completed = step.status === "completed";
          const current = step.status === "current";

          return (
            <React.Fragment key={step.id}>
              <button
                type="button"
                style={styles.stepButton}
                onClick={() =>
                  step.clickable !== false &&
                  onStepClick?.(step)
                }
              >
                <div
                  style={{
                    ...styles.circle,
                    ...(completed
                      ? styles.circleCompleted
                      : current
                      ? styles.circleCurrent
                      : styles.circlePending)
                  }}
                >
                  {completed ? "✓" : step.icon || index + 1}
                </div>

                <div style={styles.stepText}>
                  <div
                    style={{
                      ...styles.stepTitle,
                      color: completed
                        ? "#27843A"
                        : current
                        ? "#2167D5"
                        : "#667085"
                    }}
                  >
                    {step.title}
                  </div>

                  <div style={styles.stepDescription}>
                    {step.description}
                  </div>

                  {current && (
                    <div style={styles.currentBadge}>
                      CONTINÚA AQUÍ
                    </div>
                  )}
                </div>
              </button>

              {index < steps.length - 1 && (
                <div
                  style={{
                    ...styles.line,
                    background: completed
                      ? "#54C96B"
                      : "#D9E2EC"
                  }}
                />
              )}
            </React.Fragment>
          );
        })}
      </div>
    </section>
  );
}

const styles = {
  wrapper: {
    maxWidth: "1150px",
    margin: "0 auto 28px",
    padding: "22px 26px",
    background: "rgba(255,255,255,.95)",
    border: "1px solid #E2EAF4",
    borderRadius: "20px",
    boxShadow: "0 8px 24px rgba(40,80,140,.07)",
    position: "relative",
    zIndex: 3
  },

  header: {
    display: "flex",
    justifyContent: "space-between",
    gap: "20px",
    alignItems: "flex-start",
    marginBottom: "24px"
  },

  eyebrow: {
    color: "#2167D5",
    fontSize: "10px",
    fontWeight: "900",
    letterSpacing: "1.2px",
    marginBottom: "5px"
  },

  title: {
    margin: 0,
    color: "#172B4D",
    fontSize: "20px"
  },

  description: {
    margin: "6px 0 0",
    color: "#667085",
    fontSize: "13px"
  },

  legend: {
    display: "flex",
    flexWrap: "wrap",
    gap: "12px",
    color: "#667085",
    fontSize: "11px"
  },

  steps: {
    display: "flex",
    alignItems: "flex-start",
    width: "100%"
  },

  stepButton: {
    flex: 1,
    padding: 0,
    border: "none",
    background: "transparent",
    cursor: "pointer",
    fontFamily: "inherit",
    textAlign: "center"
  },

  circle: {
    width: "42px",
    height: "42px",
    margin: "0 auto 9px",
    borderRadius: "50%",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontWeight: "900",
    fontSize: "16px",
    transition: "all .2s ease"
  },

  circleCompleted: {
    background: "#E8F8ED",
    color: "#27843A",
    border: "2px solid #54C96B"
  },

  circleCurrent: {
    background: "#EAF1FF",
    color: "#2167D5",
    border: "2px solid #4A7FF5",
    boxShadow: "0 0 0 5px rgba(74,127,245,.10)"
  },

  circlePending: {
    background: "#F2F4F7",
    color: "#98A2B3",
    border: "2px solid #D0D5DD"
  },

  line: {
    flex: ".35",
    height: "3px",
    marginTop: "20px",
    borderRadius: "3px"
  },

  stepText: {
    minHeight: "80px"
  },

  stepTitle: {
    fontSize: "12px",
    fontWeight: "800"
  },

  stepDescription: {
    margin: "4px auto 0",
    maxWidth: "145px",
    color: "#98A2B3",
    fontSize: "10px",
    lineHeight: "1.35"
  },

  currentBadge: {
    display: "inline-block",
    marginTop: "6px",
    padding: "3px 7px",
    borderRadius: "999px",
    background: "#EAF1FF",
    color: "#2167D5",
    fontSize: "8px",
    fontWeight: "900"
  }
};