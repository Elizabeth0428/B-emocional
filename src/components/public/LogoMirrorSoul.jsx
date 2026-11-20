
import React from "react";
import logoMirrorSoul from "../../assets/public/logo-mirrorsoul.png";

// ============================================================
// LOGO MIRRORSOUL
//
// - Respeta la transparencia del PNG.
// - Elimina fondos oscuros duplicados.
// - Permite utilizar un fondo opcional.
// - Compatible con los componentes existentes.
// ============================================================

function LogoMirrorSoul({
  width = 120,
  height = 70,
  borderRadius = 18,
  padding = 0,
  background = false,
  style = {},
}) {
  const usarFondo = Boolean(background);

  return (
    <div
      style={{
        width,
        height,
        flexShrink: 0,

        display: "flex",
        alignItems: "center",
        justifyContent: "center",

        boxSizing: "border-box",
        overflow: "hidden",

        padding,

        background: usarFondo
          ? "var(--ms-card, #ffffff)"
          : "transparent",

        border: usarFondo
          ? "1px solid var(--ms-border, #dce7f5)"
          : "none",

        borderRadius: usarFondo
          ? borderRadius
          : 0,

        boxShadow: usarFondo
          ? "var(--ms-shadow, none)"
          : "none",

        ...style,
      }}
    >
      <img
        src={logoMirrorSoul}
        alt="MirrorSoul"
        draggable={false}
        style={{
          display: "block",
          width: "100%",
          height: "100%",
          objectFit: "contain",
          objectPosition: "center",
          background: "transparent",
        }}
      />
    </div>
  );
}

export default LogoMirrorSoul;
