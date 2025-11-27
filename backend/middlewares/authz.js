// middleware para permitir solo administradores
export function requireAdmin(req, res, next) {
  if (!req.user || req.user.rol !== "admin") {
    return res
      .status(403)
      .json({ message: "Acceso denegado: se requiere rol admin" });
  }
  next();
}

// middleware para permitir solo psicólogos
export function requirePsychologist(req, res, next) {
  if (!req.user || req.user.rol !== "psicologo") {
    return res
      .status(403)
      .json({ message: "Acceso denegado: solo psicólogos" });
  }
  next();
}
