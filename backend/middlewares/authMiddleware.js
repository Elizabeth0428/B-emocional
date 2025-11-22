import jwt from "jsonwebtoken";

// ✅ Middleware de autenticación
export function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // formato: "Bearer <token>"

  if (!token) {
    return res.status(403).json({ message: "Token requerido" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(401).json({ message: "Token inválido o expirado" });
    }
    req.user = user; // guardamos datos del usuario en la request
    next();
  });
}

// ✅ Middleware de autorización por rol (ejemplo: solo admins)
export function isAdmin(req, res, next) {
  if (req.user?.role !== 1) {
    return res.status(403).json({ message: "Acceso denegado: solo administradores" });
  }
  next();
}

// ✅ Middleware de autorización por permisos específicos
export function hasPermission(permisoId) {
  return (req, res, next) => {
    if (!req.user?.permisos?.includes(permisoId)) {
      return res.status(403).json({ message: "Acceso denegado: permiso insuficiente" });
    }
    next();
  };
}
