// middlewares/authz.js
export function requireAdmin(req, res, next) {
  // Asume que verifyToken ya cargó req.user desde el JWT
  if (!req.user || req.user.rol !== 'admin') {
    return res.status(403).json({ message: 'Acceso denegado: se requiere rol admin' });
  }
  next();
}
