/**
 * Middleware de Autenticación y Autorización JWT
 * Valida la identidad del usuario, verifica en tiempo real el estado activo
 * en la base de datos (Offboarding Express) y aplica control de acceso por roles (RBAC).
 */

const jwt = require('jsonwebtoken');
require('dotenv').config();
const { get, addAuditLog } = require('./database');

const NODE_ENV = process.env.NODE_ENV || 'development';

// Validación estricta de variables críticas en producción
if (NODE_ENV === 'production' && !process.env.JWT_SECRET) {
  console.error('❌ [FATAL SECURITY ERROR] process.env.JWT_SECRET no está configurado en producción.');
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET || 'iam_pymes_super_secret_jwt_key_2026_987654321_secure';

/**
 * Middleware para autenticar tokens JWT en encabezado Authorization (Bearer)
 * Valida firma con algoritmo HS256, expiración, y realiza comprobación en tiempo real
 * en SQLite de estado activo y concordancia de token_version (revocación inmediata).
 */
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(401).json({
      success: false,
      error: 'Acceso denegado: Cabecera Authorization no suministrada'
    });
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return res.status(401).json({
      success: false,
      error: 'Acceso denegado: Formato de token inválido. Use "Bearer <token>"'
    });
  }

  const token = parts[1];

  // Verificación estricta fijando explícitamente algoritmo HS256
  jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }, async (err, decodedUser) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({
          success: false,
          error: 'Sesión expirada: El token ha caducado. Inicie sesión nuevamente.'
        });
      }
      return res.status(401).json({
        success: false,
        error: 'Acceso denegado: Token inválido o manipulado.'
      });
    }

    try {
      const userId = decodedUser.sub || decodedUser.id;

      // Verificación en tiempo real contra la base de datos (Offboarding Express y Token Version)
      const userInDb = await get(
        'SELECT id, name, email, role, status, token_version, is_2fa_enabled FROM users WHERE id = ?',
        [userId]
      );

      // Si el usuario no existe
      if (!userInDb) {
        return res.status(401).json({
          success: false,
          error: 'Acceso denegado: Usuario no encontrado o eliminado.'
        });
      }

      const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

      // 1. Validación de estado de cuenta
      if (userInDb.status !== 'Active') {
        addAuditLog({
          userEmail: userInDb.email,
          action: 'ACCESS_DENIED_REVOKED',
          ipAddress: clientIp,
          details: {
            action: 'ACCESS_DENIED_REVOKED',
            affectedEmail: userInDb.email,
            role: userInDb.role,
            ip: clientIp,
            path: req.originalUrl || req.url,
            method: req.method,
            description: 'Intento de acceso bloqueado en tiempo real con token de cuenta revocada'
          }
        }).catch((auditErr) => console.error('[AUDIT-MIDDLEWARE] Error al registrar evento:', auditErr.message));

        return res.status(403).json({
          success: false,
          error: 'Acceso denegado: Su cuenta ha sido revocada o desactivada. Sesión invalidada de inmediato.'
        });
      }

      // 2. Validación de versión de token (Invalidación por cambio de contraseña o revocación forzada)
      const tokenVersionInJwt = decodedUser.token_version !== undefined ? decodedUser.token_version : decodedUser.tokenVersion;
      if (tokenVersionInJwt === undefined || tokenVersionInJwt !== userInDb.token_version) {
        addAuditLog({
          userEmail: userInDb.email,
          action: 'ACCESS_DENIED_TOKEN_VERSION',
          ipAddress: clientIp,
          details: {
            action: 'ACCESS_DENIED_TOKEN_VERSION',
            affectedEmail: userInDb.email,
            role: userInDb.role,
            ip: clientIp,
            path: req.originalUrl || req.url,
            method: req.method,
            tokenVersionInJwt,
            currentDbTokenVersion: userInDb.token_version,
            description: 'Token revocado: la versión del token ha cambiado por actualización de credenciales'
          }
        }).catch((auditErr) => console.error('[AUDIT-MIDDLEWARE] Error al registrar evento:', auditErr.message));

        return res.status(401).json({
          success: false,
          error: 'Sesión invalidada: La contraseña fue actualizada o las sesiones fueron revocadas. Inicie sesión nuevamente.'
        });
      }

      // Inyectar datos vigentes del usuario autenticado en la solicitud
      req.user = userInDb;
      next();
    } catch (dbError) {
      console.error('[AUTH-MIDDLEWARE] Error validando estado de usuario:', dbError);
      return res.status(500).json({
        success: false,
        error: 'Error interno al validar la sesión del usuario'
      });
    }
  });
}

/**
 * Middleware para Control de Acceso Basado en Roles (RBAC)
 * Permite acceso únicamente a los roles especificados (ej. 'Admin')
 */
function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Autenticación requerida antes de evaluar permisos de rol'
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
      addAuditLog({
        userEmail: req.user.email,
        action: 'ACCESS_DENIED_ROLE',
        ipAddress: clientIp,
        details: {
          action: 'ACCESS_DENIED_ROLE',
          affectedEmail: req.user.email,
          role: req.user.role,
          ip: clientIp,
          path: req.originalUrl || req.url,
          method: req.method,
          requiredRoles: allowedRoles,
          description: `Acceso prohibido: Rol '${req.user.role}' no autorizado. Se requiere [${allowedRoles.join(', ')}]`
        }
      }).catch((err) => console.error('[AUDIT-MIDDLEWARE] Error al registrar evento:', err.message));

      return res.status(403).json({
        success: false,
        error: `Acceso prohibido: Se requiere uno de los siguientes roles [${allowedRoles.join(', ')}]`
      });
    }

    next();
  };
}

// Compatibilidad para uso directo y desestructurado
authenticateToken.authenticateToken = authenticateToken;
authenticateToken.requireRole = requireRole;

module.exports = authenticateToken;
