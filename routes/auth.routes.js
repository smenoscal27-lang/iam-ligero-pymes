/**
 * Rutas de Autenticación Base (/api/auth)
 * Gestiona el inicio de sesión con defensas anti-enumeración y la validación de sesión activa.
 */

const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const { get, addAuditLog } = require('../database');
const { authenticateToken } = require('../authMiddleware');

const JWT_SECRET = process.env.JWT_SECRET || 'iam_pymes_super_secret_jwt_key_2026_987654321_secure';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h';

/**
 * POST /api/auth/login
 * Inicio de sesión, validación de estado activo, verificación bcrypt,
 * emisión de token JWT (expiración 1h) y registro inmutable en audit_logs.
 */
router.post('/login', async (req, res, next) => {
  const { email, password } = req.body;
  const ipAddress = req.clientIp || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      error: 'Debe suministrar "email" y "password".'
    });
  }

  const normalizedEmail = String(email).trim().toLowerCase();

  try {
    const user = await get(
      'SELECT id, name, email, password_hash, role, status, token_version FROM users WHERE email = ?',
      [normalizedEmail]
    );

    // Hash ficticio para mitigar ataques de temporización (timing attacks) si el usuario no existe
    const DUMMY_HASH = '$2a$12$e80yq9gq7aFvhV8Qn6Q4b.uYmKqK9H5wF0Z9gT9wzC01z4hQJ3h.y';
    const hashToCompare = user ? user.password_hash : DUMMY_HASH;
    const passwordMatch = await bcrypt.compare(password, hashToCompare);

    // Usuario inexistente o contraseña incorrecta -> siempre 401 con mensaje genérico
    if (!user || !passwordMatch) {
      await addAuditLog({
        userEmail: normalizedEmail,
        action: 'LOGIN_FAILED',
        ipAddress,
        details: {
          action: 'LOGIN_FAILED',
          affectedEmail: normalizedEmail,
          role: user ? user.role : 'Unknown',
          ip: ipAddress,
          reason: !user ? 'Usuario no encontrado' : 'Contraseña incorrecta'
        }
      });

      return res.status(401).json({
        success: false,
        error: 'Credenciales inválidas'
      });
    }

    // Cuenta suspendida o revocada
    if (user.status !== 'Active') {
      await addAuditLog({
        userEmail: user.email,
        action: 'LOGIN_FAILED',
        ipAddress,
        details: {
          action: 'LOGIN_FAILED',
          affectedEmail: user.email,
          role: user.role,
          ip: ipAddress,
          reason: `Acceso bloqueado: Estado de cuenta '${user.status}'`
        }
      });

      return res.status(403).json({
        success: false,
        error: 'Acceso denegado: La cuenta ha sido revocada o suspendida'
      });
    }

    // Credenciales válidas -> Generar Token JWT con algoritmo explícito HS256 y token_version
    const tokenPayload = {
      sub: user.id,
      id: user.id,
      email: user.email,
      role: user.role,
      token_version: user.token_version || 1
    };

    const token = jwt.sign(tokenPayload, JWT_SECRET, {
      algorithm: 'HS256',
      expiresIn: JWT_EXPIRES_IN
    });

    // Registro inmutable de LOGIN_SUCCESS
    await addAuditLog({
      userEmail: user.email,
      action: 'LOGIN_SUCCESS',
      ipAddress,
      details: {
        action: 'LOGIN_SUCCESS',
        affectedEmail: user.email,
        role: user.role,
        ip: ipAddress,
        userId: user.id,
        authMethod: 'Password',
        issuedAt: new Date().toISOString()
      }
    });

    return res.status(200).json({
      success: true,
      message: 'Inicio de sesión exitoso',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        status: user.status
      }
    });
  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/auth/me
 * Retorna los datos del usuario autenticado actualmente mediante su token JWT
 */
router.get('/me', authenticateToken, async (req, res, next) => {
  try {
    const user = await get(
      'SELECT id, name, email, role, status, created_at FROM users WHERE id = ?',
      [req.user.id]
    );

    if (!user) {
      return res.status(404).json({ success: false, error: 'Usuario no encontrado' });
    }

    return res.status(200).json({
      success: true,
      user
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
