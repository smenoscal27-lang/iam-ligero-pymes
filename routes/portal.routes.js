/**
 * Rutas del Portal del Empleado (/api/portal)
 * Permite el autoservicio seguro de perfil, cambio de contraseña e inicialización/confirmación 2FA.
 */

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');

const { run, get, addAuditLog } = require('../database');
const { authenticateToken } = require('../authMiddleware');
const {
  encrypt2FASecret,
  decrypt2FASecret,
  generateBackupCodes,
  hashBackupCode
} = require('../cryptoUtils');

// Todos los endpoints de portal requieren autenticación activa
router.use(authenticateToken);

/**
 * GET /api/portal/profile
 * Retorna la información detallada del empleado autenticado y su estado 2FA
 */
router.get('/profile', async (req, res, next) => {
  try {
    const user = await get(
      'SELECT id, name, email, role, status, secret_2fa, is_2fa_enabled, created_at FROM users WHERE id = ?',
      [req.user.id]
    );

    if (!user) {
      return res.status(404).json({ success: false, error: 'Usuario no encontrado.' });
    }

    const is2faActive = Boolean(user.is_2fa_enabled);
    const is2faPending = Boolean(user.secret_2fa && !user.is_2fa_enabled);

    return res.status(200).json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        status: user.status,
        has2FA: is2faActive,
        is2FAEnabled: is2faActive,
        is2FAPending: is2faPending,
        created_at: user.created_at
      }
    });
  } catch (error) {
    next(error);
  }
});

/**
 * PUT /api/portal/password
 * Permite al empleado cambiar su contraseña validando la clave actual.
 * Incrementa token_version para invalidar cualquier sesión previa de inmediato.
 */
router.put('/password', async (req, res, next) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user.id;
  const userEmail = req.user.email;
  const userRole = req.user.role;
  const ipAddress = req.clientIp || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  if (!currentPassword || !newPassword) {
    return res.status(400).json({
      success: false,
      error: 'Debe suministrar "currentPassword" y "newPassword".'
    });
  }

  if (String(newPassword).length < 8) {
    return res.status(400).json({
      success: false,
      error: 'La nueva contraseña debe tener al menos 8 caracteres.'
    });
  }

  if (currentPassword === newPassword) {
    return res.status(400).json({
      success: false,
      error: 'La nueva contraseña no puede ser idéntica a la contraseña actual.'
    });
  }

  try {
    const user = await get('SELECT password_hash FROM users WHERE id = ?', [userId]);
    if (!user) {
      return res.status(404).json({ success: false, error: 'Usuario no encontrado.' });
    }

    const passwordMatch = await bcrypt.compare(currentPassword, user.password_hash);
    if (!passwordMatch) {
      return res.status(400).json({
        success: false,
        error: 'La contraseña actual ingresada es incorrecta.'
      });
    }

    const saltRounds = 12;
    const newHash = await bcrypt.hash(newPassword, saltRounds);

    // Actualizar hash e incrementar token_version para invalidar sesiones activas
    await run(
      'UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE id = ?',
      [newHash, userId]
    );

    await addAuditLog({
      userEmail,
      action: 'PASSWORD_CHANGED',
      ipAddress,
      details: {
        action: 'PASSWORD_CHANGED',
        affectedEmail: userEmail,
        role: userRole,
        ip: ipAddress,
        userId,
        description: 'Cambio de contraseña realizado exitosamente por el usuario (sesiones previas invalidadas)'
      }
    });

    return res.status(200).json({
      success: true,
      message: 'Contraseña actualizada exitosamente. Sus sesiones previas han sido cerradas por seguridad.'
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/portal/2fa/setup
 * Genera clave secreta TOTP, la cifra en reposo con AES-256-GCM y la vincula en estado pendiente (is_2fa_enabled = 0).
 */
router.post('/2fa/setup', async (req, res, next) => {
  const userId = req.user.id;
  const userEmail = req.user.email;
  const userRole = req.user.role;
  const ipAddress = req.clientIp || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  try {
    const secret = speakeasy.generateSecret({
      name: `IAM Pymes (${userEmail})`,
      issuer: 'IAM-Pymes',
      length: 20
    });

    const encryptedSecret = encrypt2FASecret(secret.base32);

    await run(
      'UPDATE users SET secret_2fa = ?, is_2fa_enabled = 0 WHERE id = ?',
      [encryptedSecret, userId]
    );

    await addAuditLog({
      userEmail,
      action: '2FA_SETUP',
      ipAddress,
      details: {
        action: '2FA_SETUP',
        affectedEmail: userEmail,
        role: userRole,
        ip: ipAddress,
        userId,
        description: 'Configuración 2FA TOTP inicializada (pendiente de confirmación con código de 6 dígitos)'
      }
    });

    return res.status(200).json({
      success: true,
      message: 'Configuración 2FA inicializada. Ingrese el código de 6 dígitos de su aplicación para verificar y activar el doble factor.',
      twoFactor: {
        secret: secret.base32,
        otpauth_url: secret.otpauth_url,
        instructions: 'Escanee la URL o ingrese la clave secreta manualmente en Google Authenticator o Authy y confirme con el código de 6 dígitos.'
      }
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/portal/2fa/verify
 * Confirma y activa el segundo factor TOTP (Flujo seguro en 2 pasos).
 */
router.post('/2fa/verify', async (req, res, next) => {
  const { code } = req.body;
  const userId = req.user.id;
  const userEmail = req.user.email;
  const userRole = req.user.role;
  const ipAddress = req.clientIp || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';

  if (!code || !/^\d{6}$/.test(String(code).trim())) {
    return res.status(400).json({
      success: false,
      error: 'Debe suministrar un código TOTP numérico de 6 dígitos válido.'
    });
  }

  const cleanCode = String(code).trim();

  try {
    const user = await get(
      'SELECT id, email, secret_2fa, is_2fa_enabled, last_totp_code FROM users WHERE id = ?',
      [userId]
    );

    if (!user || !user.secret_2fa) {
      return res.status(400).json({
        success: false,
        error: 'No se ha iniciado la configuración 2FA. Primero debe llamar a POST /api/portal/2fa/setup.'
      });
    }

    if (user.last_totp_code && user.last_totp_code === cleanCode) {
      return res.status(400).json({
        success: false,
        error: 'Este código TOTP ya fue utilizado. Por seguridad, espere 30 segundos al siguiente ciclo.'
      });
    }

    const decryptedSecret = decrypt2FASecret(user.secret_2fa);

    const isCodeValid = speakeasy.totp.verify({
      secret: decryptedSecret,
      encoding: 'base32',
      token: cleanCode,
      window: 1
    });

    if (!isCodeValid) {
      await addAuditLog({
        userEmail,
        action: '2FA_VERIFICATION_FAILED',
        ipAddress,
        details: {
          action: '2FA_VERIFICATION_FAILED',
          affectedEmail: userEmail,
          role: userRole,
          ip: ipAddress,
          userId,
          description: 'Código TOTP incorrecto o fuera de sincronización en intento de confirmación'
        }
      });

      return res.status(400).json({
        success: false,
        error: 'Código TOTP incorrecto o expirado. Verifique la hora de su dispositivo e intente nuevamente.'
      });
    }

    const plainBackupCodes = generateBackupCodes(8);
    const hashedBackupCodes = plainBackupCodes.map((c) => hashBackupCode(c));

    await run(
      'UPDATE users SET is_2fa_enabled = 1, backup_codes = ?, last_totp_code = ? WHERE id = ?',
      [JSON.stringify(hashedBackupCodes), cleanCode, userId]
    );

    await addAuditLog({
      userEmail,
      action: '2FA_ENABLED',
      ipAddress,
      details: {
        action: '2FA_ENABLED',
        affectedEmail: userEmail,
        role: userRole,
        ip: ipAddress,
        userId,
        backupCodesCount: plainBackupCodes.length,
        description: 'Doble factor de autenticación TOTP verificado y activado exitosamente'
      }
    });

    return res.status(200).json({
      success: true,
      message: 'Doble factor de autenticación (2FA) verificado y activado exitosamente.',
      is2FAEnabled: true,
      backupCodes: plainBackupCodes,
      instructions: 'Guarde estos códigos de respaldo en un lugar seguro. Solo se mostrarán esta vez.'
    });
  } catch (error) {
    next(error);
  }
});

module.exports = router;
