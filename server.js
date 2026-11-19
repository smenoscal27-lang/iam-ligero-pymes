/**
 * Servidor Principal - Gestor de Identidad y Accesos (IAM) Ligero para Pymes
 * Arquitectura modular y segura basada en Node.js, Express, SQLite y JWT.
 */

require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');

const { db, run, get, all, initializeDatabase, addAuditLog } = require('./database');
const { authenticateToken, requireRole } = require('./authMiddleware');
const {
  encrypt2FASecret,
  decrypt2FASecret,
  generateBackupCodes,
  hashBackupCode
} = require('./cryptoUtils');

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// Validación estricta de secretos en entorno de producción
if (NODE_ENV === 'production' && !process.env.JWT_SECRET) {
  console.error('❌ [FATAL SECURITY ERROR] process.env.JWT_SECRET no está configurado en producción.');
  process.exit(1);
}

const JWT_SECRET = process.env.JWT_SECRET || 'iam_pymes_super_secret_jwt_key_2026_987654321_secure';
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '1h'; // Expiración corta recomendada por AppSec

// -------------------------------------------------------------
// Middlewares de Seguridad y Comunicación
// -------------------------------------------------------------

// 1. Cabeceras HTTP seguras con Helmet (Configuración CSP para Tailwind CDN y SPA)
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
        styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
        fontSrc: ["'self'", "https://fonts.gstatic.com", "data:"],
        imgSrc: ["'self'", "data:"],
        connectSrc: ["'self'"]
      }
    },
    crossOriginEmbedderPolicy: false
  })
);

// 2. Control de Acceso entre Orígenes (CORS)
app.use(
  cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: true
  })
);

// 3. Soporte para JSON con límite defensivo de carga (mitigación DoS)
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// 4. Middleware para extraer IP real del cliente
app.use((req, res, next) => {
  req.clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  next();
});

// -------------------------------------------------------------
// Rutas de API y Verificación de Estado (Deben preceder a estáticos)
// -------------------------------------------------------------

/**
 * Health Check: Comprobación de estado general y conectividad con SQLite
 */
app.get('/health', async (req, res) => {
  try {
    await all('SELECT 1');
    res.status(200).json({
      status: 'healthy',
      system: 'IAM Ligero para Pymes',
      environment: NODE_ENV,
      timestamp: new Date().toISOString(),
      database: 'connected'
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      database: 'error',
      error: error.message
    });
  }
});

/**
 * POST /api/auth/login
 * Inicio de sesión, validación de estado activo, verificación bcrypt,
 * emisión de token JWT (expiración 2h) y registro inmutable en audit_logs.
 */
app.post('/api/auth/login', async (req, res, next) => {
  const { email, password } = req.body;
  const ipAddress = req.clientIp;

  // Validación inicial de parámetros de entrada
  if (!email || !password) {
    return res.status(400).json({
      success: false,
      error: 'Debe suministrar "email" y "password".'
    });
  }

  const normalizedEmail = String(email).trim().toLowerCase();

  try {
    // 1. Buscar usuario en base de datos (incluyendo token_version para control de sesiones)
    const user = await get(
      'SELECT id, name, email, password_hash, role, status, token_version FROM users WHERE email = ?',
      [normalizedEmail]
    );

    // Hash ficticio para mitigar ataques de temporización (timing attacks) si el usuario no existe
    const DUMMY_HASH = '$2a$12$e80yq9gq7aFvhV8Qn6Q4b.uYmKqK9H5wF0Z9gT9wzC01z4hQJ3h.y';
    const hashToCompare = user ? user.password_hash : DUMMY_HASH;
    const passwordMatch = await bcrypt.compare(password, hashToCompare);

    // Caso A y C: Usuario inexistente o contraseña incorrecta
    // Devuelve siempre HTTP 401 con mensaje genérico idéntico para evitar enumeración de usuarios
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

    // Caso B: Cuenta suspendida o revocada (Ciberseguridad)
    // Se valida después de verificar credenciales para no revelar existencia de cuentas
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

    // Caso D: Credenciales válidas -> Generar Token JWT con algoritmo explícito HS256 y token_version
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

    // 3. Registrar evento inmutable de LOGIN_SUCCESS en audit_logs
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

    // 4. Devolver token y datos sanitizados del usuario
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

// -------------------------------------------------------------
// Rutas Protegidas por Middleware JWT (authMiddleware)
// -------------------------------------------------------------

/**
 * GET /api/auth/me
 * Retorna los datos del usuario autenticado actualmente mediante su token JWT
 */
app.get('/api/auth/me', authenticateToken, async (req, res, next) => {
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

// -------------------------------------------------------------
// Rutas del Portal del Empleado (Autoservicio Seguro)
// -------------------------------------------------------------

/**
 * GET /api/portal/profile
 * Retorna la información detallada del empleado autenticado y si tiene 2FA configurado
 * Protegido con authenticateToken.
 */
app.get('/api/portal/profile', authenticateToken, async (req, res, next) => {
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
 * Permite al empleado cambiar su propia contraseña validando la contraseña actual.
 * Incrementa token_version para invalidar cualquier sesión previa de inmediato.
 * Registra evento PASSWORD_CHANGED en audit_logs.
 * Protegido con authenticateToken.
 */
app.put('/api/portal/password', authenticateToken, async (req, res, next) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user.id;
  const userEmail = req.user.email;
  const userRole = req.user.role;
  const ipAddress = req.clientIp;

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

    // Actualizar hash de contraseña e incrementar token_version (invalidación de sesiones activas)
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
 * Registra evento 2FA_SETUP en audit_logs.
 * Protegido con authenticateToken.
 */
app.post('/api/portal/2fa/setup', authenticateToken, async (req, res, next) => {
  const userId = req.user.id;
  const userEmail = req.user.email;
  const userRole = req.user.role;
  const ipAddress = req.clientIp;

  try {
    // Generar clave secreta TOTP (20 bytes, Base32, compatible Google Authenticator)
    const secret = speakeasy.generateSecret({
      name: `IAM Pymes (${userEmail})`,
      issuer: 'IAM-Pymes',
      length: 20
    });

    // Cifrar el secreto en reposo con AES-256-GCM antes de guardarlo en SQLite
    const encryptedSecret = encrypt2FASecret(secret.base32);

    // Guardar secreto cifrado con estado pendiente (is_2fa_enabled = 0)
    await run(
      'UPDATE users SET secret_2fa = ?, is_2fa_enabled = 0 WHERE id = ?',
      [encryptedSecret, userId]
    );

    // Registro inmutable en audit_logs
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
 * Confirma y activa el segundo factor de autenticación TOTP (Flujo seguro en 2 pasos).
 * Valida un código de 6 dígitos con tolerancia window: 1, previene el reuso
 * del mismo código TOTP, activa is_2fa_enabled = 1 y devuelve códigos de respaldo de un solo uso.
 * Protegido con authenticateToken.
 */
app.post('/api/portal/2fa/verify', authenticateToken, async (req, res, next) => {
  const { code } = req.body;
  const userId = req.user.id;
  const userEmail = req.user.email;
  const userRole = req.user.role;
  const ipAddress = req.clientIp;

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

    // Prevención de reuso de código en la misma ventana de tiempo
    if (user.last_totp_code && user.last_totp_code === cleanCode) {
      return res.status(400).json({
        success: false,
        error: 'Este código TOTP ya fue utilizado. Por seguridad, espere 30 segundos al siguiente ciclo.'
      });
    }

    // Descifrar el secreto almacenado en reposo con AES-256-GCM
    const decryptedSecret = decrypt2FASecret(user.secret_2fa);

    // Verificación de código TOTP con tolerancia window: 1
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

    // Generar códigos de respaldo de un solo uso
    const plainBackupCodes = generateBackupCodes(8);
    const hashedBackupCodes = plainBackupCodes.map((c) => hashBackupCode(c));

    // Activar 2FA, registrar códigos de respaldo y guardar último código usado
    await run(
      'UPDATE users SET is_2fa_enabled = 1, backup_codes = ?, last_totp_code = ? WHERE id = ?',
      [JSON.stringify(hashedBackupCodes), cleanCode, userId]
    );

    // Registro inmutable de auditoría
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

// -------------------------------------------------------------
// Rutas Administrativas de Gestión de Usuarios (RBAC: Solo Admin)
// -------------------------------------------------------------

/**
 * GET /api/users
 * Devuelve la lista completa de usuarios registrados (excluyendo hashes y secretos 2FA).
 * Protegido con authenticateToken y requireRole('Admin').
 */
app.get('/api/users', authenticateToken, requireRole('Admin'), async (req, res, next) => {
  try {
    const users = await all(`
      SELECT id, name, email, role, status, created_at 
      FROM users 
      ORDER BY id ASC
    `);

    return res.status(200).json({
      success: true,
      count: users.length,
      data: users
    });
  } catch (error) {
    next(error);
  }
});

/**
 * POST /api/users
 * Da de alta un nuevo usuario/empleado.
 * Valida unicidad de correo, rol permitido, complejidad de contraseña y hashea con bcrypt.
 * Registra evento USER_CREATED en audit_logs.
 * Protegido con authenticateToken y requireRole('Admin').
 */
app.post('/api/users', authenticateToken, requireRole('Admin'), async (req, res, next) => {
  const { name, email, password, role = 'Employee' } = req.body;
  const ipAddress = req.clientIp;
  const adminEmail = req.user.email;

  // 1. Validaciones de presencia y formato
  if (!name || !email || !password) {
    return res.status(400).json({
      success: false,
      error: 'Debe suministrar name, email y password.'
    });
  }

  const cleanName = String(name).trim();
  const normalizedEmail = String(email).trim().toLowerCase();
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  if (cleanName.length < 2) {
    return res.status(400).json({
      success: false,
      error: 'El nombre debe tener al menos 2 caracteres.'
    });
  }

  if (!emailRegex.test(normalizedEmail)) {
    return res.status(400).json({
      success: false,
      error: 'Formato de correo electrónico inválido.'
    });
  }

  // 2. Validación de rol permitido
  const allowedRoles = ['Admin', 'Employee'];
  if (!allowedRoles.includes(role)) {
    return res.status(400).json({
      success: false,
      error: `El rol '${role}' no es válido. Debe ser 'Admin' o 'Employee'.`
    });
  }

  // 3. Validación de complejidad básica de contraseña (mínimo 8 caracteres)
  if (String(password).length < 8) {
    return res.status(400).json({
      success: false,
      error: 'La contraseña debe tener una longitud mínima de 8 caracteres.'
    });
  }

  try {
    // 4. Verificar si el correo ya existe
    const existingUser = await get('SELECT id FROM users WHERE email = ?', [normalizedEmail]);
    if (existingUser) {
      return res.status(409).json({
        success: false,
        error: 'El correo electrónico ya se encuentra registrado en el sistema.'
      });
    }

    // 5. Cifrar la contraseña con bcrypt (cost factor 12)
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // 6. Insertar en la base de datos (inicia con token_version = 1 e is_2fa_enabled = 0)
    const result = await run(
      `INSERT INTO users (name, email, password_hash, role, status, token_version, secret_2fa, is_2fa_enabled)
       VALUES (?, ?, ?, ?, 'Active', 1, NULL, 0)`,
      [cleanName, normalizedEmail, passwordHash, role]
    );

    // 7. Registro inmutable en audit_logs
    await addAuditLog({
      userEmail: adminEmail,
      action: 'USER_CREATED',
      ipAddress,
      details: {
        action: 'USER_CREATED',
        affectedEmail: normalizedEmail,
        role: role,
        ip: ipAddress,
        createdUserId: result.lastID,
        name: cleanName,
        status: 'Active',
        createdBy: adminEmail,
        description: `Usuario '${normalizedEmail}' creado exitosamente con rol '${role}' por el administrador '${adminEmail}'`
      }
    });

    return res.status(201).json({
      success: true,
      message: 'Usuario creado exitosamente',
      user: {
        id: result.lastID,
        name: cleanName,
        email: normalizedEmail,
        role,
        status: 'Active'
      }
    });

  } catch (error) {
    next(error);
  }
});

/**
 * PUT /api/users/:id/role
 * Permite cambiar el rol de un usuario (ej. de 'Employee' a 'Admin' o viceversa).
 * Protegido contra auto-degradación del último Admin del sistema.
 * Registra evento ROLE_CHANGED en audit_logs.
 * Protegido con authenticateToken y requireRole('Admin').
 */
app.put('/api/users/:id/role', authenticateToken, requireRole('Admin'), async (req, res, next) => {
  const userId = parseInt(req.params.id, 10);
  const { role } = req.body;
  const ipAddress = req.clientIp;
  const adminEmail = req.user.email;

  if (isNaN(userId)) {
    return res.status(400).json({
      success: false,
      error: 'ID de usuario inválido.'
    });
  }

  const allowedRoles = ['Admin', 'Employee'];
  if (!role || !allowedRoles.includes(role)) {
    return res.status(400).json({
      success: false,
      error: `El campo 'role' es requerido y debe ser 'Admin' o 'Employee'.`
    });
  }

  try {
    // 1. Verificar si el usuario objetivo existe
    const targetUser = await get(
      'SELECT id, name, email, role, status FROM users WHERE id = ?',
      [userId]
    );

    if (!targetUser) {
      return res.status(404).json({
        success: false,
        error: 'Usuario no encontrado.'
      });
    }

    // 2. Comprobación de seguridad: Anti auto-bloqueo del último Administrador
    if (req.user.id === targetUser.id && role !== 'Admin') {
      const adminCountRow = await get(
        "SELECT COUNT(*) as count FROM users WHERE role = 'Admin' AND status = 'Active'"
      );
      if (adminCountRow.count <= 1) {
        return res.status(400).json({
          success: false,
          error: 'Operación denegada: No se puede degradar al único Administrador activo del sistema.'
        });
      }
    }

    // 3. Actualizar rol en la base de datos
    await run('UPDATE users SET role = ? WHERE id = ?', [role, userId]);

    // 4. Registro inmutable en audit_logs
    await addAuditLog({
      userEmail: adminEmail,
      action: 'ROLE_CHANGED',
      ipAddress,
      details: {
        action: 'ROLE_CHANGED',
        affectedEmail: targetUser.email,
        role: role,
        ip: ipAddress,
        targetUserId: targetUser.id,
        previousRole: targetUser.role,
        newRole: role,
        changedBy: adminEmail,
        description: `Rol de '${targetUser.email}' actualizado de '${targetUser.role}' a '${role}' por '${adminEmail}'`
      }
    });

    return res.status(200).json({
      success: true,
      message: `Rol de usuario actualizado exitosamente a '${role}'`,
      user: {
        id: targetUser.id,
        name: targetUser.name,
        email: targetUser.email,
        role,
        status: targetUser.status
      }
    });

  } catch (error) {
    next(error);
  }
});

/**
 * PUT /api/users/:id/revoke (Offboarding Express)
 * Desactiva de inmediato la cuenta de un colaborador cambiando su estado a 'Revoked'.
 * Incluye regla defensiva anti auto-bloqueo para que el Admin no se revoque a sí mismo.
 * Registra evento USER_REVOKED_EXPRESS en audit_logs.
 * Protegido con authenticateToken y requireRole('Admin').
 */
app.put('/api/users/:id/revoke', authenticateToken, requireRole('Admin'), async (req, res, next) => {
  const userId = parseInt(req.params.id, 10);
  const ipAddress = req.clientIp;
  const adminEmail = req.user.email;

  if (isNaN(userId)) {
    return res.status(400).json({
      success: false,
      error: 'ID de usuario inválido.'
    });
  }

  // 1. Regla defensiva anti auto-bloqueo (Self-Lockout Prevention)
  if (req.user.id === userId) {
    return res.status(400).json({
      success: false,
      error: 'Operación denegada: Un Administrador no puede revocar su propia cuenta (Regla anti auto-bloqueo).'
    });
  }

  try {
    // 2. Verificar existencia del usuario objetivo
    const targetUser = await get(
      'SELECT id, name, email, role, status FROM users WHERE id = ?',
      [userId]
    );

    if (!targetUser) {
      return res.status(404).json({
        success: false,
        error: 'Usuario no encontrado.'
      });
    }

    if (targetUser.status === 'Revoked') {
      return res.status(400).json({
        success: false,
        error: `La cuenta del usuario (${targetUser.email}) ya se encuentra revocada.`
      });
    }

    // 3. Desactivación inmediata e incremento de token_version en SQLite (Offboarding Express)
    await run("UPDATE users SET status = 'Revoked', token_version = token_version + 1 WHERE id = ?", [userId]);

    // 4. Registro inmutable en audit_logs
    await addAuditLog({
      userEmail: adminEmail,
      action: 'USER_REVOKED_EXPRESS',
      ipAddress,
      details: {
        action: 'USER_REVOKED_EXPRESS',
        affectedEmail: targetUser.email,
        role: targetUser.role,
        ip: ipAddress,
        targetUserId: targetUser.id,
        previousStatus: targetUser.status,
        newStatus: 'Revoked',
        revokedBy: adminEmail,
        timestamp: new Date().toISOString(),
        description: `Offboarding Express: Cuenta de '${targetUser.email}' revocada de inmediato por '${adminEmail}'`
      }
    });

    return res.status(200).json({
      success: true,
      message: `Cuenta de usuario (${targetUser.email}) revocada exitosamente. El acceso ha sido invalidado en tiempo real.`,
      user: {
        id: targetUser.id,
        name: targetUser.name,
        email: targetUser.email,
        role: targetUser.role,
        status: 'Revoked'
      }
    });

  } catch (error) {
    next(error);
  }
});

/**
 * GET /api/audit-logs
 * Ruta protegida y con RBAC: Solo usuarios con rol 'Admin' pueden consultar la auditoría
 */
app.get('/api/audit-logs', authenticateToken, requireRole('Admin'), async (req, res, next) => {
  try {
    const limit = Math.min(parseInt(req.query.limit, 10) || 50, 100);
    const logs = await all(`
      SELECT id, timestamp, user_email, action, ip_address, details
      FROM audit_logs
      ORDER BY id DESC
      LIMIT ?
    `, [limit]);

    // Parsear details como objeto JSON estructurado si es válido
    const formattedLogs = logs.map((log) => {
      let parsedDetails = log.details;
      try {
        parsedDetails = JSON.parse(log.details);
      } catch {
        // mantener valor original si no es JSON válido
      }
      return {
        ...log,
        details: parsedDetails
      };
    });

    return res.status(200).json({
      success: true,
      count: formattedLogs.length,
      data: formattedLogs
    });
  } catch (error) {
    next(error);
  }
});

// -------------------------------------------------------------
// Rutas Estáticas y Frontend (Después de todas las rutas de API)
// -------------------------------------------------------------

// Servidor de archivos estáticos para la interfaz de usuario
app.use(express.static(path.join(__dirname, 'public')));

/**
 * GET /
 * Sirve la interfaz de usuario minimalista y limpia en la ruta principal
 */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// -------------------------------------------------------------
// Manejadores de Errores y Rutas no Encontradas
// -------------------------------------------------------------

// 404 para cualquier ruta de API no definida
app.all('/api/*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint de API no encontrado'
  });
});

// 404 general para recursos estáticos o rutas no existentes
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Recurso no encontrado'
  });
});

// Manejador centralizado de errores (seguro para producción)
app.use((err, req, res, next) => {
  const statusCode = err.status || err.statusCode || 500;
  
  if (NODE_ENV !== 'production') {
    console.error('[SERVER ERROR]', err);
  } else if (statusCode >= 500) {
    console.error(`[SERVER CRITICAL ERROR] ${err.message}`);
  }

  const errorMessage = (statusCode >= 500 && NODE_ENV === 'production')
    ? 'Error interno del servidor'
    : (err.message || 'Error inesperado en la solicitud');

  res.status(statusCode).json({
    success: false,
    error: errorMessage
  });
});

// -------------------------------------------------------------
// Inicialización del Servidor y Base de Datos
// -------------------------------------------------------------
async function startServer() {
  try {
    await initializeDatabase();

    const server = app.listen(PORT, () => {
      console.log(`=======================================================`);
      console.log(`🚀 IAM Ligero para Pymes iniciado en: http://localhost:${PORT}`);
      console.log(`🛡️ Modo: ${NODE_ENV}`);
      console.log(`📋 Rutas Principales:`);
      console.log(`   - GET  /                 -> Interfaz Web (Frontend Minimalista)`);
      console.log(`   - GET  /health           -> Verificación de estado`);
      console.log(`   - POST /api/auth/login   -> Autenticación y Token JWT`);
      console.log(`   - GET  /api/portal/profile -> Perfil del Empleado (Protegido)`);
      console.log(`   - PUT  /api/portal/password -> Cambio de Contraseña (Protegido)`);
      console.log(`   - POST /api/portal/2fa/setup -> Configuración 2FA TOTP (Protegido)`);
      console.log(`   - POST /api/portal/2fa/verify -> Confirmación y Activación 2FA TOTP (Protegido)`);
      console.log(`   - GET  /api/users        -> Listado de Usuarios (Solo Admin)`);
      console.log(`   - POST /api/users        -> Creación de Usuario (Solo Admin)`);
      console.log(`   - PUT  /api/users/:id/role -> Cambio de Rol (Solo Admin)`);
      console.log(`   - PUT  /api/users/:id/revoke -> Offboarding Express (Solo Admin)`);
      console.log(`   - GET  /api/audit-logs   -> Logs de Auditoría (Solo Admin)`);
      console.log(`=======================================================`);
    });

    const shutdown = () => {
      console.log('\n[IAM] Cerrando servidor y conexiones de base de datos...');
      server.close(() => {
        db.close((err) => {
          if (err) console.error('[DATABASE] Error cerrando SQLite:', err.message);
          else console.log('[DATABASE] Conexión SQLite cerrada con éxito.');
          process.exit(0);
        });
      });
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

  } catch (error) {
    console.error('❌ Error crítico al arrancar la aplicación:', error);
    process.exit(1);
  }
}

// Iniciar aplicación si se ejecuta directamente
if (require.main === module) {
  startServer();
}

module.exports = app;
