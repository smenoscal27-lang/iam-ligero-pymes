/**
 * Rutas Administrativas de Gestión de Usuarios (/api/users)
 * Exclusivo para administradores (RBAC: requireRole('Admin')).
 * Implementa alta de identidades, cambio de rol y Offboarding Express.
 */

const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');

const { run, get, all, addAuditLog } = require('../database');
const { authenticateToken, requireRole } = require('../authMiddleware');

// Todos los endpoints de usuarios requieren autenticación y rol Admin
router.use(authenticateToken);
router.use(requireRole('Admin'));

/**
 * GET /api/users
 * Retorna todos los usuarios registrados
 */
router.get('/', async (req, res, next) => {
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
 * Da de alta un nuevo usuario/empleado con contraseña hasheada (bcrypt).
 */
router.post('/', async (req, res, next) => {
  const { name, email, password, role = 'Employee' } = req.body;
  const ipAddress = req.clientIp || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const adminEmail = req.user.email;

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

  const allowedRoles = ['Admin', 'Employee'];
  if (!allowedRoles.includes(role)) {
    return res.status(400).json({
      success: false,
      error: `El rol '${role}' no es válido. Debe ser 'Admin' o 'Employee'.`
    });
  }

  if (String(password).length < 8) {
    return res.status(400).json({
      success: false,
      error: 'La contraseña debe tener una longitud mínima de 8 caracteres.'
    });
  }

  try {
    const existingUser = await get('SELECT id FROM users WHERE email = ?', [normalizedEmail]);
    if (existingUser) {
      return res.status(409).json({
        success: false,
        error: 'El correo electrónico ya se encuentra registrado en el sistema.'
      });
    }

    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const result = await run(
      `INSERT INTO users (name, email, password_hash, role, status, token_version, secret_2fa, is_2fa_enabled)
       VALUES (?, ?, ?, ?, 'Active', 1, NULL, 0)`,
      [cleanName, normalizedEmail, passwordHash, role]
    );

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
 * Permite cambiar el rol de un usuario con regla anti auto-degradación del último Admin.
 */
router.put('/:id/role', async (req, res, next) => {
  const userId = parseInt(req.params.id, 10);
  const { role } = req.body;
  const ipAddress = req.clientIp || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
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

    await run('UPDATE users SET role = ? WHERE id = ?', [role, userId]);

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
 * Desactiva de inmediato la cuenta del colaborador e incrementa token_version.
 */
router.put('/:id/revoke', async (req, res, next) => {
  const userId = parseInt(req.params.id, 10);
  const ipAddress = req.clientIp || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const adminEmail = req.user.email;

  if (isNaN(userId)) {
    return res.status(400).json({
      success: false,
      error: 'ID de usuario inválido.'
    });
  }

  if (req.user.id === userId) {
    return res.status(400).json({
      success: false,
      error: 'Operación denegada: Un Administrador no puede revocar su propia cuenta (Regla anti auto-bloqueo).'
    });
  }

  try {
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

    await run("UPDATE users SET status = 'Revoked', token_version = token_version + 1 WHERE id = ?", [userId]);

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

module.exports = router;
