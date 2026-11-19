/**
 * Rutas de Auditoría Forense (/api/audit-logs)
 * Exclusivo para administradores (RBAC: requireRole('Admin')).
 * Proporciona el registro inmutable de eventos de seguridad.
 */

const express = require('express');
const router = express.Router();

const { all } = require('../database');
const { authenticateToken, requireRole } = require('../authMiddleware');

router.use(authenticateToken);
router.use(requireRole('Admin'));

/**
 * GET /api/audit-logs
 * Retorna los registros forenses con límite configurable (máximo 100)
 */
router.get('/', async (req, res, next) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 100);
    const logs = await all(`
      SELECT id, timestamp, user_email, action, ip_address, details
      FROM audit_logs
      ORDER BY id DESC
      LIMIT ?
    `, [limit]);

    const formattedLogs = logs.map((log) => {
      let parsedDetails = log.details;
      try {
        parsedDetails = JSON.parse(log.details);
      } catch {
        // Mantener original si no es JSON válido
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

module.exports = router;
