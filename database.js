/**
 * Gestor de Base de Datos SQLite para IAM Ligero para Pymes
 * Diseñado con enfoque en ciberseguridad, inmutabilidad y compatibilidad.
 */

const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');
require('dotenv').config();

const dbPath = process.env.DB_PATH || path.join(__dirname, 'iam.sqlite');

// Instancia de conexión a SQLite
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('[DATABASE] ❌ Error al conectar con SQLite:', err.message);
  } else {
    console.log(`[DATABASE] 🔒 Conexión segura establecida con SQLite en: ${dbPath}`);
  }
});

/**
 * Envoltorios de Promesas para facilitar operaciones asíncronas seguras
 */
const run = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
};

const get = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
};

const all = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
};

/**
 * Función para registrar eventos de auditoría inmutables
 * Cumple con requerimientos de trazabilidad y ciberseguridad
 * Almacena en 'details' un objeto JSON con acción, correo afectado, rol, IP y descripción del evento.
 */
async function addAuditLog({ userEmail, action, ipAddress = '127.0.0.1', details = {} }) {
  const sql = `
    INSERT INTO audit_logs (user_email, action, ip_address, details)
    VALUES (?, ?, ?, ?)
  `;

  let detailsObj = {};
  if (typeof details === 'object' && details !== null) {
    detailsObj = { ...details };
  } else if (typeof details === 'string') {
    try {
      detailsObj = JSON.parse(details);
    } catch {
      detailsObj = { description: details };
    }
  }

  // Asegurar la presencia estricta de los campos clave exigidos por la auditoría de ciberseguridad
  if (!detailsObj.action) {
    detailsObj.action = action;
  }
  if (!detailsObj.affectedEmail) {
    detailsObj.affectedEmail = detailsObj.targetEmail || detailsObj.revokedUserEmail || detailsObj.userEmail || userEmail;
  }
  if (!detailsObj.role) {
    detailsObj.role = detailsObj.userRole || detailsObj.revokedUserRole || detailsObj.newRole || 'N/A';
  }
  if (!detailsObj.ip) {
    detailsObj.ip = ipAddress;
  }

  const detailsString = JSON.stringify(detailsObj);
  return await run(sql, [userEmail, action, ipAddress, detailsString]);
}

/**
 * Script de inicialización de esquemas y seeding idempotente
 */
async function initializeDatabase() {
  try {
    // Configuraciones de rendimiento y robustez
    await run('PRAGMA foreign_keys = ON;');
    await run('PRAGMA journal_mode = WAL;');

    // 1. Tabla users: control de identidades, roles, estado y 2FA
    await run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('Admin', 'Employee')) DEFAULT 'Employee',
        status TEXT NOT NULL CHECK(status IN ('Active', 'Revoked')) DEFAULT 'Active',
        secret_2fa TEXT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // 2. Tabla audit_logs: registro inmutable de auditoría
    await run(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        user_email TEXT NOT NULL,
        action TEXT NOT NULL,
        ip_address TEXT,
        details TEXT
      );
    `);

    // Índices para optimización de consultas defensivas
    await run('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);');
    await run('CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);');
    await run('CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);');
    await run('CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);');
    await run('CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_email);');

    // 3. Seeder: Insertar Administrador por defecto si no existe
    await seedDefaultAdmin();

    // 4. Normalización defensiva de registros de auditoría preexistentes
    await normalizeAuditLogs();

    console.log('[DATABASE] ✅ Tablas y esquemas IAM verificados correctamente.');
  } catch (error) {
    console.error('[DATABASE] ❌ Error durante la inicialización:', error);
    throw error;
  }
}

/**
 * Normaliza registros históricos de audit_logs para garantizar que 'details'
 * contenga siempre los campos auditables: action, affectedEmail, role, ip.
 */
async function normalizeAuditLogs() {
  try {
    const rawLogs = await all('SELECT id, user_email, action, ip_address, details FROM audit_logs');
    for (const log of rawLogs) {
      let detailsObj = {};
      try {
        detailsObj = JSON.parse(log.details);
      } catch {
        detailsObj = { description: log.details || '' };
      }

      let modified = false;
      if (!detailsObj.action) {
        detailsObj.action = log.action;
        modified = true;
      }
      if (!detailsObj.affectedEmail) {
        detailsObj.affectedEmail = detailsObj.targetEmail || detailsObj.revokedUserEmail || detailsObj.userEmail || log.user_email;
        modified = true;
      }
      if (!detailsObj.role) {
        detailsObj.role = detailsObj.userRole || detailsObj.revokedUserRole || detailsObj.newRole || 'N/A';
        modified = true;
      }
      if (!detailsObj.ip) {
        detailsObj.ip = log.ip_address || '127.0.0.1';
        modified = true;
      }

      if (modified) {
        await run('UPDATE audit_logs SET details = ? WHERE id = ?', [JSON.stringify(detailsObj), log.id]);
      }
    }
  } catch (err) {
    console.warn('[DATABASE] Aviso en normalización de logs:', err.message);
  }
}

/**
 * Inserta el usuario Administrador inicial de forma idempotente con contraseña hasheada
 */
async function seedDefaultAdmin() {
  const adminEmail = process.env.DEFAULT_ADMIN_EMAIL || 'admin@iam-pymes.local';
  const adminName = process.env.DEFAULT_ADMIN_NAME || 'Super Administrador';
  const adminPassword = process.env.DEFAULT_ADMIN_PASSWORD || 'AdminPass123!*Segura';

  // Verificar si ya existe el usuario con este email
  const existingUser = await get('SELECT id, email, role FROM users WHERE email = ?', [adminEmail]);

  if (!existingUser) {
    // Generar hash seguro con bcrypt (cost factor 12)
    const saltRounds = 12;
    const passwordHash = await bcrypt.hash(adminPassword, saltRounds);

    const result = await run(
      `INSERT INTO users (name, email, password_hash, role, status, secret_2fa)
       VALUES (?, ?, ?, 'Admin', 'Active', NULL)`,
      [adminName, adminEmail, passwordHash]
    );

    // Registro inmutable de auditoría del evento de creación inicial
    await addAuditLog({
      userEmail: adminEmail,
      action: 'SYSTEM_SEED_ADMIN',
      ipAddress: '127.0.0.1',
      details: {
        action: 'SYSTEM_SEED_ADMIN',
        affectedEmail: adminEmail,
        role: 'Admin',
        ip: '127.0.0.1',
        userId: result.lastID,
        status: 'Active',
        description: 'Inicialización de cuenta de Super Administrador por defecto'
      }
    });

    console.log('---------------------------------------------------------');
    console.log('[IAM-SECURITY] 🛡️ Super Administrador inicial configurado:');
    console.log(`  👤 Nombre:     ${adminName}`);
    console.log(`  📧 Email:      ${adminEmail}`);
    console.log(`  🔑 Contraseña: ${adminPassword}`);
    console.log(`  🏷️ Rol:        Admin | Estado: Active`);
    console.log('---------------------------------------------------------');
  } else {
    console.log(`[IAM-SECURITY] ℹ️ Administrador ya registrado (${existingUser.email}). Omitiendo inserción.`);
  }
}

// Ejecutar inicialización si se corre directamente desde CLI: `node database.js`
if (require.main === module) {
  initializeDatabase()
    .then(() => {
      console.log('[DATABASE] Proceso de inicialización finalizado.');
      process.exit(0);
    })
    .catch((err) => {
      console.error('[DATABASE] Error fatal:', err);
      process.exit(1);
    });
}

module.exports = {
  db,
  run,
  get,
  all,
  addAuditLog,
  seedDefaultAdmin,
  initializeDatabase
};
