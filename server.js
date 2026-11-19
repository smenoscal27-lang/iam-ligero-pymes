/**
 * Servidor Principal - Gestor de Identidad y Accesos (IAM) Ligero para Pymes
 * Arquitectura modular y segura basada en Node.js, Express, SQLite y JWT.
 */

require('dotenv').config();
const path = require('path');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const { db, all, initializeDatabase } = require('./database');

// Importar rutas modulares
const authRoutes = require('./routes/auth.routes');
const portalRoutes = require('./routes/portal.routes');
const usersRoutes = require('./routes/users.routes');
const auditRoutes = require('./routes/audit.routes');

const app = express();
const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

// -------------------------------------------------------------
// 1. Validación de Secretos en Producción
// -------------------------------------------------------------
if (NODE_ENV === 'production') {
  if (!process.env.JWT_SECRET) {
    console.error('❌ [FATAL SECURITY ERROR] process.env.JWT_SECRET no está configurado en producción.');
    process.exit(1);
  }
  if (!process.env.TWO_FACTOR_ENCRYPTION_KEY) {
    console.warn('⚠️ [SECURITY WARNING] process.env.TWO_FACTOR_ENCRYPTION_KEY no está definido explícitamente en producción.');
  }
}

// -------------------------------------------------------------
// 2. Middlewares de Seguridad y Comunicación
// -------------------------------------------------------------

// Cabeceras HTTP seguras con Helmet (CSP optimizado para Tailwind CDN, Google Fonts y SPA)
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

// Control de Acceso entre Orígenes (CORS)
app.use(
  cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    credentials: true
  })
);

// Soporte para JSON y URL-encoded con límite defensivo de carga (mitigación DoS)
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Middleware para extraer IP real del cliente
app.use((req, res, next) => {
  req.clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  next();
});

// Middleware de prevención de almacenamiento en caché para todas las rutas API
app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

// -------------------------------------------------------------
// 3. Verificación de Estado (Healthcheck)
// -------------------------------------------------------------
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

// -------------------------------------------------------------
// 4. Montaje de Rutas Modulares de la API
// -------------------------------------------------------------
app.use('/api/auth', authRoutes);
app.use('/api/portal', portalRoutes);
app.use('/api/users', usersRoutes);
app.use('/api/audit-logs', auditRoutes);

// -------------------------------------------------------------
// 5. Servidor de Archivos Estáticos y Frontend (SPA)
// -------------------------------------------------------------
app.use(express.static(path.join(__dirname, 'public'), {
  maxAge: NODE_ENV === 'production' ? '1h' : '0'
}));

// Ruta raíz: sirve la SPA minimalista
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// -------------------------------------------------------------
// 6. Manejo de Errores y Rutas no Encontradas
// -------------------------------------------------------------

// 404 para cualquier ruta /api/* no registrada
app.all('/api/*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Endpoint de API no encontrado'
  });
});

// 404 general para recursos estáticos no encontrados
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Recurso no encontrado'
  });
});

// Manejador centralizado de errores
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
// 7. Arranque y Cierre Grácil del Servidor
// -------------------------------------------------------------
async function startServer() {
  try {
    await initializeDatabase();

    const server = app.listen(PORT, () => {
      console.log(`=======================================================`);
      console.log(`🚀 IAM Ligero para Pymes iniciado en: http://localhost:${PORT}`);
      console.log(`🛡️ Entorno: ${NODE_ENV}`);
      console.log(`📋 Rutas Principales:`);
      console.log(`   - GET  /                     -> Interfaz Web (SPA con animaciones)`);
      console.log(`   - GET  /health               -> Comprobación de salud`);
      console.log(`   - POST /api/auth/login       -> Autenticación JWT`);
      console.log(`   - GET  /api/auth/me          -> Datos de sesión`);
      console.log(`   - GET  /api/portal/profile   -> Perfil del Empleado`);
      console.log(`   - PUT  /api/portal/password  -> Cambio de Contraseña`);
      console.log(`   - POST /api/portal/2fa/setup -> Setup 2FA TOTP (AES-256-GCM)`);
      console.log(`   - POST /api/portal/2fa/verify-> Confirmación 2FA y Backup Codes`);
      console.log(`   - GET  /api/users            -> Inventario de Usuarios (Admin)`);
      console.log(`   - POST /api/users            -> Alta de Usuario (Admin)`);
      console.log(`   - PUT  /api/users/:id/role   -> Asignación de Roles (Admin)`);
      console.log(`   - PUT  /api/users/:id/revoke -> Offboarding Express (Admin)`);
      console.log(`   - GET  /api/audit-logs       -> Bitácora Inmutable (Admin)`);
      console.log(`=======================================================`);
    });

    const shutdown = () => {
      console.log('\n[IAM] Cerrando servidor y base de datos...');
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

if (require.main === module) {
  startServer();
}

module.exports = app;
