# Gestor de Identidad y Accesos (IAM) Ligero para Pymes

Sistema modular y ligero de autenticación, control de accesos basados en roles (RBAC), autoservicio para empleados con doble factor (2FA TOTP), revocación inmediata de cuentas (**Offboarding Express**) y registro inmutable de auditoría forense, construido con **Node.js**, **Express**, **SQLite** y estándares de ciberseguridad.

---

## 🛡️ Características de Seguridad Implementadas

1. **Gestión de Identidades Seguras (`users`)**:
   - Almacenamiento seguro de contraseñas mediante **bcrypt** (factor de costo 12).
   - Control de Acceso Basado en Roles (**RBAC**) con roles definidos (`Admin`, `Employee`).
   - Estados de cuenta (`Active`, `Revoked`).
   - Soporte nativo para doble factor de autenticación TOTP (`secret_2fa`).
   - Sanitización estricta en respuestas API (nunca se exponen hashes ni secretos 2FA).

2. **Autenticación y Generación de Tokens JWT**:
   - Endpoint `POST /api/auth/login` con validación de cuentas activas y verificación criptográfica mediante `bcrypt.compare`.
   - Generación de JSON Web Tokens (JWT) firmados con expiración estricta de 2 horas.
   - Mensajes de error defensivos contra enumeración de usuarios.

3. **Portal del Empleado (Autoservicio Seguro)**:
   - `GET /api/portal/profile`: Consulta de perfil detallado indicando si 2FA está habilitado (`has2FA: true/false`).
   - `PUT /api/portal/password`: Cambio de contraseña con validación de contraseña actual, longitud mínima (8 caracteres) y política de no-repetición inmediata.
   - `POST /api/portal/2fa/setup`: Generación de secreto Base32 y URL `otpauth://` compatible con Google Authenticator y Authy mediante `speakeasy`.

4. **Offboarding Express e Invalidación en Tiempo Real**:
   - `PUT /api/users/:id/revoke`: Revocación inmediata del acceso de cualquier colaborador cambiando su estado a `Revoked`.
   - **Regla defensiva Anti Auto-Bloqueo (*Self-Lockout*)**: Impide que el Administrador revoque su propia cuenta.
   - **Invalidación de Sesión en Tiempo Real**: `authMiddleware` valida el estado activo en base de datos en cada petición, mitigando la ventana de riesgo de tokens JWT previamente emitidos (respuesta inmediata con HTTP 403 Forbidden).

5. **Gestión Administrativa de Usuarios (Solo Admin)**:
   - `POST /api/users`: Alta de nuevos usuarios/empleados con validación de email único, rol permitido, complejidad mínima de contraseña y cifrado bcrypt.
   - `PUT /api/users/:id/role`: Modificación de rol (`Employee` <-> `Admin`) con regla anti auto-bloqueo del último Administrador.
   - `GET /api/users`: Consulta completa del inventario de identidades para el panel administrativo.

6. **Registro de Auditoría Inmutable (`audit_logs`)**:
   - Trazabilidad forense automática de eventos: `SYSTEM_SEED_ADMIN`, `LOGIN_SUCCESS`, `LOGIN_FAILED`, `USER_CREATED`, `ROLE_CHANGED`, `USER_REVOKED_EXPRESS`, `PASSWORD_CHANGED` y `2FA_SETUP`.
   - Registra marca de tiempo UTC, usuario autor, acción, dirección IP y metadatos estructurados en JSON.

7. **Seguridad Perimetral en Express**:
   - Cabeceras HTTP seguras con **Helmet**.
   - Control de Acceso entre Orígenes (**CORS**).
   - Límite defensivo de carga útil en JSON (10kb) para mitigar ataques DoS.
   - Manejo centralizado de excepciones sin fuga de stack traces internas.

---

## 📁 Estructura del Proyecto

```
├── .env                  # Variables de entorno activas (no versionadas)
├── .env.example          # Plantilla de variables de entorno
├── .gitignore            # Exclusión de archivos sensibles y base de datos
├── authMiddleware.js     # Middleware de validación JWT, estado activo en tiempo real y RBAC
├── database.js           # Esquemas SQLite, seeder y helpers de auditoría
├── iam.sqlite            # Base de datos SQLite local
├── package.json          # Metadatos del proyecto y dependencias
├── public/
│   └── index.html        # Interfaz de usuario minimalista (HTML5 + Tailwind CSS + Vanilla JS)
├── MANUAL.md             # Manual operativo, credenciales por defecto y guía de pruebas paso a paso
├── README.md             # Documentación técnica
└── server.js             # Servidor Express, endpoints públicos y protegidos
```

---

## 🚀 Puesta en Marcha

### 1. Instalación de Dependencias
```bash
npm install
```

### 2. Configuración de Variables de Entorno
Copia `.env.example` a `.env` si es necesario:
```bash
cp .env.example .env
```

Variables disponibles:
- `PORT`: Puerto del servidor (por defecto `3000`).
- `DB_PATH`: Ruta al archivo SQLite (por defecto `./iam.sqlite`).
- `JWT_SECRET`: Clave secreta para la firma de tokens JWT.
- `JWT_EXPIRES_IN`: Tiempo de expiración del token (por defecto `2h`).
- `DEFAULT_ADMIN_EMAIL`: Correo del superadministrador (`admin@iam-pymes.local`).
- `DEFAULT_ADMIN_PASSWORD`: Contraseña temporal inicial (`AdminPass123!*Segura`).

### 3. Iniciar Servidor
```bash
npm start
```

---

## 📡 Catálogo Completo de Endpoints

### 1. Endpoints Públicos
| Método | Endpoint | Descripción |
| :--- | :--- | :--- |
| `GET` | `/health` | Chequeo de salud del servicio y conectividad con SQLite |
| `POST` | `/api/auth/login` | Autenticación, generación de JWT y log de auditoría |

---

### 2. Portal del Empleado (Requiere `Authorization: Bearer <token>`)
| Método | Endpoint | Permisos | Descripción |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/portal/profile` | Autenticado | Perfil detallado del usuario (incluye `has2FA`) |
| `PUT` | `/api/portal/password` | Autenticado | Cambio de propia contraseña validando actual |
| `POST` | `/api/portal/2fa/setup` | Autenticado | Configuración de 2FA TOTP (Google Authenticator) |

#### Ejemplo: Cambio de Contraseña (`PUT /api/portal/password`)
```http
PUT /api/portal/password HTTP/1.1
Authorization: Bearer <TOKEN_EMPLEADO>
Content-Type: application/json

{
  "currentPassword": "PasswordActual123!",
  "newPassword": "NuevaPasswordSegura2026!"
}
```

#### Ejemplo: Configuración 2FA TOTP (`POST /api/portal/2fa/setup`)
```http
POST /api/portal/2fa/setup HTTP/1.1
Authorization: Bearer <TOKEN_EMPLEADO>
```
Respuesta:
```json
{
  "success": true,
  "message": "Configuración 2FA TOTP generada exitosamente.",
  "twoFactor": {
    "secret": "JNNSQ53GKEUE65DXKNKTCM2XNA7HGJJX",
    "otpauth_url": "otpauth://totp/IAM%20Pymes%20(empleado%40pymes.com)?secret=JNNSQ53GKEUE65DXKNKTCM2XNA7HGJJX",
    "instructions": "Escanee la URL o ingrese la clave secreta manualmente en Google Authenticator o Authy."
  }
}
```

---

### 3. Panel Administrativo (Requiere rol `Admin`)
| Método | Endpoint | Permisos (RBAC) | Descripción |
| :--- | :--- | :--- | :--- |
| `GET` | `/api/users` | Rol `Admin` | Listado completo de identidades del sistema |
| `POST` | `/api/users` | Rol `Admin` | Alta de nuevo empleado/usuario |
| `PUT` | `/api/users/:id/role` | Rol `Admin` | Cambio de rol (`Admin` o `Employee`) |
| `PUT` | `/api/users/:id/revoke` | Rol `Admin` | **Offboarding Express**: Revocación inmediata |
| `GET` | `/api/audit-logs` | Rol `Admin` | Consulta del registro inmutable de auditoría |

---

## 🔑 Credenciales Iniciales de Administrador

- **Email**: `admin@iam-pymes.local`
- **Contraseña**: `AdminPass123!*Segura`
- **Rol**: `Admin`
- **Estado**: `Active`
