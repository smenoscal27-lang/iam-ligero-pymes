# 📖 Manual Operativo y de Pruebas: Gestor de Identidad y Accesos (IAM) Ligero para Pymes

Bienvenido al manual oficial del **Gestor de Identidad y Accesos (IAM) Ligero y Seguro para Pymes**. Este documento ha sido diseñado para la evaluación de la rúbrica institucional y para facilitar la instalación, puesta en marcha y verificación integral de las políticas de ciberseguridad implementadas.

---

## 🛠️ 1. Instrucciones de Instalación y Ejecución

### Requisitos Previos
- **Node.js**: Versión 16.x o superior (recomendado Node.js 18.x LTS o 20.x).
- **npm**: Gestor de paquetes oficial incluido con Node.js.
- Terminal o consola de comandos (PowerShell, Bash, CMD o Zsh).

### Paso 1: Clonar o Situarse en el Directorio del Proyecto
Abra una consola en la raíz del proyecto:
```bash
cd "d:\Escritorio\Proyecto 2 Gestor de Identidad y Accesos (IAM) Ligero para Pymes"
```

### Paso 2: Instalación de Dependencias
Instale los paquetes requeridos por el sistema:
```bash
npm install
```
> Las dependencias clave instaladas incluyen: `express`, `sqlite3`, `bcryptjs`, `jsonwebtoken`, `speakeasy`, `helmet`, `cors` y `dotenv`.

### Paso 3: Configuración de Variables de Entorno
El proyecto cuenta con un archivo preconfigurado `.env`. Si desea recrearlo a partir de la plantilla:
```bash
# En Windows (PowerShell):
Copy-Item .env.example .env

# En Linux / macOS / Git Bash:
cp .env.example .env
```

Contenido por defecto en `.env`:
```properties
PORT=3000
NODE_ENV=development
DB_PATH=./iam.sqlite
DEFAULT_ADMIN_NAME="Super Administrador"
DEFAULT_ADMIN_EMAIL=admin@iam-pymes.local
DEFAULT_ADMIN_PASSWORD=AdminPass123!*Segura
JWT_SECRET=iam_pymes_super_secret_jwt_key_2026_987654321_secure
JWT_EXPIRES_IN=2h
```

### Paso 4: Puesta en Marcha del Servidor
Inicie la aplicación con:
```bash
npm start
```
Al arrancar, el sistema inicializa automáticamente la base de datos SQLite en modo WAL (`iam.sqlite`), ejecuta las migraciones de esquema, crea los índices defensivos y efectúa el sembrado (*seeding*) idempotente del usuario Administrador por defecto si no existiese.

### Paso 5: Comprobación de Salud del Servicio (Health Check)
En otra terminal o navegador, verifique que la API responda:
```bash
curl -X GET http://localhost:3000/health
```
Respuesta esperada (**HTTP 200 OK**):
```json
{
  "status": "healthy",
  "system": "IAM Ligero para Pymes",
  "environment": "development",
  "timestamp": "2026-11-05T21:50:39.790Z",
  "database": "connected"
}
```

### Paso 6: Acceso a la Interfaz Web (Frontend Minimalista)
Abra su navegador web e ingrese a:
```
http://localhost:3000
```
La interfaz web minimalista permite operar y probar visualmente:
- **Login Seguro**: Validación de credenciales y almacenamiento de JWT en `localStorage`.
- **Dashboard del Administrador**: Inventario de identidades, botón de **Offboarding Express**, formulario de alta de empleados y visor en tiempo real de la bitácora de auditoría.
- **Portal del Empleado**: Consulta de perfil de identidad, actualización de contraseña y configuración de 2FA TOTP (Google Authenticator / Authy).

---

## 🔑 2. Credenciales Operativas por Defecto

El sistema incluye una cuenta de Administrador de arranque seguro para operar la plataforma y supervisar la auditoría:

| Parámetro | Valor por Defecto |
| :--- | :--- |
| **Rol** | `Admin` |
| **Nombre** | `Super Administrador` |
| **Correo Electrónico** | `admin@iam-pymes.local` |
| **Contraseña Inicial** | `AdminPass123!*Segura` |
| **Estado de Cuenta** | `Active` |

> 🛡️ **Seguridad Criptográfica**: La contraseña inicial nunca se almacena en texto claro; se procesa de forma nativa mediante **bcrypt** con un factor de coste (*salt rounds*) de **12**.

---

## 🚦 3. Matriz de Códigos de Estado HTTP

El sistema aplica estrictamente el estándar REST y las buenas prácticas de ciberseguridad:

| Código | Significado | Escenario de Uso en el IAM |
| :---: | :--- | :--- |
| **`200 OK`** | Solicitud procesada exitosamente | Login exitoso, lectura de perfiles, actualización de contraseñas, configuración 2FA, offboarding exitoso y consulta de auditoría. |
| **`201 Created`** | Recurso creado exitosamente | Alta de un nuevo empleado en `POST /api/users`. |
| **`400 Bad Request`** | Parámetros inválidos o incompletos | Faltan campos requeridos, contraseñas con longitud menor a 8 caracteres o auto-revocación prohibida (*anti self-lockout*). |
| **`401 Unauthorized`** | Credenciales o token inválidos | Mensaje genérico `"Credenciales inválidas"` ante usuario inexistente o contraseña errónea (anti-enumeración), token ausente o expirado. |
| **`403 Forbidden`** | Acceso prohibido por rol o estado | Intento de acceso de un empleado a rutas de `Admin` (RBAC) o token válido pero asociado a una cuenta con estado `Revoked` (*Offboarding Express*). |
| **`409 Conflict`** | Conflicto de estado (duplicidad) | Intento de alta de un usuario con un correo que ya existe en el sistema en `POST /api/users`. |

---

## 🧪 4. Guía Rápida de Pruebas de Funciones Clave

A continuación se presentan ejemplos listos para copiar y pegar en su terminal utilizando `curl` o **PowerShell** (`Invoke-RestMethod`).

### 🔹 Prueba 1: Autenticación Segura y Prevención de Enumeración de Usuarios

#### A. Intento de inicio de sesión con correo inexistente
```bash
curl -i -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "noexiste@iam-pymes.local", "password": "Password123!"}'
```
- **Código HTTP esperado**: `401 Unauthorized`
- **Cuerpo de respuesta**: `{"success": false, "error": "Credenciales inválidas"}`

#### B. Intento de inicio de sesión con correo existente pero contraseña incorrecta
```bash
curl -i -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@iam-pymes.local", "password": "PasswordIncorrecta999!"}'
```
- **Código HTTP esperado**: `401 Unauthorized`
- **Cuerpo de respuesta**: `{"success": false, "error": "Credenciales inválidas"}`

> 🛡️ **Defensa contra Enumeración y Temporización**: Ambos casos devuelven el mismo código de estado (401) y mensaje idéntico. Adicionalmente, el servidor ejecuta una comparación de hash de coste constante para evitar ataques de canal lateral basados en temporización (*timing attacks*).

#### C. Inicio de sesión exitoso como Administrador
```bash
curl -i -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "admin@iam-pymes.local", "password": "AdminPass123!*Segura"}'
```
- **Código HTTP esperado**: `200 OK`
- **Respuesta**: Token JWT con 2 horas de vigencia y datos sanitizados del usuario:
```json
{
  "success": true,
  "message": "Inicio de sesión exitoso",
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "name": "Super Administrador",
    "email": "admin@iam-pymes.local",
    "role": "Admin",
    "status": "Active"
  }
}
```
*(Guarde el token obtenido en una variable de entorno para los siguientes pasos)*.

---

### 🔹 Prueba 2: Alta de Empleados (Onboarding) y Control de Duplicados

#### A. Crear un nuevo empleado (Requiere rol Admin)
*(Reemplace `<ADMIN_TOKEN>` con el token obtenido en el paso 1)*:
```bash
curl -i -X POST http://localhost:3000/api/users \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Carlos Mendoza",
    "email": "carlos.mendoza@pymes.local",
    "password": "PasswordEmpleado2026!",
    "role": "Employee"
  }'
```
- **Código HTTP esperado**: `201 Created`
- **Respuesta**:
```json
{
  "success": true,
  "message": "Usuario creado exitosamente",
  "user": {
    "id": 2,
    "name": "Carlos Mendoza",
    "email": "carlos.mendoza@pymes.local",
    "role": "Employee",
    "status": "Active"
  }
}
```

#### B. Intentar registrar el mismo correo nuevamente (Verificación de conflicto)
```bash
curl -i -X POST http://localhost:3000/api/users \
  -H "Authorization: Bearer <ADMIN_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Carlos Mendoza Duplicado",
    "email": "carlos.mendoza@pymes.local",
    "password": "PasswordEmpleado2026!",
    "role": "Employee"
  }'
```
- **Código HTTP esperado**: `409 Conflict`
- **Respuesta**: `{"success": false, "error": "El correo electrónico ya se encuentra registrado en el sistema."}`

---

### 🔹 Prueba 3: Portal del Empleado y Autoservicio de Doble Factor (2FA)

#### A. Iniciar sesión como el Empleado
```bash
curl -i -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "carlos.mendoza@pymes.local", "password": "PasswordEmpleado2026!"}'
```
- **Código HTTP esperado**: `200 OK`
- Guarde el token devuelto como `<EMPLEADO_TOKEN>`.

#### B. Consultar perfil personal
```bash
curl -i -X GET http://localhost:3000/api/portal/profile \
  -H "Authorization: Bearer <EMPLEADO_TOKEN>"
```
- **Código HTTP esperado**: `200 OK`
- **Respuesta**: Indica `has2FA: false` antes de la configuración.

#### C. Configurar Segundo Factor de Autenticación TOTP (2FA - Paso 1: Inicialización)
```bash
curl -i -X POST http://localhost:3000/api/portal/2fa/setup \
  -H "Authorization: Bearer <EMPLEADO_TOKEN>"
```
- **Código HTTP esperado**: `200 OK`
- **Seguridad en Reposo**: La clave secreta se almacena cifrada en SQLite mediante **AES-256-GCM** (`enc:v1:...`) y su estado inicial queda en pendiente (`is_2fa_enabled = 0`) hasta confirmarse.
- **Respuesta**:
```json
{
  "success": true,
  "message": "Configuración 2FA inicializada. Ingrese el código de 6 dígitos de su aplicación para verificar y activar el doble factor.",
  "twoFactor": {
    "secret": "JBSWY3DPEHPK3PXP...",
    "otpauth_url": "otpauth://totp/IAM-Pymes:carlos.mendoza@pymes.local?secret=...",
    "instructions": "Escanee la URL o ingrese la clave secreta manualmente en Google Authenticator o Authy y confirme con el código de 6 dígitos."
  }
}
```

#### D. Confirmar y Activar Segundo Factor TOTP (2FA - Paso 2: Verificación y Códigos de Respaldo)
*(Ingrese el código de 6 dígitos generado en su aplicación de autenticación, por ejemplo `123456`)*:
```bash
curl -i -X POST http://localhost:3000/api/portal/2fa/verify \
  -H "Authorization: Bearer <EMPLEADO_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"code": "123456"}'
```
- **Código HTTP esperado**: `200 OK`
- **Mecanismos AppSec**:
  - Validación TOTP estricta de 6 dígitos con ventana de tolerancia `window: 1`.
  - Descifrado seguro en memoria del secreto AES-256-GCM.
  - Prevención de reuso del mismo código en el ciclo de 30 segundos (*Anti-Replay Protection* mediante `last_totp_code`).
  - Activación formal (`is_2fa_enabled = 1`).
  - Generación de 8 códigos de respaldo de un solo uso (`XXXX-XXXX`) almacenados hasheados con **SHA-256**.
- **Respuesta**:
```json
{
  "success": true,
  "message": "Doble factor de autenticación (2FA) verificado y activado exitosamente.",
  "is2FAEnabled": true,
  "backupCodes": [
    "A1B2-C3D4",
    "E5F6-G7H8",
    "I9J0-K1L2",
    "M3N4-O5P6",
    "Q7R8-S9T0",
    "U1V2-W3X4",
    "Y5Z6-A7B8",
    "C9D0-E1F2"
  ],
  "instructions": "Guarde estos códigos de respaldo en un lugar seguro. Solo se mostrarán esta vez."
}
```

#### E. Cambio de contraseña por el propio empleado (Con Invalidación de Sesión Inmediata)
```bash
curl -i -X PUT http://localhost:3000/api/portal/password \
  -H "Authorization: Bearer <EMPLEADO_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "currentPassword": "PasswordEmpleado2026!",
    "newPassword": "NuevaPasswordSegura2026!#"
  }'
```
- **Código HTTP esperado**: `200 OK`
- **Efecto de Seguridad**: Incrementa el campo numérico `token_version` en la base de datos, provocando que cualquier JWT emitido previamente con la versión anterior sea rechazado de inmediato (`HTTP 401 Unauthorized`).
- **Respuesta**: `{"success": true, "message": "Contraseña actualizada exitosamente. Sus sesiones previas han sido cerradas por seguridad."}`

---

### 🔹 Prueba 4: Offboarding Express e Invalidación en Tiempo Real

El escenario de **Offboarding Express** resuelve el problema crítico de la persistencia de tokens JWT: cuando un colaborador es desvinculado, su sesión debe cancelarse **de inmediato**, sin esperar a que el token expire naturalmente.

#### A. El Administrador revoca la cuenta del colaborador
*(Utilice el ID del empleado creado, por ejemplo `2`)*:
```bash
curl -i -X PUT http://localhost:3000/api/users/2/revoke \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```
- **Código HTTP esperado**: `200 OK`
- **Respuesta**:
```json
{
  "success": true,
  "message": "Cuenta de usuario (carlos.mendoza@pymes.local) revocada exitosamente. El acceso ha sido invalidado en tiempo real.",
  "user": {
    "id": 2,
    "name": "Carlos Mendoza",
    "email": "carlos.mendoza@pymes.local",
    "role": "Employee",
    "status": "Revoked"
  }
}
```

#### B. Verificación de Invalidación Inmediata con Token Previo
El empleado intenta consumir cualquier endpoint protegido usando su token anterior:
```bash
curl -i -X GET http://localhost:3000/api/portal/profile \
  -H "Authorization: Bearer <EMPLEADO_TOKEN>"
```
- **Código HTTP esperado**: `403 Forbidden`
- **Respuesta**:
```json
{
  "success": false,
  "error": "Acceso denegado: Su cuenta ha sido revocada o desactivada. Sesión invalidada de inmediato."
}
```

#### C. Intento de inicio de sesión con cuenta revocada
```bash
curl -i -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "carlos.mendoza@pymes.local", "password": "NuevaPasswordSegura2026!#"}'
```
- **Código HTTP esperado**: `403 Forbidden`
- **Respuesta**:
```json
{
  "success": false,
  "error": "Acceso denegado: La cuenta ha sido revocada o suspendida"
}
```

#### D. Regla defensiva anti auto-bloqueo (*Self-Lockout*)
Si el Administrador intenta revocarse a sí mismo:
```bash
curl -i -X PUT http://localhost:3000/api/users/1/revoke \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```
- **Código HTTP esperado**: `400 Bad Request`
- **Respuesta**: `{"success": false, "error": "Operación denegada: Un Administrador no puede revocar su propia cuenta (Regla anti auto-bloqueo)."}`

---

### 🔹 Prueba 5: Auditoría Descriptiva Forense (`audit_logs`)

El sistema registra de forma inmutable todos los eventos de seguridad.

#### Consultar el registro de auditoría (Solo Admin)
```bash
curl -i -X GET "http://localhost:3000/api/audit-logs?limit=10" \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```
- **Código HTTP esperado**: `200 OK`
- **Estructura detallada del registro**: Cada objeto dentro de `details` incluye de forma clara y explícita:
  1. `action`: Nombre unificado de la acción (`USER_CREATED`, `LOGIN_FAILED`, `USER_REVOKED_EXPRESS`, etc.).
  2. `affectedEmail`: Correo electrónico del usuario afectado o destino de la acción.
  3. `role`: Rol del usuario afectado (`Admin`, `Employee`).
  4. `ip`: Dirección IP del cliente que generó la petición.
  5. `description`: Resumen contextual en lenguaje natural del evento registrado.

Ejemplo de registro real devuelto:
```json
{
  "id": 28,
  "timestamp": "2026-11-05 21:51:39",
  "user_email": "admin@iam-pymes.local",
  "action": "USER_REVOKED_EXPRESS",
  "ip_address": "127.0.0.1",
  "details": {
    "action": "USER_REVOKED_EXPRESS",
    "affectedEmail": "carlos.mendoza@pymes.local",
    "role": "Employee",
    "ip": "127.0.0.1",
    "targetUserId": 2,
    "previousStatus": "Active",
    "newStatus": "Revoked",
    "revokedBy": "admin@iam-pymes.local",
    "description": "Offboarding Express: Cuenta de 'carlos.mendoza@pymes.local' revocada de inmediato por 'admin@iam-pymes.local'"
  }
}
```

---

## 🔒 5. Resumen de Cumplimiento de la Rúbrica de Ciberseguridad

| Requisito de la Rúbrica | Estado | Implementación Técnica |
| :--- | :---: | :--- |
| **1. Mensajes de Autenticación Seguros** | ✅ Cumplido | Ante email inexistente o contraseña incorrecta, se responde con HTTP `401` y `"Credenciales inválidas"`. Se utiliza un hash dummy para evitar *timing attacks*. |
| **2. Códigos de Estado HTTP Correctos** | ✅ Cumplido | Uso estricto de `200` (OK), `201` (Created), `400` (Bad Request), `401` (Unauthorized), `403` (Forbidden) y `409` (Conflict en duplicados). |
| **3. Auditoría Descriptiva (`audit_logs`)** | ✅ Cumplido | El campo `details` incluye siempre de forma estructurada: `action`, `affectedEmail`, `role`, `ip` y descripción forense. |
| **4. Manual y Credenciales (`MANUAL.md`)** | ✅ Cumplido | Documentación completa con instrucciones paso a paso, credenciales por defecto y comandos de prueba funcionales. |
| **5. Endurecimiento JWT y `token_version`** | ✅ Cumplido | Firma con `HS256`, payload con `sub`, `role` y `token_version`. Invalidación inmediata en DB tras cambio de clave o revocación (`HTTP 401`). |
| **6. Doble Factor en 2 Pasos y AES-256-GCM** | ✅ Cumplido | Setup genera secreto Base32 cifrado en reposo con AES-256-GCM (`enc:v1:`). Verificación con tolerancia `window: 1`, prevención de replay y códigos de respaldo hasheados con SHA-256. |

