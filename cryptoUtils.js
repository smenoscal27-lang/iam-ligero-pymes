/**
 * Utilidades Criptográficas y de Cifrado en Reposo (AES-256-GCM)
 * Diseñado conforme a estándares de Ciberseguridad y AppSec.
 */

const crypto = require('crypto');
require('dotenv').config();

const NODE_ENV = process.env.NODE_ENV || 'development';

// Clave base para cifrado AES-256-GCM (32 bytes requeridos)
function getDerivedKey() {
  const secretKey = process.env.TWO_FACTOR_ENCRYPTION_KEY ||
                    process.env.ENCRYPTION_KEY ||
                    process.env.JWT_SECRET ||
                    'iam_pymes_aes_256_gcm_secret_key_2026_super_secure';

  if (NODE_ENV === 'production' && !process.env.TWO_FACTOR_ENCRYPTION_KEY && !process.env.ENCRYPTION_KEY) {
    console.warn('[SECURITY WARNING] TWO_FACTOR_ENCRYPTION_KEY no está definida explícitamente en producción.');
  }

  // Derivar clave de 32 bytes (256 bits) usando SHA-256
  return crypto.createHash('sha256').update(String(secretKey)).digest();
}

/**
 * Cifra un texto en claro usando AES-256-GCM con IV aleatorio de 12 bytes y Auth Tag de 16 bytes.
 * Formato de salida: `enc:v1:${ivHex}:${tagHex}:${cipherHex}`
 */
function encrypt2FASecret(plainText) {
  if (!plainText) return null;

  const key = getDerivedKey();
  const iv = crypto.randomBytes(12); // NIST SP 800-38D estándar para GCM
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);

  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag();

  return `enc:v1:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

/**
 * Descifra un secreto cifrado con AES-256-GCM.
 * Si el secreto es legado (no contiene delimitador ':'), se retorna de forma compatible.
 */
function decrypt2FASecret(encryptedString) {
  if (!encryptedString) return null;

  let str = encryptedString;
  if (str.startsWith('enc:v1:')) {
    str = str.slice(7);
  }

  const parts = str.split(':');
  if (parts.length !== 3) {
    // Compatibilidad con registros antiguos en texto claro
    return encryptedString;
  }

  const [ivHex, tagHex, dataHex] = parts;
  const key = getDerivedKey();
  const iv = Buffer.from(ivHex, 'hex');
  const tag = Buffer.from(tagHex, 'hex');

  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);

  let decrypted = decipher.update(dataHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}

/**
 * Genera códigos de respaldo legibles y de un solo uso (ej: "A1B2-C3D4")
 */
function generateBackupCodes(count = 8) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const raw = crypto.randomBytes(4).toString('hex').toUpperCase();
    const formatted = `${raw.slice(0, 4)}-${raw.slice(4, 8)}`;
    codes.push(formatted);
  }
  return codes;
}

/**
 * Hashea un código de respaldo con SHA-256 para guardarlo de forma segura en base de datos
 */
function hashBackupCode(code) {
  const normalized = String(code).trim().toUpperCase();
  return crypto.createHash('sha256').update(normalized).digest('hex');
}

module.exports = {
  encrypt2FASecret,
  decrypt2FASecret,
  generateBackupCodes,
  hashBackupCode
};
