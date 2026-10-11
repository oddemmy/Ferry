const crypto = require("crypto");
const pool = require("./db");

const CODE_TTL_MINUTES = 15;
const MAX_ATTEMPTS = 5;
const RESEND_COOLDOWN_SECONDS = 60;

// Codes are stored hashed, never in plain text
function hashCode(code) {
    return crypto.createHash("sha256").update(String(code)).digest("hex");
}

// Creates (or replaces) the code for this user + purpose and returns the plain code to email
async function issueCode(userId, purpose) {
    const code = String(crypto.randomInt(100000, 1000000)); // always 6 digits
    const expiresAt = new Date(Date.now() + CODE_TTL_MINUTES * 60 * 1000);

    await pool.query(
        `INSERT INTO email_codes (user_id, purpose, code_hash, expires_at, attempts, created_at)
         VALUES ($1, $2, $3, $4, 0, now())
         ON CONFLICT (user_id, purpose) DO UPDATE
         SET code_hash = EXCLUDED.code_hash,
             expires_at = EXCLUDED.expires_at,
             attempts = 0,
             created_at = now()`,
        [userId, purpose, hashCode(code), expiresAt]
    );

    return code;
}

// True if a code was sent too recently to send another
async function onCooldown(userId, purpose) {
    const cutoff = new Date(Date.now() - RESEND_COOLDOWN_SECONDS * 1000);
    const result = await pool.query(
        `SELECT 1 FROM email_codes WHERE user_id = $1 AND purpose = $2 AND created_at > $3`,
        [userId, purpose, cutoff]
    );
    return result.rows.length > 0;
}

// Returns "ok" | "invalid" | "expired" | "locked". A correct code is consumed (single use).
async function checkCode(userId, purpose, code) {
    const result = await pool.query(
        `UPDATE email_codes SET attempts = attempts + 1
         WHERE user_id = $1 AND purpose = $2
         RETURNING code_hash, attempts, expires_at`,
        [userId, purpose]
    );

    if (result.rows.length === 0) return "invalid";

    const row = result.rows[0];
    if (new Date(row.expires_at) < new Date()) return "expired";
    if (row.attempts > MAX_ATTEMPTS) return "locked";
    if (hashCode(code) !== row.code_hash) return "invalid";

    await pool.query("DELETE FROM email_codes WHERE user_id = $1 AND purpose = $2", [userId, purpose]);
    return "ok";
}

module.exports = { issueCode, onCooldown, checkCode, CODE_TTL_MINUTES };