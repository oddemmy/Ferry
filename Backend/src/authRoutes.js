const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const pool = require("./db");
const { issueCode, onCooldown, checkCode } = require("./codes");
const { sendCodeEmail } = require("./mailer");

const router = express.Router();

const normalizeEmail = (email) => (typeof email === "string" ? email.trim().toLowerCase() : "");
const isEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const validPassword = (p) => typeof p === "string" && p.length >= 8;

const signToken = (user) =>
    jwt.sign({ userId: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "1h" });

const findUser = async (email) => {
    const result = await pool.query("SELECT * FROM users WHERE lower(email) = $1", [email]);
    return result.rows[0];
};

const codeErrors = {
    invalid: "Invalid code",
    expired: "This code has expired. Request a new one.",
    locked: "Too many attempts. Request a new code.",
};

// POST /auth/signup  { email, password }
router.post("/signup", async (req, res, next) => {
    const email = normalizeEmail(req.body?.email);
    const password = req.body?.password;
    if (!isEmail(email)) return res.status(400).json({ error: "Please provide a valid email" });
    if (!validPassword(password)) {
        return res.status(400).json({ error: "Password must be at least 8 characters" });
    }
    try {
        let user = await findUser(email);
        if (user?.email_verified) return res.status(409).json({ error: "Email already in use" });

        if (!user) {
            const hashed = await bcrypt.hash(password, 10);
            const result = await pool.query(
                "INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email",
                [email, hashed]
            );
            user = result.rows[0];
        }
        // Unverified account signing up again: don't touch its password, just (re)send a code
        if (!(await onCooldown(user.id, "verify"))) {
            const code = await issueCode(user.id, "verify");
            await sendCodeEmail(email, code, "verify");
        }
        return res.status(201).json({ message: "Verification code sent", email });
    } catch (error) {
        if (error.code === "23505") return res.status(409).json({ error: "Email already in use" });
        next(error);
    }
});

// POST /auth/verify-email  { email, code }  -> logs the user in on success
router.post("/verify-email", async (req, res, next) => {
    const email = normalizeEmail(req.body?.email);
    const code = req.body?.code;
    if (!email || !code) return res.status(400).json({ error: "Email and code are required" });
    try {
        const user = await findUser(email);
        if (!user) return res.status(400).json({ error: codeErrors.invalid });
        if (user.email_verified) return res.status(400).json({ error: "Email already verified" });

        const status = await checkCode(user.id, "verify", String(code));
        if (status !== "ok") return res.status(400).json({ error: codeErrors[status] });

        await pool.query("UPDATE users SET email_verified = TRUE WHERE id = $1", [user.id]);
        return res.status(200).json({ id: user.id, email: user.email, token: signToken(user) });
    } catch (error) {
        next(error);
    }
});

// POST /auth/resend-code  { email }
router.post("/resend-code", async (req, res, next) => {
    const email = normalizeEmail(req.body?.email);
    if (!email) return res.status(400).json({ error: "Email is required" });
    try {
        const user = await findUser(email);
        if (user && !user.email_verified && !(await onCooldown(user.id, "verify"))) {
            const code = await issueCode(user.id, "verify");
            await sendCodeEmail(user.email, code, "verify");
        }
        // Same response either way so this can't be used to check who has an account
        return res.status(200).json({ message: "If that account needs verification, a new code has been sent" });
    } catch (error) {
        next(error);
    }
});

// POST /auth/login  { email, password }
router.post("/login", async (req, res, next) => {
    const email = normalizeEmail(req.body?.email);
    const password = req.body?.password;
    if (!email || !password) return res.status(400).json({ error: "Please provide valid details" });
    try {
        const user = await findUser(email);
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
            return res.status(401).json({ error: "Invalid credentials" });
        }
        if (!user.email_verified) {
            return res.status(403).json({
                error: "Please verify your email first",
                code: "EMAIL_NOT_VERIFIED",
                email: user.email,
            });
        }
        return res.status(200).json({ id: user.id, email: user.email, token: signToken(user) });
    } catch (error) {
        next(error);
    }
});

// POST /auth/forgot-password  { email }
router.post("/forgot-password", async (req, res, next) => {
    const email = normalizeEmail(req.body?.email);
    if (!email) return res.status(400).json({ error: "Email is required" });
    try {
        const user = await findUser(email);
        if (user && !(await onCooldown(user.id, "reset"))) {
            const code = await issueCode(user.id, "reset");
            await sendCodeEmail(user.email, code, "reset");
        }
        return res.status(200).json({ message: "If that account exists, a reset code has been sent" });
    } catch (error) {
        next(error);
    }
});

// POST /auth/verify-reset-code  { email, code }  -> { resetToken } (valid for 10 minutes)
router.post("/verify-reset-code", async (req, res, next) => {
    const email = normalizeEmail(req.body?.email);
    const code = req.body?.code;
    if (!email || !code) return res.status(400).json({ error: "Email and code are required" });
    try {
        const user = await findUser(email);
        if (!user) return res.status(400).json({ error: codeErrors.invalid });

        const status = await checkCode(user.id, "reset", String(code));
        if (status !== "ok") return res.status(400).json({ error: codeErrors[status] });

        const resetToken = jwt.sign(
            { userId: user.id, purpose: "password-reset" },
            process.env.JWT_SECRET,
            { expiresIn: "10m" }
        );
        return res.status(200).json({ resetToken });
    } catch (error) {
        next(error);
    }
});

// POST /auth/reset-password  { resetToken, newPassword }
router.post("/reset-password", async (req, res, next) => {
    const { resetToken, newPassword } = req.body || {};
    if (!resetToken) {
        return res.status(400).json({ error: "Reset session missing. Please start again." });
    }
    if (!validPassword(newPassword)) {
        return res.status(400).json({ error: "Password must be at least 8 characters" });
    }
    const expired = { error: "Reset session expired. Please start again." };
    try {
        let decoded;
        try {
            decoded = jwt.verify(resetToken, process.env.JWT_SECRET);
        } catch {
            return res.status(400).json(expired);
        }
        if (decoded.purpose !== "password-reset") {
            return res.status(400).json(expired);
        }

        const hashed = await bcrypt.hash(newPassword, 10);
        await pool.query(
            "UPDATE users SET password_hash = $1, email_verified = TRUE WHERE id = $2",
            [hashed, decoded.userId]
        );
        return res.status(200).json({ message: "Password updated. You can now log in." });
    } catch (error) {
        next(error);
    }
});

module.exports = router;