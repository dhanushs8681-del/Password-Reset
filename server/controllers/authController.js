import bcrypt from "bcryptjs";
import User from "../models/User.js";
import { sendResetEmail } from "../utils/mailer.js";
import { generateRawToken, hashToken, tokenExpiryFromNow } from "../utils/token.js";

/**
 * POST /api/auth/forgot-password
 *
 * 1. Reads the email from the request.
 * 2. Checks if the user exists in the DB. If not, returns an error message.
 * 3. Generates a random string, stores its hash + an expiry in the DB.
 * 4. Emails the user a link containing the plaintext random string.
 */
export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "Email is required." });
    }

    const user = await User.findOne({ email: email.toLowerCase().trim() });

    // The flow explicitly requires an error message when the user is not in DB.
    if (!user) {
      return res
        .status(404)
        .json({ message: "No account found with that email address." });
    }

    // Generate a cryptographically random string for the reset link.
    const rawToken = generateRawToken();
    const expiryMinutes = Number(process.env.RESET_TOKEN_EXPIRY_MINUTES) || 15;

    // Store only the hash + expiry in the DB for later verification.
    user.resetToken = hashToken(rawToken);
    user.resetTokenExpiry = tokenExpiryFromNow(expiryMinutes);
    await user.save();

    // Build the reset link that points at the React client.
    const clientUrl = process.env.CLIENT_URL || "http://localhost:5173";
    const resetLink = `${clientUrl}/reset-password/${rawToken}`;

    try {
      await sendResetEmail(user.email, resetLink, expiryMinutes);
    } catch (mailError) {
      // If the email fails to send, roll back the token so the user can retry.
      user.resetToken = null;
      user.resetTokenExpiry = null;
      await user.save();
      // Log full details (code + response) so SMTP issues are diagnosable.
      console.error("Email send error:", {
        message: mailError.message,
        code: mailError.code,
        command: mailError.command,
        response: mailError.response,
      });
      return res.status(502).json({
        message: "Could not send the reset email. Please try again.",
        // TEMPORARY diagnostic detail (removed after debugging).
        debug: {
          message: mailError.message,
          code: mailError.code,
          response: mailError.response,
        },
      });
    }

    return res.status(200).json({
      message: "A password reset link has been sent to your email.",
    });
  } catch (error) {
    console.error("forgotPassword error:", error.message);
    return res.status(500).json({ message: "Something went wrong." });
  }
};

/**
 * GET /api/auth/verify-token/:token
 *
 * Lightweight check used by the reset page on load: confirms the token matches
 * a user AND has not expired, so the UI can show either the reset form or an
 * "expired link" alert before the user types anything.
 */
export const verifyResetToken = async (req, res) => {
  try {
    const { token } = req.params;
    const hashed = hashToken(token);

    const user = await User.findOne({
      resetToken: hashed,
      resetTokenExpiry: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({
        valid: false,
        message: "This reset link is invalid or has expired.",
      });
    }

    return res.status(200).json({ valid: true });
  } catch (error) {
    console.error("verifyResetToken error:", error.message);
    return res.status(500).json({ valid: false, message: "Something went wrong." });
  }
};

/**
 * POST /api/auth/reset-password/:token
 *
 * 1. Hashes the token from the URL and looks for a matching, unexpired user.
 * 2. If the string does not match (or expired) -> error / alert.
 * 3. If it matches -> hash and store the new password, then CLEAR the token
 *    fields so the link cannot be reused.
 */
export const resetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    if (!password || password.length < 6) {
      return res
        .status(400)
        .json({ message: "Password must be at least 6 characters long." });
    }

    const hashed = hashToken(token);

    const user = await User.findOne({
      resetToken: hashed,
      resetTokenExpiry: { $gt: new Date() },
    });

    // Covers both "string does not match" and "link has expired".
    if (!user) {
      return res.status(400).json({
        message: "This reset link is invalid or has expired.",
      });
    }

    // Save the new password and clear the reset fields in the DB.
    user.password = await bcrypt.hash(password, 10);
    user.resetToken = null;
    user.resetTokenExpiry = null;
    await user.save();

    return res
      .status(200)
      .json({ message: "Your password has been reset successfully." });
  } catch (error) {
    console.error("resetPassword error:", error.message);
    return res.status(500).json({ message: "Something went wrong." });
  }
};

/**
 * POST /api/auth/register
 *
 * Creates a new user account from the Register page. The task requires a
 * Register flow (but NOT a Login flow) so that a freshly registered user can
 * then exercise the Forgot Password flow. Passwords are hashed with bcrypt.
 */
export const register = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required." });
    }

    // Basic email format check.
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res
        .status(400)
        .json({ message: "Please enter a valid email address." });
    }

    if (password.length < 6) {
      return res
        .status(400)
        .json({ message: "Password must be at least 6 characters long." });
    }

    const normalizedEmail = email.toLowerCase().trim();

    const existing = await User.findOne({ email: normalizedEmail });
    if (existing) {
      return res
        .status(409)
        .json({ message: "An account with this email already exists." });
    }

    const user = await User.create({
      name: name ? name.trim() : "",
      email: normalizedEmail,
      password: await bcrypt.hash(password, 10),
    });

    return res.status(201).json({
      message: "Account created successfully. You can now reset its password.",
      email: user.email,
    });
  } catch (error) {
    console.error("register error:", error.message);
    return res.status(500).json({ message: "Something went wrong." });
  }
};

/**
 * POST /api/auth/seed
 *
 * Convenience endpoint to create a demo user so the flow can be tested without
 * a separate signup screen (signup is out of scope for this task). Disabled in
 * production so it cannot be abused on the deployed service.
 */
export const seedUser = async (req, res) => {
  try {
    // Only allow seeding outside of production.
    if (process.env.NODE_ENV === "production") {
      return res.status(403).json({ message: "Not available." });
    }

    const { name, email, password } = req.body;
    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email and password are required." });
    }

    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    if (existing) {
      return res.status(409).json({ message: "User already exists." });
    }

    const user = await User.create({
      name: name || "",
      email: email.toLowerCase().trim(),
      password: await bcrypt.hash(password, 10),
    });

    return res
      .status(201)
      .json({ message: "Demo user created.", email: user.email });
  } catch (error) {
    console.error("seedUser error:", error.message);
    return res.status(500).json({ message: "Something went wrong." });
  }
};
