// src/index.ts
import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import pino from "pino";
import swaggerUi from "swagger-ui-express";
import swaggerJSDoc from "swagger-jsdoc";
import jwt from "jsonwebtoken";
import { createClient } from "@supabase/supabase-js";
var logger = pino({ transport: process.env.NODE_ENV !== "production" ? { target: "pino-pretty" } : void 0 });
var PORT = Number(process.env.PORT || 4e3);
var CORS_ORIGINS = (process.env.CORS_ORIGINS || "").split(",").map((s) => s.trim()).filter(Boolean);
var SUPABASE_URL = process.env.SUPABASE_URL;
var SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
var ADMIN_JWT_SECRET = process.env.ADMIN_JWT_SECRET;
if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  logger.warn("Supabase admin env not set. Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.");
}
if (!ADMIN_JWT_SECRET) {
  logger.warn("ADMIN_JWT_SECRET is not set. Admin auth will fail.");
}
var supabaseAdmin = createClient(SUPABASE_URL || "", SUPABASE_SERVICE_ROLE_KEY || "", {
  auth: { persistSession: false, autoRefreshToken: false }
});
var swaggerSpec = swaggerJSDoc({
  definition: {
    openapi: "3.0.3",
    info: {
      title: "LinguaLink Admin API",
      version: "1.0.0",
      description: "Admin API for LinguaLink platform management including user moderation, role management, and analytics"
    },
    servers: [{ url: `http://localhost:${PORT}` }],
    components: {
      securitySchemes: {
        bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" }
      },
      schemas: {
        User: {
          type: "object",
          properties: {
            id: { type: "string", format: "uuid" },
            username: { type: "string" },
            email: { type: "string", format: "email" },
            country: { type: "string" },
            state: { type: "string" },
            city: { type: "string" },
            lga: { type: "string" },
            created_at: { type: "string", format: "date-time" },
            updated_at: { type: "string", format: "date-time" },
            referral_code: { type: "string" },
            is_banned: { type: "boolean" },
            admin_roles: { type: "array", items: { type: "string" } },
            language_roles: { type: "object" },
            referral_count: { type: "integer" }
          }
        },
        Pagination: {
          type: "object",
          properties: {
            page: { type: "integer" },
            limit: { type: "integer" },
            total: { type: "integer" },
            pages: { type: "integer" }
          }
        },
        AdminAction: {
          type: "object",
          properties: {
            id: { type: "string", format: "uuid" },
            admin_id: { type: "string", format: "uuid" },
            action: { type: "string" },
            target_user_id: { type: "string", format: "uuid" },
            details: { type: "object" },
            created_at: { type: "string", format: "date-time" }
          }
        }
      }
    },
    security: [{ bearerAuth: [] }]
  },
  apis: ["./src/index.ts"]
});
var app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(helmet());
app.use(cors({ origin: CORS_ORIGINS.length ? CORS_ORIGINS : true }));
app.set("trust proxy", 1);
var limiter = rateLimit({ windowMs: 6e4, max: 120 });
app.use(limiter);
var waitlistLimiter = rateLimit({ windowMs: 6e4, max: 10 });
app.get("/health", (_req, res) => {
  res.json({ ok: true, uptime: process.uptime() });
});
app.use("/docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));
app.post("/waitlist", waitlistLimiter, async (req, res) => {
  try {
    const rawEmail = String(req.body?.email || "").trim().toLowerCase();
    const rawPhone = String(req.body?.phoneNumber || "").trim();
    const language = String(req.body?.language || "").trim();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!rawEmail || !emailRegex.test(rawEmail)) {
      return res.status(400).json({ error: "Valid email is required" });
    }
    if (!rawPhone) {
      return res.status(400).json({ error: "Phone number is required" });
    }
    if (!language) {
      return res.status(400).json({ error: "Language is required" });
    }
    const phoneNumber = rawPhone.replace(/[^+\d]/g, "");
    const { error } = await supabaseAdmin.from("waitlist").insert({ email: rawEmail, phone_number: phoneNumber, language });
    if (error) {
      const already = error.message?.toLowerCase().includes("duplicate");
      if (already) {
        return res.json({ message: "Already on waitlist" });
      }
      logger.error({ err: error }, "Error inserting waitlist");
      return res.status(500).json({ error: "Failed to add to waitlist" });
    }
    res.json({ message: "Added to waitlist" });
  } catch (error) {
    logger.error({ err: error }, "Unexpected error in /waitlist");
    res.status(500).json({ error: "Internal server error" });
  }
});
function adminGuard(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ") ? header.slice(7) : void 0;
    if (!token) return res.status(401).json({ error: "Missing token" });
    const payload = jwt.verify(token, ADMIN_JWT_SECRET);
    if (!payload || payload.role !== "admin" && payload.role !== "superadmin") {
      return res.status(403).json({ error: "Forbidden" });
    }
    req.admin = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid token" });
  }
}
app.get("/admin/users", adminGuard, async (req, res) => {
  try {
    const { page = 1, limit = 20, banned, role, country, search } = req.query;
    const offset = (Number(page) - 1) * Number(limit);
    let query = supabaseAdmin.from("profiles").select(`
        id,
        username,
        email,
        country,
        state,
        city,
        lga,
        created_at,
        updated_at,
        referral_code,
        is_banned,
        admin_roles,
        language_roles
      `, { count: "exact" });
    if (banned !== void 0) {
      query = query.eq("is_banned", banned === "true");
    }
    if (role) {
      query = query.contains("admin_roles", [role]);
    }
    if (country) {
      query = query.eq("country", country);
    }
    if (search) {
      query = query.or(`username.ilike.%${search}%,email.ilike.%${search}%`);
    }
    const { data: users, error, count } = await query.range(offset, offset + Number(limit) - 1).order("created_at", { ascending: false });
    if (error) {
      logger.error({ err: error }, "Error fetching users");
      return res.status(500).json({ error: "Failed to fetch users" });
    }
    res.json({
      users: users || [],
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: count || 0,
        pages: Math.ceil((count || 0) / Number(limit))
      }
    });
  } catch (error) {
    logger.error({ err: error }, "Unexpected error in /admin/users");
    res.status(500).json({ error: "Internal server error" });
  }
});
app.get("/admin/users/:id", adminGuard, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: user, error } = await supabaseAdmin.from("profiles").select(`
        id,
        username,
        email,
        country,
        state,
        city,
        lga,
        created_at,
        updated_at,
        referral_code,
        is_banned,
        admin_roles,
        language_roles,
        referral_count
      `).eq("id", id).single();
    if (error) {
      if (error.code === "PGRST116") {
        return res.status(404).json({ error: "User not found" });
      }
      logger.error({ err: error }, "Error fetching user");
      return res.status(500).json({ error: "Failed to fetch user" });
    }
    res.json({ user });
  } catch (error) {
    logger.error({ err: error }, "Unexpected error in /admin/users/:id");
    res.status(500).json({ error: "Internal server error" });
  }
});
app.post("/admin/users/:id/ban", adminGuard, async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;
    const { data: user, error: fetchError } = await supabaseAdmin.from("profiles").select("id, username, is_banned").eq("id", id).single();
    if (fetchError) {
      if (fetchError.code === "PGRST116") {
        return res.status(404).json({ error: "User not found" });
      }
      return res.status(500).json({ error: "Failed to fetch user" });
    }
    if (user.is_banned) {
      return res.status(400).json({ error: "User is already banned" });
    }
    const { error: updateError } = await supabaseAdmin.from("profiles").update({
      is_banned: true,
      ban_reason: reason,
      banned_at: (/* @__PURE__ */ new Date()).toISOString()
    }).eq("id", id);
    if (updateError) {
      logger.error({ err: updateError }, "Error banning user");
      return res.status(500).json({ error: "Failed to ban user" });
    }
    await supabaseAdmin.from("admin_actions").insert({
      admin_id: req.admin?.sub,
      action: "ban_user",
      target_user_id: id,
      details: { reason },
      created_at: (/* @__PURE__ */ new Date()).toISOString()
    });
    res.json({ message: "User banned successfully" });
  } catch (error) {
    logger.error({ err: error }, "Unexpected error in /admin/users/:id/ban");
    res.status(500).json({ error: "Internal server error" });
  }
});
app.post("/admin/users/:id/unban", adminGuard, async (req, res) => {
  try {
    const { id } = req.params;
    const { data: user, error: fetchError } = await supabaseAdmin.from("profiles").select("id, username, is_banned").eq("id", id).single();
    if (fetchError) {
      if (fetchError.code === "PGRST116") {
        return res.status(404).json({ error: "User not found" });
      }
      return res.status(500).json({ error: "Failed to fetch user" });
    }
    if (!user.is_banned) {
      return res.status(400).json({ error: "User is not banned" });
    }
    const { error: updateError } = await supabaseAdmin.from("profiles").update({
      is_banned: false,
      ban_reason: null,
      banned_at: null
    }).eq("id", id);
    if (updateError) {
      logger.error({ err: updateError }, "Error unbanning user");
      return res.status(500).json({ error: "Failed to unban user" });
    }
    await supabaseAdmin.from("admin_actions").insert({
      admin_id: req.admin?.sub,
      action: "unban_user",
      target_user_id: id,
      details: {},
      created_at: (/* @__PURE__ */ new Date()).toISOString()
    });
    res.json({ message: "User unbanned successfully" });
  } catch (error) {
    logger.error({ err: error }, "Unexpected error in /admin/users/:id/unban");
    res.status(500).json({ error: "Internal server error" });
  }
});
app.post("/admin/users/:id/promote", adminGuard, async (req, res) => {
  try {
    const { id } = req.params;
    const { role = "admin" } = req.body;
    if (!["admin", "superadmin"].includes(role)) {
      return res.status(400).json({ error: "Invalid role. Must be admin or superadmin" });
    }
    const { data: user, error: fetchError } = await supabaseAdmin.from("profiles").select("id, username, admin_roles").eq("id", id).single();
    if (fetchError) {
      if (fetchError.code === "PGRST116") {
        return res.status(404).json({ error: "User not found" });
      }
      return res.status(500).json({ error: "Failed to fetch user" });
    }
    const currentRoles = user.admin_roles || [];
    if (currentRoles.includes(role)) {
      return res.status(400).json({ error: `User already has ${role} role` });
    }
    const { error: updateError } = await supabaseAdmin.from("profiles").update({
      admin_roles: [...currentRoles, role]
    }).eq("id", id);
    if (updateError) {
      logger.error({ err: updateError }, "Error promoting user");
      return res.status(500).json({ error: "Failed to promote user" });
    }
    await supabaseAdmin.from("admin_actions").insert({
      admin_id: req.admin?.sub,
      action: "promote_user",
      target_user_id: id,
      details: { role },
      created_at: (/* @__PURE__ */ new Date()).toISOString()
    });
    res.json({ message: `User promoted to ${role} successfully` });
  } catch (error) {
    logger.error({ err: error }, "Unexpected error in /admin/users/:id/promote");
    res.status(500).json({ error: "Internal server error" });
  }
});
app.post("/admin/users/:id/demote", adminGuard, async (req, res) => {
  try {
    const { id } = req.params;
    const { role = "admin" } = req.body;
    const { data: user, error: fetchError } = await supabaseAdmin.from("profiles").select("id, username, admin_roles").eq("id", id).single();
    if (fetchError) {
      if (fetchError.code === "PGRST116") {
        return res.status(404).json({ error: "User not found" });
      }
      return res.status(500).json({ error: "Failed to fetch user" });
    }
    const currentRoles = user.admin_roles || [];
    if (!currentRoles.includes(role)) {
      return res.status(400).json({ error: `User does not have ${role} role` });
    }
    const { error: updateError } = await supabaseAdmin.from("profiles").update({
      admin_roles: currentRoles.filter((r) => r !== role)
    }).eq("id", id);
    if (updateError) {
      logger.error({ err: updateError }, "Error demoting user");
      return res.status(500).json({ error: "Failed to demote user" });
    }
    await supabaseAdmin.from("admin_actions").insert({
      admin_id: req.admin?.sub,
      action: "demote_user",
      target_user_id: id,
      details: { role },
      created_at: (/* @__PURE__ */ new Date()).toISOString()
    });
    res.json({ message: `User demoted from ${role} successfully` });
  } catch (error) {
    logger.error({ err: error }, "Unexpected error in /admin/users/:id/demote");
    res.status(500).json({ error: "Internal server error" });
  }
});
app.post("/admin/users/:id/roles/validator", adminGuard, async (req, res) => {
  try {
    const { id } = req.params;
    const { language } = req.body;
    if (!language) {
      return res.status(400).json({ error: "Language is required" });
    }
    const { data: user, error: fetchError } = await supabaseAdmin.from("profiles").select("id, username, language_roles").eq("id", id).single();
    if (fetchError) {
      if (fetchError.code === "PGRST116") {
        return res.status(404).json({ error: "User not found" });
      }
      return res.status(500).json({ error: "Failed to fetch user" });
    }
    const currentRoles = user.language_roles || {};
    if (currentRoles[language]?.includes("validator")) {
      return res.status(400).json({ error: `User already has validator role for ${language}` });
    }
    const updatedRoles = {
      ...currentRoles,
      [language]: [...currentRoles[language] || [], "validator"]
    };
    const { error: updateError } = await supabaseAdmin.from("profiles").update({ language_roles: updatedRoles }).eq("id", id);
    if (updateError) {
      logger.error({ err: updateError }, "Error granting validator role");
      return res.status(500).json({ error: "Failed to grant validator role" });
    }
    await supabaseAdmin.from("admin_actions").insert({
      admin_id: req.admin?.sub,
      action: "grant_validator_role",
      target_user_id: id,
      details: { language },
      created_at: (/* @__PURE__ */ new Date()).toISOString()
    });
    res.json({ message: `Validator role granted for ${language} successfully` });
  } catch (error) {
    logger.error({ err: error }, "Unexpected error in /admin/users/:id/roles/validator");
    res.status(500).json({ error: "Internal server error" });
  }
});
app.post("/admin/users/:id/roles/ambassador", adminGuard, async (req, res) => {
  try {
    const { id } = req.params;
    const { language } = req.body;
    if (!language) {
      return res.status(400).json({ error: "Language is required" });
    }
    const { data: user, error: fetchError } = await supabaseAdmin.from("profiles").select("id, username, language_roles").eq("id", id).single();
    if (fetchError) {
      if (fetchError.code === "PGRST116") {
        return res.status(404).json({ error: "User not found" });
      }
      return res.status(500).json({ error: "Failed to fetch user" });
    }
    const currentRoles = user.language_roles || {};
    if (currentRoles[language]?.includes("ambassador")) {
      return res.status(400).json({ error: `User already has ambassador role for ${language}` });
    }
    const updatedRoles = {
      ...currentRoles,
      [language]: [...currentRoles[language] || [], "ambassador"]
    };
    const { error: updateError } = await supabaseAdmin.from("profiles").update({ language_roles: updatedRoles }).eq("id", id);
    if (updateError) {
      logger.error({ err: updateError }, "Error granting ambassador role");
      return res.status(500).json({ error: "Failed to grant ambassador role" });
    }
    await supabaseAdmin.from("admin_actions").insert({
      admin_id: req.admin?.sub,
      action: "grant_ambassador_role",
      target_user_id: id,
      details: { language },
      created_at: (/* @__PURE__ */ new Date()).toISOString()
    });
    res.json({ message: `Ambassador role granted for ${language} successfully` });
  } catch (error) {
    logger.error({ err: error }, "Unexpected error in /admin/users/:id/roles/ambassador");
    res.status(500).json({ error: "Internal server error" });
  }
});
app.delete("/admin/users/:id/roles/validator", adminGuard, async (req, res) => {
  try {
    const { id } = req.params;
    const { language } = req.body;
    if (!language) {
      return res.status(400).json({ error: "Language is required" });
    }
    const { data: user, error: fetchError } = await supabaseAdmin.from("profiles").select("id, username, language_roles").eq("id", id).single();
    if (fetchError) {
      if (fetchError.code === "PGRST116") {
        return res.status(404).json({ error: "User not found" });
      }
      return res.status(500).json({ error: "Failed to fetch user" });
    }
    const currentRoles = user.language_roles || {};
    if (!currentRoles[language]?.includes("validator")) {
      return res.status(400).json({ error: `User does not have validator role for ${language}` });
    }
    const updatedRoles = {
      ...currentRoles,
      [language]: currentRoles[language].filter((role) => role !== "validator")
    };
    const { error: updateError } = await supabaseAdmin.from("profiles").update({ language_roles: updatedRoles }).eq("id", id);
    if (updateError) {
      logger.error({ err: updateError }, "Error revoking validator role");
      return res.status(500).json({ error: "Failed to revoke validator role" });
    }
    await supabaseAdmin.from("admin_actions").insert({
      admin_id: req.admin?.sub,
      action: "revoke_validator_role",
      target_user_id: id,
      details: { language },
      created_at: (/* @__PURE__ */ new Date()).toISOString()
    });
    res.json({ message: `Validator role revoked for ${language} successfully` });
  } catch (error) {
    logger.error({ err: error }, "Unexpected error in /admin/users/:id/roles/validator");
    res.status(500).json({ error: "Internal server error" });
  }
});
app.delete("/admin/users/:id/roles/ambassador", adminGuard, async (req, res) => {
  try {
    const { id } = req.params;
    const { language } = req.body;
    if (!language) {
      return res.status(400).json({ error: "Language is required" });
    }
    const { data: user, error: fetchError } = await supabaseAdmin.from("profiles").select("id, username, language_roles").eq("id", id).single();
    if (fetchError) {
      if (fetchError.code === "PGRST116") {
        return res.status(404).json({ error: "User not found" });
      }
      return res.status(500).json({ error: "Failed to fetch user" });
    }
    const currentRoles = user.language_roles || {};
    if (!currentRoles[language]?.includes("ambassador")) {
      return res.status(400).json({ error: `User does not have ambassador role for ${language}` });
    }
    const updatedRoles = {
      ...currentRoles,
      [language]: currentRoles[language].filter((role) => role !== "ambassador")
    };
    const { error: updateError } = await supabaseAdmin.from("profiles").update({ language_roles: updatedRoles }).eq("id", id);
    if (updateError) {
      logger.error({ err: updateError }, "Error revoking ambassador role");
      return res.status(500).json({ error: "Failed to revoke ambassador role" });
    }
    await supabaseAdmin.from("admin_actions").insert({
      admin_id: req.admin?.sub,
      action: "revoke_ambassador_role",
      target_user_id: id,
      details: { language },
      created_at: (/* @__PURE__ */ new Date()).toISOString()
    });
    res.json({ message: `Ambassador role revoked for ${language} successfully` });
  } catch (error) {
    logger.error({ err: error }, "Unexpected error in /admin/users/:id/roles/ambassador");
    res.status(500).json({ error: "Internal server error" });
  }
});
app.get("/admin/stats/overview", adminGuard, async (req, res) => {
  try {
    const { data: users, error: usersError } = await supabaseAdmin.from("profiles").select("id, created_at, is_banned", { count: "exact" });
    if (usersError) {
      logger.error({ err: usersError }, "Error fetching user stats");
      return res.status(500).json({ error: "Failed to fetch user statistics" });
    }
    const totalUsers = users?.length || 0;
    const bannedUsers = users?.filter((u) => u.is_banned).length || 0;
    const activeUsers = totalUsers - bannedUsers;
    const thirtyDaysAgo = /* @__PURE__ */ new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const recentUsers = users?.filter((u) => new Date(u.created_at) > thirtyDaysAgo).length || 0;
    res.json({
      totalUsers,
      activeUsers,
      bannedUsers,
      recentUsers,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    });
  } catch (error) {
    logger.error({ err: error }, "Unexpected error in /admin/stats/overview");
    res.status(500).json({ error: "Internal server error" });
  }
});
app.get("/admin/stats/languages", adminGuard, async (req, res) => {
  try {
    const { data: users, error } = await supabaseAdmin.from("profiles").select("language_roles");
    if (error) {
      logger.error({ err: error }, "Error fetching language stats");
      return res.status(500).json({ error: "Failed to fetch language statistics" });
    }
    const languageCounts = {};
    users?.forEach((user) => {
      if (user.language_roles) {
        Object.keys(user.language_roles).forEach((language) => {
          languageCounts[language] = (languageCounts[language] || 0) + 1;
        });
      }
    });
    const languageRankings = Object.entries(languageCounts).map(([language, count]) => ({ language, count })).sort((a, b) => b.count - a.count);
    res.json({
      rankings: languageRankings,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    });
  } catch (error) {
    logger.error({ err: error }, "Unexpected error in /admin/stats/languages");
    res.status(500).json({ error: "Internal server error" });
  }
});
app.get("/admin/stats/countries", adminGuard, async (req, res) => {
  try {
    const { data: users, error } = await supabaseAdmin.from("profiles").select("country").not("country", "is", null);
    if (error) {
      logger.error({ err: error }, "Error fetching country stats");
      return res.status(500).json({ error: "Failed to fetch country statistics" });
    }
    const countryCounts = {};
    users?.forEach((user) => {
      if (user.country) {
        countryCounts[user.country] = (countryCounts[user.country] || 0) + 1;
      }
    });
    const countryRankings = Object.entries(countryCounts).map(([country, count]) => ({ country, count })).sort((a, b) => b.count - a.count);
    res.json({
      rankings: countryRankings,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    });
  } catch (error) {
    logger.error({ err: error }, "Unexpected error in /admin/stats/countries");
    res.status(500).json({ error: "Internal server error" });
  }
});
app.get("/admin/stats/growth", adminGuard, async (req, res) => {
  try {
    const { period = "30d" } = req.query;
    let days = 30;
    if (period === "7d") days = 7;
    else if (period === "90d") days = 90;
    else if (period === "1y") days = 365;
    const { data: users, error } = await supabaseAdmin.from("profiles").select("created_at").gte("created_at", new Date(Date.now() - days * 24 * 60 * 60 * 1e3).toISOString()).order("created_at", { ascending: true });
    if (error) {
      logger.error({ err: error }, "Error fetching growth stats");
      return res.status(500).json({ error: "Failed to fetch growth statistics" });
    }
    const dailyGrowth = {};
    users?.forEach((user) => {
      const date = user.created_at.split("T")[0];
      dailyGrowth[date] = (dailyGrowth[date] || 0) + 1;
    });
    const growthData = Object.entries(dailyGrowth).map(([date, count]) => ({ date, count })).sort((a, b) => a.date.localeCompare(b.date));
    res.json({
      period,
      growth: growthData,
      totalNewUsers: users?.length || 0,
      timestamp: (/* @__PURE__ */ new Date()).toISOString()
    });
  } catch (error) {
    logger.error({ err: error }, "Unexpected error in /admin/stats/growth");
    res.status(500).json({ error: "Internal server error" });
  }
});
app.get("/admin/waitlist", adminGuard, async (req, res) => {
  try {
    const { page = 1, limit = 20, language, search } = req.query;
    const offset = (Number(page) - 1) * Number(limit);
    let query = supabaseAdmin.from("waitlist").select("id, email, phone_number, language, created_at", { count: "exact" }).order("created_at", { ascending: false });
    if (language) query = query.eq("language", language);
    if (search) query = query.or(`email.ilike.%${search}%,phone_number.ilike.%${search}%`);
    const { data, error, count } = await query.range(offset, offset + Number(limit) - 1);
    if (error) {
      logger.error({ err: error }, "Error fetching waitlist");
      return res.status(500).json({ error: "Failed to fetch waitlist" });
    }
    res.json({
      entries: data || [],
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: count || 0,
        pages: Math.ceil((count || 0) / Number(limit))
      }
    });
  } catch (error) {
    logger.error({ err: error }, "Unexpected error in /admin/waitlist");
    res.status(500).json({ error: "Internal server error" });
  }
});
app.get("/admin/waitlist/export", adminGuard, async (_req, res) => {
  try {
    const { data, error } = await supabaseAdmin.from("waitlist").select("email, phone_number, language, created_at").order("created_at", { ascending: false });
    if (error) {
      logger.error({ err: error }, "Error exporting waitlist");
      return res.status(500).json({ error: "Failed to export waitlist" });
    }
    const header = "email,phone_number,language,created_at\n";
    const rows = (data || []).map((r) => [r.email, r.phone_number, r.language, r.created_at].join(","));
    const csv = header + rows.join("\n");
    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", 'attachment; filename="waitlist.csv"');
    res.send(csv);
  } catch (error) {
    logger.error({ err: error }, "Unexpected error in /admin/waitlist/export");
    res.status(500).json({ error: "Internal server error" });
  }
});
app.get("/admin/audit/actions", adminGuard, async (req, res) => {
  try {
    const { page = 1, limit = 50, admin_id, action } = req.query;
    const offset = (Number(page) - 1) * Number(limit);
    let query = supabaseAdmin.from("admin_actions").select(`
        id,
        admin_id,
        action,
        target_user_id,
        details,
        created_at
      `, { count: "exact" });
    if (admin_id) {
      query = query.eq("admin_id", admin_id);
    }
    if (action) {
      query = query.eq("action", action);
    }
    const { data: actions, error, count } = await query.range(offset, offset + Number(limit) - 1).order("created_at", { ascending: false });
    if (error) {
      logger.error({ err: error }, "Error fetching admin actions");
      return res.status(500).json({ error: "Failed to fetch admin actions" });
    }
    res.json({
      actions: actions || [],
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: count || 0,
        pages: Math.ceil((count || 0) / Number(limit))
      }
    });
  } catch (error) {
    logger.error({ err: error }, "Unexpected error in /admin/audit/actions");
    res.status(500).json({ error: "Internal server error" });
  }
});
app.get("/admin/audit/user/:id", adminGuard, async (req, res) => {
  try {
    const { id } = req.params;
    const { page = 1, limit = 50 } = req.query;
    const offset = (Number(page) - 1) * Number(limit);
    const { data: actions, error, count } = await supabaseAdmin.from("admin_actions").select(`
        id,
        admin_id,
        action,
        details,
        created_at
      `, { count: "exact" }).eq("target_user_id", id).range(offset, offset + Number(limit) - 1).order("created_at", { ascending: false });
    if (error) {
      logger.error({ err: error }, "Error fetching user audit trail");
      return res.status(500).json({ error: "Failed to fetch user audit trail" });
    }
    res.json({
      actions: actions || [],
      pagination: {
        page: Number(page),
        limit: Number(limit),
        total: count || 0,
        pages: Math.ceil((count || 0) / Number(limit))
      }
    });
  } catch (error) {
    logger.error({ err: error }, "Unexpected error in /admin/audit/user/:id");
    res.status(500).json({ error: "Internal server error" });
  }
});
app.get("/admin/overview", adminGuard, async (_req, res) => {
  try {
    const { count: usersCount } = await supabaseAdmin.from("profiles").select("id", { count: "exact", head: true });
    res.json({ usersCount: usersCount ?? 0 });
  } catch (e) {
    res.status(500).json({ error: "Failed to load overview" });
  }
});
app.listen(PORT, () => {
  logger.info({ port: PORT }, "Admin API listening");
});
export {
  supabaseAdmin
};
//# sourceMappingURL=index.js.map