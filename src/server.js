import "dotenv/config";
import dns from "node:dns";
dns.setServers(["8.8.8.8", "1.1.1.1"]);
import express from "express";
import cors from "cors";
import helmet from "helmet";
import bcrypt from "bcryptjs";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import { z } from "zod";
import { port } from "./Server_utils/port.js";
import PDFDocument from "pdfkit";
import {
  randomBytes,
  randomInt,
  createHmac,
  timingSafeEqual,
} from "node:crypto";
import nodemailer from "nodemailer";

const required = ["MONGODB_URI", "JWT_SECRET"];
for (const name of required)
  if (!process.env[name]) throw new Error(`${name} is required`);
if (process.env.JWT_SECRET.length < 32)
  throw new Error("JWT_SECRET must contain at least 32 characters");
export const app = express();
app.use(helmet());
app.use(
  cors({ origin: process.env.FRONTEND_ORIGIN || "http://localhost:3000" }),
);
app.use(express.json({ limit: "250kb" }));

const rangeSchema = z
  .object({
    target: z.number().finite(),
    min: z.number().finite(),
    max: z.number().finite(),
    unit: z.string().max(30),
  })
  .refine(
    (v) => v.min <= v.target && v.target <= v.max,
    "target must be between min and max",
  );

const batterySchema = z.object({
  initialLevel: z.number().int().min(0).max(100),
  drainMode: z.enum(["slow", "normal", "fast"]),
  charging: z.boolean(),
});

const impressionEntrySchema = z.object({
  title: z.string().trim().min(1).max(150),
  description: z.string().trim().min(1).max(3000),
});

const normalizeImpressions = (value) =>
  Array.isArray(value) ? value : value ? [value] : [];

const impressionSchema = z.preprocess(
  normalizeImpressions,
  z.array(impressionEntrySchema).min(1).max(20),
);

const scenarioInput = z.object({
  scenarioType: z.enum(["positive", "negative"]),
  scenarioName: z.string().min(1),
  enabled: z.boolean().default(true),
  scanDurationSeconds: z.number().int().min(1).max(3600),
  videoEnabled: z.boolean(),
  videoUrl: z.string().max(2048).optional().default(""),
  cps: rangeSchema,
  doseRate: rangeSchema,
  battery: batterySchema,
  temperature: rangeSchema,
  pressure: rangeSchema,
  location: z.string().max(250).default(""),
  isotopes: z
    .array(
      z.object({
        id: z.string().optional(),
        name: z.string(),
        symbol: z.string().optional(),
        status: z.enum(["stable", "unstable"]),
        energy: z.string().max(50).optional(),
        description: z.string().optional(),
      }),
    )
    .default([]),
  impression: impressionSchema,
});
const User = mongoose.model(
  "RadioUser",
  new mongoose.Schema(
    {
      username: { type: String, required: true, unique: true, trim: true },
      passwordHash: { type: String, required: true, select: false },
      name: String,
      phone: String,
      role: { type: String, enum: ["admin", "user"], default: "user" },
      otpEnabled: { type: Boolean, default: false },
      active: { type: Boolean, default: true },
    },
    { timestamps: true },
  ),
);
const Scenario = mongoose.model(
  "UserScenario",
  new mongoose.Schema(
    {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "RadioUser",
        required: true,
        unique: true,
      },
      scenarioType: String,
      scenarioName: String,
      enabled: Boolean,
      scanDurationSeconds: Number,
      videoEnabled: Boolean,
      videoUrl: String,
      cps: Object,
      doseRate: Object,
      battery: Object,
      temperature: Object,
      pressure: Object,
      location: String,
      isotopes: Array,
      impression: Object,
    },
    { timestamps: true },
  ),
);

const SimulationSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "RadioUser",
      required: true,
      index: true,
    },
    status: {
      type: String,
      enum: ["running", "stopped"],
      default: "running",
    },
    startedAt: Date,
    stoppedAt: Date,
    scenarioSnapshot: Object,
    stableResults: Object,
    environmentSnapshot: {
      type: Object,
      default: null,
    },
    seed: Number,
  },
  { timestamps: true },
);

const Simulation = mongoose.model(
  "ScannerSession",
  SimulationSchema,
  "scannersessions",
);
const Audit = mongoose.model(
  "ScannerAudit",
  new mongoose.Schema({
    actorId: mongoose.Schema.Types.ObjectId,
    action: String,
    subjectId: String,
    createdAt: { type: Date, default: Date.now },
  }),
);
const OtpChallenge = mongoose.model(
  "ScannerOtpChallenge",
  new mongoose.Schema(
    {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "RadioUser",
        required: true,
        index: true,
      },
      challengeHash: { type: String, required: true, unique: true },
      otpHash: { type: String, required: true },
      expiresAt: { type: Date, required: true, index: { expires: 0 } },
      attempts: { type: Number, default: 0 },
      resendAt: { type: Date, required: true },
      consumed: { type: Boolean, default: false },
    },
    { timestamps: true },
  ),
);
const otpHash = (value) =>
  createHmac("sha256", process.env.JWT_SECRET).update(value).digest("hex");
const otpToken = () => randomBytes(32).toString("hex");
const signInToken = (user) =>
  jwt.sign({ role: user.role }, process.env.JWT_SECRET, {
    subject: String(user.id),
    expiresIn: "8h",
  });
const otpTransport = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT),
  secure: Number(process.env.SMTP_PORT),
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASSWORD },
});
async function issueOtp(user, existingChallenge) {
  if (
    !process.env.OTP_RECIPIENT_EMAIL ||
    !process.env.SMTP_HOST ||
    !process.env.SMTP_USER ||
    !process.env.SMTP_PASSWORD ||
    !process.env.SMTP_FROM
  ) {
    throw new Error("Email OTP SMTP configuration is incomplete");
  }
  const code = String(randomInt(100000, 1000000));
  const challengeToken = otpToken();
  const now = Date.now();
  // Do not invalidate a working code until the new email is accepted.
  await otpTransport.sendMail({
    from: process.env.SMTP_FROM,
    to: process.env.OTP_RECIPIENT_EMAIL,
    subject: `Scanner login verification - ${user.username}`,
    text: `Scanner login requested for ${user.username}.\n\nYour verification code is: ${code}\n\nIt expires in 5 minutes. If you did not request this login, ignore this email.`,
  });
  await OtpChallenge.deleteMany({ userId: user._id });
  await OtpChallenge.create({
    userId: user._id,
    challengeHash: otpHash(challengeToken),
    otpHash: otpHash(code),
    expiresAt: new Date(now + 5 * 60 * 1000),
    resendAt: new Date(now + 60 * 1000),
  });
  return challengeToken;
}
const wrap = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);
const publicUser = (user) => ({
  id: String(user.id),
  username: user.username,
  name: user.name,
  phone: user.phone,
  role: user.role,
  otpEnabled: user.otpEnabled,
  active: user.active,
});
const auth = wrap(async (req, res, next) => {
  const token = /^Bearer (.+)$/.exec(req.headers.authorization || "")?.[1];
  if (!token) return res.status(401).json({ message: "Missing bearer token" });
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(payload.sub);
    if (!user || !user.active)
      return res.status(401).json({ message: "Account unavailable" });
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
});
const admin = (req, res, next) =>
  req.user.role === "admin"
    ? next()
    : res.status(403).json({ message: "Admin only" });
const audit = (actor, action, subject) =>
  Audit.create({ actorId: actor.id, action, subjectId: String(subject) });
const latest = async (userId) =>
  Simulation.findOne({ userId, status: "running" }).sort({ startedAt: -1 });

const BATTERY_DRAIN_SECONDS = {
  slow: 600,
  normal: 300,
  fast: 120,
};

function normalizeBattery(value) {
  const raw = value?.initialLevel ?? value?.target ?? 86;
  const initial = Number(raw);

  return {
    initialLevel: Number.isFinite(initial)
      ? Math.max(0, Math.min(100, Math.round(initial)))
      : 86,
    drainMode:
      value?.drainMode in BATTERY_DRAIN_SECONDS ? value.drainMode : "normal",
    charging: value?.charging === true,
  };
}

function calculateBattery(config, elapsedSeconds) {
  const battery = normalizeBattery(config);

  if (battery.charging) {
    return battery.initialLevel;
  }

  const interval = BATTERY_DRAIN_SECONDS[battery.drainMode];

  const consumed = Math.floor(Math.max(0, elapsedSeconds) / interval);

  return Math.max(0, battery.initialLevel - consumed);
}

function batteryStatus(level, charging = false) {
  if (level <= 0) return "depleted";
  if (charging) return "charging";
  if (level <= 10) return "critical";
  if (level <= 20) return "low";
  return "normal";
}

const stableFrom = (scenario) => ({
  cps: scenario.cps.target,
  doseRate: scenario.doseRate.target,
  battery: normalizeBattery(scenario.battery).initialLevel,
  temperature: scenario.temperature.target,
  pressure: scenario.pressure.target,
});

const weatherCache = new Map();

function environmentFromWeather(result) {
  return {
    temperature: result.temperature,
    pressure: result.pressure,
    humidity: result.humidity,
    windSpeed: result.windSpeed,
    source: result.source,
    location: result.location,
    observedAt: result.observedAt,
    timezone: result.timezone,
  };
}

async function saveEnvironmentSnapshot(userId, result) {
  if (!result) {
    console.warn("[Weather] No weather result provided");
    return null;
  }

  const snapshot = environmentFromWeather(result);

  console.log("[Weather] Saving environment snapshot:", {
    userId: String(userId),
    temperature: snapshot.temperature,
    pressure: snapshot.pressure,
    collection: Simulation.collection.name,
  });

  const simulation = await Simulation.findOneAndUpdate(
    {
      userId: new mongoose.Types.ObjectId(String(userId)),
      status: "running",
    },
    {
      $set: {
        environmentSnapshot: snapshot,
      },
    },
    {
      new: true,
      sort: { startedAt: -1 },
      runValidators: true,
    },
  );

  if (!simulation) {
    console.warn("[Weather] No running simulation found:", {
      userId: String(userId),
    });

    return null;
  }

  console.log("[Weather] Environment snapshot persisted:", {
    simulationId: String(simulation._id),
    temperature: simulation.environmentSnapshot?.temperature,
    pressure: simulation.environmentSnapshot?.pressure,
  });

  return simulation;
}

function liveSample(sim, at = Date.now()) {
  const elapsed = Math.max(
    0,
    Math.floor((at - new Date(sim.startedAt).getTime()) / 1000),
  );

  const scenario = sim.scenarioSnapshot;

  const values = {};

  const fields = ["cps", "doseRate", "temperature", "pressure"];

  for (const [index, key] of fields.entries()) {
    const range = scenario[key];

    const amplitude = Math.min(
      range.target - range.min,
      range.max - range.target,
      (range.max - range.min) * 0.4,
    );

    const wave =
      Math.sin((elapsed + sim.seed + index * 17) * (0.39 + index * 0.037)) *
        0.7 +
      Math.sin((elapsed + sim.seed * 2 + index * 31) * 0.13) * 0.3;

    const digits = key === "cps" ? 0 : key === "doseRate" ? 3 : 1;

    values[key] = Number(
      Math.min(
        range.max,
        Math.max(range.min, range.target + amplitude * wave),
      ).toFixed(digits),
    );
  }

  const battery = normalizeBattery(scenario.battery);

  values.battery = calculateBattery(battery, elapsed);

  return {
    timestamp: new Date(at).toISOString(),
    elapsedSeconds: elapsed,
    ...values,
    batteryStatus: batteryStatus(values.battery, battery.charging),
    charging: battery.charging,
  };
}

async function stopIfBatteryDepleted(sim, reading) {
  if (reading.battery > 0) {
    return false;
  }

  await Simulation.updateOne(
    {
      _id: sim._id,
      status: "running",
    },
    {
      $set: {
        status: "stopped",
        stoppedAt: new Date(),
        "stableResults.battery": 0,
      },
    },
  );

  return true;
}

app.get("/api/health", (_req, res) =>
  res.json({
    ok: true,
    db: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
  }),
);
app.post(
  "/api/auth/login",
  wrap(async (req, res) => {
    const input = z
      .object({ username: z.string().min(1), password: z.string().min(1) })
      .parse(req.body);
    const user = await User.findOne({ username: input.username }).select(
      "+passwordHash",
    );
    if (
      !user ||
      !user.active ||
      !(await bcrypt.compare(input.password, user.passwordHash))
    )
      return res.status(401).json({ message: "Invalid credentials" });
    if (user.role === "user" && user.otpEnabled) {
      const recent = await OtpChallenge.findOne({
        userId: user._id,
        expiresAt: { $gt: new Date() },
      });
      if (recent && recent.resendAt > new Date())
        return res.status(429).json({
          code: "OTP_COOLDOWN",
          message: "Please wait before requesting another login code.",
        });
      const challengeToken = await issueOtp(user);
      return res.json({ requiresOtp: true, challengeToken });
    }
    const token = signInToken(user);
    res.json({ token, user: publicUser(user) });
  }),
);
app.post(
  "/api/auth/resend-otp",
  wrap(async (req, res) => {
    const { challengeToken } = z
      .object({ challengeToken: z.string().min(32) })
      .parse(req.body);
    const record = await OtpChallenge.findOne({
      challengeHash: otpHash(challengeToken),
      consumed: false,
      expiresAt: { $gt: new Date() },
    });
    if (!record)
      return res
        .status(401)
        .json({ message: "OTP challenge expired. Sign in again." });
    if (record.resendAt > new Date())
      return res
        .status(429)
        .json({ message: "Please wait 60 seconds before resending." });
    if (record.attempts >= 5)
      return res
        .status(429)
        .json({ message: "Too many attempts. Sign in again." });
    const user = await User.findById(record.userId);
    if (!user || !user.active || user.role !== "user" || !user.otpEnabled)
      return res.status(403).json({ message: "OTP unavailable" });
    const nextChallengeToken = await issueOtp(user, record);
    res.json({ requiresOtp: true, challengeToken: nextChallengeToken });
  }),
);
app.post(
  "/api/auth/verify-otp",
  wrap(async (req, res) => {
    const { challengeToken, otp } = z
      .object({
        challengeToken: z.string().min(32),
        otp: z.string().regex(/^\d{6}$/),
      })
      .parse(req.body);
    // Atomically consume an attempt before checking the code.
    const record = await OtpChallenge.findOneAndUpdate(
      {
        challengeHash: otpHash(challengeToken),
        consumed: false,
        expiresAt: { $gt: new Date() },
        attempts: { $lt: 5 },
      },
      { $inc: { attempts: 1 } },
      { new: true },
    );
    if (!record)
      return res
        .status(401)
        .json({ message: "Invalid, expired, or exhausted OTP challenge" });
    const expected = Buffer.from(record.otpHash, "hex");
    const received = Buffer.from(otpHash(otp), "hex");
    if (!timingSafeEqual(expected, received))
      return res.status(401).json({ message: "Invalid OTP" });
    const consumed = await OtpChallenge.findOneAndUpdate(
      { _id: record._id, consumed: false },
      { $set: { consumed: true } },
      { new: true },
    );
    if (!consumed) return res.status(401).json({ message: "OTP already used" });
    const user = await User.findById(record.userId);
    if (!user || !user.active || user.role !== "user" || !user.otpEnabled)
      return res.status(403).json({ message: "Account unavailable" });
    await OtpChallenge.deleteMany({ userId: user._id });
    res.json({ token: signInToken(user), user: publicUser(user) });
  }),
);
app.post(
  "/api/auth/logout",
  auth,
  wrap(async (req, res) => {
    await Simulation.updateMany(
      { userId: req.user.id, status: "running" },
      { $set: { status: "stopped", stoppedAt: new Date() } },
    );
    res.json({ success: true });
  }),
);
app.get("/api/auth/me", auth, (req, res) =>
  res.json({ user: publicUser(req.user) }),
);
app.get(
  "/api/admin/users",
  auth,
  admin,
  wrap(async (req, res) =>
    res.json((await User.find().sort({ createdAt: -1 })).map(publicUser)),
  ),
);
app.post(
  "/api/admin/users",
  auth,
  admin,
  wrap(async (req, res) => {
    const input = z
      .object({
        username: z.string().min(1),
        password: z.string().min(8),
        name: z.string().default(""),
        phone: z.string().default(""),
        role: z.enum(["user", "admin"]).default("user"),
        active: z.boolean().default(true),
        otpEnabled: z.boolean().default(false),
      })
      .parse(req.body);
    const { password, ...fields } = input;
    const user = await User.create({
      ...fields,
      passwordHash: await bcrypt.hash(password, 12),
    });
    await audit(req.user, "CREATE_USER", user.id);
    res.status(201).json(publicUser(user));
  }),
);
app.patch(
  "/api/admin/users/:id",
  auth,
  admin,
  wrap(async (req, res) => {
    const input = z
      .object({
        name: z.string().optional(),
        phone: z.string().optional(),
        active: z.boolean().optional(),
        otpEnabled: z.boolean().optional(),
        role: z.enum(["admin", "user"]).optional(),
        password: z.string().min(8).optional(),
      })
      .parse(req.body);
    const { password, ...fields } = input;
    if (password) fields.passwordHash = await bcrypt.hash(password, 12);
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: fields },
      { new: true },
    );
    if (!user) return res.status(404).json({ message: "User not found" });
    await audit(req.user, "UPDATE_USER", user.id);
    res.json(publicUser(user));
  }),
);
app.delete(
  "/api/admin/users/:id",
  auth,
  admin,
  wrap(async (req, res) => {
    if (req.user.id === req.params.id)
      return res.status(400).json({ message: "Cannot delete self" });
    await User.findByIdAndDelete(req.params.id);
    await Scenario.deleteOne({ userId: req.params.id });
    await Simulation.updateMany(
      { userId: req.params.id, status: "running" },
      { $set: { status: "stopped", stoppedAt: new Date() } },
    );
    await audit(req.user, "DELETE_USER", req.params.id);
    res.status(204).end();
  }),
);
app.get(
  "/api/admin/scenarios",
  auth,
  admin,
  wrap(async (req, res) =>
    res.json(
      (await Scenario.find()).map((s) => {
        const scenario = s.toObject();
        return {
          ...scenario,
          impression: normalizeImpressions(scenario.impression),
          id: String(s.id),
          userId: String(s.userId),
        };
      }),
    ),
  ),
);
app.put(
  "/api/admin/scenarios/:userId",
  auth,
  admin,
  wrap(async (req, res) => {
    const input = scenarioInput.parse(req.body);
    if (!(await User.exists({ _id: req.params.userId, role: "user" })))
      return res.status(404).json({ message: "User not found" });
    const item = await Scenario.findOneAndUpdate(
      { userId: req.params.userId },
      { $set: input },
      { upsert: true, new: true, runValidators: true },
    );
    await audit(req.user, "ASSIGN_SCENARIO", req.params.userId);
    res.json({
      ...item.toObject(),
      id: String(item.id),
      userId: String(item.userId),
    });
  }),
);
app.get(
  "/api/user/scenario",
  auth,
  wrap(async (req, res) => {
    const s = await Scenario.findOne({ userId: req.user.id, enabled: true });
    if (!s)
      return res.status(404).json({ message: "No enabled scenario assigned" });
    const scenario = s.toObject();
    res.json({
      success: true,
      data: {
        ...scenario,
        impression: normalizeImpressions(scenario.impression),
        id: String(s.id),
        userId: String(s.userId),
      },
    });
  }),
);
app.post(
  "/api/simulations/start",
  auth,
  wrap(async (req, res) => {
    if (req.user.role !== "user") {
      return res.status(403).json({ message: "User only" });
    }

    let sim = await latest(req.user.id);

    if (!sim) {
      const s = await Scenario.findOne({
        userId: req.user.id,
        enabled: true,
      });

      if (!s) {
        return res.status(404).json({ message: "No scenario assigned" });
      }

      const snapshot = s.toObject();
      const cachedWeather = weatherCache.get(
        String(snapshot.location ?? "").trim(),
      );

      const validCachedWeather =
        cachedWeather && cachedWeather.expiresAt > Date.now()
          ? cachedWeather.data
          : null;
      sim = await Simulation.create({
        userId: req.user.id,
        status: "running",
        startedAt: new Date(),
        scenarioSnapshot: snapshot,
        stableResults: stableFrom(snapshot),
        environmentSnapshot: validCachedWeather
          ? environmentFromWeather(validCachedWeather)
          : null,
        seed: Math.floor(Math.random() * 100000),
      });
    } else if (!sim.environmentSnapshot) {
      const location = String(sim.scenarioSnapshot?.location ?? "").trim();

      const cachedWeather = weatherCache.get(location);

      if (cachedWeather && cachedWeather.expiresAt > Date.now()) {
        sim.environmentSnapshot = environmentFromWeather(cachedWeather.data);
        await sim.save();
      }
    }

    res.json({
      id: String(sim.id),
      status: sim.status,
      startedAt: sim.startedAt,
      stableResults: sim.stableResults,
    });
  }),
);
app.get(
  "/api/simulations/active",
  auth,
  wrap(async (req, res) => {
    const sim = await latest(req.user.id);

    if (!sim) {
      return res.json({ status: "idle" });
    }

    const scenario = sim.scenarioSnapshot;
    const values = liveSample(sim);
    const depleted = await stopIfBatteryDepleted(sim, values);
    if (sim.environmentSnapshot) {
      values.temperature =
        sim.environmentSnapshot.temperature ?? values.temperature;

      values.pressure = sim.environmentSnapshot.pressure ?? values.pressure;
    }
    return res.json({
      id: String(sim.id),
      status: depleted ? "stopped" : sim.status,
      startedAt: sim.startedAt,
      scenarioType: scenario?.scenarioType,
      scenarioName: scenario?.scenarioName,
      videoEnabled: scenario?.videoEnabled ?? false,
      scanDurationSeconds: scenario?.scanDurationSeconds ?? 10,
      values,
    });
  }),
);

app.get(
  "/api/simulations/:id/readings",
  auth,
  wrap(async (req, res) => {
    const sim = await Simulation.findOne({
      _id: req.params.id,
      userId: req.user.id,
      status: "running",
    });
    if (!sim) return res.status(404).json({ message: "No active simulation" });
    res.json({
      id: String(sim.id),
      status: sim.status,
      reading: liveSample(sim),
    });
  }),
);
app.get(
  "/api/dashboard",
  auth,
  wrap(async (req, res) => {
    const sim = await latest(req.user.id);

    if (!sim) {
      return res.status(404).json({
        message: "Start simulation first",
      });
    }

    const s = sim.scenarioSnapshot || {};
    const environment = sim.environmentSnapshot || {};
    res.json({
      simulationId: String(sim.id),
      scenarioType: s.scenarioType,
      scenarioName: s.scenarioName,

      results: {
        ...sim.stableResults,

        // Use actual weather readings when available.
        temperature: environment.temperature ?? sim.stableResults.temperature,

        pressure: environment.pressure ?? sim.stableResults.pressure,
      },

      units: {
        cps: s.cps?.unit ?? "CPS",
        doseRate: s.doseRate?.unit ?? "µSv/h",
        battery: s.battery?.unit ?? "%",
        temperature:
          environment.temperature != null
            ? "°C"
            : (s.temperature?.unit ?? "°C"),
        pressure:
          environment.pressure != null ? "hPa" : (s.pressure?.unit ?? "hPa"),
      },

      isotopes: s.isotopes || [],
      impression: normalizeImpressions(s.impression),
      location: s.location,
      startedAt: sim.startedAt,
      environmentSnapshot: sim.environmentSnapshot ?? null,
    });
  }),
);

app.get(
  "/api/admin/audit",
  auth,
  admin,
  wrap(async (req, res) =>
    res.json(await Audit.find().sort({ createdAt: -1 }).limit(200)),
  ),
);

/**
 * GET /api/admin/reports
 *
 * Lists simulations, newest first.
 * Optional query: userId
 */
app.get(
  "/api/admin/reports",
  auth,
  admin,
  wrap(async (req, res) => {
    const userId = req.query.userId;

    const filter = {};

    if (typeof userId === "string" && userId) {
      if (!mongoose.isValidObjectId(userId)) {
        return res.status(400).json({
          message: "Invalid user ID",
        });
      }
      filter.userId = userId;
    }

    const simulations = await Simulation.find(filter)
      .sort({ startedAt: -1 })
      .limit(200)
      .lean();

    const reports = simulations.map((sim) => {
      const snapshot = sim.scenarioSnapshot || {};

      return {
        id: String(sim._id),
        userId: String(sim.userId),
        status: sim.status,
        startedAt: sim.startedAt,
        stoppedAt: sim.stoppedAt ?? null,
        scenarioType: snapshot.scenarioType,
        scenarioName: snapshot.scenarioName,
        location: snapshot.location,
        isotopes: snapshot.isotopes || [],
        impression: normalizeImpressions(snapshot.impression),
        stableResults: sim.stableResults || {},
      };
    });

    return res.json({ reports });
  }),
);

app.get(
  "/api/admin/reports/:id/pdf",
  auth,
  admin,
  wrap(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) {
      return res.status(400).json({
        message: "Invalid simulation ID",
      });
    }

    const sim = await Simulation.findById(req.params.id).lean();

    if (!sim) {
      return res.status(404).json({
        message: "Simulation not found",
      });
    }

    const user = await User.findById(sim.userId).select("name username").lean();

    const scenario = sim.scenarioSnapshot || {};
    const results = sim.stableResults || {};

    const filename = `radioanalysis-${String(sim._id)}.pdf`;
    const download = req.query.download === "1";

    res.setHeader("Content-Type", "application/pdf");
    res.setHeader(
      "Content-Disposition",
      `${download ? "attachment" : "inline"}; filename="${filename}"`,
    );
    res.setHeader("Cache-Control", "no-store");

    const doc = new PDFDocument({
      size: "A4",
      margin: 48,
      info: {
        Title: "RIID Report",
        Author: "RIID_Radiation_Area_Monitor_v03.6.9",
      },
    });

    doc.on("error", (error) => {
      console.error("PDF generation failed:", error);
      res.destroy(error);
    });

    doc.pipe(res);

    const writeField = (label, value) => {
      doc.fontSize(10).fillColor("#64748b").text(label);

      doc
        .fontSize(12)
        .fillColor("#0f172a")
        .text(String(value ?? "—"));

      doc.moveDown(0.65);
    };

    doc
      .font("Helvetica-Bold")
      .fontSize(22)
      .fillColor("#0f172a")
      .text("RADIOANALYSIS");

    doc.font("Helvetica").fontSize(11).fillColor("#64748b").text("Report");

    doc.moveDown();

    doc.moveTo(48, doc.y).lineTo(547, doc.y).strokeColor("#cbd5e1").stroke();

    doc.moveDown();

    writeField("User", user?.name || user?.username || String(sim.userId));
    writeField("Scenario", scenario.scenarioName || scenario.scenarioType);
    writeField(
      "Started At",
      sim.startedAt ? new Date(sim.startedAt).toISOString() : "—",
    );
    writeField("Location", scenario.location);

    doc.moveDown();

    doc
      .font("Helvetica-Bold")
      .fontSize(15)
      .fillColor("#0f172a")
      .text("Recorded Results");

    doc.moveDown(0.5);

    const units = {
      cps: scenario.cps?.unit ?? "CPS",
      doseRate: scenario.doseRate?.unit ?? "µSv/h",
    };

    for (const field of ["cps", "doseRate"]) {
      const value = results[field];

      // Supports numeric stable results or objects
      // containing a target/value reading.
      const reading =
        typeof value === "number" ? value : (value?.value ?? value?.target);

      writeField(
        field === "cps" ? "Count Rate (CPS)" : "Dose Rate",
        reading == null ? "—" : `${reading} ${units[field]}`,
      );
    }

    doc.moveDown();

    doc.font("Helvetica-Bold").fontSize(15).text("Radioisotopes");

    doc.moveDown(0.5);

    if (scenario.isotopes?.length) {
      for (const isotope of scenario.isotopes) {
        doc
          .font("Helvetica")
          .fontSize(11)
          .text(`${isotope.name} (${isotope.symbol}) - ${isotope.status}`);
      }
    } else {
      doc.font("Helvetica").text("No isotopes recorded.");
    }

    doc.moveDown();

    doc
      .font("Helvetica-Bold")
      .fontSize(15)
      .fillColor("#0f172a")
      .text("Impression Summary");

    doc.moveDown(0.5);

    const impressions = Array.isArray(scenario.impression)
      ? scenario.impression
      : scenario.impression
        ? [scenario.impression]
        : [];

    if (impressions.length === 0) {
      doc.font("Helvetica").fontSize(11).text("No impression available.");
    } else {
      impressions.forEach((item, index) => {
        doc
          .font("Helvetica-Bold")
          .fontSize(11)
          .fillColor("#0f172a")
          .text(`${index + 1}. ${item.title || "Untitled"}`);

        doc.moveDown(0.3);

        doc
          .font("Helvetica")
          .fontSize(10)
          .fillColor("#334155")
          .text(item.description || "");

        doc.moveDown(0.7);
      });
    }

    doc.end();
  }),
);

app.get(
  "/api/weather/current",
  auth,
  wrap(async (req, res) => {
    const scenario = await Scenario.findOne({
      userId: req.user.id,
      enabled: true,
    });

    if (!scenario) {
      return res.status(404).json({
        message: "No assigned scenario found",
      });
    }

    const location = String(scenario.location ?? "").trim();

    if (!location || location === "[object Object]") {
      return res.status(400).json({
        message: "A valid location is required",
      });
    }

    // Check cached weather first.
    const cached = weatherCache.get(location);

    if (cached && cached.expiresAt > Date.now()) {
      await saveEnvironmentSnapshot(req.user.id, cached.data);
      return res.json(cached.data);
    }

    // Resolve configured location.
    const geoUrl = new URL("https://geocoding-api.open-meteo.com/v1/search");

    geoUrl.searchParams.set("name", location);
    geoUrl.searchParams.set("count", "1");

    const geoResponse = await fetch(geoUrl, {
      signal: AbortSignal.timeout(8000),
    });

    if (!geoResponse.ok) {
      throw new Error("Geocoding service unavailable");
    }

    const geoData = await geoResponse.json();
    const place = geoData.results?.[0];

    if (!place) {
      return res.status(404).json({
        message: "Configured location not found",
      });
    }

    // Fetch current weather.
    const weatherUrl = new URL("https://api.open-meteo.com/v1/forecast");

    weatherUrl.searchParams.set("latitude", String(place.latitude));
    weatherUrl.searchParams.set("longitude", String(place.longitude));

    weatherUrl.searchParams.set(
      "current",
      [
        "temperature_2m",
        "surface_pressure",
        "relative_humidity_2m",
        "wind_speed_10m",
        "weather_code",
      ].join(","),
    );

    weatherUrl.searchParams.set("timezone", "auto");

    const weatherResponse = await fetch(weatherUrl, {
      signal: AbortSignal.timeout(8000),
    });

    if (!weatherResponse.ok) {
      throw new Error("Weather service unavailable");
    }

    const weather = await weatherResponse.json();

    if (!weather.current) {
      throw new Error("Current weather unavailable");
    }

    const result = {
      success: true,
      source: "Open-Meteo",
      location,
      resolvedLocation: [place.name, place.admin1, place.country]
        .filter(Boolean)
        .join(", "),
      temperature: weather.current.temperature_2m,
      pressure: weather.current.surface_pressure,
      humidity: weather.current.relative_humidity_2m,
      windSpeed: weather.current.wind_speed_10m,
      weatherCode: weather.current.weather_code,
      observedAt: weather.current.time,
      timezone: weather.timezone,
    };

    // Cache weather for five minutes.
    weatherCache.set(location, {
      data: result,
      expiresAt: Date.now() + 5 * 60 * 1000,
    });

    // Save weather against the latest running simulation.
    await saveEnvironmentSnapshot(req.user.id, result);

    return res.json(result);
  }),
);

// Keep the error handler AFTER all API routes.
app.use((err, req, res, next) => {
  if (res.headersSent) {
    return next(err);
  }

  if (err instanceof z.ZodError) {
    return res.status(400).json({
      message: "Invalid input",
      issues: err.issues,
    });
  }

  if (err?.code === 11000) {
    return res.status(409).json({
      message: "Already exists",
    });
  }

  console.error("API error:", err);

  res.status(500).json({
    message: "Internal server error",
  });
});

// Connect to MongoDB before starting the server.
// Connect to MongoDB and initialize the administrator.
let databasePromise;

export async function connectDatabase() {
  if (mongoose.connection.readyState === 1) {
    return;
  }

  if (!databasePromise) {
    databasePromise = (async () => {
      await mongoose.connect(process.env.MONGODB_URI);

      console.log("MongoDB connected");

      if (
        process.env.BOOTSTRAP_ADMIN_USERNAME &&
        process.env.BOOTSTRAP_ADMIN_PASSWORD
      ) {
        if (process.env.BOOTSTRAP_ADMIN_PASSWORD.length < 8) {
          throw new Error("Bootstrap admin password is too short");
        }

        if (
          !(await User.exists({
            username: process.env.BOOTSTRAP_ADMIN_USERNAME,
          }))
        ) {
          await User.create({
            username: process.env.BOOTSTRAP_ADMIN_USERNAME,
            passwordHash: await bcrypt.hash(
              process.env.BOOTSTRAP_ADMIN_PASSWORD,
              12,
            ),
            name: "Administrator",
            role: "admin",
          });

          console.log("Bootstrap admin account created");
        }
      }
    })().catch((error) => {
      databasePromise = null;
      throw error;
    });
  }

  await databasePromise;
}

// Traditional server startup for local development and Render.
export async function startServer() {
  await connectDatabase();

  app.listen(port, () => {
    console.log(`Radioanalysis_Scanner_api listening on ${port}`);
  });
}

// Do not start a persistent listener on Vercel.
if (process.env.VERCEL !== "1") {
  startServer().catch((error) => {
    console.error("Server startup failed:", error);
    process.exit(1);
  });
}
