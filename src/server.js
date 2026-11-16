import "dotenv/config";
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
import { Resend } from "resend";

import { renderImpressionSummary } from "./Server_utils/impressionPdfRenderer.js";

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

// Ensure MongoDB is connected before processing API requests.
app.use(async (req, res, next) => {
  if (req.path === "/api/health") {
    return next();
  }

  try {
    await connectDatabase();
    next();
  } catch (error) {
    console.error("MongoDB connection failed:", error);

    if (!res.headersSent) {
      return res.status(503).json({
        message: "Database unavailable. Please try again later.",
      });
    }
  }
});

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

const EnvironmentSnapshotSchema = new mongoose.Schema(
  {
    temperature: Number,
    pressure: Number,
    humidity: Number,
    windSpeed: Number,
    source: String,
    location: String,
    observedAt: String,
    timezone: String,
  },
  { _id: false },
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
      type: EnvironmentSnapshotSchema,
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

async function issueOtp(user, existingChallenge) {
  if (
    !process.env.RESEND_API_KEY ||
    !process.env.RESEND_FROM ||
    !process.env.OTP_RECIPIENT_EMAIL
  ) {
    throw new Error("Resend email configuration is incomplete");
  }

  const resend = new Resend(process.env.RESEND_API_KEY);
  const code = String(randomInt(100000, 1000000));
  const challengeToken = otpToken();
  const now = new Date();

  const challenge = {
    userId: user._id,
    challengeHash: otpHash(challengeToken),
    otpHash: otpHash(code),
    expiresAt: new Date(now.getTime() + 5 * 60 * 1000),
    resendAt: new Date(now.getTime() + 60 * 1000),
    attempts: 0,
    consumed: false,
  };

  try {
    const { error } = await resend.emails.send({
      from: process.env.RESEND_FROM,
      to: process.env.OTP_RECIPIENT_EMAIL,
      subject: `Scanner login verification - ${user.username}`,
      text: `Scanner login requested for ${user.username}.

Your verification code is: ${code}

It expires in 5 minutes. If you did not request this login, ignore this email.`,
    });

    if (error) {
      console.error("Resend email failed:", error);
      throw new Error("Unable to send OTP email");
    }
  } catch (error) {
    console.error("OTP email delivery failed:", error);
    throw new Error("Unable to send OTP email");
  }

  if (existingChallenge) {
    await OtpChallenge.findByIdAndUpdate(existingChallenge._id, {
      $set: challenge,
    });
  } else {
    await OtpChallenge.create(challenge);
  }

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

  let payload;
  try {
    payload = jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }

  const user = await User.findById(payload.sub);
  if (!user || !user.active)
    return res.status(401).json({ message: "Account unavailable" });
  req.user = user;
  next();
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
const geocodingCache = new Map();
const weatherRequestsInFlight = new Map();

const WEATHER_CACHE_TTL = 10 * 60 * 1000; // 10 minutes
const GEOCODING_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours
const WEATHER_STALE_MAX_AGE = 24 * 60 * 60 * 1000; // 24 hours
const WEATHER_API_TIMEOUT = 10000;

function environmentFromWeather(result) {
  return {
    temperature: Number(result.temperature),
    pressure: Number(result.pressure),
    humidity: Number(result.humidity),
    windSpeed: Number(result.windSpeed),
    source: result.source ?? "OpenWeather",
    location: result.location ?? "",
    observedAt: result.observedAt ?? null,
    timezone: result.timezone ?? null,
  };
}

async function fetchExternalJson(url) {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(WEATHER_API_TIMEOUT),
    headers: {
      Accept: "application/json",
    },
  });

  if (!response.ok) {
    const error = new Error(
      `OpenWeather API returned ${response.status}: ${response.statusText}`,
    );

    error.status = response.status;

    if (response.status === 429) {
      const retryAfter = response.headers.get("retry-after");
      const seconds = Number(retryAfter);

      error.retryAfterMs =
        Number.isFinite(seconds) && seconds > 0
          ? seconds * 1000
          : 10 * 60 * 1000;
    }

    throw error;
  }

  return response.json();
}

function formatTimezone(offsetSeconds) {
  const offsetMinutes = Math.round(Number(offsetSeconds || 0) / 60);
  const sign = offsetMinutes >= 0 ? "+" : "-";
  const absoluteMinutes = Math.abs(offsetMinutes);
  const hours = String(Math.floor(absoluteMinutes / 60)).padStart(2, "0");
  const minutes = String(absoluteMinutes % 60).padStart(2, "0");

  return `UTC${sign}${hours}:${minutes}`;
}

async function fetchWeatherForLocation(location) {
  const apiKey = process.env.OPENWEATHER_API_KEY;

  if (!apiKey) {
    throw new Error("OPENWEATHER_API_KEY is not configured");
  }

  const normalizedLocation = String(location).trim();
  const now = Date.now();

  // Return cached weather for up to 10 minutes.
  const cachedWeather = weatherCache.get(normalizedLocation);

  if (cachedWeather && cachedWeather.expiresAt > now) {
    console.log("[Weather] Using fresh OpenWeather cache");

    return {
      ...cachedWeather.data,
      isStale: false,
    };
  }

  // Avoid duplicate requests for the same location.
  const existingRequest = weatherRequestsInFlight.get(normalizedLocation);

  if (existingRequest) {
    console.log("[Weather] Reusing in-flight OpenWeather request");
    return existingRequest;
  }

  const requestPromise = (async () => {
    try {
      let place;

      // Reuse cached coordinates for 24 hours.
      const cachedGeo = geocodingCache.get(normalizedLocation);

      if (cachedGeo && cachedGeo.expiresAt > Date.now()) {
        console.log("[Weather] Using cached OpenWeather geocoding");
        place = cachedGeo.data;
      } else {
        const geoUrl = new URL("https://api.openweathermap.org/geo/1.0/direct");

        geoUrl.searchParams.set("q", normalizedLocation);
        geoUrl.searchParams.set("limit", "1");
        geoUrl.searchParams.set("appid", apiKey);

        console.log("[Weather] Requesting OpenWeather geocoding");

        const geoData = await fetchExternalJson(geoUrl);

        place = geoData?.[0];

        if (
          !place ||
          !Number.isFinite(Number(place.lat)) ||
          !Number.isFinite(Number(place.lon))
        ) {
          const error = new Error("Configured location not found");
          error.status = 404;
          throw error;
        }

        geocodingCache.set(normalizedLocation, {
          data: place,
          expiresAt: Date.now() + GEOCODING_CACHE_TTL,
        });
      }

      // Fetch current weather using the resolved coordinates.
      const weatherUrl = new URL(
        "https://api.openweathermap.org/data/2.5/weather",
      );

      weatherUrl.searchParams.set("lat", String(place.lat));
      weatherUrl.searchParams.set("lon", String(place.lon));
      weatherUrl.searchParams.set("units", "metric");
      weatherUrl.searchParams.set("appid", apiKey);

      console.log("[Weather] Requesting OpenWeather current conditions");

      const weather = await fetchExternalJson(weatherUrl);

      if (
        !weather?.main ||
        !Number.isFinite(Number(weather.main.temp)) ||
        !Number.isFinite(Number(weather.main.pressure)) ||
        !Number.isFinite(Number(weather.main.humidity)) ||
        !Number.isFinite(Number(weather.wind?.speed))
      ) {
        throw new Error("OpenWeather returned incomplete weather data");
      }

      const resolvedLocation = [place.name, place.state, place.country]
        .filter(Boolean)
        .join(", ");

      const result = {
        success: true,
        source: "OpenWeather",
        location: normalizedLocation,
        resolvedLocation,
        temperature: Number(weather.main.temp),
        pressure: Number(weather.main.pressure),
        humidity: Number(weather.main.humidity),
        windSpeed: Number(weather.wind.speed),
        weatherCode: weather.weather?.[0]?.id ?? null,
        weatherDescription: weather.weather?.[0]?.description ?? "",
        observedAt: weather.dt
          ? new Date(weather.dt * 1000).toISOString()
          : new Date().toISOString(),
        timezone: formatTimezone(weather.timezone),
      };

      weatherCache.set(normalizedLocation, {
        data: result,
        expiresAt: Date.now() + WEATHER_CACHE_TTL,
        staleUntil: Date.now() + WEATHER_STALE_MAX_AGE,
      });

      console.log("[Weather] Fresh OpenWeather data cached");

      return {
        ...result,
        isStale: false,
      };
    } catch (error) {
      console.error("[Weather] OpenWeather refresh failed:", {
        location: normalizedLocation,
        message: error instanceof Error ? error.message : String(error),
        status: error?.status,
        retryAfterMs: error?.retryAfterMs,
      });

      // Use the last successful cached reading if it is still recent.
      const previousWeather = weatherCache.get(normalizedLocation);

      if (previousWeather && previousWeather.staleUntil > Date.now()) {
        console.warn("[Weather] Returning stale OpenWeather cache");

        return {
          ...previousWeather.data,
          isStale: true,
          staleReason:
            error instanceof Error
              ? error.message
              : "OpenWeather temporarily unavailable",
        };
      }

      throw error;
    }
  })();

  weatherRequestsInFlight.set(normalizedLocation, requestPromise);

  try {
    return await requestPromise;
  } finally {
    weatherRequestsInFlight.delete(normalizedLocation);
  }
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
  "/api/locations/search",
  auth,
  admin,
  wrap(async (req, res) => {
    const query = String(req.query.q ?? "").trim();

    if (query.length < 3) {
      return res.json({ locations: [] });
    }

    const apiKey = process.env.OPENWEATHER_API_KEY;

    if (!apiKey) {
      return res.status(500).json({
        message: "Location search is not configured",
      });
    }

    const url = new URL("https://api.openweathermap.org/geo/1.0/direct");

    url.searchParams.set("q", query);
    url.searchParams.set("limit", "5");
    url.searchParams.set("appid", apiKey);

    const results = await fetchExternalJson(url);

    return res.json({
      locations: (Array.isArray(results) ? results : []).map((place) => ({
        name: place.name,
        state: place.state ?? "",
        country: place.country ?? "",
        lat: place.lat,
        lon: place.lon,
      })),
    });
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
      environmentSnapshot: sim.environmentSnapshot ?? null,
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

        // Persisted environmental readings
        environmentSnapshot: sim.environmentSnapshot ?? null,
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

    renderImpressionSummary(doc, impressions);

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

    let result;

    try {
      result = await fetchWeatherForLocation(location);
    } catch (error) {
      console.error("[Weather] OpenWeather unavailable:", {
        location,
        message: error instanceof Error ? error.message : String(error),
        status: error?.status,
        retryAfterMs: error?.retryAfterMs,
      });

      // Use the latest persisted snapshot if OpenWeather fails.
      const previousSimulation = await Simulation.findOne({
        userId: req.user.id,
        status: "running",
        environmentSnapshot: { $ne: null },
      })
        .sort({ startedAt: -1 })
        .select("environmentSnapshot");

      const previousSnapshot = previousSimulation?.environmentSnapshot;

      const observedTime = previousSnapshot?.observedAt
        ? Date.parse(previousSnapshot.observedAt)
        : NaN;

      const snapshotIsRecent =
        Number.isFinite(observedTime) &&
        Date.now() - observedTime <= WEATHER_STALE_MAX_AGE &&
        observedTime <= Date.now() + 5 * 60 * 1000;

      const snapshotIsValid =
        previousSnapshot &&
        Number.isFinite(previousSnapshot.temperature) &&
        Number.isFinite(previousSnapshot.pressure) &&
        Number.isFinite(previousSnapshot.humidity) &&
        Number.isFinite(previousSnapshot.windSpeed);

      if (snapshotIsValid && snapshotIsRecent) {
        console.warn("[Weather] Returning MongoDB snapshot fallback:", {
          simulationId: String(previousSimulation._id),
          observedAt: previousSnapshot.observedAt,
        });

        result = {
          success: true,
          source: previousSnapshot.source ?? "OpenWeather",
          location: previousSnapshot.location ?? location,
          resolvedLocation: previousSnapshot.location ?? location,
          temperature: previousSnapshot.temperature,
          pressure: previousSnapshot.pressure,
          humidity: previousSnapshot.humidity,
          windSpeed: previousSnapshot.windSpeed,
          observedAt: previousSnapshot.observedAt,
          timezone: previousSnapshot.timezone,
          isStale: true,
          staleReason: "OpenWeather is temporarily unavailable",
        };
      } else {
        const retryAfterSeconds = error?.retryAfterMs
          ? Math.ceil(error.retryAfterMs / 1000)
          : 600;

        res.set("Retry-After", String(retryAfterSeconds));

        return res.status(error?.status === 404 ? 404 : 503).json({
          success: false,
          message:
            error?.status === 404
              ? error.message
              : "Weather service is temporarily unavailable",
          retryAfter: retryAfterSeconds,
        });
      }
    }

    console.log("[Weather] Saving environment snapshot:", {
      userId: String(req.user.id),
      location,
      source: result.source,
      isStale: result.isStale === true,
    });

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

app.get("/api/health", (_req, res) =>
  res.json({
    ok: true,
    db: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
  }),
);

// Traditional server startup for local development and Render.
export async function startServer() {
  await connectDatabase();

  app.listen(port, "0.0.0.0", () => {
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
export default app;
