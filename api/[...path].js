import { app, connectDatabase } from "../src/server.js";

export default async function handler(req, res) {
  try {
    await connectDatabase();
    return app(req, res);
  } catch (error) {
    console.error("Vercel API startup error:", error);

    return res.status(500).json({
      message: "Backend initialization failed",
    });
  }
}
