import { VercelRequest, VercelResponse } from "@vercel/node";
import { SecureSSEServer } from "../src/sse-server.js";
import { SecurityConfig } from "../src/types.js";

let serverInstance: SecureSSEServer | null = null;

function getConfig(): SecurityConfig {
  const demoMode = process.env.DEMO_MODE === "true" || (!process.env.JWT_SECRET && !process.env.API_KEY);
  
  return {
    jwtSecret: process.env.JWT_SECRET,
    apiKey: process.env.API_KEY,
    secureRootPath: process.env.SECURE_ROOT_PATH || "/tmp/secure-files",
    allowedExtensions: process.env.ALLOWED_EXTENSIONS?.split(",") || [".txt", ".json", ".sql", ".db", ".sqlite", ".md", ".csv", ".xml", ".yaml", ".yml"],
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE || "10485760"),
    allowedOrigins: process.env.ALLOWED_ORIGINS?.split(",") || ["*"],
    demoMode
  };
}

export default async function handler(req: VercelRequest, res: VercelResponse) {
  try {
    const config = getConfig();
    
    // In production mode, validate required environment variables
    if (!config.demoMode && (!process.env.JWT_SECRET || !process.env.API_KEY)) {
      return res.status(500).json({
        success: false,
        error: "Server configuration error: Missing required environment variables for production mode"
      });
    }

    // Initialize server instance if not exists
    if (!serverInstance) {
      serverInstance = new SecureSSEServer(config);
    }

    // Handle health check
    if (req.url === "/health") {
      return res.json({
        status: "healthy",
        timestamp: new Date().toISOString(),
        version: "1.0.0",
        mode: config.demoMode ? "demo" : "production"
      });
    }

    // Handle MCP requests
    if (req.url?.startsWith("/mcp")) {
      // Set SSE headers
      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache");
      res.setHeader("Connection", "keep-alive");
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");

      // Handle preflight
      if (req.method === "OPTIONS") {
        return res.status(200).end();
      }

      // Validate API key (only in production mode)
      if (!config.demoMode) {
        const apiKey = req.headers["x-api-key"] as string;
        if (!apiKey || apiKey !== process.env.API_KEY) {
          return res.status(401).json({
            success: false,
            error: "Invalid API key"
          });
        }
      }

      // Create SSE transport and connect
      const { SSEServerTransport } = await import("@modelcontextprotocol/sdk/server/sse.js");
      const transport = new SSEServerTransport("/mcp", res);
      
      // Connect the server
      await (serverInstance as any).server.connect(transport);
      return;
    }

    // 404 for other routes
    res.status(404).json({
      success: false,
      error: "Endpoint not found"
    });

  } catch (error) {
    console.error("Handler error:", error);
    res.status(500).json({
      success: false,
      error: "Internal server error",
      timestamp: new Date().toISOString()
    });
  }
}
