#!/usr/bin/env node

import dotenv from "dotenv";
import { SecureMCPServer } from "./mcp-server.js";
import { SecurityConfig } from "./types.js";

// Load environment variables
dotenv.config();

function validateEnvironment(): SecurityConfig {
  // In demo mode, only require SECURE_ROOT_PATH
  const demoMode = process.env.DEMO_MODE === "true" || process.env.NODE_ENV === "development";
  
  if (!demoMode) {
    const requiredEnvVars = ["JWT_SECRET", "API_KEY", "SECURE_ROOT_PATH"];
    const missing = requiredEnvVars.filter(key => !process.env[key]);
    
    if (missing.length > 0) {
      console.error(`Missing required environment variables for production mode: ${missing.join(", ")}`);
      console.error("Set DEMO_MODE=true to run in demo mode without authentication");
      process.exit(1);
    }
  }

  // Create demo files directory if it does not exist
  const secureRootPath = process.env.SECURE_ROOT_PATH || "./demo-files";
  
  return {
    jwtSecret: process.env.JWT_SECRET,
    apiKey: process.env.API_KEY,
    secureRootPath,
    allowedExtensions: process.env.ALLOWED_EXTENSIONS?.split(",") || [".txt", ".json", ".sql", ".db", ".sqlite", ".md", ".csv", ".xml", ".yaml", ".yml"],
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE || "10485760"), // 10MB default
    allowedOrigins: process.env.ALLOWED_ORIGINS?.split(",") || ["http://localhost:3000"],
    demoMode
  };
}

async function createDemoFiles(rootPath: string) {
  const fs = await import("fs/promises");
  const path = await import("path");
  
  try {
    // Create demo.txt
    await fs.writeFile(
      path.join(rootPath, "demo.txt"), 
      "Welcome to the Secure File Server MCP Demo!\n\nThis is a sample text file to demonstrate the file operations.\n\nYou can:\n- Read this file\n- Create new files\n- Edit existing files\n- Create directories\n- Search for files\n\nTry the available MCP tools!"
    );
    
    // Create demo.json
    await fs.writeFile(
      path.join(rootPath, "demo.json"),
      JSON.stringify({
        name: "Demo Data",
        version: "1.0.0",
        features: ["file_management", "secure_operations", "mcp_integration"],
        demo: true,
        timestamp: new Date().toISOString()
      }, null, 2)
    );
    
    // Create a demo directory
    await fs.mkdir(path.join(rootPath, "demo-folder"), { recursive: true });
    
    // Create a file in the demo directory
    await fs.writeFile(
      path.join(rootPath, "demo-folder", "nested-file.md"),
      "# Demo Nested File\n\nThis file is in the demo-folder directory.\n\n## Features\n\n- Nested directory support\n- Markdown files\n- File organization\n\nFeel free to explore the file structure!"
    );
    
    console.error("✅ Demo files created successfully");
  } catch (error) {
    console.warn("Could not create some demo files:", error);
  }
}

async function main() {
  try {
    const config = validateEnvironment();
    
    // Create demo files directory if in demo mode
    if (config.demoMode) {
      const fs = await import("fs/promises");
      try {
        await fs.mkdir(config.secureRootPath, { recursive: true });
        
        // Create some demo files
        await createDemoFiles(config.secureRootPath);
      } catch (error) {
        console.warn("Could not create demo files:", error);
      }
    }
    
    const server = new SecureMCPServer(config);
    
    console.error("Starting Secure MCP File Server...");
    
    if (config.demoMode) {
      console.error("🎉 DEMO MODE: Authentication is disabled for easy testing");
      console.error("💡 To enable production mode, set JWT_SECRET and API_KEY in .env");
    } else {
      console.error("🔒 PRODUCTION MODE: Authentication enabled");
    }
    
    console.error(`📁 Secure root path: ${config.secureRootPath}`);
    console.error(`📄 Allowed extensions: ${config.allowedExtensions.join(", ")}`);
    console.error(`📊 Max file size: ${(config.maxFileSize / 1024 / 1024).toFixed(2)}MB`);
    
    await server.start();
  } catch (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch(console.error);
}
