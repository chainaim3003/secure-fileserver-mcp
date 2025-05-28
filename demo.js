#!/usr/bin/env node

/**
 * Demo Script for Secure File Server MCP
 * Shows how to use the MCP server in demo mode without authentication
 */

import { spawn } from "child_process";
import fs from "fs/promises";

console.log("🎉 Secure File Server MCP - Demo Mode");
console.log("=====================================\n");

async function createEnvFile() {
  try {
    await fs.access(".env");
    console.log("✅ .env file already exists");
    return;
  } catch {
    const envContent = `# Demo Mode Configuration - No authentication required!
DEMO_MODE=true
SECURE_ROOT_PATH=./demo-files
MAX_FILE_SIZE=10485760
ALLOWED_EXTENSIONS=.txt,.json,.sql,.db,.sqlite,.md,.csv,.xml,.yaml,.yml
RATE_LIMIT_POINTS=1000
RATE_LIMIT_DURATION=60
PORT=3001
NODE_ENV=development
ALLOWED_ORIGINS=*`;

    await fs.writeFile(".env", envContent);
    console.log("✅ Created .env file for demo mode");
  }
}

async function installAndBuild() {
  console.log("📦 Installing dependencies and building...");
  
  return new Promise((resolve, reject) => {
    const install = spawn("npm", ["install"], { stdio: "inherit" });
    
    install.on("close", (code) => {
      if (code === 0) {
        const build = spawn("npm", ["run", "build"], { stdio: "inherit" });
        build.on("close", (buildCode) => {
          if (buildCode === 0) {
            console.log("✅ Ready to start!\n");
            resolve();
          } else {
            reject(new Error("Build failed"));
          }
        });
      } else {
        reject(new Error("Install failed"));
      }
    });
  });
}

async function startServer() {
  console.log("🚀 Starting MCP server in demo mode...");
  console.log("🔓 No authentication required - perfect for testing!\n");
  
  const server = spawn("npm", ["start"], { stdio: "inherit" });
  
  process.on("SIGINT", () => {
    console.log("\n👋 Shutting down demo server...");
    server.kill("SIGINT");
    process.exit(0);
  });
}

async function main() {
  try {
    await createEnvFile();
    await installAndBuild();
    await startServer();
  } catch (error) {
    console.error("❌ Demo failed:", error.message);
    process.exit(1);
  }
}

main();
