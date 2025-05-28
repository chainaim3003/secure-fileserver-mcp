import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { RateLimiterMemory } from 'rate-limiter-flexible';
import dotenv from 'dotenv';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { z } from 'zod';
import { SecurityManager } from './security.js';
import { SecureFileManager } from './file-manager.js';
import { SecurityConfig } from './types.js';

dotenv.config();

export class SecureSSEServer {
  private app: express.Application;
  private server: Server;
  private security: SecurityManager;
  private fileManager: SecureFileManager;
  private rateLimiter: RateLimiterMemory;

  constructor(config: SecurityConfig) {
    this.app = express();
    this.security = new SecurityManager(config);
    this.fileManager = new SecureFileManager(this.security);
    
    // Rate limiting
    this.rateLimiter = new RateLimiterMemory({
      points: parseInt(process.env.RATE_LIMIT_POINTS || '100'),
      duration: parseInt(process.env.RATE_LIMIT_DURATION || '60')
    });

    this.server = new Server(
      {
        name: 'secure-fileserver-sse',
        version: '1.0.0',
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.setupMiddleware(config);
    this.setupTools();
    this.setupRoutes();
  }

  private setupMiddleware(config: SecurityConfig) {
    // Security middleware
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          connectSrc: ["'self'"],
        },
      },
    }));

    // CORS
    this.app.use(cors({
      origin: config.allowedOrigins,
      credentials: true,
      methods: ['GET', 'POST', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key']
    }));

    // Parse JSON
    this.app.use(express.json({ 
      limit: `${Math.ceil(config.maxFileSize / 1024 / 1024)}mb` 
    }));

    // Rate limiting middleware
    this.app.use(async (req, res, next) => {
      try {
        await this.rateLimiter.consume(req.ip);
        next();
      } catch (rejRes) {
        res.status(429).json({
          success: false,
          error: 'Too many requests',
          retryAfter: Math.round(rejRes.msBeforeNext / 1000)
        });
      }
    });

    // API key validation middleware (only in production mode)
    this.app.use('/mcp', (req, res, next) => {
      if (config.demoMode) {
        return next(); // Skip API key validation in demo mode
      }
      
      const apiKey = req.headers['x-api-key'] as string;
      if (!apiKey || apiKey !== process.env.API_KEY) {
        return res.status(401).json({
          success: false,
          error: 'Invalid API key'
        });
      }
      next();
    });
  }

  private setupTools() {
    // Authentication helper
    const authenticate = (token?: string) => {
      if (this.security['config'].demoMode) {
        // In demo mode, always return a valid demo user
        return {
          userId: 'demo-user',
          permissions: ['read', 'write', 'delete', 'admin'],
          exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60)
        };
      }
      if (!token) throw new Error('Authentication token required');
      return this.security.verifyToken(token);
    };

    // Register all tools with the same logic as stdio version
    this.server.tool('list_directory', 'List contents of a directory', {
      path: z.string().optional().describe('Directory path (relative to secure root)'),
      token: z.string().optional().describe('Authentication token (optional in demo mode)')
    }, async ({ path, token }) => {
      const authPayload = authenticate(token);
      if (!this.security.checkPermission(authPayload, 'read')) {
        throw new Error('Insufficient permissions');
      }
      
      const listing = await this.fileManager.listDirectory(path || '');
      return { success: true, data: listing, timestamp: new Date().toISOString() };
    });

    this.server.tool('read_file', 'Read content of a file', {
      path: z.string().describe('File path (relative to secure root)'),
      token: z.string().optional().describe('Authentication token (optional in demo mode)')
    }, async ({ path, token }) => {
      const authPayload = authenticate(token);
      if (!this.security.checkPermission(authPayload, 'read')) {
        throw new Error('Insufficient permissions');
      }
      
      const content = await this.fileManager.readFile(path);
      return { success: true, data: { content, path }, timestamp: new Date().toISOString() };
    });

    this.server.tool('write_file', 'Write content to a file', {
      path: z.string().describe('File path (relative to secure root)'),
      content: z.string().describe('File content'),
      token: z.string().optional().describe('Authentication token (optional in demo mode)')
    }, async ({ path, content, token }) => {
      const authPayload = authenticate(token);
      if (!this.security.checkPermission(authPayload, 'write')) {
        throw new Error('Insufficient permissions');
      }
      
      await this.fileManager.writeFile(path, content);
      return { success: true, data: { path, size: content.length }, timestamp: new Date().toISOString() };
    });

    this.server.tool('delete_file', 'Delete a file or directory', {
      path: z.string().describe('File/directory path (relative to secure root)'),
      token: z.string().optional().describe('Authentication token (optional in demo mode)')
    }, async ({ path, token }) => {
      const authPayload = authenticate(token);
      if (!this.security.checkPermission(authPayload, 'delete')) {
        throw new Error('Insufficient permissions');
      }
      
      await this.fileManager.deleteFile(path);
      return { success: true, data: { path }, timestamp: new Date().toISOString() };
    });

    this.server.tool('create_directory', 'Create a new directory', {
      path: z.string().describe('Directory path (relative to secure root)'),
      token: z.string().optional().describe('Authentication token (optional in demo mode)')
    }, async ({ path, token }) => {
      const authPayload = authenticate(token);
      if (!this.security.checkPermission(authPayload, 'write')) {
        throw new Error('Insufficient permissions');
      }
      
      await this.fileManager.createDirectory(path);
      return { success: true, data: { path }, timestamp: new Date().toISOString() };
    });

    this.server.tool('move_file', 'Move/rename a file or directory', {
      sourcePath: z.string().describe('Source path (relative to secure root)'),
      destinationPath: z.string().describe('Destination path (relative to secure root)'),
      token: z.string().optional().describe('Authentication token (optional in demo mode)')
    }, async ({ sourcePath, destinationPath, token }) => {
      const authPayload = authenticate(token);
      if (!this.security.checkPermission(authPayload, 'write')) {
        throw new Error('Insufficient permissions');
      }
      
      await this.fileManager.moveFile(sourcePath, destinationPath);
      return { success: true, data: { from: sourcePath, to: destinationPath }, timestamp: new Date().toISOString() };
    });

    this.server.tool('copy_file', 'Copy a file', {
      sourcePath: z.string().describe('Source path (relative to secure root)'),
      destinationPath: z.string().describe('Destination path (relative to secure root)'),
      token: z.string().optional().describe('Authentication token (optional in demo mode)')
    }, async ({ sourcePath, destinationPath, token }) => {
      const authPayload = authenticate(token);
      if (!this.security.checkPermission(authPayload, 'read')) {
        throw new Error('Insufficient permissions');
      }
      
      await this.fileManager.copyFile(sourcePath, destinationPath);
      return { success: true, data: { from: sourcePath, to: destinationPath }, timestamp: new Date().toISOString() };
    });

    this.server.tool('get_file_info', 'Get detailed information about a file or directory', {
      path: z.string().describe('File/directory path (relative to secure root)'),
      token: z.string().optional().describe('Authentication token (optional in demo mode)')
    }, async ({ path, token }) => {
      const authPayload = authenticate(token);
      if (!this.security.checkPermission(authPayload, 'read')) {
        throw new Error('Insufficient permissions');
      }
      
      const fileInfo = await this.fileManager.getFileInfo(path);
      return { success: true, data: fileInfo, timestamp: new Date().toISOString() };
    });

    this.server.tool('search_files', 'Search for files by name pattern', {
      pattern: z.string().describe('Search pattern'),
      directory: z.string().optional().describe('Directory to search in (optional)'),
      token: z.string().optional().describe('Authentication token (optional in demo mode)')
    }, async ({ pattern, directory, token }) => {
      const authPayload = authenticate(token);
      if (!this.security.checkPermission(authPayload, 'read')) {
        throw new Error('Insufficient permissions');
      }
      
      const searchResults = await this.fileManager.searchFiles(pattern, directory);
      return { success: true, data: { results: searchResults, pattern }, timestamp: new Date().toISOString() };
    });

    this.server.tool('list_databases', 'List all database files (SQLite, JSON, CSV)', {
      token: z.string().optional().describe('Authentication token (optional in demo mode)')
    }, async ({ token }) => {
      const authPayload = authenticate(token);
      if (!this.security.checkPermission(authPayload, 'read')) {
        throw new Error('Insufficient permissions');
      }
      
      const databases = await this.fileManager.listDatabases();
      return { success: true, data: { databases }, timestamp: new Date().toISOString() };
    });

    this.server.tool('generate_token', 'Generate authentication token (admin only)', {
      userId: z.string().describe('User ID'),
      permissions: z.array(z.string()).optional().describe('User permissions'),
      apiKey: z.string().optional().describe('API key for authentication (optional in demo mode)')
    }, async ({ userId, permissions, apiKey }) => {
      if (!this.security['config'].demoMode && (!apiKey || apiKey !== process.env.API_KEY)) {
        throw new Error('Invalid API key');
      }
      
      const token = this.security.generateToken(userId, permissions || ['read', 'write']);
      return { success: true, data: { token, userId }, timestamp: new Date().toISOString() };
    });
  }

  private setupRoutes() {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({ 
        status: 'healthy', 
        timestamp: new Date().toISOString(),
        version: '1.0.0'
      });
    });

    // MCP SSE endpoint
    this.app.use('/mcp', async (req, res) => {
      const transport = new SSEServerTransport('/mcp', res);
      await this.server.connect(transport);
    });

    // Error handling
    this.app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
      console.error('Server error:', err);
      res.status(500).json({
        success: false,
        error: 'Internal server error',
        timestamp: new Date().toISOString()
      });
    });

    // 404 handler
    this.app.use('*', (req, res) => {
      res.status(404).json({
        success: false,
        error: 'Endpoint not found',
        timestamp: new Date().toISOString()
      });
    });
  }

  start(port: number = 3001) {
    return new Promise<void>((resolve) => {
      this.app.listen(port, () => {
        console.log(`Secure MCP File Server (SSE) running on port ${port}`);
        console.log(`Health check: http://localhost:${port}/health`);
        console.log(`MCP endpoint: http://localhost:${port}/mcp`);
        resolve();
      });
    });
  }
}

// Start server if this file is run directly
if (import.meta.url === `file://${process.argv[1]}`) {
  function validateEnvironment(): SecurityConfig {
    const demoMode = process.env.DEMO_MODE === 'true' || process.env.NODE_ENV === 'development';
    
    if (!demoMode) {
      const requiredEnvVars = ['JWT_SECRET', 'API_KEY', 'SECURE_ROOT_PATH'];
      const missing = requiredEnvVars.filter(key => !process.env[key]);
      
      if (missing.length > 0) {
        console.error(`Missing required environment variables for production mode: ${missing.join(', ')}`);
        console.error('Set DEMO_MODE=true to run in demo mode without authentication');
        process.exit(1);
      }
    }

    return {
      jwtSecret: process.env.JWT_SECRET,
      apiKey: process.env.API_KEY,
      secureRootPath: process.env.SECURE_ROOT_PATH || './demo-files',
      allowedExtensions: process.env.ALLOWED_EXTENSIONS?.split(',') || ['.txt', '.json', '.sql', '.db', '.sqlite', '.md', '.csv', '.xml', '.yaml', '.yml'],
      maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '10485760'),
      allowedOrigins: process.env.ALLOWED_ORIGINS?.split(',') || ['*'],
      demoMode
    };
  }

  const config = validateEnvironment();
  const server = new SecureSSEServer(config);
  const port = parseInt(process.env.PORT || '3001');
  
  console.log('Starting Secure MCP File Server (SSE)...');
  
  if (config.demoMode) {
    console.log('🎉 DEMO MODE: Authentication is disabled for easy testing');
  } else {
    console.log('🔒 PRODUCTION MODE: Authentication enabled');
  }
  
  server.start(port).catch(console.error);
}