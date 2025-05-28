import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import path from 'path';
import { AuthPayload, SecurityConfig } from './types.js';

export class SecurityManager {
  private config: SecurityConfig;

  constructor(config: SecurityConfig) {
    this.config = config;
  }

  // Path validation schema
  private pathSchema = z.string().refine(
    (path) => {
      // Prevent directory traversal
      return !path.includes('..') && 
             !path.includes('~') && 
             !path.startsWith('/') &&
             path.length > 0 &&
             path.length < 1000;
    },
    { message: "Invalid path: contains forbidden characters or patterns" }
  );

  // File content validation
  private fileContentSchema = z.string().max(this.config.maxFileSize, {
    message: `File content exceeds maximum size of ${this.config.maxFileSize} bytes`
  });

  validatePath(inputPath: string): string {
    // In demo mode, allow empty path for root directory
    if (this.config.demoMode && (!inputPath || inputPath === '')) {
      return this.config.secureRootPath;
    }

    // Validate input
    const validatedPath = this.pathSchema.parse(inputPath);
    
    // Resolve to absolute path within secure root
    const absolutePath = path.resolve(this.config.secureRootPath, validatedPath);
    
    // Ensure the resolved path is within the secure root
    if (!absolutePath.startsWith(path.resolve(this.config.secureRootPath))) {
      throw new Error('Access denied: Path outside secure directory');
    }

    return absolutePath;
  }

  validateFileExtension(filePath: string): boolean {
    const ext = path.extname(filePath).toLowerCase();
    return this.config.allowedExtensions.includes(ext) || this.config.allowedExtensions.includes('*');
  }

  validateFileContent(content: string): string {
    return this.getFileContentSchema().parse(content);
  }

  generateToken(userId: string, permissions: string[] = ['read', 'write']): string {
    if (this.config.demoMode || !this.config.jwtSecret) {
      // Return a demo token that's easily identifiable
      return `demo-token-${userId}-${Date.now()}`;
    }

    const payload: AuthPayload = {
      userId,
      permissions,
      exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
    };

    return jwt.sign(payload, this.config.jwtSecret);
  }

  verifyToken(token: string): AuthPayload {
    if (this.config.demoMode || !this.config.jwtSecret) {
      // In demo mode, accept any token and return demo user
      if (token.startsWith('demo-token-') || token === 'demo') {
        return {
          userId: 'demo-user',
          permissions: ['read', 'write', 'delete', 'admin'],
          exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60)
        };
      }
      // If no token provided in demo mode, still allow access
      return {
        userId: 'anonymous',
        permissions: ['read', 'write'],
        exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60)
      };
    }

    try {
      return jwt.verify(token, this.config.jwtSecret) as AuthPayload;
    } catch (error) {
      throw new Error('Invalid or expired token');
    }
  }

  async hashApiKey(apiKey: string): Promise<string> {
    return bcrypt.hash(apiKey, 12);
  }

  async verifyApiKey(apiKey: string, hashedKey: string): Promise<boolean> {
    if (this.config.demoMode) {
      return true; // Allow any API key in demo mode
    }
    return bcrypt.compare(apiKey, hashedKey);
  }

  sanitizeFilename(filename: string): string {
    // Remove or replace dangerous characters
    return filename
      .replace(/[<>:"/\\|?*\x00-\x1f]/g, '_')
      .replace(/^\.+/, '')
      .substring(0, 255);
  }

  checkPermission(authPayload: AuthPayload, operation: string): boolean {
    return authPayload.permissions.includes(operation) || 
           authPayload.permissions.includes('admin');
  }
}