import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { SecurityManager } from './security.js';
import { SecureFileManager } from './file-manager.js';
import { MCPToolResponse, SecurityConfig } from './types.js';

export class SecureMCPServer {
  private server: McpServer;
  private security: SecurityManager;
  private fileManager: SecureFileManager;

  constructor(config: SecurityConfig) {
    this.server = new McpServer({
      name: 'secure-fileserver',
      version: '1.0.0',
    });

    this.security = new SecurityManager(config);
    this.fileManager = new SecureFileManager(this.security);
    this.setupTools();
    this.setupErrorHandling();
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

    // List directory tool
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

    // Read file tool
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

    // Write file tool
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

    // Delete file tool
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

    // Create directory tool
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

    // Move file tool
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

    // Copy file tool
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

    // Get file info tool
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

    // Search files tool
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

    // List databases tool
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

    // Generate token tool (admin only)
    this.server.tool('generate_token', 'Generate authentication token (admin only)', {
      userId: z.string().describe('User ID'),
      permissions: z.array(z.string()).optional().describe('User permissions'),
      apiKey: z.string().optional().describe('API key for authentication (optional in demo mode)')
    }, async ({ userId, permissions, apiKey }) => {
      // In demo mode, allow token generation without API key
      if (!this.security['config'].demoMode && (!apiKey || apiKey !== process.env.API_KEY)) {
        throw new Error('Invalid API key');
      }
      
      const token = this.security.generateToken(userId, permissions || ['read', 'write']);
      return { success: true, data: { token, userId }, timestamp: new Date().toISOString() };
    });
  }

  private setupErrorHandling() {
    this.server.onerror = (error) => {
      console.error('[MCP Server Error]', error);
    };

    process.on('SIGINT', async () => {
      await this.server.close();
      process.exit(0);
    });
  }

  async start() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error('Secure MCP File Server started on stdio');
  }
}