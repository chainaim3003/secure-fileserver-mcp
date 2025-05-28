export interface FileInfo {
  name: string;
  path: string;
  size: number;
  isDirectory: boolean;
  lastModified: Date;
  mimeType?: string;
  permissions?: string;
}

export interface DirectoryListing {
  files: FileInfo[];
  path: string;
  totalSize: number;
  fileCount: number;
  directoryCount: number;
}

export interface SecurityConfig {
  secureRootPath: string;
  allowedExtensions: string[];
  maxFileSize: number;
  jwtSecret?: string; // Optional for demo mode
  apiKey?: string; // Optional for demo mode
  allowedOrigins: string[];
  demoMode: boolean; // New demo mode flag
}

export interface AuthPayload {
  userId: string;
  permissions: string[];
  exp: number;
}

export interface FileOperation {
  operation: "read" | "write" | "delete" | "create" | "move" | "copy";
  path: string;
  content?: string;
  destination?: string;
}

export interface DatabaseConfig {
  type: "sqlite" | "json" | "csv";
  path: string;
  name: string;
  size: number;
  tables?: string[];
}

export interface MCPToolResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  timestamp: string;
}
