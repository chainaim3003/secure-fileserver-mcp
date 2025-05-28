import fs from "fs/promises";
import path from "path";
import mime from "mime-types";
import { FileInfo, DirectoryListing, DatabaseConfig } from "./types.js";
import { SecurityManager } from "./security.js";

export class SecureFileManager {
  private security: SecurityManager;

  constructor(security: SecurityManager) {
    this.security = security;
  }

  async listDirectory(dirPath: string): Promise<DirectoryListing> {
    const absolutePath = this.security.validatePath(dirPath);
    
    try {
      const entries = await fs.readdir(absolutePath, { withFileTypes: true });
      const files: FileInfo[] = [];
      let totalSize = 0;
      let fileCount = 0;
      let directoryCount = 0;

      for (const entry of entries) {
        const fullPath = path.join(absolutePath, entry.name);
        const relativePath = path.relative(this.security["config"].secureRootPath, fullPath);
        
        try {
          const stats = await fs.stat(fullPath);
          const fileInfo: FileInfo = {
            name: entry.name,
            path: relativePath,
            size: stats.size,
            isDirectory: entry.isDirectory(),
            lastModified: stats.mtime,
            mimeType: entry.isFile() ? mime.lookup(entry.name) || "application/octet-stream" : undefined
          };

          files.push(fileInfo);
          
          if (entry.isDirectory()) {
            directoryCount++;
          } else {
            fileCount++;
            totalSize += stats.size;
          }
        } catch (error) {
          console.warn(`Could not access ${entry.name}:`, error);
        }
      }

      return {
        files: files.sort((a, b) => {
          // Directories first, then files, both alphabetically
          if (a.isDirectory && !b.isDirectory) return -1;
          if (!a.isDirectory && b.isDirectory) return 1;
          return a.name.localeCompare(b.name);
        }),
        path: dirPath,
        totalSize,
        fileCount,
        directoryCount
      };
    } catch (error) {
      throw new Error(`Failed to list directory: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  }

  async readFile(filePath: string): Promise<string> {
    const absolutePath = this.security.validatePath(filePath);
    
    if (!this.security.validateFileExtension(absolutePath)) {
      throw new Error("File type not allowed");
    }

    try {
      const content = await fs.readFile(absolutePath, "utf-8");
      return content;
    } catch (error) {
      throw new Error(`Failed to read file: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  }

  async writeFile(filePath: string, content: string): Promise<void> {
    const absolutePath = this.security.validatePath(filePath);
    
    if (!this.security.validateFileExtension(absolutePath)) {
      throw new Error("File type not allowed");
    }

    const validatedContent = this.security.validateFileContent(content);

    try {
      // Ensure directory exists
      await fs.mkdir(path.dirname(absolutePath), { recursive: true });
      await fs.writeFile(absolutePath, validatedContent, "utf-8");
    } catch (error) {
      throw new Error(`Failed to write file: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  }

  async deleteFile(filePath: string): Promise<void> {
    const absolutePath = this.security.validatePath(filePath);

    try {
      const stats = await fs.stat(absolutePath);
      if (stats.isDirectory()) {
        await fs.rmdir(absolutePath, { recursive: true });
      } else {
        await fs.unlink(absolutePath);
      }
    } catch (error) {
      throw new Error(`Failed to delete: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  }

  async createDirectory(dirPath: string): Promise<void> {
    const absolutePath = this.security.validatePath(dirPath);

    try {
      await fs.mkdir(absolutePath, { recursive: true });
    } catch (error) {
      throw new Error(`Failed to create directory: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  }

  async moveFile(sourcePath: string, destinationPath: string): Promise<void> {
    const absoluteSource = this.security.validatePath(sourcePath);
    const absoluteDestination = this.security.validatePath(destinationPath);

    if (!this.security.validateFileExtension(absoluteSource) || 
        !this.security.validateFileExtension(absoluteDestination)) {
      throw new Error("File type not allowed");
    }

    try {
      // Ensure destination directory exists
      await fs.mkdir(path.dirname(absoluteDestination), { recursive: true });
      await fs.rename(absoluteSource, absoluteDestination);
    } catch (error) {
      throw new Error(`Failed to move file: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  }

  async copyFile(sourcePath: string, destinationPath: string): Promise<void> {
    const absoluteSource = this.security.validatePath(sourcePath);
    const absoluteDestination = this.security.validatePath(destinationPath);

    if (!this.security.validateFileExtension(absoluteSource) || 
        !this.security.validateFileExtension(absoluteDestination)) {
      throw new Error("File type not allowed");
    }

    try {
      // Ensure destination directory exists
      await fs.mkdir(path.dirname(absoluteDestination), { recursive: true });
      await fs.copyFile(absoluteSource, absoluteDestination);
    } catch (error) {
      throw new Error(`Failed to copy file: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  }

  async getFileInfo(filePath: string): Promise<FileInfo> {
    const absolutePath = this.security.validatePath(filePath);

    try {
      const stats = await fs.stat(absolutePath);
      const relativePath = path.relative(this.security["config"].secureRootPath, absolutePath);
      
      return {
        name: path.basename(absolutePath),
        path: relativePath,
        size: stats.size,
        isDirectory: stats.isDirectory(),
        lastModified: stats.mtime,
        mimeType: stats.isFile() ? mime.lookup(absolutePath) || "application/octet-stream" : undefined,
        permissions: stats.mode.toString(8)
      };
    } catch (error) {
      throw new Error(`Failed to get file info: ${error instanceof Error ? error.message : "Unknown error"}`);
    }
  }

  async searchFiles(pattern: string, directory: string = ""): Promise<FileInfo[]> {
    const absoluteDir = this.security.validatePath(directory);
    const results: FileInfo[] = [];

    async function searchRecursive(dir: string): Promise<void> {
      try {
        const entries = await fs.readdir(dir, { withFileTypes: true });
        
        for (const entry of entries) {
          const fullPath = path.join(dir, entry.name);
          
          if (entry.name.toLowerCase().includes(pattern.toLowerCase())) {
            try {
              const stats = await fs.stat(fullPath);
              results.push({
                name: entry.name,
                path: path.relative(absoluteDir, fullPath),
                size: stats.size,
                isDirectory: entry.isDirectory(),
                lastModified: stats.mtime,
                mimeType: entry.isFile() ? mime.lookup(entry.name) || "application/octet-stream" : undefined
              });
            } catch (error) {
              console.warn(`Could not access ${entry.name}:`, error);
            }
          }

          if (entry.isDirectory() && results.length < 100) { // Limit results
            await searchRecursive(fullPath);
          }
        }
      } catch (error) {
        console.warn(`Could not search directory ${dir}:`, error);
      }
    }

    await searchRecursive(absoluteDir);
    return results.slice(0, 100); // Limit to 100 results
  }

  async listDatabases(): Promise<DatabaseConfig[]> {
    const databases: DatabaseConfig[] = [];
    const listing = await this.listDirectory("");

    for (const file of listing.files) {
      if (!file.isDirectory) {
        const ext = path.extname(file.name).toLowerCase();
        
        if ([".db", ".sqlite", ".sqlite3"].includes(ext)) {
          databases.push({
            type: "sqlite",
            path: file.path,
            name: file.name,
            size: file.size
          });
        } else if (ext === ".json") {
          databases.push({
            type: "json",
            path: file.path,
            name: file.name,
            size: file.size
          });
        } else if (ext === ".csv") {
          databases.push({
            type: "csv",
            path: file.path,
            name: file.name,
            size: file.size
          });
        }
      }
    }

    return databases;
  }
}
