# Secure File Server MCP

A secure Model Context Protocol (MCP) server for managing files and databases with comprehensive security features, authentication, and both stdio and SSE transport support.

## ⚡ Quick Demo (No Setup Required!)

```bash
# Clone and run demo instantly
git clone <your-repo>
cd secure-fileserver-mcp
node demo.js
```

The demo mode runs without any authentication - perfect for testing and development!

## Features

- 🔒 **Secure file operations** with path validation and sandboxing
- 🔑 **Optional JWT-based authentication** with role-based permissions
- 🎉 **Demo mode** for instant testing without setup
- 📁 **Comprehensive file management** (read, write, delete, move, copy, search)
- 🗄️ **Database detection** for SQLite, JSON, and CSV files
- 🚀 **Dual transport support** (stdio and SSE)
- ☁️ **Vercel deployment ready**
- 🛡️ **Rate limiting and security headers**
- 📊 **File system monitoring and logging**

## Quick Start

### Option 1: Demo Mode (Recommended for Testing)

```bash
# Install and run demo
npm install
node demo.js
```

### Option 2: Manual Setup

1. **Installation**
```bash
npm install
```

2. **Environment Setup**
```bash
cp .env.example .env
# Edit .env - for demo mode, just set DEMO_MODE=true
```

3. **Build and Run**
```bash
npm run build

# Demo mode (no authentication)
DEMO_MODE=true npm start

# Or production mode (requires JWT_SECRET and API_KEY)
npm start
```

## Configuration Modes

### 🎉 Demo Mode (Default)
- **No authentication required**
- **Auto-creates demo files**
- **Perfect for testing and development**
- Set `DEMO_MODE=true` or leave JWT_SECRET/API_KEY empty

```env
DEMO_MODE=true
SECURE_ROOT_PATH=./demo-files
```

### 🔒 Production Mode
- **Full JWT authentication**
- **API key protection**
- **Production-ready security**
- Set `JWT_SECRET` and `API_KEY` in .env

```env
JWT_SECRET=your-super-secret-jwt-key-here
API_KEY=your-api-key-here
SECURE_ROOT_PATH=/path/to/your/secure/directory
DEMO_MODE=false
```

## Available Tools

All tools work with optional authentication - in demo mode, no token required!

### File Operations
- `list_directory` - List directory contents
- `read_file` - Read file content  
- `write_file` - Write content to file
- `delete_file` - Delete file or directory
- `create_directory` - Create new directory
- `move_file` - Move/rename files
- `copy_file` - Copy files
- `get_file_info` - Get detailed file information
- `search_files` - Search files by pattern

### Database Operations
- `list_databases` - List all database files

### Administration
- `generate_token` - Generate JWT tokens

## Usage Examples

### Demo Mode (No Authentication)
```json
{"tool": "list_directory", "arguments": {"path": ""}}
{"tool": "read_file", "arguments": {"path": "demo.txt"}}
{"tool": "write_file", "arguments": {"path": "test.txt", "content": "Hello World!"}}
```

### Production Mode (With Authentication)
```json
{"tool": "generate_token", "arguments": {"userId": "user123", "apiKey": "your-api-key"}}
{"tool": "list_directory", "arguments": {"path": "", "token": "your-jwt-token"}}
```

## Deployment

### Local Development
```bash
# Stdio mode (for MCP clients)
npm start

# SSE mode (for web applications)  
npm run start:sse
```

### Vercel Deployment
1. Configure environment variables in Vercel dashboard
2. Deploy: `vercel deploy`

The SSE endpoint will be available at: `https://your-domain.vercel.app/mcp`

## Demo Files

In demo mode, the server automatically creates:
- `demo.txt` - Welcome message and instructions
- `demo.json` - Sample JSON data
- `demo-folder/nested-file.md` - Nested directory example

## Environment Variables

### Required for Production
- `JWT_SECRET` - Secret key for JWT tokens
- `API_KEY` - API key for admin operations

### Optional (with defaults)
- `DEMO_MODE` - Enable demo mode (default: true if no JWT_SECRET)
- `SECURE_ROOT_PATH` - File system root (default: ./demo-files)
- `MAX_FILE_SIZE` - Max file size in bytes (default: 10MB)
- `ALLOWED_EXTENSIONS` - Comma-separated file extensions
- `RATE_LIMIT_POINTS` - Requests per minute (default: 1000 in demo)
- `PORT` - Server port (default: 3001)

## Security Features

### Demo Mode
- Path traversal protection
- File type restrictions  
- Size limits
- Sandboxed access to designated directory

### Production Mode
- All demo mode protections PLUS:
- JWT authentication with role-based permissions
- API key validation for admin operations
- Rate limiting and security headers
- Full audit logging

## Development

```bash
# Development with hot reload
npm run dev

# Build TypeScript
npm run build

# Run tests (if you add them)
npm test
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test in both demo and production modes
5. Submit a pull request

## License

MIT License - see LICENSE file for details.
