const fs = require('fs');
const path = require('path');
const db = require('../config/database');
const { logActivity } = require('../middleware/logger');

// VULNERABILITY: Insecure file upload with no validation
const uploadProfilePicture = async (req, res) => {
  try {
    const userId = req.user.id;
    const { filename, fileData, fileType } = req.body;

    if (!filename || !fileData) {
      return res.status(400).json({
        success: false,
        message: 'Filename and file data required'
      });
    }

    // VULNERABILITY: No file type validation
    console.log('⚠️  Uploading file without validation');
    console.log('Filename:', filename);
    console.log('Type:', fileType);

    // VULNERABILITY: Accepting any file extension
    const uploadDir = path.join(__dirname, '../../uploads/profiles');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }

    // VULNERABILITY: Using user-provided filename directly
    const filePath = path.join(uploadDir, filename);

    // VULNERABILITY: Accepting base64 or direct content
    let fileContent = fileData;
    if (fileData.startsWith('data:')) {
      // Remove data URL prefix
      const base64Data = fileData.replace(/^data:([A-Za-z-+\/]+);base64,/, '');
      fileContent = Buffer.from(base64Data, 'base64');
    }

    // VULNERABILITY: No file size limit
    fs.writeFileSync(filePath, fileContent);

    // VULNERABILITY: Storing file path in database (can be manipulated)
    await db.run(
      'UPDATE users SET profile_picture = ? WHERE id = ?',
      [filename, userId]
    );

    // VULNERABILITY: If file is SVG or HTML, check for script tags
    if (filename.endsWith('.svg') || filename.endsWith('.html')) {
      const content = fs.readFileSync(filePath, 'utf8');
      
      if (content.includes('<script>') || content.includes('onerror=')) {
        console.log('⚠️  MALICIOUS FILE DETECTED - But allowing it anyway!');
        console.log('Content preview:', content.substring(0, 200));
        
        // VULNERABILITY: Not blocking malicious files
        await logActivity(userId, 'MALICIOUS_FILE_UPLOADED', {
          filename,
          hasScript: true
        }, req);
      }
    }

    await logActivity(userId, 'PROFILE_PICTURE_UPLOADED', {
      filename,
      fileType
    }, req);

    res.json({
      success: true,
      message: 'Profile picture uploaded',
      filename: filename,
      url: `/uploads/profiles/${filename}`,
      fileSize: Buffer.byteLength(fileContent)
    });

  } catch (error) {
    console.error('❌ Upload error:', error);
    res.status(500).json({
      success: false,
      message: 'Upload failed',
      error: error.message
    });
  }
};

// VULNERABILITY: Serving uploaded files without sanitization
const getProfilePicture = async (req, res) => {
  try {
    const { filename } = req.params;

    // VULNERABILITY: Path traversal possible
    const filePath = path.join(__dirname, '../../uploads/profiles', filename);

    if (!fs.existsSync(filePath)) {
      return res.status(404).json({
        success: false,
        message: 'File not found'
      });
    }

    // VULNERABILITY: Serving SVG/HTML files directly (XSS)
    if (filename.endsWith('.svg')) {
      res.setHeader('Content-Type', 'image/svg+xml');
    } else if (filename.endsWith('.html')) {
      res.setHeader('Content-Type', 'text/html');
    }

    // VULNERABILITY: Not setting X-Content-Type-Options: nosniff
    const fileContent = fs.readFileSync(filePath);
    res.send(fileContent);

  } catch (error) {
    console.error('❌ Get file error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

// VULNERABILITY: Update profile bio with XSS
const updateProfileBio = async (req, res) => {
  try {
    const userId = req.user.id;
    const { bio, about, website } = req.body;

    // VULNERABILITY: No input sanitization
    console.log('⚠️  Updating profile with unsanitized input');
    
    if (bio && (bio.includes('<script>') || bio.includes('onerror='))) {
      console.log('⚠️  XSS payload detected in bio!');
      console.log('Bio:', bio);
    }

    // VULNERABILITY: Storing XSS payloads directly
    await db.run(
      `UPDATE users SET bio = ?, about = ?, website = ? WHERE id = ?`,
      [bio, about, website, userId]
    );

    const user = await db.get('SELECT * FROM users WHERE id = ?', [userId]);

    await logActivity(userId, 'PROFILE_BIO_UPDATED', {
      bio: bio,
      hasScript: bio?.includes('<script>')
    }, req);

    res.json({
      success: true,
      message: 'Profile updated',
      user: {
        id: user.id,
        bio: user.bio,
        about: user.about,
        website: user.website
      }
    });

  } catch (error) {
    console.error('❌ Update bio error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

// VULNERABILITY: List all uploaded files (information disclosure)
const listUploads = async (req, res) => {
  try {
    // VULNERABILITY: No authentication check
    const uploadDir = path.join(__dirname, '../../uploads/profiles');
    
    if (!fs.existsSync(uploadDir)) {
      return res.json({ success: true, files: [] });
    }

    const files = fs.readdirSync(uploadDir);
    
    const fileList = files.map(file => {
      const stats = fs.statSync(path.join(uploadDir, file));
      const content = fs.readFileSync(path.join(uploadDir, file), 'utf8');
      
      return {
        filename: file,
        size: stats.size,
        created: stats.birthtime,
        url: `/uploads/profiles/${file}`,
        hasScript: content.includes('<script>'),
        preview: content.substring(0, 100)
      };
    });

    res.json({
      success: true,
      count: files.length,
      files: fileList
    });

  } catch (error) {
    console.error('❌ List uploads error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

// VULNERABILITY: Delete any user's profile picture
const deleteProfilePicture = async (req, res) => {
  try {
    const { userId } = req.params;

    // VULNERABILITY: No authorization check
    const user = await db.get('SELECT profile_picture FROM users WHERE id = ?', [userId]);

    if (!user || !user.profile_picture) {
      return res.status(404).json({
        success: false,
        message: 'No profile picture found'
      });
    }

    const filePath = path.join(__dirname, '../../uploads/profiles', user.profile_picture);
    
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    await db.run('UPDATE users SET profile_picture = NULL WHERE id = ?', [userId]);

    res.json({
      success: true,
      message: 'Profile picture deleted'
    });

  } catch (error) {
    console.error('❌ Delete error:', error);
    res.status(500).json({
      success: false,
      error: error.message
    });
  }
};

module.exports = {
  uploadProfilePicture,
  getProfilePicture,
  updateProfileBio,
  listUploads,
  deleteProfilePicture
};