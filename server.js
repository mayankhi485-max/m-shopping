const express = require("express");
const session = require("express-session");
const http = require("http");
const { Server } = require("socket.io");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  maxHttpBufferSize: 1e8 // 100MB File support
});

const PORT = 3000;
const ADMIN_USER = "Mayank"; 

// 1. SECURITY HEADERS (Helmet)
app.use(
  helmet({
    contentSecurityPolicy: false // Socket.io & PeerJS WebRTC access ke liye
  })
);

// 2. BRUTE FORCE / DDOS PROTECTION (Rate Limiter: 15 mins me max 150 requests per IP)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 150,
  message: "Too many requests from this IP, please try again later."
});
app.use(limiter);

// Directory Setup
const uploadDir = path.join(__dirname, "public", "uploads");
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// SECURE USER DB (Stored outside public folder)
const usersFilePath = path.join(__dirname, "users_db.json");

function loadUsers() {
  if (fs.existsSync(usersFilePath)) {
    try { return JSON.parse(fs.readFileSync(usersFilePath, "utf8")); } 
    catch (err) { return {}; }
  }
  // Default Admin creation with hashed password
  const defaultSalt = bcrypt.genSaltSync(10);
  const defaultHash = bcrypt.hashSync("123456", defaultSalt);
  const defaultUsers = { [ADMIN_USER.toLowerCase()]: { username: ADMIN_USER, password: defaultHash } };
  fs.writeFileSync(usersFilePath, JSON.stringify(defaultUsers, null, 2), "utf8");
  return defaultUsers;
}

function saveUsers(users) {
  fs.writeFileSync(usersFilePath, JSON.stringify(users, null, 2), "utf8");
}

// SECURE CHAT HISTORY DB
const historyFilePath = path.join(__dirname, "chat_history.json");

function loadChatHistory() {
  if (fs.existsSync(historyFilePath)) {
    try { return JSON.parse(fs.readFileSync(historyFilePath, "utf8")); } 
    catch (err) { return []; }
  }
  return [];
}

function saveChatHistory(history) {
  fs.writeFileSync(historyFilePath, JSON.stringify(history, null, 2), "utf8");
}

let chatBackgrounds = {};

// 3. SECURE FILE UPLOAD (Only allows Images, Videos, Audio & Docs)
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB Max limit
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|mp4|webm|mp3|pdf|doc|docx/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);

    if (extname && mimetype) {
      return cb(null, true);
    } else {
      cb(new Error("Security Alert: Harmful file types are not allowed!"));
    }
  }
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// 4. SECURE SESSION COOKIES
app.use(
  session({
    secret: "m-shopping-super-secure-key-987654321",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // Prevents XSS cookie theft
      secure: false,  // Set to true when hosted on HTTPS
      maxAge: 24 * 60 * 60 * 1000
    }
  })
);

let activeUsers = {};

// STORE FRONT PAGE
app.get("/", (req, res) => {
  if (req.session.loggedIn) return res.redirect("/chat");

  res.send(`
<!DOCTYPE html>
<html lang="hi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>M Shopping - Online Store</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #e3e6e6; color: #0f1111; font-family: "Amazon Ember", Arial, sans-serif; }
    header { background: #131921; color: white; padding: 10px 20px; display: flex; align-items: center; justify-content: space-between; gap: 20px; position: sticky; top: 0; z-index: 50; }
    .logo { font-size: 28px; font-weight: bold; color: #ff9900; text-decoration: none; font-style: italic; }
    .logo span { color: white; }
    .search-bar { flex-grow: 1; max-width: 800px; display: flex; height: 40px; }
    .search-bar input { width: 100%; padding: 0 15px; border: none; border-radius: 4px 0 0 4px; outline: none; font-size: 15px; }
    .search-bar button { background: #febd69; border: none; padding: 0 20px; border-radius: 0 4px 4px 0; cursor: pointer; font-size: 18px; }
    .header-nav { display: flex; gap: 20px; font-size: 14px; }
    .container { max-width: 1500px; margin: 20px auto; padding: 0 20px; }
    .hero-banner { background: linear-gradient(to bottom, rgba(0,0,0,0.3), transparent), url('https://images.unsplash.com/photo-1607082348824-0a96f2a4b9da?w=1200&q=80') center/cover; height: 300px; border-radius: 8px; display: flex; align-items: flex-end; padding: 30px; margin-bottom: -100px; }
    .hero-banner h1 { color: white; font-size: 36px; text-shadow: 0 2px 4px rgba(0,0,0,0.8); }
    .products-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 20px; position: relative; z-index: 10; }
    .product-card { background: white; border-radius: 8px; padding: 20px; display: flex; flex-direction: column; justify-content: space-between; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
    .product-img-box { height: 200px; display: flex; justify-content: center; align-items: center; margin-bottom: 15px; overflow: hidden; }
    .product-img-box img { max-height: 100%; max-width: 100%; object-fit: contain; }
    .product-title { font-size: 16px; font-weight: 500; line-height: 1.3; margin-bottom: 8px; }
    .rating { color: #ffa41c; font-size: 14px; margin-bottom: 8px; }
    .price { font-size: 22px; color: #0f1111; font-weight: bold; margin-bottom: 12px; }
    .buy-btn { background: #ffd814; border: 1px solid #fcd200; border-radius: 20px; padding: 10px; cursor: pointer; font-weight: bold; text-align: center; }
    .chat-fab { position: fixed; bottom: 30px; right: 30px; background: #232f3e; color: #ff9900; width: 65px; height: 65px; border-radius: 50%; display: flex; justify-content: center; align-items: center; font-size: 30px; cursor: pointer; box-shadow: 0 4px 15px rgba(0,0,0,0.3); border: 2px solid #ff9900; z-index: 99; }
    .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); backdrop-filter: blur(4px); display: none; justify-content: center; align-items: center; z-index: 100; }
    .modal-box { background: white; color: #0f1111; padding: 30px; border-radius: 10px; width: 90%; max-width: 380px; text-align: left; }
    input[type="password"], input[type="text"] { width: 100%; padding: 12px; margin: 8px 0 16px 0; border-radius: 4px; border: 1px solid #a6a6a6; outline: none; }
    .login-btn { width: 100%; padding: 12px; background: #ffd814; border: 1px solid #fcd200; border-radius: 8px; cursor: pointer; font-weight: bold; font-size: 15px; }
  </style>
</head>
<body>

  <header>
    <a href="/" class="logo">M Shopping<span>.in</span></a>
    <div class="search-bar">
      <input type="text" placeholder="Search M Shopping">
      <button>🔍</button>
    </div>
    <div class="header-nav">
      <div>Hello, Sign in<br><b>Account & Lists</b></div>
      <div>Returns<br><b>& Orders</b></div>
    </div>
  </header>

  <div class="container">
    <div class="hero-banner">
      <h1>Welcome to M Shopping</h1>
    </div>

    <div class="products-grid">
      <div class="product-card">
        <div>
          <div class="product-img-box">
            <img src="https://m.media-amazon.com/images/I/71w3oJ7aWyL._AC_SL1500_.jpg" alt="Smartphone">
          </div>
          <div class="product-title">Smartphone 5G (8GB RAM, 128GB Storage) Ultra HD Display</div>
          <div class="rating">█████ 4.5 (1,240)</div>
          <div class="price"><span>₹</span>24,999</div>
        </div>
        <div class="buy-btn" onclick="document.getElementById('chatModal').style.display='flex'">Add to Cart</div>
      </div>

      <div class="product-card">
        <div>
          <div class="product-img-box">
            <img src="https://m.media-amazon.com/images/I/61SSUx1e7KL._AC_SL1500_.jpg" alt="Headphones">
          </div>
          <div class="product-title">Wireless Noise Cancelling Over-Ear Headphones</div>
          <div class="rating">█████ 4.8 (850)</div>
          <div class="price"><span>₹</span>3,499</div>
        </div>
        <div class="buy-btn" onclick="document.getElementById('chatModal').style.display='flex'">Add to Cart</div>
      </div>
    </div>
  </div>

  <div class="chat-fab" onclick="document.getElementById('chatModal').style.display='flex'" title="Live Support Chat">💬</div>

  <div class="modal-overlay" id="chatModal">
    <div class="modal-box">
      <h2>Secure Login / Register</h2>
      <p style="font-size:13px; color:#565959; margin-bottom:15px;">Login to start end-to-end encrypted chat</p>
      <form action="/login" method="POST">
        <label style="font-size:13px; font-weight:bold;">Username</label>
        <input type="text" name="username" placeholder="Enter username" required>
        
        <label style="font-size:13px; font-weight:bold;">Password</label>
        <input type="password" name="password" placeholder="Enter password" required>
        
        <button type="submit" class="login-btn">Login</button>
      </form>
    </div>
  </div>

  <script>
    window.onclick = function(event) {
      const modal = document.getElementById('chatModal');
      if (event.target === modal) modal.style.display = "none";
    }
  </script>
</body>
</html>
  `);
});

// SECURE LOGIN WITH BCRYPT
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const users = loadUsers();
  const key = username.trim().toLowerCase();

  if (!users[key]) {
    // New User Registration with Password Hashing
    const hashedPassword = await bcrypt.hash(password.trim(), 10);
    users[key] = { username: username.trim(), password: hashedPassword };
    saveUsers(users);
  } else {
    // Existing User Authentication
    const isMatch = await bcrypt.compare(password.trim(), users[key].password);
    if (!isMatch) {
      return res.send(`<script>alert("❌ Password Galat Hai!"); window.location.href="/";</script>`);
    }
  }

  req.session.loggedIn = true;
  req.session.username = users[key].username;
  res.redirect("/chat");
});

// LOGOUT
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// CHANGE PASSWORD WITH BCRYPT
app.post("/change-password", async (req, res) => {
  if (!req.session.loggedIn) return res.status(401).json({ error: "Unauthorized" });

  const { oldPassword, newPassword } = req.body;
  const users = loadUsers();
  const key = req.session.username.toLowerCase();

  const isMatch = await bcrypt.compare(oldPassword, users[key].password);
  if (!isMatch) {
    return res.json({ success: false, message: "Purana password galat hai!" });
  }

  users[key].password = await bcrypt.hash(newPassword, 10);
  saveUsers(users);
  res.json({ success: true, message: "Password kamyabi se update ho gaya!" });
});

// UPLOAD FILE
app.post("/upload", upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded or file type restricted!" });
  res.json({
    fileUrl: "/uploads/" + req.file.filename,
    fileName: req.file.originalname,
    fileSize: (req.file.size / 1024 / 1024).toFixed(2) + " MB"
  });
});

// CHAT MAIN SCREEN
app.get("/chat", (req, res) => {
  if (!req.session.loggedIn) return res.redirect("/");

  const isAdmin = req.session.username.toLowerCase() === ADMIN_USER.toLowerCase();

  res.send(`
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>M Shopping Chat</title>
  <script src="/socket.io/socket.io.js"></script>
  <script src="https://unpkg.com/peerjs@1.5.2/dist/peerjs.min.js"></script>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #0b0f19; color: #f3f4f6; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; height: 100vh; display: flex; overflow: hidden; }
    
    .sidebar { width: 340px; background: #0f172a; border-right: 1px solid #1e293b; display: ${isAdmin ? 'flex' : 'none'}; flex-direction: column; z-index: 10; }
    .sidebar-header { padding: 18px; background: #1e293b; border-bottom: 1px solid #334155; display: flex; justify-content: space-between; align-items: center; }
    .inbox-search { padding: 10px 15px; background: #0f172a; border-bottom: 1px solid #1e293b; }
    .inbox-search input { width: 100%; padding: 8px 12px; background: #1e293b; border: 1px solid #334155; border-radius: 8px; color: white; outline: none; }
    .inbox-list { flex: 1; overflow-y: auto; }
    .inbox-item { display: flex; align-items: center; gap: 12px; padding: 14px; cursor: pointer; border-bottom: 1px solid #1e293b; transition: background 0.2s; }
    .inbox-item:hover, .inbox-item.active { background: #1e293b; }
    .avatar { width: 44px; height: 44px; border-radius: 50%; background: linear-gradient(135deg, #ff9900, #e47911); display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 18px; color: black; }
    
    .chat-area { flex: 1; display: flex; flex-direction: column; background: #020617; position: relative; }
    .chat-header { padding: 14px 24px; background: #0f172a; border-bottom: 1px solid #1e293b; display: flex; justify-content: space-between; align-items: center; z-index: 5; }
    .call-btn { background: #1e293b; border: 1px solid #334155; border-radius: 8px; width: 38px; height: 38px; display: inline-flex; justify-content: center; align-items: center; font-size: 18px; cursor: pointer; color: #ff9900; margin-right: 8px; transition: 0.2s; }
    .call-btn:hover { background: #ff9900; color: black; }

    .messages-container { flex: 1; overflow-y: auto; padding: 20px; display: flex; flex-direction: column; gap: 12px; background-size: cover; background-position: center; transition: background 0.3s ease; }
    
    .msg { max-width: 60%; padding: 12px 16px; border-radius: 18px; font-size: 15px; position: relative; word-wrap: break-word; box-shadow: 0 4px 10px rgba(0,0,0,0.3); user-select: none; cursor: pointer; }
    .sent { background: linear-gradient(135deg, #0284c7, #2563eb); color: white; align-self: flex-end; border-bottom-right-radius: 4px; }
    .received { background: #1e293b; color: #f1f5f9; align-self: flex-start; border-bottom-left-radius: 4px; border: 1px solid #334155; }
    .media-preview { max-width: 100%; max-height: 320px; border-radius: 12px; margin-top: 8px; border: 1px solid rgba(255,255,255,0.1); }

    .input-bar { padding: 14px 20px; background: #0f172a; border-top: 1px solid #1e293b; display: flex; align-items: center; gap: 10px; position: relative; z-index: 5; }
    .input-bar input[type="text"] { flex: 1; background: #020617; border: 1px solid #334155; padding: 12px 18px; border-radius: 25px; color: white; outline: none; font-size: 15px; }
    .btn { background: #ff9900; color: black; border: none; padding: 10px 18px; border-radius: 20px; cursor: pointer; font-size: 14px; font-weight: bold; }
    .btn-danger { background: linear-gradient(90deg, #ef4444, #dc2626); color: white; }

    /* CALL SCREEN MODAL */
    .call-modal { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(2, 6, 23, 0.95); backdrop-filter: blur(12px); display: none; flex-direction: column; justify-content: center; align-items: center; z-index: 300; }
    .video-grid { display: flex; gap: 20px; margin-bottom: 20px; width: 90%; max-width: 900px; justify-content: center; }
    video { width: 48%; max-height: 450px; background: #0f172a; border-radius: 16px; border: 2px solid #ff9900; transform: scaleX(-1); object-fit: cover; }
    .timer-badge { font-size: 20px; font-weight: bold; color: #10b981; background: #1e293b; padding: 6px 16px; border-radius: 20px; margin-bottom: 15px; border: 1px solid #334155; }

    /* INSTAGRAM STYLE INCOMING CALL POPUP */
    .incoming-call-overlay { position: fixed; top: 30px; right: 30px; background: #0f172a; border: 2px solid #ff9900; padding: 20px 25px; border-radius: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.8); display: none; align-items: center; gap: 18px; z-index: 400; animation: bounceIn 0.5s ease; }
    @keyframes bounceIn { 0% { transform: translateY(-50px); opacity: 0; } 100% { transform: translateY(0); opacity: 1; } }
    .caller-avatar { width: 50px; height: 50px; border-radius: 50%; background: #ff9900; color: black; font-weight: bold; font-size: 22px; display: flex; justify-content: center; align-items: center; }
    .call-actions { display: flex; gap: 12px; }
    .action-btn { width: 45px; height: 45px; border-radius: 50%; border: none; font-size: 20px; cursor: pointer; display: flex; justify-content: center; align-items: center; color: white; transition: 0.2s; }
    .accept-btn { background: #10b981; }
    .decline-btn { background: #ef4444; }
    .action-btn:hover { transform: scale(1.1); }
  </style>
</head>
<body>

  <!-- ADMIN SIDEBAR -->
  <div class="sidebar">
    <div class="sidebar-header">
      <b>👑 ${req.session.username} (Admin)</b>
      <button class="btn btn-danger" style="font-size:12px; padding:6px 12px;" onclick="logout()">Logout</button>
    </div>
    <div class="inbox-search">
      <input type="text" id="userSearch" placeholder="Search chats..." onkeyup="filterUsers()">
    </div>
    <div class="inbox-list" id="inboxList"></div>
  </div>

  <!-- CHAT AREA -->
  <div class="chat-area">
    <div class="chat-header">
      <div style="display:flex; align-items:center; gap:12px;">
        <div class="avatar" id="headerAvatar">?</div>
        <div>
          <div id="headerUsername" style="font-weight:bold; font-size:16px;">Connecting...</div>
          <small id="headerStatus" style="color:#10b981;">Online</small>
        </div>
      </div>
      <div style="display:flex; align-items:center;">
        <button class="call-btn" onclick="startCall(false)" title="Audio Call">📞</button>
        <button class="call-btn" onclick="startCall(true)" title="Video Call">📹</button>
        
        <label class="call-btn" title="Change Background Wallpaper" style="cursor:pointer;">
          🖼️️<input type="file" id="bgInput" accept="image/*" hidden onchange="uploadBackground()">
        </label>
        <button class="call-btn" onclick="removeBackground()" title="Remove Wallpaper" style="font-size:15px; color:#ef4444;">🗑️</button>

        <a href="/" class="btn" style="text-decoration:none; margin-left:8px;">🛒 Store</a>
        <button class="btn" style="margin-left:8px;" onclick="openPasswordModal()">⚙ Password</button>
        <button class="btn btn-danger" style="margin-left:8px;" onclick="logout()">Logout</button>
      </div>
    </div>

    <!-- MESSAGES CONTAINER -->
    <div class="messages-container" id="messagesContainer"></div>

    <!-- INPUT BAR -->
    <div class="input-bar">
      <label style="cursor:pointer;" title="Attach File">
        📎<input type="file" id="fileInput" hidden onchange="uploadFile()">
      </label>
      <input type="text" id="msgInput" placeholder="Write a message..." onkeypress="if(event.key==='Enter') sendMessage()">
      <button class="btn" onclick="sendMessage()">Send</button>
    </div>
  </div>

  <!-- INSTAGRAM STYLE INCOMING CALL POPUP -->
  <div class="incoming-call-overlay" id="incomingCallPopup">
    <div class="caller-avatar" id="popupAvatar">U</div>
    <div>
      <h4 id="popupCallerName" style="color:white; margin-bottom: 2px;">User</h4>
      <small style="color:#10b981;" id="popupCallType">Incoming Call...</small>
    </div>
    <div class="call-actions">
      <button class="action-btn accept-btn" onclick="acceptIncomingCall()" title="Answer">📞</button>
      <button class="action-btn decline-btn" onclick="declineIncomingCall()" title="Decline">✖</button>
    </div>
  </div>

  <!-- CALL SCREEN MODAL WITH TIMER -->
  <div class="call-modal" id="callModal">
    <h2 id="callStatus" style="margin-bottom: 10px; color:#ff9900;">Calling...</h2>
    <div class="timer-badge" id="callTimer">00:00</div>
    <div class="video-grid">
      <video id="localVideo" autoplay muted playsinline></video>
      <video id="remoteVideo" autoplay playsinline></video>
    </div>
    <button class="btn btn-danger" style="padding: 12px 30px; font-size: 18px;" onclick="endCall()">End Call 🛑</button>
  </div>

  <script>
    const socket = io();
    const currentUser = "${req.session.username}";
    const isAdmin = ${isAdmin};
    const adminUser = "${ADMIN_USER}";
    
    let selectedUser = isAdmin ? null : adminUser;
    let allHistory = [];
    let activeUserList = {};
    let peer, localStream, currentCall, incomingCallSession = null;
    
    let timerInterval = null;
    let secondsElapsed = 0;

    socket.on('connect', () => {
      socket.emit('register_user', currentUser);
    });

    socket.on('active_users_update', (users) => {
      activeUserList = users;
      renderInbox();
      updateHeaderStatus();
    });

    socket.on('call_declined', ({ sender }) => {
      alert("🚫 Call declined by " + sender);
      endCall();
    });

    peer = new Peer(currentUser.toLowerCase());
    
    peer.on('call', (call) => {
      incomingCallSession = call;
      const callerName = call.peer.toUpperCase();

      document.getElementById('popupCallerName').innerText = callerName;
      document.getElementById('popupAvatar').innerText = callerName.charAt(0);
      document.getElementById('incomingCallPopup').style.display = 'flex';
    });

    function acceptIncomingCall() {
      if (!incomingCallSession) return;
      document.getElementById('incomingCallPopup').style.display = 'none';

      navigator.mediaDevices.getUserMedia({ video: true, audio: true }).then((stream) => {
        localStream = stream;
        document.getElementById('localVideo').srcObject = stream;
        
        incomingCallSession.answer(stream);
        document.getElementById('callModal').style.display = 'flex';
        document.getElementById('callStatus').innerText = "Connected with " + incomingCallSession.peer.toUpperCase();
        
        incomingCallSession.on('stream', (remoteStream) => {
          const remoteVideo = document.getElementById('remoteVideo');
          remoteVideo.srcObject = remoteStream;
          remoteVideo.play().catch(e => console.log("Audio play error:", e));
          startCallTimer();
        });

        currentCall = incomingCallSession;
      }).catch(err => alert("Camera/Mic Access Required: " + err));
    }

    function declineIncomingCall() {
      document.getElementById('incomingCallPopup').style.display = 'none';
      if (incomingCallSession) {
        socket.emit('decline_call', { targetUser: incomingCallSession.peer, sender: currentUser });
        incomingCallSession.close();
        incomingCallSession = null;
      }
    }

    function startCall(isVideo) {
      if (!selectedUser) return alert("Pehle kisi user ko select karein!");
      
      const isTargetOnline = activeUserList[selectedUser.toLowerCase()];
      const callModal = document.getElementById('callModal');
      const callStatus = document.getElementById('callStatus');

      callModal.style.display = 'flex';
      resetCallTimer();

      callStatus.innerText = isTargetOnline ? ("🔔 Ringing " + selectedUser + "...") : ("📵 " + selectedUser + " is Offline");

      navigator.mediaDevices.getUserMedia({ video: isVideo, audio: true }).then((stream) => {
        localStream = stream;
        document.getElementById('localVideo').srcObject = stream;

        const call = peer.call(selectedUser.toLowerCase(), stream);
        
        call.on('stream', (remoteStream) => {
          callStatus.innerText = "Connected with " + selectedUser;
          const remoteVideo = document.getElementById('remoteVideo');
          remoteVideo.srcObject = remoteStream;
          remoteVideo.play().catch(e => console.log("Audio play error:", e));
          startCallTimer();
        });

        currentCall = call;
      }).catch(err => {
        alert("Camera/Mic access denied!");
        endCall();
      });
    }

    function startCallTimer() {
      if (timerInterval) clearInterval(timerInterval);
      secondsElapsed = 0;
      timerInterval = setInterval(() => {
        secondsElapsed++;
        const mins = String(Math.floor(secondsElapsed / 60)).padStart(2, '0');
        const secs = String(secondsElapsed % 60).padStart(2, '0');
        document.getElementById('callTimer').innerText = mins + ":" + secs;
      }, 1000);
    }

    function resetCallTimer() {
      if (timerInterval) clearInterval(timerInterval);
      secondsElapsed = 0;
      document.getElementById('callTimer').innerText = "00:00";
    }

    function endCall() {
      resetCallTimer();
      if (currentCall) currentCall.close();
      if (localStream) localStream.getTracks().forEach(track => track.stop());
      document.getElementById('callModal').style.display = 'none';
      document.getElementById('incomingCallPopup').style.display = 'none';
    }

    socket.on('chat_history', (history) => {
      allHistory = history;
      renderInbox();
      renderMessages();
    });

    socket.on('new_message', (msg) => {
      allHistory.push(msg);
      renderInbox();
      if (shouldShowMsg(msg)) renderMessages();
    });

    socket.on('bg_updated', ({ user, bgUrl }) => {
      if (selectedUser === user || (!isAdmin && user === adminUser)) {
        applyBackground(bgUrl);
      }
    });

    function shouldShowMsg(m) {
      if (!selectedUser) return false;
      const s = currentUser.toLowerCase();
      const t = selectedUser.toLowerCase();
      const sender = m.sender.toLowerCase();
      const receiver = m.receiver.toLowerCase();
      return (sender === s && receiver === t) || (sender === t && receiver === s);
    }

    function renderMessages() {
      const container = document.getElementById('messagesContainer');
      container.innerHTML = '';
      
      const filtered = allHistory.filter(shouldShowMsg);
      filtered.forEach(m => {
        const isSent = m.sender.toLowerCase() === currentUser.toLowerCase();
        const div = document.createElement('div');
        div.className = "msg " + (isSent ? "sent" : "received");
        
        let contentHtml = m.text || '';
        if (m.type === 'image') contentHtml = '<img src="' + m.fileUrl + '" class="media-preview">';
        else if (m.type === 'video') contentHtml = '<video src="' + m.fileUrl + '" controls class="media-preview"></video>';

        div.innerHTML = contentHtml;
        container.appendChild(div);
      });

      container.scrollTop = container.scrollHeight;
    }

    function sendMessage() {
      const input = document.getElementById('msgInput');
      const text = input.value.trim();
      if (!text || !selectedUser) return;

      socket.emit('send_message', {
        sender: currentUser,
        receiver: selectedUser,
        type: 'text',
        text: text
      });

      input.value = '';
    }

    function uploadBackground() {
      const file = document.getElementById('bgInput').files[0];
      if (!file) return;

      const formData = new FormData();
      formData.append('file', file);

      fetch('/upload', { method: 'POST', body: formData })
        .then(res => res.json())
        .then(data => {
          socket.emit('set_background', { user: currentUser, bgUrl: data.fileUrl });
          applyBackground(data.fileUrl);
        });
    }

    function removeBackground() {
      socket.emit('set_background', { user: currentUser, bgUrl: null });
      applyBackground(null);
    }

    function applyBackground(url) {
      const container = document.getElementById('messagesContainer');
      if (url) {
        container.style.backgroundImage = "url('" + url + "')";
      } else {
        container.style.backgroundImage = 'none';
      }
    }

    function uploadFile() {
      const file = document.getElementById('fileInput').files[0];
      if (!file || !selectedUser) return;

      const formData = new FormData();
      formData.append('file', file);

      fetch('/upload', { method: 'POST', body: formData })
        .then(res => res.json())
        .then(data => {
          let type = 'file';
          if (file.type.startsWith('image/')) type = 'image';
          else if (file.type.startsWith('video/')) type = 'video';

          socket.emit('send_message', {
            sender: currentUser,
            receiver: selectedUser,
            type: type,
            fileUrl: data.fileUrl
          });
        });
    }

    function renderInbox() {
      if (!isAdmin) {
        selectedUser = adminUser;
        updateHeaderStatus();
        return;
      }

      const inbox = document.getElementById('inboxList');
      inbox.innerHTML = '';

      const users = new Set();
      allHistory.forEach(m => {
        if (m.sender !== currentUser) users.add(m.sender);
        if (m.receiver !== currentUser) users.add(m.receiver);
      });

      users.forEach(u => {
        const div = document.createElement('div');
        div.className = "inbox-item " + (selectedUser === u ? "active" : "");
        const isOnline = activeUserList[u.toLowerCase()];

        div.onclick = () => {
          selectedUser = u;
          renderInbox();
          renderMessages();
          updateHeaderStatus();
        };

        div.innerHTML = \`
          <div class="avatar">\${u.charAt(0).toUpperCase()}</div>
          <div style="flex:1;">
            <div style="font-weight:bold;">\${u}</div>
            <small style="color:\${isOnline ? '#10b981' : '#64748b'};">\${isOnline ? 'Online' : 'Offline'}</small>
          </div>
        \`;
        inbox.appendChild(div);
      });

      if (!selectedUser && users.size > 0) {
        selectedUser = Array.from(users)[0];
        renderMessages();
        updateHeaderStatus();
      }
    }

    function updateHeaderStatus() {
      if (!selectedUser) return;
      document.getElementById('headerUsername').innerText = selectedUser;
      document.getElementById('headerAvatar').innerText = selectedUser.charAt(0).toUpperCase();

      const isOnline = activeUserList[selectedUser.toLowerCase()];
      const status = document.getElementById('headerStatus');
      status.innerText = isOnline ? 'Online' : 'Offline';
      status.style.color = isOnline ? '#10b981' : '#64748b';
    }

    function logout() {
      window.location.href = '/logout';
    }

    function openPasswordModal() {
      const oldP = prompt("Purana Password dalein:");
      if (!oldP) return;
      const newP = prompt("Naya Password dalein:");
      if (!newP) return;

      fetch('/change-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ oldPassword: oldP, newPassword: newP })
      })
      .then(r => r.json())
      .then(d => alert(d.message));
    }

    function filterUsers() {
      const input = document.getElementById('userSearch').value.toLowerCase();
      const items = document.getElementsByClassName('inbox-item');
      Array.from(items).forEach(item => {
        const text = item.innerText.toLowerCase();
        item.style.display = text.includes(input) ? 'flex' : 'none';
      });
    }
  </script>
</body>
</html>
  `);
});

// SOCKET SERVER
io.on("connection", (socket) => {
  socket.emit("chat_history", loadChatHistory());

  socket.on("register_user", (username) => {
    socket.username = username;
    activeUsers[username.toLowerCase()] = socket.id;
    io.emit("active_users_update", activeUsers);
  });

  socket.on("send_message", (msgData) => {
    const history = loadChatHistory();
    const newMsg = {
      id: Date.now().toString(),
      sender: msgData.sender,
      receiver: msgData.receiver,
      type: msgData.type,
      text: msgData.text || "",
      fileUrl: msgData.fileUrl || ""
    };

    history.push(newMsg);
    saveChatHistory(history);
    io.emit("new_message", newMsg);
  });

  socket.on("set_background", ({ user, bgUrl }) => {
    chatBackgrounds[user] = bgUrl;
    io.emit("bg_updated", { user, bgUrl });
  });

  socket.on("decline_call", ({ targetUser, sender }) => {
    const targetSocketId = activeUsers[targetUser.toLowerCase()];
    if (targetSocketId) {
      io.to(targetSocketId).emit("call_declined", { sender });
    }
  });

  socket.on("disconnect", () => {
    if (socket.username) {
      delete activeUsers[socket.username.toLowerCase()];
      io.emit("active_users_update", activeUsers);
    }
  });
});

server.listen(PORT, () => {
  console.log(`M Shopping Secured Server running on http://localhost:${PORT}`);
});