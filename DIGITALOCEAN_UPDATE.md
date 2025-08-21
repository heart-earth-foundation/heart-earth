# Digital Ocean WebSocket Update Commands

## ✅ **Changes Made Successfully**

**Files Updated:**
- `/p2p/src/bin/bootstrap.rs` - Added WebSocket listener
- `/p2p/src/bin/bootstrap_railway.rs` - Enhanced WebSocket support
- `/p2p/tests/websocket_integration_test.rs` - Tests pass ✅

**Build Status:** ✅ SUCCESSFUL
```
cargo build --release -p p2p --bin bootstrap
cargo test test_websocket_listener_starts ... ok
```

## 🚀 **Digital Ocean Deployment Steps**

### **Step 1: SSH to Server**
```bash
ssh root@157.245.208.60
```

### **Step 2: Update Code**
```bash
cd heart-earth
git pull origin main
```

### **Step 3: Rebuild Bootstrap**
```bash
cargo build --release -p p2p --bin bootstrap
```

### **Step 4: Stop Current Bootstrap**
```bash
pkill bootstrap
```

### **Step 5: Start WebSocket-Enabled Bootstrap**
```bash
nohup ./target/release/bootstrap > bootstrap.log 2>&1 &
```

### **Step 6: Verify Both Transports**
```bash
tail -f bootstrap.log
```

**Expected Output:**
```
Bootstrap node starting...
Peer ID: 12D3KooWP6VY4vsRWi73nHLCEoqDnJ674ZjP5mNUKXHELM84Jsfm
Developer channel: /art/dev/general/v1
Listening on /ip4/0.0.0.0/tcp/4001
Listening on /ip4/0.0.0.0/tcp/4001/ws
Web clients connect: ws://157.245.208.60:4001/ws
HTTP health server listening on 0.0.0.0:3000
```

### **Step 7: Test Connections**

**TCP Test (existing CLI clients):**
```bash
echo "test" | nc 157.245.208.60 4001
```

**WebSocket Test:**
```bash
# From local machine with wscat installed
wscat -c ws://157.245.208.60:4001/ws
```

## 🔍 **Verification Commands**

**Check if bootstrap is running:**
```bash
ps aux | grep bootstrap
```

**Check logs:**
```bash
tail -20 bootstrap.log
```

**Check port listeners:**
```bash
netstat -tlnp | grep 4001
```
Should show:
- TCP: `0.0.0.0:4001` 
- Same process listening on both

## 🚨 **Rollback Plan (If Needed)**

If something goes wrong:
```bash
# Stop new version
pkill bootstrap

# Get previous working version from git
git checkout HEAD~1 p2p/src/bin/bootstrap.rs

# Rebuild and restart
cargo build --release -p p2p --bin bootstrap
nohup ./target/release/bootstrap > bootstrap.log 2>&1 &
```

## 📱 **Web Client Connection**

Once deployed, web browsers can connect using:
```
WebSocket URL: ws://157.245.208.60:4001/ws
Peer ID: 12D3KooWP6VY4vsRWi73nHLCEoqDnJ674ZjP5mNUKXHELM84Jsfm
Channel: /art/dev/general/v1
```

## ⏱️ **Estimated Downtime**
- **Stop bootstrap**: 5 seconds
- **Rebuild**: 30-60 seconds  
- **Start bootstrap**: 5 seconds
- **Total**: ~1-2 minutes

**CLI clients will automatically reconnect when bootstrap comes back online.**

---

**Ready to deploy? Run these commands in order when you're ready.**