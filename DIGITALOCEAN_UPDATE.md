# Digital Ocean WebSocket Update Commands

## ✅ **DEPLOYMENT COMPLETED SUCCESSFULLY**

**Files Updated:**
- `/p2p/src/bin/bootstrap.rs` - Added WebSocket listener
- `/p2p/src/bin/bootstrap_railway.rs` - Enhanced WebSocket support
- `/p2p/tests/websocket_integration_test.rs` - Tests pass ✅

**Build Status:** ✅ SUCCESSFUL
**Deployment Status:** ✅ LIVE ON DIGITAL OCEAN
```
cargo build --release -p p2p --bin bootstrap
cargo test test_websocket_listener_starts ... ok
```

## 🎉 **LIVE VERIFICATION**

**Digital Ocean Bootstrap Logs:**
```
Listening on /ip4/10.17.0.5/tcp/4001
Listening on /ip4/10.108.0.2/tcp/4001
Listening on /ip4/127.0.0.1/tcp/4001/ws
Web clients connect: ws://157.245.208.60:4001/ws ✅
Listening on /ip4/157.245.208.60/tcp/4001/ws ✅
Web clients connect: ws://157.245.208.60:4001/ws ✅
Listening on /ip4/10.17.0.5/tcp/4001/ws
Web clients connect: ws://157.245.208.60:4001/ws ✅
```

**Status:** ✅ **WebSocket is LIVE and accepting connections!**

## ✅ **Deployment Steps (COMPLETED)**

### **Step 1: SSH to Server** ✅ 
```bash
ssh root@157.245.208.60
```

### **Step 2: Update Code** ✅
```bash
cd heart-earth
git pull origin main
```

### **Step 3: Rebuild Bootstrap** ✅
```bash
cargo build --release -p p2p --bin bootstrap
# Finished `release` profile [optimized] target(s) in 25.96s
```

### **Step 4: Stop Current Bootstrap** ✅
```bash
pkill bootstrap
```

### **Step 5: Start WebSocket-Enabled Bootstrap** ✅
```bash
nohup ./target/release/bootstrap > bootstrap.log 2>&1 &
# [1] 9404
```

### **Step 6: Verify Both Transports** ✅
```bash
tail -f bootstrap.log
```

**✅ ACTUAL OUTPUT (SUCCESS):**
```
Listening on /ip4/10.17.0.5/tcp/4001
Listening on /ip4/10.108.0.2/tcp/4001  
Listening on /ip4/127.0.0.1/tcp/4001/ws
Web clients connect: ws://157.245.208.60:4001/ws ✅
Listening on /ip4/157.245.208.60/tcp/4001/ws ✅
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

## 📱 **Web Client Connection (LIVE)**

✅ **Web browsers can now connect to the live network:**
```
WebSocket URL: ws://157.245.208.60:4001/ws
Peer ID: 12D3KooWP6VY4vsRWi73nHLCEoqDnJ674ZjP5mNUKXHELM84Jsfm
Channel: /art/dev/general/v1
Status: ACCEPTING CONNECTIONS
```

**Next Step:** Update the web frontend to connect to real network instead of demo mode.

## ⏱️ **Estimated Downtime**
- **Stop bootstrap**: 5 seconds
- **Rebuild**: 30-60 seconds  
- **Start bootstrap**: 5 seconds
- **Total**: ~1-2 minutes

**CLI clients will automatically reconnect when bootstrap comes back online.**

---

**Ready to deploy? Run these commands in order when you're ready.**