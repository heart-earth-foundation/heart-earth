# Server Deployment Instructions

## Quick Deploy Process

### 1. Commit Changes Locally
```bash
cd /Users/cliff/Desktop/heart-earth
git add .
git commit -m "Your commit message"
```

### 2. Push to GitHub (with token)
```bash
git remote set-url origin https://YOUR_TOKEN@github.com/heart-earth-foundation/heart-earth.git
git push origin main
```

### 3. Deploy on Server
```bash
ssh root@157.245.208.60
cd heart-earth
git pull origin main
cargo build --release -p p2p --bin bootstrap
pkill bootstrap
nohup ./target/release/bootstrap > bootstrap.log 2>&1 &
curl localhost:3000/health
```

### 4. Verify Deployment
Should return: `OK`

## Notes
- Always build on Linux server (not macOS)
- Use token for GitHub authentication
- Check health endpoint to verify success
- Logs available in `bootstrap.log`