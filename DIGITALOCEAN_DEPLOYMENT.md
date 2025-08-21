# Deploy P2P Bootstrap Node to DigitalOcean

## Step 1: Create DigitalOcean Droplet

1. Go to [DigitalOcean.com](https://digitalocean.com)
2. Create account and login
3. Click **"Create Droplet"**
4. Choose:
   - **Image**: Ubuntu 25.04 x64
   - **Size**: Basic ($6/month) - 1 vCPU, 1GB RAM, 25GB disk
   - **Region**: Choose closest to you (NYC3, SFO3, etc.)
   - **Authentication**: Password (easier) or SSH Key
5. Click **"Create Droplet"**
6. Wait for it to boot up
7. **Copy the IPv4 address** (example: `157.245.208.60`)

## Step 2: Connect to Your Server

**Open Terminal on your local machine** and run:

```bash
ssh root@YOUR_IP_ADDRESS
```

Replace `YOUR_IP_ADDRESS` with your actual IP (like `157.245.208.60`)

- It will ask about authenticity - type `yes`
- Enter your password when prompted
- You should see: `root@ubuntu-s-1vcpu-1gb-nyc3-01:~#`

**YOU ARE NOW ON THE SERVER** - all following commands run here!

## Step 3: Install Dependencies

**Copy/paste these commands ONE AT A TIME:**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
Press Enter when it asks (choose default option 1)

```bash
source "$HOME/.cargo/env"
```

```bash
apt update && apt install -y git build-essential pkg-config libssl-dev
```

## Step 4: Get Your Code

**Make sure your GitHub repo is PUBLIC**, then:

```bash
git clone https://github.com/AudioLedger/heart-earth.git
```

```bash
cd heart-earth
```

## Step 5: Build and Run

```bash
cargo build --release -p p2p --bin bootstrap
```
(This takes 5-10 minutes to build)

```bash
./target/release/bootstrap
```

**Your P2P bootstrap is now running!**

## Step 6: Update Client Configuration

On your **local machine**, update `.env` file:

```bash
BOOTSTRAP_PEER_ID=[copy the Peer ID from server output]
BOOTSTRAP_ADDRESS=/ip4/YOUR_IP_ADDRESS/tcp/4001
```

## Step 7: Test Connection

Run your client locally:

```bash
cargo run --release -p p2p --bin client login --name default
```

You should connect to your DigitalOcean bootstrap node!

## Making it Run 24/7 (Optional)

To keep it running when you close terminal:

```bash
nohup ./target/release/bootstrap > bootstrap.log 2>&1 &
```

## Costs
- **$6/month** for DigitalOcean droplet
- **Reliable 24/7** P2P bootstrap node
- **Static IP address** that never changes

## Troubleshooting

**Can't SSH?** 
- Check your IP address is correct
- Check your password
- Try again after 2-3 minutes

**Git clone fails?**
- Make sure your GitHub repo is public
- Try the command again

**Build fails?**
- Make sure you're in the `heart-earth` directory: `cd heart-earth`
- Check you have internet connection on the server

## Alternative: Free Local Testing

If you don't want to pay $6/month:

1. Run bootstrap locally: `cargo run --release -p p2p --bin bootstrap`
2. Share your local IP with users
3. Only works when your computer is on