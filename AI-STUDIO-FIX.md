# AI Studio Service Fix - 2026-09-17

## Status
🔴 **BLOCKED** - Service divergence + Windows Firewall blocking port 8300
✅ **Backend running** - ai-studio service healthy on port 8300
❌ **Not accessible** - Reverse proxy returns 503 Service Unavailable

## Root Cause Analysis

### Service Divergence
Two separate ai-studio installations exist on the Windows box:

| Aspect | Configured (Selfhost) | Actually Running |
|--------|----------------------|-----------------|
| Location | `C:\Users\Alex\Self-Host\checkouts\ai-studio` | `D:\SARA\ai-studio` |
| Manager | Selfhost daemon (configured but never started) | Windows Scheduled Task + PowerShell wrapper |
| Status | ❌ Failed to start | ✅ Running (PID 6044, python.exe) |
| Port | 8300 (configured) | 8300 (actual) |
| Health | N/A | HTTP 200 verified |

### Why Reverse Proxy Returns 503

```
Client Request: https://ai.rockywearsahat.com
    ↓
Reverse Proxy: Routes to localhost:8300 (configured)
    ↓
TcpStream::connect(127.0.0.1:8300) → FAILS
    ├─ Reason 1: Windows Firewall blocks inbound port 8300
    └─ Reason 2: Service divergence (configured ≠ actual)
    ↓
Response: 502 Bad Gateway / 503 Service Unavailable
```

## Solution: Two Options

### ✅ Option A: Quick Firewall Fix (5 min) - RECOMMENDED FOR NOW

Run these PowerShell commands **as Administrator** on the Windows box:

```powershell
# Add inbound firewall rule for port 8300
New-NetFirewallRule `
  -DisplayName "Allow ai-studio 8300" `
  -Direction Inbound `
  -LocalPort 8300 `
  -Protocol TCP `
  -Action Allow

# Verify it was created
Get-NetFirewallRule -DisplayName "Allow ai-studio 8300"

# Test from the box itself
curl http://127.0.0.1:8300/health
```

**Expected result:** Should return `{"status":"ok"}` and firewall rule is created.

After this, test from your Mac:
```bash
# Through VPN tunnel
curl -v https://ai.rockywearsahat.com
```

---

### ✅ Option B: Consolidate Service Configuration (15 min) - LONG-TERM

**Goal:** Retire the unused `checkouts/ai-studio` path and make selfhost manage the real service at `D:\SARA\ai-studio`.

**Steps:**
1. Update selfhost service registry:
   - Current: `C:\Users\Alex\Self-Host\checkouts\ai-studio`
   - Change to: `D:\SARA\ai-studio`
2. Update service build/run commands to match D:\SARA setup
3. Disable Windows Scheduled Task (selfhost will handle startup)
4. Apply firewall rule from Option A
5. Verify: `selfhost services show ai-studio` should show status: RUNNING

---

## Verification Steps

Once firewall rule is added:

```bash
# 1. From Mac through VPN, test the site loads
open https://ai.rockywearsahat.com

# 2. Check Chrome DevTools - should be 200 OK (not 502/503)

# 3. Verify page content loads (not error page)
```

**Expected:** Page loads without errors, no 503 response.

---

## Files Involved

- **Reverse Proxy Source:** `crates/app/proxy/src/server.rs` (line 2372 - `forward()` function)
- **Configured Service:** Selfhost daemon registry
- **Actual Service:** `D:\SARA\ai-studio` (Windows Scheduled Task)
- **Unused Path:** `C:\Users\Alex\Self-Host\checkouts\ai-studio`

---

## Next Steps

**Immediate (today):**
1. Choose Option A or Option B
2. Execute the fix
3. Test ai.rockywearsahat.com through VPN

**If choosing Option A:** 
- Just run the firewall commands, test, and report back

**If choosing Option B:**
- I can push a fix to GitHub to update selfhost configuration
- Use GitHub webhook to auto-deploy the service changes
- Verify the consolidated setup works

---

## Related Issues

- Service divergence prevents unified management
- Firewall rules not documented in setup scripts
- No "auto-firewall-rule" provisioning for services on Windows

