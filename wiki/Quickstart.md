# 🚀 Quickstart Guide

Get Firedamp installed and run your first isolation audit in less than two minutes.

---

### Step 1: Install Firedamp

#### Option A: Release-Pinned Linux Installer Script
Download the `v0.1.0` installer to a temporary file, inspect it, and run it:
```bash
curl -fsSL https://raw.githubusercontent.com/pr60t/firedamp/v0.1.0/install.sh -o /tmp/firedamp-install.sh
less /tmp/firedamp-install.sh
bash /tmp/firedamp-install.sh
```

#### Option B: Manual Setup from Source (Recommended Cross-Platform)
```bash
# 1. Clone the repository
git clone https://github.com/pr60t/firedamp.git
cd firedamp

# 2. Set up virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -e .
```

Verify your installation:
```bash
firedamp version
```

---

### Step 2: Run a Simulation Scan (No Setup Needed)
To see the terminal telemetry report and simulated canary detection without needing Docker or network:

```bash
firedamp scan --dry-run
```

---

### Step 3: Run an Audit Against a Target Instance

#### Mode A: Existing Identities (Default)
Run against a local or remote target using pre-existing test persona credentials (see `.env.example`):

```bash
export FIREDAMP_ALICE_USERNAME="alice_owner"
export FIREDAMP_ALICE_PASSWORD="<alice-password>"
export FIREDAMP_BOB_USERNAME="bob_attacker"
export FIREDAMP_BOB_PASSWORD="<bob-password>"

firedamp scan --target-url http://localhost:8080
```

#### Mode B: Optional Dynamic Provisioning
In an isolated dev/lab environment with administrative access:

```bash
export FIREDAMP_PROVISION_ADMIN_TOKEN="<admin-jwt-token>"

firedamp scan --target-url http://localhost:8080 --identity-mode provision --confirm-provisioning
```

> ⚠️ **Permission Notice:** Only run Firedamp against systems you own or have explicit written permission to test. Use disposable local/dev instances.

**What happens behind the scenes:**
1. Firedamp resolves and verifies test personas (**Alice** as data owner, **Bob** as unprivileged attacker).
   - In **Existing Mode**: authenticates existing accounts, verifies independent sessions, and never deletes operator accounts.
   - In **Provisioning Mode**: provisions run-scoped accounts with strong random passwords (`secrets` module), records them in a secure journal (`0600`), and decommissions them upon completion.
2. Plants 4 decoy documents containing unique tokens (`CANARY-FRDP-...`) into Alice's private collection.
3. Verifies Alice can retrieve her own canaries (positive baseline check).
4. Fires adversarial retrieval queries as Bob.
5. Displays the atmospheric report card.
6. Automatically cleans up test files and knowledge collections. In provisioning mode, Bob and Alice accounts are also cleanly deleted and verified. If an audit is interrupted, recover with `firedamp cleanup-identities --run-id <RUN_ID>`.

