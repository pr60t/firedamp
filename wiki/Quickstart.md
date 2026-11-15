# 🚀 Quickstart Guide

Get Firedamp installed and run your first isolation audit in less than two minutes.

---

### Step 1: Install Firedamp

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
To see the terminal telemetry report and simulated canary detection without needing Docker:

```bash
firedamp scan --dry-run
```

---

### Step 3: Run an Audit Against a Live Open WebUI Instance
If you have Open WebUI running locally (e.g., at `http://localhost:8080`):

```bash
firedamp scan --target-url http://localhost:8080
```

**What happens behind the scenes:**
1. Firedamp automatically creates a test data owner (**Alice**) and an unprivileged attacker (**Bob**).
2. Plants 4 decoy documents containing unique tokens (`CANARY-FRDP-...`) into Alice's private collection.
3. Verifies Alice can retrieve her own canaries (positive baseline check).
4. Fires adversarial retrieval queries as Bob.
5. Displays the atmospheric report card.
6. Automatically cleans up all test documents, knowledge collections, and sessions.

