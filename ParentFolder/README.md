# Banking Management & Security System (CLI)

A concurrent, text-file-based, POSIX socket Banking System with single-session control, atomic OS file locking, and real-time transaction anomaly monitoring.

## 🚀 Quick Start

### 1. Build the project
```bash
./build.sh
```
*(Or use `make` if installed)*

### 2. Start the Bank Server
In Terminal 1:
```bash
./server 8080
```

### 3. Launch the Client(s)
In Terminal 2 (and any additional terminals):
```bash
./client 8080
```

---

## 👥 Default Accounts & Roles

| Role | Username | Password | Purpose |
| :--- | :--- | :--- | :--- |
| **Administrator** | `admin` | `admin123` | Add bank staff, modify roles, reset passwords |
| **Manager** | `manager` | `manager123` | Review anomaly alerts, unfreeze accounts, assign loans |
| **Employee** | `emp1` | `emp123` | Create customers, view passbooks, process loans |
| **Customer 1** | `alice` | `alice123` | Account #1 (Initial Balance: ₹1,000.00) |
| **Customer 2** | `bob` | `bob123` | Account #2 (Initial Balance: ₹500.00) |

---

## 🛡️ Key Architectural Features

1. **Text-File Database with OS-Level Locking (`fcntl`)**:
   - `data/bank.lock` handles concurrency.
   - Atomic file updates write to temporary files, `fsync()`, and `rename()` over the target file.
2. **Single-Session Enforcement**:
   - `data/sessions/<user_id>.lock` guarantees exactly one active terminal per user.
   - If a client disconnects or crashes, the OS kernel automatically releases the lock.
3. **Transaction Anomaly Detection & Freezing**:
   - Monitored pattern: **3 transfers of the same amount within 60 seconds**.
   - The 3rd transfer is immediately blocked.
   - Both sender and receiver accounts are frozen (`FROZEN_ANOMALY`).
   - Audit trail recorded in `data/alerts.txt` and `data/freezes.txt`.
   - Only a Bank Manager can inspect and unfreeze the accounts.
