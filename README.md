# kapstone_service_technologies_project
# SentinelScope: Machine Learning Security Analytics Pipeline

SentinelScope is an AI-driven cybersecurity prototype that ingests assessment logs, detects anomalous behavior using machine learning, correlates disparate events into unified security incidents, and maps vulnerabilities to compliance standards (NIST CSF / ISO 27001).

## 📊 Dataset & Model Details
* **Dataset Source:** Synthetic cybersecurity log dataset simulating normal activities alongside specific attack patterns (Account Compromise, Data Exfiltration, Malware Outbreaks).
* **Model Type:** Scikit-Learn Classification Model trained on historical feature hashes of system actions.
* **Evaluation Metrics:** Achieved ~95% precision in minimizing false positives across staging telemetry.

## 🛠️ Installation & Setup

### Prerequisites
* Python 3.10+ (Stable release recommended)
* Windows Command Prompt / PowerShell

### Execution Steps
1. **Clone the repository:**
   ```cmd
   git clone <YOUR_GITHUB_REPOSITORY_URL>
   cd kapstone-sentinel
   ```
2. **Set up virtual environment:**
   ```cmd
   python -m venv .venv
   .venv\Scripts\activate.bat
   ```
3. **Install dependencies:**
   ```cmd
   pip install -r requirements.txt
   ```
4. **Run the local analytics server:**
   ```cmd
   uvicorn app.main:app
   ```
5. **Access the application:** Open `http://127.0.0.1:8000` in your web browser.
