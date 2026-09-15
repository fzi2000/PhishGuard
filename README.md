# 🛡️ PhishGuard

### AI-Powered Phishing Detection & Email Security

PhishGuard is an AI-powered phishing detection and email security platform that combines **NLP-based machine learning with cybersecurity analysis** to identify suspicious emails and provide actionable threat intelligence.

It analyzes email content, URLs, sender information, and social-engineering indicators to generate a threat score and security assessment.

##  Features

*  **NLP Phishing Detection** — Machine learning model analyzes email subject and body.
*  **URL Analysis** — Identifies suspicious URLs, IP-based URLs, URL shorteners, and other indicators.
*  **Sender Analysis** — Evaluates suspicious sender-domain characteristics.
*  **Social Engineering Detection** — Detects urgency, credential requests, and account-verification patterns.
*  **Brand Impersonation Detection** — Identifies potential impersonation of well-known brands.
*  **IOC Extraction** — Extracts URLs, domains, and email addresses from messages.
*  **Threat Classification** — Classifies potential phishing and social-engineering attack patterns.
*  **MITRE ATT&CK Mapping** — Maps detected behaviors to relevant ATT&CK techniques where applicable.
*  **Risk Scoring** — Combines multiple security signals into an overall threat score.
*  **Response Recommendations** — Provides recommended actions such as allow, review, or block.

##  Architecture

```text
                 Email
                   │
                   ▼
          ┌─────────────────┐
          │ NLP ML Model    │
          │ TF-IDF +        │
          │ Logistic Reg.   │
          └────────┬────────┘
                   │
       ┌───────────┼───────────┐
       ▼           ▼           ▼
   URL Analysis  Sender     Social
                 Analysis   Engineering
       │           │           │
       └───────────┼───────────┘
                   ▼
             Risk Engine
                   │
        ┌──────────┼──────────┐
        ▼          ▼          ▼
     Threat     IOC         MITRE
     Score    Extraction   ATT&CK
        │
        ▼
 Response Recommendation
```

##  Streamlit Web Application

PhishGuard includes a Streamlit interface that allows users to submit an email and receive a security analysis.

The application provides:

* Threat level
* Risk score
* NLP prediction
* URL risk
* Sender risk
* Social-engineering indicators
* Brand impersonation detection
* Attack classification
* IOC extraction
* MITRE ATT&CK mapping
* Recommended response

##  Gmail Chrome Extension

PhishGuard also includes a **Chrome extension prototype designed to integrate phishing detection directly into Gmail**.

### How it works

```text
Gmail
  │
  ▼
Chrome Extension
  │
  │ Extracts:
  │ • Sender
  │ • Subject
  │ • Email body
  │
  ▼
FastAPI Backend
  │
  ▼
ML + Security Analysis
  │
  ▼
Threat Report
  │
  ▼
Warning displayed in Gmail
```

When a user opens an email in Gmail, the extension extracts the relevant email content and sends it to the PhishGuard backend for analysis.

The backend runs:

1. NLP phishing classification
2. URL analysis
3. Sender analysis
4. Social-engineering detection
5. Brand impersonation detection
6. IOC extraction
7. Threat classification
8. MITRE ATT&CK mapping
9. Risk scoring

The resulting security assessment can then be displayed directly within Gmail.

### Extension Structure

```text
extension/
├── manifest.json
├── content.js
├── background.js
├── popup.html
├── popup.js
└── styles.css
```

> **Note:** The Gmail integration is currently a prototype. The extension requires the FastAPI backend to be running and is not yet distributed through the Chrome Web Store.

##  Local Setup

Clone the repository:

```bash
git clone https://github.com/fzi2000/PhishGuard.git
cd PhishGuard
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the Streamlit application:

```bash
streamlit run app.py
```

##  Running the API

Start the FastAPI backend:

```bash
uvicorn backend.api:app --reload
```

The API will be available at:

```text
http://127.0.0.1:8000
```

API documentation:

```text
http://127.0.0.1:8000/docs
```

##  Gmail Extension Setup

1. Start the FastAPI backend.
2. Open Chrome and navigate to:

```text
chrome://extensions
```

3. Enable **Developer mode**.
4. Select **Load unpacked**.
5. Select the `extension` folder.
6. Open Gmail.
7. Open an email.
8. PhishGuard extracts the email and sends it to the analysis API.

## Technology Stack

**Machine Learning**

* Python
* Scikit-learn
* TF-IDF
* Logistic Regression
* NLP

**Cybersecurity**

* Phishing Detection
* URL Analysis
* IOC Extraction
* Social Engineering Detection
* Brand Impersonation
* MITRE ATT&CK

**Backend**

* FastAPI
* REST API

**Frontend / Deployment**

* Streamlit
* Chrome Extension
* JavaScript
* HTML/CSS

**Data**

* Phishing Email Dataset containing Enron, CEAS, Ling, Nazario, Nigerian and SpamAssassin email data.

## Future Improvements

* Chrome Web Store deployment
* Public cloud-hosted API
* Gmail warning banners and security indicators
* Threat-intelligence API integration
* Domain reputation checks
* More robust email extraction
* Explainable phishing predictions
* Authentication and API security
* Enterprise SIEM integration
* Improved source-aware model evaluation

##  Disclaimer

PhishGuard is an educational and portfolio cybersecurity project. Its security detections are based on machine-learning predictions and heuristic analysis and should not be considered a replacement for enterprise email-security solutions.



Computer Science (Artificial Intelligence) graduate
Heriot-Watt University Dubai
