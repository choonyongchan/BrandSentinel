# Brand Sentinel 🛡️

Proactive detection of scam, fraudulent, and impersonation websites to protect your brand's digital presence.

<img src="./docs/BrandSentinel.png" width="300"> 
<img src="./docs/BrandSentinel.jpg" width="300">

## Credits  

This project was inspired by the invaluable guidance I received during my internship, where I had the privilege of learning from the Asia-Pacific Digital Risk Protection team at a leading Russia-founded cybersecurity company. Their passion for defending against cybercrime and their patience in mentoring me broadened my perspective on Digital Risk Protection and directly inspired this work. I dedicate this project to them in gratitude. 

## Problem: The Rising Tide of Digital Threats

In the digital age, a company's brand is one of its most valuable assets. However, this asset is under constant assault. Malicious actors are no longer just sending fear-mongering emails; they are deploying sophisticated social engineering campaigns using fraudulent websites that perfectly impersonate trusted brands.

These attacks have a devastating impact:
 * Financial Loss: Direct theft from customers and the company.
 * Reputational Damage: Erosion of customer trust that can take years to rebuild.
 * Data Breaches: Loss of sensitive customer and corporate data.

Traditional defenses like simple blocklists are reactive and insufficient. Scammers can register and weaponize new domains in minutes, staying one step ahead. This is a critical challenge for businesses of all sizes—from startups operating on thin margins to large corporations whose brand equity is paramount.

Digital Risk Protection (DRP) is the practice of safeguarding these digital assets. Brand Sentinel is a tool built on DRP principles to provide a proactive defense against web-based brand impersonation.

## Guiding Question

> Can we create a free, open-source data pipeline that provides accurate, real-time intelligence on scam domains impersonating a brand, empowering businesses to defend their online presence?

With the intelligence gathered by Brand Sentinel, your security team can:
 * Gain immediate visibility into active scam campaigns targeting your company.
 * Triage threats effectively and prioritize takedown actions.
 * Build a case to engage cybersecurity vendors for domain takedown services with concrete evidence.

## ✨ Key Features
 * Real-time Monitoring: Ingests data from multiple high-quality threat intelligence feeds.
 * Heuristic-Based Analysis: Uses a sophisticated ensemble of checks to identify malicious domains with high accuracy, minimizing false positives.
 * Extensible Architecture: Built on an event-driven model that is easy to extend with new data sources or custom detection logic.
 * Cost-Effective: Leverages free and open-source intelligence feeds to provide powerful protection without expensive subscriptions.
 * Actionable Output: Classifies domains into clear categories (Scam, Benign, Inconclusive) so you know exactly where to focus your efforts.


## ⚙️ How It Works
Brand Sentinel operates on a three-stage pipeline: Ingestion, Detection, and Triage.

```mermaid
flowchart TD
    subgraph Sources["🔌 Ingestion Sources (async workers)"]
        S1["CertStream\nCT logs · live"]
        S2["URLhaus\nevery 5 min"]
        S3["PhishTank\nevery 1 h"]
        S4["OpenPhish\nevery 12 h"]
        S5["+ 6 more feeds\nCERT Polska · Phishing.Database\nPhishing Army · Botvrij\nDigitalSide · Manual Import"]
    end

    Q[("asyncio.Queue\ndedup")]

    S1 & S2 & S3 & S4 & S5 --> Q

    Q --> FT["filter_task\nkeyword accept/reject"]
    FT -->|irrelevant| IR["irrelevant.txt"]
    FT -->|relevant| CT

    subgraph CT["classify_task (per domain, async · retries=1)"]
        BC["build_context\nHTTP · DNS · TLS"]
        H["15 Heuristics\nlazy · short-circuit"]
        BC --> H
    end

    H --> OT["output_task"]
    OT --> SC["scam.txt"]
    OT --> INC["inconclusive.txt"]
    OT --> BN["benign.txt"]
```

### 1. Data Ingestion: The Sourcing Pipeline
To provide robust and timely intelligence, we aggregate data from a variety of trusted, open-source threat feeds. This multi-source approach ensures broader coverage of newly emerging threats. The choice of free and open-source feeds makes this tool accessible to everyone.
Our core ingestion sources include:
 * CertStream: Monitors certificate transparency logs to find new domains through newly issued SSL certificates for domains. This could be an early signal of a planned attack.
 * URLhaus: A project from abuse.ch that collects and shares URLs distributing malware.
 * OpenPhish: A community feed that provides active phishing URLs.
 * PhishTank: A collaborative clearinghouse for data and information about phishing on the Internet.
 * CERT Polska: Phishing feed maintained by Poland's national CERT.
 * Phishing.Database: Community-maintained database of phishing domains.
 * Phishing Army: Blocklist of phishing websites, updated regularly.
 * Botvrij.eu: Open-source threat intelligence data sets.
 * DigitalSide IT-Threat: Italian threat intelligence feed covering malicious domains.
 * Manual File Ingestion: Import suspicious domains from your existing Threat Intelligence sources.
Brand Sentinel is also designed to be easily extended with commercial, subscription-based data sources like URLScan.io or OTX for organizations requiring even deeper intelligence.
### 2. Detection Engine: The Heuristic Model
A single indicator is rarely enough to condemn a domain. Instead of relying on simple signatures, Brand Sentinel uses an ensemble of heuristics, where each heuristic acts as a weighted signal. Some signals are conclusive (e.g., a HTTP 404 status), while others are contributing (e.g., a newly registered SSL certificate). The cumulative score determines the final classification.
Our key heuristics include:
| Heuristic | Description |
|---|---|
| Inactive Domain | Checks if the domain is unresponsive or returns a non-200 HTTP status (e.g., 404, 503). Inactive domains are often parked or have been taken down. |
| Parking Domain | Identifies if the domain resolves to a known domain parking service. These are typically benign but can be weaponized later. |
| Brand Lookalike | Detects domains using typosquatting, combosquatting, or other visual similarities to impersonate a legitimate brand. |
| Forbidden Token | Scans the page content for suspicious keywords often associated with scams (e.g., "limited offer," "account suspended," "verify now"). |
| Forms Exfil | Detects login forms or input fields that submit data to a different, potentially malicious domain. |
| Redirect/Cloaking | Identifies domains that use suspicious redirects or cloaking techniques to hide their true nature from automated scanners. |
| Phishing Kit | Checks for known signatures or file structures associated with popular, off-the-shelf phishing kits. |
| DNS/Email Posture | Analyzes DNS records (MX, SPF, DMARC) to assess if the domain is configured to send legitimate email, a common trait of legitimate domains. |
| TLS Certificate | Examines the SSL/TLS certificate. A short lifespan or issuance from a less-reputable CA can be a red flag. |
| Long Lived Certificate | A supplementary check to reward domains with a long-standing, trusted certificate history. |

### 3. Triage & Output: Actionable Intelligence
Domains are classified into one of three categories to guide your security team's response:
 * 🚨 Scam: High Priority. These domains have either been positively identified as malicious by a high-confidence heuristic or have accumulated a high-risk score across multiple checks. Your team should investigate these immediately for takedown.
 * 🤔 Inconclusive: Requires Manual Review. These domains exhibit suspicious characteristics but lack definitive proof of malice. They warrant a closer look by an analyst after all high-priority alerts have been addressed.
 * ✅ Benign: Low Priority. These domains have passed all checks or have been identified as legitimate (e.g., a known parking page). They can be safely ignored for now, though Brand Sentinel will continue to monitor them for any future changes.

## 🏗️ System Architecture
Brand Sentinel is built on an asynchronous, event-driven architecture. This design choice provides two key advantages:
 * Scalability & Performance: Each stage of the pipeline (ingestion, analysis, output) can operate independently, allowing for real-time processing of large volumes of data without bottlenecks.
 * Extensibility: Adding a new data source or a custom detection heuristic is as simple as creating a new, self-contained module that subscribes to the event stream. This makes it incredibly easy for your team to customize the tool with proprietary intelligence.


## 🚀 Getting Started: Local Demo
You can run a local instance of Brand Sentinel to monitor your own brand.

### Prerequisites
 * [Docker](https://docs.docker.com/get-docker/) (for running the Prefect orchestration server)
 * Python 3.13+

### Installation & Setup

0. Clone the repository:

```bash
git clone https://github.com/your-username/brand-sentinel.git
cd brand-sentinel
```

1. Start the Prefect server:

```bash
docker-compose up -d
```

2. Point the runtime at the local Prefect server:

```bash
export PREFECT_API_URL=http://localhost:4200/api
```

3. Create and activate a virtual environment:

```bash
python -m venv .env
source .env/bin/activate
```
> On Windows, use: `.env\Scripts\activate`

4. Install dependencies:

```bash
pip install -r requirements.txt
```

5. Configure your brands:
   Open `config.yaml` and add the brands you want to monitor under the `brands` field. Use variations without TLDs.

### Running the Tool

6. Start the pipeline:
   The tool will begin ingesting data and analyzing domains.

```bash
python main.py
```
   The pipeline streams indefinitely. Stop it with `Ctrl+C`.

7. Monitor via the Prefect UI:
   Open [http://localhost:4200](http://localhost:4200) to observe flow runs, task states, and logs in real time.

8. Check the output:
   Results are continuously written to the following files in the project root:
   * `scam.txt`
   * `inconclusive.txt`
   * `benign.txt`
   * `irrelevant.txt`

## 🤝 Contributing
We welcome contributions from the community! Whether it's adding a new data source, improving a heuristic, or fixing a bug, your help is appreciated. Please feel free to open an issue or submit a pull request.

## Credits & Contact
Hi, I'm Choonyong Chan! I'm passionate about building tools that make the digital world a safer place.

Feel free to reach out on [LinkedIn](https://www.linkedin.com/in/chanchoonyong/) for collaborations or questions.
