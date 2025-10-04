bugbounty-automation/
├── README.md
├── docker-compose.yml
├── orchestrator/
│   ├── __init__.py
│   ├── main.py               ← Python orchestrator script
│   ├── modules/
│   │   ├── discovery.py      ← subfinder wrapper
│   │   ├── scanner_nuclei.py ← nuclei wrapper
│   │   ├── scanner_semgrep.py← semgrep wrapper
│   └── utils/
│       └── helpers.py        ← shared utils
├── config/
│   ├── targets.txt
│   ├── semgrep.yml
│   └── nuclei-config.yaml
├── results/                  ← output artifacts
├── .github/
│   └── workflows/
│       └── scan.yml          ← GitHub Actions workflow
└── requirements.txt
