"""
Training Labs Recommendation Database — curated vulnerable-by-design environments
for testing and validating Itzraven capabilities.
"""

from typing import List, Dict

TRAINING_LABS: List[Dict] = [
    # Web / API / GraphQL
    {"name": "DVGA", "url": "https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application", "category": "graphql", "difficulty": "easy", "description": "Damn Vulnerable GraphQL Application"},
    {"name": "Juice Shop", "url": "https://github.com/juice-shop/juice-shop", "category": "web", "difficulty": "medium", "description": "OWASP Juice Shop — modern web app with OWASP Top 10 vulns"},
    {"name": "DVWA", "url": "https://github.com/digininja/DVWA", "category": "web", "difficulty": "easy", "description": "Damn Vulnerable Web Application"},
    {"name": "WebGoat", "url": "https://github.com/WebGoat/WebGoat", "category": "web", "difficulty": "easy", "description": "OWASP WebGoat — deliberately insecure web app"},
    {"name": "crAPI", "url": "https://github.com/OWASP/crAPI", "category": "api", "difficulty": "medium", "description": "Completely Ridiculous API — vulnerable API for training"},
    {"name": "vAPI", "url": "https://github.com/roottusk/vapi", "category": "api", "difficulty": "medium", "description": "Vulnerable API — REST API security testing"},
    {"name": "VAmPI", "url": "https://github.com/erev0s/VAmPI", "category": "api", "difficulty": "easy", "description": "Vulnerable API — Flask-based API with OWASP Top 10"},
    {"name": "Hackazon", "url": "https://github.com/OWASP/Hackazon", "category": "web", "difficulty": "medium", "description": "Vulnerable e-commerce web app"},
    {"name": "DSVW", "url": "https://github.com/stamparm/DSVW", "category": "web", "difficulty": "easy", "description": "Damn Small Vulnerable Web"},
    {"name": "bWAPP", "url": "https://github.com/raesene/bWAPP", "category": "web", "difficulty": "easy", "description": "Buggy Web Application — 100+ vulnerabilities"},
    # Active Directory / Windows
    {"name": "GOAD", "url": "https://github.com/Orange-Cyberdefense/GOAD", "category": "ad", "difficulty": "hard", "description": "Game of Active Directory — vulnerable AD lab"},
    {"name": "BadBlood", "url": "https://github.com/davidprowe/BadBlood", "category": "ad", "difficulty": "medium", "description": "AD misconfiguration generator"},
    {"name": "AutomatedLab", "url": "https://github.com/AutomatedLab/AutomatedLab", "category": "ad", "difficulty": "hard", "description": "Automated AD lab deployment"},
    # Cloud
    {"name": "CloudGoat", "url": "https://github.com/RhinoSecurityLabs/cloudgoat", "category": "cloud", "difficulty": "medium", "description": "AWS vulnerable-by-design deployment"},
    {"name": "Flaws Cloud", "url": "https://github.com/OWASP/Cloud-Security", "category": "cloud", "difficulty": "medium", "description": "OWASP Cloud Security challenges"},
    {"name": "SadCloud", "url": "https://github.com/nccgroup/sadcloud", "category": "cloud", "difficulty": "medium", "description": "AWS misconfiguration generator"},
    # Kubernetes
    {"name": "Kubernetes Goat", "url": "https://github.com/madhuakula/kubernetes-goat", "category": "kubernetes", "difficulty": "medium", "description": "Vulnerable K8s cluster"},
    {"name": "KubeSec", "url": "https://github.com/controlplaneio/kubectl-display", "category": "kubernetes", "difficulty": "medium", "description": "K8s security testing environment"},
    # IoT
    {"name": "FirmAE", "url": "https://github.com/pr0v3rbs/FirmAE", "category": "iot", "difficulty": "hard", "description": "IoT firmware emulation and analysis"},
    {"name": "Embenet", "url": "https://github.com/embenettools/embenettools", "category": "iot", "difficulty": "hard", "description": "Embedded device testing framework"},
    {"name": "IoTGoat", "url": "https://github.com/scriptingxss/IoTGoat", "category": "iot", "difficulty": "medium", "description": "Deliberately insecure IoT firmware"},
    # Network / Infrastructure
    {"name": "VulnHub", "url": "https://www.vulnhub.com/", "category": "network", "difficulty": "medium", "description": "Vulnerable VM repository"},
    {"name": "HackTheBox", "url": "https://www.hackthebox.com/", "category": "network", "difficulty": "medium", "description": "Online hacking platform"},
    {"name": "Proving Grounds", "url": "https://www.offsec.com/labs/", "category": "network", "difficulty": "medium", "description": "Offensive Security labs"},
]


def get_labs_by_category(category: str) -> List[Dict]:
    return [lab for lab in TRAINING_LABS if lab["category"] == category]


def get_labs_by_difficulty(difficulty: str) -> List[Dict]:
    return [lab for lab in TRAINING_LABS if lab["difficulty"] == difficulty]


def get_all_labs() -> List[Dict]:
    return TRAINING_LABS


def get_lab_summary() -> Dict:
    categories = {}
    for lab in TRAINING_LABS:
        cat = lab["category"]
        if cat not in categories:
            categories[cat] = 0
        categories[cat] += 1
    return {"total": len(TRAINING_LABS), "categories": categories}
