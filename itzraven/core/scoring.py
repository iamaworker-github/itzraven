import math
from typing import Dict, Any, Optional
from itzraven.core.logger import get_logger

logger = get_logger()

SEVERITY_MAP: Dict[str, tuple] = {
    "AV:N": "network", "AV:A": "adjacent", "AV:L": "local", "AV:P": "physical",
    "AC:L": "low", "AC:H": "high",
    "PR:N": "none", "PR:L": "low", "PR:H": "high",
    "UI:N": "none", "UI:R": "required",
    "S:U": "unchanged", "S:C": "changed",
    "C:H": "high", "C:L": "low", "C:N": "none",
    "I:H": "high", "I:L": "low", "I:N": "none",
    "A:H": "high", "A:L": "low", "A:N": "none",
}

# CVSS v3.1 base score weights
CVSS31_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 6.42, "C": 7.52},
    "C": {"H": 0.56, "L": 0.22, "N": 0.00},
    "I": {"H": 0.56, "L": 0.22, "N": 0.00},
    "A": {"H": 0.56, "L": 0.22, "N": 0.00},
}

CVSS31_PR_SCOPE_CHANGED = {
    "N": 0.85, "L": 0.68, "H": 0.50,
}

CVSS31_IMPACT_BASE = {
    "C": 0.56, "I": 0.56, "A": 0.56,
}

# CVSS v4.0 simplified weights
CVSS40_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.00},
    "I": {"H": 0.56, "L": 0.22, "N": 0.00},
    "A": {"H": 0.56, "L": 0.22, "N": 0.00},
}


class CVSS31Scorer:
    """CVSS v3.1 Base Score calculator.

    Usage::

        scorer = CVSS31Scorer()
        result = scorer.score(
            av="N", ac="L", pr="N", ui="N",
            s="U", c="H", i="H", a="H"
        )
        # Returns: {"base_score": 9.8, "severity": "critical", "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
    """

    @staticmethod
    def score(av: str, ac: str, pr: str, ui: str,
              s: str, c: str, i: str, a: str) -> Dict[str, Any]:
        """Calculate CVSS v3.1 base score.

        Args:
            av: Attack Vector — N(etwork), A(djacent), L(ocal), P(hysical)
            ac: Attack Complexity — L(ow), H(igh)
            pr: Privileges Required — N(one), L(ow), H(igh)
            ui: User Interaction — N(one), R(equired)
            s: Scope — U(nchanged), C(hanged)
            c: Confidentiality — H(igh), L(ow), N(one)
            i: Integrity — H(igh), L(ow), N(one)
            a: Availability — H(igh), L(ow), N(one)

        Returns:
            Dict with keys: base_score, severity, vector_string
        """
        params = {"AV": av.upper(), "AC": ac.upper(), "PR": pr.upper(),
                   "UI": ui.upper(), "S": s.upper(), "C": c.upper(),
                   "I": i.upper(), "A": a.upper()}

        vector = f"CVSS:3.1/{'/'.join(f'{k}:{v}' for k, v in params.items())}"

        # Impact sub-score (ISS)
        iss = 1.0 - (
            (1.0 - CVSS31_WEIGHTS["C"][params["C"]]) *
            (1.0 - CVSS31_WEIGHTS["I"][params["I"]]) *
            (1.0 - CVSS31_WEIGHTS["A"][params["A"]])
        )

        # Impact
        if params["S"] == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15

        # Exploitability
        pr_weight = CVSS31_PR_SCOPE_CHANGED[params["PR"]] if params["S"] == "C" else CVSS31_WEIGHTS["PR"][params["PR"]]
        exploitability = 8.22 * CVSS31_WEIGHTS["AV"][params["AV"]] * CVSS31_WEIGHTS["AC"][params["AC"]] * pr_weight * CVSS31_WEIGHTS["UI"][params["UI"]]

        # Base score
        if impact <= 0:
            base_score = 0.0
        elif params["S"] == "U":
            base_score = min(impact + exploitability, 10.0) * 1.0
        else:
            base_score = min(1.08 * (impact + exploitability), 10.0)

        base_score = round(base_score * 10) / 10.0

        severity = CVSS31Scorer._severity(base_score)

        return {
            "base_score": base_score,
            "severity": severity,
            "vector_string": vector,
        }

    @staticmethod
    def _severity(score: float) -> str:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score >= 0.1:
            return "low"
        return "none"


class CVSS40Scorer:
    """Simplified CVSS v4.0 Base Score calculator.

    Uses a weight-based approximation of CVSS v4.0.
    """

    @staticmethod
    def score(av: str, ac: str, pr: str, ui: str,
              c: str, i: str, a: str) -> Dict[str, Any]:
        """Calculate a simplified CVSS v4.0 base score.

        Args: Same as CVSS31Scorer, without 's' (scope) parameter.

        Returns:
            Dict with keys: base_score, severity, vector_string
        """
        params = {"AV": av.upper(), "AC": ac.upper(), "PR": pr.upper(),
                   "UI": ui.upper(), "C": c.upper(), "I": i.upper(), "A": a.upper()}

        vector = f"CVSS:4.0/{'/'.join(f'{k}:{v}' for k, v in params.items())}"

        # Simplified scoring: weighted average of all metric values
        weights = CVSS40_WEIGHTS
        av_w = weights["AV"][params["AV"]]
        ac_w = weights["AC"][params["AC"]]
        pr_w = weights["PR"][params["PR"]]
        ui_w = weights["UI"][params["UI"]]
        c_w = weights["C"][params["C"]]
        i_w = weights["I"][params["I"]]
        a_w = weights["A"][params["A"]]

        # Simplified score computation
        exploitability = av_w * ac_w * pr_w * ui_w
        impact = 1.0 - ((1.0 - c_w) * (1.0 - i_w) * (1.0 - a_w))

        base_score = round(min(10.0, (exploitability * 10.0 + impact * 10.0) / 2.0) * 10) / 10.0

        severity = CVSS40Scorer._severity(base_score)

        return {
            "base_score": base_score,
            "severity": severity,
            "vector_string": vector,
        }

    @staticmethod
    def _severity(score: float) -> str:
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        if score >= 0.1:
            return "low"
        return "none"


class PlatformScorer:
    """Selects the appropriate CVSS scorer based on bug bounty platform."""

    _scorers = {
        "hackerone": CVSS31Scorer,
        "bugcrowd": CVSS40Scorer,
        "intigriti": CVSS31Scorer,
        "synack": CVSS31Scorer,
        "yeswehack": CVSS40Scorer,
    }

    def __init__(self, platform: str = "hackerone"):
        self.platform = platform.lower()
        self.scorer_class = self._scorers.get(self.platform, CVSS31Scorer)
        self.scorer = self.scorer_class()

    def score(self, **kwargs) -> Dict[str, Any]:
        """Score a vulnerability using the platform-appropriate CVSS version.

        CVSS 3.1 parameters: av, ac, pr, ui, s, c, i, a
        CVSS 4.0 parameters: av, ac, pr, ui, c, i, a
        """
        if self.scorer_class == CVSS40Scorer and "s" in kwargs:
            logger.debug(f"PlatformScorer ({self.platform}): ignoring scope (S) for CVSS 4.0")
            kwargs.pop("s", None)
        return self.scorer.score(**kwargs)
