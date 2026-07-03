"""Log Analysis Agent: detects attack patterns in parsed log entries.

Rule-based detection runs always (deterministic, no external dependency).
If GROQ_API_KEY is configured, each finding is additionally enriched with
an LLM-generated natural-language explanation.
"""
import logging
import re
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, wait
from urllib.parse import unquote

logger = logging.getLogger(__name__)

FAILED_LOGIN_RE = re.compile(r"fail|invalid user|denied", re.IGNORECASE)
SQLI_RE = re.compile(
    r"(\bselect\b.+\bfrom\b|\bunion\b.+\bselect\b|\bor\b\s+['\"]?1['\"]?\s*=\s*['\"]?1|--|;--|'\s*or\s*')",
    re.IGNORECASE,
)
XSS_RE = re.compile(r"<script|onerror\s*=|onload\s*=|javascript:", re.IGNORECASE)
PRIV_ESC_RE = re.compile(r"\bsudo\b|user=root|usermod|setuid|chmod\s+\+s", re.IGNORECASE)

BRUTE_FORCE_THRESHOLD = 3
SCAN_DISTINCT_PATH_THRESHOLD = 4
SUSPICIOUS_ERROR_THRESHOLD = 3


def _new_finding(attack_type: str, entry_ids: list[str], ip: str | None, username: str | None,
                  severity: str, confidence: float, evidence: str) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "attack_type": attack_type,
        "entry_ids": entry_ids,
        "ip": ip,
        "username": username,
        "severity": severity,
        "confidence": confidence,
        "evidence": evidence,
        "explanation": None,
    }


def detect_patterns(entries: list[dict]) -> list[dict]:
    findings: list[dict] = []

    failed_by_key: dict[tuple, list[dict]] = defaultdict(list)
    paths_by_ip: dict[str, set] = defaultdict(set)
    errors_by_ip: dict[str, list[dict]] = defaultdict(list)

    for entry in entries:
        event = entry.get("event") or ""
        decoded_event = unquote(event)
        ip = entry.get("ip")
        username = entry.get("username")

        if FAILED_LOGIN_RE.search(event):
            key = (ip, username)
            failed_by_key[key].append(entry)

        if SQLI_RE.search(decoded_event):
            findings.append(_new_finding(
                "sql_injection", [entry["id"]], ip, username, "high", 0.85,
                f"Suspicious SQL pattern in event: {decoded_event[:200]}",
            ))

        if XSS_RE.search(decoded_event):
            findings.append(_new_finding(
                "xss", [entry["id"]], ip, username, "high", 0.85,
                f"Suspicious script pattern in event: {decoded_event[:200]}",
            ))

        if PRIV_ESC_RE.search(decoded_event):
            findings.append(_new_finding(
                "privilege_escalation", [entry["id"]], ip, username, "medium", 0.6,
                f"Privilege-related command detected: {decoded_event[:200]}",
            ))

        path_match = re.search(r"(?:GET|POST|PUT|DELETE)\s+(\S+)", event)
        if ip and path_match:
            paths_by_ip[ip].add(path_match.group(1))

        status_match = re.search(r"->\s*(4\d\d|5\d\d)", event)
        if ip and status_match:
            errors_by_ip[ip].append(entry)

    for (ip, username), group in failed_by_key.items():
        if len(group) >= BRUTE_FORCE_THRESHOLD:
            findings.append(_new_finding(
                "brute_force", [e["id"] for e in group], ip, username, "high",
                min(0.5 + 0.1 * len(group), 0.95),
                f"{len(group)} failed login attempts for user={username!r} from ip={ip!r}",
            ))
        elif len(group) > 0:
            findings.append(_new_finding(
                "failed_login", [e["id"] for e in group], ip, username, "low", 0.4,
                f"{len(group)} failed login attempt(s) for user={username!r} from ip={ip!r}",
            ))

    for ip, paths in paths_by_ip.items():
        if len(paths) >= SCAN_DISTINCT_PATH_THRESHOLD:
            entry_ids = [e["id"] for e in entries if e.get("ip") == ip]
            findings.append(_new_finding(
                "port_scan", entry_ids, ip, None, "medium", 0.6,
                f"{len(paths)} distinct endpoints probed from ip={ip!r}: {sorted(paths)[:10]}",
            ))

    for ip, errs in errors_by_ip.items():
        if len(errs) >= SUSPICIOUS_ERROR_THRESHOLD:
            findings.append(_new_finding(
                "suspicious_traffic", [e["id"] for e in errs], ip, None, "medium", 0.5,
                f"{len(errs)} error responses (4xx/5xx) from ip={ip!r} in this batch",
            ))

    return findings


def _get_llm():
    from backend.config import settings
    if not settings.groq_api_key:
        return None
    try:
        from langchain_groq import ChatGroq
        return ChatGroq(model="llama-3.1-8b-instant", api_key=settings.groq_api_key)
    except Exception:
        logger.warning("Could not initialize Groq LLM", exc_info=True)
        return None


# A large upload can produce thousands of findings; explaining every one
# sequentially would block the request for many minutes. Explain only the
# highest-severity findings, up to a bounded count, fetched concurrently and
# capped by wall-clock time — mirrors the same bound applied to threat-intel
# lookups in agents/threat_intel.py, for the same reason.
MAX_EXPLAINED_FINDINGS_PER_RUN = 20
TIME_BUDGET_SECONDS = 15.0
_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="log-analysis-llm")


def _invoke_llm(llm, finding: dict) -> str | None:
    prompt = (
        "You are a SOC analyst. In 1-2 sentences, explain the security risk of this finding "
        "and why it matters, for a non-expert reader.\n"
        f"Attack type: {finding['attack_type']}\n"
        f"Evidence: {finding['evidence']}\n"
    )
    try:
        response = llm.invoke(prompt)
        return getattr(response, "content", str(response))
    except Exception:
        logger.warning("LLM enrichment failed for finding %s", finding["id"], exc_info=True)
        return None


def enrich_with_llm(findings: list[dict]) -> list[dict]:
    llm = _get_llm()
    if llm is None or not findings:
        return findings

    batch = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.get("severity"), 3))
    batch = batch[:MAX_EXPLAINED_FINDINGS_PER_RUN]

    future_to_finding = {_executor.submit(_invoke_llm, llm, f): f for f in batch}
    done, not_done = wait(future_to_finding, timeout=TIME_BUDGET_SECONDS)

    for future in done:
        future_to_finding[future]["explanation"] = future.result()
    if not_done:
        # Leftovers keep running in the shared pool but we stop waiting on
        # them here; those findings simply keep explanation=None this run.
        logger.info("LLM enrichment budget reached; %d finding(s) left unexplained", len(not_done))

    return findings


def analyze(entries: list[dict]) -> list[dict]:
    findings = detect_patterns(entries)
    return enrich_with_llm(findings)
