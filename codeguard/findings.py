"""Shared data types for CodeGuard."""
from dataclasses import dataclass, field

CATEGORIES = [
    "secret_access",
    "data_exfiltration",
    "destructive_command",
    "persistence_or_privesc",
    "obfuscated_execution",
    "dependency_risk",
    "resource_exhaustion",
    "ssrf_network_exfil",
    "ai_targeted_instructions",
]

# A "capability" is something code CAN do (network call, file read). Alone it is
# weak evidence. A "threat" is a suspicious indicator (sensitive path, webhook,
# decode->exec). Idea adapted from DataDog GuardDog (Apache-2.0).
CAPABILITY = "capability"
THREAT = "threat"


@dataclass
class Finding:
    category: str
    kind: str          # CAPABILITY or THREAT
    weight: float      # 0..1 contribution to the category score
    line: int          # 1-based line number (0 = whole snippet)
    reason: str
    source: str = "rule"   # rule | ast | sql | yaml | markdown | injection | deobf | combo | typosquat
    # Evidence chain for explanations (UI graph, `codeguard scan --graph`): the path that makes this a threat,
    # e.g. [source: reads ~/.aws/credentials (line 2)] -> [sink: sent over the network (line 3)].
    # Each step: {"line": int, "role": source|encoded|decoded|carrier|step|sink, "label": str, "via": str?}
    chain: list = field(default_factory=list)

    def key(self):
        return (self.category, self.reason, self.line)


@dataclass
class Context:
    """Everything the pipeline learned about one snippet."""
    code: str
    language: str = "unknown"
    findings: list = field(default_factory=list)
    decoded_layers: int = 0

    def add(self, f: Finding):
        self.findings.append(f)
