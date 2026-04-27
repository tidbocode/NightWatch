import json
from pathlib import Path


def load_mitre_attack(path: str) -> list[dict]:
    """Parse a MITRE ATT&CK enterprise STIX JSON bundle into intel chunks."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    chunks = []
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        name = obj.get("name", "")
        description = obj.get("description", "").strip()
        if not description:
            continue

        attack_id = ""
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                attack_id = ref.get("external_id", "")
                break

        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        text = f"[{attack_id}] {name}\nTactics: {', '.join(tactics)}\n\n{description[:2000]}"
        chunks.append({
            "id": f"mitre-{attack_id or obj['id']}",
            "text": text,
            "metadata": {
                "source": "mitre-attack",
                "technique_id": attack_id,
                "name": name,
                "tactics": ",".join(tactics),
            },
        })
    return chunks


def load_nvd_feed(path: str) -> list[dict]:
    """Parse an NVD CVE JSON 1.1 feed file into intel chunks."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    chunks = []
    for item in data.get("CVE_Items", []):
        cve = item.get("cve", {})
        cve_id = cve.get("CVE_data_meta", {}).get("ID", "")
        descs = cve.get("description", {}).get("description_data", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        if not desc or desc.startswith("** RESERVED") or desc.startswith("** REJECT"):
            continue

        impact = item.get("impact", {})
        score = (
            impact.get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore")
            or impact.get("baseMetricV2", {}).get("cvssV2", {}).get("baseScore")
            or ""
        )
        text = f"[{cve_id}] CVSS: {score}\n{desc[:2000]}"
        chunks.append({
            "id": f"cve-{cve_id}",
            "text": text,
            "metadata": {
                "source": "nvd",
                "cve_id": cve_id,
                "cvss_score": str(score),
            },
        })
    return chunks
