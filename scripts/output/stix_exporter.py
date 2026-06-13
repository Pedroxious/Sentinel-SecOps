import os
import json
import uuid
from datetime import datetime, timezone

def export_to_stix(cves_analyzed, output_path="output/stix_bundle.json"):
    """
    Exports the analyzed CVEs to a STIX 2.1 compliant JSON bundle.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    bundle_id = f"bundle--{uuid.uuid4()}"
    objects = []
    
    for item in cves_analyzed:
        cve = item["cve"]
        an = item["analysis_raw"]
        
        vuln_id = f"vulnerability--{uuid.uuid4()}"
        
        # Build external references for NVD
        external_references = [
            {
                "source_name": "cve",
                "external_id": cve["id"]
            },
            {
                "source_name": "nvd",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}"
            }
        ]
        
        # Add references from NVD if any
        for ref in cve.get("references", []):
            external_references.append({
                "source_name": "vendor-advisory",
                "url": ref
            })
            
        vuln_obj = {
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": vuln_id,
            "created": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "modified": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "name": cve["id"],
            "description": an.get("resumo_o_que_e", cve.get("description", "")),
            "external_references": external_references,
            "x_sentinel_secops_priority_score": cve.get("priority_score", 0.0),
            "x_sentinel_secops_epss_probability": cve.get("epss_data", {}).get("epss", 0.0),
            "x_sentinel_secops_ransomware_linked": cve.get("ransomware_known", False),
            "x_sentinel_secops_sla_label": cve.get("sla_label", "LOW"),
            "x_sentinel_secops_software_affected": an.get("software", "N/A"),
            "x_sentinel_secops_mitre_technique_id": cve.get("mitre_technique_id", "N/A"),
            "x_sentinel_secops_mitre_technique_name": cve.get("mitre_technique_name", "N/A")
        }
        
        objects.append(vuln_obj)
        
    bundle = {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects
    }
    
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2, ensure_ascii=False)
        print(f"STIX 2.1 bundle exported to {output_path}")
        return output_path
    except Exception as e:
        print(f"Error exporting to STIX: {e}")
        return None
