import os
import json

JSON_PATH = os.path.join("data", "mitre_attack.json")

# In-memory lookup dictionaries
_techniques_by_id = {}

def load_mitre_data():
    global _techniques_by_id
    if _techniques_by_id:
        return
    if not os.path.exists(JSON_PATH):
        return

    try:
        with open(JSON_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        objects = data.get("objects", [])
        for obj in objects:
            if obj.get("type") == "attack-pattern":
                tech_name = obj.get("name", "")
                tech_desc = obj.get("description", "")
                tech_id = None
                
                for ref in obj.get("external_references", []):
                    if ref.get("source_name") == "mitre-attack":
                        tech_id = ref.get("external_id")
                        break
                
                tactic = "N/A"
                kill_chain = obj.get("kill_chain_phases", [])
                if kill_chain:
                    # e.g., "initial-access" -> "Initial Access"
                    phase = kill_chain[0].get("phase_name", "")
                    tactic = phase.replace("-", " ").title()

                if tech_id:
                    _techniques_by_id[tech_id.upper()] = {
                        "id": tech_id,
                        "name": tech_name,
                        "description": tech_desc,
                        "tactic": tactic
                    }
    except Exception as e:
        print(f"Error loading MITRE JSON: {e}")

def get_mitre_technique(technique_id_or_str):
    """
    Looks up a technique by ID (e.g. 'T1190') or a string containing the ID.
    Returns a dict with key/values or default dict if not found.
    """
    load_mitre_data()
    
    if not technique_id_or_str:
        return {"id": "N/A", "name": "N/A", "tactic": "N/A"}

    # Extract ID (e.g. T1190 from "T1190 - Exploit Public-Facing Application")
    tech_id = technique_id_or_str.strip().split(" ")[0].upper()
    
    if tech_id in _techniques_by_id:
        return _techniques_by_id[tech_id]
        
    return {
        "id": tech_id,
        "name": "N/A",
        "tactic": "N/A"
    }
