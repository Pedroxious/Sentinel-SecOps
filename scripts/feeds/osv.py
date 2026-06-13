import requests

def check_osv_cve(cve_id):
    """
    Checks the OSV API for a specific CVE ID.
    If there is a match, returns (True, list_of_ecosystems).
    Else returns (False, []).
    """
    url = f"https://api.osv.dev/v1/vulns/{cve_id}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            ecosystems = set()
            for affected in data.get("affected", []):
                package = affected.get("package", {})
                ecosystem = package.get("ecosystem")
                if ecosystem:
                    ecosystems.add(ecosystem)
            return True, list(ecosystems)
        else:
            return False, []
    except Exception as e:
        print(f"OSV API lookup failed for {cve_id}: {e}")
        return False, []
