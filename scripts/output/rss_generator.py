import os
from datetime import datetime, timezone
import xml.etree.ElementTree as ET

def generate_rss_feed(cves_analyzed, output_path="feed.xml"):
    """
    Generates a valid RSS 2.0 XML feed file from analyzed CVEs with score >= 8.0.
    """
    # Create the RSS feed structure
    rss = ET.Element("rss", version="2.0")
    channel = ET.SubElement(rss, "channel")
    
    # Required channel elements
    title = ET.SubElement(channel, "title")
    title.text = "Sentinel SecOps - Critical Threat Feed"
    
    link = ET.SubElement(channel, "link")
    link.text = "https://pedroxious.github.io/Sentinel-SecOps/"
    
    description = ET.SubElement(channel, "description")
    description.text = "Autonomous threat intelligence and critical vulnerability alerts feed from Sentinel SecOps."
    
    pub_date = ET.SubElement(channel, "pubDate")
    pub_date.text = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    
    for item in cves_analyzed:
        cve = item["cve"]
        an = item["analysis_raw"]
        
        # Only include critical CVEs (priority_score >= 8.0)
        score = cve.get("priority_score", 0.0)
        if score < 8.0:
            continue
            
        cve_id = cve["id"]
        software = an.get("software", "N/A")
        
        # Create item
        rss_item = ET.SubElement(channel, "item")
        
        item_title = ET.SubElement(rss_item, "title")
        item_title.text = f"{cve_id} | {software} - Priority Score {score:.1f}"
        
        item_link = ET.SubElement(rss_item, "link")
        item_link.text = f"https://pedroxious.github.io/Sentinel-SecOps/#cve-{cve_id}"
        
        item_desc = ET.SubElement(rss_item, "description")
        desc_text = (
            f"Vulnerability ID: {cve_id}<br/>"
            f"Software: {software}<br/>"
            f"CVSS Score: {cve['score']}<br/>"
            f"Priority Score: {score:.1f} ({cve.get('priority_rating', 'UNKNOWN')})<br/>"
            f"SLA Label: {cve.get('sla_label', 'N/A')}<br/>"
            f"Exploit Available: {'Yes' if cve.get('exploitdb_has_exploit') else 'No'}<br/><br/>"
            f"<b>Summary:</b> {an.get('resumo_o_que_e', '')}<br/>"
            f"<b>Immediate Action:</b> {an.get('immediate_action', an.get('resumo_o_que_fazer', ''))}"
        )
        item_desc.text = desc_text
        
        item_guid = ET.SubElement(rss_item, "guid", isPermaLink="false")
        item_guid.text = cve_id
        
        item_pub = ET.SubElement(rss_item, "pubDate")
        # Format date from CSV or use current time
        item_pub.text = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")

    # Write the XML to a file with proper encoding and declaration
    try:
        xml_str = ET.tostring(rss, encoding="utf-8")
        # Prepend xml declaration
        xml_content = b'<?xml version="1.0" encoding="UTF-8" ?>\n' + xml_str
        
        with open(output_path, "wb") as f:
            f.write(xml_content)
        print(f"RSS feed successfully generated at {output_path}")
        return output_path
    except Exception as e:
        print(f"Error generating RSS feed: {e}")
        return None
