from flask import Flask, jsonify, send_from_directory, request
import json
import subprocess
import os

from fpdf import FPDF
from datetime import datetime

app = Flask(__name__, static_folder='static')

RESULTS_PATH = os.environ.get('RESULTS_PATH', '/data/assessment-results.json')
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/api/results')
def get_results():
    oscal_dir = os.path.join(PROJECT_ROOT, 'oscal')
    provider = request.args.get('provider', 'all')
    
    all_data = {}
    
    for filename in sorted(os.listdir(oscal_dir)):
        if filename.startswith('assessment-results-') and filename.endswith('.json'):
            prov = filename.replace('assessment-results-', '').replace('.json', '')
            
            if provider != 'all' and provider != prov:
                continue
            
            filepath = os.path.join(oscal_dir, filename)
            with open(filepath) as f:
                data = json.load(f)
                ar = data.get("assessment-results", {})
                
                # Tag each result with its provider
                for result in ar.get("results", []):
                    result["_provider"] = prov
                
                if prov not in all_data:
                    all_data[prov] = {"metadata": ar.get("metadata", {}), "results": []}
                all_data[prov]["results"].extend(ar.get("results", []))
    
    if not all_data:
        return jsonify({"error": "No scan results found."}), 404
    
    # Combine into single response with provider tags preserved
    combined = {"assessment-results": {"results": [], "metadata": {}, "providers": []}}
    for prov, pdata in all_data.items():
        combined["assessment-results"]["metadata"] = pdata["metadata"]
        combined["assessment-results"]["results"].extend(pdata["results"])
        combined["assessment-results"]["providers"].append(prov)
    
    return jsonify(combined)

@app.route('/api/scan', methods=['POST'])
def run_scan():
    catalog = request.json.get('catalog', 'all')
    try:
        if catalog == 'all':
            cmd = [os.path.join(PROJECT_ROOT, 'scan.sh')]
        else:
            cmd = [os.path.join(PROJECT_ROOT, 'scan.sh'), f'catalog/{catalog}']

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
            cwd=PROJECT_ROOT
        )
        return jsonify({
            "status": "complete",
            "output": result.stdout,
            "errors": result.stderr
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Scan timed out after 5 minutes"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/catalogs')
def list_catalogs():
    return jsonify([
        {"id": "fedramp-moderate-aws.json", "name": "AWS — FedRAMP Moderate + PCI DSS + SOC 2", "provider": "aws"},
        {"id": "fedramp-moderate-azure.json", "name": "Azure — FedRAMP Moderate + PCI DSS + SOC 2", "provider": "azure"},
        {"id": "github-security.json", "name": "GitHub — Repository Security", "provider": "github"}
    ])

@app.route('/api/upload-ssp', methods=['POST'])
def upload_ssp():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    if not file.filename.endswith('.docx'):
        return jsonify({"error": "File must be a .docx file"}), 400
    
    import tempfile
    temp_path = os.path.join(tempfile.gettempdir(), 'ssp-upload.docx')
    file.save(temp_path)
    
    try:
        # Run the parser
        parser_dir = os.path.join(PROJECT_ROOT, 'ssp-parser')
        parsed_path = os.path.join(PROJECT_ROOT, 'oscal', 'ssp-parsed.json')
        oscal_path = os.path.join(PROJECT_ROOT, 'oscal', 'oscal-ssp.json')
        
        result = subprocess.run(
            ['python3', os.path.join(parser_dir, 'ssp_parser.py'), temp_path, '--output', parsed_path],
            capture_output=True, text=True, timeout=120, cwd=PROJECT_ROOT
        )
        
        if result.returncode != 0:
            return jsonify({"error": f"Parser failed: {result.stderr}"}), 500
        
        # Generate OSCAL SSP
        result2 = subprocess.run(
            ['python3', os.path.join(parser_dir, 'ssp_to_oscal.py'), parsed_path, '--output', oscal_path, '--name', file.filename.replace('.docx', '')],
            capture_output=True, text=True, timeout=120, cwd=PROJECT_ROOT
        )
        
        # Load parsed results for display
        with open(parsed_path) as f:
            parsed = json.load(f)
        
        return jsonify({
            "status": "complete",
            "statistics": parsed.get("statistics", {}),
            "controls_preview": parsed.get("controls", [])[:10],
            "oscal_generated": result2.returncode == 0
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/ssp-results')
def ssp_results():
    parsed_path = os.path.join(PROJECT_ROOT, 'oscal', 'ssp-parsed.json')
    if not os.path.exists(parsed_path):
        return jsonify({"error": "No SSP parsed yet. Upload an SSP docx first."}), 404
    with open(parsed_path) as f:
        return jsonify(json.load(f))
    
@app.route('/api/export', methods=['GET'])
def export_report():
    provider = request.args.get('provider', 'all')
    oscal_dir = os.path.join(PROJECT_ROOT, 'oscal')
    
    all_results = []
    metadata = {}
    providers_found = set()
    for filename in sorted(os.listdir(oscal_dir)):
        if filename.startswith('assessment-results-') and filename.endswith('.json'):
            prov = filename.replace('assessment-results-', '').replace('.json', '')
            if provider != 'all' and provider != prov:
                continue
            filepath = os.path.join(oscal_dir, filename)
            with open(filepath) as f:
                data = json.load(f)
                ar = data.get("assessment-results", {})
                metadata = ar.get("metadata", metadata)
                for r in ar.get("results", []):
                    r["_provider"] = prov
                    all_results.append(r)
                    providers_found.add(prov)
    
    all_findings = []
    for r in all_results:
        for f in r.get("findings", []):
            f["_provider"] = r.get("_provider", "")
            f["_control"] = r.get("title", "")
            all_findings.append(f)
    
    passes = [f for f in all_findings if f.get("target", {}).get("status", {}).get("state") == "satisfied"]
    fails = [f for f in all_findings if f.get("target", {}).get("status", {}).get("state") == "not-satisfied"]
    total = len(all_findings)
    pass_rate = round(len(passes) / total * 100) if total > 0 else 0
    
    # Count per provider
    prov_stats = {}
    for f in all_findings:
        p = f.get("_provider", "unknown")
        if p not in prov_stats:
            prov_stats[p] = {"pass": 0, "fail": 0}
        if f.get("target", {}).get("status", {}).get("state") == "satisfied":
            prov_stats[p]["pass"] += 1
        else:
            prov_stats[p]["fail"] += 1
    
    # Count severities
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in fails:
        title = f.get("title", "")
        for sev in sev_counts:
            if title.startswith(sev):
                sev_counts[sev] += 1
                break
    
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=20)
    
    # ── COVER PAGE ──
    pdf.add_page()
    pdf.set_fill_color(20, 24, 40)
    pdf.rect(0, 0, 210, 297, 'F')
    
    pdf.set_y(60)
    pdf.set_text_color(34, 211, 238)
    pdf.set_font("Helvetica", "B", 36)
    pdf.cell(0, 15, "OpenFRAMP", new_x="LMARGIN", new_y="NEXT", align="C")
    
    pdf.set_text_color(200, 205, 216)
    pdf.set_font("Helvetica", "", 14)
    pdf.cell(0, 10, "Multi-Framework Compliance Report", new_x="LMARGIN", new_y="NEXT", align="C")
    
    pdf.ln(20)
    pdf.set_draw_color(34, 211, 238)
    pdf.line(60, pdf.get_y(), 150, pdf.get_y())
    pdf.ln(20)
    
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(148, 163, 184)
    report_date = datetime.now().strftime('%B %d, %Y at %H:%M UTC')
    pdf.cell(0, 8, f"Generated: {report_date}", new_x="LMARGIN", new_y="NEXT", align="C")
    
    prov_label = provider.upper() if provider != 'all' else 'All Providers'
    prov_names = {"aws": "Amazon Web Services", "azure": "Microsoft Azure & Entra ID", "github": "GitHub"}
    if provider != 'all':
        prov_label = prov_names.get(provider, provider.upper())
    else:
        prov_label = ", ".join([prov_names.get(p, p.upper()) for p in sorted(providers_found)])
    pdf.cell(0, 8, f"Scope: {prov_label}", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.cell(0, 8, "Frameworks: FedRAMP Moderate | PCI DSS 4.0.1 | SOC 2", new_x="LMARGIN", new_y="NEXT", align="C")
    
    pdf.ln(30)
    status = "SATISFACTORY" if pass_rate >= 80 else "NEEDS IMPROVEMENT" if pass_rate >= 50 else "NEEDS REMEDIATION"
    status_color = (52, 211, 153) if pass_rate >= 80 else (251, 191, 36) if pass_rate >= 50 else (248, 113, 113)
    pdf.set_text_color(*status_color)
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 12, status, new_x="LMARGIN", new_y="NEXT", align="C")
    
    pdf.set_text_color(148, 163, 184)
    pdf.set_font("Helvetica", "", 13)
    pdf.cell(0, 10, f"{pass_rate}% Pass Rate  |  {len(passes)} Passed  |  {len(fails)} Failed  |  {total} Total", new_x="LMARGIN", new_y="NEXT", align="C")
    
    # ── EXECUTIVE SUMMARY ──
    pdf.add_page()
    pdf.set_fill_color(255, 255, 255)
    pdf.rect(0, 0, 210, 297, 'F')
    pdf.set_text_color(30, 30, 30)
    
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, "Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(34, 211, 238)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(8)
    
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 7, f"This report presents automated compliance scan results from OpenFRAMP across {len(providers_found)} cloud provider(s).", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, f"A total of {total} compliance checks were evaluated against FedRAMP Moderate, PCI DSS 4.0.1, and SOC 2 controls.", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    
    # Summary table
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(240, 240, 245)
    pdf.cell(50, 8, "Metric", border=1, fill=True)
    pdf.cell(40, 8, "Value", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Helvetica", "", 10)
    rows = [
        ("Total Findings", str(total)),
        ("Passed", str(len(passes))),
        ("Failed", str(len(fails))),
        ("Pass Rate", f"{pass_rate}%"),
        ("Controls Evaluated", str(len(all_results))),
        ("Providers Scanned", str(len(providers_found))),
    ]
    for label, val in rows:
        pdf.cell(50, 7, label, border=1)
        pdf.cell(40, 7, val, border=1, new_x="LMARGIN", new_y="NEXT")
    
    pdf.ln(8)
    
    # Provider breakdown
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "Results by Provider", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(240, 240, 245)
    pdf.cell(60, 8, "Provider", border=1, fill=True)
    pdf.cell(30, 8, "Passed", border=1, fill=True)
    pdf.cell(30, 8, "Failed", border=1, fill=True)
    pdf.cell(30, 8, "Total", border=1, fill=True)
    pdf.cell(30, 8, "Pass Rate", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Helvetica", "", 10)
    for p in sorted(prov_stats.keys()):
        s = prov_stats[p]
        t = s["pass"] + s["fail"]
        r = round(s["pass"] / t * 100) if t > 0 else 0
        pdf.cell(60, 7, prov_names.get(p, p.upper()), border=1)
        pdf.cell(30, 7, str(s["pass"]), border=1)
        pdf.cell(30, 7, str(s["fail"]), border=1)
        pdf.cell(30, 7, str(t), border=1)
        pdf.cell(30, 7, f"{r}%", border=1, new_x="LMARGIN", new_y="NEXT")
    
    pdf.ln(8)
    
    # Severity breakdown
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "Failed Findings by Severity", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(240, 240, 245)
    pdf.cell(50, 8, "Severity", border=1, fill=True)
    pdf.cell(30, 8, "Count", border=1, fill=True, new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_font("Helvetica", "", 10)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev_counts[sev] > 0:
            pdf.cell(50, 7, sev, border=1)
            pdf.cell(30, 7, str(sev_counts[sev]), border=1, new_x="LMARGIN", new_y="NEXT")
    
    # ── FAILED FINDINGS BY PROVIDER ──
    for prov_key in sorted(providers_found):
        prov_fails = [f for f in fails if f.get("_provider") == prov_key]
        if not prov_fails:
            continue
        
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.set_text_color(30, 30, 30)
        prov_title = prov_names.get(prov_key, prov_key.upper())
        pdf.cell(0, 12, f"Failed Findings: {prov_title} ({len(prov_fails)})", new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(248, 113, 113)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)
        
        # Group by control
        control_groups = {}
        for f in prov_fails:
            cid = f.get("target", {}).get("target-id", "unknown").upper()
            if cid not in control_groups:
                control_groups[cid] = []
            control_groups[cid].append(f)
        
        for cid in sorted(control_groups.keys()):
            findings = control_groups[cid]
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(60, 60, 60)
            pdf.cell(0, 8, f"{cid}", new_x="LMARGIN", new_y="NEXT")
            
            for f in findings:
                title = f.get("title", "")
                severity = ""
                detail = title
                for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "FAIL"]:
                    if title.startswith(sev + ":"):
                        severity = sev
                        detail = title[len(sev)+2:]
                        break
                
                pdf.set_font("Helvetica", "B", 9)
                pdf.set_text_color(180, 50, 50)
                sev_display = f"  [{severity}]  " if severity else "  "
                pdf.cell(20, 6, sev_display)
                
                pdf.set_font("Helvetica", "", 9)
                pdf.set_text_color(60, 60, 60)
                safe = detail.encode('latin-1', 'replace').decode('latin-1')
                if len(safe) > 120:
                    safe = safe[:117] + "..."
                pdf.cell(0, 6, safe, new_x="LMARGIN", new_y="NEXT")
            
            pdf.ln(2)
    
    # ── PASSED FINDINGS BY PROVIDER ──
    for prov_key in sorted(providers_found):
        prov_passes = [f for f in passes if f.get("_provider") == prov_key]
        if not prov_passes:
            continue
        
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 16)
        pdf.set_text_color(30, 30, 30)
        prov_title = prov_names.get(prov_key, prov_key.upper())
        pdf.cell(0, 12, f"Passed Findings: {prov_title} ({len(prov_passes)})", new_x="LMARGIN", new_y="NEXT")
        pdf.set_draw_color(52, 211, 153)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(5)
        
        for f in prov_passes:
            title = f.get("title", "").replace("PASS: ", "")
            cid = f.get("target", {}).get("target-id", "").upper()
            
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(40, 120, 80)
            pdf.cell(15, 5, cid)
            
            pdf.set_text_color(80, 80, 80)
            safe = title.encode('latin-1', 'replace').decode('latin-1')
            if len(safe) > 130:
                safe = safe[:127] + "..."
            pdf.cell(0, 5, safe, new_x="LMARGIN", new_y="NEXT")
    
    # ── ABOUT PAGE ──
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 16)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(0, 12, "About This Report", new_x="LMARGIN", new_y="NEXT")
    pdf.set_draw_color(34, 211, 238)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(8)
    
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(0, 6, "Generated by OpenFRAMP, an open-source multi-framework compliance scanner.", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, "OpenFRAMP runs inside authorization boundaries where SaaS tools cannot operate.", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    pdf.cell(0, 6, "Frameworks: FedRAMP Moderate (NIST SP 800-53 Rev 5), PCI DSS 4.0.1, SOC 2.", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"OSCAL version: {metadata.get('oscal-version', '1.1.2')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, f"Report scope: {prov_label}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    pdf.cell(0, 6, "https://github.com/RupinderSecurity/openframp", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(148, 163, 184)
    pdf.cell(0, 6, "This report reflects a point-in-time assessment. Cloud environments change continuously.", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, "Re-scan regularly and after infrastructure changes to maintain compliance posture.", new_x="LMARGIN", new_y="NEXT")
    
    import tempfile
    output_path = os.path.join(tempfile.gettempdir(), 'openframp-report.pdf')
    pdf.output(output_path)
    
    return send_from_directory(os.path.dirname(output_path), os.path.basename(output_path),
                              as_attachment=True, download_name=f'openframp-report-{provider}-{datetime.now().strftime("%Y%m%d")}.pdf')
    
    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4000)