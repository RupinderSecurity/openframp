from flask import Flask, jsonify, send_from_directory, request
import json
import subprocess
import os

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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=4000)