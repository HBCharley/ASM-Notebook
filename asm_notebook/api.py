from flask import Flask, request, jsonify
import typer

from asm_notebook.api_cli import create_company, update_domains, trigger_scan, retrieve_scan_history, retrieve_discovered_assets

app = Flask(__name__)

@app.route('/create_company', methods=['POST'])
def create_company_endpoint():
    data = request.get_json()
    name = data['name']
    company_id = create_company(name)
    return jsonify({'company_id': company_id}), 201

@app.route('/update_domains', methods=['POST'])
def update_domains_endpoint():
    data = request.get_json()
    company_id = data['company_id']
    domains = data['domains']
    update_domains(company_id, domains)
    return jsonify({'message': 'Domains updated'}), 200

@app.route('/trigger_scan', methods=['POST'])
def trigger_scan_endpoint():
    data = request.get_json()
    company_id = data['company_id']
    scan_run_id = trigger_scan(company_id)
    return jsonify({'scan_run_id': scan_run_id}), 201

@app.route('/retrieve_scan_history/<int:company_id>', methods=['GET'])
def retrieve_scan_history_endpoint(company_id):
    scan_history = retrieve_scan_history(company_id)
    return jsonify(scan_history), 200

@app.route('/retrieve_discovered_assets/<int:company_id>', methods=['GET'])
def retrieve_discovered_assets_endpoint(company_id):
    discovered_assets = retrieve_discovered_assets(company_id)
    return jsonify(discovered_assets), 200

if __name__ == "__main__":
    app.run(debug=True)