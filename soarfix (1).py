from flask import Flask, request, jsonify
import requests
from functools import wraps
import time
import ipaddress

app = Flask(__name__)

# FortiGate API configuration
FORTIGATE_URL = "http://10.10.10.42/api/v2"
API_TOKEN = "sfx8Qrqc1hp17gtfqzpg5zr5q361xj" # untuk akses ke fw
HEADERS = {"Authorization": f"Bearer {API_TOKEN}", "Content-Type": "application/json"}
API_KEY = "3bf19c3f517e434085ec99def3c5db83"  # Define the API key required for requests untuk akses ke flask
IP_ADDRESS_DATABASE = {}

# TODO: read from json
# { "ip_address": [
# {"timestamp": "", "ip": "", "status": ""}
# ]  
# }
# with open("ip_address_database.json", "r") as doc:
#     IP_ADDRESS_DATABASE = json.loads(doc.read())


def is_local_ip(ip):
    try:
        # Konversi string IP menjadi objek ipaddress
        ip_obj = ipaddress.ip_address(ip)
        # Periksa apakah IP termasuk dalam range lokal
        return ip_obj.is_private or ip_obj.is_loopback
    except ValueError:
        # IP tidak valid
        return False


def require_api_key(func):
    """Decorator to require API key in request headers."""
    @wraps(func)  # Use wraps to preserve the original function name
    def wrapper(*args, **kwargs):
        if request.headers.get("Authorization") == f"Bearer {API_KEY}":
            return func(*args, **kwargs)
        else:
            return jsonify({"error": "Unauthorized"}), 401
    return wrapper

@app.route('/block_ip', methods=['POST'])
@require_api_key
def block_ip():
    try:
        ip_statuses = {}
        datas = request.json

        # Cek apakah 'data' adalah list
        if isinstance(datas, list):
            for data in datas:
                try:
                    ip_to_block = data.get("address")
                    address_group_name = "SOAR_BLOCKING"  # Specify the address group to use

                    if not ip_to_block:
                        raise Exception("IP address is required")

                    if ip_to_block == "255.255.255.255" or is_local_ip(ip_to_block):
                        continue

                    # # TODO: If IP already blocked, please continue
                    # if ip_to_block in IP_ADDRESS_DATABASE:
                    #     continue

                    # 1. Create the address object
                    address_payload = {
                        "name": ip_to_block,
                        "subnet": f"{ip_to_block} 255.255.255.255",
                        "comment": "Blocked via API",
                        "type": "ipmask"
                    }

                    address_response = requests.post(
                        f"{FORTIGATE_URL}/cmdb/firewall/address",
                        headers=HEADERS,
                        json=address_payload
                    )
                    address_response.raise_for_status()
                    print(address_response.json(), flush=True)

                    # 2. Add the new address to the existing address group
                    group_payload = {"name": ip_to_block}
                    group_response = requests.post(
                        f"{FORTIGATE_URL}/cmdb/firewall/addrgrp/{address_group_name}/member",
                        headers=HEADERS,
                        json=group_payload
                    )
                    group_response.raise_for_status()
                    print(group_response.json(), flush=True)

                    ip_statuses[ip_to_block] = "success"
                    time.sleep(5)

                except Exception as e:
                    ip_statuses[ip_to_block] = "failed"
                    print(f"{ip_to_block} Error: {e}")

        elif isinstance(datas, dict):
            try:
                ip_to_block = datas.get("address")
                address_group_name = "SOAR_BLOCKING"  # Specify the address group to use

                if not ip_to_block:
                    raise Exception("IP address is required")

                if ip_to_block == "255.255.255.255" or is_local_ip(ip_to_block):
                    raise Exception("IP is a local address")

                # 1. Create the address object
                address_payload = {
                    "name": ip_to_block,
                    "subnet": f"{ip_to_block} 255.255.255.255",
                    "comment": "Blocked via API",
                    "type": "ipmask"
                }

                address_response = requests.post(
                    f"{FORTIGATE_URL}/cmdb/firewall/address",
                    headers=HEADERS,
                    json=address_payload
                )
                address_response.raise_for_status()
                print(address_response.json(), flush=True)

                # 2. Add the new address to the existing address group
                group_payload = {"name": ip_to_block}
                group_response = requests.post(
                    f"{FORTIGATE_URL}/cmdb/firewall/addrgrp/{address_group_name}/member",
                    headers=HEADERS,
                    json=group_payload
                )
                group_response.raise_for_status()
                print(group_response.json(), flush=True)

                ip_statuses[ip_to_block] = "success"

            except Exception as e:
                ip_statuses[ip_to_block] = "failed"
                print(f"{ip_to_block} Error: {e}")

        return jsonify({"message": ip_statuses}), 200

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to block IP: {e}"}), 500


@app.route('/block_domain', methods=['POST'])
@require_api_key
def block_domain():
    try:
        data = request.json  # Expects {"domain": "<domain_to_block>"}
        domain_to_block = data.get("domain")
        id_filter = 1  # Specify the filter id for the URL filter list

        if not domain_to_block:
            return jsonify({"error": "Domain is required"}), 400

        # Create the web filter entry
        domain_payload = {
            "url": domain_to_block,
            "type": "simple",
            "action": "block",
            "status": "enable"
        }

        domain_response = requests.post(
            f"{FORTIGATE_URL}/cmdb/webfilter/urlfilter/{id_filter}/entries",
            headers=HEADERS,
            json=domain_payload
        )
        domain_response.raise_for_status()

        return jsonify({"message": f"Domain {domain_to_block} blocked successfully"}), 200

    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to block domain: {e}"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, ssl_context=('/opt/soar/certificate.crt', '/opt/soar/private.key'))
