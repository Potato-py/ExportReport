import requests, json, sys
requests.packages.urllib3.disable_warnings()
import configparser

#
#   nessus商业版才支持API、故本脚本废弃
#   若有好心人更新该脚本请pull request
#

config = configparser.ConfigParser()
config.read('./config.ini')
nessus_url = config['nessus']['nessus_url']
nessus_accesskey = config['nessus']['nessus_accesskey']
nessus_secretkey = config['nessus']['nessus_secretkey']
nessus_headers = {'X-ApiKeys': f'accessKey={nessus_accesskey}; secretkey={nessus_secretkey}', 'Accept': 'application/json'}

def get_nessus_api_data():
    print('\033[32m[o] Nessus API提取信息中…… \033[0m')
    targets_info = []
    vuln_info = []

    try:
        response_targets = requests.get(f'{nessus_url}/scans', headers=nessus_headers, verify=False)
        targets_list = json.loads(response_targets.content)
        print(targets_list)
#         [targets_info.append(format_nessus_targets_data(targets)) for targets in targets_list]
#
#         response = requests.get(f'{nessus_url}/api/v1/vulnerabilities', headers=nessus_headers, verify=False) #高中低位，排除信息告警
#         content = json.loads(response.content)
#         for vuln in content['vulnerabilities']:
#             #   排除信息级漏洞
#             if vuln['severity'] == 0:
#                 continue
#
#             vuln_id = vuln['vuln_id']
#
#             response_details = requests.get(f'{nessus_url}/api/v1/vulnerabilities/{vuln_id}', headers=nessus_headers, verify=False) #0-3
#             content_details = json.loads(response_details.content)
#
#             response_response = requests.get(f'{nessus_url}/api/v1/vulnerabilities/{vuln_id}/http_response', headers=nessus_headers, verify=False) #0-3
#             content_response = response_response.text
#             content_details['response'] = content_response
#
#             tmp_data = format_nessus_vulns_data(content_details)
#
#             vuln_info.append(tmp_data)
#         return targets_info, vuln_info
    except Exception as e:
        print(f'\033[31m[x] {str(e)} \033[0m')
        sys.exit()

    print('\033[32m[o] Nessus API信息提取完毕!!! \033[0m')
