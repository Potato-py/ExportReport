# coding= utf-8
import requests, json, sys
import datetime
import configparser

requests.packages.urllib3.disable_warnings()

config = configparser.ConfigParser()
config.read('./config.ini')
awvs_url = config['awvs']['awvs_url']
awvs_api = config['awvs']['awvs_api']
awvs_headers = {'X-Auth': awvs_api, 'Accept': 'application/json'}


def format_awvs_targets_data(targets_list, target_scan):
    tmp_data = {'目标地址': targets_list['description'] if targets_list['description'] else '-',
                '目标主机': targets_list['address'],
                '目标描述': targets_list['description'] if targets_list['description'] else '-',
                '危险程度': targets_list['criticality'], '目标ID': targets_list['target_id'],
                '开始时间': datetime.datetime.strptime(target_scan['start_date'], '%Y-%m-%dT%H:%M:%S.%f%z').strftime(
                    '%Y-%m-%d %H:%M:%S'),
                '结束时间': datetime.datetime.strptime(target_scan['end_date'], '%Y-%m-%dT%H:%M:%S.%f%z').strftime(
                    '%Y-%m-%d %H:%M:%S'), '上次扫描时间': targets_list['last_scan_date'],
                '上次扫描sessionID': targets_list['last_scan_session_id'], '风险数量': targets_list['severity_counts']
                }
    # tmp_data['扫描认证'] = targets_list['scan_authorization']
    # tmp_data['链接'] = targets_list['link']
    return tmp_data


def format_awvs_vulns_data(content_details):
    tmp_data = {'影响细节': content_details['affects_detail'],
                '受影响链接': content_details['affects_url'],
                '程序': content_details['app'],
                '存档': content_details['archived'],
                'comment': content_details['comment'],
                '置信度': content_details['confidence'],
                '连续': content_details['continuous'],
                '危险程度': content_details['criticality'],
                'cvss2信息': content_details['cvss2'],
                'cvss3信息': content_details['cvss3'],
                'cvss评分': content_details['cvss_score'],
                '风险描述': content_details['description'],
                '漏洞细节': content_details['details'],
                '首次发现漏洞的日期': content_details['first_seen'],
                '亮点': content_details['highlights'],
                '影响': content_details['impact'],
                '问题ID': content_details['issue_id'],
                '问题跟踪ID': content_details['issue_tracker_id'],
                '上次发现漏洞的日期': content_details['last_seen'],
                'locID': content_details['loc_id'],
                '更多描述': content_details['long_description'],
                '修复建议': content_details['recommendation'],
                '参考': content_details['references'],
                '请求数据': content_details['request'],
                '响应信息': content_details['response_info'],
                '响应数据': content_details['response'],
                '风险级别': '高' if content_details['severity'] == 3 else '中' if content_details['severity'] == 2 else '低',
                '来源': content_details['source'],
                '漏洞状态': content_details['status'],
                '风险标签': ', '.join(content_details['tags']),
                '目标描述': content_details['target_description'],
                '目标ID': content_details['target_id'],
                '漏洞录入时间': content_details['vt_created'],
                '漏洞ID': content_details['vt_id'],
                '风险名称': content_details['vt_name'],
                '漏洞更新时间': content_details['vt_updated'],
                '本次漏洞ID': content_details['vuln_id']}
    return tmp_data


def get_awvs_api_data():
    print('\033[32m[o] AWVS API提取信息中…… \033[0m')
    targets_info = []
    vuln_info = []
    global content_details, target_scan
    try:
        response_targets = requests.get(f'{awvs_url}/api/v1/targets', headers=awvs_headers, verify=False)
        targets_list = json.loads(response_targets.content)['targets']
        response_scan = requests.get(f'{awvs_url}/api/v1/scans', headers=awvs_headers, verify=False)  # 连接所有扫描状态
        target_scans = json.loads(response_scan.content)
        response = requests.get(f'{awvs_url}/api/v1/vulnerabilities', headers=awvs_headers, verify=False)  # 高中低位，排除信息告警
        content = json.loads(response.content)
        for vuln in content['vulnerabilities']:
            #   排除信息级漏洞
            if vuln['severity'] == 0:
                continue
            vuln_id = vuln['vuln_id']
            response_details = requests.get(f'{awvs_url}/api/v1/vulnerabilities/{vuln_id}', headers=awvs_headers,
                                            verify=False)  # 0-3
            content_details = json.loads(response_details.content)

            response_response = requests.get(f'{awvs_url}/api/v1/vulnerabilities/{vuln_id}/http_response',
                                             headers=awvs_headers, verify=False)  # 0-3
            content_response = response_response.text
            content_details['response'] = content_response.replace('\x00', '')
            tmp_data = format_awvs_vulns_data(content_details)
            vuln_info.append(tmp_data)
        for scans in target_scans["scans"]:
            scan_id = scans['scan_id']
            scan_session_id = scans['current_session']['scan_session_id']
            res_scan = requests.get(f'{awvs_url}/api/v1/scans/{scan_id}/results/{scan_session_id}/statistics',
                                    headers=awvs_headers, verify=False)  # 获取单个扫描状态
            target_scan = json.loads(res_scan.content)["scanning_app"]['wvs']  # 获取开始时间与结束时间
        [targets_info.append(format_awvs_targets_data(targets, target_scan)) for targets in targets_list]
        print('\033[32m[o] AWVS API信息提取完毕!!! \033[0m')
        return targets_info, vuln_info
    except Exception as e:
        print(f'\033[31m[x] {str(e)} \033[0m')
        sys.exit()
