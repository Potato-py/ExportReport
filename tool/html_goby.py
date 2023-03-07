import json
from datetime import datetime
import pandas as pd  # pip3 install pandas,openpyxl
import configparser

config = configparser.ConfigParser()
config.read('./config.ini')
targets_file = config['goby']['goby_asset_report_file']
vulns_file = config['goby']['goby_vul_report_file']

#
#   This script was written by ZhangRT, and pull request into the potato project.
#

def format_goby_targets_data(target_dict, vulns_dict, targets_info):  # 提取goby中的基本信息
    if not targets_info:
        tmp_target = {
            '目标地址': target_dict['IP'],
            '目标主机': target_dict['Host'],
            '目标描述': target_dict['Host'],
            '开始时间': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            '结束时间': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            '风险数量': {
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }
        targets_info.append(tmp_target)
    for item in vulns_dict:
        for target in targets_info:
            level = item.get('level')
            if level == "High":
                target['风险数量']['high'] += 1
            elif level == "medium":
                target['风险数量']['medium'] += 1
            else:
                target['风险数量']['low'] += 1
    return targets_info


def format_goby_vulns_data(vulns_dict):  # 提取goby中的漏洞信息
    vulns_data = {
        '风险名称': vulns_dict['filename'],
        '风险标签': vulns_dict['filename'],
        '风险描述': vulns_dict['vulurl'],
        '请求数据': '-',
        '响应数据': '-'
    }
    if vulns_dict['level'] == "High":
        vulns_data['风险级别'] = "高"
    elif vulns_dict['level'] == "medium":
        vulns_data['风险级别'] = "中"
    else:
        vulns_data['风险级别'] = "低"
    return vulns_data


def get_goby_html_data():  # 提取goby文件中的数据
    print('\033[32m[o] Goby Html提取信息中…… \033[0m')
    targets_info = []
    vuln_info = []
    target_dic = pd.read_excel(targets_file).to_dict(orient='records')
    vulns_dic = pd.read_excel(vulns_file).to_dict(orient='records')
    for i in target_dic:
        targets_info = format_goby_targets_data(i, vulns_dic, targets_info)
    for j in vulns_dic:
        vuln_info.append(format_goby_vulns_data(j))
    return targets_info, vuln_info
