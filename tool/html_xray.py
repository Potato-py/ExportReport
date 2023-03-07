# coding: utf-8
import json
import time
import re
import tldextract
from lxml import etree  # pip3 install wheel
import configparser

config = configparser.ConfigParser()
config.read('./config.ini')
file_name = config['xray']['xray_report_file']

heightType = ['sqldet', 'cmd-injection', 'xxe', 'phantasm', 'upload', 'brute-force', 'struts', 'thinkphp']
mediumType = ['xss', 'path-traversal', 'ssrf']
lowType = ['dirscan', 'jsonp', 'baseline', 'redirect', 'crlf-injection']


# 获取xray中的基本数据
def format_xray_targets_data(vuln_info, targets_info, vuln_time):
    if not targets_info:
        tmp_data = {'目标地址': vuln_info['目标地址'], '目标描述': vuln_info['目标描述'], '目标主机': vuln_info['目标主机'],
                    '开始时间': 1,
                    '结束时间': 1,
                    '风险数量': {"high": 0, "medium": 0, "low": 0}}
        targets_info.append(tmp_data)
    for target in targets_info:
        target['开始时间'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(min(vuln_time) / 1000)))
        target['结束时间'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(max(vuln_time) / 1000)))
        if target['目标主机'] == vuln_info['目标主机']:
            if any(a in vuln_info['风险标签'] for a in heightType):
                target['风险数量']['high'] += 1
            elif any(a in vuln_info['风险标签'] for a in mediumType):
                target['风险数量']['medium'] += 1
            else:
                target['风险数量']['low'] += 1
    return targets_info


# 整理xray报告中的漏洞数据
def format_xray_vulns_data(vt_data, ):
    domainInfo = tldextract.extract(vt_data['target']['url'])
    ip_pattern = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")  # 获取ip地址
    tmp_data = {'目标主机': ip_pattern.search(vt_data['target']['url']).group(0), '风险名称': vt_data['plugin'],
                '风险标签': vt_data['plugin'], '风险描述': vt_data['plugin'],
                '目标地址': domainInfo.domain + '.' + domainInfo.suffix if domainInfo.suffix else domainInfo.domain}
    if isinstance(vt_data['detail']['snapshot'][0], str):
        tmp_data['请求数据'] = vt_data['detail']['snapshot'][0]
        tmp_data['响应数据'] = vt_data['detail']['snapshot'][1]
    else:
        tmp_data['请求数据'] = vt_data['detail']['snapshot'][0][0]
        tmp_data['响应数据'] = vt_data['detail']['snapshot'][0][1]
    if any(a in vt_data['plugin'] for a in heightType):
        tmp_data['风险级别'] = '高'
    elif any(a in vt_data['plugin'] for a in mediumType):
        tmp_data['风险级别'] = '中'
    else:
        tmp_data['风险级别'] = '低'
    return tmp_data


# 获取xray漏扫报告中的数据
def get_xray_html_data():
    print('\033[32m[o] Xray Html提取信息中…… \033[0m')
    Vulns_time = []
    targets_info = []
    vuln_info = []
    html = etree.parse(file_name, etree.HTMLParser())
    data_list = html.xpath('//script[@class="web-vulns"]/text()')
    for data in data_list:
        tmp_vulns_dic = format_xray_vulns_data(json.loads(data[14:-1]))
        vuln_info.append(tmp_vulns_dic)
        Vulns_time.append(json.loads(data[14:-1])['create_time'])
        targets_info = format_xray_targets_data(tmp_vulns_dic, targets_info, Vulns_time)
    print('\033[32m[o] Xray Html信息提取完毕!!! \033[0m')
    return targets_info, vuln_info

# get_xray_html_data('../0823.html')
