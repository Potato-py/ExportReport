# coding: utf-8
from datetime import datetime
from lxml import etree  # pip3 insatll wheel
import base64, zlib
import requests, json
import configparser

requests.packages.urllib3.disable_warnings()

config = configparser.ConfigParser()
config.read('./config.ini')
file_name = config['awvs']['awvs_report_file']

# 获取awvs的基本数据
def format_awvs_targets_data(targets_list):
    tmp_data = {'目标主机': targets_list['host'], '目标地址': targets_list['start_url'], '目标服务': targets_list['server'],
                '目标描述': targets_list['host'],
                '开始时间': datetime.fromisoformat(targets_list['start_date']).strftime('%Y-%m-%d %H:%M:%S'),  # 转换时间格式
                '结束时间': datetime.fromisoformat(targets_list['end_date']).strftime('%Y-%m-%d %H:%M:%S'),
                '风险数量': {"high": 0, "medium": 0, "low": 0}, '主机发现': targets_list['hosts_discovered']}
    return tmp_data


# 获取awvs中的漏洞数据
def format_awvs_vulns_data(vt_data_dic, decode_scan_data, decode_targets_data, response_str):
    vt_data = vt_data_dic[decode_scan_data['vt_id']]
    tmp_data = {'漏洞ID': decode_scan_data['vt_id'],
                '来源': decode_scan_data['source'],
                '漏洞细节': decode_scan_data['details'],
                '首次发现漏洞的日期': decode_scan_data['first_seen'],
                '风险名称': decode_scan_data['name'],
                '目标主机': decode_scan_data['host'],
                '请求数据': decode_scan_data['request'],
                '响应数据': response_str,
                '目标地址': decode_scan_data['url'],
                '目标描述': decode_scan_data['loc_url'],
                '分类地址': decode_scan_data['loc_url'],
                '危险分类': decode_targets_data['start_url'],
                '影响': vt_data['impact'],
                '风险描述': vt_data['description'],
                '修复建议': vt_data['recommendation'],
                '风险标签': ', '.join(vt_data['tags']),
                'cvss评分': vt_data['cvss_score'],
                '参考': vt_data['refs'], '风险类型': vt_data['type'],
                '风险级别': '高' if vt_data['severity'] == 3 else '中' if vt_data['severity'] == 2 else '低'}
    return tmp_data


# 风险计数
def targets_severity_counts(targets_info, vuln_info):
    for targets in targets_info:
        for vuln in vuln_info:
            if vuln['危险分类'] == targets['目标地址']:
                if vuln['风险级别'] == '高':
                    targets['风险数量']['high'] += 1
                if vuln['风险级别'] == '中':
                    targets['风险数量']['medium'] += 1
                if vuln['风险级别'] == '低':
                    targets['风险数量']['low'] += 1
    return targets_info


# 获取awvs漏扫报告中的数据，并将其解密
def get_awvs_html_data():
    global decode_targets_data
    print('\033[32m[o] AWVS Html提取信息中…… \033[0m')
    html = etree.parse(file_name, etree.HTMLParser())
    encode_scan_data_list = html.xpath('//script[@id="scanData"]/text()')[0].split('\n')
    vt_data_dic = {}
    targets_info = []
    vuln_info = []
    for index, encode_scan_data in enumerate(encode_scan_data_list):
        response_str = ''
        if encode_scan_data.startswith('eyJob3N0IjogIj'):
            decode_targets_data = json.loads(base64.b64decode(encode_scan_data).decode("utf-8", 'ignore'))
            tmp_targets_dic = format_awvs_targets_data(decode_targets_data)
            targets_info.append(tmp_targets_dic)
        if encode_scan_data.startswith('eyJ2dF9pZCI6IC'):
            decode_vt_data = json.loads(base64.b64decode(encode_scan_data).decode("utf-8", 'ignore'))
            vt_data_dic[decode_vt_data['vt_id']] = decode_vt_data
        if encode_scan_data.startswith('H4sIAAAAAAAAA'):
            continue
        if len(encode_scan_data_list) > (index + 1) and encode_scan_data_list[index + 1].startswith('H4sIAAAAAAAAA'):
            response_str = zlib.decompress(base64.decodebytes(encode_scan_data_list[index + 1].encode()),
                                           16 + zlib.MAX_WBITS).decode('utf-8', 'ignore').replace('\x00', '')  # 将响应包中的空字符串全部替换,awvs生成报告时，生成的不完全应该就是这个空字符的问题
        if encode_scan_data.startswith('eyJsb2NfdXJsI'):
            decode_scan_data = json.loads(base64.b64decode(encode_scan_data).decode("utf-8", 'ignore'))
            tmp_vuln_dic = format_awvs_vulns_data(vt_data_dic, decode_scan_data, decode_targets_data, response_str)
            vuln_info.append(tmp_vuln_dic)
    targets_info = targets_severity_counts(targets_info, vuln_info)
    print('\033[32m[o] AWVS Html信息提取完毕!!! \033[0m')
    return targets_info, vuln_info
    #     print(encode_scan_data)

    #     f=open('./html_data.txt','r')
    #     for line in f:
    #         line = line.strip()
    #         with open('./new_html_data.txt','a+') as fd:
    #             if line.startswith('H4sIAAAAAAAAA'):
    #                 decodeStr = zlib.decompress(base64.decodebytes(line.encode()), 16 + zlib.MAX_WBITS).decode("utf-8",'ignore')
    #                 decodeStr = '响应结果'
    #             else:
    #                 decodeStr = base64.b64decode(line).decode("utf-8",'ignore')
    #             fd.write(decodeStr+'\n')
    #     f.close()
