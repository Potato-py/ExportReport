import argparse
from wordReport import *
from tool.api_awvs import *
# from tool.api_nessus import *
from tool.html_xray import *
from tool.html_awvs import *
from tool.html_goby import *

#
#   本脚本用于从API\原始报告中提取数据，调用wordReport生成新的报告
#

def initData():
    parser = argparse.ArgumentParser(description="This script is used to extract data from API/original report and call wordReport to generate a new report.")
    parser.add_argument("-m", "--model", dest="model", type=str, required=True, choices=['api_awvs','html_awvs','html_goby','html_xray'], help="选择模式:[api_awvs\html_awvs\html_goby\html_xray]")
    parser.add_argument("-d", "--demo", dest="demo", type=str, help="报告模板 【默认使用：./reportDemo/reportDemo.docx】")
    parser.add_argument("-o", "--out", dest="out", type=str, help="输出文件路径 【默认：./result/{项目名称}渗透测试报告_{'生成时间'}.docx】")
    args = parser.parse_args()
    return args.model, args.demo, args.out

if __name__ == "__main__":
    model, demo, out = initData()
    if model == 'api_awvs':
        targets_info, vuln_info = get_awvs_api_data()
    elif model == 'html_awvs':
        targets_info, vuln_info = get_awvs_html_data()
    elif model == 'html_goby':
        targets_info, vuln_info = get_goby_html_data()
    elif model == 'html_xray':
        targets_info, vuln_info = get_xray_html_data()
#     elif model == 'api_nessus':
#         targets_info, vuln_info = get_nessus_api_data()

    reportWord = Report(targets_info, vuln_info, demo, out)
    reportWord.create()
