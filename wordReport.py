from docxtpl import DocxTemplate, InlineImage
from docx.shared import Mm  # 毫米
import plotly as py  # pip3 install kaleido
import plotly.graph_objs as go
from io import BytesIO
import datetime
from colorama import init

init(autoreset=True)


class Report:
    def __init__(self, targets_info, vuln_info, doc='./reportDemo/reportDemo.docx', out_file=''):
        self.targets_info = targets_info
        self.vuln_info = vuln_info
        self.out_file = out_file
        self.demo_doc = doc if doc else './reportDemo/reportDemo.docx'
        # 加载模板文件
        self.doc = DocxTemplate(self.demo_doc)

    #   风险名称统计
    #   [ {'风险名称':'sql注入','风险标签':['web安全'],'风险数量':4}, {'风险名称':'RCE','风险类型':['web安全'],'风险数量':3} ]
    def vulnCount(self, vulns_list):
        print('\033[32m[o] 风险数量统计中…… \033[0m')
        vuln_count_list = []
        [vuln_count_list.append({'风险名称': vuln['风险名称'], '风险标签': vuln['风险标签'], '风险数量': 0}) for vuln in
         vulns_list if
         {'风险名称': vuln['风险名称'], '风险标签': vuln['风险标签'], '风险数量': 0} not in vuln_count_list]
        #   计入相同漏洞名个数
        for index, vuln_count in enumerate(vuln_count_list):
            for vuln in vulns_list:
                if vuln['风险名称'] == vuln_count['风险名称']:
                    vuln_count_list[index]['风险数量'] += 1
        return vuln_count_list

    #   饼状图绘制,返回图片IO数据流
    #   其他绘制参考：https://zhuanlan.zhihu.com/p/484401646
    def getImage(self, values, labels, title):
        print('\033[32m[o] 饼状图绘制中…… \033[0m')
        pyplt = py.offline.plot
        trace = [go.Pie(labels=labels, values=values)]
        layout = go.Layout(title=title)
        fig = go.Figure(data=trace, layout=layout)
        image_io = BytesIO()
        fig.write_image(image_io, format="jpeg", scale=3)  # scale调整清晰度
        return image_io

    #   将所有漏洞list以高、中、低危害进行划分
    #   rank_list = [[高危],[中危],[低危]]
    def sortVuln(self, vuln_info):
        print('\033[32m[o] 漏洞按风险级别分类中…… \033[0m')
        vuln_h_list = []
        vuln_m_list = []
        vuln_d_list = []
        for vuln in vuln_info:
            if vuln['风险级别'] == '高':
                vuln_h_list.append(vuln)
            if vuln['风险级别'] == '中':
                vuln_m_list.append(vuln)
            if vuln['风险级别'] == '低':
                vuln_d_list.append(vuln)
        print('\033[32m[o] 漏洞按风险级别分类完毕!!! \033[0m')
        return vuln_h_list, vuln_m_list, vuln_d_list

    #   ↓ ↓ ↓ 自定义方法在此处添加 ↓ ↓ ↓
    #   ↑ ↑ ↑ 自定义方法在此处添加 ↑ ↑ ↑

    def create(self):
        vuln_h_list, vuln_m_list, vuln_d_list = self.sortVuln(self.vuln_info)
        #   针对高、中、低危进行统计计算
        vuln_h_Count = self.vulnCount(vuln_h_list)
        vuln_m_Count = self.vulnCount(vuln_m_list)
        vuln_d_Count = self.vulnCount(vuln_d_list)
        print('\033[32m[o] 风险数量统计完毕!!! \033[0m')
        #   高中低纬度下的饼状图  [[[若不需要请注释]]]
        line_charts = self.getImage([len(vuln_h_list), len(vuln_m_list), len(vuln_d_list)], ['高危', '中危', '低危'], '风险级别')
        #   漏洞名称纬度下的饼状图  [[[若不需要请注释]]]
        tmp_img_value = []
        tmp_img_nama = []
        vuln_Count = vuln_h_Count + vuln_m_Count + vuln_d_Count
        [tmp_img_value.append(vuln['风险数量']) for vuln in vuln_Count]
        [tmp_img_nama.append(vuln['风险名称']) for vuln in vuln_Count]
        line_charts_all = self.getImage(tmp_img_value, tmp_img_nama, '风险级别')
        print('\033[32m[o] 饼状图绘制完毕!!! \033[0m')

        # 获取开始时间和结束时间
        min_start_time = None
        max_end_time = None
        for item in self.targets_info:
            start_time = datetime.datetime.strptime(item["开始时间"], "%Y-%m-%d %H:%M:%S")
            end_time = datetime.datetime.strptime(item["结束时间"], "%Y-%m-%d %H:%M:%S")
            if not min_start_time or start_time < min_start_time:
                min_start_time = start_time
            if not max_end_time or end_time > max_end_time:
                max_end_time = end_time

        #   ↓ ↓ ↓ 二改自定义数据在此处添加 ↓ ↓ ↓
        #   ↑ ↑ ↑ 二改自定义数据在此处添加 ↑ ↑ ↑

        data_dic = {
            '项目名称': 'XXX集团',
            '测试单位': 'Potato',
            '大图标': InlineImage(self.doc, './img/logo.png', height=Mm(20)),
            '小图标': InlineImage(self.doc, './img/logo.png', height=Mm(7.3)),
            '密级': '商业保密',
            '开始时间': min_start_time,
            '结束时间': max_end_time,
            '生成时间': datetime.datetime.now().strftime('%Y年%m月%d日'),
            '版本编号': 'V1.0',
            '版本说明': '由DX-Tools导出初版渗透测试报告',
            '制作人': 'DX-Tools',
            '目标详情': self.targets_info,
            '目标总数': len(self.targets_info),
            '高危详情': vuln_h_list,
            '中危详情': vuln_m_list,
            '低危详情': vuln_d_list,
            '高危总数': len(vuln_h_list),
            '中危总数': len(vuln_m_list),
            '低危总数': len(vuln_d_list),
            '风险总数': len(vuln_h_list) + len(vuln_m_list) + len(vuln_d_list),
            '高危统计': vuln_h_Count,
            '中危统计': vuln_m_Count,
            '低危统计': vuln_d_Count,
            '级别饼图': InlineImage(self.doc, line_charts, height=Mm(90)),
            '全量饼图': InlineImage(self.doc, line_charts_all, height=Mm(90)),
        }
        print(f'\033[32m[o] 引用模板文件【{self.demo_doc}】，导出最终报告中……')
        self.doc.render(data_dic, autoescape=True)  # 填充数据
        out_file = self.out_file if self.out_file else f"{data_dic['项目名称']}渗透测试报告_{data_dic['生成时间']}.docx"
        self.doc.save('./result/'+out_file)  # 保存目标文件
        print(f'\033[32m[o] 报告导出完毕，文件：【./result/{out_file}】 \033[0m')
