# 0x01 概述：
 
- 本项目用于<u>**自动化生成报告**</u>。可根据项目需求，通过简单的提取变量来<u>**自定义报告模板**</u>。内附<u>**常见扫描器API/原报告(awvs、xray、goby)数据提取模块**</u>，可直接生成全新的自定义报告。
- 对有复杂的功能需求时，<u>**适用于有Python基础的人使用**</u>。
- 本项目内附<u>**二次开发所用的资料文档**</u>，欢迎各位提Pull Request。

![image](/img/11.png)

- This project is used for <u>**automatic generation of reports**</u>. According to the project requirements, you can <u>**customize the report template**</u> by simply extracting variables. The attached <u>**common scanner API/original report (awvs, xray, goby) data extraction module**</u> can directly generate new customized reports.
- For complex functional requirements, <u>**is suitable for people with Python foundation to use**</u>.
- The project is <u>**attached with the data and documents used for the secondary development**</u>. Welcome to pull requests.

## 适用场景：

- **适用于[安服仔]、[渗透仔]、[SRC仔]**：常见漏扫工具扫描完毕后，一键导出项目报告
- **适用于[漏扫开发仔]**：将漏扫结果导出自定义格式化报告

# 0x02 目录架构：

- **tool**[dir]：常见工具报告\API数据提取模块目录；
- **reportDemo**[dir]：报告模板目录；
- **testReport**[dir]：测试使用的awvs、xray、goby等原报告目录(内容可删除)；
- **result**[dir]：输出结果目录；
- **img**[dir]：wordDemo资源加载图片、readme文档测试图片目录(测试图片可删除)；
- **refer**[dir]：二开参考数据目录；

# 0x03 开始使用：

## 1、安装三方包：

- 执行命令：**pip install -r requirements.txt**

## 2、配置对应API认证Key/原报告文件路径：

- config.ini

## 3、自写漏扫接入使用方法：

```
from wordReport import *

  targets_info = 目标信息(格式可参考./refer/xxx_targets_Demo.txt)
  vulns_info = 漏洞信息(格式可参考./refer/xxx_vulns_Demo.txt)
  demo = 报告模板 【默认使用：./reportDemo/reportDemo.docx】
  out = 输出文件路径 【默认：./result/{项目名称}渗透测试报告_{'生成时间'}.docx】

  reportWord = Report(targets_info, vulns, demo, out)
  reportWord.create()
``` 

## 4、常见工具导出报告数据提取，形成新报告：

- python drawReport.py -m [api_awvs/html_awvs/html_goby/html_xray] -d ./reportDemo/reportDemo.docx -o ./result/报告名称.docx
- 例如：python drawReport.py -m html_awvs

  ![image](/img/1.png)

  ![image](/img/2.png)

  ![image](/img/3.png)

  ![image](/img/4.png)

  ![image](/img/5.png)

## 5、多款工具报告提取后形成新报告：

- 请修改drawReport脚本，将多个get_xxx_xxx_data获取到的targets_info, vuln_info对应组合形成新的targets_info, vuln_info，最后调用
  reportWord = Report(targets_info, vuln_info)
  reportWord.create()
- 因为会涉及不同数据直接格式略有不同，作者懒，所以没写，等着闲人pull request

# 0x04 二改调用三方API/html提取请看以下内容：

## 1、html_xray脚本二改可参考的数据文档：

- 【**./refer/html_xray_data.txt**】：为xray页面提取出来的漏洞信息

## 2、api_awvs脚本二改可参考的数据文档：

- https://个人awvs地址:3443/Acunetix-API-Documentation.html
- https://www.sqlsec.com/2020/04/awvsapi.html
- 【**./refer/api_awvs_vluns_Demo.txt**】：为apiReport.py获取awvs的【**漏洞数据**】结果例子
- 【**./refer/api_awvs_targets_Demo.txt**】：为apiReport.py获取awvs的【**目标数据**】结果例子

## 3、html_awvs脚本二改可参考的数据文档：

- 【**./refer/html_awvs_data.txt**】：记录awvs生成的html中加密的漏洞及目标信息
- 【**./refer/html_awvs_new_data.txt**】：html_awvs_data.txt解密后的数据

## 4、html_goby脚本二改可参考的数据文档：

- 由于goby导出的文档中的数据太少，我将一些必要的做了默认处理（如：开始时间和结束时间）
- 【**./refer/html_goby_target_data.txt**】：为apiReport.py获取goby的【**目标数据**】结果例子
- 【**./refer/html_goby_vulns_data.txt**】：为apiReport.py获取goby的【**漏洞数据**】结果例子

## 5、api_nessus脚本编写请参考链接（注意个人版不支持调用API）：

- https://个人nessus地址:8834/api

# 0x05 更新贡献：
##Thank them for pull request into this project.

- **'html_goby.py'** was written by **ZhangRT**.