import json

from django.shortcuts import render, redirect, reverse
from django.http import HttpResponse
from django.core.paginator import Paginator
from web.models import File
from scapy.all import *
import os
import time
import urllib.parse

# Create your views here.

''' IDS index '''
def index(request):
    return render(request, 'index.html')

''' IDS index redirect '''
def indexRedirect(request):
    return redirect(reverse("index"))

'''file upload and delete view function '''
def package_upload(request):
    if request.method == 'POST':
        if 'upload' in request.POST:
            try:
                file = request.FILES['file']
                file_model = File(name=file.name, path=os.path.join('./pcapng_files', file.name))
                file_model.save()
                destination = open(os.path.join("./pcapng_files", file.name), 'wb+')
                for chunk in file.chunks():
                    destination.write(chunk)
                destination.close()
                return render(request, 'package_upload.html',
                    {'success_message': "上传文件成功"}
                )
            except:
                return render(request, 'package_upload.html',
                    {'error_message': "你没有选择文件"}
                )
        elif 'delete' in request.POST:
            try:
                file_name = request.POST.get('file_name')
                file = File.objects.get(name=file_name)
                os.remove(file.path)
                file.delete()
                return render(request, 'package_upload.html',
                    {'delete_success_message': "删除文件成功"}
                )
            except:
                return render(request, 'package_upload.html',
                    {"delete_error_message": "删除文件失败"}
                )
    else:
        return render(request, 'package_upload.html')


''' protocol resolution view function '''
res, proto_res, time_res = None, None, None
def protocol_resolution(request):
    if request.method == 'POST':
        try:
            file_name = request.POST.get('file_name')
            file_path = File.objects.get(name=file_name).path
            pcaps = rdpcap(file_path)
            global res, proto_res, time_res
            res = pcaps_analysis(pcaps)
            proto_res, time_res = chart(res)
            # 对字典排个序
            time_res = sorted(time_res.items(), key=lambda x : x[0])
            time_res = dict(time_res)
            return protocol_resolution_p(request)
        except:
            return render(request, 'protocol_resolution.html', {"error_message": "文件不存在"})
    else:
        return render(request, 'protocol_resolution.html')

'''protocol resolution paging show function'''
def protocol_resolution_p(request, pIndex = 1):
    try:
        p = Paginator(res, 10)
        if pIndex < 1:
            pIndex = 1
        if pIndex > p.num_pages:
            pIndex = p.num_pages
        resTen = p.page(pIndex)
        context = {"res": resTen, "flag": True, "pIndex": pIndex,
                   "pagelist": p.page_range[max(0, pIndex - 3):min(pIndex + 3, p.num_pages)],
                   "proto_data": json.dumps(proto_res), "time_data": json.dumps(time_res)}
        return render(request, 'protocol_resolution_p.html', context)
    except:
        return redirect(reverse("protocol_resolution"))

''' pcap file analysis main function '''
def pcaps_analysis(pcaps):
    res=[]
    for i in range(len(pcaps)):
        No = i + 1
        ltime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(pcaps[i].time)))
        source = ''
        destination = ''
        protocol = ''
        length = len(pcaps[i])
        information = '' 
        
        # Ethernet
        if pcaps[i].haslayer('Ether'):
            # IPv4
            if pcaps[i].type == 2048:
                source = pcaps[i]['IP'].src
                destination = pcaps[i]['IP'].dst
                information = pcaps[i].show(dump=True)
                # TCP
                if pcaps[i].proto == 6:
                    # HTTP
                    if pcaps[i].sport == 80 or pcaps[i].dport == 80:
                        if pcaps[i].haslayer('Raw'):
                            if pcaps[i].load.find(b'HTTP') != -1 and pcaps[i]['TCP'].flags == 0x18:
                                protocol = 'HTTP'
                                information = pcaps[i].load.splitlines()[0].decode()
                            else:
                                protocol = 'TCP'
                        else:
                            protocol = 'TCP'
                
                    # HTTPS
                    elif pcaps[i].sport == 443 or pcaps[i].dport == 443:
                        if pcaps[i].haslayer('Raw') and pcaps[i]['TCP'].flags == 0x18:
                            protocol = 'TLS'
                        else:
                            protocol = 'TCP'
                
                    else:
                        protocol = 'UnKnown'
                        information = "Can't analyze the pcapng packet"
                # UDP
                elif pcaps[i].proto == 17:
                    # DNS
                    if pcaps[i].haslayer('DNS'):
                        protocol = 'DNS'
                
                    # SSDP
                    elif pcaps[i].sport == 1900 or pcaps[i].dport == 1900:
                        protocol = 'SSDP'

                    # DHCP 
                    elif pcaps[i].sport == 67 or pcaps[i].dport == 67:
                        protocol = 'DHCP'
                
                    else:
                        protocol = 'UnKnown'
                        information = "Can't analyze the pcapng packet"
                # ICMP
                elif pcaps[i].proto == 58:
                    protocol = 'ICMP'
            
                else:
                    protocol = 'UnKnown'
                    information = "Can't analyze the pcapng packet"

            # IPv6
            elif pcaps[i].type == 34525:
                source = pcaps[i]['IPv6'].src
                destination = pcaps[i]['IPv6'].dst
                information = pcaps[i].show(dump=True)
                # TCP
                if pcaps[i].nh == 6:
                    # HTTP
                    if pcaps[i].sport == 80 or pcaps[i].dport == 80:
                        if pcaps[i].haslayer('Raw'):
                            if pcaps[i].load.find(b'HTTP') != -1  and pcaps[i]['TCP'].flags == 0x18:
                                protocol = 'HTTP'
                                information = pcaps[i].load.splitlines()[0].decode()
                            else:
                                protocol = 'TCP'
                        else:
                            protocol = 'TCP'
                
                    # HTTPS
                    elif pcaps[i].sport == 443 or pcaps[i].dport == 443:
                        if pcaps[i].haslayer('Raw') and pcaps[i]['TCP'].flags == 0x18:
                            protocol = 'TLS'
                        else:
                            protocol = 'TCP'
                
                    else:
                        protocol = 'UnKnown'
                        information = "Can't analyze the pcapng packet"

                
                # UDP
                elif pcaps[i].nh == 17:
                    # DNS
                    if pcaps[i].haslayer('DNS'):
                        protocol = 'DNS'
                
                    # SSDP
                    elif pcaps[i].sport == 1900 or pcaps[i].dport == 1900:
                        protocol = 'SSDP'
                
                    # DHCP 
                    elif pcaps[i].sport == 67 or pcaps[i].dport == 67:
                        protocol = 'DHCP'
                
                    else:
                        protocol = 'UnKnown'
                        information = "Can't analyze the pcapng packet"
                # ICMPv6
                elif pcaps[i].nh == 58:
                    protocol = 'ICMPv6'
            
                else:
                    protocol = 'UnKnown'
                information = "Can't analyze the pcapng packet"

            else:
                source = pcaps[i].src
                destination = pcaps[i].dst
            
                # ARP
                if pcaps[i].type == 2054:
                    protocol = 'ARP'
                    # ARP request
                    if pcaps[i].op == 1:
                        # ARP Probe
                        if pcaps[i].psrc == '0.0.0.0':
                            information = f"Who has {pcaps[i].pdst}? (ARP Probe)"
                    
                        elif pcaps[i].pdst != pcaps[i].psrc:
                            information = f"Who has {pcaps[i].pdst}? Tell {pcaps[i].psrc}"
                        # ARP Announcement
                        else:
                            information = f"ARP Announcement for {pcaps[i].psrc}"
                    # ARP reply
                    elif pcaps[i].op == 2:
                        information = f"{pcaps[i].psrc} is at {pcaps[i].hwsrc}"
            
                # Unknown protocol
                else:
                    protocol = 'UnKnown'
                    information = "Can't analyze the pcapng packet"
        # Loopback
        elif pcaps[i].haslayer('Loopback'):
            # IPv4
            if pcaps[i].type == 2048:
                source = '127.0.0.1'
                destination = '127.0.0.1'
            # IPv6
            else:
                source = '::1'
                destination ='::1'
        res.append([No,ltime,source,destination,protocol,length,information])
    return res
        
'''chart  function'''
def chart(res):
        proto_key = set()
        time_key = set()
        for item in res:
            proto_key.add(item[4])
            time_key.add(item[1])
        proto_chart_dict = dict.fromkeys(proto_key, 0)
        time_chart_dict = dict.fromkeys(time_key, 0)
        # 协议流量图字典。key：proto；value：sum of packets。
        for item in res:
            for key in proto_chart_dict.keys():
                if key == item[4]:
                    proto_chart_dict[key] += 1
                    break
        # 时间流量图字典。key：time；value：sum of length。
        for item in res:
            for key in time_chart_dict.keys():
                if key == item[1]:
                    time_chart_dict[key] += item[5]
                    break
        return (proto_chart_dict, time_chart_dict)


''' intrusion detection view function '''
def intrusion_detection(request):
    if request.method == 'POST':
        try:
            file_name = request.POST.get('file_name')
            file_path = File.objects.get(name=file_name).path
            pcaps = rdpcap(file_path)
            res = pcaps_detect(pcaps)
            return render(request, 'intrusion_detection.html',{"sql_get_res": res['sql']['GET'], "sql_post_res": res['sql']['POST'],
                "xss_get_res": res['xss']['GET'], "xss_post_res": res['xss']['POST']
                })
        except:
            return render(request, 'intrusion_detection.html', {"error_message": "文件不存在"})
    else:
        return render(request, 'intrusion_detection.html')

'''pcap file detection '''
def pcaps_detect(pcaps):
    res = {'sql':{}, 'xss':{}}
    res['sql'] = sql_detect(pcaps)
    res['xss'] = xss_detect(pcaps)
    return res


'''pcap file sql injection detection'''
def sql_detect(pcaps):
    res = {'GET':[], 'POST':[]}
    payloads = []
    dic = open(os.path.join("./dic_files/sql_dic.txt"), "r");
    for payload in dic:
        payloads.append(payload)
    get_http_pcaps = []
    post_http_pcaps = []
    for i in range(len(pcaps)):
        No = i + 1
        ltime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(pcaps[i].time)))
        if pcaps[i].haslayer('TCP') and pcaps[i].haslayer('Raw') and pcaps[i].load.find(b'HTTP') != -1:
            # Get请求取HTTP请求头
            if pcaps[i].load.find(b'GET') == 0:
                get_http_pcaps.append([No, ltime, urllib.parse.unquote(pcaps[i].load.decode(errors='ignore').split('\r\n')[0])])
            # Post请求取HTTP数据
            elif pcaps[i].load.find(b'POST') == 0:
                data = urllib.parse.unquote(pcaps[i].load.decode(errors='ignore').split('\r\n\r\n')[1])
                # 如果post的数据为空，证明数据在下一个报文的load中
                if data != '':
                    post_http_pcaps.append([No, ltime, data])
                else:
                    post_http_pcaps.append([No, ltime, urllib.parse.unquote(pcaps[i+1].load.decode(errors='ignore'))])
    
    # GET型注入检测
    for http_pcap in get_http_pcaps:
        for payload in payloads:
            payload = payload.replace("\n","")
            if payload in http_pcap[2]:
                res['GET'].append(http_pcap);
                break
    
    # POST型注入检测
    for http_pcap in post_http_pcaps:
        for payload in payloads:
            payload = payload.replace("\n","")
            if payload in http_pcap[2]:
                res['POST'].append(http_pcap);
                break

    dic.close()
    return res

'''pcap file xss injection detection'''
def xss_detect(pcaps):
    res = {'GET':[], 'POST':[]}
    payloads = []
    dic = open(os.path.join("./dic_files/xss_dic.txt"), "r");
    for payload in dic:
        payloads.append(payload)
    get_http_pcaps = []
    post_http_pcaps = []
    for i in range(len(pcaps)):
        No = i + 1
        ltime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(pcaps[i].time)))
        if pcaps[i].haslayer('TCP') and pcaps[i].haslayer('Raw') and pcaps[i].load.find(b'HTTP') != -1:
            # Get请求取HTTP请求头
            if pcaps[i].load.find(b'GET') == 0:
                get_http_pcaps.append([No, ltime, urllib.parse.unquote(pcaps[i].load.decode(errors='ignore').split('\r\n')[0])])
            # Post请求取HTTP数据
            elif pcaps[i].load.find(b'POST') == 0:
                data = urllib.parse.unquote(pcaps[i].load.decode(errors='ignore').split('\r\n\r\n')[1])
                # 如果post的数据为空，证明数据在下一个报文的load中
                if data != '':
                    post_http_pcaps.append([No, ltime,data])
                else:
                    post_http_pcaps.append([No, ltime, urllib.parse.unquote(pcaps[i+1].load.decode(errors='ignore'))])
    
    # GET型注入检测
    for http_pcap in get_http_pcaps:
        for payload in payloads:
            payload = payload.replace("\n","")
            if payload in http_pcap[2]:
                res['GET'].append(http_pcap);
                break
    
    # POST型注入检测
    for http_pcap in post_http_pcaps:
        for payload in payloads:
            payload = payload.replace("\n","")
            if payload in http_pcap[2]:
                res['POST'].append(http_pcap);
                break

    dic.close()
    return res


def real_time_network(request):
    return render(request, 'real_time_network.html')