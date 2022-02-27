# !/usr/bin/env python

from asyncore import write
import subprocess
import threading
import sys
import os
import json
from colorama import Fore

__author__ = 'themalwarenews ( @themalwarenews) '
html_begin = "<html><head><title>APP Analysis Report </title></head><body><h1 style=\"text-align: center;\"><strong>Drozer Analysis Report</strong></h1>"
inspiration = "interference-security"

def welcome():
        __banner__='''\t 
                                                                                           
\t@@@@@@@   @@@@@@@    @@@@@@   @@@@@@@@              @@@@@@    @@@@@@@   @@@@@@   @@@  @@@  
\t@@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@             @@@@@@@   @@@@@@@@  @@@@@@@@  @@@@ @@@  
\t@@!  @@@  @@!  @@@  @@!  @@@       @@!             !@@       !@@       @@!  @@@  @@!@!@@@  
\t!@!  @!@  !@!  @!@  !@!  @!@      !@!              !@!       !@!       !@!  @!@  !@!!@!@!  
\t@!@  !@!  @!@!!@!   @!@  !@!     @!!    @!@!@!@!@  !!@@!!    !@!       @!@!@!@!  @!@ !!@!  
\t!@!  !!!  !!@!@!    !@!  !!!    !!!     !!!@!@!!!   !!@!!!   !!!       !!!@!!!!  !@!  !!!  
\t!!:  !!!  !!: :!!   !!:  !!!   !!:                      !:!  :!!       !!:  !!!  !!:  !!!  
\t:!:  !:!  :!:  !:!  :!:  !:!  :!:                      !:!   :!:       :!:  !:!  :!:  !:!  
\t :::: ::  ::   :::  ::::: ::   :: ::::             :::: ::    ::: :::  ::   :::   ::   ::  
\t:: :  :    :   : :   : :  :   : :: : :             :: : :     :: :: :   :   : :  ::    :   
                                                                                           
 '''
        
        print("\n")
        print(Fore.RED+" \t \t Automated drozer to test the android components Security\n")
        print(Fore.GREEN+__banner__)
       
        print ("      ------------------------------------------------------------------")
        print ("\n\t| TOOL    :  DROZER-SCANNER\t\t|")
        print ("\t| AUTHOR  :  " + __author__ + " |") 
        print ("\t| Inspiration  :  " + inspiration + "\t\t|")
        

        print ("\t| VERSION :  1.0  \t\t\t\t|\n")
        print ("      ------------------------------------------------------------------")

        print("\n\n")
        print(Fore.RED+"\t NOTE: MAKE SURE YOU HAVE TURNED ON YOUR ANDROID VIRTUAL DEVICE / REAL DEVICE AND CONNECTED VIA ADB")


def __perform_scan__(query_type,p_name,a=0):
    drozer_command = 'drozer console connect -c "run ' + str(query_type)+ ' ' + str(p_name)+ '"'
    if a==1:
        drozer_command = 'drozer console connect -c "run ' + str(query_type)+' '+'"'
    process = subprocess.Popen(drozer_command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,shell=True,universal_newlines=True)
    input,output = process.stdin,process.stdout
    process_data = output.read()
    input.close()
    output.close()
    status=process.wait()
    if int(process_data.find("could not find the package"))!=-1:
        process_data = 'Invaliid Package'
    else:
        pass
    return process_data

def __format_data__(task,result,file_name):
    html_out = 1
    separator = ("*"*50)
    print(Fore.GREEN+"\n%s:\n%s\n%s" % (task,separator,result))
    result = result.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\\n","<br>").replace("\\r","")
    final_res={str(task):result}
    with open(file_name, "a") as outfile:
        json.dump(final_res,outfile)
    if html_out:
        global html_begin
        html_begin += "<table style=\"border-style: solid; width: 100%; margin-left: auto; margin-right: auto;\" border=\"1\" width=\"100%\"><tbody><tr style=\"background: #12294d; color: #ffffff; text-align: left;\"><td>"+task+"</td></tr><tr><td style=\"text-align: left;\"><pre style=\"line-height: 0.8em;\"><span >"+result+"</span></pre></td></tr></tbody></table><br><br>"



if __name__ == '__main__': 
    welcome()
    print(Fore.BLUE+"\n \n[+]Enter the Package Name")
    p_name=input("\t[+] Tha Package name is :  ")

    print("\n [+]Enter the file name to store the results ")
    file_name=input("\t[+] the file name is : ")
    f_json=file_name+".json"
    f_html=file_name+".html"
    

    separator =(("_"*100)+"\n")
    

    print(Fore.GREEN+separator)
    #Get Package complete Info
    package_info=__perform_scan__('app.package.info -a',p_name)
    __format_data__("Package Information", package_info,f_json)
    print(separator)

    #Get activities information
    activity_info = __perform_scan__('app.activity.info -i -u -a', p_name)
    __format_data__("Activities Information", activity_info,f_json)
    print(separator)

    #Get broadcast receivers information
    broadcast_info = __perform_scan__('app.broadcast.info -i -u -a', p_name)
    __format_data__("Broadcast Receivers Information", broadcast_info,f_json)
    print(separator)

    #Get attack surface details
    attacksurface_info = __perform_scan__('app.package.attacksurface', p_name)
    __format_data__("Attack Surface Information", attacksurface_info,f_json)
    print(separator)

    #Get package with backup API details
    backupapi_info = __perform_scan__('app.package.backup -f', p_name)
    __format_data__("Package with Backup API Information", backupapi_info,f_json)
    print(separator)

    #Get Android Manifest of the package
    manifest_info = __perform_scan__('app.package.manifest', p_name,file_name)
    __format_data__("Android Manifest File", manifest_info,f_json)
    print(separator)

    #Get native libraries information
    nativelib_info = __perform_scan__('app.package.native', p_name)
    __format_data__("Native Libraries used", nativelib_info,f_json)
    print(separator)

    #Get content provider information
    contentprovider_info = __perform_scan__('app.provider.info -u -a', p_name)
    __format_data__("Content Provider Information", contentprovider_info,f_json)
    print(separator)

    #Get URIs from package
    finduri_info = __perform_scan__('app.provider.finduri', p_name)
    __format_data__("Content Provider URIs", finduri_info,f_json)
    print(separator)

    #Get services information
    services_info = __perform_scan__('app.service.info -i -u -a', p_name)
    __format_data__("Services Information", services_info,f_json)
    print(separator)

    #Get native components included in package
    nativecomponents_info = __perform_scan__('scanner.misc.native -a', p_name)
    __format_data__("Native Components in Package", nativecomponents_info,f_json)
    print(separator)

    #Get world readable files in app installation directory /data/data/<package_name>/
    worldreadable_info = __perform_scan__('scanner.misc.readablefiles /data/data/'+p_name+'/', p_name, 1)
    __format_data__("World Readable Files in App Installation Location", worldreadable_info,f_json)
    print(separator)

    #Get world writeable files in app installation directory /data/data/<package_name>/
    worldwriteable_info = __perform_scan__('scanner.misc.readablefiles /data/data/'+p_name+'/', p_name, 1)
    __format_data__("World Writeable Files in App Installation Location", worldwriteable_info,f_json)
    print(separator)

    #Get content providers that can be queried from current context
    querycp_info = __perform_scan__('scanner.provider.finduris -a', p_name)
    __format_data__("Content Providers Query from Current Context", querycp_info,f_json)
    print(separator)

    #Perform SQL Injection on content providers
    sqli_info = __perform_scan__('scanner.provider.injection -a', p_name)
    __format_data__("SQL Injection on Content Providers", sqli_info,f_json)
    print(separator)

    #Find SQL Tables trying SQL Injection
    sqltables_info = __perform_scan__('scanner.provider.sqltables -a', p_name)
    __format_data__("SQL Tables using SQL Injection", sqltables_info,f_json)
    print(separator)

    #Test for directory traversal vulnerability
    dirtraversal_info = __perform_scan__('scanner.provider.traversal -a', p_name)
    __format_data__("Directory Traversal using Content Provider", dirtraversal_info,f_json)
    print(separator)

    html_begin += "</body></html>"
    f = open(f_html,"wb")
    f.write(html_begin.encode("utf-8"))
    f.close()

    print("\n All the results are stored in"+file_name+" JSon, TXT and html file..!!!")
    print(separator)


