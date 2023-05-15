#!/usr/bin/env python

from asyncore import write
import subprocess
import threading
import sys
import os
import json
from colorama import Fore

__author__ = 'themalwarenews ( @themalwarenews) '
inspiration = "interference-security"

def welcome():
    ...
    # Your banner code
    ...

# Function to execute drozer command and return the output
def perform_scan(query_type, p_name, a=0):
    drozer_command = 'drozer console connect -c "run ' + str(query_type)+ ' ' + str(p_name)+ '"'
    if a==1:
        drozer_command = 'drozer console connect -c "run ' + str(query_type)+' '+'"'
    process = subprocess.Popen(drozer_command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, universal_newlines=True)
    process_data = process.communicate()[0]
    if "could not find the package" in process_data:
        process_data = 'Invalid Package'
    return process_data

# Function to print and write the task result
def format_data(task, result, outfile_json):
    print(Fore.GREEN + f"\n{task}:\n{'*' * 50}\n{result}")
    result = result.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace("\\n","<br>").replace("\\r","")
    with outfile_json:
        json.dump({str(task): result}, outfile_json)
# List of tasks to perform
tasks = [
    ("Package Information", 'app.package.info -a'),
    ("Activities Information", 'app.activity.info -i -u -a'),
    ("Broadcast Receivers Information", 'app.broadcast.info -i -u -a'),
    ("Attack Surface Information", 'app.package.attacksurface'),
    ("Package with Backup API Information", 'app.package.backup -f'),
    ("Android Manifest File", 'app.package.manifest'),
    ("Native Libraries used", 'app.package.native'),
    ("Content Provider Information", 'app.provider.info -u -a'),
    ("Content Provider URIs", 'app.provider.finduri'),
    ("Services Information", 'app.service.info -i -u -a'),
    ("Native Components in Package", 'scanner.misc.native -a'),
    ("World Readable Files in App Installation Location", f'scanner.misc.readablefiles /data/data/{p_name}/', 1),
    ("World Writeable Files in App Installation Location", f'scanner.misc.readablefiles /data/data/{p_name}/', 1),
    ("Content Providers Query from Current Context", 'scanner.provider.finduris -a'),
    ("SQL Injection on Content Providers", 'scanner.provider.injection -a'),
    ("SQL Tables using SQL Injection", 'scanner.provider.sqltables -a'),
    ("Directory Traversal using Content Provider", 'scanner.provider.traversal -a')
]

if __name__ == '__main__': 
    welcome()
    p_name = input(Fore.BLUE + "\n\nEnter the Package Name: ")
    file_name = input("\nEnter the file name to store the results: ")
    f_json = file_name + ".json"
    f_html = file_name + ".html"
    
    with open(f_json, "a") as outfile_json:
        # Perform all tasks
        for task, command in tasks:
            result = perform_scan(command, p_name)
            format_data(task, result, outfile_json)
            print("_" * 100)

    # HTML report
    html_begin = """
    <!DOCTYPE html>
    <html>
    <head>
    <title>APP Analysis Report</title>
    <style>
    body {
        font-family: Arial, sans-serif;
    }
    table {
        width: 100%;
        border-collapse: collapse;
        margin-bottom: 20px;
    }
    th, td {
        border: 1px solid #ddd;
        padding: 8px;
    }
    th {
        background-color: #4CAF50;
        color: white;
    }
    </style>
    </head>
    <body>
    <h1 style="text-align: center;"><strong>Drozer Analysis Report</strong></h1>
    """
    
    # Add tables to HTML report
    with open(f_json, "r") as outfile_json:
        data = json.load(outfile_json)
        for task, result in data.items():
            html_begin += f"""
            <table>
            <tr><th>{task}</th></tr>
            <tr><td>{result}</td></tr>
            </table>
            """
    
    html_begin += "</body></html>"
    
    # Write HTML report to file
    with open(f_html,"w") as outfile_html:
        outfile_html.write(html_begin)

    print("\nAll the results are stored in the JSON and HTML files.")

