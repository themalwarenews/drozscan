# Drozscan
### Nothing unique, just an automation
---

![image](https://user-images.githubusercontent.com/100226024/155892663-669e4fcc-1869-4472-95f1-10bd589f987b.png)

### Drozscan is just an automated script to run all drozer commands in a single run. See the results in CLI, JSON or HTML.
---

## NOTE : Make sure you installed and configured the [drozer](https://labs.f-secure.com/tools/drozer/) tool before running the script.
---

### PRESEQUITES
1. Linux/OSX machine
2. Genymotion/Android emulator/Rooted device

---

### QUERIES EXECUTED BY TOOL.
1. Get Package complete Info
2. Get activities information
3. Get broadcast receivers information
4. Get attack surface details
5. Get package with backup API details
6. Get Android Manifest of the package
7. Get native libraries information
8. Get content provider information
9. Get URIs from package
10. Get services information
11. Get native components included in package
12. Get world readable files in app installation directory /data/data/<package_name>/
13. Get world writeable files in app installation directory /data/data/<package_name>/
14. Get content providers that can be queried from current context
15. Perform SQL Injection on content providers
16. Find SQL Tables trying SQL Injection
17. Test for directory traversal vulnerability

---


## How to use
1. Make sure you have connected the android virtual device to your attacking machine.
2. Check whether Port forwarding is done for drozer client.
3. Download or Clone the drozscan Repo.
4. From the terminal, move into Garuda Directory
5. Run ```python scanme.py```

---

#### Bad UI in html page, will be working on them, however tool does its job

### Inspired by interference-security

# Thank YOU

