# Intrusion-Detection-System 💻

This is an Intrusion Detection system created in the Python programming language. The system was designed to detect specific cybersecurity threats such as brute force attacks, Xmas scans, SYN scans, SSH intrusions, and reverse shell attempts. The main goal of this project was to develop a live monitoring system with logging via e-mail and text if any intrusions were detected.

Below is a summary of each file:

* [main.py](https://github.com/SHussain84/Intrusion-Detection-System/blob/main/main.py) is responsible for linking all the other modules together. This is done by using the __threading__ module in Python to run all modules simultaneously. Modularity of the system allows for easier maintenance and scalability, as each module can be updated or modified independently without affecting the core functionality of the overall system.

* [BruteForceDetection.py](https://github.com/SHussain84/Intrusion-Detection-System/blob/main/BruteForceDetection.py) continuously monitors __SSH__ login attempts and flags patterns that suggest brute forcing, such as login attempts in rapid succession or repeatedly entering the incorrect password. This is done by parsing the Linux log file in real time for failed login attempts.

* [XMASScanDetection.py](https://github.com/SHussain84/Intrusion-Detection-System/blob/main/XMASScanDetection.py) is dedicated to identifying __XMAS__ scans, a type of attack that can reveal information about which ports are open on a network device. This module looks for specific packet signatures associated with __XMAS__ scans where multiple TCP flags are set to “on”. 

* [SYNScanDetection.py](https://github.com/SHussain84/Intrusion-Detection-System/blob/main/SYNScanDetection.py) focuses on detecting __SYN__ scans, which is a technique used by attackers like XMAS scanning to figure out which ports are open. This module analyses incoming __SYN__ packets to identify potential scanning activity.

* [PingDetection.py](https://github.com/SHussain84/Intrusion-Detection-System/blob/main/PingDetection.py) is responsible for detecting pings. While ping requests are not harmful or indicative of an attack, they are essential for network diagnostics and ensuring that communication paths between virtual machines (VMs) are open and functioning correctly, without packet loss.

* [ReverseShellDetection.py](https://github.com/SHussain84/Intrusion-Detection-System/blob/main/ReverseShellDetection.py) detects if a reverse shell has been spawned from a certain IP address.

* [SSHAttemptDetection.py](https://github.com/SHussain84/Intrusion-Detection-System/blob/main/SSHAttemptDetection.py) tracks and analyses __SSH__ connection attempts to identify unauthorised or suspicious activities. This module is crucial for detecting potential __SSH__ brute force attacks where attackers try to obtain access by repeatedly trying different passwords and usernames.

* [Logger.py](https://github.com/SHussain84/Intrusion-Detection-System/blob/main/Logger.py) is responsible for sending out notifications via email and text if any attacks are detected. They are also logged to a text file.

* [sendEmail.py](https://github.com/SHussain84/Intrusion-Detection-System/blob/main/sendEmail.py) contains the required information to send email notifications.

* [sendText.py](https://github.com/SHussain84/Intrusion-Detection-System/blob/main/sendText.py) contains the required information to send text notifications.


