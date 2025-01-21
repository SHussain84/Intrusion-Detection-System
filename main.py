import threading
from SSHAttemptDetection import SSHAttemptDetection
from PingDetection import PingDetection
from XMASScanDetection import XMASScanDetection
from SYNScanDetection import SYNScanDetection
from ReverseShellDetection import ReverseShellDetection
from BruteForceDetection import BruteForceDetection

def main():
    # Initialize detection instances
    print("""
 /$$$$$$$            /$$$$$$ /$$$$$$$   /$$$$$$ 
| $$__  $$          |_  $$_/| $$__  $$ /$$__  $$
| $$  \ $$ /$$   /$$  | $$  | $$  \ $$| $$  \__/
| $$$$$$$/| $$  | $$  | $$  | $$  | $$|  $$$$$$ 
| $$____/ | $$  | $$  | $$  | $$  | $$ \____  $$
| $$      | $$  | $$  | $$  | $$  | $$ /$$  \ $$
| $$      |  $$$$$$$ /$$$$$$| $$$$$$$/|  $$$$$$/
|__/       \____  $$|______/|_______/  \______/ 
           /$$  | $$                            
          |  $$$$$$/                            
           \______/                                                                                             
    """)

    sshDetection = SSHAttemptDetection()
    pingDetection = PingDetection()
    xmasDetection = XMASScanDetection()
    synDetection = SYNScanDetection()
    reverseShellDetection = ReverseShellDetection()
    bruteforceDetection = BruteForceDetection()


    sshThread = threading.Thread(target=sshDetection.start_detection, daemon=True)
    pingThread = threading.Thread(target=pingDetection.start_detection, daemon=True)
    xmasThread = threading.Thread(target=xmasDetection.start_detection, daemon=True)
    synThread = threading.Thread(target=synDetection.start_detection, daemon=True)
    reverseThread = threading.Thread(target=reverseShellDetection.start_detection, daemon=True)
    monitorLogThread = threading.Thread(target=bruteforceDetection.monitorLogFile, args=(3,1), daemon=True)

    sshThread.start()
    pingThread.start()
    xmasThread.start()
    synThread.start()
    reverseThread.start()
    monitorLogThread.start()

    if bruteforceDetection.checkLogFile() == True:
        print("Failed or accepted SSH login attempts found!")
        userResponse = None

        while userResponse not in ('Y', 'N'):
            userResponse = input("Would you like to view them? (Y/N): ").upper()
            if userResponse not in ('Y', 'N'):
                print("Invalid response. Please enter 'Y' for Yes or 'N' for No.")

        if userResponse == "Y":
            bruteforceDetection.detectBruteForceAttempts()
    else:
        print("No failed or accepted SSH login attempts found.")

    try:
        while True:
            pass  # Keep the main thread alive
    except KeyboardInterrupt:
        print("Stopping threads and exiting program...")

if __name__ == "__main__":
    main()