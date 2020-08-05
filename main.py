import threading
import socket
from time import sleep
from datetime import datetime
from pythonping import ping
from sys import stdout, argv
import json

knownServices = {
    21: "ftp",
    22: "ssh",
    53: "dns",
    80: "http",
    443: "https",
    3306: "mysql",
    3389: "rdp",
    11211: "memcached"
}

class scan(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.targetIP = argv[1]
        self.newDict = {}
    

    def recognizeServices(self, ip, port):
        if(port in knownServices):
            self.newDict[ip]["ports"][port] = knownServices[port]
            print("\x1b[95m[\x1b[92mSCANNER\x1b[95m]\x1b[92mFound Port\x1b[97m: \x1b[95m%d \x1b[92mService\x1b[97m: \x1b[95m%s\x1b[97m" %  (port, knownServices[port]))
        else:
            print("\x1b[95m[\x1b[92mSCANNER\x1b[95m]\x1b[92mFound Port\x1b[97m: \x1b[95m%d \x1b[92mService\x1b[97m: \x1b[95mUnknown\x1b[97m" %  port)
            self.newDict[ip]["ports"][port] = "unknown"
    

    def scan(self, ip, rangeToScan, tts):
        sRange = int(rangeToScan.split('-')[0])
        eRange = int(rangeToScan.split('-')[1])
        for ports in range(sRange, eRange):
            scanS = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            scanS.settimeout(tts)

            scanC = scanS.connect_ex((ip, ports))
            if scanC == 0:
                self.recognizeServices(ip, ports)
                scanS.close()
            else:
                scanS.close()

        

    def run(self, ip):
        activeThreads = []
        threads_to_use = 255
        delayScan = ping(ip, size=5, count=4)

        if(float(delayScan.rtt_avg_ms) >= 1000):
            ourDelay = 0.08
        else:
            ourDelay = delayScan.rtt_avg_ms / 1000 + 0.01
            

        self.newDict[ip] = {}
        self.newDict[ip]["ports"] = {}
        port_a = 0
        port_b = 257
        self.totalSTime = datetime.now()
        print("\x1b[95m[\x1b[92mSCANNER\x1b[95m]\x1b[92mAssigning \x1b[95m%d \x1b[92mThreads to\x1b[97m: \x1b[95m%s\x1b[97m" % (threads_to_use, ip))
        for x in range(0, threads_to_use):
            port_range = "%d-%d" % (
                port_a,
                port_b
            )
            thread = threading.Thread(target=self.scan, args=(ip, port_range, ourDelay))
            thread.start()
            activeThreads.append(thread)
            port_a += 257
            port_b += 257

        
        
        for threads in activeThreads:
            threads.join()
            activeThreads.remove(threads)
        self.t2 = datetime.now()
        if(22 in self.newDict[ip]['ports']):
            self.newDict[ip]["type"] = "Possible server"
        else:
            self.newDict[ip]["type"] = "Possible home router"

        print("\x1b[95m[\x1b[92mSCANNER\x1b[95m]\x1b[92mIP\x1b[97m: \x1b[95m%s \x1b[92mdone.\x1b[97m" % ip)
        self.saveStats(self.newDict)


    def saveStats(self, dictionary):
        with open('data.json', 'w+')as  f:
            json.dump(dictionary, f, indent=4)
        print("\x1b[95m[\x1b[92mSCANNER\x1b[95m]\x1b[92mSaved infos to data.json\x1b[97m")


    def main(self):
        print("\x1b[95m[\x1b[92mSCANNER\x1b[95m]\x1b[92mStarting threads for scanning.\x1b[97m")
        self.run(self.targetIP)
        
        sleep(0.2)
        total = self.t2 - self.totalSTime
        print("\x1b[95m[\x1b[92mSCANNER\x1b[95m]\x1b[92mTotal Scanning Time\x1b[97m: \x1b[95m%s\x1b[97m" % total)
        return True

scan().main()
