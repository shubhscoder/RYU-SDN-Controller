import json
import sys
import time
import subprocess
import os
import signal

def get_cmd(mode, bandwidth, server, port, time):
    if mode == "server":
        return ['exec iperf -s -i 1 -p {0}'.format(port)]
    elif mode == "client":
        return ['exec iperf -c {0} -p {1} -b {2}M -t {3}s'.format(server, port, bandwidth, time)]
    else:
        return [] 

file = sys.argv[2]
host = sys.argv[1]
config_file = []

mode = "undefined"

with open(file) as f:
    config = json.load(f)
    print(config)

if config["server"] == host:
    mode = "server"
else:
    mode = "client"

test_cases = config["tests"]
server = config["server"]
server_ip = config["server_ip"]
server_port = config["server_port"]
client = config["client"]
current_time = 0

for test in test_cases:
    start = test["begin"]
    end = test["end"]
    bandwidth = test["bandwidth"]
    time.sleep(start - current_time)
    print("Running test with start: {0} end: {1} bandwidth: {2} server: {3} client: {4}".format(start, end, bandwidth, server, client))
    cmd = get_cmd(mode, bandwidth, server_ip, server_port, end - start)
    print("Running cmd : ", cmd)
    if mode == "client":
        time.sleep(2)
    process = subprocess.Popen(cmd, 
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=True)
    try:
        stdout, stderr = process.communicate(timeout=end - start + 2)
        print("stdout: ",stdout.decode("utf-8", "strict"))
        print("stderr: ",stderr.decode("utf-8", "strict"))
    except subprocess.TimeoutExpired:
        process.kill()
        print('Killing process for cmd: ',cmd)
    print("Done cmd : ", cmd)
    current_time += end
