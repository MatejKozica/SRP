# Labovi

## ARP-spoofing

Cloned git repo: `git clone https://github.com/mcagalj/SRP-2021-22`

In directory run bash script that started docker containers: `sh ./start/sh`

Entered docker container with `docker exec -it station-1 bash` and pinged station-2 with `ping station-2`

Got containers IP and MAC addresses using `ipconfig`

station-1:
`IP: 172.21.0.2`

`ETH: 00:02`

station-2:

`IP: 172.21.0.4`

`ETH: 00:04`

evil-station:

`IP: 172.21.0.3`

`ETH: 00:03`

Emulated conversation between 2 stations, entered container 1 and 2 with aforementioned command. On station-2 used command: `netstat -l -p 8000` and on station-1: `netstat station-2 8000`. After that every "message" we write in one of containers the other one gets it.

On evil-station we listened on eth0 with `tcpdump` command. To arpspoof we used command `arpspoof -t station-1 -r station-2`. And to filter out messages we don't want to see we used `tcpdump -XA station-1 and not arp`.
After that we blocked communication between 2 stations using DoS attack with command:

`echo 0 > /proc/sys/net/ipv4/ip_forward`