# PyzmqWriter
Python Implementation of pktwriter.exe that can be found at https://github.com/Fullaxx/pktstreamer

Built to work with the pcap2zmq.exe & live2zmq.exe as ZMQ
publishers to the ZMQ bus.

## Requirements for building
First we need to make sure we have all the appropriate libraries. \
Please consult this chart for help with installing the required packages. \
If your OS is not listed, please help us fill out the table, or submit a request via github.

| OS     | Commands (as root)                                                   |
| ------ | -------------------------------------------------------------------- |
| Ubuntu | `apt update; apt install python3-pip; pip install pyzmq`             |

## Usage

### Subscribing to a packet stream
The ZMQ data that is written by pywriter can be piped into network analysis tools such
as wireshark, tshark, and tcpdump. The data can also be redirected to a pcap file with bash redirect or specified with the `-p` parameter.
```
python3 pywriter.py -Z tcp://localhost:9999  | wireshark -k -i -
python3 pywriter.py -Z tcp://localhost:9999  | tshark -r -
python3 pywriter.py -Z tcp://localhost:9999  | tcpdump -r -
python3 pywriter.py -Z tcp://localhost:9999  > shiny_new.pcap
python3 pywriter.py -Z tcp://localhost:9999  -P shiny_new.pcap
```

### Options
|Flag| Description | 
|-----------------|----------------------------------------|
| --ZMQ,  -Z <arg>| Set the ZMQ bus to listen on           |
| --PCAP, -P <arg>| Write data to a pcap file              | 
| --stats         | Display writing stats to stderr        |
| --us, --ns      | Force microsecond/nanosecond timestamps|
| --maxtime <arg> | Stop after <arg> seconds               | 
| --maxpkts <arg> | Stop after <arg> packets               |
| --maxsize <arg> | Stop after <arg> MB                    |
|

### Define a stop condition
Stop conditions can be specified by using the following 
`--maxtime 60` Stop after 60 Seconds
`--maxpkts 10000` Stop after 10000 packets
`--maxsize 100` Stop after 100 MB
```
python3 pywriter.py -Z tcp://localhost:9999 -P shiny_new.pcap --stats --maxtime 60
python3 pywriter.py -Z tcp://localhost:9999 -P shiny_new.pcap --stats --maxpkts 10000
python3 pywriter.py -Z tcp://localhost:9999 -P shiny_new.pcap --stats --maxsize 100
```
