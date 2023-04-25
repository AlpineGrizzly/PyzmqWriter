#	Copyright (C) 2023 Dalton Kinney <daltonckinney@gmail.com>
#
#	This program is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; version 2 of the License.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

import argparse
import zmq
import sys 
import signal
import struct 
import time

class pcap_hdr_t():
    """ Class struct to represent a pcap header """
    def __init__(self, magic, vers_major, vers_minor, timezone, sigfigs, snaplen, linktype) -> None:
        self.format = 'I2H4I'        # Little-endian format of bytes to be written
        self.magic = magic           # Time precision of pcap 
        self.vers_major = vers_major # Pcap Version Major
        self.vers_minor = vers_minor # "          " Minor
        self.timezone = timezone     # Timezone
        self.sigfigs = sigfigs       # Timestamp accuracy
        self.snaplen = snaplen       # Snapshot length of capture
        self.linktype = linktype     # Network link

    def write_pcap_header(self, outstream) -> int:
        """ 
        write_pcap Write the pcap to an outstream 
        :outstream: Outstream to write pcap to

        return: Returns bytes written to outstream
        """
        bytes_w = outstream.write(struct.pack(self.format, 
                                              self.magic, 
                                              self.vers_major, 
                                              self.vers_minor, 
                                              self.timezone, 
                                              self.sigfigs, 
                                              self.snaplen, 
                                              self.linktype))
        return bytes_w

class packet():
    """ Class to represent a packet """
    
    def __init__(self, format, sec, frac, cap_len, pkt_len, message) -> None:
        self.format = format
        self.sec = sec
        self.frac = frac
        self.cap_len = cap_len
        self.pkt_len = pkt_len
        self.message = message
    
    def write_packet(self, outstream) -> bool:
        """
        write_packet Write the packet to an outstream 
        
        :outstream: Outstream for packet to be written to

        return: Returns bytes written to outstream
        """
        bytes_w = outstream.write(struct.pack(self.format, self.sec, self.frac, self.cap_len, self.pkt_len, self.message))

        if(bytes_w == struct.calcsize(self.format)):
            count_packet(bytes_w) # Count the bytes written
            return True
        
        return False
        
def get_args(parser):
    """
    get_args Retrieves and parse arguments from the command line.

    :parser: Parser object to store parsed arguments

    return: Returns parser with parsed arguments
    """
    parser.add_argument('--help', '-h', action='help', help='Displays this information')
    parser.add_argument('--ZMQ', '-Z', action='store', metavar='<args>', required=True, type=str, help='Set the ZMQ bus to listen on') 
    parser.add_argument('--PCAP', '-P', action='store', metavar='', type=str, help='Write data to a pcap file')
    parser.add_argument('--stats', action='store_true', default=False, help='Display stats on stderr')
    parser.add_argument('--us', action='store_true', default=False, help='Force Microsecond Timestamps')
    parser.add_argument('--ns',	action='store_true', default=False, help='Force Nanosecond Timestamps')
    parser.add_argument('--maxtime', action='store',metavar='<args>', type=int, help='Stop after X seconds')
    parser.add_argument('--maxpkts', action='store', metavar='<args>', type=int, help='Stop after X pkts')
    parser.add_argument('--maxsize', action='store', metavar='<args>', type=int, help='Stop after X MB')

    return parser.parse_args()

def handle_error(sub) -> None:
    """
    handler_error Handle ZMQ SUB related errors

    :sub: ZMQ subscriber
    """
    sub.close()        # Close the subscriber
    sub.context.term() # Terminate context 
	
def create_zmq_sub(zmq_pub, filter) -> int:
    """
    create_zmq_sub Creates ZMQ subscriber given an address and port to a zmq publisher
    e.g. protocol://interface:port

    :zmq_pub: ZMQ publisher to connect subscriber to  
    :filter: ZMQ topics to subscriber to

    return: Returns socket connected to ZMQ publiser
    """
    context = zmq.Context()          # Initialize zmq context object
    socket = context.socket(zmq.SUB) # Assign context socket
    socket.setsockopt(zmq.RCVHWM, 0) # Set maximum amount of outstanding messages to 0

    try: 
        socket.connect(zmq_pub) # Connect to the publisher
    except zmq.ZMQError as exc:
        print("Error in create_zmq_sub: %s\n" % exc)
        handle_error(socket)
        socket.context.term()
        return -1;              # Unable to connect to publisher

    socket.setsockopt_string(zmq.SUBSCRIBE, filter) # Set topic filter

    return socket

def zmq_sub_destroy(sub) -> None:
    """
    zmq_sub_destroy Destroy the ZMQ subscriber
    :sub: ZMQ subscriber to be destroyed
    """
    sub.close()        # Close the subscriber
    sub.context.term() # Terminate context 

def signal_handler(signum, frame) -> None:
    """
    Handles signals thrown by system 
    :signum: Signal ID
    :frame: Frame of execution interrupted
    """
    global g_shutdown

    # If we catch one of these signals, begin shutdown of program
    match signum:
        case signal.SIGHUP:
            set_shutdown("SIGHUP")
        case signal.SIGINT:
            set_shutdown("SIGINT")
        case signal.SIGTERM:
            set_shutdown("SIGTERM")
        case signal.SIGQUIT:
            set_shutdown("SIGQUIT")

def alarm_handler(signum, frame) -> None:
    """ 
    alarm handler Enabled when g_stats is defined, prints bytes/second of packet data written
    """
    global g_bw_count
    bw_units = ""    # Byte write units
    bw = g_bw_count
    g_bw_count = 0   # Reinitialize bw counter

    # The tower of bs
    if bw >= 10**12:  # TB/s
        bw_units = "TB/s"
        bw = bw / 10**12
    elif bw >= 10**9: # GB/s
        bw_units = "GB/s"
        bw = bw / 10**9        
    elif bw >= 10**6: # MB/s
        bw_units = "MB/s"
        bw = bw / 10**6
    elif bw >= 10**3: # KB/s
        bw_units = "KB/s"
        bw = bw / 10**3
    else:             # B/s
        bw_units = "B/s"
        bw = bw

    sys.stderr.write("%lu %s\n" % (bw, bw_units))
    sys.stderr.flush()

    signal.alarm(1)


def write_header(fh, outstream, ts_mode) -> bool:
    """ 
    write_header: write the file header from the ZMQ PUB to a designated 
                  stream 

    :fh: File header information
    :outstream: Outstream for header to be printed to
    :ts_mode: Timestamp precision mode

    return: Returns True on successfully writing header, false otherwise
    """
    global g_magic
    tokens = fh.decode("utf-8").split('/') # Decode header binary + tokenize
    
    if len(tokens) != 5:
        return False

    # Get our timestamp precision
    match ts_mode:
        case 0: # Default given by header
            g_magic = int(tokens[0], 10)
        case 1: # Microseconds
            g_magic = 0xA1B2C3D4 
        case 2: # Nanoseconds
            g_magic = 0xA1B23C4D    

    # Parse tokens
    linktype = int(tokens[1], 10)                # Link type of connection
    timezone = int(tokens[2], 10)                # Timezone 
    sigfigs = int(tokens[3], 10)                 # Timestamp accuracy
    snaplen = int(tokens[4].rstrip('\x00'), 10)  # Snapshot length of capture
    
    # Initialize our Pcap header
    pcap_header = pcap_hdr_t(g_magic, 2, 4, timezone, sigfigs, snaplen, linktype)

    # Write header to outstream
    bytes_w = pcap_header.write_pcap_header(outstream)

    # Check to see if all bytes have been written to the outstream
    if(bytes_w == struct.calcsize(pcap_header.format)):
        return True # Success
    
    return False

def write_packet(ts_msg, pkt_msg, outstream) -> bool:
    """ 
    write_packet: Print packet data to a given outstream

    :ts_msg: Timestamp info for packet
    :pkt_msg: Packet content 
    :outstream: stdout, pcap, or other file to have data written out to

    return: Returns True if able to write packet, False otherwise
    """
    global g_magic
    
    ts_data = ts_msg.decode("utf-8").split('.')

    if(len(ts_data) != 2):
        return False
    
    # Store our timestamp data
    sec = int(ts_data[0].rstrip('\x00'), 10)  
    frac = int(ts_data[1].rstrip('\x00'), 10)

    cap_len = pkt_len = len(pkt_msg) # Get our capture/packet length in bytes

    # Check for Microsecond precision
    if(g_magic == 0xA1B2C3D4): 
        frac /= 1000
    
    # byte format for packet header and messsage body    
    byte_format = '4I%ss' % pkt_len # [int][int][int][int][message_size_nbytes] 
    
    # Set the packet header and message body
    this_packet = packet(byte_format, sec, int(frac), cap_len, pkt_len, pkt_msg)

    return this_packet.write_packet(outstream) # Return bool if we were able to write to stream

def count_packet(pkt_bytes) -> None:
    """
    count_packet: Add a processed packet and its size in bytes to a running total
    
    :pkt_bytes: Size in bytes of processed packet
    """
    global g_num_pkts, g_num_bytes, g_bw_count
    g_num_pkts += 1
    g_num_bytes += pkt_bytes
    g_bw_count += pkt_bytes

def set_shutdown(debug: str):
    """ 
    set_shutdown Set the global shutdown var 
    :debug: String containing debug info related to shutdown
    """
    global g_shutdown, g_enable_debug
    g_shutdown = 1

    if(g_enable_debug):
        sys.stderr.write("DEBUG -- Shutdown: %s --\n" % debug)

def check_for_stop_condition(stop_time: int, arg_pkts: int, arg_mb: int) -> bool:
    """
    check_for_stop_condition: Checks if any of our stop conditions are true and need to be handled
    
    :arg_time: Time in seconds that program should cease operation
    :arg_pkts: Number of packets to be processed before ceasing
    :arg_mb: Number of mb to process before ceasing

    return: Returns True if we should stop, False otherwise
    """
    global g_shutdown
    
    if (stop_time is not None and (time.time() >= stop_time)):    # Check for time condition in seconds
        set_shutdown("Maxtime exceeded")
    
    if(arg_pkts is not None and g_num_pkts >= arg_pkts):        # Check for number of packets
        set_shutdown("%d packets written" % g_num_pkts)
    
    if(arg_mb is not None and (g_num_bytes >= arg_mb * 10**6)): # Check for number of bytes
        set_shutdown("%d mbs exceeded" % g_num_bytes)
    
def unpack_zmq(socket, outstream, ts_mode) -> int:
    """ 
    unpack_zmq: Unpack ZMQ PUB data 

    :socket: socket to receive ZMQ PUB data on 
    :outstream: Outstream for packet data to be printed to
    :ts_mode: Timestamp precision mode

    return: Returns 0 on success, -1 on failure
    """
    global g_header_written
    err = 0
    
    # Receive a packet of information from ZMQ to unpack
    dev_msg = socket.recv() # Device source
    fh_msg = socket.recv()  # File Header 
    ts_msg = socket.recv()  # Time stamp
    pkt_msg = socket.recv() # Packet content/message
    
    if(g_header_written == False):
        g_header_written = write_header(fh_msg, outstream, ts_mode)

    if(g_header_written and ts_msg and pkt_msg):
        rslt = write_packet(ts_msg, pkt_msg, outstream)
        if not rslt:
            print("Error:: Unable to write packet data: Status Code -> %s\n" % err)
            return -1
    else:
        print("Error:: Incomplete message/No data received\n")
        return -1
    
    return 0 # Success

def main():
    global g_header_written, g_magic, g_num_pkts, g_num_bytes, g_shutdown, g_bw_count, g_enable_debug
    g_header_written = False      # Have we written the file header to the packet
    g_shutdown = 0                # Shutdowns program if set to 1
    g_num_pkts = 0                # Keeps track of number of packets written
    g_num_bytes = 0               # Keeps track of number of bytes written
    g_bw_count= 0                 # Counter used for --stats prints
    g_enable_debug = 0            # Set to 1 to enable debug prints to stderr
    stop_time = None              # Used to store a given time for stopping the program
    filter = ""                   # Blank string means we subscribe to all topics
    outstream = sys.stdout.buffer # Initialize output stream to stdout

    parser = argparse.ArgumentParser(description="Use pkt_writer.exe to save packets to a pcap file or \
        to print packets into wireshark/tshark/tcpdump.", add_help=False) # Initialize argument parser object

    args = get_args(parser) # Retrieve and parse arguments from the cl

    socket = create_zmq_sub(args.ZMQ, filter) # Initialize ZMQ SUB

    # Initialize our signals that we would like to handle
    signal.signal(signal.SIGHUP,  signal_handler)
    signal.signal(signal.SIGINT,  signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)

    # If a PCAP file is provided for output stream, use it instead
    if args.PCAP is not None:
        outstream = open(args.PCAP, "wb") # Write to pcap as binary file
    
    if args.maxtime is not None:
        stop_time = time.time() + args.maxtime # What time do we disintegrate

    if args.stats is not None:
        signal.signal(signal.SIGALRM, alarm_handler)
        signal.alarm(1)

    # Evaluate timestamp precision argument
    if args.us is not None:
        ts_mode = 1 # Use microseconds
    elif args.ns is not None:
        ts_mode = 2 # Use nanoseconds
    else:
        ts_mode = 0 # Use default

    # Begin packet writing loop with a valid socket
    if socket != -1:
        err = 0
        while(err == 0 and not g_shutdown):
            err = unpack_zmq(socket, outstream, ts_mode) # Receive and unpack zmq messages as they come in 
            check_for_stop_condition(stop_time, args.maxpkts, args.maxsize)
    
    # Shutdown the ZMQ SUB bus
    zmq_sub_destroy(socket)

    # Close the PCAP file if opened
    if args.PCAP is not None and not outstream.closed:
        outstream.close()

    sys.stderr.write("Total Packets: %lu\nTotal Bytes  : %lu\n" %  (g_num_pkts, g_num_bytes))

if __name__ == "__main__":
    main()