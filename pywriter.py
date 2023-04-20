#	Copyright (C) 2023 Brett Kuskie <fullaxx@gmail.com>
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
from datetime import datetime

def get_args(parser):
    """
    Retrieves and parse arguments from the command line.
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
    Handle ZMQ SUB related errors
    """
    sub.close()        # Close the subscriber
    sub.context.term() # Terminate context 
	
def create_zmq_sub(zmq_pub, filter) -> int:
    """
    Creates ZMQ subscriber given an address and port to a zmq publisher
    e.g. protocol://interface:port
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
        return -1;             # Unable to connect to publisher
    
    socket.setsockopt_string(zmq.SUBSCRIBE, filter) # Set topic filter

    # as_zmq_sub_attach -> Attaches the zmq sub to a thread - Do once working

    return socket

def zmq_sub_destroy(sub) -> None:
    sub.close()        # Close the subscriber
    sub.context.term() # Terminate context 

def signal_handler(signum, frame):
    """
    Handles signals thrown by system 
    :signum: Signal ID
    :frame: Frame of execution interrupted
    """
    global g_shutdown

    # If we catch one of these signals, begin shutdown of program
    match signum:
        case signal.SIGHUP:
            g_shutdown = 1
        case signal.SIGINT:
            g_shutdown = 1
        case signal.SIGTERM:
            g_shutdown = 1
        case signal.SIGQUIT:
            g_shutdown = 1

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
        print("Error:: Insufficient header data\n") #DEBUG
        return False

    # Get our timestamp precision
    match ts_mode:
        case 0: # Default given by header
            g_magic = int(tokens[0], 10)
        case 1: # Microseconds
            g_magic = 0xA1B2C3D4 
        case 2: # Nanoseconds
            g_magic = 0xA1B23C4D    

    linktype = int(tokens[1], 10)                # Link type of connection
    thiszone = int(tokens[2], 10)                # Not sure what this is
    sigfigs = int(tokens[3], 10)                 # Need a better verbose name
    snaplen = int(tokens[4].rstrip('\x00'), 10)  # Snapshot length of capture
    
    # Version Numbers
    vers_major = 2
    vers_minor = 4
    
    # Write header to outstream
    byte_format = 'I2H4I' # Little-endian format of bytes to be written
    bytes_w = outstream.write(struct.pack(byte_format, g_magic, vers_major, vers_minor, thiszone, sigfigs, snaplen, linktype))
    
    # Check to see if all bytes have been written to the outstream
    if(bytes_w == struct.calcsize(byte_format)):
        return True # Success
    return False

def write_packet(ts_msg, ts_mode, pkt_msg, outstream) -> bool:
    """ 
    write_packet: Print packet data to a given outstream

    :ts_msg: Timestamp info for packet
    :ts_mode: Timestamp precision
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

    # Write the packet
    byte_format = '4I' # Little-endian format of bytes to be written
    bytes_w = outstream.write(struct.pack(byte_format, sec, int(frac), cap_len, pkt_len)) # Write packet header 
    
    # Check to see if all packet header have been written to the outstream
    if(bytes_w != struct.calcsize(byte_format)):
        return False
    
    # Write the packet payload
    byte_format = '%ss'% pkt_len # Little-endian format of bytes to be written
    bytes_w = outstream.write(struct.pack(byte_format, pkt_msg)) # Write packet header 
    
    # Check to see if all packet payload have been written to the outstream
    if(bytes_w == struct.calcsize(byte_format)):
        count_packet(bytes_w) # Count the processed packet
        return True # Success
    
    return False

def count_packet(pkt_bytes) -> None:
    """
    count_packet: Add a processed packet and its size in bytes to a running
                  total
    
    :pkt_bytes: Size in bytes of processed packet
    """
    global g_num_pkts, g_num_bytes
    g_num_pkts += 1
    g_num_bytes += pkt_bytes

def check_for_stop_condition(arg_time: int, arg_pkts: int, arg_bytes: int) -> bool:
    """
    check_for_stop_condition: Checks if any of our stop conditions are true and need to be handled
    
    :arg_time: Time in seconds that program should cease operation
    :arg_pkts: Number of packets to be processed before ceasing
    :arg_bytes: Number of bytes to process before ceasing

    return: Returns True if we should stop, False otherwise
    """
    global g_shutdown
    # Check for time
    
    if(arg_pkts is not None and g_num_pkts >= arg_pkts):   # Check for number of packets
        g_shutdown = 1
    
    if(arg_bytes is not None and (g_num_bytes / 10**6) >= arg_bytes): # Check for number of bytes
        g_shutdown = 1
    
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
        rslt = write_packet(ts_msg, ts_mode, pkt_msg, outstream)
        if not rslt:
            print("Error:: Unable to write packet data: Status Code -> %s\n" % err)
            return -1
    else:
        print("Error:: Incomplete message/No data received\n")
        return -1
    
    return 0 # Success
    
    

def main():
    global g_header_written, g_magic, g_num_pkts, g_num_bytes, g_shutdown
    g_header_written = False      # Have we written the file header to the packet
    g_shutdown = 0
    g_num_pkts = 0
    g_num_bytes = 0
    filter = ""                   # Blank string means we subscribe to all topics
    outstream = sys.stdout.buffer # Initialize output stream to stdout

    parser = argparse.ArgumentParser(description="Use pkt_writer.exe to save packets to a pcap file or \
        to print packets into wireshark/tshark/tcpdump.", add_help=False) # Initialize argument parser object

    args = get_args(parser) # Retrieve and parse arguments from the cl
    print(args)
    # If a PCAP file is provided for output stream, use it instead
    if args.PCAP is not None:
        outstream = open(args.PCAP, "wb") # Write to pcap as binary file

    # Evaluate timestamp precision argument
    if args.us is not None:
        ts_mode = 1 # Use microseconds
    elif args.ns is not None:
        ts_mode = 2 # Use nanoseconds
    else:
        ts_mode = 0 # Use default

    socket = create_zmq_sub(args.ZMQ, filter) # Initialize ZMQ SUB

    # Initialize our signals that we would like to handle
    signal.signal(signal.SIGHUP,  signal_handler)
    signal.signal(signal.SIGINT,  signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGQUIT, signal_handler)

    # Begin packet writing loop with a valid socket
    if socket != -1:
        err = 0
        while(err == 0 and not g_shutdown):
            err = unpack_zmq(socket, outstream, ts_mode) # Receive and unpack zmq messages as they come in 
            check_for_stop_condition(args.maxtime, args.maxpkts, args.maxsize)
    
    # Shutdown the ZMQ SUB bus
    zmq_sub_destroy(socket)

    # Close the PCAP file if opened
    if not outstream.closed:
        outstream.close()

if __name__ == "__main__":
    main()