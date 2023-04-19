# 	Copyright (C) 2023 Dalton Kinney <daltonckinney@gmail.com>
#
# 	This program is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; version 2 of the License.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

#import os
import time
import argparse
import zmq
import sys 
import signal
import struct 

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
    :frame: ...idk
    """
    print("Signal: %s :::: Frame: %s\n" % (signum, frame))

def exit_handler(signum, frame):
    print("Exiting...")
    exit(0)

def write_header(fh, outstream, ts_mode) -> bool:
    """ 
    write_header: write the file header from the ZMQ PUB to a designated stream 

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
        return True # Success
    
    return False

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
        err = write_packet(ts_msg, ts_mode, pkt_msg, outstream)
        if not err:
            print("Error:: Unable to write packet data: Status Code -> %s\n" % err)
            return -1
        else:
            return 0
    else:
        print("Error:: Incomplete message/No data received\n")
        return -1

def main():
    global g_header_written       # Initialize Global header written boolean
    global g_magic
    g_header_written = False      # Have we written the file header to the packet
    ts_mode = 0                   # Timestamp Mode, 0 by default, 1 for Microsecond, 2 for Nanosecond
    filter = ""                   # Blank string means we subscribe to all topics
    outstream = sys.stdout.buffer # Initialize output stream to stdout

    parser = argparse.ArgumentParser(description="Use pkt_writer.exe to save packets to a pcap file or \
        to print packets into wireshark/tshark/tcpdump.", add_help=False) # Initialize argument parser object

    args = get_args(parser) # Retrieve and parse arguments from the cl

    # If a PCAP file is provided for output stream, use it instead
    if args.PCAP is not None:
        outstream = open(args.PCAP, "wb") # Write to pcap as binary file

    # Initialize ZMQ SUB
    socket = create_zmq_sub(args.ZMQ, filter)

    if socket != -1:
    # Temp til threads implemented: while loop to catch information coming in and print to stdout. Kill it after
        err = 0
        while(err == 0): 
            err = unpack_zmq(socket, outstream, ts_mode) # Receive and unpack zmq messages as they come in 
    
    # Wait for the slow release of death
    
    # Shutdown the ZMQ SUB bus
    zmq_sub_destroy(socket)

    # Close the PCAP file if opened
    if not outstream.closed:
        print("Closing stream\n")
        outstream.close()

if __name__ == "__main__":
    main()