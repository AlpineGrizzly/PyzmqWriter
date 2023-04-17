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

global header_written
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

def handle_error(sub):
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

def zmq_sub_destroy(sub):
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

def print_header(fh):
    """ 
    print_header: Print the file header from the ZMQ PUB 
    :fh: File header information
    """
    print("File Header: %s\n" % fh)

def unpack_zmq(socket, header_written):
    """ 
    unpack_zmq: Unpack ZMQ PUB data 
    :socket: socket to receive ZMQ PUB data on 
    :header_written: Boolean for whether or not we have written our file header already
    return none
    """
    # Receive a packet of information from ZMQ to unpacks
    dev_msg = socket.recv() # Device source
    fh_msg = socket.recv()  # File Header 
    ts_msg = socket.recv()  # Time stamp
    pkt_msg = socket.recv() # Packet content/message
    
    if(header_written == False):
        print_header(fh_msg)
        return True  # We write the file header only once

    if(dev_msg and ts_msg and pkt_msg):
        print("Device: %s\nTime: %s\nContent:%s\n" % (dev_msg, ts_msg, pkt_msg))
    else:
        print("Error:: No message data received\n")

def main():
    filter = ""                   # Blank string means we subscribe to all topics
    outstream = sys.stdout.buffer # Initialize output stream to stdout
    header_written = False        # Have we written the file header to the packet

    parser = argparse.ArgumentParser(description="Use pkt_writer.exe to save packets to a pcap file or \
        to print packets into wireshark/tshark/tcpdump.", add_help=False) # Initialize argument parser object

    args = get_args(parser) # Retrieve and parse arguments from the cl

    # If a PCAP file is provided for output stream, use it instead
    if args.PCAP is not None:
        outstream = open(args.PCAP, "w") # Write to pcap as binary file
    
    # Initialize ZMQ SUB
    socket = create_zmq_sub(args.ZMQ, filter)
    
    if socket != -1:
    # Temp til threads implemented: while loop to catch information coming in and print to stdout. Kill it after
        while(1): 
            unpack_zmq(socket, header_written) # Receive and unpack zmq messages as they come in 
    
    # Wait for the slow release of death
    
    # Shutdown the ZMQ SUB bus
    
    # Close the PCAP file if opened
    if not outstream.closed:
        print("Closing stream\n")
        outstream.close()

if __name__ == "__main__":
    main()