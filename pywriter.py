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

#
#   Hello World client in Python
#   Connects REQ socket to tcp://localhost:5555
#   Sends "Hello" to server, expects "World" back
#

import os
import time
import argparse
import zmq
import sys 

#context = zmq.Context()

#  Socket to talk to server
#print("Connecting to hello world server…")
#socket = context.socket(zmq.REQ)
#socket.connect("tcp://localhost:5555")

#  Do 10 requests, waiting each time for a response
#for request in range(10):
#    print("Sending request %s …" % request)
#    socket.send(b"Hello")

    #  Get the reply.
#    message = socket.recv()
#    print("Received reply %s [ %s ]" % (request, message))

def get_args(parser):
    """
    Retrieves and parse arguments from the command line.
    """
    parser.add_argument('--help', '-h', action='help', help='Displays this information')
    parser.add_argument('--ZMQ', '-Z',  action='store', metavar='<args>', required=True, type=str, help='Set the ZMQ bus to listen on') 
    parser.add_argument('--PCAP', '-P',  action='store', metavar='', type=str, help='Write data to a pcap file')
    parser.add_argument('--stats', action='store_true', default=False, help='Display stats on stderr')
    parser.add_argument('--us', action='store_true', default=False, help='Force Microsecond Timestamps')
    parser.add_argument('--ns',	action='store_true', default=False, help='Force Nanosecond Timestamps')
    parser.add_argument('--maxtime', action='store',metavar='<args>', type=int, help='Stop after X seconds')
    parser.add_argument('--maxpkts', action='store', metavar='<args>', type=int, help='Stop after X pkts')
    parser.add_argument('--maxsize', action='store', metavar='<args>', type=int, help='Stop after X MB')

    args = parser.parse_args()
    print(args)
    return args

def create_zmq_sub(zmq_pub):
    """
    Creates ZMQ subscriber given an address and port to a zmq publisher
    e.g. tcp://localhost:9999
    """
    context = zmq.Context()          # Initialize zmq context object
    socket = context.socket(zmq.SUB) # Connect and subscribe the socket to the publisher
    socket.connect(zmq_pub)
    socket.subscribe("")

    return socket

def main():
    g_outstream = sys.stdout.buffer # Initialize output stream to stdout

    parser = argparse.ArgumentParser(description="Use pkt_writer.exe to save packets to a pcap file or \
        to print packets into wireshark/tshark/tcpdump.", add_help=False) # Initialize argument parser object

    args = get_args(parser) # Retrieve and parse arguments from the cl

    # If a PCAP file is provided for output stream, use it instead
    if args.PCAP is not None:
        g_outstream = open(args.PCAP, "wb") # Write to pcap as binary file
    
    # Initialize ZMQ SUB
    print("Connecting to ZMQ BUS\n")
    socket = create_zmq_sub(args.ZMQ)

    message = socket.recv()
    print("Received reply [ %s ]" % message)
    
    # Wait for the slow release of death

    # Shutdown the ZMQ SUB bus

    # Close the PCAP file if opened
    if not g_outstream.closed:
        print("Closing stream\n")
        g_outstream.close()

if __name__ == "__main__":
    main()