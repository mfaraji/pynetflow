#!/usr/bin/python2.7

# Python NetFlow Collector
#
# Copyright (C) 2011 pynetflow Project
# Author: Choonho Son <choonho@kt.com>
# URL: <http://pynetflow.googlecode.com>
# For license information, see LICENSE.TXT
#

import sys
import os
import time
import socket
import Queue
import threading
import signal
import struct
import SocketServer
import pickle                  # for dump & load (recovery process)
import datetime
import operator

from threading import Thread
from optparse import OptionParser

from proto import *

# Global variable
port = 9996
network = []          # [(nw1,subnet1), (nw2,subnet2) ...]
verbose = False
verbose_tag = "None"
repos = "/tmp"
BACKUP_PERIOD = 3600  # BACKUP TIME after last backup (second)
SAVE_PERIOD = 3600    # SAVE Data, during SAVE_PERIOD (second)
SIZE_OF_HEADER = 24   # Netflow v5 header size
SIZE_OF_RECORD = 48   # Netflow v5 record size
ONEDAY_SECOND = 86400 # 60 second * 60 minute * 24 hours
TIMELINE_PERIOD = 300 # 60 second * 5 minute
NUM_OF_TIMELINE_INDEX = 288     # 5 minute slot (86400 / 60*5)
UPLINK = 0            # UPLINK of timeline
DOWNLINK = 1          # DOWNLINK of timeline
dump_file = "/tmp/pynetflow.pkl"
console = 9000
options = None
o_packets = {}
o_bytes = {}
t_packets = {}
t_bytes = {}
o_packets_p = {}
o_bytes_p = {}
start_date = ""
is_console=False

NETMASK = {0: socket.inet_aton("255.255.255.255"),
           8: socket.inet_aton("0.255.255.255"),
           16: socket.inet_aton("0.0.255.255"),
           24: socket.inet_aton("0.0.0.255"),
}


API_ERROR = {"IP": "IP address is not correct format",
             "no data": "No data"
             }
# Data Structure of Final Result
DataStructure = {}

# Queue
queue_netflow = Queue.Queue()

# SIGNAL
WORKING = True
LOCK = threading.Lock()
STOP = 0

def debug(value, comment='', tag="None"):
    global verbose
    global verbose_tag
    global is_console
    if verbose == True and (verbose_tag == tag or verbose_tag == "all") and is_console==False:
        print "[DEBUG %s] %s  (%s)" % (comment, value,is_console)

class Signalled(Exception):
    # Finalize queue_netflow
    debug("Signalled occured", tag="signal")


def sigBreak(signum, f):
    global STOP
    LOCK.acquire()
    STOP = 1
    LOCK.release()
    debug("Raise Signalled", tag="signal")
    raise Signalled

class Netflow_Parser(SocketServer.BaseRequestHandler):
    """
    Netflow Collector
    1) Listen UDP packet,
    2) Push to Queue, if it is netflow 5
    """
    def handle(self):
        debug("called handler")
        data = self.request[0].strip()
        socket = self.request[1]
        debug("%s len(%s)" % (self.client_address[0],len(data)) , "client IP")
        # Check Packet is netflow v5
        (TF, version) = self.checkNetflowPacket(data)
        global queue_netflow
        if TF == True:
            queue_netflow.put(data)
            debug(len(data), "Push to Queue")
        else:
            print "Wrong Netflow packet"
            debug(data, "Wrong Netflow packet")

    def checkNetflowPacket(self, packet):
        # Check packet is Netflow v5
        # return (TF, records)
        version = socket.ntohs(struct.unpack('H',packet[0:2])[0])
        count = socket.ntohs(struct.unpack('H',packet[2:4])[0])
        #print "Version", version, "count", count
        if version == 5 and (count*SIZE_OF_RECORD + SIZE_OF_HEADER) == len(packet):
            # correct netflow 5
            return (True, 5)
        return (False, -1)

class Netflow_Analyzer(Thread):
    def run(self):
        debug("Start Netflow Analyzer Thread....")
        global queue_netflow
        while STOP == 0:
            data = queue_netflow.get()
            # Check of signal
            if data == False:
                # end of process (signalled)
                return
            (header, records) = self.parseNetflow5Packet(data)
            for index in range(len(records) / SIZE_OF_RECORD):
                start = index * SIZE_OF_RECORD
                record = records[start:start+SIZE_OF_RECORD]
                flow = self.parseRecord(record)

                # Find slot
                ((slot,netmask), direction) = self.getSlot(flow['saddr'], flow['daddr'])
                if slot == False:
                    debug(direction)
                    continue

                # Find slot index
                index = 0
                if direction == UPLINK:
                    index = self.toInt(self.bitwiseAND(flow['saddr'], netmask))

                    debug(index, "UPLINK")
                else:
                    index = self.toInt(self.bitwiseAND(flow['daddr'], netmask))
                    debug(index, "DOWNLINK")
                debug(index, "Slot index",tag="backup")
                timeline = slot[index]

                # Find timeline
                (timeline_index, stime) = self.getTimeline(flow['stime'], header['SysUpTime'], header['EpochSeconds'])

                debug(timeline_index, "Timeline_index", tag="parse")

                # TEST
                if timeline_index > NUM_OF_TIMELINE_INDEX:
                    debug(timeline_index, "Timeline Index Overflow", tag="parse")

                # Find link
                links = timeline[timeline_index]
                link = links[direction]   # 0:uplink, 1:downlink
                flow_t = [flow['saddr'], flow['daddr'], flow['pcount'], flow['bcount'], \
                              stime, flow['etime']-flow['stime'], flow['sport'], flow['dport'], flow['protocol']]
                # Append Data
                ip_saddr=socket.inet_ntoa(flow['saddr'])
                ip_daddr=socket.inet_ntoa(flow['daddr'])
                dport=flow['dport']
                protocol=flow['protocol']
                #print "received ip is %s -- > %s" %(ip_saddr,ip_daddr)
                p = o_packets.get(ip_saddr, 0)
                b = o_bytes.get(ip_saddr, 0)

                o_packets[ip_saddr] = p+flow['pcount']
                o_bytes[ip_saddr] = b+flow['bcount']

                p2 = o_packets_p.get((ip_saddr, ip_daddr, dport, protocol), 0)
                b2 = o_bytes_p.get((ip_saddr, ip_daddr, dport, protocol), 0)

                o_packets_p[(ip_saddr, ip_daddr, dport, protocol)] = p2+flow['pcount']
                o_bytes_p[(ip_saddr, ip_daddr, dport, protocol)] = b2+flow['bcount']

                p = t_packets.get(ip_daddr, 0)
                b = t_bytes.get(ip_daddr, 0)

                t_packets[ip_daddr] = p+flow['pcount']
                t_bytes[ip_daddr] = b+flow['bcount']

                link.append(flow_t)


    def parseNetflow5Packet(self, packet):
        # parse to Header , Records
        header = {}
        header['SysUpTime'] = socket.ntohl(struct.unpack('I',packet[4:8])[0])
        # fix time to localtime zone
        #header['EpochSeconds'] = socket.ntohl(struct.unpack('I',packet[8:12])[0]) - (time.timezone)
        header['EpochSeconds'] = socket.ntohl(struct.unpack('I',packet[8:12])[0])


        return (header,packet[SIZE_OF_HEADER:])

    def parseRecord(self, record):
        d = {}
        d['saddr'] = record[0:4]
        d['daddr'] = record[4:8]
        d['pcount'] = socket.ntohl(struct.unpack('I',record[16:20])[0])
        d['bcount'] = socket.ntohl(struct.unpack('I',record[20:24])[0])
        d['stime'] = socket.ntohl(struct.unpack('I',record[24:28])[0])
        d['etime'] = socket.ntohl(struct.unpack('I',record[28:32])[0])
        d['sport'] = socket.ntohs(struct.unpack('H',record[32:34])[0])
        d['dport'] = socket.ntohs(struct.unpack('H',record[34:36])[0])
        d['protocol'] = ord(record[38])
        result = "%s(%d) -(%d)-> %s(%d) from %s to %s, pcount:%d, bcount:%d" % (
            socket.inet_ntoa(d['saddr']), d['sport'], d['protocol'], socket.inet_ntoa(d['daddr']), d['dport'], \
                d['stime'], d['etime'], d['pcount'], d['bcount'])
        debug(result, "Record")
        return d

    def getSlot(self, saddr, daddr):
        # return (Slot, direction) from DataStructure
        for nw in DataStructure.keys():
            # check DADDR
            if self.bitwiseAND(daddr , nw) == nw:
                return (DataStructure[nw], DOWNLINK)
            elif self.bitwiseAND(saddr , nw) == nw:
                return (DataStructure[nw], UPLINK)
        return ( (False,False), "Cannot Find Slot")

    def getTimeline(self, stime, SysUpTime, EpochSeconds):
        # return (timeline_index, second.milisecond)
        # timeline_index is where to save flow_t
        milisecond = stime - SysUpTime
        elapse_second = milisecond / 1000
        (time_s, time_m) = (EpochSeconds + elapse_second, milisecond % 1000)
        timeline = (time_s % ONEDAY_SECOND) / TIMELINE_PERIOD
        return (timeline, "%s.%s" % (time_s, time_m) )

    def bitwiseAND(self, a, b):
        # bitwise 4 bytes string a,b
        return "%s%s%s%s" % (chr( ord(a[0]) & ord(b[0]) ), chr( ord(a[1]) & ord(b[1]) ), \
                                 chr( ord(a[2]) & ord(b[2]) ), chr( ord(a[3]) & ord(b[3]) ) )
    def toInt(self, bytes):
        # convert 4 bytes string to integer
        debug(socket.inet_ntoa(bytes),"slot index")

        return (ord(bytes[0]) << 24) + (ord(bytes[1]) << 16) + (ord(bytes[2]) < 8) + (ord(bytes[3]))

class Backup_Manager(Thread):
    def run(self):
        debug("Start Netflow Backup Manager....",tag="backup")

        self.backup_timeline_index = 0
        # data is backup from backup_timeline_index to current_timeline_index
        #
        while STOP == 0:
            # Loop until exit signal
            # init value
            # TODO: check time.time() is localtime second or GMT (we needs it is based on localtime)
            current_timeline_index = (time.time() % ONEDAY_SECOND) / TIMELINE_PERIOD

            new_backup = 0
            # after wake up, start backup
            for network in DataStructure.keys():
                # DATA structure
                (slot,subnet) = DataStructure[network]

                # start time index
                local_backup_timeline_index = self.backup_timeline_index

                if current_timeline_index < local_backup_timeline_index:
                    # this case is change of day
                    current_timeline_index = current_timeline_index + NUM_OF_TIMELINE_INDEX

                # check time to backup
                # update_timeline_index is timeline index  until this time
                update_timeline_index = local_backup_timeline_index + (BACKUP_PERIOD / (5*60))


                debug("Check %s->%s in %s(outer)" % (local_backup_timeline_index, update_timeline_index, current_timeline_index), "backup time index", tag="backup")

                final_index = current_timeline_index - (SAVE_PERIOD / (5*60))
                while update_timeline_index <= final_index:
                # Backup data
                    debug("Backup: from (%s) to (%s)" % (local_backup_timeline_index, update_timeline_index), tag="backup")

                    filename = "%s/%s_%s" % (repos, self.get_time(local_backup_timeline_index), socket.inet_ntoa(network))
                    debug(filename, "Open file to backup", tag="backup")
                    fp = open(filename,'w')
                    for timeline in slot:
                        # backup for each timeline
                        self.backup(timeline, local_backup_timeline_index, fp)
                        new_backup = local_backup_timeline_index + 12
                    # close file for network
                    fp.close()
                    # update backup_timeline_index
                    #self.backup_timeline_index = update_timeline_index % NUM_OF_TIMELINE_INDEX
                    local_backup_timeline_index = update_timeline_index

                    # Check next day
                    if local_backup_timeline_index > NUM_OF_TIMELINE_INDEX:
                        break # Finish loop

                    update_timeline_index = local_backup_timeline_index + (BACKUP_PERIOD / (5*60))


            # End of each network backup
            self.backup_timeline_index = new_backup % NUM_OF_TIMELINE_INDEX
            time.sleep(BACKUP_PERIOD)
            #time.sleep(60)
            debug(time.localtime(), "wakeup", tag="backup")

    def backup(self, timeline, bti, fp, delta=12):
        # backup data in timeline (up, down link)
        # delta is number of timeline index for backup
        # ,since timeline index consists of 5 minute interval (1 hour = 12)
        for index in range(delta):
            (uplink, downlink) = timeline[(bti+index)%NUM_OF_TIMELINE_INDEX]
            r_uplink = self.get_flow_t(uplink, UPLINK)
            r_downlink = self.get_flow_t(downlink, DOWNLINK)
            fp.write(r_uplink)
            fp.write(r_downlink)
            # free link
            timeline[(bti+index)%NUM_OF_TIMELINE_INDEX] = ([],[])
            #debug((bti+index)%NUM_OF_TIMELINE_INDEX, "Free  timeline",tag="backup")

    def get_flow_t(self, list, dir):
        # dir is direction (0: uplink, 1:downlink)
        # return data from link
        result = ""
        for flow_t in list:
            saddr = socket.inet_ntoa(flow_t[0])
            daddr = socket.inet_ntoa(flow_t[1])
            result= result + "%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n" % \
            (dir, saddr, daddr, flow_t[2], flow_t[3], flow_t[4], flow_t[5], flow_t[6], flow_t[7], flow_t[8])
        #debug(result,"flow_t","backup")
        return result

    def get_time(self, timeline_index):
        # return date of timeline_index
        # ex) if timeline_index : 0
        #     return 201101180000
        # ex) if timeline_index : 1
        #     return 201101180005
        if timeline_index >= 264: # in a next day, save previous day's data
            date = time.strftime("%Y%m%d", time.gmtime(time.time() - 12000))
        else:
            date = time.strftime("%Y%m%d", time.gmtime())

        hour = time.strftime("%H%M", time.gmtime(timeline_index * 60 * 5))
        file_time = "%s%s" % (date, hour)
        debug("%s %s" % (timeline_index, file_time), "filename", tag="backup")
        return file_time

class ThreadedConsoleAPIHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(1024)
        cur_thread = threading.currentThread()

        # Parse Command
        (tf, response) = self.parseAPI(data)
        if tf == False:
            self.request.send(response)
            return
        if tf == True and response == "exit":
            self.request.send(response)
            return
        # General command API
        if tf == True:
            self.request.send(response)

    def parseAPI(self, data):
        global API_ERROR
        global is_console
        temp = data.split("\n")       # delete enter
        token = temp[0].split(" ")       # parse cmd

        debug(token, tag="api")
        if token[0] == "exit" or token[0] == "quit":
            # exit signal
            return (True, "exit")

        # show <IP> <Timestamp> <link> <limit>
        if token[0] == "show":
            nip = None
            timestamp = None
            link = -1
            limit = 100000   # MAX result row
            try:
                nip = socket.inet_aton(token[1])
                print "packet count is %s " %packets[nip]
                print "byte count is %s " %bytes[nip]
                timestamp = long(token[2])
                link = int(token[3])
                limit = int(token[4])
                if limit == 0:
                    limit = 100000
            except:
                return (False, API_ERROR['IP'])

            # get timeline Data
            timeline = getTimeline(nip)

            if timeline == False:
                return (False, API_ERROR['no data'])

            # make result
            r_index = (int(token[2]) % ONEDAY_SECOND) / TIMELINE_PERIOD         #requested index
            c_index = (int(time.time()) % ONEDAY_SECOND) / TIMELINE_PERIOD      #current index
            print r_index, c_index
            # check next day
            if c_index < r_index:
                c_index = c_index + NUM_OF_TIMELINE_INDEX


            result = []
            for index in range(c_index - r_index + 1):
                fetch_index = (r_index + index) % NUM_OF_TIMELINE_INDEX
                debug(fetch_index, tag="api")
                (u_link, d_link) = timeline[ fetch_index ]

                if link == 0 or link == -1:
                    self.getIPbyTimestamp(u_link, timestamp, result)
                if link == 1 or link == -1:
                    self.getIPbyTimestamp(d_link, timestamp, result)

            result.sort()
            output = self.toString(result, limit)
            debug(output, tag="api")
        return (True, output)

    def getIPbyTimestamp(self, link, timestamp, result):
        for flow_t in link:
            # output format [timestamp, saddr, sport, proto, daddr, dport, bcount, pcount]
            if timestamp < flow_t[4]:
                result.append([flow_t[4], flow_t[0], flow_t[6], flow_t[8], flow_t[1], flow_t[7], flow_t[3], flow_t[2]])

    def toString(self, result, limit):
        output = ""
        global PROTO_DIC
        count = len(result)
        if len(result) > limit:
            count = limit

        for index_t in range(count):
            index = result[index_t]
            # format: timestamp srcIP(srcPort)-(PROTO)->dstIP(dstPort) nBytes nPacket
            print "index", index, len(index)
            output = output + "%s %s(%s)-%s->%s(%s) %s %s\n" % \
                     (index[0],socket.inet_ntoa(index[1]), index[2], PROTO_DIC[index[3]], \
                      socket.inet_ntoa(index[4]), index[5], index[6], index[7])
        print output
        return output




class ThreadedConsleAPI(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass

class Console_Manager(Thread):

    def __init__(self):
        self.__cmd_history = ""
        Thread.__init__(self)

    def run(self):
        debug("Start Console Manager....")
        global is_console
        first_time=True
        cmd=""
        while STOP == 0:
            if(is_console==False and cmd.rstrip()=="continue"):
                cmd = raw_input("logout")
            else:
                cmd = raw_input("Console Manager(? help) >")
            self.parse_cmd(cmd)
            if cmd.rstrip() != "continue":
                is_console=True

    def parse_cmd(self, cmd):
        global is_console
        token = cmd.split(" ")
        if token[0] == "last":
           print "running last command: %s" %self._cmd_history
           self.parse_cmd(self._cmd_history)
           return
        if token[0] == "plot":
            # ex) plot 10.1.1.2
            self._cmd_history = cmd
            self.plot(token[1])
            print "packet count is %s " %packets[token[1]]
            print "byte count is %s " %bytes[token[1]]
        elif token[0] == "stat":
            self._cmd_history = cmd
            self.stat()
        elif token[0] == "exit":
            os._exit(0)
        elif token[0] == "show":
            self._cmd_history = cmd
            now = datetime.datetime.now()

            print "date and time is: %s " %str(now)
            print "date and time is: %s " %str(now)

            p = o_packets.get(token[1], 0)
            b = o_bytes.get(token[1], 0)
            print "O packet count is %s " %p
            print "O byte count is %s " %b
            p = t_packets.get(token[1], 0)
            b = t_bytes.get(token[1], 0)
            print "T packet count is %s " %p
            print "T byte count is %s " %b
        elif token[0] == "sort":
            self._cmd_history = cmd
            now = datetime.datetime.now()
            print "Starting date and time is: %s " %str(start_date)
            print "Now      date and time is: %s " %str(now)
            diff = (now - start_date).seconds
            print "Seconds since start %d, and hours %.2f " %(diff, diff/float(3600))
            sorted_x = sorted(o_bytes.iteritems(), key=operator.itemgetter(1), reverse=True)
            #print sorted_x
            i = 0
            sorted_y=[]
            total = 0
            for k, val in sorted_x:
                #print "value %s, %s" %(k, val)
                sorted_y.append((k, val/1000, val*8/diff/1000))
                total += val
            max_lines = len(sorted_y)
            try:
               temp1 = int(token[1])
               max_lines = temp1
            except:
               pass
            for k, val, rate in sorted_y[:max_lines]:
                print "address, bytes, rate is:  %s, %s KB, %s kbps" %(k, val, rate)
            print "total byte is %s KB, total bit rate: %s kbps" %(total/1000, total*8/diff/1000)
            #print sorted_y
            #print sorted_x.reverse()
        elif token[0] == "ports":
            self._cmd_history = cmd
            now = datetime.datetime.now()
            print "Starting date and time is: %s " %str(start_date)
            print "Now      date and time is: %s " %str(now)
            diff = (now - start_date).seconds
            print "Seconds since start %d, and hours %.2f " %(diff, diff/float(3600))
            list1={}
            for i in o_bytes_p.items():
                ((k1,k2,k3,k4), v) = i
                if k1 == token[1]:
                   list1[(k2,k3,k4)]=v

            sorted_x = sorted(list1.iteritems(), key=operator.itemgetter(1), reverse=True)
            #print sorted_x
            i = 0
            sorted_y=[]
            total = 0
            for k, val in sorted_x:
                #print "value %s, %s" %(k, val)
                sorted_y.append((k, val/1000, val*8/diff/1000))
                total += val
            max_lines = len(sorted_y)
            try:
               temp1 = int(token[2])
               max_lines = temp1
            except:
               pass
            for k, val, rate in sorted_y[:max_lines]:
                print "address, bytes, rate is:  (%s->%s), %s KB, %s kbps" %(token[1], k, val, rate)
            print "total byte is %s KB, total bit rate: %s kbps" %(total/1000, total*8/diff/1000)
            #print sorted_y
            #print sorted_x.reverse()
        elif (token[0] == "help" or token[0] == "?"):
            print "show <ip address> : shows byte and packet counts for an IP address"
            print "ports <ip address> [n] : shows tcp/udp ports for an IP address (sorted), n: first n entries"
            print "sort [n] : shows sorted list of bw usgae for all IP addresses, n: first n enetries"
            print "exit"
        elif (token[0] == "continue"):
            is_console = False

    def plot(self, ip):
        # plot graph of ip

        nip = socket.inet_aton(ip)
        timeline = getTimeline(nip)
        if timeline == False:
            # error
            return
        # draw line
        d_uplink = []
        d_downlink = []
        for (uplink, downlink) in timeline:
            d_uplink.append(getBytesFromLink(uplink)/1000)
            d_downlink.append(0 - getBytesFromLink(downlink)/1000)
        try:
            import matplotlib.pyplot as plt
            plt.plot(d_uplink)
            plt.plot(d_downlink)
            plt.ylabel('UPLINK')
            plt.show()
        except:
            print "Uplink", d_uplink
            print "Downlink", d_downlink

    def stat(self):
        global DataStructure
        for slot in DataStructure.keys():
            print slot

def startAnalyzer():
    # start threads
    global port
    netflow_parser = SocketServer.UDPServer(("",port), Netflow_Parser)

    # new
    thr_netflow_analyzer = Netflow_Analyzer()
    thr_backup_manager = Backup_Manager()
    thr_console_manager = Console_Manager()
    # Console API
    global console
    HOST, PORT = "localhost", console
    consoleAPI = ThreadedConsleAPI( (HOST,PORT), ThreadedConsoleAPIHandler)
    consoleAPIthread = threading.Thread(target=consoleAPI.serve_forever)
    consoleAPIthread.setDaemon(True)
    consoleAPIthread.start()


    # start Thread first
    thr_netflow_analyzer.start()
    thr_backup_manager.start()
    thr_console_manager.start()

    # start Collect Server
    debug(port, "Start UDP Server")


    # signal
    try:
        netflow_parser.serve_forever()
        signal.pause()
    except Signalled:
        #netflow_parser.socket.close()
        debug("exept Singall 1", tag="signal")
        netflow_parser.server_close()
        debug("except Signall 2" , "server_close", tag="signal")

        # send Null data to Queue for last computation of queue_netflow
        queue_netflow.put(False)
        debug("except signall 3", "end of queue", tag="signal")

        # shutdown consoleAPI server
        #consoleAPIthread.shutdown()

    # join

    debug("wait Before Join", tag="signal")
    thr_netflow_analyzer.join()
    debug("thr_netflow_analyzer joined", tag="signal")

    exit(0)

    thr_console_manager.join()
    debug("thr_console_manager joined", tag="signal")

    thr_backup_manager.join(timeout=10)
    debug("thr_backup_manager joined", tag="signal")


    consoleAPIthread.join(timeout=10)
    debug("consoleAPIthread joined", tag="signal")
    return
    dump_DataStructure()
    queue_netflow.join()
    debug("finish join", tag="signal")
    return

def initDataStructure(restore=False):
    # init Data Structure of Netflow result
    global DataStructure
    global network
    global NETMASK

    if restore == True:
        # restore data from dump
        global dump_file
        file = open(dump_file, 'rb')
        DataStructure = pickle.load(file)
        file.close()
        return

    for (nw,subnet) in network:
        ip = 0x01 <<(32 - subnet)
        # init default slot (NUM_OF_TIMELINE_INDEX)
        # make slot per network
        slot = []
        for index in range(ip+1):
            # make timeline
            timeline = []
            for slot_index in range(NUM_OF_TIMELINE_INDEX):
                # add uplink, downlink
                uplink = []
                downlink = []
                timeline.append( (uplink, downlink) )
            # append timeline to slot
            slot.append(timeline)

        # assign slot to DataStructure
        DataStructure[nw] = (slot,NETMASK[subnet])
        debug(socket.inet_ntoa(nw), "Add DataStructure")

def dump_DataStructure():
    # Dump DataStructure with pickle dump
    global dump_file
    file = open(dump_file, 'wb')
    global DataStructure
    pickle.dump(DataStructure, file)
    file.close()

def getSlot(ip):
    # param ip: network order
    # return Slot from DataStructure
    # which has ip
    for nw in DataStructure.keys():
        # check bitwiseAND
        if bitwiseAND(ip, nw) == nw:
            return DataStructure[nw]
    debug(socket.inet_ntoa(ip), "Cannot find Slot")
    return (False, "Cannot find slot of %s" % socket.inet_ntoa(ip))

def getTimeline(ip):
    # return timeline of ip
    # find Slot
    (slot, subnet) = getSlot(ip)
    if slot == False:
        return False

    nw_index = bitwiseAND(ip, subnet)
    return slot[toInt(nw_index)]

def getBytesFromLink(link):
    # retrieve data from link
    result = 0
    for index in link:
        bcount = index[3]
        result = result + bcount
    return result


def bitwiseAND(a,b):
    # bitwise a and b
    # bitwise 4 bytes string a,b
    return "%s%s%s%s" % (chr( ord(a[0]) & ord(b[0]) ), chr( ord(a[1]) & ord(b[1]) ), \
                             chr( ord(a[2]) & ord(b[2]) ), chr( ord(a[3]) & ord(b[3]) ) )

def toInt(bytes):
    # convert 4 bytes string to integer
    return (ord(bytes[0]) << 24) + (ord(bytes[1]) << 16) + (ord(bytes[2]) < 8) + (ord(bytes[3]))

def add_network(nw):
    #config setting of monitoring network
    temp=nw.split("/")
    return ( socket.inet_aton(temp[0]), int(temp[1]) )

def parse_config(fname):
    # parse configure file
    # return cofig dictionary
    fp = open(fname,'r')
    config = {}
    for index in fp:
        if index[0] == "#" or index[0] == "\n":
            # Comment line
            continue
        line = index.split("\n")
        content = line[0].split(" ")
        config[content[0]] = content[1:]
    return config


def init():
    parser = OptionParser()
    parser.add_option("-c", "--config", dest="config", help="Load Configure file")
    parser.add_option("-p", "--port", dest="port", help="Netflow Collection UDP port", default="9996")
    parser.add_option("-n", "--network", dest="network", help="Monitoring Network range", default="10.10.10.0/24")
    parser.add_option("-v", "--verbose", dest="verbose", help="Debug options", default="all")
    parser.add_option("-r", "--restore", action="store_true", dest="restore", help="Restore data")

    global options
    (options, args) = parser.parse_args()

    global verbose
    global verbose_tag
    global port
    global network
    global repos
    global console

    if options.verbose:
        verbose = True
        verbose_tag = options.verbose
    if options.config:
        config = parse_config(options.config)
        if config.has_key('port'):
            # Port Number
            port = int(config['port'][0])
        if config.has_key('network'):
            # Network
            networks = config['network']
            for nw in networks:
                network.append( add_network(nw) )
        if config.has_key('repos'):
            # Repository
            repos = config['repos'][0]
        if config.has_key('backup_time'):
            # Data backup period
            BACKUP_PERIOD = int(config['backup_period'][0])
        if config.has_key('console'):
            # Console API port
            console = int(config['console'][0])

    debug(network, "Network Range")
    # Netflow collector UDP Port
    if options.port:
        port = int(options.port)
        debug(port, "UDP port")
    # Monitoring Network Range
    if options.network:
        nw = options.network
        network.append( add_network(nw) )
        debug(network, "Network Range")

    print network
    print port
    options.restore=False
    # Init DataStruct
    initDataStructure(restore=options.restore)

if __name__ == "__main__":
    print "started1"
    signal.signal(signal.SIGINT, sigBreak)
    # Data Struct Initialize
    print "started2"

    #global start_date

    start_date = datetime.datetime.now()
    print "start date and time is %s" %str(start_date)

    init()
    # Netflow collection & Analyzer
    startAnalyzer()
