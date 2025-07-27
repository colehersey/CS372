from segment import Segment

# Cole Hersey Programming Assignment 2 - Reliable Data Transmission
# Description:
# Built a RDT layer that effectively handles all of the below unreliable channel features through the use of selective repeat 
#   - Packet Loss (both data and ACK packets)
#   - Packet Delays
#   - Out of order delivery 
#   - Corrupted Transmissions (checksum errors)
# My goal was to maximize the effieciecy of the project with the use of selective repeat and optimal pipelining

class RDTLayer(object):
    # CLASS SCOPE VARIABLES
    DATA_LENGTH = 4 # in characters                     # string data that is sent per packet
    FLOW_CONTROL_WIN_SIZE = 15 # in characters          # Max window size for flow-control
    TIMEOUT_ITERATIONS = 8                              # timeout threshold calculation explained in depth in report


    def __init__(self):
        self.sendChannel = None
        self.receiveChannel = None
        self.dataToSend = ''
        self.currentIteration = 0
        

        # Sender state variables
        self.nextSeqNum = 0                             # Next sequence number to send
        self.sendBase = 0                               # start of the send window
        self.sentSegments = {}                          # {seqnum: (segment, send_time)}
        self.sndpkt = {}                                # buffed packets for retransmission
        self.lastSentTime = {}                          # Track when each segment was last sent
        
        # Receiver state variables (Selective Repeat)
        self.rcvBase = 0                                # Start of receiving window in characters
        self.receivedSegments = {}                      # {seqnum: data} -> buffed out of order segments
        self.receivedDataInOrder = ""                   # received data in correct order
        self.lastAckSent = {}                           # Track last ACK sent for each segment (duplicate detection)
        
        # Statistics and debugging
        self.countSegmentTimeouts = 0
        self.duplicateDataReceived = 0
        self.duplicateAcksReceived = 0


    # Called by main to set the unreliable sending lower-layer channel                                                 
    def setSendChannel(self, channel):
        self.sendChannel = channel
    
    # Called by main to set the unreliable receiving lower-layer channel                                               
    def setReceiveChannel(self, channel):
        self.receiveChannel = channel

    # Called by main to set the string data to send                                                                    
    def setDataToSend(self,data):
        self.dataToSend = data

    # Called by main to get the buffered string data in order                               
    def getDataReceived(self):
        return self.receivedDataInOrder

    # data processing method                                                             
    def processData(self):
        self.currentIteration += 1
        self.processSend()
        self.processReceiveAndSendRespond()

    # Manages the segment sending tasks                                                                                                    
    def processSend(self):
        # only send if there is data to send
        if not self.dataToSend:
            return
        
        # check for any timeouts and retransmit this data with the highest priority
        self.checkTimeoutsAndRetransmit()

        # then send the new packets to fill in the window
        self.sendNewPacketsInWindow()

    #send as many packets as efficiently possible within the flow control window
    def sendNewPacketsInWindow(self):
        packets_sent_this_iteration = 0

        while (self.nextSeqNum < len(self.dataToSend) and
               self.nextSeqNum < self.sendBase + self.FLOW_CONTROL_WIN_SIZE and
               packets_sent_this_iteration < 4): # (15 char/win) / (4 char/packet) = 4 packets/win 
               # this gives the time for processing to take place and limits the retransmission bursts
        
        # data boundaries
            data_start = self.nextSeqNum
            data_end = min(data_start + self.DATA_LENGTH, len(self.dataToSend))
            data_chunk = self.dataToSend[data_start:data_end]
            
            # create the segments proprely 
            segment = Segment()
            segment.setData(str(data_start), data_chunk)
            segment.setStartIteration(self.currentIteration)

            # dict copy of segment for each seqnum (reusable when needed instead of retransmitting the whole window)
            self.sndpkt[data_start] = segment
            self.sentSegments[data_start] = (segment, self.currentIteration)
            self.lastSentTime[data_start] = self.currentIteration

            # send the created seg and print info to terminal
            print(f"Sending NEW segment: seq={data_start}, data='{data_chunk}' [window: {self.sendBase}-{self.sendBase + self.FLOW_CONTROL_WIN_SIZE - 1}]")
            self.sendChannel.send(segment)
            
            #increase iteration count at end of each segment
            self.nextSeqNum = data_end
            packets_sent_this_iteration += 1

    #check for timeouts and only retransmit the needed segments    
    def checkTimeoutsAndRetransmit(self):
        current_time = self.currentIteration
        segments_to_retransmit = []
        
        # identify the segments that have timed out
        for seqnum, (segment, send_time) in self.sentSegments.items():
            if current_time - send_time >= self.TIMEOUT_ITERATIONS:
                segments_to_retransmit.append(seqnum)
        
        # retrasmit only the segments that have (selective repeat)
        for seqnum in segments_to_retransmit:
            if seqnum in self.sndpkt:
                segment = self.sndpkt[seqnum]
                
                # CRITICAL FIX: Create a NEW segment to avoid reference issues
                new_segment = Segment()
                new_segment.setData(str(seqnum), segment.payload)
                new_segment.setStartIteration(current_time)

                # Update ALL tracking dictionaries with current time
                self.sndpkt[seqnum] = new_segment
                self.sentSegments[seqnum] = (new_segment, current_time)
                self.lastSentTime[seqnum] = current_time
                
                #print error message for debugging
                print(f"RETRANSMITTING segment: seq={seqnum} (timeout after {self.TIMEOUT_ITERATIONS} iterations)")
                self.sendChannel.send(segment)
                self.countSegmentTimeouts += 1

    #identify if the incoming segments are data or ack
    def processReceiveAndSendRespond(self):
        listIncomingSegments = self.receiveChannel.receive()
        
        for segment in listIncomingSegments:
            if segment.acknum == -1:  # Data segment
                self.processDataSegment(segment)
            else:  # ACK segment
                self.processAckSegment(segment)

    def processDataSegment(self, segment):
         
        # verify checksum (data corruption)
        if not segment.checkChecksum():
            print(f"CORRUPTED segment received: seq={segment.seqnum} (checksum failed)")
            return  #ignore, timeout and retransmit

        seqnum = int(segment.seqnum)
        data = segment.payload
        
        print(f"Received data segment: seq={seqnum}, data='{data}'")
        
        # always ACK (even duplicates)
        self.sendAckForSegment(seqnum)
        
        # check if the new segment fits within the window
        if self.rcvBase <= seqnum < self.rcvBase + self.FLOW_CONTROL_WIN_SIZE:
            
            #check duplicates
            if seqnum in self.receivedSegments:
                print(f"Duplicate segment received: seq={seqnum}")
                self.duplicateDataReceived += 1
                return  # Already have this segment
            
            # buffer the segment
            self.receivedSegments[seqnum] = data
            print(f"Buffered segment: seq={seqnum}")
            
            # if a gap is filled at the base, deliver the following segments
            if seqnum == self.rcvBase:
                self.deliverConsecutiveSegments()
        
        else:
            # if the segment is outside of the window them send an ACK, but do not buffer
            print(f"Segment outside window: seq={seqnum} (window: {self.rcvBase}-{self.rcvBase + self.FLOW_CONTROL_WIN_SIZE - 1})")

    def processAckSegment(self, segment):
        ack_seqnum = int(segment.acknum)

        # check if the new ACK is a duplicate
        if ack_seqnum not in self.sentSegments:
            print(f"Received duplicate/late ACK: {ack_seqnum}")
            self.duplicateAcksReceived += 1
            return
        
        print(f"Received valid ACK: {ack_seqnum}")
        
        # remove the ackd segment from the buffer list
        if ack_seqnum in self.sentSegments:
            del self.sentSegments[ack_seqnum]
        if ack_seqnum in self.sndpkt:
            del self.sndpkt[ack_seqnum]
        if ack_seqnum in self.lastSentTime:
            del self.lastSentTime[ack_seqnum]
        
        #slide the window if ACK recieved is for the base segment
        if ack_seqnum == self.sendBase:
            old_base = self.sendBase

            #find the next segment in order that has yet to be ACKd
            while self.sendBase < self.nextSeqNum and self.sendBase not in self.sentSegments:
                # Advance by segment size (find where the next segment starts and move pointer)
                next_boundary = self.findNextSegmentBoundary(self.sendBase)
                self.sendBase = next_boundary
            
            #if moving base print message
            if self.sendBase != old_base:
                print(f"WINDOW ADVANCED: {old_base} -> {self.sendBase}")
        
    def sendAckForSegment(self, seqnum):
        # Send new ACK for duplicates in case the network failed
        segmentAck = Segment()
        segmentAck.setAck(str(seqnum))
        
        print(f"Sending ACK: {seqnum}")
        self.sendChannel.send(segmentAck)
        
        self.lastAckSent[seqnum] = self.currentIteration

    # deliver all of the segments starting from the recieved base
    def deliverConsecutiveSegments(self):
        delivered_count = 0
        
        while self.rcvBase in self.receivedSegments:
            # add the new recieved data to the string
            data = self.receivedSegments[self.rcvBase]
            self.receivedDataInOrder += data
            
            # remove it from the buffer
            del self.receivedSegments[self.rcvBase]
            
            # advance the recieved base by the length of the data recieved
            old_base = self.rcvBase
            self.rcvBase += len(data)
            delivered_count += 1
            
            print(f"DELIVERED segment: seq={old_base}, new rcvBase: {self.rcvBase}")
        
        if delivered_count > 0:
            print(f"Delivered {delivered_count} consecutive segments, total received: {len(self.receivedDataInOrder)} chars")

    #find the beginning of the next segment
    def findNextSegmentBoundary(self, current_pos):
       
        if current_pos >= len(self.dataToSend):
            return len(self.dataToSend)
        
        # calc for index of the segment
        # what char the next segment begins at
        segment_start = (current_pos // self.DATA_LENGTH) * self.DATA_LENGTH
        next_segment_start = segment_start + self.DATA_LENGTH
        
        #edge cases, dont let the next segment exceed the total data length
        return min(next_segment_start, len(self.dataToSend))

    # print state information for debugging purposes
    def printDebugInfo(self):
        print(f"DEBUG - Send: base={self.sendBase}, next={self.nextSeqNum}, pending={len(self.sentSegments)}")
        print(f"DEBUG - Recv: base={self.rcvBase}, buffered={len(self.receivedSegments)}, total={len(self.receivedDataInOrder)}")
        print(f"DEBUG - Stats: timeouts={self.countSegmentTimeouts}, dupData={self.duplicateDataReceived}, dupAcks={self.duplicateAcksReceived}")
