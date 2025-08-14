# Imports                                                                                                              
import os
from socket import *
import struct
import time
import select

# Class IcmpHelperLibrary                                                                                              
class IcmpHelperLibrary:
    
    # Class IcmpPacket Parameters                                                                                           
    # https://www.iana.org/assignments/icmp-parameters/icmp-parameters.xhtml                                           
    
    class IcmpPacket:
        # IcmpPacket Class Scope Variables                                                                             
        __icmpTarget = ""               # Remote Host
        __destinationIpAddress = ""     # Remote Host IP Address
        __header = b''                  # Header after byte packing
        __data = b''                    # Data after encoding
        __dataRaw = ""                  # Raw string data before encoding
        __icmpType = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __icmpCode = 0                  # Valid values are 0-255 (unsigned int, 8 bits)
        __packetChecksum = 0            # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetIdentifier = 0          # Valid values are 0-65535 (unsigned short, 16 bits)
        __packetSequenceNumber = 0      # Valid values are 0-65535 (unsigned short, 16 bits)
        __ipTimeout = 30
        __ttl = 255                     # Time to live

        __DEBUG_IcmpPacket = False      # Allows for debug output
        __DEBUG_IcmpPacket_VALIDATION = False  # Debug output for packet validation

        # IcmpPacket Class Getters:
        def getIcmpTarget(self):
            return self.__icmpTarget

        def getDataRaw(self):
            return self.__dataRaw

        def getIcmpType(self):
            return self.__icmpType

        def getIcmpCode(self):
            return self.__icmpCode

        def getPacketChecksum(self):
            return self.__packetChecksum

        def getPacketIdentifier(self):
            return self.__packetIdentifier

        def getPacketSequenceNumber(self):
            return self.__packetSequenceNumber

        def getTtl(self):
            return self.__ttl

        # IcmpPacket Class Setters:                                                                                     
        def setIcmpTarget(self, icmpTarget):
            self.__icmpTarget = icmpTarget

            # Only attempt to get destination address if it is not whitespace
            if len(self.__icmpTarget.strip()) > 0:
                self.__destinationIpAddress = gethostbyname(self.__icmpTarget.strip())

        def setIcmpType(self, icmpType):
            self.__icmpType = icmpType

        def setIcmpCode(self, icmpCode):
            self.__icmpCode = icmpCode

        def setPacketChecksum(self, packetChecksum):
            self.__packetChecksum = packetChecksum

        def setPacketIdentifier(self, packetIdentifier):
            self.__packetIdentifier = packetIdentifier

        def setPacketSequenceNumber(self, sequenceNumber):
            self.__packetSequenceNumber = sequenceNumber

        def setTtl(self, ttl):
            self.__ttl = ttl

        # IcmpPacket Class Private Functions                                                                           
        def __recalculateChecksum(self):
            print("calculateChecksum Started...") if self.__DEBUG_IcmpPacket else 0
            packetAsByteData = b''.join([self.__header, self.__data])
            checksum = 0

            # This checksum function will work with pairs of values with two separate 16 bit segments. Any remaining
            # 16 bit segment will be handled on the upper end of the 32 bit segment.
            countTo = (len(packetAsByteData) // 2) * 2

            # Calculate checksum for all paired segments
            print(f'{"Count":10} {"Value":10} {"Sum":10}') if self.__DEBUG_IcmpPacket else 0
            count = 0
            while count < countTo:
                thisVal = packetAsByteData[count + 1] * 256 + packetAsByteData[count]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture 16 bit checksum as 32 bit value
                print(f'{count:10} {hex(thisVal):10} {hex(checksum):10}') if self.__DEBUG_IcmpPacket else 0
                count = count + 2

            # Calculate checksum for remaining segment (if there are any)
            if countTo < len(packetAsByteData):
                thisVal = packetAsByteData[len(packetAsByteData) - 1]
                checksum = checksum + thisVal
                checksum = checksum & 0xffffffff        # Capture as 32 bit value
                print(count, "\t", hex(thisVal), "\t", hex(checksum)) if self.__DEBUG_IcmpPacket else 0

            # Add 1's Complement Rotation to original checksum
            checksum = (checksum >> 16) + (checksum & 0xffff)   # Rotate and add to base 16 bits
            checksum = (checksum >> 16) + checksum              # Rotate and add

            answer = ~checksum                  # Invert bits
            answer = answer & 0xffff            # Trim to 16 bit value
            answer = answer >> 8 | (answer << 8 & 0xff00)
            print("Checksum: ", hex(answer)) if self.__DEBUG_IcmpPacket else 0

            self.setPacketChecksum(answer)

        def __packHeader(self):
            # The following header is based on http://www.networksorcery.com/enp/protocol/icmp/msg8.htm
            # Type = 8 bits
            # Code = 8 bits
            # ICMP Header Checksum = 16 bits
            # Identifier = 16 bits
            # Sequence Number = 16 bits
            self.__header = struct.pack("!BBHHH",
                                   self.getIcmpType(),              #  8 bits / 1 byte  / Format code B
                                   self.getIcmpCode(),              #  8 bits / 1 byte  / Format code B
                                   self.getPacketChecksum(),        # 16 bits / 2 bytes / Format code H
                                   self.getPacketIdentifier(),      # 16 bits / 2 bytes / Format code H
                                   self.getPacketSequenceNumber()   # 16 bits / 2 bytes / Format code H
                                   )

        def __encodeData(self):
            data_time = struct.pack("d", time.time())               # Used to track overall round trip time
                                                                    # time.time() creates a 64 bit value of 8 bytes
            dataRawEncoded = self.getDataRaw().encode("utf-8")

            self.__data = data_time + dataRawEncoded

        def __packAndRecalculateChecksum(self):
            # Checksum is calculated with the following sequence to confirm data in up to date
            self.__packHeader()                 # packHeader() and encodeData() transfer data to their respective bit
                                                # locations, otherwise, the bit sequences are empty or incorrect.
            self.__encodeData()
            self.__recalculateChecksum()        # Result will set new checksum value
            self.__packHeader()                 # Header is rebuilt to include new checksum value

        def __validateIcmpReplyPacketWithOriginalPingData(self, icmpReplyPacket):
            # Hint: Work through comparing each value and identify if this is a valid response.
            isValid = True
            
            # Compare sequence number
            expectedSequenceNumber = self.getPacketSequenceNumber()
            actualSequenceNumber = icmpReplyPacket.getIcmpSequenceNumber()
            sequenceNumberValid = (expectedSequenceNumber == actualSequenceNumber)
            icmpReplyPacket.setIcmpSequenceNumber_isValid(sequenceNumberValid)
            
            if self.__DEBUG_IcmpPacket_VALIDATION:
                print(f"Sequence Number - Expected: {expectedSequenceNumber}, Actual: {actualSequenceNumber}, Valid: {sequenceNumberValid}")
            
            if not sequenceNumberValid:
                isValid = False
            
            # Compare packet identifier
            expectedIdentifier = self.getPacketIdentifier()
            actualIdentifier = icmpReplyPacket.getIcmpIdentifier()
            identifierValid = (expectedIdentifier == actualIdentifier)
            icmpReplyPacket.setIcmpIdentifier_isValid(identifierValid)
            
            if self.__DEBUG_IcmpPacket_VALIDATION:
                print(f"Identifier - Expected: {expectedIdentifier}, Actual: {actualIdentifier}, Valid: {identifierValid}")
            
            if not identifierValid:
                isValid = False
            
            # Compare raw data
            expectedData = self.getDataRaw()
            actualData = icmpReplyPacket.getIcmpData()
            dataValid = (expectedData == actualData)
            icmpReplyPacket.setIcmpData_isValid(dataValid)
            
            if self.__DEBUG_IcmpPacket_VALIDATION:
                print(f"Data - Expected: '{expectedData}', Actual: '{actualData}', Valid: {dataValid}")
            
            if not dataValid:
                isValid = False
            
            # Validate ICMP type (should be 0 for echo reply)
            actualType = icmpReplyPacket.getIcmpType()
            typeValid = (actualType == 0)
            icmpReplyPacket.setIcmpType_isValid(typeValid)
            
            if self.__DEBUG_IcmpPacket_VALIDATION:
                print(f"ICMP Type - Expected: 0 (Echo Reply), Actual: {actualType}, Valid: {typeValid}")
            
            if not typeValid:
                isValid = False
            
            # Validate ICMP code (should be 0 for echo reply)
            actualCode = icmpReplyPacket.getIcmpCode()
            codeValid = (actualCode == 0)
            icmpReplyPacket.setIcmpCode_isValid(codeValid)
            
            if self.__DEBUG_IcmpPacket_VALIDATION:
                print(f"ICMP Code - Expected: 0, Actual: {actualCode}, Valid: {codeValid}")
            
            if not codeValid:
                isValid = False
            
            icmpReplyPacket.setIsValidResponse(isValid)
            
            if self.__DEBUG_IcmpPacket_VALIDATION:
                print(f"Overall packet validation: {isValid}")

        # IcmpPacket Class Public Functions                                                                           
        def buildPacket_echoRequest(self, packetIdentifier, packetSequenceNumber):
            self.setIcmpType(8)
            self.setIcmpCode(0)
            self.setPacketIdentifier(packetIdentifier)
            self.setPacketSequenceNumber(packetSequenceNumber)
            self.__dataRaw = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
            self.__packAndRecalculateChecksum()

        def sendEchoRequest(self):
            if len(self.__icmpTarget.strip()) <= 0 | len(self.__destinationIpAddress.strip()) <= 0:
                self.setIcmpTarget("127.0.0.1")

            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(5)
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', self.getTtl()))  # Unsigned int - 4 bytes
            try:
                mySocket.sendto(b''.join([self.__header, self.__data]), (self.__destinationIpAddress, 0))
                timeLeft = 5
                pingStartTime = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                endSelect = time.time()
                howLongInSelect = (endSelect - startedSelect)
                if whatReady[0] == []:  # Timeout
                    print("  *        *        *        *        *    Request timed out.")
                    return None
                recvPacket, addr = mySocket.recvfrom(1024)  # recvPacket - bytes object representing data received
                # addr  - address of socket sending data
                timeReceived = time.time()
                timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    print("  *        *        *        *        *    Request timed out (By no remaining time left).")
                    return None

                else:
                    # Fetch the ICMP type and code from the received packet
                    icmpType, icmpCode = recvPacket[20:22]

                    # Get ICMP code description from parent class
                    helperLibrary = IcmpHelperLibrary()
                    codeDescription = helperLibrary._IcmpHelperLibrary__getIcmpCodeDescription(icmpType, icmpCode)
                    
                    if icmpType == 11:                          # Time Exceeded
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s    (%s)" %
                                (
                                    self.getTtl(),
                                    (timeReceived - pingStartTime) * 1000,
                                    icmpType,
                                    icmpCode,
                                    addr[0],
                                    codeDescription
                                )
                              )
                        return {
                            'addr': addr[0],
                            'rtt': (timeReceived - pingStartTime) * 1000,
                            'icmpType': icmpType,
                            'icmpCode': icmpCode,
                            'description': codeDescription
                        }

                    elif icmpType == 3:                         # Destination Unreachable
                        print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s    (%s)" %
                                  (
                                      self.getTtl(),
                                      (timeReceived - pingStartTime) * 1000,
                                      icmpType,
                                      icmpCode,
                                      addr[0],
                                      codeDescription
                                  )
                              )
                        return {
                            'addr': addr[0],
                            'rtt': (timeReceived - pingStartTime) * 1000,
                            'icmpType': icmpType,
                            'icmpCode': icmpCode,
                            'description': codeDescription
                        }

                    elif icmpType == 0:                         # Echo Reply
                        icmpReplyPacket = IcmpHelperLibrary.IcmpPacket_EchoReply(recvPacket)
                        self.__validateIcmpReplyPacketWithOriginalPingData(icmpReplyPacket)
                        rtt = icmpReplyPacket.printResultToConsole(self.getTtl(), timeReceived, addr)
                        return rtt     # Echo reply is the end and therefore should return RTT

                    else:
                        print(f"  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s    (Unknown ICMP Type)" %
                              (
                                  self.getTtl(),
                                  (timeReceived - pingStartTime) * 1000,
                                  icmpType,
                                  icmpCode,
                                  addr[0]
                              )
                             )
            except timeout:
                print("  *        *        *        *        *    Request timed out (By Exception).")
            except OSError as e:
                if e.winerror == 10051:  # Network unreachable
                    print(f"  TTL={self.getTtl()}    RTT=0 ms    Type=3    Code=0    Network Unreachable    (OS Error: {e})")
                    return {
                        'addr': 'N/A',
                        'rtt': 0,
                        'icmpType': 3,
                        'icmpCode': 0,
                        'description': 'Network Unreachable (OS Level)'
                    }
                else:
                    print(f"  TTL={self.getTtl()}    Network Error: {e}")
            except Exception as e:
                print(f"  TTL={self.getTtl()}    Other Error: {e}")
            finally:
                mySocket.close()
                
            return None  # Return None if no successful echo reply

        def printIcmpPacketHeader_hex(self):
            print("Header Size: ", len(self.__header))
            for i in range(len(self.__header)):
                print("i=", i, " --> ", self.__header[i:i+1].hex())

        def printIcmpPacketData_hex(self):
            print("Data Size: ", len(self.__data))
            for i in range(len(self.__data)):
                print("i=", i, " --> ", self.__data[i:i + 1].hex())

        def printIcmpPacket_hex(self):
            print("Printing packet in hex...")
            self.printIcmpPacketHeader_hex()
            self.printIcmpPacketData_hex()

    # Class IcmpPacket_EchoReply                                                                                       #
    # References:                                                                                                      #
    # http://www.networksorcery.com/enp/protocol/icmp/msg0.htm                                                         #

    class IcmpPacket_EchoReply:
       
        # IcmpPacket_EchoReply Class Scope Variables 
        __recvPacket = b''
        __isValidResponse = False
        __icmpIdentifier_isValid = False
        __icmpSequenceNumber_isValid = False
        __icmpData_isValid = False
        __icmpType_isValid = False
        __icmpCode_isValid = False
        __icmpHeaderChecksum_isValid = False

        # IcmpPacket_EchoReply Constructors                                                                            #
        def __init__(self, recvPacket):
            self.__recvPacket = recvPacket

        # IcmpPacket_EchoReply Getters                                                                                 #
        def getIcmpType(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[20:20 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 20)

        def getIcmpCode(self):
            # Method 1
            # bytes = struct.calcsize("B")        # Format code B is 1 byte
            # return struct.unpack("!B", self.__recvPacket[21:21 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("B", 21)

        def getIcmpHeaderChecksum(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[22:22 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 22)

        def getIcmpIdentifier(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[24:24 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 24)

        def getIcmpSequenceNumber(self):
            # Method 1
            # bytes = struct.calcsize("H")        # Format code H is 2 bytes
            # return struct.unpack("!H", self.__recvPacket[26:26 + bytes])[0]

            # Method 2
            return self.__unpackByFormatAndPosition("H", 26)

        def getDateTimeSent(self):
            # This accounts for bytes 28 through 35 = 64 bits
            return self.__unpackByFormatAndPosition("d", 28)   # Used to track overall round trip time
                                                               # time.time() creates a 64 bit value of 8 bytes

        def getIcmpData(self):
            # This accounts for bytes 36 to the end of the packet.
            return self.__recvPacket[36:].decode('utf-8')

        def isValidResponse(self):
            return self.__isValidResponse

        def getIcmpIdentifier_isValid(self):
            return self.__icmpIdentifier_isValid

        def getIcmpSequenceNumber_isValid(self):
            return self.__icmpSequenceNumber_isValid

        def getIcmpData_isValid(self):
            return self.__icmpData_isValid

        def getIcmpType_isValid(self):
            return self.__icmpType_isValid

        def getIcmpCode_isValid(self):
            return self.__icmpCode_isValid

        def getIcmpHeaderChecksum_isValid(self):
            return self.__icmpHeaderChecksum_isValid

        # IcmpPacket_EchoReply Setters                                                                                 #
        
        def setIsValidResponse(self, booleanValue):
            self.__isValidResponse = booleanValue

        def setIcmpIdentifier_isValid(self, booleanValue):
            self.__icmpIdentifier_isValid = booleanValue

        def setIcmpSequenceNumber_isValid(self, booleanValue):
            self.__icmpSequenceNumber_isValid = booleanValue

        def setIcmpData_isValid(self, booleanValue):
            self.__icmpData_isValid = booleanValue

        def setIcmpType_isValid(self, booleanValue):
            self.__icmpType_isValid = booleanValue

        def setIcmpCode_isValid(self, booleanValue):
            self.__icmpCode_isValid = booleanValue

        def setIcmpHeaderChecksum_isValid(self, booleanValue):
            self.__icmpHeaderChecksum_isValid = booleanValue

        # IcmpPacket_EchoReply Private Functions                                                                       #
        def __unpackByFormatAndPosition(self, formatCode, basePosition):
            numberOfbytes = struct.calcsize(formatCode)
            return struct.unpack("!" + formatCode, self.__recvPacket[basePosition:basePosition + numberOfbytes])[0]

        # IcmpPacket_EchoReply Public Functions                                                                        #
        def printResultToConsole(self, ttl, timeReceived, addr):
            bytes = struct.calcsize("d")
            timeSent = struct.unpack("d", self.__recvPacket[28:28 + bytes])[0]
            rtt = (timeReceived - timeSent) * 1000
            
            # Get ICMP code description
            helperLibrary = IcmpHelperLibrary()
            codeDescription = helperLibrary._IcmpHelperLibrary__getIcmpCodeDescription(self.getIcmpType(), self.getIcmpCode())
            
            # Determine validation status
            validationStatus = "[VALID]" if self.isValidResponse() else "[INVALID]"
            
            # Print basic information with validation status and description
            print("  TTL=%d    RTT=%.0f ms    Type=%d    Code=%d    %s    Identifier=%d    Sequence Number=%d    %s    %s" %
                  (
                      ttl,
                      rtt,
                      self.getIcmpType(),
                      self.getIcmpCode(),
                      codeDescription,
                      self.getIcmpIdentifier(),
                      self.getIcmpSequenceNumber(),
                      addr[0],
                      validationStatus
                  )
                 )
            
            # If invalid, show detailed validation information
            if not self.isValidResponse():
                print("    Validation Details - ID Valid: %s, Seq Valid: %s, Data Valid: %s, Type Valid: %s, Code Valid: %s" %
                     (
                         self.getIcmpIdentifier_isValid(),
                         self.getIcmpSequenceNumber_isValid(),
                         self.getIcmpData_isValid(),
                         self.getIcmpType_isValid(),
                         self.getIcmpCode_isValid()
                     )
                     )
            
            return rtt  # Return RTT for statistics calculation

    # Class IcmpHelperLibrary                                                                                          #



    # IcmpHelperLibrary Class Scope Variables                                                                          #
    __DEBUG_IcmpHelperLibrary = False                  # Allows for debug output
    
    # ICMP Type and Code lookup dictionary for human-readable messages
    __ICMP_CODES = {
        0: {  # Echo Reply
            0: "Echo Reply"
        },
        3: {  # Destination Unreachable
            0: "Network Unreachable",
            1: "Host Unreachable",
            2: "Protocol Unreachable",
            3: "Port Unreachable",
            4: "Fragmentation needed but DF bit set",
            5: "Source route failed",
            6: "Destination network unknown",
            7: "Destination host unknown",
            8: "Source host isolated",
            9: "Destination network administratively prohibited",
            10: "Destination host administratively prohibited",
            11: "Network unreachable for TOS",
            12: "Host unreachable for TOS",
            13: "Communication administratively prohibited",
            14: "Host precedence violation",
            15: "Precedence cutoff in effect"
        },
        8: {  # Echo Request
            0: "Echo Request"
        },
        11: {  # Time Exceeded
            0: "Time to Live exceeded in transit",
            1: "Fragment reassembly time exceeded"
        }
    }

    # IcmpHelperLibrary Private Functions                                                                              #

    def __getIcmpCodeDescription(self, icmpType, icmpCode):
        if icmpType in self.__ICMP_CODES:
            if icmpCode in self.__ICMP_CODES[icmpType]:
                return self.__ICMP_CODES[icmpType][icmpCode]
            else:
                return f"Unknown Code {icmpCode} for Type {icmpType}"
        else:
            return f"Unknown ICMP Type {icmpType}, Code {icmpCode}"
    def __sendIcmpEchoRequest(self, host):
        print("sendIcmpEchoRequest Started...") if self.__DEBUG_IcmpHelperLibrary else 0

        # Statistics tracking
        packetsSent = 0
        packetsReceived = 0
        rtts = []
        
        print(f"PING {host} ({gethostbyname(host)})")
        print()

        for i in range(4):
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()

            randomIdentifier = (os.getpid() & 0xffff)      # Get as 16 bit number - Limit based on ICMP header standards
                                                           # Some PIDs are larger than 16 bit

            packetIdentifier = randomIdentifier
            packetSequenceNumber = i

            icmpPacket.buildPacket_echoRequest(packetIdentifier, packetSequenceNumber)  # Build ICMP for IP payload
            icmpPacket.setIcmpTarget(host)
            
            packetsSent += 1
            response = icmpPacket.sendEchoRequest()  # Build IP
            
            if response is not None:
                packetsReceived += 1
                if isinstance(response, dict):
                    rtts.append(response['rtt'])
                else:
                    rtts.append(response)

            icmpPacket.printIcmpPacketHeader_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            icmpPacket.printIcmpPacket_hex() if self.__DEBUG_IcmpHelperLibrary else 0
            # we should be confirming values are correct, such as identifier and sequence number and data
        
        # Print statistics
        print()
        print("--- Ping Statistics ---")
        print(f"Packets: Sent = {packetsSent}, Received = {packetsReceived}, Lost = {packetsSent - packetsReceived} ({((packetsSent - packetsReceived) / packetsSent * 100):.1f}% loss)")
        
        if rtts:
            minRtt = min(rtts)
            maxRtt = max(rtts)
            avgRtt = sum(rtts) / len(rtts)
            print(f"Round-trip times: Minimum = {minRtt:.0f}ms, Maximum = {maxRtt:.0f}ms, Average = {avgRtt:.0f}ms")
        else:
            print("No successful round-trip times recorded")

    def __sendIcmpTraceRoute(self, host):
        print("sendIcmpTraceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        
        print(f"TRACEROUTE to {host} ({gethostbyname(host)})")
        print()
        
        consecutiveTimeouts = 0
        ttl = 1
        
        while True:
            # Build packet
            icmpPacket = IcmpHelperLibrary.IcmpPacket()
            
            randomIdentifier = (os.getpid() & 0xffff)
            packetSequenceNumber = ttl  # Simple sequence number
            
            icmpPacket.buildPacket_echoRequest(randomIdentifier, packetSequenceNumber)
            icmpPacket.setIcmpTarget(host)
            icmpPacket.setTtl(ttl)  # Set TTL for this hop
            
            # Use the updated sendEchoRequest method
            response = icmpPacket.sendEchoRequest()
            
            if response:
                consecutiveTimeouts = 0  # Reset timeout counter
                
                # Handle different response types
                if isinstance(response, dict):
                    # TTL Exceeded (Type 11) or Destination Unreachable (Type 3)
                    print(f"Hop {ttl}:")
                    
                    # Check if we reached the destination (got Echo Reply)
                    if response['icmpType'] == 0:
                        print(f"Reached destination {host}")
                        break
                else:
                    # Echo Reply (RTT value returned) - we reached the destination
                    print(f"Hop {ttl}:   Reached destination with RTT={response:.0f} ms")
                    print(f"Reached destination {host}")
                    break
            else:
                consecutiveTimeouts += 1
                print(f"Hop {ttl}:   *    *    *    Request timed out")
            
            # Only stop if we have too many consecutive timeouts (10 in a row)
            if consecutiveTimeouts >= 10:
                print("Too many consecutive timeouts, stopping traceroute")
                break
                
            ttl += 1
    
    def __sendTracerouteProbe(self, icmpPacket, timeout):
        mySocket = None
        try:
            destinationIp = gethostbyname(icmpPacket.getIcmpTarget().strip())
            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.settimeout(timeout / 1000.0)  # Convert to seconds
            mySocket.bind(("", 0))
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', icmpPacket.getTtl()))
            
            # Send the packet (use the existing packet structure)
            pingStartTime = time.time()
            
            # Ensure the packet is properly built before accessing private members
            if not hasattr(icmpPacket, '_IcmpPacket__header') or not hasattr(icmpPacket, '_IcmpPacket__data'):
                # Rebuild the packet if not properly built
                icmpPacket._IcmpPacket__packAndRecalculateChecksum()
            
            # Get the properly built packet from the icmpPacket object
            packetData = icmpPacket._IcmpPacket__header + icmpPacket._IcmpPacket__data
            
            mySocket.sendto(packetData, (destinationIp, 0))
            
            # Wait for response
            startedSelect = time.time()
            whatReady = select.select([mySocket], [], [], timeout / 1000.0)
            endSelect = time.time()
            
            if whatReady[0] == []:  # Timeout
                return None
                
            recvPacket, addr = mySocket.recvfrom(1024)
            timeReceived = time.time()
            rtt = (timeReceived - pingStartTime) * 1000
            
            # Parse ICMP response
            icmpType, icmpCode = recvPacket[20:22]
            
            return {
                'addr': addr[0],
                'rtt': rtt,
                'icmpType': icmpType,
                'icmpCode': icmpCode,
                'description': self.__getIcmpCodeDescription(icmpType, icmpCode)
            }
            
        except Exception as e:
            print(f"Error in traceroute probe: {e}") if self.__DEBUG_IcmpHelperLibrary else 0
            return None
        finally:
            if mySocket:
                mySocket.close()

    # IcmpHelperLibrary Public Functions                                                                               #

    def sendPing(self, targetHost):
        print("ping Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpEchoRequest(targetHost)

    def traceRoute(self, targetHost):
        print("traceRoute Started...") if self.__DEBUG_IcmpHelperLibrary else 0
        self.__sendIcmpTraceRoute(targetHost)


# #################################################################################################################### #
# main()                                                                                                               #
def main():
    icmpHelperPing = IcmpHelperLibrary()
    
    # Test ping functionality
    print("=== PING TEST ===")
    icmpHelperPing.sendPing("8.8.8.8")  # Google DNS
    
    print("=== ADDITIONAL PING TESTS ===")
    icmpHelperPing.sendPing("www.google.com")
    icmpHelperPing.sendPing("gaia.cs.umass.edu")
    
    # Test traceroute functionality
    print("=== TRACEROUTE TEST ===")
    icmpHelperPing.traceRoute("www.google.com")  # Google
    
    print("=== INTERNATIONAL TRACEROUTE TESTS ===")
    icmpHelperPing.traceRoute("www.bbc.co.uk")    # Europe
    icmpHelperPing.traceRoute("www.ntt.co.jp")    # Japan
    
    print("=== TYPE 3 ERROR TESTING ===")
    # These addresses should hopefully generate someType 3 responses (got rid of those that dont)
    type3_targets = [
    "169.254.1.1"         # Link-local address
    ]

    for target in type3_targets:
        print(f"\nTesting {target}:")
        icmpHelperPing.sendPing(target)


if __name__ == "__main__":
    main()
