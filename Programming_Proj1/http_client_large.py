# the change that is made in this version of the http client is:
# - still connects to a web server using a raw TCP socket and sending a GET request for a LARGE file
# - because of how TCP is a streaming protocol, it does not know where one HTTP request begins and the next ends
# - TCP delievers a continuous stream of information in the form of bytes -> broken into packets
# - recv(4096) reads max 4096 bytes of information, or however many bytes are available at the time of the transmission 
# - there is no 'End of File' flag, the TCP connections continues to read information until the recv() return b'' -> an empty byte string

# because of this, for handling files of large sizes we must loop recv() until an empty byte string is returned, in which case we can safely assume that this is the end of the transmission. 

import socket

# same setup/formatting as the previous http client example
host = "gaia.cs.umass.edu"
port = 80

path = f"/wireshark-labs/HTTP-wireshark-file3.html"
request = f"GET {path} HTTP/1.1\r\nHost:{host}\r\n\r\n"

print(f"Request: {request}")

# create the same TCP socket setup
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


#connect to the created socket
sock.connect((host, port))

#send the HTTP GET request to the server, send method expects bytes so the string must be encoded
sock.send(request.encode())

#unlike the first simple http client, this version uses a loop to handle file sizes that are arbitrarely large
#does not guarantee all of the data transmission in a singular call, TCP is stream based ans so you must loop until the server closes the connection

raw_response = b'' #empty string of bytes that is used to accumulate the chunks of data

while True:
    data = sock.recv(4096)
    if not data:
        #if 'data' is empty the server has closed the connection meaning that we have recieved the entirety of the file
        break
    
    raw_response += data #append each chunk of data the the accumulator raw_response

# once the transmission has finished -> decode all of the raw byte data at once
decoded_response = raw_response.decode(errors = 'replace')

#display the decoded data and close the socket connection

print("-----Server's Response-----\n")
print(decoded_response)

sock.close()
