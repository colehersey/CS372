# the goal of this file is to accomplish the following tasks in order to create a basic and working http client
# 1. create a TCP socket to carry the data that is being transferred
# 2. connects to the provided server 
# 3. sends an HTTP GET request for a particular file that is contained within the server
# 4. recieve the HTTP response from the server and print it to the terminal for the user to view

# ***I USED THE OFFICIAL PYTHON MANUAL AND WATCHED some youtube videos on the topics if I was still a bit confuesed *** -> ontop of textbook examples and notes that were provided



import socket 

#define the host url 
host = "gaia.cs.umass.edu"
port = 80

# the proper HTTP 1.1/GET request (includes the use of line endings and the hosts header).
path = f"/wireshark-labs/INTRO-wireshark-file1.html"
request = f"GET {path} HTTP/1.1\r\nHost:{host}\r\n\r\n"

print(f"Request: {request}")

# creating the TCP socket and connecting to the server
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, port))

#send the http connection request
sock.send(request.encode()) #converts the string object to bytes 

#recieve the servers response (also in bytes of information)
response = sock.recv(4096)

#print the network response as a decoded string 
print("-----Server Response-----\n")
print(response.decode(errors='replace'))

#close the socket connection
sock.close()
 