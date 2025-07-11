# my intrepretation of the goals for the http server section of the lab are as follows
# 1. listen on localhost and port > 1023 (midigates any issue that may arise as a result of admin priveldges)
# 2. accept a new browser request
# 3. print the RAW http GET request sent from the client
# 4. send back the requested HTML content
# 5. close the connection

# ***I USED THE OFFICIAL PYTHON MANUAL AND WATCHED some youtube videos on the topics if I was still a bit confuesed *** -> ontop of textbook examples and notes that were provided

import socket

#bind to the localhost to listen for TCP connections only from my computer
HOST = "127.0.0.1"
PORT = 8080

# AF_INET -> IPv4, SOCK_STREAM -> TCP CONNECTION 
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#bind the created socket to my IP address and the chosen port
server_socket.bind((HOST, PORT))

# backlog = 1 -> a maximum of 1 queued connection which is enough for this lab
server_socket.listen(1)
print(f"Server is listening on: http://{HOST}:{PORT}")
 
#sits and waits for the TCP connection to be made from my local browser. 
#once the accept() clause finishes and the connection has been made, the server returns 2 things
# client_socket = a new TCP connection for communicating only with the localhost (this is how multiple TCP conncetion can be made to a server simutaneuously)
# client_address = the IP address and port number of the client (my browser)
client_socket, client_address = server_socket.accept()
print(f"Accepted a conncetion from {client_address}")

# read the bytes request from the client (my browser) 
request_data = client_socket.recv(1024)
print("\n-----Request Recieved-----")
#decode the bytes request that the browser made and print to the terminal (browser does not see this, only the terminal does)
print(request_data.decode(errors = 'replace'))

# the send function of the socket library requires that the information being sent is in bytes
# because of this rencode the data and then send it back to the client to display

response = (
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: text/html; charset=UTF-8\r\n\r\n"
    "<html>Congratulations! You've downloaded the first Wireshark lab file!</html>\r\n"
)

client_socket.send(response.encode())

#close the client socket first and then the server socket
client_socket.close()
server_socket.close()

print("The server has shutdown after handling the request from localhost")



