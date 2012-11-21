import socket
import sys
import time

HOST, PORT = "localhost", 9000

def get_netflow(addr):
  data = "show %s %s -1 1000" % (addr, (long(time.time()) - 3600) )

  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

  sock.connect( (HOST,PORT) )
  sock.send(data+"\n")

  recv = sock.recv(1024)
  print recv
  sock.close()
