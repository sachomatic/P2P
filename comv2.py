import socket
import zmq

MCAST_GRP = ""
MCAST_PORT = 5007

def send():
    context = zmq.Context()
    socket = context.socket(zmq.REQ)
    socket.connect("tcp://192.168.1.254:5555")

    socket.send(b"Hello")
    message = socket.recv()
    print(f"Received reply: {message}")

def recv():
    context = zmq.Context()
    socket = context.socket(zmq.REP)
    socket.bind("tcp://*:5555")

    while True:
        message = socket.recv()
        print(f"Received request: {message}")
        socket.send(b"World")

choice = input("Receive or Send (R/S) : ")
if choice.upper() == "R":
    recv()
elif choice.upper() == "S":
    send()