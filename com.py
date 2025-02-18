import asyncio
import websockets
from websockets.asyncio.server import serve
import time
import os, colorama
from pynput.keyboard import Controller, Key
keyboard = Controller()
import socket
from scapy.all import ARP, Ether, srp
import ipaddress
from multiprocessing import Pool, Manager, Value
import sys, pandas as pd
PATH = os.path.abspath(__file__)

def store_ip(ip):
    with open("Coomunication/ip.csv","a+") as file:
        file.seek(0)
        content = file.read()
        ips = content.split(";")
        print(ips)
        if ip not in ips:            
                file.write(ip+";")

def read_ips():
    with open("Coomunication/ip.csv","r") as file:
        content = file.read()
        ips = content.split(";")
        del ips[-1]
    return ips

def log(message):
    print(message)
    with open("Coomunication/log.txt","a") as file:
        file.write(f"\n{message}")
    return message

async def handle_client(websocket):
    global restart
    import time
    log(f"Client connected on {get_local_ip()}")

    async def send_pings():
        """Send a ping every 30 seconds to keep the connection alive."""
        while True:
            try:
                await websocket.ping()
                await asyncio.sleep(5)  # Adjust the interval as needed
            except websockets.ConnectionClosed:
                break

    log("Starting keep alive task")
    asyncio.create_task(send_pings())

    try:
        async for message in websocket:  # Loop to handle multiple messages
            log(f"Client: {message}")

            match message:
                case "sleep":
                    response = log("Turning off...")
                case "wakeup":
                    response = log("Waking up...")
                case "stop":
                    await websocket.send("Stopping server...")
                    log("Exiting...")
                    quit()
                case "hour_test":
                        response = log(str(time.time()))
                case "restart":
                    os.system("cls") 
                    await websocket.send("Restarting")
                    restart.set()
                    try:
                        await asyncio.get_event_loop().stop()
                    except:
                        pass
                case _:
                    response = f"Unknown command : {message}"
            
            await websocket.send(response)
            log(f"Server: {response}")

    except websockets.ConnectionClosed:
        log("Client disconnected")

async def test(websocket):
    import time
    dep = time.time()
    await websocket.send("hour_test")
    try:
        rep = await asyncio.wait_for(websocket.recv(), timeout=0.5)
        ping = (float(rep) - dep) / 1000
        output = f"{ping:.6f} ms of ping"
        return output
    except asyncio.TimeoutError:
        return "None ; TimeOut"

async def send_message(ip,port):
    os.system("cls")
    try:
        server_ip = ip
        server_port = port

        color = colorama.Back.WHITE + colorama.Fore.BLACK
        
        uri = f"ws://{server_ip}:{server_port}"
        input_message = ""
        must_restart = False
        async with websockets.connect(uri) as websocket:
            print(f"Connected to {uri}")
            #Test server response time
            print("Server has ",await test(websocket))
            while True:
                #To allow for keep alive task in the background
                message = await asyncio.to_thread(input, input_message)

                match message:
                    case "clear":
                        os.system("cls")
                        print(f"Connected to {uri}")
                        print("Server has ",await test(websocket))
                    case "restart":
                        must_restart = True
                    case "exit":
                        return "stop"

                # Send the message to the server
                await websocket.send(message)
                
                # Wait for the server's response
                try:
                    #Allow to receive mutliple messages from server
                    while True:
                        response = await asyncio.wait_for(websocket.recv(), timeout=1)
                        print(color + response + colorama.Style.RESET_ALL)
                except asyncio.TimeoutError:
                    if must_restart == True:
                        return 'restart'
                except asyncio.IncompleteReadError:
                    print("Incomplete read, connection might be closed")
                    return
                except websockets.exceptions.ConnectionClosedError:
                    print("Connection closed")
                    if must_restart == True:
                        return 'restart'
                    return 'stop'
    except Exception as error:
        print("Error : ",error)

def get_local_ip():
    # Create a temporary socket to connect to an external server
    # This will allow us to retrieve the correct local IP used for communication
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            # Connect to an external IP (Google's public DNS server)
            s.connect(("8.8.8.8", 80))
            ip_address = s.getsockname()[0]
        except Exception as e:
            print(f"Error retrieving local IP: {e}")
            ip_address = None
    return ip_address

def scan_network()->list:
    print("Searching for connection")
    ip_address = get_local_ip()

    network = ipaddress.IPv4Network(ip_address + '/24', strict=False)
    ip_range = str(network)
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=5, verbose=0)[0]
    
    # List to store the connected devices
    devices = []
    for sent, received in result:
        devices.append(received.psrc)
    return devices

def port_scanner(port_range,waiting_list,queue,lock):
    with lock:
        if len(waiting_list) == 0:
            return
        ip = waiting_list.pop(0)
        print(f"Scanning {ip}   ",end="\r")
    for port in range(*port_range):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            result = sock.connect_ex((ip, port))
            if result == 10061:
                print(f"Connection refused on {ip}:{port} (WSAECONNREFUSED).")
            elif result == 10049:
                print(f"Address not available: {ip}:{port} (WSAEADDRNOTAVAIL).")
            elif result == 10035:
                pass
            elif result == 0:
                print(f"Success on {ip}:{port}")
                queue.put((ip,port))
                return
            else:
                print(f"Error code: {result} on {ip}:{port}.")
        except socket.gaierror:
            print(f"Invalid Ip adress : {ip}")
        finally:
            sock.close()

def scan_ports(ip:list, port_range):
    with Manager() as manager:
        open_ports = []
        ips =  manager.list(ip)
        queue = manager.Queue(len(ip))
        lock = manager.Lock()
        args = [(port_range, ips, queue, lock)]*len(ips)
        print(f"Scanning {len(ips)} IPs")
        with Pool(processes=len(ip)) as pool:
            pool.starmap(port_scanner,args)
            while not queue.empty():
                ip_,port = queue.get()
                open_ports.append((ip_,port))
    return open_ports

async def Client():
    try:
        devices = scan_network()
    except RuntimeError:
        print("You need to install Winpcap (https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe) or Npcap (https://npcap.com/dist/npcap-1.80.exe)")
        quit()
    if len(devices) == 0:
        print("Returned no results : no machines found")
        return
    machines = {}
    for ip in read_ips():
        if ip not in devices:
            devices.append(ip)
    ports = scan_ports(devices,(8080, 8090))
    if ports != []:
        for port in ports:
            machines[port[0]] = port[1]
    else:
        print("No devices available at the moment.")
        return    

    for index, mach in enumerate(machines.keys()):
        try:
            print(index,": ",socket.gethostbyaddr(mach)[0])
        except socket.herror:
            machines.pop(index)
            pass
    sel = input("Select : ")
    try:
        sel = int(sel)
    except:
        print("Invalid choice")
        return
    store_ip(list(machines.keys())[sel])
    result = None
    try:
        while result != "stop" or result == "restart":
            result = await send_message(list(machines.keys())[sel],list(machines.items())[sel][1])
    except Exception as error:
        print("Error : ",error)

async def Server():
    global restart
    try:
        restart = asyncio.Event()
        serv = await websockets.serve(handle_client, get_local_ip(), 8085)
        await serv.wait_closed()
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 1:
        a = sys.argv[1]
    else:
        a= input("Launch Server or Client : ").upper()
    if a == "S":
        log("------------------New session------------------\nLaunching server")
        try:
            asyncio.run(Server())
        except RuntimeError:
            if restart.is_set():
                log("Relaunching")
                os.system(f"python {PATH} S")
                quit()
            else:
                log("Fatal error")
        except SystemExit:
            log("Stopping server...")
            quit()
    elif a == "C":
        asyncio.run(Client())