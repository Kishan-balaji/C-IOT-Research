import socket
import nmap
import pymongo
import socket

mongo_connection_string = "mongodb://localhost:27017"
database_name = "IOT"
collection_name = "wii"
client = pymongo.MongoClient(mongo_connection_string)
db = client[database_name]
collection = db[collection_name]



def get_all_mongo_ips():
    ips = []
    data = list(collection.find({}, {'_id': 0}))
    for entry in data:
        ip = entry.get('IP:')
        if ip:
            ips.append(ip)
    return ips 

def wifi_scan(): 
    hosts_list=[]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        nm2 = nmap.PortScanner()
        subnet = local_ip + '/24'
        try:
            nm2.scan(subnet, arguments='-sn')
        
            for x in nm2.all_hosts():
                hosts_list.append(x)
        except:
            print('no element list',flush=True)

        return hosts_list
    except:
        return None
        
    # (Previous wifi_scan() function remains the same)

def get(ip):
    nm=nmap.PortScanner()
    # udp_ports = []
    # tcp_ports = []
    device={}
    mal="0"
    try:
        nm.scan(ip, arguments='-O')
    except:
        print(f"coudld'nt connect to {ip}",flush=True)
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname==ip:
            hostname="None"
    except:
        hostname="None"
    try:
        mac=nm[ip]['addresses']['mac']
    except:
        mac="None"
    try:
        os=nm[ip]['osmatch'][0]['name']
    except:
        os="None"
    try:
        status=nm[ip]['status']['state']
    except:
        status="None"
    try:
        protocol=nm[ip]['portused'][0]['proto']
    except:
        return "None"
    try:
        manufacturer=list(nm[ip]['vendor'].keys())[0]
    except:
        manufacturer="None"
    try:
        manufacturer_ip=list(nm[ip]['vendor'].values())[0]
    except:
        manufacturer_ip="None"
    try:
        nm.scan(ip, arguments='-sSU -T5')

        open_ports = {'udp': [], 'tcp': []}
        if ip in nm.all_hosts():
            for proto in ['udp', 'tcp']:
                if proto in nm[ip]:
                    for port, port_info in nm[ip][proto].items():
                        if port_info['state'] == 'open':
                            open_ports[proto].append({
                                'port': port,
                                'service': port_info['name'],
                                'protocol': proto.upper()
                            })
    except:
        open_ports=[]
            
    try:
        device={
                'IP:':ip,
                'Hostname:':hostname,
                'mac Address:':mac,
                'Os:':os,
                'Status:':status,
                'Protocol:':protocol,
                'Manufacturer Name:':manufacturer,
                'Manufacturer ip:':manufacturer_ip,
                'udp/tcp open ports:': open_ports,
                # 'tcp open ports:':tcp_ports,
                'Malicious:':mal
                }
    except:
        return device
    return device
  
def store_in_mongodb(documents):
    
    try:
        
        
        collection.insert_many(documents)
        print("Data stored in MongoDB successfully.",flush=True)
    except:
        print(f"Error storing data in MongoDB",flush=True)
    finally:
        client.close()

def func1():
    iplist = wifi_scan()
    mongo_ip=get_all_mongo_ips()
    print(iplist,flush=True)
    if iplist is not None:
        devices = []
        for ip in iplist:
            if ip in mongo_ip:
                continue
            else:
                try:
                    device_data = get(ip)
                    print(device_data,flush=True)
                    devices.append(device_data)
                    store_in_mongodb([device_data])
                except:
                    print(f"No data found for IP: {ip}",flush=True)

                
            return devices
        else:
            print("WiFi scan failed.",flush=True)
            
            return []
if __name__ == "__main__":
    # mongo_connection_string = "mongodb://localhost:27017"
    # database_name = "IOT"
    # collection_name = "wii"
    # client = pymongo.MongoClient(mongo_connection_string)
    # db = client[database_name]
    # collection = db[collection_name]
    func1()
    client.close()
