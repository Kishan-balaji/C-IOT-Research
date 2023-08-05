import concurrent.futures
import socket,nmap,pymongo

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
        print("check internet connection")
        return None


def get(ip):
    nm=nmap.PortScanner()
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
        open_ports= {'udp': [], 'tcp': []}
            
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
                'Malicious:':mal
                }
    except:
        pass
    
    return device

def get_all_mongo_ips():
    try:
        ips = []
        data = list(collection.find({}, {'_id': 0}))
        for entry in data:
            ip = entry.get('IP:')
            if ip:
                ips.append(ip)
        return ips 
    except:
        print("check mongo connection")
def store_in_mongodb(documents):
    try:
        collection.insert_many(documents)
        print("Data stored in MongoDB successfully.",flush=True)
    except:
        print(f"Error storing data in MongoDB",flush=True)
    

if __name__ == "__main__":
    mongo_connection_string = "mongodb://localhost:27017"
    database_name = "IOT"
    collection_name = "final"
    client = pymongo.MongoClient(mongo_connection_string)
    db = client[database_name]
    collection = db[collection_name]
    iplist=wifi_scan()
    mongo_ip=get_all_mongo_ips()


    with concurrent.futures.ThreadPoolExecutor() as executor:
        if iplist is not None:
            for ip in iplist:
                if ip in mongo_ip:
                    continue
                else:
                    try:
                        f=executor.submit(get,ip)
                        store_in_mongodb([f.result()])
                    except:
                        print('scan failed')