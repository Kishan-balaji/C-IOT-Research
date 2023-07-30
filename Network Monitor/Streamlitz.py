
# import streamlit as st
# import pymongo
# import pandas as pd
# import time
# from streamlit_custom_notification_box import custom_notification_box as scnb
# import paho.mqtt.client as mqtt

# broker_address = "mqtt.eclipseprojects.io"
# broker_port = 1883  # Default MQTT port
# client1 = mqtt.Client()  
# client1.connect(broker_address, broker_port)
# client1.subscribe("mytopic")
# print('connected')
# client = pymongo.MongoClient("mongodb://localhost:27017/")
# db = client["IOT"]
# collection = db["wii"]

# def AlertBox(wht_msg,ip):
#     styles = {'material-icons':{'color': '#FF0000'},
#             'text-icon-link-close-container': {'box-shadow': '#3896de 0px 4px'},
#             'notification-text': {'':''},
#             'close-button':{'':''},
#             'link':{'':''}}
#   # Replace this with the specific IP address
#     scnb(icon='info', 
#         textDisplay=wht_msg, 
#         externalLink='', 
#         url='#', 
#         styles=styles, 
#         key=f"alert_box_{ip}")

# def get_data():
#     data = list(collection.find({}, {'_id': 0}))
#     unique_data = {}
#     for entry in data:
#         ip = entry['IP:']
#         if ip not in unique_data:
#             unique_data[ip] = entry

#     return unique_data

# def update_malicious(ip):

#     collection.update_one({"IP:": ip}, {'$set': {'Malicious:': "1"}})
#     AlertBox("Test message...",ip)


# def main():
#     st.title('Monitor')
#     table_placeholder = st.empty()
#     while True:
#         data = get_data()
#         df = pd.DataFrame(data).T
#         table_placeholder.table(df)
#         time.sleep(10)
        
# if __name__ == '__main__':
#     main()









import streamlit as st
import pymongo
import pandas as pd
import time
import paho.mqtt.client as mqtt
from streamlit_custom_notification_box import custom_notification_box as scnb

broker_address = "mqtt.eclipseprojects.io"
broker_port = 1883  # Default MQTT port
client1 = mqtt.Client()
client1.connect(broker_address, broker_port)
client1.subscribe("mytopic")
print('connected')

client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["IOT"]
collection = db["wii"]

def AlertBox(wht_msg, ip):
    styles = {'material-icons':{'color': '#FF0000'},
              'text-icon-link-close-container': {'box-shadow': '#3896de 0px 4px'},
              'notification-text': {'':''},
              'close-button':{'':''},
              'link':{'':''}}
    scnb(icon='info', 
         textDisplay=wht_msg, 
         externalLink='', 
         url='#', 
         styles=styles, 
         key=f"alert_box_{ip}")

def get_data():
    data = list(collection.find({}, {'_id': 0}))
    unique_data = {}
    for entry in data:
        ip = entry['IP:']
        if ip not in unique_data:
            unique_data[ip] = entry
    return unique_data

def update_malicious(ip):
    collection.update_one({"IP:": ip}, {'$set': {'Malicious:': "1"}})
    AlertBox(f"IP {ip} marked as malicious.", ip)

def on_message(client, userdata, message):
    msg = message.payload.decode("utf-8")
    print(msg)
    if msg == "1":
        update_malicious('192.168.1.1')

def main():
    st.title('Monitor')
    table_placeholder = st.empty()
    
    # Set the on_message callback
    client1.on_message = on_message
    client1.loop_start()

    while True:
        data = get_data()
        df = pd.DataFrame(data).T
        table_placeholder.table(df)
        time.sleep(10)

if __name__ == '__main__':
    main()
