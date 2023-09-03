
# Network Monitoring
Keeps in check of activities of all the devices connected to a particular network and detects anamolies or suspicious activities in the network


# Installation



```bash
pip install socket,nmap,pymongo,pandas as pd,paho.mqtt.client as mqtt,pickle,sklearn
pip install scikit,scipy
```

## Deployment

To deploy this project run

```bash
python Network_Scan.py
```

Now let the scan finish and store in the database
then run


```bash
streamlit run streamlitz.py
```
To check the anamoly download https://sourceforge.net/projects/loic/ and start flooding packets to an intended IP address present in the network

To detect the anamoly run
```bash
python Detect_Mal.py
```

Remainder the system which is scanning should also be in the same network to monitor things. 
All the pkl and csv files should be added to the path properly if placed in different directories