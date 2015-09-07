The scripts for CCS2015 paper "Seeing through Network Protocol Obfuscation"

Dependencies
----------------
Install Tor Stem and Selenium driver
```
sudo pip install stem selenium 
```
Install scikit-learn
```
sudo apt-get install build-essential python-dev python-setuptools \
                     python-numpy python-scipy \
                     libatlas-dev libatlas3gf-base
sudo pip install -U numpy scipy scikit-learn
```

Use the framework to collect Tor traces 
----------------
1. Download the source code of the newest Tor Browser Bundle 
from https://www.torproject.org/projects/torbrowser.html.en, and 
unzip it. 
2. Download the Alexa Top 1M domain list from http://s3.amazonaws.com/alexa-static/top-1m.csv.zip, 
or create your own file that contains target domains. The format of the file must be "unique_id, domain_name".   
3. Put tor_trace_collection.py and   
