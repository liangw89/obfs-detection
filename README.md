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
unzip it. The resulting directory should be "path/tor-browser_en-US".
2. Download the Alexa Top 1M domain list from http://s3.amazonaws.com/alexa-static/top-1m.csv.zip, 
or create your own file that contains target domains. The format of the file must be "unique_ID, domain_name". 
The unique IDs should be numeric values.  
3. Follow the instructions in https://github.com/Yawning/obfs4 to build 
obfsproxy4, change the output to obfs4proxy.bin (or obfs4proxy4.exe) and 
put it in the "path/tor-browser_en-US/Browser/TorBrowser/Tor/PluggableTransports/"
4. Put tor_trace_collection.py and conf.py in the "path/tor-browser_en-US/Browser/", and configure the conf.py. 
5. Disable the TorLauncher extension in the TBB.
6. Run "python tor_trace_collection.py -h" to see how to use it. 
7. The pcaps for a given type of PT will be stored at "PCAP_ROOT_DIRECTORY/ROUND_NUMBER/PT_NAME/"

