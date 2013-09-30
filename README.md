PyTriage
========

A python script for easy static analysis and automatic signature generation of malware. Currently it only runs flawlessly in Linux. Some issues are observed on Windows systems.

Dependencies
------------

Requires magic,simplejson and pefile modules in python. Also requires the libdasm library for disassembly.

Installing dependencies
-----------------------

```shell
sudo apt-get install python-magic
sudo pip install simplejson
sudo pip install pefile
wget https://libdasm.googlecode.com/files/libdasm-1.5.tar.gz
tar -zxvf libdasm-1.5.tar.gz
cd libdasm-1.5/
make
sudo make install
cd pydasm
sudo python setup.py install
```

Getting started
---------------

Get a VirusTotal key after signing up at https://www.virustotal.com/en/#signup. Once you have the key replace the API_KEY with the API key you received from VirusTotal.
