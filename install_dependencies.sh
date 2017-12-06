#!/bin/bash -       
#title           : intall_dependecies.sh
#description     : Install all the dependencies for the monito_tools.sh
#author		 	 : Federico Marinelli
#bash_version    : 4.1.5(1)-release
#==============================================================================

sudo apt-get install python-pcapy -y
sudo apt-get install ngrep -y
sudo apt-get install vnstat -y
sudo apt-get install nmon -y
sudo apt-get install bmon -y
sudo apt-get install speedometer -y
