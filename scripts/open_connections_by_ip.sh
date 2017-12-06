#!/bin/bash -       
#title           : connections_by_ip.sh
#description     : This script return the number of connection per IPs connect to the node
#author		 	 : Federico Marinelli
#bash_version    : 4.1.5(1)-release
#==============================================================================

sudo netstat -anp |grep 'tcp\|udp' | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -n
