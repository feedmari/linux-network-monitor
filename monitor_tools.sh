#!/bin/bash -       
#title           : monitor_tools.sh
#description     : This program is a wrapper for a different scripts that are used to monitor the entire network
#author		 	 : Federico Marinelli
#notes           : Setup: use ./install_dependencies.sh 
#bash_version    : 4.1.5(1)-release
#==============================================================================

echo "   _____                .__  __                 ___________           .__     "     
echo "  /     \   ____   ____ |__|/  |_  ___________  \__    ___/___   ____ |  |   ______"
echo " /  \ /  \ /  _ \ /    \|  \   __\/  _ \_  __ \   |    | /  _ \ /  _ \|  |  /  ___/"
echo "/    Y    (  <_> )   |  \  ||  | (  <_> )  | \/   |    |(  <_> |  <_> )  |__\___ \ "
echo "\____|__  /\____/|___|  /__||__|  \____/|__|      |____| \____/ \____/|____/____  >"
echo "        \/            \/                                                        \/ "


PS3='Please enter your choice: '
options=("INCOMING PACKETS PER SECOND" \
            "NETWORK SPEED" \
			"PACKETS BY IP (WITH FLAGS)" \
            "TCPDUMP"  \
            "PACKETS INSPECTION [MAC - IP - PROTOCOL]" \
            "MONITOR CONNECTIONS PORT 80 NGREP" \
            "MONITOR UNIQUE CONNECTIONS PORT 80"\
            "NUMBER OF PACKETS BY PROTOCOL [TCP-UDP-ICMP]" \
            "PACKETS INSPECTION NGREP" \
            "CHECK ICMP's" \
            "ACTIVITY ON SPECIFIC PORT" \
            "ACTIVITY BY SPECIFIC SOURCE IP" \
            "CHECK FOR ERRORS [all interfaces]"\
            "SHOW PACKETS IN HEX" \
            "SHOW OPEN CONNECTIONS"\
            "RUN VNSTAT"\
            "RUN NMON"\
            "NGINX LOG")
echo ""
echo ""
echo "These are the available interfaces: "
ip r show|grep " src "|cut -d " " -f 3,12
echo ""
echo "Type the  interface, followed by [ENTER]:"
read interface

select opt in "${options[@]}"
do
    case $opt in
        "INCOMING PACKETS PER SECOND")
            echo " [MODE] INCOMING PACKETS PER SECOND"
            ./scripts/netpps.sh $interface
            ;;
        "NETWORK SPEED")
            echo " [MODE] NETWORK SPEED"
            ./scripts/netspeed.sh $interface
            ;;
        "TCPDUMP")
            echo " [MODE] TCPDUMP"
            sudo tcpdump -nn -i $interface
            ;;
        "PACKETS INSPECTION [MAC - IP - PROTOCOL]")
            echo " [MODE] PACKETS INSPECTION"
            sudo ./scripts/packet_monitoring.py $interface
            ;;
        "MONITOR CONNECTIONS PORT 80 NGREP")
            echo " [MODE] CONNECTIONS PORT 80"
            sudo ngrep -q '^GET .* HTTP/1.[01]' 'port 80' -d $interface
            ;;
        "MONITOR UNIQUE CONNECTIONS PORT 80")
            echo " [MODE] unique IPs making new connections with SYN set"
            echo "Type the  interval for printing stats, followed by [ENTER]:"
            read inval
            sudo ./scripts/connection_monitor.py -i $interface -n $inval -I
            ;;
        "NUMBER OF PACKETS BY PROTOCOL [TCP-UDP-ICMP]")
            echo "Type the  interval for printing stats, followed by [ENTER]:"
            read inval
            sudo ./scripts/monitor_connections.py -i $interface -n $inval -M proto_type -a ALL_PORTS
            ;;
        "PACKETS INSPECTION NGREP")
            echo " [MODE] PACKETS INSPECTION NGREP"
            sudo ngrep -W byline port 80 -d $interface
            ;;
        "CHECK ICMP's")
            echo " [MODE] CHECK FOR ICMP packets"
            sudo ngrep -q '.' 'icmp' -d $interface
            ;;
        "ACTIVITY ON SPECIFIC PORT")
            echo " [MODE] ACVITITY ON A SPECIFIC PORT"
            echo "Type the  PORT, followed by [ENTER]:"
            read port
            sudo ngrep port $port -d $interface
            ;;
        "CHECK FOR ERRORS [all interfaces]")
            echo " [MODE] SEACHING FOR ERRORS IN THE PACKETS"
            sudo ngrep -d any 'error' port syslog
            ;;
        "ACTIVITY BY SPECIFIC SOURCE IP")
            echo " [MODE] ACTIVITY BY IP"
            echo "Type the  IP, followed by [ENTER]:"
            read IP
            sudo tcpdump -i $interface src $IP
            ;;
        "SHOW PACKETS IN HEX")
            echo " [MODE] SHOW PACKETS IN HEX"
            sudo tcpdump -XX -i $interface
            ;;
        "SHOW OPEN CONNECTIONS")
            echo " [MODE] SHOW OPEN CONNECTIONS"
            ./scripts/c_ip.sh
            ;;
        "RUN VNSTAT")
            echo " [MODE] RUN VNSTAT"
            sudo vnstat -l
            ;;
        "RUN NMON")
            echo " [MODE] NMON"
            sudo nmon
            ;;
        "NGINX LOG")
            sudo tail -f /var/log/nginx/access.log 
            ;;
        "PACKETS BY IP (WITH FLAGS)")
            echo "type the interval"
            read inval
            sudo ./scripts/monitor_connections.py -i $interface -n $inval -M ppip -a ALL_PORTS
            ;;
        "Quit")
            break
            ;;
        *) echo invalid option;;
    esac
done
