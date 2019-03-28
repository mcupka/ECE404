#Homework Number: 9
#Name: Michael Cupka
#ECN Login: mcupka
#Due Date: 3/28/19

#delete all previous rules or chains
sudo iptables -t filter -F
sudo iptables -t filter -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X
sudo iptables -t nat    -F
sudo iptables -t nat    -X
sudo iptables -t raw    -F
sudo iptables -t raw    -X

#change outgoing packet ip to my ip address. My device is wlp2s0 for wifi
sudo iptables -t nat -A POSTROUTING -o wlp2s0 -j MASQUERADE


#Block incoming connections from certain IP addresses
sudo iptables -A INPUT -s 10.10.10.10 -j DROP
sudo iptables -A INPUT -s 192.168.1.5 -j DROP
sudo iptables -A INPUT -s 15.16.17.18 -j DROP
sudo iptables -A INPUT -s 33.65.101.51 -j DROP

#prevent anyone pinging my laptop
sudo iptables -A INPUT  -p icmp --icmp-type echo-request -j DROP

#set up port forwarding
sudo iptables -A INPUT -p tcp -i wlp2s0 --dport 10001 -j ACCEPT
sudo iptables -t nat -A PREROUTING -p tcp -i wlp2s0 --dport 10001 -j REDIRECT --to-port 22

#Allow ssh access from engineering.purdue.edu only
sudo iptables -A INPUT -p tcp --destination-port 22 -s engineering.purdue.edu -j ACCEPT
sudo iptables -A INPUT -p tcp --destination-port 22 -j REJECT

#allow only a single IP address to access the HTTP service on my machine (only 10.10.10.15)
sudo iptables -A INPUT -i wlp2s0 -p tcp -s 10.10.10.15 --dport 80 --syn -j ACCEPT
sudo iptables -A INPUT -i wlp2s0 -p tcp --dport 80 -j REJECT

#permit auth/ident on port 113
sudo iptables -A INPUT -i wlp2s0 -p tcp --dport 113 -j ACCEPT


