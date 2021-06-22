all:
	go build -ldflags "-s -w"  -o wilddns

iptables:
	sudo iptables -t nat -I PREROUTING 1 -p udp -d 8.8.8.8  --dport 53 -j DNAT --to "${IP}"

run:
	cat .envrc
	sudo -E ./wilddns
