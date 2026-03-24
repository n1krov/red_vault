> Al hacer un reconocimiento de una red ya sea para una empresa pequenia o grande descubrir todas las direcciones IP de la misma es clave. Herramientas como nmap, arp-scan, scripts propios o masscan son alternativas para ello.
### NMAP
```
nmap -sn 192.168.100.1/24
```

### ARP-SCAN
```
arp-scan -I wlp2s0 --localnet --ignoredups
```

### Con un script propio para ICMP
```bash
#!/bin/bash

function ctrl_c(){
	echo -e "\n\n[!] Saliendo..."
	tput cnorm; exit 1
}

tput civis

trap ctrl_c

for i in $(seq 1 254); do
	for port in $(22,80,139,443,445,8080); do
		timeout 1 bash -o "echo '' >  /dev/tcp/192.168.111.$i/$port" && 2>/dev/null && echo -e [+]Host: 192.168.111.$i - Port: $port - [OPEN] &
	done
done

wait

tput cnorm
```

### MASSCAN
```
masscan -p22,80,8080,445,443 -Pn 192.168.111.0/24 --rate=5000
```

## Comandos utilizados
- [[nmap]]
- [[arp-scan]]
- [[masscan]]