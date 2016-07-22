send_arp: main.cpp
	g++ -o send_arp main.cpp -L./ -lpcap

clean:
	rm -f *.o send_arp

