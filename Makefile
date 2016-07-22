network_hw2_: main.cpp
	g++ -o network_hw2_ main.cpp -L./ -lpcap

clean:
	rm -f *.o network_hw2_

