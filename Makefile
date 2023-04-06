all : send-arp

send-arp : main.o proto_structures.o local_address.o
	g++ main.o proto_structures.o local_address.o -lpcap -o send-arp

main.o : main.cpp proto_structures.h local_address.h
	g++ -c main.cpp -o main.o

local_address.o : local_address.cpp local_address.h
	g++ -c local_address.cpp -o local_address.o

proto_structures.o : proto_structures.cpp proto_structures.h
	g++ -c proto_structures.cpp -o proto_structures.o

clean :
	rm -f *.o
	rm -f send-arp
