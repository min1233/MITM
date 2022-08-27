all : mitm

mitm : main.o
	g++ -g -o ./mitm main.o -lpcap -lpthread

main.o:
	g++ -g -c -o main.o main.cpp

clean:
	rm -f ./mitm
	rm -rf ./*.o
