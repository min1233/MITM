all : mitm

mitm : main.o
	g++ -Wall -o ./mitm main.o -L /usr/local/lib -lnfnetlink -lnetfilter_queue

main.o:
	g++ -Wall -c -o main.o main.cpp

clean:
	rm -f ./mitm
	rm -rf ./*.o
