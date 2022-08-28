all : mitm

mitm : main.o
	gcc -Wall -o ./mitm main.o -L /usr/local/lib -lnfnetlink -lnetfilter_queue

main.o:
	gcc -Wall -c -o main.o main.c

clean:
	rm -f ./mitm
	rm -rf ./*.o
