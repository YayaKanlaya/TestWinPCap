all: cap.o cap capByWhile.o capByWhile adapterList.o adapterList 

cap.o:
	gcc -Wall -O -I ${CURDIR}\includes -c cap.c

cap: cap.o
	gcc -LD:\Repo\lib cap.o -lwpcap -lws2_32 -o cap

capByWhile.o:
	gcc -Wall -O -I ${CURDIR}\includes -c capByWhile.c

capByWhile: capByWhile.o
	gcc -LD:\Repo\lib capByWhile.o -lwpcap -o capByWhile
	
adapterList.o:
	gcc -Wall -O -I ${CURDIR}\includes -c adapterList.c

adapterList: adapterList.o
	gcc -LD:\Repo\lib adapterList.o -lwpcap -o adapterList
	
#clean:
#	rm cap.o cap.exe capByWhile.o capByWhile.exe  adapterList.o adapterList.exe 

clean:
	rm cap.o cap.exe 
