all: cap.o cap adapterList.o adapterList

cap.o:
	gcc -Wall -O -I ${CURDIR}\includes -c cap.c

cap: cap.o
	gcc -LD:\Repo\lib cap.o -lwpcap -lws2_32 -o cap

adapterList.o:
	gcc -Wall -O -I ${CURDIR}\includes -c adapterList.c

adapterList: adapterList.o
	gcc -LD:\Repo\lib adapterList.o -lwpcap -o adapterList
	
clean:
	rm cap.o cap.exe adapterList.o adapterList.exe 
	
