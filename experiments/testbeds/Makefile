all: genTestbedCfg

genTestbedCfg: genTestbedCfg.o
	gcc genTestbedCfg.o -o genTestbedCfg

genTestbedCfg.o: genTestbedCfg.c
	gcc -c genTestbedCfg.c

clean:
	rm -f genTestbedCfg genTestbedCfg.o 

