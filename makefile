TARGET = bin/ssl_sni_forwarder

OPTS = -D_POSIX_SOURCE -g -Wall -Wextra -pedantic -Werror

COPTS = $(OPTS) -std=c11
CPPOPTS = $(OPTS) -std=c++11
LOPTS = 

SRC = main.cpp Server.cpp Client.cpp

OBJECTS = $(SRC:%.cpp=tmp/%.o)

all: $(OBJECTS)
	g++ $(LOPTS) $^ -o $(TARGET)

tmp/%.o: src/%.c
	gcc $(COPTS) -c $< -o $@

tmp/%.o: src/%.cpp
	g++ $(CPPOPTS) -c $< -o $@

clean:
	rm -f $(OBJECTS)
