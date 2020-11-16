CPPFLAGS = -I include -Wall -Werror -pthread

src = $(wildcard src/*.c)
obj = $(patsubst src/%.c, build/%.o, $(src))
headers = $(wildcard include/*.h)

lvl-ip: $(obj)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(obj) -o lvl-ip
	@echo
	@echo "lvl-ip needs CAP_NET_ADMIN:"
	sudo setcap cap_net_admin,cap_net_raw=eip lvl-ip

native:
	$(CC) native_tcp_test.c -o native_tcp_test

build/%.o: src/%.c ${headers}
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

debug: CFLAGS+= -DDEBUG -g
debug: lvl-ip

all: lvl-ip

run_server:
	sudo ./lvl-ip server 10.0.0.254 7891

debug_server:
	valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./lvl-ip server 10.0.0.254 7891

run_client:
	sudo ip netns exec ns0 ./lvl-ip client 10.0.0.1 7891

debug_client:
	sudo ip netns exec ns0 valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes ./lvl-ip client 10.0.0.1 7891


run_native_server:
	sudo ./native_tcp_test server 7891

run_native_client:
	sudo ip netns exec ns0 ./native_tcp_test client 7891

clean:
	rm build/*.o lvl-ip


