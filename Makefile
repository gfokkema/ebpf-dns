CC=clang
CFLAGS=-g -O -Wall -I/usr/include/bpf

DEV=enp1s0

BPF_PROG=bpf_demo.o
XDP_PROG=xdp_demo.o

all: $(BPF_PROG) $(XDP_PROG)

$(BPF_PROG): bpf_demo.c
	$(CC) -target bpf $(CFLAGS) -c -o $@ $<

$(XDP_PROG): xdp_demo.c
	$(CC) -target bpf $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(BPF_PROG) $(XDP_PROG)

dump: $(XDP_PROG)
	llvm-objdump -S $(XDP_PROG)

clsact:
	sudo /sbin/tc qdisc add dev $(DEV) clsact
	/usr/bin/touch clsact

bpf_load: clsact $(BPF_PROG)
	sudo /sbin/tc filter del dev $(DEV) ingress || true
	sudo /sbin/tc filter del dev $(DEV) egress || true
	sudo /sbin/tc filter add dev $(DEV) ingress bpf da obj $(BPF_PROG) sec ingress
	sudo /sbin/tc filter add dev $(DEV) egress bpf da obj $(BPF_PROG) sec egress

bpf_unload:
	sudo /sbin/tc filter del dev $(DEV) ingress || true
	sudo /sbin/tc filter del dev $(DEV) egress || true
	sudo /sbin/tc qdisc del dev $(DEV) clsact || true
	rm -f clsact

xdp_load: $(XDP_PROG)
	sudo ip --force link set dev $(DEV) xdpgeneric obj $(XDP_PROG) sec xdp/demo

xdp_unload:
	sudo ip link set dev $(DEV) xdpgeneric off

show:
	sudo ip link show dev $(DEV)
	/sbin/tc filter show dev $(DEV) ingress
	/sbin/tc filter show dev $(DEV) egress

debug:
	sudo cat /sys/kernel/debug/tracing/trace_pipe