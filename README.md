# pktgen-uml
This is a modified packet generator from http://dpdk.org/browse/apps/pktgen-dpdk/ that allows customized packet headers and packet size

This pktgen is used only for internal test, there are still some places that needs to be changed or optimized.

1. in the Makefile, "CFLAGS += -DPORT_MASK=0x01" needs to be changed accordingly. In our server, we only use the first port.

2. in the main.c, "#define RTE_MAX_ETHPORTS" needs to be changed accordingly. In our server, it has max 2 ports.

3. in the main.c, "#define RTE_MAX_LCORE" needs to be changed accordingly. In our server, it has max 12 cores.

4. in the main.c "#define MAX_MBUFS_PER_PORT" needs to be changed accordingly. This is because the current setting would consume 256*1024*2048 bytes per port. Especially, this macro will determine how many unique random packets each core would generate, since each mbuf matches one unique random packet.

5. it does not support jumbo frame, the maximum packet size would be 1518 (normal UDP packet: 14+20+8+1472+4)

6. the feature of pcap file is still under improvement, please don't use it.

7. To build the program, please "export RTE_SDK=<DPDK build dir>" and "make"

    To run the program, please "sudo ./build/tx_test -c 0xaaa -- --saddr 10.0.0.1 --daddr 10.0.0.2 --sport 22 --dport 80 --psize 22"
        1) all the source mac address and destination mac address are random
        2) --saddr specify the source address of each packet, if not set, then all the source address will be random
        3) --daddr specify the destination address of each packet, if not set, then all the destination address will be random
        4) --sport specify the source port of each packet, if not set, then all the source port will be random
        5) --dport specify the destination port of each packet, if not set, then all the destination port will be random
        6) --psize specify the payload size of each packet, if not set, the all the payload size will be 1460.
        
8. There three subroutines each core can run, in default, it is using "app_thread_throughput"
        1. app_thread_fps: this one tests how much time needs to be used to generate and send the packets. It has been used to see how much unique random flows per second can be genrated.
        2. app_thread_throughput: this one is used to test the rough throughput. When running, every 10 seconds, each core prints its throughput of sending all the packets for all the ports. When "CFLAGS += -DPORT_MASK=0x01" has only 1 bit masked, we can see the performance of that masked port of the NIC by summing the printout from each core.
        3. app_thread_sendnumpkts: this one is used to send a fixed amount of packets. The fixed amount is determined by the macro "#define APP_THREAD_SENDNUMPKTS_ROUND (64 *1024 * 1024 / PKTQ_HWQ_OUT_BURST_SIZE) ", where "64 *1024 * 1024" determine the total number of packets each core will send out for each port and "PKTQ_HWQ_OUT_BURST_SIZE" determine the the number of packets sent out per round. 
        
9. If any issue or bugs are found, please report them to Xiaoban_Wu@student.uml.edu.
