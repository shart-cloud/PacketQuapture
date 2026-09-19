#include "flow_aggregator.hpp"
#include <malloc.h>
#include <iostream>
using namespace packetquapture;
int main() {
	const auto before = mallinfo2().uordblks;
	FlowAggregator a;
	FlowSummary row;
	for (uint32_t n = 0; n < 16384; ++n) {
		FlowInput x;
		x.section = 1;
		x.stamp = {n + 1ULL, true, 0};
		x.packet.network = x.packet.transport = x.packet.udp = true;
		x.packet.ip_version = 4;
		x.packet.src_port = n;
		x.packet.dst_port = 65535;
		a.Push(x);
		while (a.Next(row)) {
		}
	}
	const auto active = mallinfo2().uordblks;
	for (uint32_t n = 1; n < 65536; ++n) {
		FlowInput x;
		x.section = 1;
		x.interface_id = n;
		x.stamp = {n + 16385ULL, true, 0};
		a.Push(x);
		while (a.Next(row)) {
		}
	}
	std::cout << "state_bytes=" << FlowAggregator::StateSize() << " active_16384_heap=" << active - before
	          << " with_65536_scopes_heap=" << mallinfo2().uordblks - before << '\n';
}
