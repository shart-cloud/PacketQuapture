#include "pq_assert.hpp"

#include <cassert>
#include <cstdio>
#include <string>

using namespace packetquapture;

int main() {
	// A true condition is silent.
	PQ_ASSERT(1 + 1 == 2);

	// A false one throws with the condition text and its location, so a bug report
	// names the broken invariant without a debugger.
	bool thrown = false;
	try {
		const int count = 3;
		PQ_ASSERT(count < 2);
	} catch (const AssertionFailure &error) {
		const std::string message = error.what();
		assert(message.find("count < 2") != std::string::npos);
		assert(message.find("pq_assert_test.cpp") != std::string::npos);
		thrown = true;
	}
	assert(thrown);

	// It is a logic_error, so generic handlers that rethrow logic errors keep it.
	thrown = false;
	try {
		PQ_ASSERT(false);
	} catch (const std::logic_error &) {
		thrown = true;
	}
	assert(thrown);
	printf("PQ_ASSERT throws with condition and location\n");
	return 0;
}
