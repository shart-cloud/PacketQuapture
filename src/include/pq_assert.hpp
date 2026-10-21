#pragma once

#include <stdexcept>
#include <string>

namespace packetquapture {

// A failed PQ_ASSERT means this code is wrong, never that the input is bad: hostile
// bytes are rejected with a status or an InvalidInputException instead. Unlike
// D_ASSERT it stays on in release builds, and it throws rather than aborting so a bug
// fails the query without taking down the user's database process.
class AssertionFailure : public std::logic_error {
public:
	explicit AssertionFailure(const std::string &message) : std::logic_error(message) {
	}
};

[[noreturn]] inline void FailAssertion(const char *condition, const char *file, int line) {
	throw AssertionFailure(std::string("packetquapture assertion failed: ") + condition + " (" + file + ":" +
	                       std::to_string(line) + ")");
}

} // namespace packetquapture

#define PQ_ASSERT(condition)                                                                                           \
	do {                                                                                                               \
		if (!(condition)) {                                                                                            \
			::packetquapture::FailAssertion(#condition, __FILE__, __LINE__);                                           \
		}                                                                                                              \
	} while (false)
