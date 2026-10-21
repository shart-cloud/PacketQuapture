#include "dns_decoder.hpp"

#include <cassert>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <iterator>
#include <random>
#include <vector>

using namespace packetquapture;

static void Check(const std::vector<uint8_t> &bytes) {
	const auto result = DecodeDns(bytes.data(), bytes.size());
	if (result.valid) {
		assert(result.error.empty());
		assert(bytes.size() >= 12 && bytes.size() <= 65535);
		assert(result.questions.size() + result.answers.size() + result.authorities.size() +
		           result.additionals.size() <=
		       4096);
	} else {
		assert(!result.error.empty());
		assert(result.questions.empty() && result.answers.empty() && result.authorities.empty() &&
		       result.additionals.empty());
	}
}

// Header for a response with one question and one answer.
static std::vector<uint8_t> Header() {
	return {0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0};
}

static void AppendAnswerTail(std::vector<uint8_t> &bytes) {
	const uint8_t tail[] = {0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1};
	bytes.insert(bytes.end(), tail, tail + sizeof(tail));
}

// A legal 255-octet name of 127 labels whose last label comes through a
// pointer takes 129 steps; it must decode, not trip a combined hop cap.
static void TestLongestCompressedName() {
	auto bytes = Header();
	const uint8_t question[] = {1, 'z', 0, 0, 1, 0, 1}; // "z" at offset 12
	bytes.insert(bytes.end(), question, question + sizeof(question));
	for (int i = 0; i < 126; ++i) {
		bytes.push_back(1);
		bytes.push_back('a');
	}
	bytes.push_back(0xC0);
	bytes.push_back(12);
	AppendAnswerTail(bytes);
	const auto result = DecodeDns(bytes.data(), bytes.size());
	assert(result.valid);
	assert(result.answers.size() == 1);
	assert(result.answers[0].name.size() == 253);
	assert(result.answers[0].name.compare(result.answers[0].name.size() - 2, 2, ".z") == 0);
}

// A pointer must target a prior occurrence, before the segment holding it, so
// a pointer back into its own name, or to its own label, is rejected.
static void TestPointerCycles() {
	auto bytes = Header();
	const uint8_t question[] = {1, 'z', 0, 0, 1, 0, 1};
	bytes.insert(bytes.end(), question, question + sizeof(question));
	const size_t answer = bytes.size();
	bytes.push_back(1);
	bytes.push_back('a');
	bytes.push_back(0xC0);
	bytes.push_back(static_cast<uint8_t>(answer)); // back to its own first label
	AppendAnswerTail(bytes);
	assert(!DecodeDns(bytes.data(), bytes.size()).valid);
}

int main() {
	TestLongestCompressedName();
	TestPointerCycles();
	std::mt19937 random(998877);
	for (unsigned i = 0; i < 19; ++i) {
		char path[80];
		std::snprintf(path, sizeof(path), "test/data/dns/message_%02u.bin", i);
		std::ifstream input(path, std::ios::binary);
		assert(input.good());
		std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
		const auto result = DecodeDns(bytes.data(), bytes.size());
		assert(result.valid == (i < 9 || i == 16));
		if (i == 1) {
			assert(result.questions[0].name == "example.com");
			assert(result.answers[0].text == "192.0.2.5" && result.answers[0].ttl == 300);
		}
		if (i == 3) {
			assert(result.answers[0].text == "www.example.com");
			assert(result.answers[1].name == "www.example.com");
		}
		for (size_t length = 0; length <= bytes.size(); ++length) {
			Check(std::vector<uint8_t>(bytes.begin(), bytes.begin() + length));
		}
		for (unsigned mutation = 0; mutation < 2000; ++mutation) {
			auto changed = bytes;
			for (unsigned j = 0; j < 4 && !changed.empty(); ++j) {
				changed[random() % changed.size()] = static_cast<uint8_t>(random());
			}
			Check(changed);
		}
	}
	for (unsigned i = 0; i < 20000; ++i) {
		std::vector<uint8_t> bytes(random() % 1024);
		for (auto &byte : bytes) {
			byte = static_cast<uint8_t>(random());
		}
		Check(bytes);
	}
	Check(std::vector<uint8_t>(65536));
	std::cout << "DNS checks passed: fixture prefixes, 38,000 mutations, 20,000 random inputs\n";
}
