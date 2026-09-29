#include "dns_analytics.hpp"
#include "dns_analytics_resources.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/common/vector_operations/unary_executor.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/parsed_data/create_macro_info.hpp"
#include "duckdb/parser/statement/create_statement.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cmath>
#include <sstream>
#include <unordered_set>

namespace duckdb {
namespace {

struct PslSection {
	unordered_set<string> exact;
	unordered_set<string> wildcard;
	unordered_set<string> exception;
};

struct PslData {
	PslSection icann;
	PslSection private_domains;
};

struct PslResult {
	string public_suffix;
	string registrable_domain;
	string left_payload;
	string section = "unknown";
	string rule = "*";
};

static string LowerAscii(string value) {
	for (auto &character : value) {
		character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
	}
	return value;
}

static const PslData &GetPslData() {
	static const PslData data = [] {
		PslData result;
		PslSection *section = &result.icann;
		std::istringstream input(PUBLIC_SUFFIX_LIST);
		string line;
		while (std::getline(input, line)) {
			if (!line.empty() && line.back() == '\r') {
				line.pop_back();
			}
			if (line == "// ===BEGIN PRIVATE DOMAINS===") {
				section = &result.private_domains;
				continue;
			}
			if (line.empty() || line.rfind("//", 0) == 0) {
				continue;
			}
			line = LowerAscii(line);
			if (line[0] == '!') {
				section->exception.insert(line.substr(1));
			} else if (line.rfind("*.", 0) == 0) {
				section->wildcard.insert(line.substr(2));
			} else {
				section->exact.insert(std::move(line));
			}
		}
		return result;
	}();
	return data;
}

static bool SplitName(const string &input, vector<string> &labels) {
	string name = LowerAscii(input);
	while (!name.empty() && name.back() == '.') {
		name.pop_back();
	}
	if (name.empty()) {
		return false;
	}
	idx_t begin = 0;
	while (begin <= name.size()) {
		auto end = name.find('.', begin);
		if (end == string::npos) {
			end = name.size();
		}
		if (end == begin) {
			return false;
		}
		labels.push_back(name.substr(begin, end - begin));
		if (end == name.size()) {
			break;
		}
		begin = end + 1;
	}
	return true;
}

static string JoinLabels(const vector<string> &labels, idx_t begin, const char *separator = ".") {
	string result;
	for (idx_t i = begin; i < labels.size(); ++i) {
		if (!result.empty()) {
			result += separator;
		}
		result += labels[i];
	}
	return result;
}

static PslResult ResolvePsl(const string &input) {
	vector<string> labels;
	PslResult result;
	if (!SplitName(input, labels)) {
		return result;
	}
	const auto &data = GetPslData();
	idx_t public_label_count = 1;
	bool exception_match = false;
	for (idx_t i = 0; i < labels.size(); ++i) {
		const auto candidate = JoinLabels(labels, i);
		for (const auto section : {&data.icann, &data.private_domains}) {
			if (section->exception.find(candidate) != section->exception.end()) {
				public_label_count = labels.size() - i - 1;
				result.section = section == &data.icann ? "icann" : "private";
				result.rule = "!" + candidate;
				exception_match = true;
				break;
			}
		}
		if (exception_match) {
			break;
		}
	}
	if (!exception_match) {
		for (idx_t i = 0; i < labels.size(); ++i) {
			const auto candidate = JoinLabels(labels, i);
			const auto candidate_count = labels.size() - i;
			for (const auto section : {&data.icann, &data.private_domains}) {
				if (section->exact.find(candidate) != section->exact.end() &&
				    (candidate_count > public_label_count || result.section == "unknown")) {
					public_label_count = candidate_count;
					result.section = section == &data.icann ? "icann" : "private";
					result.rule = candidate;
				}
				if (i > 0 && section->wildcard.find(candidate) != section->wildcard.end() &&
				    candidate_count + 1 > public_label_count) {
					public_label_count = candidate_count + 1;
					result.section = section == &data.icann ? "icann" : "private";
					result.rule = "*." + candidate;
				}
			}
		}
	}
	if (public_label_count == 0 || public_label_count > labels.size()) {
		return result;
	}
	result.public_suffix = JoinLabels(labels, labels.size() - public_label_count);
	if (labels.size() > public_label_count) {
		const auto registrable_begin = labels.size() - public_label_count - 1;
		result.registrable_domain = JoinLabels(labels, registrable_begin);
		for (idx_t i = 0; i < registrable_begin; ++i) {
			result.left_payload += labels[i];
		}
	}
	return result;
}

template <string PslResult::*MEMBER>
static void PslStringFunction(DataChunk &args, ExpressionState &, Vector &result) {
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t input) {
		const auto resolved = ResolvePsl(input.GetString());
		return StringVector::AddString(result, resolved.*MEMBER);
	});
}

static void NormalizedEntropy(DataChunk &args, ExpressionState &, Vector &result) {
	UnaryExecutor::Execute<string_t, double>(args.data[0], result, args.size(), [&](string_t input) {
		const auto value = input.GetString();
		if (value.empty()) {
			return 0.0;
		}
		std::array<idx_t, 256> counts {};
		for (const auto character : value) {
			counts[static_cast<unsigned char>(character)]++;
		}
		double entropy = 0;
		for (const auto count : counts) {
			if (count == 0) {
				continue;
			}
			const auto probability = static_cast<double>(count) / static_cast<double>(value.size());
			entropy -= probability * std::log2(probability);
		}
		return std::min(1.0, entropy / 6.0);
	});
}

static void EncodedRatio(DataChunk &args, ExpressionState &, Vector &result) {
	UnaryExecutor::Execute<string_t, double>(args.data[0], result, args.size(), [&](string_t input) {
		const auto value = LowerAscii(input.GetString());
		if (value.empty()) {
			return 0.0;
		}
		idx_t hexadecimal = 0;
		idx_t base32 = 0;
		for (const auto character : value) {
			if ((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
				hexadecimal++;
			}
			if ((character >= 'a' && character <= 'z') || (character >= '2' && character <= '7')) {
				base32++;
			}
		}
		const auto denominator = static_cast<double>(value.size());
		return std::max(hexadecimal / denominator, base32 / denominator);
	});
}

static void RegisterMacros(ExtensionLoader &loader) {
	Parser parser;
	parser.ParseQuery(DNS_ANALYTICS_SQL);
	for (auto &statement : parser.statements) {
		if (statement->type != StatementType::CREATE_STATEMENT) {
			throw InternalException("DNS analytics SQL contains a non-CREATE statement");
		}
		auto &create = statement->Cast<CreateStatement>();
		if (create.info->type != CatalogType::TABLE_MACRO_ENTRY) {
			throw InternalException("DNS analytics SQL contains a non-table-macro definition");
		}
		auto &macro = create.info->Cast<CreateMacroInfo>();
		macro.catalog = SYSTEM_CATALOG;
		macro.schema = DEFAULT_SCHEMA;
		macro.internal = true;
		macro.on_conflict = OnCreateConflict::ALTER_ON_CONFLICT;
		loader.RegisterFunction(macro);
	}
}

} // namespace

void RegisterDnsAnalytics(ExtensionLoader &loader) {
	loader.RegisterFunction(ScalarFunction("packetquapture_dns_public_suffix", {LogicalType::VARCHAR},
	                                       LogicalType::VARCHAR, PslStringFunction<&PslResult::public_suffix>));
	loader.RegisterFunction(ScalarFunction("packetquapture_dns_registrable_domain", {LogicalType::VARCHAR},
	                                       LogicalType::VARCHAR, PslStringFunction<&PslResult::registrable_domain>));
	loader.RegisterFunction(ScalarFunction("packetquapture_dns_left_payload", {LogicalType::VARCHAR},
	                                       LogicalType::VARCHAR, PslStringFunction<&PslResult::left_payload>));
	loader.RegisterFunction(ScalarFunction("packetquapture_dns_suffix_section", {LogicalType::VARCHAR},
	                                       LogicalType::VARCHAR, PslStringFunction<&PslResult::section>));
	loader.RegisterFunction(ScalarFunction("packetquapture_dns_suffix_rule", {LogicalType::VARCHAR},
	                                       LogicalType::VARCHAR, PslStringFunction<&PslResult::rule>));
	loader.RegisterFunction(ScalarFunction("packetquapture_dns_normalized_entropy", {LogicalType::VARCHAR},
	                                       LogicalType::DOUBLE, NormalizedEntropy));
	loader.RegisterFunction(
	    ScalarFunction("packetquapture_dns_encoded_ratio", {LogicalType::VARCHAR}, LogicalType::DOUBLE, EncodedRatio));
	RegisterMacros(loader);
}

} // namespace duckdb
