#include "traffic_analytics.hpp"
#include "traffic_analytics_sql.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/types/vector.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/parser/expression/constant_expression.hpp"
#include "duckdb/parser/expression/function_expression.hpp"
#include "duckdb/parser/parser.hpp"
#include "duckdb/parser/parsed_data/create_macro_info.hpp"
#include "duckdb/parser/statement/create_statement.hpp"
#include "duckdb/parser/tableref/table_function_ref.hpp"

#include <array>
#include <cctype>
#include <cstdint>

namespace duckdb {
namespace {

constexpr int64_t DEFAULT_TCP_IDLE_MICROS = 300000000;
constexpr int64_t DEFAULT_UDP_IDLE_MICROS = 60000000;

struct ParsedAddress {
	std::array<uint8_t, 16> bytes {};
	uint8_t bits = 0;
};

static bool ParseDecimalByte(const string &text, idx_t begin, idx_t end, uint8_t &result) {
	if (begin == end || end - begin > 3) {
		return false;
	}
	uint32_t value = 0;
	for (idx_t i = begin; i < end; ++i) {
		if (!std::isdigit(static_cast<unsigned char>(text[i]))) {
			return false;
		}
		value = value * 10 + static_cast<uint32_t>(text[i] - '0');
		if (value > 255) {
			return false;
		}
	}
	result = static_cast<uint8_t>(value);
	return true;
}

static bool ParseIPv4(const string &text, std::array<uint8_t, 16> &bytes, idx_t offset = 0) {
	idx_t begin = 0;
	for (idx_t part = 0; part < 4; ++part) {
		auto end = part == 3 ? text.size() : text.find('.', begin);
		if (end == string::npos || !ParseDecimalByte(text, begin, end, bytes[offset + part])) {
			return false;
		}
		begin = end + 1;
	}
	return begin == text.size() + 1;
}

static bool ParseHexWord(const string &text, idx_t begin, idx_t end, uint16_t &result) {
	if (begin == end || end - begin > 4) {
		return false;
	}
	uint16_t value = 0;
	for (idx_t i = begin; i < end; ++i) {
		const auto c = static_cast<unsigned char>(text[i]);
		uint8_t digit;
		if (c >= '0' && c <= '9') {
			digit = c - '0';
		} else if (c >= 'a' && c <= 'f') {
			digit = c - 'a' + 10;
		} else if (c >= 'A' && c <= 'F') {
			digit = c - 'A' + 10;
		} else {
			return false;
		}
		value = static_cast<uint16_t>((value << 4U) | digit);
	}
	result = value;
	return true;
}

static bool ParseIPv6Side(const string &side, vector<uint16_t> &words, bool allow_ipv4) {
	if (side.empty()) {
		return true;
	}
	idx_t begin = 0;
	while (begin <= side.size()) {
		auto end = side.find(':', begin);
		if (end == string::npos) {
			end = side.size();
		}
		if (begin == end) {
			return false;
		}
		const auto token = side.substr(begin, end - begin);
		if (token.find('.') != string::npos) {
			if (!allow_ipv4 || end != side.size()) {
				return false;
			}
			std::array<uint8_t, 16> ipv4 {};
			if (!ParseIPv4(token, ipv4)) {
				return false;
			}
			words.push_back(static_cast<uint16_t>((ipv4[0] << 8U) | ipv4[1]));
			words.push_back(static_cast<uint16_t>((ipv4[2] << 8U) | ipv4[3]));
		} else {
			uint16_t word;
			if (!ParseHexWord(side, begin, end, word)) {
				return false;
			}
			words.push_back(word);
		}
		if (end == side.size()) {
			break;
		}
		begin = end + 1;
	}
	return true;
}

static bool ParseAddress(const string &text, ParsedAddress &result) {
	if (text.find(':') == string::npos) {
		result.bits = 32;
		return ParseIPv4(text, result.bytes);
	}
	const auto compression = text.find("::");
	if (compression != string::npos && text.find("::", compression + 2) != string::npos) {
		return false;
	}
	vector<uint16_t> left;
	vector<uint16_t> right;
	if (compression == string::npos) {
		if (!ParseIPv6Side(text, left, true) || left.size() != 8) {
			return false;
		}
	} else {
		if (!ParseIPv6Side(text.substr(0, compression), left, false) ||
		    !ParseIPv6Side(text.substr(compression + 2), right, true) || left.size() + right.size() >= 8) {
			return false;
		}
	}
	vector<uint16_t> words = left;
	if (compression != string::npos) {
		words.resize(8 - right.size(), 0);
		words.insert(words.end(), right.begin(), right.end());
	}
	result.bits = 128;
	for (idx_t i = 0; i < 8; ++i) {
		result.bytes[i * 2] = static_cast<uint8_t>(words[i] >> 8U);
		result.bytes[i * 2 + 1] = static_cast<uint8_t>(words[i]);
	}
	return true;
}

static bool ParsePrefix(const string &text, ParsedAddress &address, uint8_t &prefix) {
	const auto slash = text.find('/');
	if (slash == string::npos || text.find('/', slash + 1) != string::npos ||
	    !ParseAddress(text.substr(0, slash), address)) {
		return false;
	}
	const auto value = text.substr(slash + 1);
	if (value.empty() || value.size() > 3) {
		return false;
	}
	uint32_t parsed = 0;
	for (const auto c : value) {
		if (!std::isdigit(static_cast<unsigned char>(c))) {
			return false;
		}
		parsed = parsed * 10 + static_cast<uint32_t>(c - '0');
	}
	if (parsed > address.bits) {
		return false;
	}
	prefix = static_cast<uint8_t>(parsed);
	return true;
}

static bool PrefixContains(const ParsedAddress &network, uint8_t prefix, const ParsedAddress &address) {
	if (network.bits != address.bits) {
		return false;
	}
	const idx_t whole_bytes = prefix / 8;
	const uint8_t remaining = prefix % 8;
	for (idx_t i = 0; i < whole_bytes; ++i) {
		if (network.bytes[i] != address.bytes[i]) {
			return false;
		}
	}
	if (remaining) {
		const auto mask = static_cast<uint8_t>(0xffU << (8U - remaining));
		if ((network.bytes[whole_bytes] & mask) != (address.bytes[whole_bytes] & mask)) {
			return false;
		}
	}
	return true;
}

static void IpInCidrs(DataChunk &args, ExpressionState &, Vector &result) {
	UnifiedVectorFormat ips;
	UnifiedVectorFormat lists;
	args.data[0].ToUnifiedFormat(args.size(), ips);
	args.data[1].ToUnifiedFormat(args.size(), lists);
	auto &children = ListVector::GetEntry(args.data[1]);
	UnifiedVectorFormat child_data;
	children.ToUnifiedFormat(ListVector::GetListSize(args.data[1]), child_data);
	const auto ip_values = UnifiedVectorFormat::GetData<string_t>(ips);
	const auto list_values = UnifiedVectorFormat::GetData<list_entry_t>(lists);
	const auto cidr_values = UnifiedVectorFormat::GetData<string_t>(child_data);
	result.SetVectorType(VectorType::FLAT_VECTOR);
	auto output = FlatVector::GetData<bool>(result);
	auto &validity = FlatVector::Validity(result);
	validity.SetAllValid(args.size());
	for (idx_t row = 0; row < args.size(); ++row) {
		const auto ip_index = ips.sel->get_index(row);
		const auto list_index = lists.sel->get_index(row);
		if (!lists.validity.RowIsValid(list_index)) {
			throw InvalidInputException("local_networks must not be NULL");
		}
		const auto entry = list_values[list_index];
		vector<ParsedAddress> networks;
		vector<uint8_t> prefixes;
		networks.reserve(entry.length);
		prefixes.reserve(entry.length);
		for (idx_t i = 0; i < entry.length; ++i) {
			const auto child_index = child_data.sel->get_index(entry.offset + i);
			if (!child_data.validity.RowIsValid(child_index)) {
				throw InvalidInputException("local_networks must not contain NULL");
			}
			networks.emplace_back();
			prefixes.emplace_back();
			const auto cidr = cidr_values[child_index].GetString();
			if (!ParsePrefix(cidr, networks.back(), prefixes.back())) {
				throw InvalidInputException("Invalid CIDR in local_networks: '%s'", cidr);
			}
		}
		if (!ips.validity.RowIsValid(ip_index)) {
			validity.SetInvalid(row);
			continue;
		}
		ParsedAddress address;
		if (!ParseAddress(ip_values[ip_index].GetString(), address)) {
			validity.SetInvalid(row);
			continue;
		}
		bool contained = false;
		for (idx_t i = 0; i < networks.size(); ++i) {
			if (PrefixContains(networks[i], prefixes[i], address)) {
				contained = true;
			}
		}
		output[row] = contained;
	}
	result.SetVectorType(args.AllConstant() ? VectorType::CONSTANT_VECTOR : VectorType::FLAT_VECTOR);
}

static void RegisterMacros(ExtensionLoader &loader) {
	Parser parser;
	parser.ParseQuery(TRAFFIC_ANALYTICS_SQL);
	for (auto &statement : parser.statements) {
		if (statement->type != StatementType::CREATE_STATEMENT) {
			throw InternalException("Traffic analytics SQL contains a non-CREATE statement");
		}
		auto &create = statement->Cast<CreateStatement>();
		if (create.info->type != CatalogType::TABLE_MACRO_ENTRY) {
			throw InternalException("Traffic analytics SQL contains a non-table-macro definition");
		}
		auto &macro = create.info->Cast<CreateMacroInfo>();
		macro.catalog = SYSTEM_CATALOG;
		macro.schema = DEFAULT_SCHEMA;
		macro.internal = true;
		macro.on_conflict = OnCreateConflict::ALTER_ON_CONFLICT;
		try {
			loader.RegisterFunction(macro);
		} catch (const std::exception &exception) {
			throw InvalidInputException("Failed to register traffic analytics macro '%s': %s", macro.name,
			                            exception.what());
		}
	}
}

static Value NamedOrDefault(TableFunctionBindInput &input, const string &name, Value value) {
	const auto entry = input.named_parameters.find(name);
	return entry == input.named_parameters.end() ? std::move(value) : entry->second;
}

static unique_ptr<TableRef> SummarizeTalkersBindReplace(ClientContext &, TableFunctionBindInput &input) {
	vector<unique_ptr<ParsedExpression>> arguments;
	arguments.push_back(make_uniq<ConstantExpression>(input.inputs[0]));
	arguments.push_back(make_uniq<ConstantExpression>(input.inputs[1]));
	arguments.push_back(make_uniq<ConstantExpression>(NamedOrDefault(input, "by", Value("host"))));
	arguments.push_back(make_uniq<ConstantExpression>(NamedOrDefault(input, "metric", Value("payload_bytes"))));
	arguments.push_back(make_uniq<ConstantExpression>(NamedOrDefault(input, "scope", Value("all"))));
	arguments.push_back(make_uniq<ConstantExpression>(NamedOrDefault(input, "max_results", Value::UBIGINT(100))));
	arguments.push_back(make_uniq<ConstantExpression>(
	    NamedOrDefault(input, "tcp_idle_timeout", Value::INTERVAL(interval_t {0, 0, DEFAULT_TCP_IDLE_MICROS}))));
	arguments.push_back(make_uniq<ConstantExpression>(
	    NamedOrDefault(input, "udp_idle_timeout", Value::INTERVAL(interval_t {0, 0, DEFAULT_UDP_IDLE_MICROS}))));
	auto result = make_uniq<TableFunctionRef>();
	result->function = make_uniq<FunctionExpression>("_packetquapture_summarize_talkers", std::move(arguments));
	return std::move(result);
}

static void RegisterSummarizeTalkers(ExtensionLoader &loader) {
	TableFunctionSet functions("summarize_talkers");
	const vector<LogicalType> path_types {LogicalType(LogicalType::VARCHAR), LogicalType::LIST(LogicalType::VARCHAR)};
	for (const auto &path_type : path_types) {
		vector<LogicalType> arguments {path_type, LogicalType::LIST(LogicalType::VARCHAR)};
		TableFunction function(arguments, nullptr, nullptr);
		function.bind_replace = SummarizeTalkersBindReplace;
		function.named_parameters["by"] = LogicalType::VARCHAR;
		function.named_parameters["metric"] = LogicalType::VARCHAR;
		function.named_parameters["scope"] = LogicalType::VARCHAR;
		function.named_parameters["max_results"] = LogicalType::UBIGINT;
		function.named_parameters["tcp_idle_timeout"] = LogicalType::INTERVAL;
		function.named_parameters["udp_idle_timeout"] = LogicalType::INTERVAL;
		functions.AddFunction(std::move(function));
	}
	loader.RegisterFunction(std::move(functions));
}

} // namespace

void RegisterTrafficAnalytics(ExtensionLoader &loader) {
	loader.RegisterFunction(ScalarFunction("packetquapture_ip_in_cidrs",
	                                       {LogicalType::VARCHAR, LogicalType::LIST(LogicalType::VARCHAR)},
	                                       LogicalType::BOOLEAN, IpInCidrs));
	RegisterMacros(loader);
	RegisterSummarizeTalkers(loader);
}

} // namespace duckdb
