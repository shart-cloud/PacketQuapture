CREATE MACRO packetquapture_dns_facts(
    path_or_list,
    tcp_idle_timeout := INTERVAL '5 minutes'
) AS TABLE
WITH raw_messages AS MATERIALIZED (
    SELECT *
    FROM read_dns_messages(path_or_list, tcp_idle_timeout := tcp_idle_timeout)
), numbered AS (
    SELECT *, row_number() OVER (
        PARTITION BY filename, section_number, interface_id,
                     first_packet_number, last_packet_number, stream_id, message_number,
                     src_ip, dst_ip, src_port, dst_port, dns_id, dns_response,
                     dns_question_name, dns_question_type, dns_question_class
        ORDER BY filename
    )::UBIGINT AS duplicate_ordinal
    FROM raw_messages
), oriented AS (
    SELECT *,
           CASE WHEN dns_response = false THEN src_ip
                WHEN dns_response = true THEN dst_ip
                WHEN dst_port = 53 THEN src_ip
                WHEN src_port = 53 THEN dst_ip END AS client_ip,
           CASE WHEN dns_response = false THEN dst_ip
                WHEN dns_response = true THEN src_ip
                WHEN dst_port = 53 THEN dst_ip
                WHEN src_port = 53 THEN src_ip END AS resolver_ip,
           CASE WHEN dns_response = false THEN src_port
                WHEN dns_response = true THEN dst_port
                WHEN dst_port = 53 THEN src_port
                WHEN src_port = 53 THEN dst_port END AS client_port,
           CASE WHEN dns_response = false THEN dst_port
                WHEN dns_response = true THEN src_port
                WHEN dst_port = 53 THEN dst_port
                WHEN src_port = 53 THEN src_port END AS resolver_port,
           lower(dns_question_name) AS normalized_name
    FROM numbered
), featured AS (
    SELECT *,
           packetquapture_dns_public_suffix(normalized_name) AS public_suffix_value,
           packetquapture_dns_registrable_domain(normalized_name) AS registrable_value,
           packetquapture_dns_left_payload(normalized_name) AS left_payload_value,
           packetquapture_dns_suffix_section(normalized_name) AS suffix_section_value,
           packetquapture_dns_suffix_rule(normalized_name) AS suffix_rule_value
    FROM oriented
)
SELECT
    filename AS source_locator,
    concat_ws(':', section_number::VARCHAR, interface_id::VARCHAR,
              coalesce(first_packet_number::VARCHAR, ''), coalesce(last_packet_number::VARCHAR, ''),
              coalesce(stream_id::VARCHAR, 'udp'), coalesce(message_number::VARCHAR, ''),
              duplicate_ordinal::VARCHAR) AS source_record_id,
    section_number, interface_id, first_packet_number, last_packet_number,
    first_timestamp, last_timestamp, transport,
    client_ip, resolver_ip, client_port, resolver_port,
    CASE WHEN dns_response = false THEN 'query'
         WHEN dns_response = true THEN 'response' ELSE 'unknown' END AS message_direction,
    dns_valid, dns_id, dns_opcode, dns_rcode, dns_truncated,
    dns_question_name AS question_name,
    normalized_name AS question_name_normalized,
    dns_question_type AS question_type,
    dns_question_class AS question_class,
    dns_answers AS answers,
    len(dns_answers)::UBIGINT AS answer_count,
    nullif(public_suffix_value, '') AS public_suffix,
    nullif(registrable_value, '') AS registrable_domain,
    coalesce(nullif(registrable_value, ''), normalized_name) AS grouping_domain,
    suffix_section_value AS suffix_section,
    suffix_rule_value AS suffix_rule,
    left_payload_value AS left_payload,
    length(normalized_name)::UBIGINT AS name_length,
    length(left_payload_value)::UBIGINT AS left_payload_length,
    packetquapture_dns_normalized_entropy(left_payload_value) AS normalized_entropy,
    packetquapture_dns_encoded_ratio(left_payload_value) AS encoded_character_ratio,
    reassembly_status, reassembly_error, dns_error,
    list_filter([
        CASE WHEN first_timestamp IS NULL THEN 'missing_timestamp' END,
        CASE WHEN NOT dns_valid THEN 'invalid_dns' END,
        CASE WHEN reassembly_status <> 'complete' THEN 'incomplete_reassembly' END,
        CASE WHEN dns_truncated THEN 'dns_truncated' END,
        CASE WHEN suffix_section_value = 'unknown' THEN 'unknown_suffix' END,
        CASE WHEN dns_question_name IS NULL THEN 'missing_question' END
    ], lambda flag: flag IS NOT NULL) AS quality_flags
FROM featured;

CREATE MACRO analyze_dns_tunnels(
    path_or_list,
    "window" := NULL,
    min_queries := 20,
    min_span := INTERVAL '1 minute',
    min_score := 0,
    max_results := 1000,
    evidence_rows := 8,
    profile := 'balanced-v1',
    tcp_idle_timeout := INTERVAL '5 minutes'
) AS TABLE
WITH checked AS (
    SELECT
        CASE WHEN "window" IS NULL OR "window" > INTERVAL '0 microseconds' THEN "window"
             ELSE error('analyze_dns_tunnels window must be positive') END AS window_value,
        CASE WHEN min_queries >= 2 THEN min_queries::UBIGINT
             ELSE error('analyze_dns_tunnels min_queries must be at least 2') END AS query_limit,
        CASE WHEN min_span >= INTERVAL '0 microseconds' THEN min_span
             ELSE error('analyze_dns_tunnels min_span must be nonnegative') END AS span_limit,
        CASE WHEN min_score BETWEEN 0 AND 100 THEN min_score::DOUBLE
             ELSE error('analyze_dns_tunnels min_score must be between 0 and 100') END AS score_limit,
        CASE WHEN max_results > 0 THEN max_results::UBIGINT
             ELSE error('analyze_dns_tunnels max_results must be positive') END AS result_limit,
        CASE WHEN evidence_rows >= 0 AND evidence_rows <= 1024 THEN evidence_rows::UBIGINT
             ELSE error('analyze_dns_tunnels evidence_rows must be between 0 and 1024') END AS evidence_limit,
        CASE WHEN profile = 'balanced-v1' THEN profile
             ELSE error('analyze_dns_tunnels profile must be balanced-v1') END AS profile_value
), facts AS MATERIALIZED (
    SELECT f.*, c.*,
           CASE WHEN c.window_value IS NULL OR f.first_timestamp IS NULL THEN NULL::TIMESTAMP
                ELSE time_bucket(c.window_value, f.first_timestamp) END AS window_bucket
    FROM packetquapture_dns_facts(path_or_list, tcp_idle_timeout) f, checked c
    WHERE f.dns_valid AND f.question_name_normalized IS NOT NULL
      AND f.client_ip IS NOT NULL AND f.resolver_ip IS NOT NULL
), groups AS (
    SELECT client_ip, resolver_ip, grouping_domain, public_suffix, registrable_domain,
           suffix_section, suffix_rule, window_bucket,
           count(*) FILTER (WHERE message_direction = 'query')::UBIGINT AS query_count,
           count(*) FILTER (WHERE message_direction = 'response')::UBIGINT AS response_count,
           count(DISTINCT question_name_normalized) FILTER (WHERE message_direction = 'query')::UBIGINT
               AS distinct_name_count,
           count(DISTINCT left_payload) FILTER (WHERE message_direction = 'query')::UBIGINT
               AS distinct_left_payload_count,
           min(first_timestamp) FILTER (WHERE message_direction = 'query') AS first_seen,
           max(first_timestamp) FILTER (WHERE message_direction = 'query') AS last_seen,
           max(last_timestamp) AS last_observed,
           median(name_length) FILTER (WHERE message_direction = 'query')::DOUBLE AS median_name_length,
           max(name_length) FILTER (WHERE message_direction = 'query')::UBIGINT AS max_name_length,
           median(left_payload_length) FILTER (WHERE message_direction = 'query')::DOUBLE
               AS median_left_payload_length,
           max(left_payload_length) FILTER (WHERE message_direction = 'query')::UBIGINT
               AS max_left_payload_length,
           round(avg(normalized_entropy) FILTER (
               WHERE message_direction = 'query' AND left_payload_length > 0), 12)
               AS mean_normalized_entropy,
           round(avg(encoded_character_ratio) FILTER (
               WHERE message_direction = 'query' AND left_payload_length > 0), 12)
               AS mean_encoded_character_ratio,
           count(*) FILTER (WHERE message_direction = 'response' AND dns_rcode = 3)::UBIGINT
               AS nxdomain_count,
           count(*) FILTER (WHERE message_direction = 'response' AND answer_count = 0)::UBIGINT
               AS no_answer_count,
           max(query_limit) AS query_limit, any_value(span_limit) AS span_limit,
           max(score_limit) AS score_limit, max(result_limit) AS result_limit,
           max(evidence_limit) AS evidence_limit, any_value(profile_value) AS profile_value,
           any_value(window_value) AS window_value,
           bit_xor(hash(source_locator, source_record_id)) AS evidence_hash,
           bool_or(list_contains(quality_flags, 'missing_timestamp')) AS has_missing_timestamp,
           bool_or(list_contains(quality_flags, 'dns_truncated')) AS has_dns_truncation,
           bool_or(list_contains(quality_flags, 'unknown_suffix')) AS has_unknown_suffix
    FROM facts
    GROUP BY client_ip, resolver_ip, grouping_domain, public_suffix, registrable_domain,
             suffix_section, suffix_rule, window_bucket
    HAVING count(*) FILTER (WHERE message_direction = 'query') >= max(query_limit)
), type_counts AS (
    SELECT client_ip, resolver_ip, grouping_domain, window_bucket, question_type,
           count(*)::UBIGINT AS query_count
    FROM facts
    WHERE message_direction = 'query'
    GROUP BY client_ip, resolver_ip, grouping_domain, window_bucket, question_type
), type_distributions AS (
    SELECT client_ip, resolver_ip, grouping_domain, window_bucket,
           list(struct_pack(question_type := question_type, query_count := query_count)
                ORDER BY question_type) AS question_types
    FROM type_counts
    GROUP BY client_ip, resolver_ip, grouping_domain, window_bucket
), evidence_ranked AS (
    SELECT *, row_number() OVER (
        PARTITION BY client_ip, resolver_ip, grouping_domain, window_bucket
        ORDER BY first_timestamp NULLS LAST, source_locator, source_record_id
    ) AS evidence_rank
    FROM facts
    WHERE message_direction = 'query'
), evidence AS (
    SELECT client_ip, resolver_ip, grouping_domain, window_bucket,
           list(struct_pack(source_locator := source_locator, source_record_id := source_record_id,
                            observed_at := first_timestamp, question_name := question_name,
                            question_type := question_type)
                ORDER BY evidence_rank) FILTER (WHERE evidence_rank <= evidence_limit) AS evidence
    FROM evidence_ranked
    GROUP BY client_ip, resolver_ip, grouping_domain, window_bucket
), metrics AS (
    SELECT g.*, t.question_types, e.evidence,
           g.last_seen - g.first_seen AS active_span,
           g.query_count::DOUBLE /
               greatest(1.0, epoch_ms(g.last_seen - g.first_seen)::DOUBLE / 60000.0) AS queries_per_minute,
           g.distinct_name_count::DOUBLE / greatest(1.0, g.query_count::DOUBLE) AS unique_name_ratio,
           g.nxdomain_count::DOUBLE / greatest(1.0, g.response_count::DOUBLE) AS nxdomain_ratio,
           g.no_answer_count::DOUBLE / greatest(1.0, g.response_count::DOUBLE) AS no_answer_ratio
    FROM groups g
    LEFT JOIN type_distributions t
      ON g.client_ip = t.client_ip AND g.resolver_ip = t.resolver_ip
     AND g.grouping_domain = t.grouping_domain
     AND g.window_bucket IS NOT DISTINCT FROM t.window_bucket
    LEFT JOIN evidence e
      ON g.client_ip = e.client_ip AND g.resolver_ip = e.resolver_ip
     AND g.grouping_domain = e.grouping_domain
     AND g.window_bucket IS NOT DISTINCT FROM e.window_bucket
), components AS (
    SELECT *,
           100.0 * greatest(0.0, least(1.0, (median_left_payload_length - 12.0) / 40.0)) AS length_score,
           100.0 * coalesce(mean_normalized_entropy, 0.0) AS entropy_score,
           100.0 * coalesce(mean_encoded_character_ratio, 0.0) *
               greatest(0.0, least(1.0, (median_left_payload_length - 12.0) / 20.0)) AS encoded_score,
           100.0 * unique_name_ratio AS uniqueness_score,
           100.0 * greatest(nxdomain_ratio, no_answer_ratio) AS failure_score,
           100.0 * greatest(0.0, least(1.0, queries_per_minute / 30.0)) AS rate_score,
           least(100.0, 50.0 + 50.0 * (query_count - query_limit)::DOUBLE /
                                      greatest(1.0, query_limit::DOUBLE)) AS support_score,
           CASE WHEN epoch_us(span_limit) = 0 THEN 100.0
                ELSE least(100.0, 100.0 * epoch_us(active_span)::DOUBLE / epoch_us(span_limit)::DOUBLE)
                END AS span_score
    FROM metrics
), scored AS (
    SELECT *, 0.20 * length_score + 0.20 * entropy_score + 0.10 * encoded_score +
              0.20 * uniqueness_score + 0.10 * failure_score + 0.10 * rate_score +
              0.05 * support_score + 0.05 * span_score AS score
    FROM components
), ranked AS (
    SELECT row_number() OVER (
               ORDER BY score DESC, query_count DESC, client_ip, resolver_ip, grouping_domain,
                        window_bucket NULLS FIRST
           )::UBIGINT AS rank, *
    FROM scored
    WHERE score >= score_limit
)
SELECT md5(concat_ws('|', 'pq-dns-tunnel-v1', profile_value, client_ip, resolver_ip,
                     grouping_domain, coalesce(window_bucket::VARCHAR, ''), evidence_hash::VARCHAR)) AS finding_id,
       'dns_tunnel' AS detector, 'pq-dns-tunnel-v1' AS detector_version, profile_value AS profile,
       'psl-2023-09-30-02074b85' AS suffix_list_version,
       rank, client_ip, resolver_ip, grouping_domain, public_suffix, registrable_domain,
       suffix_section, suffix_rule,
       coalesce(window_bucket, first_seen) AS window_start,
       CASE WHEN window_bucket IS NULL THEN last_observed ELSE window_bucket + window_value END AS window_end,
       first_seen, last_seen, active_span, query_count, response_count,
       distinct_name_count, distinct_left_payload_count, question_types,
       median_name_length, max_name_length, median_left_payload_length, max_left_payload_length,
       mean_normalized_entropy, mean_encoded_character_ratio,
       nxdomain_count, no_answer_count, nxdomain_ratio, no_answer_ratio,
       queries_per_minute, unique_name_ratio,
       length_score, entropy_score, encoded_score, uniqueness_score, failure_score,
       rate_score, support_score, span_score, score,
       list_filter([
           CASE WHEN length_score >= 75 THEN 'left-of-domain payloads are long' END,
           CASE WHEN entropy_score >= 75 THEN 'left-of-domain payloads have high character entropy' END,
           CASE WHEN encoded_score >= 90 THEN 'left-of-domain payloads resemble hex or base32 text' END,
           CASE WHEN uniqueness_score >= 75 THEN 'most queried names are distinct' END,
           CASE WHEN failure_score >= 50 THEN 'responses frequently fail or contain no answers' END,
           CASE WHEN rate_score >= 75 THEN 'query rate is high' END
       ], lambda reason: reason IS NOT NULL) AS reasons,
       list_filter([
           CASE WHEN has_missing_timestamp THEN 'missing_timestamp' END,
           CASE WHEN has_dns_truncation THEN 'dns_truncated' END,
           CASE WHEN has_unknown_suffix THEN 'unknown_suffix' END,
           CASE WHEN active_span < span_limit THEN 'insufficient_span' END,
           CASE WHEN response_count = 0 THEN 'responses_not_observed' END,
           CASE WHEN query_count > evidence_limit THEN 'evidence_truncated' END,
           'cleartext_dns_only'
       ], lambda flag: flag IS NOT NULL) AS quality_flags,
       coalesce(evidence, []::STRUCT(source_locator VARCHAR, source_record_id VARCHAR,
                                    observed_at TIMESTAMP, question_name VARCHAR,
                                    question_type USMALLINT)[]) AS evidence,
       query_count > evidence_limit AS evidence_truncated
FROM ranked
WHERE rank <= result_limit;
