CREATE MACRO packetquapture_connection_facts(
    path_or_list,
    local_networks,
    tcp_idle_timeout := INTERVAL '5 minutes',
    udp_idle_timeout := INTERVAL '1 minute'
) AS TABLE
WITH raw_flows AS MATERIALIZED (
    SELECT *
    FROM read_flows(
        path_or_list,
        tcp_idle_timeout := tcp_idle_timeout,
        udp_idle_timeout := udp_idle_timeout
    )
), membership AS (
    SELECT *,
           packetquapture_ip_in_cidrs(orig_ip, local_networks) AS a_is_local,
           packetquapture_ip_in_cidrs(resp_ip, local_networks) AS b_is_local
    FROM raw_flows
), oriented AS (
    SELECT *,
           CASE
               WHEN a_is_local IS NULL OR b_is_local IS NULL THEN 'unknown'
               WHEN a_is_local AND b_is_local THEN 'internal'
               WHEN NOT a_is_local AND NOT b_is_local THEN 'external'
               WHEN simultaneous_open OR equal_endpoints THEN 'unknown'
               WHEN a_is_local THEN 'outbound'
               ELSE 'inbound'
           END AS direction
    FROM membership
)
SELECT
    filename AS source_locator,
    input_index::VARCHAR || ':' || flow_id::VARCHAR AS source_record_id,
    input_index AS source_occurrence,
    transport,
    orig_ip AS endpoint_a_ip,
    resp_ip AS endpoint_b_ip,
    orig_port AS endpoint_a_port,
    resp_port AS endpoint_b_port,
    CASE WHEN simultaneous_open OR equal_endpoints THEN 'unknown' ELSE 'a' END AS initiator,
    originator_basis AS initiator_basis,
    first_timestamp,
    last_timestamp,
    duration,
    orig_packets AS a_packets,
    resp_packets AS b_packets,
    orig_captured_bytes AS a_captured_bytes,
    resp_captured_bytes AS b_captured_bytes,
    orig_reported_bytes AS a_reported_bytes,
    resp_reported_bytes AS b_reported_bytes,
    orig_payload_bytes AS a_payload_bytes,
    resp_payload_bytes AS b_payload_bytes,
    handshake_complete,
    partial_session,
    ambiguous,
    finalized_by,
    direction,
    CASE WHEN a_is_local THEN orig_ip WHEN b_is_local THEN resp_ip END AS local_ip,
    CASE WHEN a_is_local THEN resp_ip WHEN b_is_local THEN orig_ip END AS remote_ip,
    CASE WHEN a_is_local THEN orig_port WHEN b_is_local THEN resp_port END AS local_port,
    CASE WHEN a_is_local THEN resp_port WHEN b_is_local THEN orig_port END AS remote_port,
    CASE WHEN a_is_local THEN orig_packets WHEN b_is_local THEN resp_packets END AS local_packets,
    CASE WHEN a_is_local THEN resp_packets WHEN b_is_local THEN orig_packets END AS remote_packets,
    CASE WHEN a_is_local THEN orig_captured_bytes WHEN b_is_local THEN resp_captured_bytes END AS local_captured_bytes,
    CASE WHEN a_is_local THEN resp_captured_bytes WHEN b_is_local THEN orig_captured_bytes END AS remote_captured_bytes,
    CASE WHEN a_is_local THEN orig_reported_bytes WHEN b_is_local THEN resp_reported_bytes END AS local_reported_bytes,
    CASE WHEN a_is_local THEN resp_reported_bytes WHEN b_is_local THEN orig_reported_bytes END AS remote_reported_bytes,
    CASE WHEN a_is_local THEN orig_payload_bytes WHEN b_is_local THEN resp_payload_bytes END AS local_payload_bytes,
    CASE WHEN a_is_local THEN resp_payload_bytes WHEN b_is_local THEN orig_payload_bytes END AS remote_payload_bytes,
    list_filter([
        CASE WHEN missing_timestamp_packets > 0 OR first_timestamp IS NULL THEN 'missing_timestamps' END,
        CASE WHEN late_packets > 0 THEN 'late_packets' END,
        CASE WHEN partial_session THEN 'partial_session' END,
        CASE WHEN ambiguous THEN 'ambiguous_orientation' END,
        CASE WHEN finalized_by IN ('eof', 'section_boundary') THEN 'capture_boundary' END,
        CASE WHEN a_is_local IS NULL OR b_is_local IS NULL THEN 'invalid_address' END
    ], lambda flag: flag IS NOT NULL) AS quality_flags
FROM oriented;

CREATE MACRO _packetquapture_summarize_talkers(
    path_or_list,
    local_networks,
    talker_by,
    metric,
    scope,
    max_results,
    tcp_idle_timeout,
    udp_idle_timeout
) AS TABLE
WITH checked AS (
    SELECT
        CASE WHEN talker_by IN ('host', 'service') THEN talker_by
             ELSE error('summarize_talkers by must be host or service') END AS by_value,
        CASE WHEN metric IN ('payload_bytes', 'captured_bytes', 'reported_bytes', 'packets', 'connections', 'peers')
             THEN metric ELSE error('summarize_talkers metric is not supported') END AS metric_value,
        CASE WHEN scope IN ('all', 'outbound', 'inbound', 'local_remote', 'internal', 'external') THEN scope
             ELSE error('summarize_talkers scope is not supported') END AS scope_value,
        CASE WHEN max_results > 0 THEN max_results::UBIGINT
             ELSE error('summarize_talkers max_results must be positive') END AS result_limit
), facts AS MATERIALIZED (
    SELECT f.*, c.by_value, c.metric_value, c.scope_value, c.result_limit
    FROM packetquapture_connection_facts(path_or_list, local_networks, tcp_idle_timeout, udp_idle_timeout) f,
         checked c
    WHERE c.scope_value = 'all'
       OR f.direction = c.scope_value
       OR (c.scope_value = 'local_remote' AND f.local_ip IS NOT NULL AND f.remote_ip IS NOT NULL)
), endpoints AS (
    SELECT source_locator, source_record_id, direction, first_timestamp, last_timestamp,
           endpoint_a_ip AS endpoint_ip, endpoint_b_ip AS peer_ip,
           transport, endpoint_a_port AS endpoint_port,
           a_packets AS sent_packets, b_packets AS received_packets,
           a_captured_bytes AS sent_captured_bytes, b_captured_bytes AS received_captured_bytes,
           a_reported_bytes AS sent_reported_bytes, b_reported_bytes AS received_reported_bytes,
           a_payload_bytes AS sent_payload_bytes, b_payload_bytes AS received_payload_bytes,
           by_value, metric_value, result_limit
    FROM facts
    WHERE scope_value = 'all' OR direction IN ('internal', 'external', 'outbound')
       OR (direction = 'unknown' AND endpoint_a_ip = local_ip)
    UNION ALL
    SELECT source_locator, source_record_id, direction, first_timestamp, last_timestamp,
           endpoint_b_ip, endpoint_a_ip, transport, endpoint_b_port,
           b_packets, a_packets, b_captured_bytes, a_captured_bytes,
           b_reported_bytes, a_reported_bytes, b_payload_bytes, a_payload_bytes,
           by_value, metric_value, result_limit
    FROM facts
    WHERE scope_value = 'all' OR direction IN ('internal', 'external', 'inbound')
       OR (direction = 'unknown' AND endpoint_b_ip = local_ip)
), totals AS (
    SELECT any_value(by_value) AS by_value, any_value(metric_value) AS metric_value,
           any_value(result_limit) AS result_limit,
           endpoint_ip,
           CASE WHEN by_value = 'service' THEN transport END AS transport,
           CASE WHEN by_value = 'service' THEN endpoint_port END AS port,
           CASE WHEN count(DISTINCT direction) = 1 THEN min(direction) ELSE 'mixed' END AS direction,
           sum(sent_packets)::UBIGINT AS sent_packets,
           sum(received_packets)::UBIGINT AS received_packets,
           sum(sent_packets + received_packets)::UBIGINT AS total_packets,
           sum(sent_captured_bytes)::UBIGINT AS sent_captured_bytes,
           sum(received_captured_bytes)::UBIGINT AS received_captured_bytes,
           sum(sent_captured_bytes + received_captured_bytes)::UBIGINT AS total_captured_bytes,
           sum(sent_reported_bytes)::UBIGINT AS sent_reported_bytes,
           sum(received_reported_bytes)::UBIGINT AS received_reported_bytes,
           sum(sent_reported_bytes + received_reported_bytes)::UBIGINT AS total_reported_bytes,
           sum(sent_payload_bytes)::UBIGINT AS sent_payload_bytes,
           sum(received_payload_bytes)::UBIGINT AS received_payload_bytes,
           sum(sent_payload_bytes + received_payload_bytes)::UBIGINT AS total_payload_bytes,
           count(*)::UBIGINT AS connection_count,
           count(DISTINCT peer_ip)::UBIGINT AS peer_count,
           min(first_timestamp) AS first_seen,
           max(last_timestamp) AS last_seen
    FROM endpoints
    GROUP BY endpoint_ip,
             CASE WHEN by_value = 'service' THEN transport END,
             CASE WHEN by_value = 'service' THEN endpoint_port END
), measured AS (
    SELECT *, CASE metric_value
        WHEN 'payload_bytes' THEN total_payload_bytes
        WHEN 'captured_bytes' THEN total_captured_bytes
        WHEN 'reported_bytes' THEN total_reported_bytes
        WHEN 'packets' THEN total_packets
        WHEN 'connections' THEN connection_count
        WHEN 'peers' THEN peer_count END AS selected_metric_value
    FROM totals
), ranked AS (
    SELECT row_number() OVER (
               ORDER BY selected_metric_value DESC, endpoint_ip, transport NULLS FIRST, port NULLS FIRST
           )::UBIGINT AS rank,
           *
    FROM measured
)
SELECT rank, by_value AS grouping, metric_value AS metric, selected_metric_value,
       endpoint_ip, transport, port, direction,
       sent_packets, received_packets, total_packets,
       sent_captured_bytes, received_captured_bytes, total_captured_bytes,
       sent_reported_bytes, received_reported_bytes, total_reported_bytes,
       sent_payload_bytes, received_payload_bytes, total_payload_bytes,
       connection_count, peer_count, first_seen, last_seen
FROM ranked
WHERE rank <= result_limit;

CREATE MACRO analyze_long_connections(
    path_or_list,
    local_networks,
    scope := 'local_remote',
    min_duration := INTERVAL '1 hour',
    include_partial := true,
    min_score := 0,
    max_results := 1000,
    profile := 'balanced-v1',
    tcp_idle_timeout := INTERVAL '5 minutes',
    udp_idle_timeout := INTERVAL '1 minute'
) AS TABLE
WITH checked AS (
    SELECT
        CASE WHEN scope IN ('all', 'outbound', 'inbound', 'local_remote', 'internal', 'external') THEN scope
             ELSE error('analyze_long_connections scope is not supported') END AS scope_value,
        CASE WHEN min_duration >= INTERVAL '0 microseconds' THEN min_duration
             ELSE error('analyze_long_connections min_duration must be nonnegative') END AS duration_limit,
        CASE WHEN min_score BETWEEN 0 AND 100 THEN min_score::DOUBLE
             ELSE error('analyze_long_connections min_score must be between 0 and 100') END AS score_limit,
        CASE WHEN max_results > 0 THEN max_results::UBIGINT
             ELSE error('analyze_long_connections max_results must be positive') END AS result_limit,
        CASE WHEN profile = 'balanced-v1' THEN profile
             ELSE error('analyze_long_connections profile must be balanced-v1') END AS profile_value
), admitted AS MATERIALIZED (
    SELECT f.*, c.* EXCLUDE (scope_value)
    FROM packetquapture_connection_facts(path_or_list, local_networks, tcp_idle_timeout, udp_idle_timeout) f,
         checked c
    WHERE (c.scope_value = 'all'
        OR f.direction = c.scope_value
        OR (c.scope_value = 'local_remote' AND f.local_ip IS NOT NULL AND f.remote_ip IS NOT NULL))
      AND f.duration >= c.duration_limit
      AND (include_partial OR NOT f.partial_session)
), components AS (
    SELECT *,
           least(100.0, 50.0 + 25.0 * log2(greatest(1.0, epoch_us(duration)::DOUBLE /
                                                        greatest(1.0, epoch_us(duration_limit)::DOUBLE))))
               AS duration_score,
           CASE WHEN NOT partial_session THEN 100.0
                WHEN finalized_by IN ('eof', 'section_boundary') THEN 25.0
                ELSE 40.0 END AS completeness_score
    FROM admitted
), scored AS (
    SELECT *, 0.8 * duration_score + 0.2 * completeness_score AS score
    FROM components
), ranked AS (
    SELECT row_number() OVER (
               ORDER BY score DESC, duration DESC, source_locator, source_record_id
           )::UBIGINT AS rank,
           *
    FROM scored
    WHERE score >= score_limit
)
SELECT md5(concat_ws('|', 'pq-long-v1', profile_value, source_locator, source_record_id)) AS finding_id,
       'long_connection' AS detector, 'pq-long-v1' AS detector_version, profile_value AS profile,
       rank, source_locator, source_record_id, direction, local_ip, remote_ip, local_port, remote_port,
       endpoint_a_ip, endpoint_b_ip, endpoint_a_port, endpoint_b_port, transport,
       first_timestamp, last_timestamp, duration,
       a_packets, b_packets, a_captured_bytes, b_captured_bytes,
       a_reported_bytes, b_reported_bytes, a_payload_bytes, b_payload_bytes,
       handshake_complete, partial_session, ambiguous, finalized_by,
       duration_score, completeness_score, score,
       list_filter([
           CASE WHEN duration_score >= 100 THEN 'observed duration is at least four times the threshold'
                ELSE 'observed duration meets the configured threshold' END,
           CASE WHEN partial_session THEN 'session completeness is limited' END
       ], lambda reason: reason IS NOT NULL) AS reasons,
       quality_flags
FROM ranked
WHERE rank <= result_limit;

CREATE MACRO analyze_beacons(
    path_or_list,
    local_networks,
    scope := 'outbound',
    group_by := 'service',
    "window" := NULL,
    min_connections := 6,
    min_span := INTERVAL '5 minutes',
    min_score := 0,
    max_results := 1000,
    evidence_rows := 8,
    profile := 'balanced-v1',
    tcp_idle_timeout := INTERVAL '5 minutes',
    udp_idle_timeout := INTERVAL '1 minute'
) AS TABLE
WITH checked AS (
    SELECT
        CASE WHEN scope IN ('outbound', 'inbound', 'local_remote') THEN scope
             ELSE error('analyze_beacons scope must be outbound, inbound, or local_remote') END AS scope_value,
        CASE WHEN group_by = 'service' THEN group_by
             ELSE error('analyze_beacons group_by must be service') END AS grouping,
        CASE WHEN min_connections >= 2 THEN min_connections::UBIGINT
             ELSE error('analyze_beacons min_connections must be at least 2') END AS connection_limit,
        CASE WHEN min_span >= INTERVAL '0 microseconds' THEN min_span
             ELSE error('analyze_beacons min_span must be nonnegative') END AS span_limit,
        CASE WHEN min_score BETWEEN 0 AND 100 THEN min_score::DOUBLE
             ELSE error('analyze_beacons min_score must be between 0 and 100') END AS score_limit,
        CASE WHEN max_results > 0 THEN max_results::UBIGINT
             ELSE error('analyze_beacons max_results must be positive') END AS result_limit,
        CASE WHEN evidence_rows >= 0 AND evidence_rows <= 1024 THEN evidence_rows::UBIGINT
             ELSE error('analyze_beacons evidence_rows must be between 0 and 1024') END AS evidence_limit,
        CASE WHEN profile = 'balanced-v1' THEN profile
             ELSE error('analyze_beacons profile must be balanced-v1') END AS profile_value,
        CASE WHEN "window" IS NULL OR "window" > INTERVAL '0 microseconds' THEN "window"
             ELSE error('analyze_beacons window must be positive') END AS window_value
), facts AS MATERIALIZED (
    SELECT f.*, c.* EXCLUDE (scope_value),
           (f.a_payload_bytes + f.b_payload_bytes)::UBIGINT AS payload_bytes,
           CASE WHEN c.window_value IS NULL THEN NULL::TIMESTAMP
                WHEN f.first_timestamp IS NULL THEN NULL::TIMESTAMP
                ELSE time_bucket(c.window_value, f.first_timestamp) END AS window_bucket
    FROM packetquapture_connection_facts(path_or_list, local_networks, tcp_idle_timeout, udp_idle_timeout) f,
         checked c
    WHERE c.grouping = 'service'
      AND (f.direction = c.scope_value
       OR (c.scope_value = 'local_remote' AND f.local_ip IS NOT NULL AND f.remote_ip IS NOT NULL))
), admitted_groups AS (
    SELECT local_ip, remote_ip, remote_port, transport, direction, window_bucket,
           count(*)::UBIGINT AS connection_count,
           count(first_timestamp)::UBIGINT AS timed_connection_count,
           min(first_timestamp) AS first_seen,
           max(first_timestamp) AS last_seen,
           max(last_timestamp) AS last_observed,
           max(connection_limit) AS connection_limit,
           any_value(span_limit) AS span_limit,
           max(score_limit) AS score_limit,
           max(result_limit) AS result_limit,
           max(evidence_limit) AS evidence_limit,
           any_value(profile_value) AS profile_value,
           any_value(window_value) AS window_value,
           bit_xor(hash(source_locator, source_record_id)) AS evidence_hash,
           median(payload_bytes)::DOUBLE AS median_payload_bytes,
           mad(payload_bytes)::DOUBLE AS payload_mad_bytes,
           bool_or(list_contains(quality_flags, 'missing_timestamps')) AS has_missing_timestamps,
           bool_or(list_contains(quality_flags, 'late_packets')) AS has_late_packets,
           bool_or(list_contains(quality_flags, 'partial_session')) AS has_partial_session,
           bool_or(list_contains(quality_flags, 'ambiguous_orientation')) AS has_ambiguous_orientation,
           bool_or(list_contains(quality_flags, 'capture_boundary')) AS has_capture_boundary
    FROM facts
    GROUP BY local_ip, remote_ip, remote_port, transport, direction, window_bucket
    HAVING count(*) >= max(connection_limit)
), distinct_starts AS (
    SELECT DISTINCT local_ip, remote_ip, remote_port, transport, direction, window_bucket, first_timestamp
    FROM facts
    WHERE first_timestamp IS NOT NULL
), intervals AS (
    SELECT *, date_diff('microsecond',
                        lag(first_timestamp) OVER (
                            PARTITION BY local_ip, remote_ip, remote_port, transport, direction, window_bucket
                            ORDER BY first_timestamp
                        ), first_timestamp)::DOUBLE / 1000.0 AS interval_ms
    FROM distinct_starts
), interval_metrics AS (
    SELECT local_ip, remote_ip, remote_port, transport, direction, window_bucket,
           count(interval_ms)::UBIGINT AS interval_count,
           median(interval_ms)::DOUBLE AS median_interval_ms,
           mad(interval_ms)::DOUBLE AS interval_mad_ms,
           quantile_cont(interval_ms, 0.25)::DOUBLE AS interval_q1_ms,
           quantile_cont(interval_ms, 0.75)::DOUBLE AS interval_q3_ms
    FROM intervals
    GROUP BY local_ip, remote_ip, remote_port, transport, direction, window_bucket
), evidence_ranked AS (
    SELECT *, row_number() OVER (
               PARTITION BY local_ip, remote_ip, remote_port, transport, direction, window_bucket
               ORDER BY first_timestamp NULLS LAST, source_locator, source_record_id
           ) AS evidence_rank
    FROM facts
), evidence AS (
    SELECT local_ip, remote_ip, remote_port, transport, direction, window_bucket,
           list(struct_pack(
               source_locator := source_locator,
               source_record_id := source_record_id,
               started_at := first_timestamp,
               payload_bytes := payload_bytes,
               duration := duration
           ) ORDER BY evidence_rank) FILTER (WHERE evidence_rank <= evidence_limit) AS evidence
    FROM evidence_ranked
    GROUP BY local_ip, remote_ip, remote_port, transport, direction, window_bucket
), metrics AS (
    SELECT g.*, i.interval_count, i.median_interval_ms, i.interval_mad_ms,
           i.interval_q1_ms, i.interval_q3_ms,
           CASE WHEN i.interval_q3_ms > i.interval_q1_ms
                THEN (i.interval_q3_ms + i.interval_q1_ms - 2.0 * i.median_interval_ms) /
                     (i.interval_q3_ms - i.interval_q1_ms) END AS interval_bowley_skew,
           e.evidence,
           g.last_seen - g.first_seen AS observation_span
    FROM admitted_groups g
    LEFT JOIN interval_metrics i
      ON g.local_ip = i.local_ip AND g.remote_ip = i.remote_ip
     AND g.remote_port = i.remote_port AND g.transport = i.transport AND g.direction = i.direction
     AND g.window_bucket IS NOT DISTINCT FROM i.window_bucket
    LEFT JOIN evidence e
      ON g.local_ip = e.local_ip AND g.remote_ip = e.remote_ip
     AND g.remote_port = e.remote_port AND g.transport = e.transport AND g.direction = e.direction
     AND g.window_bucket IS NOT DISTINCT FROM e.window_bucket
), components AS (
    SELECT *,
           CASE WHEN interval_count >= 3 AND median_interval_ms > 0
                THEN 100.0 * greatest(0.0, least(1.0, 1.0 - 4.0 * interval_mad_ms / median_interval_ms))
                END AS timing_score,
           100.0 * greatest(0.0, least(1.0,
               1.0 - 2.0 * payload_mad_bytes / greatest(1.0, median_payload_bytes))) AS size_score,
           least(100.0, 50.0 + 50.0 * (connection_count - connection_limit)::DOUBLE /
                                      greatest(1.0, connection_limit::DOUBLE)) AS support_score,
           CASE WHEN epoch_us(span_limit) = 0 THEN 100.0
                ELSE least(100.0, 50.0 * epoch_us(observation_span)::DOUBLE / epoch_us(span_limit)::DOUBLE)
                END AS span_score
    FROM metrics
), scored AS (
    SELECT *, CASE WHEN timing_score IS NOT NULL
                   THEN 0.50 * timing_score + 0.20 * size_score +
                        0.15 * support_score + 0.15 * span_score END AS score
    FROM components
), ranked AS (
    SELECT row_number() OVER (
               ORDER BY score DESC NULLS LAST, connection_count DESC,
                        local_ip, remote_ip, transport, remote_port, direction
           )::UBIGINT AS rank,
           *
    FROM scored
    WHERE (score IS NULL AND score_limit = 0) OR score >= score_limit
)
SELECT md5(concat_ws('|', 'pq-beacon-v1', profile_value, local_ip, remote_ip,
                     transport, remote_port::VARCHAR, direction,
                     coalesce(window_bucket::VARCHAR, ''), evidence_hash::VARCHAR)) AS finding_id,
       'beacon' AS detector, 'pq-beacon-v1' AS detector_version, profile_value AS profile,
       rank, local_ip, remote_ip, remote_port, transport, direction,
       coalesce(window_bucket, first_seen) AS window_start,
       CASE WHEN window_bucket IS NULL THEN last_observed
            ELSE window_bucket + window_value END AS window_end,
       first_seen, last_seen, connection_count, timed_connection_count,
       observation_span, median_interval_ms, interval_mad_ms,
       interval_q1_ms, interval_q3_ms, interval_bowley_skew,
       median_payload_bytes, payload_mad_bytes,
       timing_score, size_score, support_score, span_score, score,
       list_filter([
           CASE WHEN timing_score >= 75 THEN 'connection starts have low interval dispersion' END,
           CASE WHEN size_score >= 75 THEN 'connection payload sizes have low dispersion' END,
           CASE WHEN support_score >= 75 THEN 'connection count provides strong support' END,
           CASE WHEN span_score >= 75 THEN 'observations span the configured minimum' END
       ], lambda reason: reason IS NOT NULL) AS reasons,
       list_filter([
           CASE WHEN has_missing_timestamps THEN 'missing_timestamps' END,
           CASE WHEN has_late_packets THEN 'late_packets' END,
           CASE WHEN has_partial_session THEN 'partial_session' END,
           CASE WHEN has_ambiguous_orientation THEN 'ambiguous_orientation' END,
           CASE WHEN has_capture_boundary THEN 'capture_boundary' END,
           CASE WHEN interval_count IS NULL OR interval_count < 3 THEN 'insufficient_intervals' END,
           CASE WHEN observation_span < span_limit THEN 'insufficient_span' END,
           CASE WHEN connection_count > evidence_limit THEN 'evidence_truncated' END
       ], lambda flag: flag IS NOT NULL) AS quality_flags,
       coalesce(evidence, []::STRUCT(source_locator VARCHAR, source_record_id VARCHAR,
                                    started_at TIMESTAMP, payload_bytes UBIGINT, duration INTERVAL)[]) AS evidence,
       connection_count > evidence_limit AS evidence_truncated
FROM ranked
WHERE rank <= result_limit;
