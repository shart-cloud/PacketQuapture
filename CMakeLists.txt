cmake_minimum_required(VERSION 3.5)

set(TARGET_NAME packetquapture)

set(EXTENSION_NAME ${TARGET_NAME}_extension)
set(LOADABLE_EXTENSION_NAME ${TARGET_NAME}_loadable_extension)

project(${TARGET_NAME})

set(CMAKE_CXX_STANDARD "17" CACHE STRING "C++ standard to enforce")
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(src/include)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/traffic_analytics.sql)
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/src/traffic_analytics.sql TRAFFIC_ANALYTICS_SQL_CONTENT)
configure_file(src/include/traffic_analytics_sql.hpp.in
               ${CMAKE_CURRENT_BINARY_DIR}/generated/traffic_analytics_sql.hpp @ONLY)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/dns_analytics.sql)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/public_suffix_list/public_suffix_list.dat)
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/src/dns_analytics.sql DNS_ANALYTICS_SQL_CONTENT)
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/third_party/public_suffix_list/public_suffix_list.dat PUBLIC_SUFFIX_LIST_CONTENT)
configure_file(src/include/dns_analytics_resources.hpp.in
               ${CMAKE_CURRENT_BINARY_DIR}/generated/dns_analytics_resources.hpp @ONLY)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/generated)

set(EXTENSION_SOURCES src/packetquapture_extension.cpp src/traffic_analytics.cpp src/dns_analytics.cpp src/pcap_writer.cpp src/pcap_copy.cpp src/flow_aggregator.cpp src/packet_decoder.cpp src/dns_decoder.cpp src/tcp_reassembly.cpp src/dns_tcp_framer.cpp src/tls_record.cpp src/tls_handshake.cpp src/tls_fingerprint.cpp src/x509_certificate.cpp src/sparse_readahead.cpp)

build_static_extension(${TARGET_NAME} ${EXTENSION_SOURCES})
build_loadable_extension(${TARGET_NAME} " " ${EXTENSION_SOURCES})

install(
  TARGETS ${EXTENSION_NAME}
  EXPORT "${DUCKDB_EXPORT_SET}"
  LIBRARY DESTINATION "${INSTALL_LIB_DIR}"
  ARCHIVE DESTINATION "${INSTALL_LIB_DIR}")
