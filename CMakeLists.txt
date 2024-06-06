cmake_minimum_required(VERSION 3.10)
project(MyPcapProject) # プロジェクト名を変更しました。

set(CMAKE_CXX_STANDARD 17)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(${PCAP_INCLUDE_DIRS})

add_executable(myPcapExecutable main.cpp)
set_target_properties(myPcapExecutable PROPERTIES OUTPUT_NAME "myPcapExecutable")

target_include_directories(myPcapExecutable PRIVATE ${PCAP_INCLUDE_DIRS})
target_link_libraries(myPcapExecutable PRIVATE ${PCAP_LIBRARIES})