cmake_minimum_required(VERSION 3.5)

project(vpn_project)

# Create a sources variable with a link to all cpp files to compile
set (vpn_adu_sou
    src/vpn_adu/main_vpn_adu.cpp
    src/vpn_adu/vpn_adu_flow.cpp
)

# Add an executable with the above sources
add_executable(vpn_adu ${vpn_adu_sou})
target_include_directories(vpn_adu PRIVATE ${PROJECT_SOURCE_DIR}/include)

target_link_libraries(vpn_adu 
    ${PROJECT_SOURCE_DIR}/lib/win/liblibconfig++.dll.a
    ${PROJECT_SOURCE_DIR}/lib/win/libFlow2SE.a 
    ${PROJECT_SOURCE_DIR}/lib/win/libPcapSE.a
    ${PROJECT_SOURCE_DIR}/lib/win/libPacketSE.a 
    ${PROJECT_SOURCE_DIR}/lib/win/libHashSE.a )

