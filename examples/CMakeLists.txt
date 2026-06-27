add_executable(scan_self scan_self.cpp)
target_link_libraries(scan_self PRIVATE mooring)

if(MSVC)
    target_compile_options(scan_self PRIVATE /W4 /permissive-)
else()
    target_compile_options(scan_self PRIVATE -Wall -Wextra -Wpedantic)
endif()
