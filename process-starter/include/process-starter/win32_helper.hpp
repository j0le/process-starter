#pragma once
#include <Windows.h>
#include <string>


namespace process_starter {
namespace win32_helper {

void print_error_message(DWORD error_code, const ::std::string_view &fn_name);

} // end namespace win32_helper
} // end namespace process_starter