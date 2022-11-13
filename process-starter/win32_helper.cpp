
#include "process-starter/win32_helper.hpp"
#include <nowide/convert.hpp>
#include <nowide/iostream.hpp>

#if !defined(UNICODE)
#error macro UNICODE is not defined
#endif

#if !defined(_UNICODE)
#error macro _UNICODE is not defined
#endif

constexpr const char8_t UTF_8_test_1[] = u8"ü";
static_assert(sizeof(UTF_8_test_1) == 3);
static_assert(UTF_8_test_1[0] == static_cast<char8_t>(0xC3u));
static_assert(UTF_8_test_1[1] == static_cast<char8_t>(0xBCu));
static_assert(UTF_8_test_1[2] == static_cast<char8_t>(0x0u));

constexpr const char UTF_8_test_2[] = "ü";
static_assert(sizeof(UTF_8_test_2) == 3);
static_assert(UTF_8_test_2[0] == static_cast<char>(0xC3u));
static_assert(UTF_8_test_2[1] == static_cast<char>(0xBCu));
static_assert(UTF_8_test_2[2] == static_cast<char>(0x0u));


static_assert(sizeof(UTF_8_test_1) == sizeof(UTF_8_test_2));

static_assert(TRUE == true);
static_assert(FALSE == false);

namespace process_starter {
namespace win32_helper {

void print_error_message(DWORD error_code, const ::std::string_view &fn_name) {

  LPWSTR wstr_buffer = nullptr;
  DWORD number_of_wchars_without_terminating_nul = ::FormatMessageW(
      FORMAT_MESSAGE_IGNORE_INSERTS // ignore paremeter "Arguments"
          | FORMAT_MESSAGE_FROM_SYSTEM |
          FORMAT_MESSAGE_ALLOCATE_BUFFER, // function allocates buffer using
                                          // LocalAlloc. That means we have to
                                          // use local free
      nullptr,                            // lpSource
      error_code,                         // dwMessageId
      0, // dwLanguageId. Zero means: Try different languages until message is
         // found.
      reinterpret_cast<LPWSTR>(
          &wstr_buffer), // We have to cast, because the argument is interpreted
                         // differently based on flags
      0,                 // nSize. We don't know the size yet
      nullptr);
  if (number_of_wchars_without_terminating_nul == 0) {
    ::nowide::cout << "A message for the error coundn't be generated. "
                      "FormatMessageW() failed with 0x"
                   << ::std::hex << GetLastError() << "\n"
                   << ::std::flush;

  } else {
    if (!fn_name.empty()) {
      ::nowide::cout << fn_name
                     << "() failed with last error code in hexadecimal 0x"
                     << ::std::hex << error_code << ", in decimal "
                     << ::std::dec << error_code
                     << "\n"
                        "Here is the correspondig ";
    }
    ::nowide::cout << "Windows error message: "
                   << ::nowide::narrow(wstr_buffer,
                                       number_of_wchars_without_terminating_nul)
                   << "\n"
                   << ::std::flush;
  }

  if (wstr_buffer != nullptr) {
    if (LocalFree(wstr_buffer) != nullptr) {
      ::nowide::cout << "LocalFree() failed with last error code: 0x"
                     << ::std::hex << ::GetLastError() << "\n"
                     << ::std::flush;
    }
  }
}

} // end namespace win32_helper
} // end namespace process_starter