// process-starter.cpp

// References:
// - launching an interactive process from windows service in windows vista and
//   later
//   https://web.archive.org/web/20101009012531/http://blogs.msdn.com/b/winsdk/archive/2009/07/14/launching-an-interactive-process-from-windows-service-in-windows-vista-and-later.aspx
// - My projects: dll-injector
// - StackOverflow: How to start a process from windows service into currently
//   logged in user's session
//   https://stackoverflow.com/questions/4278373/how-to-start-a-process-from-windows-service-into-currently-logged-in-users-sess
//
//
// Goals:
// - Start an interactive process in the session of the loged-on user from
//   session 0.
// - If the user is elevated (admin or NT-AUTHORITY/SYSTEM), start an
//   un-elevated process with integrity Medium as another user.
//
//
// Plan:
// - enumerate processes
// - get token of a process
// - start a process with that token. The session of the new process is
//   determined by the token.
//
// More info:
//
// There are two types of sessions:
// - LSA Logon Sessions
//   https://docs.microsoft.com/en-us/windows/win32/secauthn/lsa-logon-sessions
// - Remote Desktop (RD) / Terminal Services (WTS) Sessions
//   https://docs.microsoft.com/en-us/windows/win32/termserv/terminal-services-sessions

// 2022-08-28 23:17
// new Plan:
// - get token of a process
// - (duplicate token with DuplicateTokenEx, because we don't want to change the token of an existing process. I don't know, if this is needed.)
// - Set the WTS Session of the Token with SetTokenInformation
// - do something with window stations and desktops
// ...
//
// more info:
// > If TokenSessionId is set with SetTokenInformation, the application must
// > have the Act As Part Of the Operating System privilege, and the application
// > must be enabled to set the session ID in a token.
// 
// from https://docs.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-token_information_class
//
// - "Act As Part Of the Operating System privilege" is SeTcbPrivilege
// - DuplicateTokenEx not only creates a new handle, but also a new token object.


#include <Windows.h>
#include <TlHelp32.h>
#include <memory>
#include <string>
#include <type_traits>
#include "process-starter/win32_helper.hpp"
#include <nowide/iostream.hpp>
#include <nowide/args.hpp>
#include <sstream>
#include <optional>
#include <thread>
#include <chrono>
#include <variant>
#include <type_traits>


namespace helper_std {
// https://youtu.be/pbkQG09grFw?t=1442
// https://www.open-std.org/jtc1/sc22/wg21/docs/papers/2022/p2590r2.pdf
#if !defined(__cpp_lib_start_lifetime_as)
static_assert(__cplusplus == _MSVC_LANG);
static_assert(__cplusplus >= 202002L);
template <typename T> T *start_lifetime_as(void *p) noexcept {
  const auto bytes = new (p) std::byte[sizeof(T)];
  const auto ptr = reinterpret_cast<T *>(bytes);
  (void)*ptr;
  return ptr;
}
#else
  #error Use std::start_lifetime_as instead of helper_std::start_lifetime_as
#endif
}

namespace process_starter {

DWORD GetProcId(const std::string_view procName_utf8) {

  std::wstring procName = nowide::widen(procName_utf8);
  DWORD procId = 0;
  HANDLE hSnap = nullptr;
  PROCESSENTRY32 procEntry{};
  procEntry.dwSize = sizeof(procEntry);

  assert(procName.data()[procName.length() - 1 + 1] == L'\0');

  hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

  if (hSnap == INVALID_HANDLE_VALUE) {
    nowide::cout << "Cannot create snapshot of process list" << std::endl;
    std::exit(1);
    goto exit;
  }

  if (!Process32FirstW(hSnap, &procEntry))
    goto close_hSnap;

  do {
    if (CSTR_EQUAL == CompareStringW(LOCALE_INVARIANT, NORM_IGNORECASE,
                                     procName.data(), procName.length() + 1,
                                     procEntry.szExeFile, -1)) {
      procId = procEntry.th32ProcessID;
      break;
    }
  } while (Process32NextW(hSnap, &procEntry));

close_hSnap:
  CloseHandle(hSnap);
exit:
  return procId;
}

enum class result : bool { FAIL = false, SUCCESS = true };


result EnableSeTakeOwnershipPrivilegeAndGetUser(PTOKEN_USER* ppTokenUser) {
  result return_value{result::SUCCESS};
  HANDLE h_current_Process{nullptr};
  HANDLE h_current_process_token{nullptr};
  LUID luidSeTakeOwnershipPrivilege{};
  TOKEN_PRIVILEGES tp{};
  PTOKEN_USER pTU{nullptr};
  DWORD dw_required_size{0};
  decltype(GetLastError()) last_error{0};

  if (ppTokenUser == nullptr) {
    return_value = result::FAIL;
    goto end;
  }

  h_current_Process =
      OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId());
  if (h_current_Process == INVALID_HANDLE_VALUE ||
      h_current_Process == nullptr) {
    win32_helper::print_error_message(GetLastError(), "OpenProcess");
    return_value = result::FAIL;
    goto end;
  }
  if (!OpenProcessToken(h_current_Process,
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                        &h_current_process_token) ||
      h_current_process_token == nullptr) {
    win32_helper::print_error_message(GetLastError(), "OpenProcessToken");
    return_value = result::FAIL;
    goto end;
  }

  if (!CloseHandle(h_current_Process)) {
    h_current_Process = nullptr;
    win32_helper::print_error_message(GetLastError(), "CloseHandle");
    return_value = result::FAIL;
    goto end;
  }
  h_current_Process = nullptr;



  static_assert(
      std::is_same_v<
          decltype(SE_TAKE_OWNERSHIP_NAME),
          const wchar_t(&)[sizeof(SE_TAKE_OWNERSHIP_NAME) / sizeof(wchar_t)]>,
      "SE_TAKE_OWNERSHIP_NAME must be a wide string literal, because we use "
      "LookupPrivilegeValueW with the W suffix");
  if (!LookupPrivilegeValueW(nullptr, SE_TAKE_OWNERSHIP_NAME,
                             &luidSeTakeOwnershipPrivilege)) {
    win32_helper::print_error_message(GetLastError(), "LookupPrivilegeValueW");
    return_value = result::FAIL;
    goto end;
  }

  tp.PrivilegeCount = 1;
  tp.Privileges[0].Luid = luidSeTakeOwnershipPrivilege;
  tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  if (!AdjustTokenPrivileges(h_current_process_token, false, &tp, 0, nullptr,
                             nullptr) ||
      (last_error = GetLastError()) != ERROR_SUCCESS) {
    win32_helper::print_error_message(last_error, "AdjustTokenPrivileges");
    return_value = result::FAIL;
    goto end;
  }


  if (!GetTokenInformation(h_current_process_token,
                           TOKEN_INFORMATION_CLASS::TokenUser, nullptr, 0, &dw_required_size)) {
    if ((last_error = GetLastError()) != ERROR_INSUFFICIENT_BUFFER) {
      win32_helper::print_error_message(last_error, "GetTokenInformation");
      return_value = result::FAIL;
      goto end;
    }
    static_assert(std::is_unsigned_v<decltype(dw_required_size)>);
    static_assert(std::is_unsigned_v<SIZE_T>);
    static_assert(sizeof(dw_required_size) < sizeof(SIZE_T));
    void* pAlloc = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dw_required_size);
    if (pAlloc == nullptr) {
      return_value = result::FAIL;
      goto end;
    }
    pTU = helper_std::start_lifetime_as<TOKEN_USER>(pAlloc);
    if (!GetTokenInformation(h_current_process_token, TOKEN_INFORMATION_CLASS::TokenUser,
                             pTU, dw_required_size, &dw_required_size)) {
      win32_helper::print_error_message(GetLastError(), "GetTokenInformation");
      return_value = result::FAIL;
      goto end;
    }

  } else {
    nowide::cout << "GetTokenInformation succeded apperently, even though a "
                    "size of zero was passed to it.\n" << std::flush;
    return_value = result::FAIL;
    goto end;
  }

  *ppTokenUser = pTU;
  pTU = nullptr;


end:
  if (h_current_Process != nullptr)
    return_value = CloseHandle(h_current_Process) ? return_value : result::FAIL;
  if (h_current_process_token != nullptr)
    return_value =
        CloseHandle(h_current_process_token) ? return_value : result::FAIL;
  if (pTU != nullptr)
    return_value = HeapFree(GetProcessHeap(), 0, static_cast<void *>(pTU))
                       ? return_value
                       : result::FAIL;

  return return_value;
}

result TakeOwnerShipOfProcessTokenAndAsignFullAccess(HANDLE hProcess, PHANDLE phToken) {


  // https://learn.microsoft.com/en-us/windows/win32/secauthz/taking-object-ownership-in-c--  the trailing dashes/hyphens are part of the URL

  result return_value{result::SUCCESS};
  HANDLE h_token{nullptr};
  PSECURITY_DESCRIPTOR pSD{nullptr};
  PTOKEN_USER pTU{nullptr};

  //if (!AllocateAndInitializeSid(nullptr, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  //                              &pSID_new_owner)) {
  //  win32_helper::print_error_message(GetLastError(),
  //                                    "AllocateAndInitializeSid");
  //  return_value = result::FAIL;
  //  goto end;
  //}

  if (result::FAIL == EnableSeTakeOwnershipPrivilegeAndGetUser(&pTU)) {
    return_value = result::FAIL;
    goto end;
  }

  
  // Open token with WRITE_OWNER
  if (!OpenProcessToken(hProcess, WRITE_OWNER, &h_token)) {
    nowide::cout << "process token couldn't be opened with WRITE_OWNER, even "
                    "though the Privilege SeTakeOwnershipPrivilege is enabled.\n";
    win32_helper::print_error_message(GetLastError(), "OpenProcess");
    return_value = result::FAIL;
    goto end;
  }
  
  // overwrite owner with current user
 
  pSD =
      (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);
  if (pSD == nullptr) {
    win32_helper::print_error_message(GetLastError(), "LocalAlloc");
    return_value = result::FAIL;
    goto end;
  }
  if (!InitializeSecurityDescriptor(pSD,
                                    SECURITY_DESCRIPTOR_REVISION)) {
    win32_helper::print_error_message(GetLastError(),
                                      "InitializeSecurityDescriptor");
    return_value = result::FAIL;
    goto end;
  }

  if (!SetSecurityDescriptorOwner(pSD, pTU->User.Sid, false)) {
    win32_helper::print_error_message(GetLastError(),
                                      "SetSecurityDescriptorOwner");
    return_value = result::FAIL;
    goto end;
  }

  if (!SetKernelObjectSecurity(h_token, OWNER_SECURITY_INFORMATION, pSD)) {
    win32_helper::print_error_message(GetLastError(),
                                      "SetKernelObjectSecurity");
    return_value = result::FAIL;
    goto end;
  }
  if (!CloseHandle(h_token)) {
    h_token = nullptr;
    win32_helper::print_error_message(GetLastError(), "CloseHandle");
    return_value = result::FAIL;
    goto end;
  }
  h_token = nullptr;

  // TODO: reopen token with READ_CONTROL | WRITE_DAC
  if (!OpenProcessToken(hProcess, READ_CONTROL | WRITE_DAC, &h_token)) {
    nowide::cout << "process token couldn't be opened with READ_CONTROL | "
                    "WRITE_DAC, even though the ownership was taken.\n";
    win32_helper::print_error_message(GetLastError(), "OpenProcess");
    return_value = result::FAIL;
    goto end;
  }


  
  
  // TODO: read permissions, modify permissions, so that the current user has access

  nowide::cout << "Function is not finished --> result::FAIL\n" << std::flush;
  return_value = result::FAIL; // not finished implementing this function. TODO: finish

end:
  if (nullptr != h_token)
    return_value = CloseHandle(h_token) == TRUE ? return_value : result::FAIL;
  if (nullptr != pSD)
    return_value = LocalFree(pSD)==NULL ? return_value : result::FAIL;
  if (nullptr != pTU)
    return_value =
        HeapFree(GetProcessHeap(), 0, pTU) == TRUE ? return_value : result::FAIL;


  return return_value;
}

enum class cmd_decision {
  no,
  as_required,
  yes
};

namespace change_session {
typedef DWORD session_id_t;
static_assert(
    std::is_same_v<decltype(WTSGetActiveConsoleSessionId()), session_id_t>);
struct active_console_session {};
struct dont_change_session {};
typedef std::variant<session_id_t, active_console_session, dont_change_session>
    var;
}// end namespace change_session

result start_process_via_OpenProcessToken(DWORD proc_id,
                                          std::optional<std::string_view> prog_name,
                                          std::optional<std::string_view> cmd_line,
                                          change_session::var change_sess,
                                          cmd_decision cmd_decs_dup_token) {
  constexpr DWORD access_required_for_CreateProcessAsUserW =
      TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;
  //constexpr DWORD access_required_for_CreateProcessAsUserW = MAXIMUM_ALLOWED;
  DWORD access{};
  wchar_t lpDesktop[] = L"";
  result return_value = result::SUCCESS;
  HANDLE h_proc = nullptr;
  HANDLE h_token = nullptr;
  HANDLE h_duplicated_token = nullptr;
  STARTUPINFOW startup_info;
  PROCESS_INFORMATION process_infos{};
  std::wstring prog_name_wstr;
  const wchar_t *prog_name_const_w_str_ptr = nullptr;
  std::unique_ptr<wchar_t[]> cmd_line_buf{nullptr};
  decltype(WTSGetActiveConsoleSessionId()) active_console_session_id = 0;

  if (!prog_name.has_value() && !cmd_line.has_value()) {
    nowide::cout << "Error: Neither prog_name, nor cmd_line has a value.\n"
                 << std::flush;
    return_value = result::FAIL;
    goto end;
  }

  if (prog_name.has_value()) {
    prog_name_wstr = nowide::widen(*prog_name);
    prog_name_const_w_str_ptr = prog_name_wstr.c_str();
  }

  if (cmd_line.has_value()) {
    auto cmd_line_wstr = nowide::widen(*cmd_line);
    static_assert(std::is_same_v<decltype(cmd_line_wstr)::value_type, wchar_t>);
    const std::size_t size_with_terminating_null_in_wchars =
        cmd_line_wstr.size() + 1;

    cmd_line_buf = std::make_unique<wchar_t[]>(
        size_with_terminating_null_in_wchars);

    memcpy(cmd_line_buf.get(), cmd_line_wstr.data(),
           (size_with_terminating_null_in_wchars - 1) * sizeof(wchar_t));

    cmd_line_buf[size_with_terminating_null_in_wchars - 1] = L'\0';
  }


  if (proc_id == 0) {
    h_proc = GetCurrentProcess();
  } else {
    h_proc = OpenProcess(MAXIMUM_ALLOWED, false, proc_id);
  }

  if (h_proc == nullptr) {
    win32_helper::print_error_message(GetLastError(), "OpenProcess");
    return_value = result::FAIL;
    goto end;
  }

  if (!std::holds_alternative<change_session::dont_change_session>(
          change_sess)) {
    if (std::holds_alternative<change_session::active_console_session>(
            change_sess)) {

      active_console_session_id = WTSGetActiveConsoleSessionId();
      if (0xFFFFFFFF == active_console_session_id) {
        nowide::cout << "Error: There is no active console session right now.\n"
                     << std::flush;
        return_value = result::FAIL;
        goto end;
      }
    } else {
      active_console_session_id =
          std::get<change_session::session_id_t>(change_sess);
    }

    nowide::cout << "The ID of the active console session is "
                 << active_console_session_id << "\n"
                 << std::flush;
    switch (cmd_decs_dup_token) {
    case cmd_decision::no:
      nowide::cout
          << "Error: dupplicating tokens is not allowed as per cmd decision. "
             "But it is required for setting the session id.\n";
      return_value = result::FAIL;
      goto end;
      break;
    
    case cmd_decision::as_required:
    case cmd_decision::yes:
      cmd_decs_dup_token = cmd_decision::yes;
      break;
    }
  }

  if (cmd_decs_dup_token == cmd_decision::yes) {
    access = TOKEN_DUPLICATE;
  } else {
    access = access_required_for_CreateProcessAsUserW;
  }

  if (!OpenProcessToken(h_proc, access, &h_token)) {
    win32_helper::print_error_message(GetLastError(), "OpenProcessToken");
    if (result::FAIL ==
        TakeOwnerShipOfProcessTokenAndAsignFullAccess(h_proc, &h_token)) {

      return_value = result::FAIL;
      goto end;
    }
  }

  if (cmd_decs_dup_token == cmd_decision::yes) {
    if (!DuplicateTokenEx(h_token, MAXIMUM_ALLOWED, nullptr,
                          SECURITY_IMPERSONATION_LEVEL::SecurityDelegation,
                          TOKEN_TYPE::TokenPrimary, &h_duplicated_token)) {
      win32_helper::print_error_message(GetLastError(), "DuplicateTokenEx");
      return_value = result::FAIL;
      goto end;
    }
    // close original Handle, because we don't need it anymore
    CloseHandle(h_token);
    h_token = nullptr;
    // move new handle value to variable of old handle
    h_token = h_duplicated_token;
    h_duplicated_token = nullptr;
  }

  if (!std::holds_alternative<change_session::dont_change_session>(
          change_sess)) {

    if (!SetTokenInformation(h_token, TOKEN_INFORMATION_CLASS::TokenSessionId,
                             &active_console_session_id,
                             sizeof(active_console_session_id))) {
      win32_helper::print_error_message(GetLastError(), "SetTokenInformation");
      return_value = result::FAIL;
      goto end;
    }
  }

  startup_info = {.cb = sizeof(startup_info),
                  .lpReserved = nullptr,
                  .lpDesktop = lpDesktop,
                  .lpTitle = nullptr,
                  .dwX = 0,
                  .dwY = 0,
                  .dwXSize = 0,
                  .dwYSize = 0,
                  .dwXCountChars = 0,
                  .dwYCountChars = 0,
                  .dwFillAttribute = 0,
                  .dwFlags = 0,
                  .wShowWindow = 0,
                  .cbReserved2 = 0,
                  .lpReserved2 = nullptr,
                  .hStdInput = nullptr,
                  .hStdOutput = nullptr,
                  .hStdError = nullptr};

  // We set bInheritHandles to false, because we cannot inherit accross sessions
  // (I don't know which sessions: LSA Logon Sessions, or Remote Desktop
  // Sessions). And we also don't want to.

  if (!CreateProcessAsUserW(
          /*hToken*/ h_token, /*lpApplicationName*/ prog_name_const_w_str_ptr,
          /*lpCommandLine*/ cmd_line_buf.get(), /*lpProcessAttributes*/ nullptr,
          /*lpThreadAttributes*/ nullptr, /*bInheritHandles*/ false,
          /*dwCreationFlags*/ CREATE_NEW_CONSOLE, /*lpEnvironment*/ nullptr,
          /*lpCurrentDirectory*/ nullptr, /*lpStartupInfo*/ &startup_info,
          /*lpProcessInformation*/ &process_infos)) {
    win32_helper::print_error_message(GetLastError(), "CreateProcessAsUserW");

    if (!CreateProcessWithTokenW(h_token, 0, prog_name_const_w_str_ptr,
                                 cmd_line_buf.get(), 0, nullptr, nullptr,
                                 &startup_info, &process_infos)) {
      win32_helper::print_error_message(GetLastError(), "CreateProcessWithTokenW");
      return_value = result::FAIL;
      goto end;
    }
  }
  CloseHandle(process_infos.hProcess);
  CloseHandle(process_infos.hThread);


end:
  if (h_duplicated_token != nullptr)
    CloseHandle(h_duplicated_token);
  if (h_token != nullptr)
    CloseHandle(h_token);
  if (h_proc != nullptr)
    CloseHandle(h_proc);

  return return_value;
}

std::pair<result,uint32_t> string_to_uint32(const std::string_view& str) {
  if (str.empty() || str.size() >= 11)
    return {result::FAIL, 0};

  static_assert(sizeof(uint32_t) == 4);
  // 2^32 == 4'294'967'296
  const uint32_t max_number_digits[10] = {4,2,9,4,9,6,7,2,9,6};

  bool must_check_for_max_num = str.size() == 10;
  unsigned index = 0;

  uint32_t out_number = 0;
  for (char c : str) {
    static_assert('0' < '9');
    if (c < '0' || c > '9')
      return {result::FAIL, 0};

    uint32_t digit = c - '0';
    if (must_check_for_max_num) {
      auto max_num_digit = max_number_digits[index];
      ++index;
      if (digit > max_num_digit)
        return {result::FAIL, 0};
      if (digit < max_num_digit)
        must_check_for_max_num = false;
    }

    out_number *= 10;
    out_number += digit;
  }
  return {result::SUCCESS, out_number};
}


int main(int argc, char **argv) {
  nowide::args args(argc, argv);

  DWORD proc_id = 0;
  bool proc_id_set = false;
  bool debug = false;

  std::optional<std::string_view> prog_name_take_token_from{std::nullopt};
  std::optional<std::string_view> program_name{std::nullopt};
  std::optional<std::string_view> cmd_line{std::nullopt};
  change_session::var change_sess{change_session::dont_change_session{}};
  cmd_decision duplicate_token{cmd_decision::as_required};

  constexpr std::string_view OPT_PID{"--pid"};
  constexpr std::string_view OPT_PROGFROM("--process-copy-from");
  constexpr std::string_view OPT_PROGNAME{"--program-name"};
  constexpr std::string_view OPT_CMDLINE{"--cmd-line"};
  constexpr std::string_view OPT_DEBUG{"--debug"};
  constexpr std::string_view OPT_WT_SESSION{"--wt-session"};
  constexpr std::string_view OPT_DUP_TOKEN{"--dup-token"};

  constexpr std::string_view quote_open{"\xC2\xBB"};  // >> U+00BB
  constexpr std::string_view quote_close{"\xC2\xAB"}; // << U+00AB

  for (int i = 1; i < argc; i++) {
    bool next_available = i + 1 < argc;
    if (OPT_PID == argv[i]) {
      if (next_available) {
        uint32_t number = 0;
        result res = result::FAIL;
        auto next_arg = argv[++i];
        std::tie(res, number) = string_to_uint32(next_arg);
        if (res == result::FAIL) {
          nowide::cout << "argument \"" << next_arg << "\" for \"" << OPT_PID
                       << "\" cannot be interpreted as a 32 bit number"
                       << std::endl;
          return 1;
        }
        proc_id_set = true;
        proc_id = number;
      } else {
        nowide::cout << "argument missing for \"" << OPT_PID << "\""
                     << std::endl;
        return 1;
      }
    } else if (OPT_PROGFROM == argv[i]) {
      if (next_available) {
        prog_name_take_token_from.emplace(argv[++i]);
      } else {
        nowide::cout << "argument missing for \"" << OPT_PROGFROM << "\""
                     << std::endl;
        return 1;
      }
    } else if (OPT_PROGNAME == argv[i]) {
      if (next_available) {
        program_name.emplace(argv[++i]);
      } else {
        nowide::cout << "argument missing for \"" << OPT_PROGNAME << "\""
                     << std::endl;
        return 1;
      }
    } else if (OPT_CMDLINE == argv[i]) {
      if (next_available) {
        cmd_line.emplace(argv[++i]);
      } else {
        nowide::cout << "argument missing for \"" << OPT_CMDLINE << "\""
                     << std::endl;
        return 1;
      }
    } else if (OPT_DUP_TOKEN == argv[i]) {
      if (next_available) {
        ++i;
        if (std::string_view{"yes"} == argv[i]) {
          duplicate_token = cmd_decision::yes;
        } else if (std::string_view{"no"} == argv[i]) {
          duplicate_token = cmd_decision::no;
        } else if (std::string_view{"as-required"} == argv[i]) {
          duplicate_token = cmd_decision::as_required;
        } else {
          nowide::cout << "Error: value for option " << quote_open
                       << OPT_DUP_TOKEN << quote_close << " is neither "
                       << quote_open << "yes" << quote_close << " nor "
                       << quote_open << "no" << quote_close << " nor "
                       << quote_open << "as-required" << quote_close << ".\n"
                       << std::flush;
          return 1;
        }
      } else {
        nowide::cout << "argument missing for \"" << OPT_DUP_TOKEN << "\""
                     << std::endl;
        return 1;
      }
    } else if (OPT_WT_SESSION == argv[i]) {
      if (next_available) {
        ++i;
        if (std::string_view{"active"} == argv[i]) {
          change_sess = change_session::active_console_session{};
        } else if (std::string_view{"not-specified"} == argv[i]) {
          change_sess = change_session::dont_change_session{};
        } else {
          uint32_t number = 0;
          result res = result::FAIL;
          std::tie(res, number) = string_to_uint32(argv[i]);

          static_assert(std::is_unsigned_v<change_session::session_id_t> &&
                        std::is_unsigned_v<decltype(number)> &&
                        sizeof(number) == sizeof(change_session::session_id_t));

          if (res == result::FAIL) {
            nowide::cout << "Error: value for option " << quote_open
                         << OPT_WT_SESSION << quote_close << " is neither "
                         << quote_open << "active" << quote_close << " nor "
                         << quote_open << "not-specified" << quote_close
                         << " nor a number.\n"
                         << std::flush;
            return 1;
          } else {
            change_sess = change_session::session_id_t{number};
          }
        }
      } else {
        nowide::cout << "argument missing for \"" << OPT_WT_SESSION << "\""
                     << std::endl;
        return 1;
      }
    } else if (OPT_DEBUG == argv[i]) {
      debug = true;
    } else {
      nowide::cout << "unhandled argument: " << quote_open << argv[i] << quote_close << "." << std::endl;
      return 1;
    }
  }

  if (debug) {
    using namespace std::chrono_literals;
    while (!IsDebuggerPresent()) {
      std::this_thread::sleep_for(10ms);
    }
    DebugBreak();
  }

  nowide::cout << "let's go!" << std::endl;

  if (proc_id_set && prog_name_take_token_from.has_value()) {
    nowide::cout << "The options \"" << OPT_PID << "\" and \"" << OPT_PROGFROM
                 << "\" are mutally exclusive. You cannot specifiy both.\n"
                 << std::flush;
    return 1;
  }

  if (!proc_id_set) {
    std::string_view pn = prog_name_take_token_from.value_or("explorer.exe");
    nowide::cout << "Searching for process with name \""
                 << pn << "\".\n"
                 << std::flush;
    while (true) {
      proc_id = GetProcId(pn);
      if (proc_id != 0)
        break;
      Sleep(30);
    }
  }

  nowide::cout << "taking process with PID: " << std::dec << proc_id
               << std::endl;

  if (result::FAIL ==
      start_process_via_OpenProcessToken(proc_id, program_name, cmd_line, change_sess, duplicate_token))
    return 1;

  nowide::cout << "It should have worked." << std::endl;

  return 0;
}

} // end namespace process_starter

int main(int argc, char **argv) { return process_starter::main(argc, argv); }