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

// return value:
//   true: success
//   false: failure
result start_process_via_OpenProcessToken(DWORD proc_id,
                                          std::optional<std::string_view> prog_name,
                                          std::optional<std::string_view> cmd_line) {
  constexpr DWORD access_required_for_CreateProcessAsUserW =
      TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;
  //constexpr DWORD access_required_for_CreateProcessAsUserW = MAXIMUM_ALLOWED;
  wchar_t lpDesktop[] = L"";
  result return_value = result::SUCCESS;
  HANDLE h_proc = nullptr;
  HANDLE h_token = nullptr;
  STARTUPINFOW startup_info;
  PROCESS_INFORMATION process_infos{};
  std::wstring prog_name_wstr;
  const wchar_t *prog_name_const_w_str_ptr = nullptr;
  std::unique_ptr<wchar_t[]> cmd_line_buf{nullptr};

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

  if (!OpenProcessToken(h_proc, access_required_for_CreateProcessAsUserW,
                        &h_token)) {
    win32_helper::print_error_message(GetLastError(), "OpenProcessToken");
    return_value = result::FAIL;
    goto end;
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
    return_value = result::FAIL;
    goto end;
  }
  CloseHandle(process_infos.hProcess);
  CloseHandle(process_infos.hThread);


end:
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

  constexpr std::string_view OPT_PID{"--pid"};
  constexpr std::string_view OPT_PROGFROM("--process-copy-from");
  constexpr std::string_view OPT_PROGNAME{"--program-name"};
  constexpr std::string_view OPT_CMDLINE{"--cmd-line"};
  constexpr std::string_view OPT_DEBUG{"--debug"};


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
    } else if (OPT_DEBUG == argv[i]) {
      debug = true;
    } else {
      nowide::cout << "unhandled argument: \"" << argv[i] << "\"." << std::endl;
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
      start_process_via_OpenProcessToken(proc_id, program_name, cmd_line))
    return 1;

  nowide::cout << "It should have worked." << std::endl;

  return 0;
}

} // end namespace process_starter

int main(int argc, char **argv) { return process_starter::main(argc, argv); }