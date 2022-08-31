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


namespace process_starter {

DWORD GetProcId(const std::wstring_view procName) {
  DWORD procId = 0;
  HANDLE hSnap = nullptr;
  PROCESSENTRY32 procEntry{};
  procEntry.dwSize = sizeof(procEntry);

  if (procName.data()[procName.length() - 1 + 1] != L'\0')
    goto exit;

  hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

  if (hSnap == INVALID_HANDLE_VALUE)
    goto exit;

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

enum class result : bool { FAIL = false, SUCESS = true };

// return value:
//   true: success
//   false: failure
result start_process_via_OpenProcessToken(DWORD proc_id,
                                          std::wstring_view prog_name,
                                          std::wstring_view cmd_line) {
  constexpr DWORD access_required_for_CreateProcessAsUserW =
      TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;
  wchar_t lpDesktop[] = L"";
  result return_value = result::SUCESS;
  HANDLE h_proc = nullptr;
  HANDLE h_token = nullptr;
  STARTUPINFOW startup_info;
  PROCESS_INFORMATION process_infos{};
  std::wstring prog_name_str{prog_name};
  std::unique_ptr<wchar_t[]> cmd_line_buf;

  {
    static_assert(std::is_same_v<decltype(cmd_line)::value_type, wchar_t>);
    const std::size_t size_with_terminating_null_in_wchars =
        cmd_line.size() + 1;

    cmd_line_buf = std::make_unique<decltype(cmd_line)::value_type[]>(
        size_with_terminating_null_in_wchars);

    memcpy(cmd_line_buf.get(), cmd_line.data(),
           (size_with_terminating_null_in_wchars - 1) * sizeof(wchar_t));

    cmd_line_buf[size_with_terminating_null_in_wchars - 1] = L'\0';
  }

  h_proc = OpenProcess(PROCESS_ALL_ACCESS, false, proc_id);

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
          /*hToken*/ h_token, /*lpApplicationName*/ prog_name_str.c_str(),
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



int main() {
  nowide::cout << "let's go!" << std::endl;
  constexpr std::wstring_view proc_name_take_token = L"explorer.exe";
  constexpr std::wstring_view prog_to_call =
      LR"(C:\WINDOWS\system32\cmd.exe)";
  constexpr std::wstring_view cmd_line = LR"(C:\WINDOWS\system32\cmd.exe)";

  DWORD proc_id = 0;

  while (true) {
    proc_id = GetProcId(proc_name_take_token);
    if (proc_id != 0)
      break;
    Sleep(30);
  }

  nowide::cout << "taking explorer.exe with PID: " << std::dec << proc_id
               << std::endl;

  if (result::FAIL ==
      start_process_via_OpenProcessToken(proc_id, prog_to_call, cmd_line))
    return 1;

  nowide::cout << "It should have worked." << std::endl;

  return 0;
}

} // end namespace process_starter

int main() { return process_starter::main(); }