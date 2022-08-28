// process-starter.cpp

// References:
// - https://web.archive.org/web/20101009012531/http://blogs.msdn.com/b/winsdk/archive/2009/07/14/launching-an-interactive-process-from-windows-service-in-windows-vista-and-later.aspx
// - My projects: dll-injector
// - https://stackoverflow.com/questions/4278373/how-to-start-a-process-from-windows-service-into-currently-logged-in-users-sess
//
// Goals:
// - Start an interactive process in the session of the loged-on user from session 0.
// - If the user is elevated (admin or NT-AUTHORITY/SYSTEM), start an un-elevated 
//   process with integrity Medium as another user.
//
// Plan:
// - enumerate processes
// - get token of a process
// - start a process with that token. The session of the new process is determined by the token.
//
// More info:
// There are two types of sessions:
// - LSA Logon Sessions - https://docs.microsoft.com/en-us/windows/win32/secauthn/lsa-logon-sessions
// - Remote Desktop Sessions - https://docs.microsoft.com/en-us/windows/win32/termserv/terminal-services-sessions

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>

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
    if (CSTR_EQUAL == CompareStringW(
      LOCALE_INVARIANT,
      NORM_IGNORECASE,
      procName.data(),
      procName.length() + 1,
      procEntry.szExeFile,
      -1
    )) {
      procId = procEntry.th32ProcessID;
      break;
    }
  } while (Process32NextW(hSnap, &procEntry));


close_hSnap:
  CloseHandle(hSnap);
exit:
  return procId;
}

int main()
{
  constexpr DWORD access_required_for_CreateProcessAsUserW = TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY;
  std::cout << "let's go!" << std::endl;
  constexpr std::wstring_view proc_name_take_token = L"explorer.exe";
  const wchar_t prog_to_call[] = LR"(C:\WINDOWS\system32\cmd.exe)";
  wchar_t cmd_line[] = LR"(C:\WINDOWS\system32\cmd.exe)";
  wchar_t lpDesktop[] = L"";
  int return_value = 0;
  HANDLE h_proc = nullptr;
  HANDLE h_token = nullptr;
  STARTUPINFOW startup_info;
  PROCESS_INFORMATION process_infos{};

  DWORD proc_id = 0;

  while (true) {
    proc_id = GetProcId(proc_name_take_token);
    if (proc_id != 0)
      break;
    Sleep(30);
  }

  std::cout << "taking explorer.exe with PID: " << std::dec << proc_id << std::endl;

  h_proc = OpenProcess(PROCESS_ALL_ACCESS, false, proc_id);

  if (h_proc == nullptr) {
    std::cout << "OpenProcess failed with 0x" << std::hex << GetLastError() << std::endl;
    return_value = 1;
    goto end;
  }


  if (!OpenProcessToken(h_proc, access_required_for_CreateProcessAsUserW, &h_token)) {
    std::cout << "OpenProcessToken failed with 0x" << std::hex << GetLastError() << std::endl;
    return_value = 1;
    goto end;
  }

  startup_info = {
    .cb = sizeof(startup_info),
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
    .hStdError = nullptr
  };

  if (!CreateProcessAsUserW(
    /*[in, optional]      HANDLE                hToken,              */ h_token,
    /*[in, optional]      LPCWSTR               lpApplicationName,   */ prog_to_call,
    /*[in, out, optional] LPWSTR                lpCommandLine,       */ cmd_line,
    /*[in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes, */ nullptr,
    /*[in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,  */ nullptr,
    /*[in]                BOOL                  bInheritHandles,     */ false, // cannot inherit accross sessions (I don't know which sessions (LSA Logon Sessions, or Remote Desktop Sessions). And we also don't want to.
    /*[in]                DWORD                 dwCreationFlags,     */ CREATE_NEW_CONSOLE,
    /*[in, optional]      LPVOID                lpEnvironment,       */ nullptr,
    /*[in, optional]      LPCWSTR               lpCurrentDirectory,  */ nullptr,
    /*[in]                LPSTARTUPINFOW        lpStartupInfo,       */ &startup_info,
    /*[out]               LPPROCESS_INFORMATION lpProcessInformation */ &process_infos
    )) {
    std::cout << "CreateProcessAsUserW failed with 0x" << std::hex << GetLastError() << std::endl;
    return_value = 1;
    goto end;
  }
  CloseHandle(process_infos.hProcess);
  CloseHandle(process_infos.hThread);

  std::cout << "It should have worked." << std::endl;

end:
  if (h_token != nullptr)
    CloseHandle(h_token);
  if (h_proc != nullptr)
    CloseHandle(h_proc);

  return return_value;
}

