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

#include <iostream>

int main()
{
    std::cout << "Hello World!\n";
}

