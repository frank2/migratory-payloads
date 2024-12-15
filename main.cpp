#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <windows.h>
#include <psapi.h>

int main(int argc, char *argv[]) {
   /* enum processes and get pid tied to explorer.exe */
   DWORD proc_array_bytes = 0;
   EnumProcesses(nullptr, 0, &proc_array_bytes);

   proc_array_bytes += sizeof(DWORD) * 16;
   
   DWORD *proc_array = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, proc_array_bytes);
   assert(EnumProcesses(proc_array, proc_array_bytes, &proc_array_bytes));
   /* open pid with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE
    * allocate space for our executable
    * copy the executable in memory and relocate it to the allocated base
    * write the relocated executable to the process's allocation with WriteProcessMemory
    * get the rva of the loader and call it with CreateRemoteThread
    * wait for the thread to finish
    * get the rva of the target routine and call it with CreateRemoteThread and the current pid as the arg
    * exit the process
    */

   return 0;
}
