#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <windows.h>
#include <psapi.h>

int main(void *formal) {
   /* enum processes and get pid tied to explorer.exe */
   DWORD proc_array_bytes = sizeof(DWORD) * 1024;
   DWORD *proc_array = (DWORD *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, proc_array_bytes);
   DWORD proc_array_needed;
   EnumProcesses(proc_array, proc_array_bytes, &proc_array_needed);

   if (proc_array_needed > proc_array_bytes) {
      proc_array = (DWORD *)HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, proc_array, proc_array_needed);
      proc_array_bytes = proc_array_needed;
      EnumProcesses(proc_array, proc_array_bytes, &proc_array_needed);
   }

   std::size_t pids = proc_array_needed / sizeof(DWORD);

   for (std::size_t i=0; i<pids; ++i) {
      HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, proc_array[i]);

      if (proc == NULL)
         continue;

      char filename[MAX_PATH+1];
      std::memset(&filename[0], 0, MAX_PATH+1);
      DWORD filename_size = GetModuleFileNameExA(proc, nullptr, &filename[0], MAX_PATH);

      std::size_t j=filename_size;
      
      for (j; j!=0; --j)
         if (filename[j] == '\\')
            break;

      ++j;

      if (std::strncmp(&filename[j], "explorer.exe", std::strlen("explorer.exe")) == 0) {
         DWORD found_pid = i;
         break;
      }
   }
      
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
