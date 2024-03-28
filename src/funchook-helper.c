#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include "funchook-helper.h"

#if __FHH_HAS_ATTRIBUTE(visibility)
#define FHH_PRIVATE __attribute__((visibility("hidden")))
#else
#define FHH_PRIVATE
#endif

static bool find_lowest_load_vaddr(ElfW(Phdr) const* phdr, size_t phnum, ElfW(Addr)* out) {
  bool found = false;
  ElfW(Addr) addr = 0;
  for (size_t i = 0; i < phnum; i++) {
    if (phdr[i].p_type == PT_LOAD) {
      if (!found || phdr[i].p_vaddr < addr) {
        found = true;
        addr = phdr[i].p_vaddr;
      }
    }
  }

  if (found) {
    *out = addr;
    return true;
  }

  return false;
}

static bool find_strtab_ptr(ElfW(Dyn)* dyn, ElfW(Addr)* out) {
  while (dyn->d_tag != DT_NULL) {
    if (dyn->d_tag == DT_STRTAB) {
      *out = dyn->d_un.d_ptr;
      return true;
    }
    dyn++;
  }

  return false;
}

static bool validate_libtool_version(char* s) {
  size_t i = 0;
  bool has_digits = false;

  for (; s[i] != '\0'; i++) {
    if (s[i] >= '0' && s[i] <= '9') {
      has_digits = true;
    } else {
      break;
    }
  }

  if (!has_digits) return false;
  if (s[i] == '\0') return true;
  if (s[i] != '.') return false;
  i++;

  has_digits = false;
  for (; s[i] != '\0'; i++) {
    if (s[i] >= '0' && s[i] <= '9') {
      has_digits = true;
    } else {
      break;
    }
  }

  if (!has_digits) return false;
  if (s[i] == '\0') return true;
  if (s[i] != '.') return false;
  i++;

  has_digits = false;
  for (; s[i] != '\0'; i++) {
    if (s[i] >= '0' && s[i] <= '9') {
      has_digits = true;
    } else {
      break;
    }
  }

  if (!has_digits) return false;
  if (s[i] == '\0') return true;
  return false;
}

static int phdr_callback(struct dl_phdr_info* info, size_t size, void* data) {
  (void)size;

  bool* out = (bool*)data;

  ElfW(Addr) lowest_load_vaddr;
  if (!find_lowest_load_vaddr(info->dlpi_phdr, info->dlpi_phnum, &lowest_load_vaddr)) {
    goto fail;
  }

  for (size_t i = 0; i < info->dlpi_phnum; i++) {
    ElfW(Phdr)* phdr = (ElfW(Phdr)*)info->dlpi_phdr + i;

    if (phdr->p_type == PT_DYNAMIC) {
      ElfW(Dyn)* dyn;
      if (info->dlpi_addr == 0) {
        dyn = (void*)phdr->p_vaddr;
      } else {
        dyn = (void*)(info->dlpi_addr + phdr->p_vaddr - lowest_load_vaddr);
      }

      char* strtab;
      if (!find_strtab_ptr(dyn, (void*)&strtab)) {
        goto fail;
      }

      for (; dyn->d_tag != DT_NULL; dyn++) {
        if (dyn->d_tag == DT_NEEDED) {
          char* soname = strtab + dyn->d_un.d_val;

          static char libc_so[] = "libc.so";
          if (strcmp(soname, libc_so) == 0) {
            goto success;
          }

          if (strstr(soname, libc_so) == soname) {
            char* suffix = &soname[sizeof(libc_so) - 1];
            if (suffix[0] == '.' && validate_libtool_version(suffix + 1)) {
              goto success;
            }
          }
        }
      }
    }
  }

fail:
  *out = false;
  return -1;

success:
  *out = true;
  return -1;
}

static bool has_dynamic_libc() {
  static bool has_libc = false;
  static bool init = false;
  if (!init) {
    init = true;
    dl_iterate_phdr(phdr_callback, &has_libc);
  }
  return has_libc;
}

FHH_PRIVATE
bool fhh_uninstall(fhh_hook_state_t* hook) {
  int rv;

  if (hook == NULL) {
    return false;
  }

  if (hook->funchook_handle == NULL) {
    return false;
  }

  rv = funchook_uninstall(hook->funchook_handle, 0);
  // Ignore memory failures because the original function might've been
  // unmapped from memory.
  if (rv == FUNCHOOK_ERROR_MEMORY_FUNCTION) {
    // XXX: funchook_destroy complains unless we successfully uninstall the hook
    // This is ugly as sin. Sorry...
    int* installed = (int*)hook->funchook_handle;
    *installed = 0;
  } else if (rv != FUNCHOOK_ERROR_SUCCESS) {
    fprintf(stderr, "fhh_helper: funchook_uninstall failed (%d)\n", rv);
  }

  rv = funchook_destroy(hook->funchook_handle);
  if (rv != FUNCHOOK_ERROR_SUCCESS) {
    fprintf(stderr, "fhh_helper: funchook_destroy failed (%d)\n", rv);
  }

  hook->funchook_handle = NULL;
  hook->original_func = NULL;
  hook->original_func_hooked = NULL;
  return true;
}

FHH_PRIVATE
bool fhh_install(
  void* dl_handle,
  char const* name,
  void const* func,
  fhh_hook_state_t* hook_state
) {
  int rv;
  funchook_t* funchook = NULL;

  if (!has_dynamic_libc()) {
    return false;
  }

  // Make sure we don't attempt to install the hook twice
  assert(hook_state->original_func == NULL);

  void* sym = dlsym(dl_handle, name);

  if (sym == NULL) {
    goto fail;
  }

  // Skip if we've already hooked this symbol
  if (hook_state->original_func_hooked == sym) {
    goto fail;
  }

  hook_state->original_func = sym;
  hook_state->original_func_hooked = sym;

  funchook = funchook_create();

  if (funchook == NULL) {
    goto fail;
  }

  rv = funchook_prepare(funchook, &hook_state->original_func, (void*)func);
  if (rv != FUNCHOOK_ERROR_SUCCESS) {
    goto fail;
  }

  rv = funchook_install(funchook, 0);
  if (rv != FUNCHOOK_ERROR_SUCCESS) {
    goto fail;
  }

  hook_state->funchook_handle = funchook;

  return true;

fail:
  if (funchook != NULL) {
    funchook_destroy(funchook);
    funchook = NULL;
  }

  return false;
}
