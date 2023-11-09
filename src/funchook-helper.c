#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <dlfcn.h>
#include "funchook-helper.h"

#if __FHH_HAS_ATTRIBUTE(visibility)
#define FHH_PRIVATE __attribute__((visibility("hidden")))
#else
#define FHH_PRIVATE
#endif

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
