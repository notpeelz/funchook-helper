#ifndef FUNCHOOK_HELPER_H
#define FUNCHOOK_HELPER_H

#include <stddef.h>
#include <funchook.h>

#if defined(__has_attribute)
#define __FHH_HAS_ATTRIBUTE(x) __has_attribute(x)
#else
#define __FHH_HAS_ATTRIBUTE(x) 0
#endif

#if defined(__has_builtin)
#define __FHH_HAS_BUILTIN(x) __has_builtin(x)
#else
#define __FHH_HAS_BUILTIN(x) 0
#endif

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202000L
#define __FHH_C2X
#endif

#if defined(__FHH_C2X) && __FHH_HAS_BUILTIN(__builtin_types_compatible_p)
#define FHH_ASSERT_HOOK_SIG_MATCHES(name) \
  static_assert( \
    __builtin_types_compatible_p( \
      typeof(name), \
      typeof(name ## _hook) \
    ), \
    "hook signature doesn't match original function" \
  )
#else
#define FHH_ASSERT_HOOK_SIG_MATCHES(name) ((void)0)
#endif

#define FHH_GET_ORIGINAL_FUNC(name) ((typeof(&name))name ## _hook_state.original_func)

typedef struct {
  funchook_t* funchook_handle;
  void* original_func;
  void* original_func_hooked;
} fhh_hook_state_t;

#define FHH_INSTALL(lib, name) ( \
  fhh_install( \
    lib, \
    #name, \
    (void*)&name ## _hook, \
    &name ## _hook_state \
  ) \
)

#define FHH_UNINSTALL(name) ( \
  fhh_uninstall(&name ## _hook_state) \
)

bool fhh_uninstall(fhh_hook_state_t* hook);

bool fhh_install(
  void* dl_handle,
  char const* name,
  void const* func,
  fhh_hook_state_t* hook_state
);

#endif
