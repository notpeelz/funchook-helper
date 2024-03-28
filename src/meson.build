inc = include_directories('.')
deps = [DEP_DL, DEP_FUNCHOOK]
lib = static_library(
  meson.project_name(),
  'funchook-helper.c',
  include_directories: inc,
  dependencies: deps,
)

DEP_FUNCHOOK_HELPER = declare_dependency(
  link_with: lib,
  include_directories: inc,
  dependencies: deps,
)
