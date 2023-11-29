project(
  'funchook-helper',
  'c',
  default_options: [
    'warning_level=3',
    'c_std=c17',
    'default_library=static',
  ],
)

files = [
  'src/funchook-helper.c',
]

c_args = [
  '-Wno-pedantic',
  '-Werror',
  '-Wno-error=unused-function',
  '-Wno-error=unused-parameter',
  '-Wno-error=unused-but-set-parameter',
  '-Wno-error=unused-but-set-variable',
  '-Wno-error=unused-variable',
  '-Wno-error=unused-value',
  '-Wno-error=unused-label',
  '-Wno-error=unused-const-variable',
  '-Wno-error=unused-result',
]

cmake = import('cmake')

funchook_opt = cmake.subproject_options()
funchook_opt.add_cmake_defines({
  'CMAKE_POSITION_INDEPENDENT_CODE': true,
})
funchook_opt.set_install(false)
funchook_opt.append_compile_args(
  'c',
  '-Werror',
  '-Wno-pedantic',
  '-Wno-unused-function',
  '-Wno-unused-parameter',
  '-Wno-implicit-fallthrough',
  '-Wno-sign-compare',
  '-Wno-strict-aliasing',
)
funchook = cmake.subproject('funchook', options: funchook_opt)
funchook_dep = funchook.dependency('funchook-static')

dl_dep = dependency('dl', include_type: 'system')

funchook_helper_inc = include_directories('src/include')
funchook_helper_deps = [dl_dep, funchook_dep]

funchook_helper_lib = static_library(
  meson.project_name(),
  files,
  include_directories: funchook_helper_inc,
  dependencies: funchook_helper_deps,
  c_args: c_args,
)

funchook_helper_dep = declare_dependency(
  link_with: funchook_helper_lib,
  include_directories: funchook_helper_inc,
  dependencies: funchook_helper_deps,
)
