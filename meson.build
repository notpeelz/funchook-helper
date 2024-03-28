project(
  'funchook-helper',
  'c',
  default_options: [
    'warning_level=3',
    'c_std=c17',
    'default_library=static',
  ],
)

add_project_arguments([
  '-D_GNU_SOURCE',
  '-Wno-pedantic',
  '-Wno-error=unused-function',
  '-Wno-error=unused-parameter',
  '-Wno-error=unused-but-set-parameter',
  '-Wno-error=unused-but-set-variable',
  '-Wno-error=unused-variable',
  '-Wno-error=unused-value',
  '-Wno-error=unused-label',
  '-Wno-error=unused-const-variable',
  '-Wno-error=unused-result',
], language: 'c')

cmake = import('cmake')

opts = cmake.subproject_options()
opts.add_cmake_defines({
  'CMAKE_POSITION_INDEPENDENT_CODE': true,
})
opts.set_install(false)
opts.append_compile_args(
  'c',
  '-Wno-pedantic',
  '-Wno-unused-function',
  '-Wno-unused-parameter',
  '-Wno-implicit-fallthrough',
  '-Wno-sign-compare',
  '-Wno-strict-aliasing',
)
funchook = cmake.subproject('funchook', options: opts)

DEP_FUNCHOOK = funchook.dependency('funchook-static')
DEP_DL = dependency('dl', include_type: 'system')

subdir('src')
