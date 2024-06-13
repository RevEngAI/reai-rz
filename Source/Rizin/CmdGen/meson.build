project('rz_cmdgen', 'c')

cmd_descs_generate_py = files('cmd_descs_generate.py')

# Replace this list of files with your command descriptions
cmd_descs_yaml = files(
  'cmd_descs.yaml',
  'cmd_reai.yaml',
)

# Replace these c/h files with your filenames that you want to generate
cmd_descs_src_c = files('cmd_descs.c', 'cmd_descs.h')

# Generation commands. DO NOT CHANGE until unless you know what you're doing
py3_exe = import('python').find_installation()
r = run_command(py3_exe, '-c', 'import yaml', check: false)
cmd_option = get_option('regenerate_cmds')
has_pyyaml = r.returncode() == 0
if (cmd_option.auto() or cmd_option.enabled()) and has_pyyaml
  cmd_descs_ch = custom_target(
    'cmd_descs.[ch]',
    output: ['cmd_descs.c', 'cmd_descs.h'],
    input: cmd_descs_yaml,
    command: [py3_exe, cmd_descs_generate_py, '--output-dir', '@OUTDIR@', '--src-output-dir', meson.current_source_dir(), '@INPUT@']
  )
elif cmd_option.enabled() and not has_pyyaml
  error('PyYAML python module was not found, but it is required to regenerate cmd_descs.[ch]')
else
  warning('PyYAML python module was not found, using cmd_descs.c/cmd_descs.h from source directory. Install PyYAML (either from your package manager or through pip) if you need to modify cmd_descs files.')
  cmd_descs_ch = cmd_descs_src_c
endif

library('rz_cmdgen', cmd_descs_ch)
