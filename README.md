# RevEng.AI Rizin & Cutter Plugins

[![Build Linux](https://github.com/RevEngAI/reai-rz/workflows/Build%20Linux/badge.svg)](https://github.com/RevEngAI/reai-rz/actions/workflows/build-linux.yml)
[![Build macOS](https://github.com/RevEngAI/reai-rz/workflows/Build%20macOS/badge.svg)](https://github.com/RevEngAI/reai-rz/actions/workflows/build-macos.yml)
[![Build Windows](https://github.com/RevEngAI/reai-rz/workflows/Build%20Windows/badge.svg)](https://github.com/RevEngAI/reai-rz/actions/workflows/build-windows.yml)
[![Create Release](https://github.com/RevEngAI/reai-rz/workflows/Create%20Release/badge.svg)](https://github.com/RevEngAI/reai-rz/actions/workflows/release.yml)

RevEng.AI plugins for Rizin & Cutter.

## Installation

### Docker

Build with:

```bash
git clone https://github.com/revengai/reai-rz &&
cd reai-rz && git submodule update --init --recursive &&
docker build --build-arg REVENG_APIKEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -t reai-rz .
```

Then run rizin with the following command:

```bash
docker run -v {file}:/home/revengai/ -it reai-rz {file}
```

Notes:

- Make sure to put correct value for `REVENG_APIKEY` build arg. You can also change it after installing by
  directly editing the guest config file, or using the `REi` command inside the plugin. Your API key can be found under account settings in the Web Portal.
- You can also use an offline installation or custom host by setting the `REVENG_HOST` variable.

### Manual

The build scripts assume default settings that'll work for most users. For advanced users,
who wish to change the intallation process, they may fetch the script and make modifications
and then perform the installation.

PyYaml is a required dependency for the rizin plugin. If your package manager blocks package
installation from `pip`, then `pipx` will help get an easy installation. `pipx` needs to be
installed from package manager.

```bash
# On Linux/MacOSX
curl -fsSL https://raw.githubusercontent.com/RevEngAI/reai-rz/refs/heads/master/Scripts/Build.sh | bash

# On Windows, from developer powershell (requires MSVC build tools)
Set-ExecutionPolicy Bypass -Scope Process -Force; iex (iwr -UseBasicParsing 'https://raw.githubusercontent.com/RevEngAI/reai-rz/refs/heads/master/Scripts/Build.ps1')
```

### Possible Errors

If you get a segmentation fault after installing the plugin on the first run,
then please make sure that either your current working directory is writable
by current user (the user launching the plugin), or there exist environment
varibles `$TMPDIR` or `$TMP` and those are writable as well.
So it should be either `$PWD` or `$TMP` or `$TMPDIR`.

If you cannot see dialogs or messages when intercting with plugin in cutter UI,
make sure that you have a cutter installation with bundled rizin. If your cutter
installation uses pre-installed rizin, then the way the plugin is written, you'll
end up using rizin's command line plugin through the cutter UI, and will only be
able to see output through the command line. Cutter with bundled rizin is very
important!

If rizin fails to automatically load the plugin, you can

- Open rizin and run `e dir.plugins`. You'll get the exact path where
  rizin expects the plugins to be present. Note the prefix for `/rizin/plugins`.
  It'll be something like `/usr/lib` or `/usr/local/lib`. Now during the plugin
  cmake configure step, provide this prefix path by appending `-D CMAKE_INSTALL_PREFIX=<prefix_path>`
  to the cmake configure command. In my case it looks like this : `cmake -B build -G Ninja -D CMAKE_INSTALL_PREFIX=/usr`

- load it by running the command `L <plugin_path>`. This is usually something like
  `L /usr/local/lib/rizin/plugins/libreai_rizin.so` on a linux based system.
  The exact path is displayed when installing the plugin. You'll need to do this
  all the time btw, on every rizin run. This is not the best solution.

### Dependencies

Before running any of the above commands, you must install cmake, make, ninja, meson, gcc/g++ (if required), pkg-config, libcurl (development package), and [rizin](https://github.com/rizinorg/rizin?tab=readme-ov-file#how-to-build).

## CMake Configure Options

- `BUILD_CUTTER_PLUGIN = ON/OFF` : When enabled will build cutter plugin alongside rizin plugin. By default
  this is set to `OFF`. If you have cutter installed, and want to use the cutter plugin, set this to on
  by adding `-D BUILD_CUTTER_PLUGIN=ON` in the cmake configure step.

## Basic Usage

Before being able to use anything in the plugin, a config file in the user's home
directory is required. Name of file must be `.creait.toml`

```toml
apikey = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"    # Replace this with your own API key
host = "https://api.reveng.ai"                  # API version and base endpoint
```

### Generating Config File In Plugins

This config file can be generated using the `REi` command after plugin installation.
Without a config, the plugin will keep erroring out for all other commands.

`REi <apikey>`

Execute the above command to automatically create a config file similar to the one above.
You can get the api key in `https://portal.reveng.ai/settings` API Key section. The plugin
will automatically reload the new saved configuration

## Uninstall

Assuming you didn't make any changes to `Build.sh` or `Build.ps1` before install, you can directly
execute any one of these commands, depending on your operating system.

```bash
# On Linux/MacOSX
curl -fsSL https://raw.githubusercontent.com/RevEngAI/reai-rz/refs/heads/master/Scripts/Uninstall.sh | bash

# On Windows. Execute this from same directory where "Build.ps1" script was executed.
# Execute in developer powershell (different from powershell)
Set-ExecutionPolicy Bypass -Scope Process -Force; iex (iwr -UseBasicParsing 'https://raw.githubusercontent.com/RevEngAI/reai-rz/refs/heads/master/Scripts/Uninstall.ps1')
```
