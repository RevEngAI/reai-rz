# RevEng.AI Rizin & Cutter Plugins

RevEng.AI plugins for Rizin & Cutter.

## Installation

### Docker

Don't want to go through all the manual hassle? We have a dockerfile as well.
Just do :

```bash
git clone https://github.com/revengai/reai-rz && 
cd reai-rz && docker build --no-cache --build-arg apikey=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx -t reai-rz . &&
docker run -v /tmp/userdata:/home/revengai/userdata -it reai-rz
```

This will get you a working installation of the rizin plugin in a single command!

- Store the files you want to access into `/tmp/userdata` directory of host,
  and access these files through `~/userdata` inside the docker container.

- Make sure to put correct value for `apikey` build arg. You can also change it after installing
  though, through directly editing config file, or using the `REi` command inside the plugin.

- This will do a clean build always to make sure you get latest commits of all RevEngAI maintained
  repos. If you don't want to do that, just remove the `--no-cache` flag passed to `docker build ...`

### Manual

PyYaml is a required dependency for the plugin commands. If your package manager manages
python packages instead of `pip`, then `pipx` will help get an easy installation.
`pipx` needs to be installed from package manager.

```sh
# Get plugin or download a release
git clone git@github.com:RevEngAI/reai-rz.git && cd reai-rz

# Configure the build. Remove -G Ninja if you prefer GNU Makefiles (requires make)
cmake -B Build -G Ninja

# Build & Install plugin
ninja -C Build && sudo ninja -C Build install
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

### Command List

After installing rizin plugin, you'll see the following commands listed when you execute the
`RE?` command in rizin shell.

```sh
Usage: RE<imhua?>   # RevEngAI Plugin Commands
| REi XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX # Initialize plugin config.
| REm                     # Get all available models for analysis.
| REh                     # Check connection status with RevEngAI servers.
| REu                     # Upload currently loaded binary to RevEngAI servers.
| REa <prog_name> <cmd_line_args> <ai_model> # Upload and analyse currently loaded binary
| REau[?] <min_confidence>=90 # Auto analyze binary functions using ANN and perform batch rename.
| REap <bin_id>           # Apply already existing RevEng.AI analysis to this binary.
| REd  <fn_name>          # Perform AI Decompilation
| REfl[?]                 # Get & show basic function info for selected binary.
| REfr <old_name> <new_name> # Rename function with given function id to given name.
| REfs <function_name> <min_confidence>=95 # RevEng.AI ANN functions similarity search.
| REart                   # Show RevEng.AI ASCII art.
```

### `REh` : Health Check

Can be used to check connection status with RevEng.AI servers. It is not required to be executed
before using the plugin. This comand does not require a binary opened before it's execution as well.

### `REm` : Get Available AI Models

Creating new analysis requires AI models. Currently available AI models are loaded at the start of the
plugin so an internet connection is required, otherwise a plugin restart is necessary for this command to work.

```
[0x00000000]> REm
binnet-0.3-x86-windows
binnet-0.3-x86-linux
binnet-0.3-x86-macos
binnet-0.3-x86-android
binnet-0.4-x86-windows
binnet-0.4-x86-linux
binnet-0.4-x86-macos
binnet-0.4-x86-android
```

### `REa` : Create Analysis

This command requires an open binary. This will upload a binary to RevEng.AI servers and then
create an analysis for the uploaded binary file. Wait for analysis operation to complete before
using using any related API.

Analysis progress can be tracked in detail on RevEngAI's dashboard. Any command that requires
a binary id will automatically fail and display an analysis status if available.

If you save a rizin project after creating a new analysis, the analysis ID automatically gets
stored in the rizin project and is automatically loaded when you open the project.

### `REau` : Auto Analysis

After analysis is complete, the command will get function matches for all functions in a binary,
that have a confidence greater than that provide as command argument and rename the current names
with best match.

Save your rizin project after performing an auto-analysis. Or when you re-open the binary, apply
the existing analysis using the command below.

### `REap` : Apply Existing Analysis

Anyone with access to an existing analysis can apply the analysis to a binary in the plugin.
This will automatically perfrom function renames for all existing functions in order to
sync names between RevEngAI server and rizin.

If you save a rizin project after creating a new analysis, the analysis ID automatically gets
stored in the rizin project and is automatically loaded when you open the project.

### `REd` : AI Decompiler

This plugin also comes with RevEngAI's AI decompiler. This command can be used to decompile
a function by using it's name.

### `REfl` : Function List

To print the names and boundaries of current functions in the binary in rizin, you do `afl`.
This command is similar to `afl`, but it fetches the names from RevEng.AI servers instead of
rizin project.

### `REfr` : Function Rename

Rename a function in RevEng.AI analysis. Renames function in both rizin and RevEngAI.

### `REfs` : Function Search

Searches for functions similar to provided function and have a confidence greater than
the provided `min_confidence`.

### `REart`

This is the most awesome command. Tag us on twitter with a screenshot of the output of this command :-)
if you like what we're doing here :-)

---

Same features exist in Cutter, just with a nice GUI
