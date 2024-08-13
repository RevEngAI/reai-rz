# RevEng.AI Rizin & Cutter Plugins

RevEng.AI plugins for Rizin & Cutter.

## Installation

PyYaml is a required dependency for the plugin commands. If your package manager manages
python packages instead of `pip`, then `pipx` will help get an easy installation.
`pipx` needs to be installed from package manager.

``` sh
# Get plugin or download a release
git clone git@github.com:RevEngAI/reai-rz.git && cd reai-rz

# Configure the build. Remove -G Ninja if you prefer GNU Makefiles (requires make)
cmake -B Build -G Ninja

# Build & Install plugin
ninja -C Build && sudo ninja -C Build install
```

### Dependencies

Before running any of the above commands, you must install cmake, make, ninja, meson, gcc/g++ (if required), pkg-config, libcurl (development package), sqlite3 (development package) and [rizin](https://github.com/rizinorg/rizin?tab=readme-ov-file#how-to-build).

If while running rizin, you get address sanitizer (ASAN) issues, reconfigure rizin build again with `-bsanitize=address` and pass a `-D CMAKE_BUILD_TYPE=Debug` when building this plugin.

## CMake Configure Options

- `AUTOINSTALL_REQUIRED = ON/OFF` : When enabled, will automatically fetch required dependencies to build plugin. `ON` by default.
- `BUILD_RIZIN_PLUGIN_ONLY = ON/OFF` : When enabled will build rizin plugin only. This is useful when you only have rizin installed. `ON` by default.

## Basic Usage

Before being able to use anything in the plugin, a config file in the user's home
directory is required.

``` toml
apikey = "libr3" # Replace this with your own API key
host = "https://api.reveng.ai/v1"
model = "binnet-0.3-x86"
db_dir_path = "/home/<user>/.reai"
log_dir_path = "/tmp"
```

### Generating Config File

This config file can be generated using the `REi` command after plugin installation.
Without a config, the plugin will keep erroring out for all other commands.  

`REi https://api.reveng.ai/v1 <apikey> binnet-0.3`  

Execute the above command to automatically create a config file similar to the one above.
You can get the api key in `https://portal.reveng.ai/settings` API Key section. Once
the config file is generated, exit rizin using `q` command and then run rizin again.

### Command List

After installing rizin plugin, you'll see the following commands listed when you execute the
`RE?` command in rizin shell.

``` sh
Usage: RE<ihuas?>   # RevEngAI Plugin Commands
| REi <host> <api_key> <model> # Initialize plugin config.
| REh                     # Check connection status with RevEngAI servers.
| REu                     # Upload currently loaded binary to RevEngAI servers.
| REa                     # Upload and analyse currently loaded binary
| REau[?] <distance>=0.1 <results_per_function>=5 <min_confidence>=0.95 # Auto analyze binary functions using ANN and perform batch rename.
| REs[?] [<binary_id>]    # Get analysis status of given binary id
| REfl[?]                 # Get & show basic function info for selected binary.
| REfr <function_id> <new_name> # Rename function with given function id to given name.
```

### `REh` : Health Check

Can be used to check connection status with RevEng.AI servers. It is not required to be executed
before using the plugin. This comand does not require a binary opened before it's execution as well.
For any of the following commands, you atleast need a binary file opened.

### `REu` : Upload Binary

You can open a binary file in rizin using `o /path/to/binary/file`. Then run `aaaa` to perform all
available analysis in rizin. This is required if you want to create an analysis on RevEng.AI as well.
This will detect all the function boundaries and will help the plugin send correct values to RevEng.AI.

To upload the currently opened binary, you run the command `REu`.

### `REa` : Create Analysis

This command requires an open binary as well. This will upload a binary to RevEng.AI servers if not
already uploaded and then create an analysis for the uploaded binary file. A background worker
thread keeps updating the analysis status after some interval (if required).

During the upload operation, if multiple binaries exist with same file path, then the one with latest
upload time will be used. In future versions this can be tackled by providing user the list of hashes
and upload time they want to select from.

### `REs` : Get Analysis Status

This will check the analysis status of currently opened binary and print it on the terminal.

### `REau` : Auto Analysis

After analysis is complete, the command will get function matches for all functions in a binary,
(with default values displayed in the command itself), and rename the current names with best match,
having maximum confidence (above the given confidence level).

After perform an auto analysis, it is highly recommended to save the project to a project file.
If the name of your project is "my_awesome_ai_analysis", you'll use the command `Ps my_awesome_ai_analysis.rzdb`.
This will make sure all the function renames are properly saved and will be loaded back when you
reopen the project. In other words, this is a required step if you want to work later on with your
project and be in sync with RevEng.AI servers. Not performing this will lead to inconsistencies.

To reopen your project, you need `Po my_awesome_analysis.rzdb`

> ⚠️ **Warning:**
>
> For now the auto-analysis feature is a fire and forget style command. It will indiscriminately
> rename all detected functions in your project.
>

### `REfl` : Function List

To print the names and boundaries of current functions in the binary in rizin, you do `afl`.
This command is similar to `afl`, but it fetches the names from RevEng.AI servers instead of
rizin project.

### `REfr` : Function Rename

Rename a function in RevEng.AI analysis.
