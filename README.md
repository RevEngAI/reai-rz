# RevEng.AI Rizin & Cutter Plugins

RevEng.AI plugins for Rizin & Cutter.

## Installation

Before any of the following commands are executed, you must first build & install
[`creait`](https://github.com/RevEngAI/creait).

``` sh
git clone git@github.com:RevEngAI/reai-rz.git
cd reai-rz
mkdir Build
cd Build
cmake .. -G Ninja -D CMAKE_BUILD_TYPE=Debug
ninja
ninja install # Prepend "sudo" if required, or change prefix path using -D CMAKE_INSTALL_PREFIX=/to/install/path in configure step
```

The above sequence of commands will install rizin & cutter plugins automatically and when you
launch rizin or cutter, the plugins will be automatically loaded. The rizin plugin is a core
plugin so to check whether it's loaded or not, execute the command `Lc` in rizin shell. The
plugin name will be visible as `reai_rizin`

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

After installing rizin plugin, you'll see the following commands listed when you execute the
`RE?` command in rizin shell.

``` sh
Usage: RE<huas?>   # RevEngAI Plugin Commands
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
