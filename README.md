# RevEng.AI Rizin & Cutter Plugins

RevEng.AI plugins for Rizin & Cutter.

# Installation

> ⚠️ **Warning:**
>
> Plugins are under development, unstable and not ready for use (except by developers).
>

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

# Features

Working towards first realease, version 0.1 will contain following features :

- [x] Upload and analyse binary
- [x] Local database for keeping track of uploaded and analysed binaries
- [ ] Auto analyse all functions and apply rename from ANN requests
- [ ] find similar functions from a single function (single ANN request)
