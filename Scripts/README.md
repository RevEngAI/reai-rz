# RevEngAI Plugin Installation Scripts

This directory contains platform-specific installation scripts that properly set up the RevEngAI plugins with correct library paths.

## Available Scripts

### macOS: `install-macos.sh`
- Uses `install_name_tool` to fix rpath in plugins
- Sets up relative paths for Rizin plugin (`@loader_path/../../../lib`)
- Sets up absolute paths for Cutter plugin (since it's in a different directory structure)
- Creates environment script for DYLD_LIBRARY_PATH

### Linux: `install-linux.sh`
- Uses `patchelf` to fix rpath in plugins  
- Sets up relative paths for Rizin plugin (`$ORIGIN/../../../lib`)
- Sets up absolute paths for Cutter plugin
- Creates environment script for LD_LIBRARY_PATH

### Windows: `install-windows.ps1`
- Installs DLLs to user's bin directory
- Installs plugins to appropriate directories
- Updates system PATH permanently
- No rpath fixing needed (Windows DLL search handles this)

## Usage

### From CI Artifacts
1. Download the platform-specific artifact from GitHub Actions
2. Extract the archive
3. Run the appropriate install script:

**macOS/Linux:**
```bash
chmod +x install-*.sh
./install-macos.sh    # or ./install-linux.sh
```

**Windows:**
```powershell
.\install-windows.ps1
```

### Manual Installation
If you build the project locally, you can use these scripts after building:

```bash
# Build the project first
make

# Then run the install script from the Scripts directory
cd Scripts
./install-macos.sh    # or appropriate script for your platform
```

## What the Scripts Do

1. **Install shared libraries** to `~/.local/lib/` (Unix) or `%USERPROFILE%\.local\bin\` (Windows)
2. **Install Rizin plugin** to the directory returned by `rizin -H RZ_USER_PLUGINS`
3. **Install Cutter plugin** to the appropriate platform-specific directory:
   - **macOS**: `~/Library/Application Support/rizin/cutter/plugins/native/`
   - **Linux**: `~/.local/share/rizin/cutter/plugins/native/`
   - **Windows**: `%APPDATA%\rizin\cutter\plugins\native\`
4. **Fix rpath/library paths** so plugins can find the rizin libraries
5. **Create environment script** for easy setup

## Requirements

### macOS
- Xcode command line tools (`xcode-select --install`)
- rizin installed

### Linux
- `patchelf` tool (`sudo apt install patchelf` on Ubuntu)
- rizin installed

### Windows
- PowerShell
- rizin installed

## Troubleshooting

### Plugin not loading
1. Make sure rizin is installed and in PATH
2. Check that the environment script is sourced:
   ```bash
   source ~/.local/bin/reai-env.sh
   ```
3. Verify plugin paths:
   ```bash
   rizin -H RZ_USER_PLUGINS
   ls "$(rizin -H RZ_USER_PLUGINS)"
   ```

### Library not found errors
1. Check library installation:
   ```bash
   ls ~/.local/lib/librz_*
   ```
2. Verify rpath (Unix only):
   ```bash
   # macOS
   otool -l ~/.local/lib/rizin/plugins/libreai_rizin.dylib | grep -A2 LC_RPATH
   
   # Linux  
   patchelf --print-rpath ~/.local/lib/rizin/plugins/libreai_rizin.so
   ```

### Environment variables
Make sure these are set:

**macOS:**
```bash
export DYLD_LIBRARY_PATH="$HOME/.local/lib:$DYLD_LIBRARY_PATH"
```

**Linux:**
```bash
export LD_LIBRARY_PATH="$HOME/.local/lib:$LD_LIBRARY_PATH"
```

**Windows:**
```powershell
$env:PATH = "$env:USERPROFILE\.local\bin;$env:PATH"
``` 