# RevEng.AI Rizin & Cutter Plugins

[![Build Linux](https://github.com/RevEngAI/reai-rz/workflows/Build%20Linux/badge.svg)](https://github.com/RevEngAI/reai-rz/actions/workflows/build-linux.yml)
[![Build macOS](https://github.com/RevEngAI/reai-rz/workflows/Build%20macOS/badge.svg)](https://github.com/RevEngAI/reai-rz/actions/workflows/build-macos.yml)
[![Build Windows](https://github.com/RevEngAI/reai-rz/workflows/Build%20Windows/badge.svg)](https://github.com/RevEngAI/reai-rz/actions/workflows/build-windows.yml)
[![Docker Build and Test](https://github.com/RevEngAI/reai-rz/workflows/Docker%20Build%20and%20Test/badge.svg)](https://github.com/RevEngAI/reai-rz/actions/workflows/docker-test.yml)

RevEng.AI plugins for Rizin & Cutter that provide AI-powered reverse engineering capabilities including decompilation, function analysis, binary similarity, and more.

## Support

Need help? Join our Discord server: [![Discord](https://img.shields.io/badge/Discord-Join%20Us-7289da?logo=discord&logoColor=white)](https://discord.com/invite/ZwQTvzfSbA)

## Quick Installation (Recommended)

### Prerequisites

- **Rizin** installed and available in PATH
- **Cutter** (optional, for GUI plugin support)

### Platform-Specific Installation

Download the latest release for your platform and run the automated install script:

#### Linux

**x86_64:**
```bash
# Download and extract
wget https://github.com/RevEngAI/reai-rz/releases/latest/download/reai-rz-linux-x86_64.tar.gz
tar -xzf reai-rz-linux-x86_64.tar.gz
cd reai-rz-linux-x86_64

# Install dependencies
sudo apt install patchelf  # Ubuntu/Debian
# sudo dnf install patchelf    # Fedora/RHEL
# sudo pacman -S patchelf      # Arch

# Run installer
chmod +x install-linux.sh
./install-linux.sh
```

**ARM64:**
```bash
# Download and extract
wget https://github.com/RevEngAI/reai-rz/releases/latest/download/reai-rz-linux-aarch64.tar.gz
tar -xzf reai-rz-linux-aarch64.tar.gz
cd reai-rz-linux-aarch64

# Install dependencies
sudo apt install patchelf  # Ubuntu/Debian
# sudo dnf install patchelf    # Fedora/RHEL
# sudo pacman -S patchelf      # Arch

# Run installer
chmod +x install-linux.sh
./install-linux.sh
```

#### macOS
```bash
# Download and extract
curl -L -O https://github.com/RevEngAI/reai-rz/releases/latest/download/reai-rz-macos.tar.gz
tar -xzf reai-rz-macos.tar.gz
cd reai-rz-macos

# Install dependencies
xcode-select --install

# Run installer
chmod +x install-macos.sh
./install-macos.sh
```

#### Windows
```powershell
# Download and extract
Invoke-WebRequest "https://github.com/RevEngAI/reai-rz/releases/latest/download/reai-rz-windows.zip" -OutFile "reai-rz-windows.zip"
Expand-Archive "reai-rz-windows.zip" -Force
cd reai-rz-windows

# Run installer
Set-ExecutionPolicy Bypass -Scope Process -Force; .\install-windows.ps1
```

### What the Install Scripts Do

The automated installation scripts handle all the complex setup:

- **Install libraries** to user directories (`~/.local/lib/` on Unix, `%USERPROFILE%\.local\bin\` on Windows)
- **Install Rizin plugin** to `$(rizin -H RZ_USER_PLUGINS)`
- **Install Cutter plugin** to platform-specific Cutter plugin directories
- **Fix library paths** so plugins can find rizin libraries and dependencies
- **Set up environment variables** for library discovery (Windows: updates system PATH; Unix: creates environment script)
- **Verify installation** and provide status messages

## Configuration

Before using the plugins, create a configuration file in your home directory:

**Unix (Linux/macOS):** `~/.creait`
**Windows:** `%USERPROFILE%\.creait`

```ini
api_key = YOUR_REVENGAI_API_KEY
host = https://api.reveng.ai
```

### Generate Config with Plugin

You can also generate the config file using the plugin itself:

```bash
# In rizin
REi YOUR_API_KEY_HERE
```

Get your API key from [RevEng.AI Portal Settings](https://portal.reveng.ai/settings).

## Usage

### Rizin Command Line

After installation, the plugin commands are available in rizin:

```bash
rizin -AA your_binary
> RE?          # Show all RevEng.AI commands
```

### Cutter GUI

1. **For Linux/macOS**: Run `source ~/.local/bin/reai-env.sh` before launching Cutter
2. **For Windows**: 
   - Usually works automatically after restarting your terminal/PowerShell
   - If plugins don't load, run: `%USERPROFILE%\.local\bin\reai-env.ps1`
3. Launch Cutter and look for RevEng.AI options in the menus

## Manual Build (For Developers)

If you want to build from source or contribute to development:

### Prerequisites

Before building, install:
- **cmake**, **make**, **ninja**, **pkg-config**
- **gcc/g++** (Linux) or **Xcode command line tools** (macOS) or **MSVC build tools** (Windows)
- **libcurl development headers**
- **rizin** with development headers
- **Python 3** with **PyYAML**

### Build Commands

#### Linux/macOS
```bash
# Automated build script
curl -fsSL https://raw.githubusercontent.com/RevEngAI/reai-rz/refs/heads/master/Scripts/Build.sh | bash

# Or manual build
git clone https://github.com/RevEngAI/reai-rz
cd reai-rz
git submodule update --init --recursive

# Build
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_CUTTER_PLUGIN=ON
cmake --build build
cmake --install build --prefix ~/.local
```

#### Windows
```powershell
# Automated build script (from Developer PowerShell)
Set-ExecutionPolicy Bypass -Scope Process -Force; iex (iwr -UseBasicParsing 'https://raw.githubusercontent.com/RevEngAI/reai-rz/refs/heads/master/Scripts/Build.ps1')

# Manual build requires Visual Studio build tools and more setup
```

### Build Options

- `BUILD_CUTTER_PLUGIN=ON/OFF`: Enable Cutter plugin compilation (default: OFF)
- `CMAKE_INSTALL_PREFIX`: Installation prefix (default: system-specific)

## Docker Installation

For isolated environments or when you want a pre-configured setup. The Docker image builds everything from source and supports multiple architectures (x86_64, ARM64).

### Quick Start (Recommended)

```bash
# Build Docker image with your API key
docker build --build-arg REVENG_APIKEY=your-api-key-here -t reai-rz \
    https://github.com/RevEngAI/reai-rz.git

# Run rizin with your binary
docker run -it --rm \
    -v /path/to/your/binary:/home/revengai/binary \
    reai-rz rizin binary
```

### Advanced Usage

```bash
# Clone and build locally (if you want to modify the Dockerfile)
git clone https://github.com/RevEngAI/reai-rz
cd reai-rz

# Build with custom configuration
docker build \
    --build-arg REVENG_APIKEY=your-api-key-here \
    --build-arg REVENG_HOST=https://api.reveng.ai \
    -t reai-rz .

# Run with your binary mounted (example with obscuratron binary)
docker run -it --rm \
    -v ~/Desktop/obscuratron:/home/revengai/binary \
    reai-rz rizin binary

# Run rizin with auto-analysis
docker run -it --rm \
    -v /path/to/your/binary:/home/revengai/binary \
    reai-rz rizin -AA binary

# Run interactively for multiple analyses
docker run -it --rm \
    -v $(pwd):/home/revengai/workspace \
    reai-rz
```

### Using RevEng.AI Commands in Docker

Once rizin is running inside the container, use the RevEng.AI commands:

```bash
# Start rizin with your binary
docker run -it --rm \
    -v ~/Desktop/obscuratron:/home/revengai/binary \
    reai-rz rizin -AA binary

# Inside rizin, use RevEng.AI commands:
[0x00000000]> RE?                    # Show all RevEng.AI commands
```

### Build Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `REVENG_APIKEY` | `CHANGEME` | Your RevEng.AI API key from [portal.reveng.ai](https://portal.reveng.ai/settings) |
| `REVENG_HOST` | `https://api.reveng.ai` | RevEng.AI API endpoint |
| `BRANCH_NAME` | `master` | Git branch to build from |

### Docker Features

- **Built from source**: Compiles rizin and plugins from source for multi-architecture support
- **Multi-architecture**: Supports x86_64 and ARM64 builds
- **Pre-configured**: API key and host are set during build
- **User-local installation**: Everything installed in `/home/revengai/.local`
- **Lightweight runtime**: Multi-stage build keeps final image small
- **Verified setup**: Checks plugin installation during build
- **Usage help**: Shows commands and examples when container starts

## Troubleshooting

### Plugin Not Loading

1. **Check rizin installation**:
   ```bash
   rizin -v
   rizin -H RZ_USER_PLUGINS
   ```

2. **Verify plugin installation**:
   ```bash
   ls "$(rizin -H RZ_USER_PLUGINS)" | grep reai
   ```

3. **Check environment**:
   ```bash
   # Linux/macOS
   source ~/.local/bin/reai-env.sh
   echo $LD_LIBRARY_PATH    # Linux
   echo $DYLD_LIBRARY_PATH  # macOS
   
   # Windows (if automatic setup failed)
   %USERPROFILE%\.local\bin\reai-env.ps1
   echo $env:PATH
   ```

### Library Not Found Errors

1. **Verify library installation**:
   ```bash
   ls ~/.local/lib/libreai.*  # Unix
   ls "%USERPROFILE%\.local\bin\reai.dll"  # Windows
   ```

2. **Check library paths** (Unix):
   ```bash
   # Linux
   patchelf --print-rpath "$(rizin -H RZ_USER_PLUGINS)/libreai_rizin.so"
   
   # macOS
   otool -l "$(rizin -H RZ_USER_PLUGINS)/libreai_rizin.dylib" | grep -A2 LC_RPATH
   ```

### Cutter Issues

- **Use Cutter with bundled rizin** for best compatibility
- **Environment setup**:
  - **Linux/macOS**: Source environment script before launching Cutter: `source ~/.local/bin/reai-env.sh`
  - **Windows**: If plugins don't load, run `%USERPROFILE%\.local\bin\reai-env.ps1` or restart terminal
- Check Cutter plugin directory permissions

### Windows Environment Issues

If plugins don't work after installation:

1. **Restart your terminal/PowerShell** - Windows needs to reload the updated PATH
2. **Check if PATH was updated**:
   ```powershell
   echo $env:PATH | findstr ".local"
   ```
3. **Manually run environment script**:
   ```powershell
   %USERPROFILE%\.local\bin\reai-env.ps1
   ```
4. **Manually add to PATH** if script fails:
   - Open System Properties → Environment Variables
   - Add `%USERPROFILE%\.local\bin` to your user PATH

### Permission Errors

Ensure your user has write permissions to:
- `~/.local/` directory (Unix)
- `%USERPROFILE%\.local\` directory (Windows)
- Current working directory (for temporary files)

## Uninstall

```bash
# Linux/macOS
curl -fsSL https://raw.githubusercontent.com/RevEngAI/reai-rz/refs/heads/master/Scripts/Uninstall.sh | bash

# Windows (from Developer PowerShell)
Set-ExecutionPolicy Bypass -Scope Process -Force; iex (iwr -UseBasicParsing 'https://raw.githubusercontent.com/RevEngAI/reai-rz/refs/heads/master/Scripts/Uninstall.ps1')
```
