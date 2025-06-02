#!/bin/bash

# RevEngAI Plugin Installer for Linux
# This script installs the plugins and fixes rpath to point to the correct library locations

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTIFACT_DIR="$SCRIPT_DIR"

echo "=== RevEngAI Plugin Installer for Linux ==="
echo "Script directory: $SCRIPT_DIR"
echo "Artifact directory: $ARTIFACT_DIR"

# Check if we have required tools
if ! command -v patchelf &> /dev/null; then
    echo "❌ Error: patchelf not found. Please install it:"
    echo "  Ubuntu/Debian: sudo apt install patchelf"
    echo "  Fedora/RHEL:   sudo dnf install patchelf"
    echo "  Arch:          sudo pacman -S patchelf"
    exit 1
fi

# Detect user's local library directory
USER_LIB_DIR="$HOME/.local/lib"
mkdir -p "$USER_LIB_DIR"

# Install exact shared libraries from CI artifacts
echo "=== Installing shared libraries ==="

# Install libreai.so (from creait)
LIBREAI_PATH="$ARTIFACT_DIR/libreai.so"
if [ -f "$LIBREAI_PATH" ]; then
    echo "Installing: libreai.so -> $USER_LIB_DIR/"
    cp "$LIBREAI_PATH" "$USER_LIB_DIR/"
    chmod 755 "$USER_LIB_DIR/libreai.so"
    echo "✅ libreai.so installed"
else
    echo "❌ Error: libreai.so not found in artifacts"
    exit 1
fi

# Find and install Rizin plugin
echo "=== Installing Rizin plugin ==="
RIZIN_PLUGIN="$ARTIFACT_DIR/libreai_rizin.so"
if [ -f "$RIZIN_PLUGIN" ]; then
    # Get rizin plugin directory
    RIZIN_PLUGIN_DIR=$(rizin -H RZ_USER_PLUGINS 2>/dev/null) || {
        echo "❌ Error: Could not get rizin plugin directory. Is rizin installed?"
        exit 1
    }
    
    mkdir -p "$RIZIN_PLUGIN_DIR"
    
    echo "Installing Rizin plugin: libreai_rizin.so -> $RIZIN_PLUGIN_DIR/"
    cp "$RIZIN_PLUGIN" "$RIZIN_PLUGIN_DIR/"
    chmod 755 "$RIZIN_PLUGIN_DIR/libreai_rizin.so"
    
    # Fix rpath for Rizin plugin
    echo "Fixing rpath for Rizin plugin..."
    RIZIN_INSTALLED_PLUGIN="$RIZIN_PLUGIN_DIR/libreai_rizin.so"
    
    # Clear existing rpath and add correct one
    # Plugin is at: ~/.local/lib/rizin/plugins/plugin.so
    # Libraries at: ~/.local/lib/librz_*.so
    # So we need: $ORIGIN/../../../lib
    patchelf --set-rpath "\$ORIGIN/../../../lib:$USER_LIB_DIR:/usr/local/lib:/usr/lib" "$RIZIN_INSTALLED_PLUGIN"
    
    echo "✅ Rizin plugin installed and rpath fixed"
else
    echo "❌ Error: libreai_rizin.so not found in artifacts"
    exit 1
fi

# Find and install Cutter plugin
echo "=== Installing Cutter plugin ==="
CUTTER_PLUGIN="$ARTIFACT_DIR/libreai_cutter.so"
if [ -f "$CUTTER_PLUGIN" ]; then
    # Common Cutter plugin directories on Linux
    CUTTER_PLUGIN_DIRS=(
        "$HOME/.local/share/rizin/cutter/plugins/native"
        "$HOME/.config/cutter/plugins/native"
        "$HOME/.local/lib/cutter/plugins"
    )
    
    # Use first existing directory or create the first one
    CUTTER_PLUGIN_DIR="${CUTTER_PLUGIN_DIRS[0]}"
    for dir in "${CUTTER_PLUGIN_DIRS[@]}"; do
        if [ -d "$(dirname "$dir")" ]; then
            CUTTER_PLUGIN_DIR="$dir"
            break
        fi
    done
    
    mkdir -p "$CUTTER_PLUGIN_DIR"
    
    echo "Installing Cutter plugin: libreai_cutter.so -> $CUTTER_PLUGIN_DIR/"
    cp "$CUTTER_PLUGIN" "$CUTTER_PLUGIN_DIR/"
    chmod 755 "$CUTTER_PLUGIN_DIR/libreai_cutter.so"
    
    # Fix rpath for Cutter plugin
    echo "Fixing rpath for Cutter plugin..."
    CUTTER_INSTALLED_PLUGIN="$CUTTER_PLUGIN_DIR/libreai_cutter.so"
    
    # Cutter plugin is too far from libraries for simple relative path
    # Add absolute path to user's lib directory and common system paths
    patchelf --set-rpath "$USER_LIB_DIR:/usr/local/lib:/usr/lib" "$CUTTER_INSTALLED_PLUGIN"
    
    echo "✅ Cutter plugin installed and rpath fixed"
else
    echo "❌ Error: libreai_cutter.so not found in artifacts"
    exit 1
fi

# Create environment setup script
echo "=== Creating environment setup ==="
ENV_SCRIPT="$HOME/.local/bin/reai-env.sh"
mkdir -p "$(dirname "$ENV_SCRIPT")"

cat > "$ENV_SCRIPT" << 'EOF'
#!/bin/bash
# RevEngAI Environment Setup
# Source this script to set up environment for using RevEngAI plugins

# Add library path for plugin discovery
export LD_LIBRARY_PATH="$HOME/.local/lib:$LD_LIBRARY_PATH"

# Add binary path
export PATH="$HOME/.local/bin:$PATH"

echo "RevEngAI environment configured"
echo "Library path: $LD_LIBRARY_PATH"
EOF

chmod +x "$ENV_SCRIPT"

echo ""
echo "🎉 Installation complete!"
echo ""
echo "📋 Summary:"
echo "  • Shared libraries installed to: $USER_LIB_DIR"
echo "    - libreai.so"
echo "  • Rizin plugin installed to: $RIZIN_PLUGIN_DIR"
echo "    - libreai_rizin.so"
echo "  • Cutter plugin installed to: $CUTTER_PLUGIN_DIR"
echo "    - libreai_cutter.so"
echo "  • Environment script created: $ENV_SCRIPT"
echo ""
echo "🚀 To use the plugins:"
echo "  1. For command line rizin: plugins should work automatically"
echo "  2. For Cutter: run 'source $ENV_SCRIPT' before launching Cutter"
echo "  3. Or add to your ~/.bashrc:"
echo "     echo 'source $ENV_SCRIPT' >> ~/.bashrc"
echo "" 