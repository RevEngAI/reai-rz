#!/bin/bash

# RevEngAI Plugin Installer for macOS
# This script installs the plugins and fixes rpath to point to the correct library locations

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTIFACT_DIR="$SCRIPT_DIR"

echo "=== RevEngAI Plugin Installer for macOS ==="
echo "Script directory: $SCRIPT_DIR"
echo "Artifact directory: $ARTIFACT_DIR"

# Check if we have required tools
if ! command -v install_name_tool &> /dev/null; then
    echo "❌ Error: install_name_tool not found. Please install Xcode command line tools."
    echo "Run: xcode-select --install"
    exit 1
fi

# Detect user's local library directory
USER_LIB_DIR="$HOME/.local/lib"
mkdir -p "$USER_LIB_DIR"

# Install exact shared libraries from CI artifacts
echo "=== Installing shared libraries ==="

# Install libreai.dylib (from creait)
LIBREAI_PATH="$ARTIFACT_DIR/libreai.dylib"
if [ -f "$LIBREAI_PATH" ]; then
    echo "Installing: libreai.dylib -> $USER_LIB_DIR/"
    cp "$LIBREAI_PATH" "$USER_LIB_DIR/"
    chmod 755 "$USER_LIB_DIR/libreai.dylib"
    echo "✅ libreai.dylib installed"
else
    echo "❌ Error: libreai.dylib not found in artifacts"
    exit 1
fi

# Find and install Rizin plugin
echo "=== Installing Rizin plugin ==="
RIZIN_PLUGIN="$ARTIFACT_DIR/libreai_rizin.dylib"
if [ -f "$RIZIN_PLUGIN" ]; then
    # Get rizin plugin directory
    RIZIN_PLUGIN_DIR=$(rizin -H RZ_USER_PLUGINS 2>/dev/null) || {
        echo "❌ Error: Could not get rizin plugin directory. Is rizin installed?"
        exit 1
    }
    
    mkdir -p "$RIZIN_PLUGIN_DIR"
    
    echo "Installing Rizin plugin: libreai_rizin.dylib -> $RIZIN_PLUGIN_DIR/"
    cp "$RIZIN_PLUGIN" "$RIZIN_PLUGIN_DIR/"
    chmod 755 "$RIZIN_PLUGIN_DIR/libreai_rizin.dylib"
    
    # Fix rpath for Rizin plugin
    echo "Fixing rpath for Rizin plugin..."
    RIZIN_INSTALLED_PLUGIN="$RIZIN_PLUGIN_DIR/libreai_rizin.dylib"
    
    # Clear existing rpaths
    install_name_tool -delete_rpath "/Users/runner/.local/lib" "$RIZIN_INSTALLED_PLUGIN" 2>/dev/null || true
    install_name_tool -delete_rpath "/Users/runner/.local/bin" "$RIZIN_INSTALLED_PLUGIN" 2>/dev/null || true
    
    # Add correct rpath relative to plugin location
    # Plugin is at: ~/.local/lib/rizin/plugins/plugin.dylib
    # Libraries at: ~/.local/lib/librz_*.dylib
    # So we need: @loader_path/../../../lib
    install_name_tool -add_rpath "@loader_path/../../../lib" "$RIZIN_INSTALLED_PLUGIN" 2>/dev/null || true
    install_name_tool -add_rpath "$USER_LIB_DIR" "$RIZIN_INSTALLED_PLUGIN" 2>/dev/null || true
    
    echo "✅ Rizin plugin installed and rpath fixed"
else
    echo "❌ Error: libreai_rizin.dylib not found in artifacts"
    exit 1
fi

# Find and install Cutter plugin
echo "=== Installing Cutter plugin ==="
CUTTER_PLUGIN="$ARTIFACT_DIR/libreai_cutter.dylib"
if [ -f "$CUTTER_PLUGIN" ]; then
    # Cutter plugin directory
    CUTTER_PLUGIN_DIR="$HOME/Library/Application Support/rizin/cutter/plugins/native"
    mkdir -p "$CUTTER_PLUGIN_DIR"
    
    echo "Installing Cutter plugin: libreai_cutter.dylib -> $CUTTER_PLUGIN_DIR/"
    cp "$CUTTER_PLUGIN" "$CUTTER_PLUGIN_DIR/"
    chmod 755 "$CUTTER_PLUGIN_DIR/libreai_cutter.dylib"
    
    # Fix rpath for Cutter plugin
    echo "Fixing rpath for Cutter plugin..."
    CUTTER_INSTALLED_PLUGIN="$CUTTER_PLUGIN_DIR/libreai_cutter.dylib"
    
    # Clear existing rpaths
    install_name_tool -delete_rpath "/Users/runner/.local/lib" "$CUTTER_INSTALLED_PLUGIN" 2>/dev/null || true
    install_name_tool -delete_rpath "/Users/runner/.local/bin" "$CUTTER_INSTALLED_PLUGIN" 2>/dev/null || true
    
    # Add correct rpath - Cutter plugin is too far from libraries for relative path
    # So add absolute path to user's lib directory
    install_name_tool -add_rpath "$USER_LIB_DIR" "$CUTTER_INSTALLED_PLUGIN" 2>/dev/null || true
    
    echo "✅ Cutter plugin installed and rpath fixed"
else
    echo "❌ Error: libreai_cutter.dylib not found in artifacts"
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
export DYLD_LIBRARY_PATH="$HOME/.local/lib:$DYLD_LIBRARY_PATH"

# Add binary path
export PATH="$HOME/.local/bin:$PATH"

echo "RevEngAI environment configured"
echo "Library path: $DYLD_LIBRARY_PATH"
EOF

chmod +x "$ENV_SCRIPT"

echo ""
echo "🎉 Installation complete!"
echo ""
echo "📋 Summary:"
echo "  • Shared libraries installed to: $USER_LIB_DIR"
echo "    - libreai.dylib"
echo "  • Rizin plugin installed to: $RIZIN_PLUGIN_DIR"
echo "    - libreai_rizin.dylib"
echo "  • Cutter plugin installed to: $CUTTER_PLUGIN_DIR"
echo "    - libreai_cutter.dylib"
echo "  • Environment script created: $ENV_SCRIPT"
echo ""
echo "🚀 To use the plugins:"
echo "  1. For command line rizin: plugins should work automatically"
echo "  2. For Cutter: run 'source $ENV_SCRIPT' before launching Cutter"
echo "  3. Or add to your ~/.bashrc or ~/.zshrc:"
echo "     echo 'source $ENV_SCRIPT' >> ~/.zshrc"
echo "" 