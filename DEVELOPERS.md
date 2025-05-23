# Developers Documentation

# Developing Plugin In Windows

- The `BuildOnWindows.ps1` script not only builds the whole plugin, it also sets up all required dependencies for
  future builds. You just run the script once and then later use parts of it to setup your development environment,
  everytime you want to build either `creait` or `reai-rz`
- My current workflow is :
  - Clone the `reai-rz` repo, or do a git pull to get latest changes.
  - Change into `reai-rz` directory using `cd reai-rz`.
  - Build the plugin using `BuildOnWindows.ps1` script
  - Update development environment by executing the following in current shell (where you want to subsequent builds)
  ```ps1
  $InstallPath = "~\\.local\\RevEngAI\\Rizin\\Install"
  $env:Path = $env:Path + ";$InstallPath;$InstallPath\\bin;$InstallPath\\lib"
  ```
  - Go to cloned `reai-rz` repo, and then use the cmake configure, build and install commands from `BuildOnWindows.ps1` script to build the plugin with your latest changes
  - Configure
  ```ps1
   # Build reai-rz
   cmake -A x64 -B "Build" `
   -G "Visual Studio 17 2022" `
   -D Rizin_DIR="$InstallPath\\lib\\cmake\\Rizin" `
   -D Cutter_DIR="$InstallPath\\lib\\cmake\\Cutter" `
   -D Qt5_DIR="$InstallPath\\lib\\cmake\\Qt5" `
   -D CMAKE_PREFIX_PATH="$InstallPath" `
   -D CMAKE_INSTALL_PREFIX="$InstallPath" `
   -D BUILD_CUTTER_PLUGIN=ON `
   -D CUTTER_USE_QT6=OFF `
   -D CMAKE_C_FLAGS="/TC" `
   -D CMAKE_CXX_FLAGS="/TC" `
   -D CMAKE_POLICY_VERSION_MINIMUM="3.5"
  ```
  - Build
  ```ps1
  cmake --build Build --config Release
  ```
  - Clean
  ```ps1
  cmake --build Build --config Release --target clean
  ```
  - Install
  ```ps1
  cmake --install Build --prefix "$InstallPath" --config Release
  ```

Make sure when you update `creait` code, you build and install it in the same way.
