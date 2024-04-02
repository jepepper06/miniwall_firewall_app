; Nombre del instalador y el archivo de salida
Name "Miniwall Installer"
OutFile "miniwall_installer.exe"

; Request application privileges for Windows Vista+
RequestExecutionLevel admin

; Definición de las rutas de instalación
InstallDir "$PROGRAMFILES\Miniwall"
InstallDirRegKey HKLM "Software\MiEmpresa\Miniwall" "Install_Dir"

; Página de instalación
; Pages
Page Directory
Page InstFiles

Unicode True
; Sections
Section "Install" SecInstall
  SetOutPath $INSTDIR

  ; Copy your compiled CLI tool executable
  File "target\debug\miniwall.exe"

  EnVar::SetHKLM
  EnVar::AddValue "Path" "$INSTDIR"
  ; Write the uninstaller
  WriteUninstaller "$INSTDIR\uninstall_miniwall.exe"
SectionEnd

Section "Uninstall" SecUninstall
  Delete "$INSTDIR\miniwall.exe"
  Delete "$INSTDIR\firewall.db"
  RMDir /r "$INSTDIR"
  Delete "$INSTDIR\uninstall_miniwall.exe"
SectionEnd