; Nombre del instalador y el archivo de salida
Name "Miniwall Installer"
OutFile "miniwall.exe"

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
  File "target\release\firewall.exe"
  File "target\release\daemon.exe"
  File "firewall.db"

  EnVar::SetHKLM
  EnVar::AddValue "Path" "target\release\miniwall.exe"
SectionEnd
Section "Copy to Startup" SecInstall
  SetOutPath "$PROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
  File ""

SectionEnd

Section "Uninstall" SecUninstall
   RMDir /r "$INSTDIR"
SectionEnd