#ifndef AppVersion
  #error AppVersion is required
#endif
#ifndef StageDir
  #error StageDir is required
#endif
#ifndef ChineseMessages
  #error ChineseMessages is required
#endif

[Setup]
AppId=ExeBlueprint.Desktop
AppName=ExeBlueprint
AppVersion={#AppVersion}
AppPublisher=NickYCLin
AppPublisherURL=https://github.com/NickYCLin/exe-blueprint
AppSupportURL=https://github.com/NickYCLin/exe-blueprint/issues
DefaultDirName={localappdata}\Programs\ExeBlueprint
DefaultGroupName=ExeBlueprint
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
DisableProgramGroupPage=yes
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
OutputBaseFilename=ExeBlueprint-v{#AppVersion}-win-x64-setup
UninstallDisplayIcon={app}\ExeBlueprint.exe
CloseApplications=yes
RestartApplications=no
LicenseFile=..\..\LICENSE

[Languages]
Name: "zh-TW"; MessagesFile: "{#ChineseMessages}"
Name: "en"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; Flags: unchecked

[Files]
Source: "{#StageDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\ExeBlueprint"; Filename: "{app}\ExeBlueprint.exe"; WorkingDir: "{userdocs}"
Name: "{autodesktop}\ExeBlueprint"; Filename: "{app}\ExeBlueprint.exe"; WorkingDir: "{userdocs}"; Tasks: desktopicon

[Run]
Filename: "{app}\ExeBlueprint.exe"; Description: "{cm:LaunchProgram,ExeBlueprint}"; WorkingDir: "{userdocs}"; Flags: nowait postinstall skipifsilent
