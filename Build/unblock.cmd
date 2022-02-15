@echo on
set solution_dir=%~dp0
powershell.exe "Get-ChildItem -Path '%solution_dir%..\' -Recurse | Unblock-File"