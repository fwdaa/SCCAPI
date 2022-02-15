set msbuild_dir=C:\Windows\Microsoft.NET\Framework64\v4.0.30319
set msbuild_dir=C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\amd64
"%msbuild_dir%\msbuild.exe" build.all.xml /toolsversion:4.0 /t:Build -restore /p:VisualStudioVersion=16.0 /clp:PerformanceSummary;Summary;Verbosity=diag