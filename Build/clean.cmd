set msbuild_dir=C:\Windows\Microsoft.NET\Framework64\v4.0.30319
%msbuild_dir%\msbuild.exe build.all.xml /toolsversion:4.0 /t:Clean /p:VisualStudioVersion=17.0 /clp:PerformanceSummary;Summary;Verbosity=diag
