set msbuild_dir=C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\amd64
rem "%msbuild_dir%\msbuild.exe" SCCAPI.NET.Core.sln /t:restore 
rem "%msbuild_dir%\msbuild.exe" build.all.xml /toolsversion:4.0 /t:Build -restore /p:VisualStudioVersion=16.0 /clp:PerformanceSummary;Summary;Verbosity=diag
"%msbuild_dir%\msbuild.exe" build.all.xml /t:Build /p:VisualStudioVersion=16.0 /clp:PerformanceSummary;Summary;Verbosity=diag