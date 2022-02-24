set msbuild_dir=C:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\MSBuild\Current\Bin\amd64
rem "%msbuild_dir%\msbuild.exe" SCCAPI.NET.Core.sln /restore /p:VisualStudioVersion=16.0 /clp:PerformanceSummary;Summary;Verbosity=minimal
"%msbuild_dir%\msbuild.exe" build.all.xml /t:Build /restore /p:VisualStudioVersion=16.0 /clp:PerformanceSummary;Summary;Verbosity=minimal