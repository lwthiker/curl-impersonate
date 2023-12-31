REM Usage: dll2lib [32|64] some-file.dll
REM
REM Generates some-file.lib from some-file.dll, making an intermediate
REM some-file.def from the results of dumpbin /exports some-file.dll.
REM Currently must run without path on DLL.
REM (Fix by removing path when of lib_name for LIBRARY line below?)
REM
REM Requires 'dumpbin' and 'lib' in PATH - run from VS developer prompt.
REM
REM Script inspired by http://stackoverflow.com/questions/9946322/how-to-generate-an-import-library-lib-file-from-a-dll
SETLOCAL
if "%1"=="32" (set machine=x86) else (set machine=x64)
set dll_file=%2
set dll_file_no_ext=%dll_file:~0,-4%
set exports_file=%dll_file_no_ext%-exports.txt
set def_file=%dll_file_no_ext%.def
set lib_file=%dll_file_no_ext%.lib
set lib_name=%dll_file_no_ext%

dumpbin /exports %dll_file% > %exports_file%

echo LIBRARY %lib_name% > %def_file%
echo EXPORTS >> %def_file%
for /f "skip=19 tokens=1,4" %%A in (%exports_file%) do if NOT "%%B" == "" (echo %%B @%%A >> %def_file%)

lib /def:%def_file% /out:%lib_file% /machine:%machine%

REM Clean up temporary intermediate files
del %exports_file% %def_file% %dll_file_no_ext%.exp
