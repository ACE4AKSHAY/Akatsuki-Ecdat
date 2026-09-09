@echo off
setlocal DisableDelayedExpansion
set "PYTHONUTF8=1"
pushd "%~dp0" || exit /b 1
set "ECDAT_PYTHON="
for %%V in (3.12 3.11 3.10 3) do (
    if not defined ECDAT_PYTHON (
        py -%%V -c "import sys; sys.exit(sys.version_info[:2].__lt__((3, 10)))" >nul 2>nul
        if not errorlevel 1 set "ECDAT_PYTHON=py -%%V"
    )
)
if not defined ECDAT_PYTHON (
    python -c "import sys; sys.exit(sys.version_info[:2].__lt__((3, 10)))" >nul 2>nul
    if not errorlevel 1 set "ECDAT_PYTHON=python"
)
if not defined ECDAT_PYTHON goto missing_python
%ECDAT_PYTHON% scripts\launcher.py %*
set "ECDAT_EXIT=%errorlevel%"
if "%~1"=="" pause
popd
exit /b %ECDAT_EXIT%

:missing_python
echo Python 3.10 or newer is required. Python 3.12 is recommended.
echo Install Python with its launcher and PATH option, then reopen this file.
echo Optional Windows Package Manager command:
echo winget install --id Python.Python.3.12 --exact
if "%~1"=="" pause
popd
exit /b 1
