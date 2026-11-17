@echo off
rem Usage: packaging\windows.bat [executable [destination [APKiD-checkout]]]
rem Defaults: build\bin\Release\cxapkid.exe (or build\bin\cxapkid.exe),
rem release\windows, dep\APKiD. The destination must not exist.
rem Python 3 is needed only for packaging. No build or download is performed.
setlocal
if defined PYTHON goto custom_python
py -3 --version >nul 2>nul
if not errorlevel 1 goto python_launcher
python -c "import sys; sys.exit(sys.version_info[0] != 3)" >nul 2>nul
if not errorlevel 1 goto python_command
echo cxapkid package: Python 3 is required; set PYTHON to its executable path 1>&2
exit /b 1

:custom_python
"%PYTHON%" "%~dp0..\cmake\package_cxapkid.py" --platform windows %*
exit /b %errorlevel%

:python_launcher
py -3 "%~dp0..\cmake\package_cxapkid.py" --platform windows %*
exit /b %errorlevel%

:python_command
python "%~dp0..\cmake\package_cxapkid.py" --platform windows %*
exit /b %errorlevel%
