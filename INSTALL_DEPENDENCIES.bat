@echo off
chcp 65001 >nul
title Installing Dependencies

echo ================================================
echo   Installing Python to EXE Converter dependencies
echo ================================================
echo.

:: Detect Python executable
echo Detecting Python...
where python >nul 2>&1
if %errorlevel%==0 (
    set PY=python
) else (
    where py >nul 2>&1
    if %errorlevel%==0 (
        set PY=py
    ) else (
        echo.
        echo ERROR: Python not found!
        echo Install Python from https://www.python.org/downloads/
        echo.
        pause
        exit /b
    )
)

echo Python detected: %PY%
echo.

echo Updating pip...
%PY% -m pip install --upgrade pip --quiet --user
echo OK!
echo.

echo Installing PyInstaller...
%PY% -m pip install pyinstaller --quiet --user
echo OK!
echo.

echo Installing tkinterdnd2...
%PY% -m pip install tkinterdnd2 --quiet --user
echo OK!
echo.

echo.
echo ================================================
echo          Installation completed!
echo ================================================
echo Press any key to close...
pause >nul
exit /b
