@echo off
cd /d "%~dp0"
set TOOLSURVEY_PORT=8113
..\..\runtime\python.exe releases\1\main.py
