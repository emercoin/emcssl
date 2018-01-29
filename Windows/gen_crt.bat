@echo off
echo Generate emcssl certificate from template *.tpl


SET PATH=%PATH%;%~dp0\openssl-1.0.2a-i386-win32;%~dp0\shell.w32-ix86
SET OPENSSL_CONF=%~dp0\CA-WINCONF\openssl.cnf
cd %~dp0

set /p tpl="Enter template filename: "

sh ./gen_crt.sh %tpl%
pause
