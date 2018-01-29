@echo off
echo Create emcssl InfoCard

SET PATH=%PATH%;%~dp0\openssl-1.0.2a-i386-win32;%~dp0\shell.w32-ix86
SET OPENSSL_CONF=%~dp0\CA-WINCONF\openssl.cnf
cd %~dp0

set /p tpl="Enter infocard filename: "

sh ./info_crypt.sh %tpl%
pause
