@echo off
SET PATH=%PATH%;%~dp0\openssl-1.0.2a-i386-win32;%~dp0\shell.w32-ix86
SET OPENSSL_CONF=%~dp0\CA-WINCONF\openssl.cnf
cd %~dp0

sh ./gen_tpl.sh
pause
