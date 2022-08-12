# ClamPsy
Autopsy module for malware scanning using ClamAV antivirus.

## Installation

**Stage 1: Install and configure ClamAV**

* [Download](https://www.clamav.net/downloads) the ZIP archive with ClamAV antivirus and extract it to `C:\`.
* Add the ClamAV location to the `%PATH%` environment variable and reboot the computer.
* Create configuration file for the `freshcam.exe` tool using following command interpreter's command:
```
copy "C:\clamav-0.105.1.win.x64\conf_examples\freshclam.conf.sample" "C:\clamav-0.105.1.win.x64\freshclam.conf"
```
* Remove from freshclam.conf file the following line (or make it a comment):
```
Example
```
* Run the `freshclam.exe` to download/update database:
```
C:\clamav-0.105.1.win.x64\freshclam.exe
```

**Stage 2: Install the module**

* [Download](https://github.com/dyussekeyev/ClamPsy/releases) the release ZIP archive and extract it to a folder with Python Plugins (`%APPDATA%\autopsy\python_modules`).
* Make the appropriate changes to the `config.json` file.

## How to build wrap DLL

Make sure you have installed and configured ClamAV according to *Stage 1* of the *Installation* section.

**Stage 1: Installing Prerequisites**

* Download `Microsoft Visual Studio Build Tools 2022` installer and run it.
* Select `Desktop development with C++` option during the installation process.
* [Download](https://github.com/Cisco-Talos/clamav) ZIP file with source code of `ClamAV` and extract it to `C:\`.
* [Download](https://slproweb.com/products/Win32OpenSSL.html) `Win64 OpenSSL v3.0.5` binary and install it in `C:\OpenSSL-Win64`.

**Stage 2: Building wrap DLL**

* [Download](https://github.com/dyussekeyev/ClamPsy) ZIP file with source code of this repository and extract it to `C:\`.
* Run the `x64 Native Tools Command Prompt for VS 2022` and type following command interpreter's commands:
```
cd "C:\ClamPsy-main"
cl /LD /I"C:\clamav-main\libclamav" /I"C:\OpenSSL-Win64\include" /I"C:\ClamPsy-main\empty-headers" clampsy.c "C:\clamav-0.105.1.win.x64\clamav.lib" /Fo"clampsy" /Os
```

**Stage 3: Testing**
* [Download](https://www.python.org/downloads/release/python-272/) and install `Python 2.7.2 amd64 (x86-64)` to `C:\Python27`.
* [Download](https://secure.eicar.org/eicar.com) the EICAR test file and save it to `C:\ClamPsy-main`.
* Run following command interpreter's commands:
```
cd C:\ClamPsy-main\
C:\Python27\python.exe clampsy-test.py
```
