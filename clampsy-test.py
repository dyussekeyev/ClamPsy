# Copyright (c) 2022 Askar Dyussekeyev
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
# DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
# OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
# OR OTHER DEALINGS IN THE SOFTWARE.

import json
import ctypes as ct
import os
import tempfile
from ctypes import *

# specify path to the antivirus engine
dir_root = os.path.dirname(os.path.abspath(__file__))
file_test = "eicar.com"

# import config
with open("C:\\Projects\\ClamPsy\\config.json", "r") as f:
    print f.name
    config = json.load(f)

print "CONFIG:"
print "dir_clamav: " + config["dir_clamav"]
print "dir_database: " + config["dir_database"]
print "dir_root: " + dir_root
print "file_test: " + dir_root + "\\" + file_test

# try to load library
try:
    clampsy_lib = cdll.LoadLibrary(dir_root + "\\clampsy.dll")
except OSError:
    print "Unable to load library"
    exit()

clampsy_lib.clampsy_init.argtypes = [c_char_p, c_char_p]
clampsy_lib.clampsy_init.restype = c_int

clampsy_lib.clampsy_scanfile.argtypes = [c_int, c_char_p]
clampsy_lib.clampsy_scanfile.restype = c_int

clampsy_lib.clampsy_free.argtypes = [c_int]
clampsy_lib.clampsy_free.restype = c_int

clampsy_lib.clampsy_virname_get.argtypes = [c_int]
clampsy_lib.clampsy_virname_get.restype = c_char_p

engine_num = clampsy_lib.clampsy_init(config["dir_clamav"] + "\\libclamav.dll", config["dir_clamav"] + "\\" + config["dir_database"])
print "Engine ID: " + str(engine_num)
if (engine_num != -1):
    # scan file
    print "\nFILE SCAN TEST #1"
    print "Test file path: " + dir_root + "\\" + file_test
    result = clampsy_lib.clampsy_scanfile(engine_num, dir_root + "\\" + file_test)
    print "clampsy_scanfile result:", str(result)
    if result == 1:
        print "Detected VIRUS name: " + clampsy_lib.clampsy_virname_get(engine_num)
    
    # read file
    print "\nTEMP FILE SCAN TEST #2"
    with open(dir_root + "\\" + file_test, mode="rb") as file:
        fileContent = file.read()
    print "Number of bytes read: " + str(len(fileContent))
    
    # write content into tmpfile
    tmpfile = tempfile.NamedTemporaryFile(prefix = "clampsy_", delete = False)
    tmpfile.write(fileContent)
    tmpfile.close();
    
    # scan file
    print "Temp test file path: " + tmpfile.name
    result = clampsy_lib.clampsy_scanfile(engine_num, tmpfile.name)
    print "clampsy_scanfile result:", str(result)
    if result == 1:
        print "Detected VIRUS name: " + clampsy_lib.clampsy_virname_get(engine_num)
    
    # remove the file
    os.remove(tmpfile.name)

    result = clampsy_lib.clampsy_free(engine_num)
else:
    print "Error during clampsy_init"
