/*
Copyright (c) 2022 Askar Dyussekeyev

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "clamav.h"
#include <stdio.h>
#include <Windows.h>

// DLL global variables
HINSTANCE hDLL = NULL;
struct engine_data {
    struct cl_engine* engine;
    unsigned int signo;
    char virname[100];
} engine_datas[100];

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

__declspec(dllexport) int __cdecl clampsy_init(char* libpath, char* dbpath)
{
    int engine_num = -1;
    cl_error_t cl_result;
    unsigned int dboptions = CL_DB_PHISHING |
                             CL_DB_PHISHING_URLS |
                             CL_DB_PUA |
                             CL_DB_BYTECODE |
                             CL_DB_ENHANCED;

    hDLL = LoadLibrary(libpath);
    if (NULL != hDLL)
    {
        // init libclamav
        if ((cl_result = cl_init(CL_INIT_DEFAULT)) != CL_SUCCESS) {
            return -1;
        }

        // get free engine_num
        for (int i = 0; i < 100; i++) {
            if (engine_datas[i].signo == 0) {
                engine_num = i;
                break;
            }
        }
        if (!(engine_num >= 0 && engine_num < 100)) {
            return -2;
        }

        // create new engine
        if (!(engine_datas[engine_num].engine = cl_engine_new())) {
            return -3;
        }

        // load database
        if ((cl_result = cl_load(dbpath, engine_datas[engine_num].engine, &engine_datas[engine_num].signo, dboptions)) != CL_SUCCESS) {
            // free engine
            cl_engine_free(engine_datas[engine_num].engine);
            return -4;
        }

        // compile engine
        if ((cl_result = cl_engine_compile(engine_datas[engine_num].engine)) != CL_SUCCESS) {
            // free engine
            cl_engine_free(engine_datas[engine_num].engine);
            return -5;
        }
    }
    else
    {
        return -6;
    }

    return engine_num;
}

__declspec(dllexport) int __cdecl clampsy_scanfile(int engine_num, char* filepath)
{
    cl_error_t cl_result;
    struct cl_scan_options options;
    const char* virname;
    unsigned long int scanned;

    // check engine_num
    if (!(engine_num >= 0 && engine_num < 100)) {
        return -1;
    }

    // set options
    memset(&options, 0, sizeof(struct cl_scan_options));
    options.general = CL_SCAN_GENERAL_ALLMATCHES |
                      CL_SCAN_GENERAL_HEURISTICS |
                      CL_SCAN_GENERAL_HEURISTIC_PRECEDENCE;
    options.parse = CL_SCAN_PARSE_ARCHIVE |
                    CL_SCAN_PARSE_ELF |
                    CL_SCAN_PARSE_PDF |
                    CL_SCAN_PARSE_SWF |
                    CL_SCAN_PARSE_HWP3 |
                    CL_SCAN_PARSE_XMLDOCS |
                    CL_SCAN_PARSE_MAIL |
                    CL_SCAN_PARSE_OLE2 |
                    CL_SCAN_PARSE_HTML |
                    CL_SCAN_PARSE_PE;
    options.heuristic = CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE | CL_SCAN_HEURISTIC_ENCRYPTED_DOC;
    options.mail = CL_SCAN_MAIL_PARTIAL_MESSAGE;

    cl_result = cl_scanfile(filepath, &virname, &scanned, engine_datas[engine_num].engine, &options);

    if (cl_result == CL_VIRUS) {
        strcpy(engine_datas[engine_num].virname, virname);
        return 1;
    }
    else if (cl_result == CL_CLEAN) {
        return 0;
    }
    else {
        return -1;
    }
}

__declspec(dllexport) int __cdecl clampsy_free(int engine_num)
{
    cl_error_t cl_result;

    // check engine_num
    if (!(engine_num >= 0 && engine_num < 100)) {
        return -1;
    }

    // free engine
    if ((cl_result = cl_engine_free(engine_datas[engine_num].engine)) != CL_SUCCESS) {
        printf("cl_engine_free() error: %s\n", cl_strerror(cl_result));
        return -1;
    }

    // set variables
    engine_datas[engine_num].engine = NULL;
    engine_datas[engine_num].signo = 0;

    // unload library
    FreeLibrary(hDLL);

    return 0;
}

__declspec(dllexport) const char* __cdecl clampsy_virname_get(int engine_num) {
    // check engine_num
    if (!(engine_num >= 0 && engine_num < 100)) {
        printf("virname error");
        return "Error";
    }

    return engine_datas[engine_num].virname;
}
