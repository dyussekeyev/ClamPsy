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
import os
import tempfile
from ctypes import *

import jarray
import inspect
from java.lang import System
from java.util.logging import Level
from java.io import File
from org.sleuthkit.datamodel import Score
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.casemodule.services import Blackboard
from org.sleuthkit.autopsy.datamodel import ContentUtils
from java.util import Arrays

# Factory that defines the name and details of the module and allows Autopsy
# to create instances of the modules that will do the anlaysis.
# TODO: Rename this to something more specific.  Search and replace for it because it is used a few times
class ClamPsyFileIngestModuleFactory(IngestModuleFactoryAdapter):

    # TODO: give it a unique name.  Will be shown in module list, logs, etc.
    moduleName = "ClamPsy"

    def getModuleDisplayName(self):
        return self.moduleName

    # TODO: Give it a description
    def getModuleDescription(self):
        return "Module for Autopsy that scans files using ClamAV antivirus"

    def getModuleVersionNumber(self):
        return "0.1"

    # Return true if module wants to get called for each file
    def isFileIngestModuleFactory(self):
        return True

    # can return null if isFileIngestModuleFactory returns false
    def createFileIngestModule(self, ingestOptions):
        return ClamPsyFileIngestModule()


# File-level ingest module.  One gets created per thread.
# TODO: Rename this to something more specific. Could just remove "Factory" from above name.
# Looks at the attributes of the passed in file.
class ClamPsyFileIngestModule(FileIngestModule):

    _logger = Logger.getLogger(ClamPsyFileIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)

    def __init__(self):
        self.context = None

    # Where any setup and configuration is done
    # 'context' is an instance of org.sleuthkit.autopsy.ingest.IngestJobContext.
    # See: http://sleuthkit.org/autopsy/docs/api-docs/latest/classorg_1_1sleuthkit_1_1autopsy_1_1ingest_1_1_ingest_job_context.html
    # TODO: Add any setup code that you need here.
    def startUp(self, context):
        self.context = context
        self.filesFound = 0
        self.files = []

        self.engine_num = -1
        self.workdir = os.path.dirname(os.path.abspath(__file__))

        # import and parse config
        with open(self.workdir + "\\config.json", "r") as f:
            config = json.load(f)
        self.dir_clamav = config["dir_clamav"]
        self.dir_database = config["dir_database"]

        # try to load library
        try:
            self.clampsy_lib = cdll.LoadLibrary(self.workdir + "\\clampsy.dll")

            # specify arguments types
            self.clampsy_lib.clampsy_init.argtypes = [c_char_p, c_char_p]
            self.clampsy_lib.clampsy_init.restype = c_int
    
            self.clampsy_lib.clampsy_scanfile.argtypes = [c_int, c_char_p]
            self.clampsy_lib.clampsy_scanfile.restype = c_int
    
            self.clampsy_lib.clampsy_free.argtypes = [c_int]
            self.clampsy_lib.clampsy_free.restype = c_int
    
            self.clampsy_lib.clampsy_virname_get.argtypes = [c_int]
            self.clampsy_lib.clampsy_virname_get.restype = c_char_p
        except OSError:
            self.log(Level.SEVERE, "Unable to load a library")
            raise IngestModuleException("Unable to load a library")
            exit()
            
        # try to init lib
        result = self.clampsy_lib.clampsy_init(self.dir_clamav + "\\libclamav.dll", self.dir_clamav + "\\" + self.dir_database)
        if (result == -1):
            self.log(Level.SEVERE, "Unable to init library wrapper")
            raise IngestModuleException("Unable to init library wrapper")
            exit()
        else:
            self.engine_num = result

    # Where the analysis is done.  Each file will be passed into here.
    # The 'file' object being passed in is of type org.sleuthkit.datamodel.AbstractFile.
    # See: http://www.sleuthkit.org/sleuthkit/docs/jni-docs/latest/classorg_1_1sleuthkit_1_1datamodel_1_1_abstract_file.html
    # TODO: Add your analysis code in here.
    def process(self, file):
        # Skip non-files
        if ((file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNALLOC_BLOCKS) or
            (file.getType() == TskData.TSK_DB_FILES_TYPE_ENUM.UNUSED_BLOCKS) or
            (file.isFile() == False) or (file.getSize() == 0)):
            return IngestModule.ProcessResult.OK

        # Use blackboard class to index blackboard artifacts for keyword search
        blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
        
        # create tmpfile
        tmpfile = tempfile.NamedTemporaryFile(prefix = "clampsy_", delete = False)
        tmpfile.close();
        self.files.append(tmpfile.name)
        
        # write content to tmpfile
        ContentUtils.writeToFile(file, File(tmpfile.name))
        
        scan_result = self.clampsy_lib.clampsy_scanfile(self.engine_num, tmpfile.name)
        if scan_result == 1:
            virname = self.clampsy_lib.clampsy_virname_get(self.engine_num)
        
            self.log(Level.INFO, "Found a VIRUS: " + file.getName() + " (virname:" + virname + ")")
            self.filesFound+=1
            
            attrs = Arrays.asList(BlackboardAttribute(BlackboardAttribute.Type.TSK_SET_NAME, ClamPsyFileIngestModuleFactory.moduleName, "MALWARE"))
            art = file.newAnalysisResult(BlackboardArtifact.Type.TSK_INTERESTING_FILE_HIT, Score.SCORE_NOTABLE, virname, "STANDARD", "Scan Engine", attrs).getAnalysisResult()
    
            try:
                blackboard.postArtifact(art, ClamPsyFileIngestModuleFactory.moduleName, context.getJobId())
            except Blackboard.BlackboardException as e:
                self.log(Level.SEVERE, "Error indexing artifact " + art.getDisplayName())

        return IngestModule.ProcessResult.OK

    # Where any shutdown code is run and resources are freed.
    # TODO: Add any shutdown code that you need here.
    def shutDown(self):
        # As a final part of this example, we'll send a message to the ingest inbox with the number of files found (in this thread)
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, ClamPsyFileIngestModuleFactory.moduleName, str(self.filesFound) + " files found")
        ingestServices = IngestServices.getInstance().postMessage(message)

        # free lib
        if (self.engine_num >= 0) and (self.engine_num < 100):
            result = self.clampsy_lib.clampsy_free(self.engine_num)
            if (result != 0):
                self.log(Level.SEVERE, "Unable to free library wrapper: unexpected error")
                raise IngestModuleException("Unable to free library wrapper: unexpected error")
                exit()
            
        # delete all tmpfiles
        for f in self.files:
            os.remove(f)
