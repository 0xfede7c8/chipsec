# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2017, Intel Security
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# Authors:
#   Yuriy Bulygin
#   Alex Bazhaniuk
#

"""
The module can generate a list of EFI executables from (U)EFI firmware file or
extracted from flash ROM, and then later check firmware image in flash ROM or
file against this list of [expected/whitelisted] executables

Usage:
  ``chipsec_main -m tools.uefi.whitelist [-a generate|check,<json>,<fw_image>]``
    - ``generate``	Generates a list of EFI executable binaries from the UEFI
                        firmware image (default)
    - ``check``		Decodes UEFI firmware image and checks all EFI executable
                        binaries against a specified list
    - ``json``		JSON file with configuration of white-listed EFI
                        executables (default = ``efilist.json``)
    - ``fw_image``	Full file path to UEFI firmware image. If not specified,
                        the module will dump firmware image directly from ROM
    
Examples:

>>> chipsec_main -m tools.uefi.whitelist

Creates a list of EFI executable binaries in ``efilist.json`` from the firmware
image extracted from ROM

>>> chipsec_main -i -n -m tools.uefi.whitelist -a generate,efilist.json,uefi.rom

Creates a list of EFI executable binaries in ``efilist.json`` from ``uefi.rom``
firmware binary 

>>> chipsec_main -i -n -m tools.uefi.whitelist -a check,efilist.json,uefi.rom

Decodes ``uefi.rom`` UEFI firmware image binary and checks all EFI executables
in it against a list defined in ``efilist.json``

Note: ``-i`` and ``-n`` arguments can be used when specifying firmware file
because the module doesn't depend on the platform and doesn't need kernel driver
"""
import json
import hashlib

from chipsec.module_common import *

import chipsec.hal.uefi
import chipsec.hal.spi
from chipsec.hal import uefi_common
from chipsec.hal import spi_uefi
from chipsec.hal import uefi_search

TAGS = [MTAG_BIOS]

DEF_FWIMAGE_FILE = 'fw.bin'
DEF_EFILIST_FILE = 'efilist.json'
DEF_HASHTYPE     = "hash"

COLLECT_PE_INFO  = False
COLLECT_OBJ      = "exe"
OUTPUT_FILE      = "not_matches.json"

USAGE_TEXT = '''
The module can generate a list of EFI executables from (U)EFI firmware file or
extracted from flash ROM, and then later check firmware image in flash ROM or
file against this list of [expected/whitelisted] executables

Usage:

  chipsec_main -m tools.uefi.whitelist [-a generate|check,<json>,<fw_image>]
    - generate    Generates a list of EFI executable binaries from the UEFI
                  firmware image (default)
    - check       Decodes UEFI firmware image and checks all EFI executable
                  binaries against a specified list
    - <json>      JSON file with configuration of white-listed EFI executables
                  (default = efilist.json)
    - <fw_image>  Full file path to UEFI firmware image. If not specified, the
                  module will dump firmware image directly from ROM
   
Examples:

  chipsec_main -m tools.uefi.whitelist
    Creates a list of EFI executable binaries in efilist.json from the firmware
    image extracted from ROM

  chipsec_main -i -n -m tools.uefi.whitelist -a generate,efilist.json,uefi.rom
    Creates a list of EFI executable binaries in efilist.json from uefi.rom
    firmware binary 

  chipsec_main -i -n -m tools.uefi.whitelist -a check,efilist.json,uefi.rom
    Decodes uefi.rom UEFI firmware image binary and checks all EFI executables
    in it against a list defined in whitelist.json

Note: -i and -n arguments can be used when specifying firmware file because the
module doesn't depend on the platform and doesn't need kernel driver
'''

class whitelist(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.uefi = chipsec.hal.uefi.UEFI( self.cs )
        self.image = None
        self.efi_list = None
        self.suspect_modules = {}

    def is_supported(self):
        return True

    #
    # callbacks to uefi_search.check_match_criteria
    #
    def genlist_callback(self, efi_module):
        md = {}
        if type(efi_module) == spi_uefi.EFI_SECTION:
            if obj_type != "exe":
                return 
            ##print efi_module.ui_string
            ##print efi_module.parentGuid
            ##print len(efi_module.Image)
            ##hsha256 = hashlib.sha256()
            ##hsha256.update( efi_module.Image[4:] )
            ##print hsha256.hexdigest()
            #if COLLECT_PE_INFO:
            #    if efi_module.pe_info:
            #         #print len(efi_module.pe_info)
            #         md["pe_info_size"] = len(efi_module.pe_info) 
            #         md["pe_info"]      = efi_module.pe_info
    
            #if efi_module.MD5:        md["md5"]     = efi_module.MD5
            if efi_module.parentGuid: md["guid"]    = efi_module.parentGuid
            if efi_module.ui_string:  md["name"]    = efi_module.ui_string
            if efi_module.Name and efi_module.Name != uefi_common.SECTION_NAMES[uefi_common.EFI_SECTION_PE32]:
                md["type"]   = efi_module.Name
            if hash_type == "ac":
                if  efi_module.SHA1_AC: md["sha1_ac"]    = efi_module.SHA1_AC
                elif efi_module.SHA1:   md["sha1"]    = efi_module.SHA1
                if efi_module.SHA256_AC:  self.efi_list[efi_module.SHA256_AC] = md
                else: self.efi_list[efi_module.SHA256] = md
            elif hash_type == "nt":
                if  efi_module.SHA1_NT:  md["sha1_nt"]    = efi_module.SHA1_NT
                elif efi_module.SHA1:    md["sha1"]    = efi_module.SHA1
                if efi_module.SHA256_NT: self.efi_list[efi_module.SHA256_NT] = md
                else: self.efi_list[efi_module.SHA256] = md
            elif hash_type == "acnt":
                if  efi_module.SHA1_ACNT:  md["sha1_acnt"]    = efi_module.SHA1_ACNT
                elif efi_module.SHA1:	   md["sha1"]    = efi_module.SHA1
                if efi_module.SHA256_ACNT: self.efi_list[efi_module.SHA256_ACNT] = md
                else: self.efi_list[efi_module.SHA256] = md
            else:
                if efi_module.SHA1: md["sha1"]    = efi_module.SHA1
                self.efi_list[efi_module.SHA256] = md
        elif type(efi_module) == spi_uefi.EFI_FILE or type(efi_module) == spi_uefi.EFI_FV:
            if obj_type != "fv":
                return 
            if efi_module.Name: md["guid"]    = efi_module.Name
            self.efi_list[efi_module.SHA256] = md
        else: pass

    #
    # Generates new white-list of EFI executable binaries
    #
    def generate_efilist( self, json_pth ):
        self.efi_list = {}
        self.logger.log( "[*] generating a list of EFI executables from firmware image..." )
        efi_tree = spi_uefi.build_efi_model(self.uefi, self.image, None)
        if obj_type == "exe":
            matching_modules = spi_uefi.search_efi_tree(efi_tree, self.genlist_callback, spi_uefi.EFIModuleType.SECTION_EXE, True)
        if obj_type == "fv":
            matching_modules = spi_uefi.search_efi_tree(efi_tree, self.genlist_callback, spi_uefi.EFIModuleType.FILE|spi_uefi.EFIModuleType.FV, True)
        self.logger.log( "[*] found %d EFI executables in UEFI firmware image '%s'" % (len(self.efi_list),self.image_file) )
        self.logger.log( "[*] creating JSON file '%s'..." % json_pth )
        chipsec.file.write_file( "%s" % json_pth, json.dumps(self.efi_list, indent=2, separators=(',', ': ')) )
        return ModuleResult.PASSED

    #
    # Checks EFI executable binaries against white-list
    #
    def check_whitelist( self, json_pth ):
        self.efi_list = {}
        with open(json_pth) as data_file:    
            self.efi_whitelist = json.load(data_file)

        self.logger.log( "[*] checking EFI executables against the list '%s'" % json_pth )

        # parse the UEFI firmware image and look for EFI modules matching white-list
        # - match only executable EFI sections (PE/COFF, TE)
        # - find all occurrences of matching EFI modules
        efi_tree = spi_uefi.build_efi_model(self.uefi, self.image, None)
        matching_modules = spi_uefi.search_efi_tree(efi_tree, self.genlist_callback, spi_uefi.EFIModuleType.SECTION_EXE, True)
        self.logger.log( "[*] found %d EFI executables in UEFI firmware image '%s'" % (len(self.efi_list),self.image_file) )

        for m in self.efi_list:
            if not (m in self.efi_whitelist):
                self.suspect_modules[m] = self.efi_list[m]
                guid = self.efi_list[m]["guid"] if 'guid' in self.efi_list[m] else '?'
                name = self.efi_list[m]["name"] if 'name' in self.efi_list[m] else '<unknown>'
                sha1 = self.efi_list[m]["sha1"] if 'sha1' in self.efi_list[m] else ''
                self.logger.log_important( "found EFI executable not in the list:\n    %s (sha256)\n    %s (sha1)\n    {%s}\n    %s" % (m,sha1,guid,name))

        if len(self.suspect_modules) > 0:
            self.logger.log_warn_check( "found %d EFI executables not in the list '%s'" % (len(self.suspect_modules),json_pth) )
            return ModuleResult.WARNING
        else:
            self.logger.log_passed_check( "all EFI executables match the list '%s'" % json_pth )
            return ModuleResult.PASSED

    #
    # Checks FV/FILE binaries against apple white-list
    #
    def check_whitelist_apple( self, json_pth ):
        self.efi_list = {}
        with open(json_pth) as data_file:    
            self.efi_whitelist = json.load(data_file)

        self.logger.log( "[*] checking FV against the list '%s'" % json_pth )

        # parse the UEFI firmware image and look for FV/FILE file matching white-list
        # - match only FV/FILE
        # - find all occurrences of matching FV/FILE files
        efi_tree = spi_uefi.build_efi_model(self.uefi, self.image, None)
        self.suspect_modules = spi_uefi.match_FV_efi_tree(efi_tree, self.efi_whitelist, spi_uefi.EFIModuleType.FILE|spi_uefi.EFIModuleType.FV)
        #print json.dumps(self.suspect_modules, indent=3, separators=(',', ': '))
        self.logger.log( "[*] Not found %d FV/FILE/EFI executables in UEFI firmware image '%s'" % (len(self.suspect_modules),self.image_file) )
        print output_file
        chipsec.file.write_file( output_file, json.dumps(self.suspect_modules, indent=3, separators=(',', ': ')) )

        for m in self.suspect_modules:
        #    guid = m["guid"] if 'guid' in m else '?'
            self.logger.log_important( "[*] Found FV/FILE/EFI executable not in the list:\n    %s (sha256)\n" % (m))

        if len(self.suspect_modules) > 0:
            self.logger.log_warn_check( "[*] Found %d FV/FILE/EFI executables files not in the list '%s'" % (len(self.suspect_modules),json_pth) )
            return ModuleResult.WARNING
        else:
            self.logger.log_passed_check( "[*] All FV match the list '%s'" % json_pth )
            return ModuleResult.PASSED

    def usage(self):
        self.logger.log( USAGE_TEXT )


    # --------------------------------------------------------------------------
    # run( module_argv )
    # Required function: run here all tests from this module
    # --------------------------------------------------------------------------
    def run( self, module_argv ):
        self.logger.start_test("simple white-list generation/checking for (U)EFI firmware")

        self.res = ModuleResult.SKIPPED

        op = module_argv[0] if len(module_argv) > 0 else 'generate'

        if op in ['generate','check']:

            global hash_type
            global obj_type
            global output_file

            if len(module_argv) > 1:
                json_file  = module_argv[1]
                image_file = module_argv[2]
                self.logger.log("[*] reading firmware from '%s'..." % image_file)
                if len(module_argv) > 3:
                    hash_type = module_argv[3]
                    self.logger.log("[*] Use Hash type '%s'..." % hash_type)
                else:
                    hash_type  = DEF_HASHTYPE
                if len(module_argv) > 4:
                    obj_type = module_argv[4]
                    self.logger.log("[*] Use type matching of: '%s'..." % obj_type)
                else:
                    obj_type  = COLLECT_OBJ
                if len(module_argv) > 5:
                    output_file = module_argv[5]
                    self.logger.log("[*] Use Output File of: '%s'..." % output_file)
                else:
                    output_file  = OUTPUT_FILE
            else:
                image_file = DEF_FWIMAGE_FILE
                json_file  = DEF_EFILIST_FILE
                hash_type  = DEF_HASHTYPE
                obj_type  = COLLECT_OBJ
                output_file  = OUTPUT_FILE
                self.spi = chipsec.hal.spi.SPI(self.cs)
                (base,limit,freg) = self.spi.get_SPI_region(chipsec.hal.spi.BIOS)
                image_size = limit + 1 - base
                self.logger.log("[*] dumping firmware image from ROM to '%s': 0x%08X bytes at [0x%08X:0x%08X]" % (image_file,image_size,base,limit))
                self.spi.read_spi_to_file(base, image_size, image_file)

            self.image_file = image_file
            self.image = chipsec.file.read_file(image_file)
            json_pth = os.path.abspath(json_file)

            if op == 'generate':
                if os.path.exists(json_pth):
                    self.logger.error("JSON file '%s' already exists. Exiting..." % json_file)
                    self.res = ModuleResult.ERROR
                else:
                    self.res = self.generate_efilist(json_pth)
            elif op == 'check':
                if not os.path.exists(json_pth):
                    self.logger.error("JSON file '%s' doesn't exists. Exiting..." % json_file)
                    self.res = ModuleResult.ERROR
                else:
                    if obj_type == "exe":
                        self.res = self.check_whitelist(json_pth)
                    if obj_type == "fv":
                        self.res = self.check_whitelist_apple(json_pth)

        elif op == 'help':
            self.usage()
        else:
            self.logger.error("unrecognized command-line argument to the module")
            self.usage()

        return self.res
