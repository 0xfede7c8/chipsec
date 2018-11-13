#!/usr/bin/python
#CHIPSEC: Platform Security Assessment Framework
#Copyright (c) 2010-2016, Intel Corporation
# 
#This program is free software; you can redistribute it and/or
#modify it under the terms of the GNU General Public License
#as published by the Free Software Foundation; Version 2.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program; if not, write to the Free Software
#Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#Contact information:
#chipsec@intel.com
#


# -------------------------------------------------------------------------------
#
# CHIPSEC: Platform Hardware Security Assessment Framework
#
# -------------------------------------------------------------------------------

"""
UEFI firmware image parsing and manipulation functionality

usage:
    >>> parse_uefi_region_from_file(_uefi, filename, fwtype, outpath):
"""

import os
import fnmatch
import struct
import sys
import time
import collections
import hashlib
import re
import random
import binascii
import json
#import phex

import pefile
from functools import partial
import io


from chipsec.helper.oshelper import helper
from chipsec.logger import *
from chipsec.file import *

from chipsec.cfg.common import *
from chipsec.hal.uefi_common import *
from chipsec.hal.uefi_platform import *
from chipsec.hal.uefi import identify_EFI_NVRAM

CMD_UEFI_FILE_REMOVE        = 0
CMD_UEFI_FILE_INSERT_BEFORE = 1
CMD_UEFI_FILE_INSERT_AFTER  = 2
CMD_UEFI_FILE_REPLACE       = 3

type2ext = {EFI_SECTION_PE32: 'pe32', EFI_SECTION_TE: 'te', EFI_SECTION_PIC: 'pic', EFI_SECTION_COMPATIBILITY16: 'c16'}

#
# Calculate hashes for all FVs, FW files and sections (PE/COFF or TE executables)
# and write them on the file system
#
WRITE_ALL_HASHES = False

def image_minus_timestamp_(image):
    Data = ""
    try:
        pe = pefile.PE(None,image, fast_load=True)
    except: return image
    image_file_header_offset = pe.FILE_HEADER.get_file_offset()
    relative_timestamp_offset = 4 
    file_timestamp_offset = image_file_header_offset + relative_timestamp_offset
    return image[:file_timestamp_offset]+image[file_timestamp_offset+4:]

def authenticode_data_minus_timestamp_(image):
    Data = ""
    try:
        pe = pefile.PE(None,image, fast_load=True)
    except: return image
    Offset = pe.OPTIONAL_HEADER.get_file_offset()
    Offset += pe.OPTIONAL_HEADER.get_field_relative_offset('CheckSum')
    Header = pe.get_data(0, pe.OPTIONAL_HEADER.SizeOfHeaders)

    image_file_header_offset = pe.FILE_HEADER.get_file_offset()
    relative_timestamp_offset = 4 
    file_timestamp_offset = image_file_header_offset + relative_timestamp_offset

    Header_cut_Offset = Header[0:Offset]
    if Offset > file_timestamp_offset:
        Data = Data + Header_cut_Offset[:file_timestamp_offset] + Header_cut_Offset[file_timestamp_offset+4:]
    else:
        Data = Data + Header_cut_Offset

    lastOffset = Offset + 4
    index = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
    CertificateTable = pe.OPTIONAL_HEADER.DATA_DIRECTORY[index]
    Offset = CertificateTable.get_file_offset()
    SigOff = CertificateTable.VirtualAddress

    Data = Data + Header[lastOffset:Offset]
    Data = Data + Header[Offset+8:pe.OPTIONAL_HEADER.SizeOfHeaders]

    sections = [ s for s in pe.sections if s.SizeOfRawData ]
    sections = sorted(sections, key=lambda s: s.PointerToRawData)
    for s in sections:
        Data = Data + s.get_data()
    sect_end = max([ s.PointerToRawData+s.SizeOfRawData for s in pe.sections ])
    SigOff -= sect_end
    if SigOff < 0:
        return Data

    print "authenticode_data_minus_timestamp_ NOT TESTED FLOW"

    idx = sect_end
    if SigOff:
        Data = Data + image[idx:idx+SigOff]
    sig_hdr = image[idx:idx+8]
    size, hdr_sig = struct.unpack("<II", sig_hdr)
    
    r = image[idx+size:] 
    Data = Data + r

    return Data

def authenticode_data_(image):
    Data = ""
    try:
        pe = pefile.PE(None,image, fast_load=True)
    except: return image
    Offset = pe.OPTIONAL_HEADER.get_file_offset()
    Offset += pe.OPTIONAL_HEADER.get_field_relative_offset('CheckSum')
    Header = pe.get_data(0, pe.OPTIONAL_HEADER.SizeOfHeaders)

    Data = Data + Header[0:Offset]

    lastOffset = Offset + 4
    index = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
    CertificateTable = pe.OPTIONAL_HEADER.DATA_DIRECTORY[index]
    Offset = CertificateTable.get_file_offset()
    SigOff = CertificateTable.VirtualAddress

    Data = Data + Header[lastOffset:Offset]
    Data = Data + Header[Offset+8:pe.OPTIONAL_HEADER.SizeOfHeaders]

    sections = [ s for s in pe.sections if s.SizeOfRawData ]
    sections = sorted(sections, key=lambda s: s.PointerToRawData)
    for s in sections:
        Data = Data + s.get_data()
    sect_end = max([ s.PointerToRawData+s.SizeOfRawData for s in pe.sections ])
    SigOff -= sect_end
    if SigOff < 0:
        return Data

    print "authenticode_data_ NOT TESTED FLOW"

    idx = sect_end
    if SigOff:
        Data = Data + image[idx:idx+SigOff]
    sig_hdr = image[idx:idx+8]
    size, hdr_sig = struct.unpack("<II", sig_hdr)
    
    r = image[idx+size:] 
    Data = Data + r

    return Data

class PEFileFeatures():
    ''' Create instance of PEFileFeatures class. This class pulls static
        features out of a PE file using the python pefile module.
    '''

    def __init__(self):
        ''' Init method '''

        # Dense feature list: this only functions to ensure that all of these
        #               features get extracted with a sanity check at the end.
        self._dense_feature_list = None
        self._dense_features = None

        # Okay now the sparse fields
        self._sparse_feature_list = None
        self._sparse_features = None

        # Verbose
        self._verbose = False

        # Warnings handle
        self._warnings = []

        # Set the features that I'm expected PE File to extract, note this is just
        # for sanity checking, meaning that if you don't get some of these features
        # the processing will spit out warnings for each feature not extracted.
        self.set_dense_features(['check_sum', 'generated_check_sum', 'compile_date', 'debug_size', 'export_size', 'iat_rva', 'major_version', \
                                 'minor_version', 'number_of_bound_import_symbols', 'number_of_bound_imports', 'number_of_export_symbols', \
                                 'number_of_import_symbols', 'number_of_imports', 'number_of_rva_and_sizes', 'number_of_sections', 'pe_warnings', \
                                 'std_section_names', 'total_size_pe', 'virtual_address', 'virtual_size', 'virtual_size_2', \
                                 'datadir_IMAGE_DIRECTORY_ENTRY_BASERELOC_size', 'datadir_IMAGE_DIRECTORY_ENTRY_RESOURCE_size', \
                                 'datadir_IMAGE_DIRECTORY_ENTRY_IAT_size', 'datadir_IMAGE_DIRECTORY_ENTRY_IMPORT_size', \
                                 'pe_char', 'pe_dll', 'pe_driver', 'pe_exe', 'pe_i386', 'pe_majorlink', 'pe_minorlink', \
                                 'file_align', 'sec_align', 'subsystem', 'addr_of_entry_point', 'addr_code_sec', 'loader_flag', \
                                 'sec_chars_data', 'sec_chars_rdata', 'sec_chars_code', 'sec_chars_reloc', 'sec_chars_text', 'sec_chars_rsrc', \
                                 'sec_rawptr_rsrc', 'sec_rawsize_rsrc', 'sec_vasize_rsrc', 'sec_raw_execsize', \
                                 'sec_rawptr_data', 'sec_rawptr_text', 'sec_rawsize_data', 'sec_rawsize_text', 'sec_va_execsize', \
                                 'sec_vasize_data', 'sec_vasize_text', 'size_code', 'size_image', 'size_initdata', 'size_uninit'])
        #                                 'sec_entropy_data', 'sec_entropy_rdata', 'sec_entropy_reloc', 'sec_entropy_text', 'sec_entropy_rsrc', \
        self.set_sparse_features(['imported_symbols', 'section_names', 'pe_warning_strings'])

    def execute(self, input_data):

        ''' Process the input bytes with pefile '''
        raw_bytes = input_data

        # Have the PE File module process the file
        pefile_handle, error_str = self.open_using_pefile('unknown', raw_bytes)
        if not pefile_handle:
            return {'error': error_str}

        # Now extract the various features using pefile
        return self.extract_features_using_pefile(pefile_handle)


    def set_dense_features(self, dense_feature_list):
        ''' Set the dense feature list that the Python pefile module should extract.
            This is really just sanity check functionality, meaning that these
            are the features you are expecting to get, and a warning will spit
            out if you don't get some of these. '''
        self._dense_feature_list = dense_feature_list

    def get_dense_features(self):
        ''' Set the dense feature list that the Python pefile module should extract. '''
        #s = "{"
        #for key in sorted(self._dense_features.iterkeys()):
        #    s = s + " '%s' : %s," % (key, self._dense_features[key])
        #s = s[:-1]+" }"
        #return s
        return self._dense_features

    def set_sparse_features(self, sparse_feature_list):
        ''' Set the sparse feature list that the Python pefile module should extract.
            This is really just sanity check functionality, meaning that these
            are the features you are expecting to get, and a warning will spit
            out if you don't get some of these. '''
        self._sparse_feature_list = sparse_feature_list

    def get_sparse_features(self):
        ''' Set the sparse feature list that the Python pefile module should extract. '''
        return self._sparse_features


    # Make sure pe can parse this file
    def open_using_pefile(self, input_name, input_bytes):
        ''' Open the PE File using the Python pefile module. '''
        try:
            pe = pefile.PE(data=input_bytes, fast_load=False)
        except Exception, error:
            print 'warning: pe_fail (with exception from pefile module) on file: %s' % input_name
            error_str =  '(Exception):, %s' % (str(error))
            return None, error_str

        # Now test to see if the features are there/extractable if not return FAIL flag
        if (pe.PE_TYPE is None or pe.OPTIONAL_HEADER is None or len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) < 7):
            print 'warning: pe_fail on file: %s' % input_name
            error_str = 'warning: pe_fail on file: %s' % input_name
            return None, error_str

        # Success
        return pe, None

    # Extract various set of features using PEfile module
    def extract_features_using_pefile(self, pe):
        ''' Process the PE File using the Python pefile module. '''

        # Store all extracted features into feature lists
        extracted_dense = {}
        extracted_sparse = {}

        # Now slog through the info and extract the features
        feature_not_found_flag = -99
        feature_default_value = 0
        self._warnings = []

        # Set all the dense features and sparse features to 'feature not found'
        # value and then check later to see if it was found
        for feature in self._dense_feature_list:
            extracted_dense[feature] = feature_not_found_flag
        for feature in self._sparse_feature_list:
            extracted_sparse[feature] = feature_not_found_flag


        # Check to make sure all the section names are standard
        std_sections = ['.text', '.bss', '.rdata', '.data', '.rsrc', '.edata', '.idata', \
                        '.pdata', '.debug', '.reloc', '.stab', '.stabstr', '.tls', \
                        '.crt', '.gnu_deb', '.eh_fram', '.exptbl', '.rodata']
        for i in range(200):
            std_sections.append('/'+str(i))
        std_section_names = 1
        extracted_sparse['section_names'] = []
        for section in pe.sections:
            name = convertToAsciiNullTerm(section.Name).lower()
            extracted_sparse['section_names'].append(name)
            if (name not in std_sections):
                std_section_names = 0

        extracted_dense['std_section_names']      = std_section_names
        extracted_dense['debug_size']             = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6].Size
        extracted_dense['major_version']	      = pe.OPTIONAL_HEADER.MajorImageVersion
        extracted_dense['minor_version']          = pe.OPTIONAL_HEADER.MinorImageVersion
        extracted_dense['iat_rva']			      = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress
        extracted_dense['export_size']		      = pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size
        extracted_dense['check_sum']	          = pe.OPTIONAL_HEADER.CheckSum
        try:
            extracted_dense['generated_check_sum'] = pe.generate_checksum()
        except ValueError:
            #self._logger.logMessage('warning', 'pe.generate_check_sum() threw an exception, setting to 0!')
            extracted_dense['generated_check_sum'] = 0
        if (len(pe.sections) > 0):
            extracted_dense['virtual_address']     = pe.sections[0].VirtualAddress
            extracted_dense['virtual_size']	       = pe.sections[0].Misc_VirtualSize
        extracted_dense['number_of_sections']      = pe.FILE_HEADER.NumberOfSections
        extracted_dense['compile_date']            = pe.FILE_HEADER.TimeDateStamp
        extracted_dense['number_of_rva_and_sizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        extracted_dense['subsystem']               = pe.OPTIONAL_HEADER.Subsystem
        extracted_dense['addr_of_entry_point']     = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        extracted_dense['addr_code_sec']           = pe.OPTIONAL_HEADER.BaseOfCode
        extracted_dense['loader_flag']             = pe.OPTIONAL_HEADER.LoaderFlags
        extracted_dense['total_size_pe']	   = len(pe.__data__)


        # Number of import and exports
        if hasattr(pe,'DIRECTORY_ENTRY_IMPORT'):
            extracted_dense['number_of_imports'] = len(pe.DIRECTORY_ENTRY_IMPORT)
            num_imported_symbols = 0
            for module in pe.DIRECTORY_ENTRY_IMPORT:
                num_imported_symbols += len(module.imports)
            extracted_dense['number_of_import_symbols'] = num_imported_symbols

        if hasattr(pe, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
            extracted_dense['number_of_bound_imports'] = len(pe.DIRECTORY_ENTRY_BOUND_IMPORT)
            num_imported_symbols = 0
            for module in pe.DIRECTORY_ENTRY_BOUND_IMPORT:
                num_imported_symbols += len(module.entries)
            extracted_dense['number_of_bound_import_symbols'] = num_imported_symbols

        if hasattr(pe,'DIRECTORY_ENTRY_EXPORT'):
            extracted_dense['number_of_export_symbols'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
            symbol_set = set()
            for symbol in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                symbol_info = 'unknown'
                if (not symbol.name):
                    symbol_info = 'ordinal=' + str(symbol.ordinal)
                else:
                    symbol_info = 'name=' + symbol.name

                symbol_set.add(convertToUTF8('%s'%(symbol_info)).lower())

            # Now convert set to list and add to features
            extracted_sparse['ExportedSymbols'] = list(symbol_set)

        # Specific Import info (Note this will be a sparse field woo hoo!)
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            symbol_set = set()
            for module in pe.DIRECTORY_ENTRY_IMPORT:
                for symbol in module.imports:
                    symbol_info = 'unknown'
                    if symbol.import_by_ordinal is True:
                        symbol_info = 'ordinal=' + str(symbol.ordinal)
                    else:
                        symbol_info = 'name=' + symbol.name
                        #symbol_info['hint'] = symbol.hint
                    if symbol.bound:
                        symbol_info += ' bound=' + str(symbol.bound)

                    symbol_set.add(convertToUTF8('%s:%s'%(module.dll, symbol_info)).lower())

            # Now convert set to list and add to features
            extracted_sparse['imported_symbols'] = list(symbol_set)


        # Do we have a second section
        if (len(pe.sections) >= 2):
            extracted_dense['virtual_size_2']	   = pe.sections[1].Misc_VirtualSize

        extracted_dense['size_image']             = pe.OPTIONAL_HEADER.SizeOfImage
        extracted_dense['size_code']              = pe.OPTIONAL_HEADER.SizeOfCode
        extracted_dense['size_initdata']          = pe.OPTIONAL_HEADER.SizeOfInitializedData
        extracted_dense['size_uninit']            = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        extracted_dense['pe_majorlink']           = pe.OPTIONAL_HEADER.MajorLinkerVersion
        extracted_dense['pe_minorlink']           = pe.OPTIONAL_HEADER.MinorLinkerVersion
        extracted_dense['file_align']             = pe.OPTIONAL_HEADER.FileAlignment
        extracted_dense['sec_align']              = pe.OPTIONAL_HEADER.SectionAlignment
        extracted_dense['pe_driver']              = 1 if pe.is_driver() else 0
        extracted_dense['pe_exe']                 = 1 if pe.is_exe() else 0
        extracted_dense['pe_dll']                 = 1 if pe.is_dll() else 0
        extracted_dense['pe_i386']                = 1
        if pe.FILE_HEADER.Machine != 0x014c:
            extracted_dense['pe_i386'] = 0
        extracted_dense['pe_char']                = pe.FILE_HEADER.Characteristics

        # Data directory features!!
        datadirs = { 0: 'IMAGE_DIRECTORY_ENTRY_EXPORT', 1:'IMAGE_DIRECTORY_ENTRY_IMPORT', 2:'IMAGE_DIRECTORY_ENTRY_RESOURCE', 5:'IMAGE_DIRECTORY_ENTRY_BASERELOC', 12:'IMAGE_DIRECTORY_ENTRY_IAT'}
        for idx, datadir in datadirs.items():
            datadir = pefile.DIRECTORY_ENTRY[ idx ]
            if len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= idx:
                continue

            directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
            extracted_dense['datadir_%s_size' % datadir] = directory.Size

        # Section features
        section_flags = ['IMAGE_SCN_MEM_EXECUTE', 'IMAGE_SCN_CNT_CODE', 'IMAGE_SCN_MEM_WRITE', 'IMAGE_SCN_MEM_READ']
        rawexecsize = 0
        vaexecsize = 0
        for sec in pe.sections:
            if not sec:
                continue

            for char in section_flags:
                # does the section have one of our attribs?
                if hasattr(sec, char):
                    rawexecsize += sec.SizeOfRawData
                    vaexecsize  += sec.Misc_VirtualSize
                    break

            # Take out any weird characters in section names
            secname = convertToAsciiNullTerm(sec.Name).lower()
            secname = secname.replace('.','')
            #extracted_dense['sec_entropy_%s' % secname ] = sec.get_entropy()
            extracted_dense['sec_rawptr_%s' % secname] = sec.PointerToRawData
            extracted_dense['sec_rawsize_%s' % secname] = sec.SizeOfRawData
            extracted_dense['sec_vasize_%s' % secname] = sec.Misc_VirtualSize
            extracted_dense['sec_chars_%s' % secname] = hex(sec.Characteristics)

        extracted_dense['sec_va_execsize'] = vaexecsize
        extracted_dense['sec_raw_execsize'] = rawexecsize

        # Register if there were any pe warnings
        warnings = pe.get_warnings()
        if (warnings):
            extracted_dense['pe_warnings'] = 1
            extracted_sparse['pe_warning_strings'] = warnings
        else:
            extracted_dense['pe_warnings'] = 0


        # Issue a warning if the feature isn't found
        for feature in self._dense_feature_list:
            if (extracted_dense[feature] == feature_not_found_flag):
                extracted_dense[feature] = feature_default_value
                if (self._verbose):
                    self.log('info: Feature: %s not found! Setting to %d' % (feature, feature_default_value))
                    self._warnings.append('Feature: %s not found! Setting to %d' % (feature, feature_default_value))

        # Issue a warning if the feature isn't found
        for feature in self._sparse_feature_list:
            if (extracted_sparse[feature] == feature_not_found_flag):
                extracted_sparse[feature] = feature_default_value
                if (self._verbose):
                    self.log('info: Feature: %s not found! Setting to %d' % (feature, feature_default_value))
                    self._warnings.append('Feature: %s not found! Setting to %d' % (feature, feature_default_value))


        # Set the features for the class var
        self._dense_features = extracted_dense
        self._sparse_features = extracted_sparse

        return self.get_dense_features() #, self.get_sparse_features()

# Helper functions
def convertToUTF8(s):
    if (isinstance(s, unicode)):
        return s.encode( "utf-8" )
    try:
        u = unicode( s, "utf-8" )
    except:
        return str(s)
    utf8 = u.encode( "utf-8" )
    return utf8

def convertToAsciiNullTerm(s):
    s = s.split('\x00', 1)[0]
    return s.decode('ascii', 'ignore')

# Unit test: Create the class, the proper input and run the execute() method for a test
def pe_extractor(file_data):
    my_extractor = PEFileFeatures()
    return my_extractor.execute(file_data)

def decompress_section_data( _uefi, section_dir_path, sec_fs_name, compressed_data, compression_type, remove_files=False ):
    compressed_name = os.path.join(section_dir_path, "%s.gz" % sec_fs_name)
    uncompressed_name = os.path.join(section_dir_path, sec_fs_name)
    write_file(compressed_name, compressed_data)
    uncompressed_image = _uefi.decompress_EFI_binary( compressed_name, uncompressed_name, compression_type )
    if remove_files:
        try:
            os.remove(compressed_name)
            os.remove(uncompressed_name)       
        except: pass
    return uncompressed_image

def compress_image( _uefi, image, compression_type ):
    precomress_file = 'uefi_file.raw.comp'
    compressed_file = 'uefi_file.raw.comp.gz'
    write_file(precomress_file, image)
    compressed_image = _uefi.compress_EFI_binary(precomress_file, compressed_file, compression_type)
    write_file(compressed_file, compressed_image)
    os.remove(precomress_file)
    os.remove(compressed_file)
    return compressed_image


def modify_uefi_region(data, command, guid, uefi_file = ''):
    RgLengthChange = 0
    FvOffset, FsGuid, FvLength, FvAttributes, FvHeaderLength, FvChecksum, ExtHeaderOffset, FvImage, CalcSum = NextFwVolume(data)
    while FvOffset is not None:
        FvLengthChange = 0
        polarity = bit_set(FvAttributes, EFI_FVB2_ERASE_POLARITY)
        if ((FsGuid == EFI_FIRMWARE_FILE_SYSTEM2_GUID) or (FsGuid == EFI_FIRMWARE_FILE_SYSTEM_GUID)):
            cur_offset, next_offset, Name, Type, Attributes, State, Checksum, Size, FileImage, HeaderSize, UD, fCalcSum = NextFwFile(FvImage, FvLength, FvHeaderLength, polarity)
            while next_offset is not None:
                if (Name == guid):
                    uefi_file_size = (len(uefi_file) + 7) & 0xFFFFFFF8
                    CurFileOffset  = FvOffset + cur_offset  + FvLengthChange
                    NxtFileOffset  = FvOffset + next_offset + FvLengthChange
                    if command == CMD_UEFI_FILE_REMOVE:
                        FvLengthChange -= (next_offset - cur_offset)
                        logger().log( "Removing UEFI file with GUID=%s at offset=%08X, size change: %d bytes" % (Name, CurFileOffset, FvLengthChange) )
                        data = data[:CurFileOffset] + data[NxtFileOffset:]
                    elif command == CMD_UEFI_FILE_INSERT_BEFORE:
                        FvLengthChange += uefi_file_size
                        logger().log( "Inserting UEFI file before file with GUID=%s at offset=%08X, size change: %d bytes" % (Name, CurFileOffset, FvLengthChange) )
                        data = data[:CurFileOffset] + uefi_file.ljust(uefi_file_size, '\xFF') + data[CurFileOffset:]
                    elif command == CMD_UEFI_FILE_INSERT_AFTER:
                        FvLengthChange += uefi_file_size
                        logger().log( "Inserting UEFI file after file with GUID=%s at offset=%08X, size change: %d bytes" % (Name, CurFileOffset, FvLengthChange) )
                        data = data[:NxtFileOffset] + uefi_file.ljust(uefi_file_size, '\xFF') + data[NxtFileOffset:]
                    elif command == CMD_UEFI_FILE_REPLACE:
                        FvLengthChange += uefi_file_size - (next_offset - cur_offset)
                        logger().log( "Replacing UEFI file with GUID=%s at offset=%08X, new size: %d, old size: %d, size change: %d bytes" % (Name, CurFileOffset, len(uefi_file), Size, FvLengthChange) )
                        data = data[:CurFileOffset] + uefi_file.ljust(uefi_file_size, '\xFF') + data[NxtFileOffset:]
                    else:
                        raise Exception('Invalid command')

                if next_offset - cur_offset >= 24:
                    FvEndOffset = FvOffset + next_offset + FvLengthChange

                cur_offset, next_offset, Name, Type, Attributes, State, Checksum, Size, FileImage, HeaderSize, UD, fCalcSum = NextFwFile(FvImage, FvLength, next_offset, polarity)

            if FvLengthChange >= 0:
                data = data[:FvEndOffset] + data[FvEndOffset + FvLengthChange:]
            else:
                data = data[:FvEndOffset] + (abs(FvLengthChange) * '\xFF') + data[FvEndOffset:]

            FvLengthChange = 0

            #if FvLengthChange != 0:
            #    logger().log( "Rebuilding Firmware Volume with GUID=%s at offset=%08X" % (FsGuid, FvOffset) )
            #    FvHeader = data[FvOffset: FvOffset + FvHeaderLength]
            #    FvHeader = FvHeader[:0x20] + struct.pack('<Q', FvLength) + FvHeader[0x28:]
            #    NewChecksum = FvChecksum16(FvHeader[:0x32] + '\x00\x00' + FvHeader[0x34:])
            #    FvHeader = FvHeader[:0x32] + struct.pack('<H', NewChecksum) + FvHeader[0x34:]
            #    data = data[:FvOffset] + FvHeader + data[FvOffset + FvHeaderLength:]

        FvOffset, FsGuid, FvLength, FvAttributes, FvHeaderLength, FvChecksum, ExtHeaderOffset, FvImage, CalcSum = NextFwVolume(data, FvOffset + FvLength)
    return data


DEF_INDENT = "    "
class EFI_MODULE(object):
    def __init__(self, Offset, Guid, HeaderSize, Attributes, Image):
        self.Offset      = Offset
        self.Guid        = Guid
        self.HeaderSize  = HeaderSize
        self.Attributes  = Attributes
        self.Image       = Image
        self.ui_string   = None
        self.isNVRAM     = False
        self.NVRAMType   = None

        self.indent      = ''

        self.MD5         = None
        self.SHA1        = None
        self.SHA256      = None

        self.MD5_AC      = None
        self.SHA1_AC     = None
        self.SHA256_AC   = None

        self.MD5_NT      = None
        self.SHA1_NT     = None
        self.SHA256_NT   = None

        self.MD5_ACNT    = None
        self.SHA1_ACNT   = None
        self.SHA256_ACNT = None

        # a list of children EFI_MODULE nodes to build the EFI_MODULE object model
        self.children   = []
        self.pe_info    = {}
  

    def name(self):
        return "%s {%s} %s" % (type(self).__name__.encode('ascii', 'ignore'),self.Guid,self.ui_string.encode('ascii', 'ignore') if self.ui_string else '')

    def __str__(self):
        _ind = self.indent + DEF_INDENT
        _s = ''
        if self.MD5         : _s  = "\n%sMD5   : %s" % (_ind,self.MD5)
        if self.SHA1        : _s += "\n%sSHA1  : %s" % (_ind,self.SHA1)
        if self.SHA256      : _s += "\n%sSHA256: %s" % (_ind,self.SHA256)
        if self.MD5_AC      : _s += "\n%sAC MD5   : %s" % (_ind,self.MD5_AC)
        if self.SHA1_AC     : _s += "\n%sAC SHA1  : %s" % (_ind,self.SHA1_AC)
        if self.SHA256_AC   : _s += "\n%sAC SHA256: %s" % (_ind,self.SHA256_AC)
        if self.MD5_NT      : _s += "\n%sNT MD5   : %s" % (_ind,self.MD5_NT)
        if self.SHA1_NT     : _s += "\n%sNT SHA1  : %s" % (_ind,self.SHA1_NT)
        if self.SHA256_NT   : _s += "\n%sNT SHA256: %s" % (_ind,self.SHA256_NT)
        if self.MD5_ACNT    : _s += "\n%sACNT MD5   : %s" % (_ind,self.MD5_ACNT)
        if self.SHA1_ACNT   : _s += "\n%sACNT SHA1  : %s" % (_ind,self.SHA1_ACNT)
        if self.SHA256_ACNT : _s += "\n%sACNT SHA256: %s" % (_ind,self.SHA256_ACNT)
        return _s


    def write_file( self, filename, buffer ):
        try:
            f = open(filename, 'ab')
        except:
            return 0
        f.write( buffer )
        f.close()
    
        return True
    

    def calc_hashes( self, off=0 ):
        if self.Image is None: return
        hmd5 = hashlib.md5()
        hmd5.update( self.Image[off:] )
        self.MD5 = hmd5.hexdigest()
        hsha1 = hashlib.sha1()
        hsha1.update( self.Image[off:] )
        self.SHA1   = hsha1.hexdigest()
        hsha256 = hashlib.sha256()
        hsha256.update( self.Image[off:] )
        self.SHA256 = hsha256.hexdigest()
        if type(self) == EFI_SECTION:
            if self.Type == EFI_SECTION_PE32:
                self.pe_info = pe_extractor( self.Image[off:] )
                #authenticode_data_()
                #try:
                ac_image = authenticode_data_(self.Image[off:])
                if ac_image != self.Image[off:]:
                    ac_hmd5 = hashlib.md5()
                    ac_hmd5.update( ac_image )
                    self.MD5_AC = ac_hmd5.hexdigest()
                    ac_hsha1 = hashlib.sha1()
                    ac_hsha1.update( ac_image )
                    self.SHA1_AC   = ac_hsha1.hexdigest()
                    ac_hsha256 = hashlib.sha256()
                    ac_hsha256.update( ac_image )
                    self.SHA256_AC = ac_hsha256.hexdigest()
                nt_image = image_minus_timestamp_(self.Image[off:])
                if nt_image != self.Image[off:]:
                    nt_hmd5 = hashlib.md5()
                    nt_hmd5.update( nt_image )
                    self.MD5_NT = nt_hmd5.hexdigest()
                    nt_hsha1 = hashlib.sha1()
                    nt_hsha1.update( nt_image )
                    self.SHA1_NT   = nt_hsha1.hexdigest()
                    nt_hsha256 = hashlib.sha256()
                    nt_hsha256.update( nt_image )
                    self.SHA256_NT = nt_hsha256.hexdigest()
                acnt_image =  authenticode_data_minus_timestamp_(self.Image[off:])
                if acnt_image != self.Image[off:]:
                    acnt_hmd5 = hashlib.md5()
                    acnt_hmd5.update( acnt_image )
                    self.MD5_ACNT = acnt_hmd5.hexdigest()
                    acnt_hsha1 = hashlib.sha1()
                    acnt_hsha1.update( acnt_image )
                    self.SHA1_ACNT   = acnt_hsha1.hexdigest()
                    acnt_hsha256 = hashlib.sha256()
                    acnt_hsha256.update( acnt_image )
                    self.SHA256_ACNT = acnt_hsha256.hexdigest()
                #except:
                #    pass
                #    #print "authenticode_data_ failed"
                #    #self.write_file ( "/tmp/test-"+self.MD5 , self.Image[off:] )
                    

class EFI_FV(EFI_MODULE):
    def __init__(self, Offset, Guid, Size, Attributes, HeaderSize, Checksum, ExtHeaderOffset, Image, CalcSum):
        super(EFI_FV, self).__init__(Offset, Guid, HeaderSize, Attributes, Image)
        self.Size            = Size
        self.Checksum        = Checksum
        self.ExtHeaderOffset = ExtHeaderOffset
        self.CalcSum         = CalcSum

    def __str__(self):
        schecksum = ('%04Xh (%04Xh) *** checksum mismatch ***' % (self.Checksum,self.CalcSum)) if self.CalcSum != self.Checksum else ('%04Xh' % self.Checksum)
        _s = "\n%s%s +%08Xh {%s}: Size %08Xh, Attr %08Xh, HdrSize %04Xh, ExtHdrOffset %08Xh, Checksum %s\n" % (self.indent,type(self).__name__,self.Offset,self.Guid,self.Size,self.Attributes,self.HeaderSize,self.ExtHeaderOffset,schecksum)
        _s += super(EFI_FV, self).__str__()
        return _s

class EFI_FILE(EFI_MODULE):
    def __init__(self, Offset, Guid, Type, Attributes, State, Checksum, Size, Image, HeaderSize, UD, CalcSum):
        super(EFI_FILE, self).__init__(Offset, Guid, HeaderSize, Attributes, Image)
        self.Name        = Guid
        self.Type        = Type
        self.State       = State
        self.Size        = Size
        self.Checksum    = Checksum
        self.UD          = UD
        self.CalcSum     = CalcSum
        hsha256 = hashlib.sha256()
        hsha256.update( self.Image )
        self.SHA256 = hsha256.hexdigest()

    def __str__(self):
        schecksum = ('%04Xh (%04Xh) *** checksum mismatch ***' % (self.Checksum,self.CalcSum)) if self.CalcSum != self.Checksum else ('%04Xh' % self.Checksum)
        _s = "\n%s+%08Xh %s\n%sType %02Xh, Attr %08Xh, State %02Xh, Size %06Xh, Checksum %s" % (self.indent,self.Offset,self.name(),self.indent,self.Type,self.Attributes,self.State,self.Size,schecksum)
        _s += (super(EFI_FILE, self).__str__() + '\n')
        return _s

class EFI_SECTION(EFI_MODULE):
    def __init__(self, Offset, Name, Type, Image, HeaderSize):
        super(EFI_SECTION, self).__init__(Offset, None, HeaderSize, None, Image)
        self.Name        = Name
        self.Type        = Type
        self.DataOffset  = None

        # parent GUID used in search, export to JSON/log
        self.parentGuid  = None
    
    def name(self):
        return "%s section of binary {%s} %s" % (self.Name.encode('ascii', 'ignore'),self.parentGuid,self.ui_string.encode('ascii', 'ignore') if self.ui_string else '')

    def __str__(self):
        _s = "%s+%08Xh %s: Type %02Xh" % (self.indent,self.Offset,self.name(),self.Type)
        if self.Guid: _s += " GUID {%s}" % self.Guid
        if self.Attributes: _s += " Attr %04Xh" % self.Attributes
        if self.DataOffset: _s += " DataOffset %04Xh" % self.DataOffset
        _s += super(EFI_SECTION, self).__str__()
        return _s


def build_efi_modules_tree( _uefi, fwtype, data, Size, offset, polarity ):
    sections = []
    secn = 0

    _off, next_offset, _name, _type, _img, _hdrsz = NextFwFileSection( data, Size, offset, polarity )
    while next_offset is not None:
        if _name is not None:
            sec = EFI_SECTION( _off, _name, _type, _img, _hdrsz )
            # pick random file name in case dumpall=False - we'll need it to decompress the section
            sec_fs_name = "sect%02d_%s" % (secn, ''.join(random.choice(string.ascii_lowercase) for _ in range(4)))

            if sec.Type in EFI_SECTIONS_EXE:
                # "leaf" executable section: update hashes and check against match criteria
                sec.calc_hashes( sec.HeaderSize )
            elif sec.Type == EFI_SECTION_USER_INTERFACE:
                # "leaf" UI section: update section's UI name
                sec.ui_string = unicode(sec.Image[sec.HeaderSize:], "utf-16-le", errors="ignore")[:-1]
            elif sec.Type == EFI_SECTION_GUID_DEFINED:
                guid0, guid1, guid2, guid3, sec.DataOffset, sec.Attributes = struct.unpack(EFI_GUID_DEFINED_SECTION, sec.Image[sec.HeaderSize:sec.HeaderSize+EFI_GUID_DEFINED_SECTION_size])
                sec.Guid = guid_str(guid0, guid1, guid2, guid3)

            # "container" sections: keep parsing
            if sec.Type in (EFI_SECTION_COMPRESSION, EFI_SECTION_GUID_DEFINED, EFI_SECTION_FIRMWARE_VOLUME_IMAGE):
                if sec.Type == EFI_SECTION_COMPRESSION:
                    ul, ct = struct.unpack(EFI_COMPRESSION_SECTION, sec.Image[sec.HeaderSize:sec.HeaderSize+EFI_COMPRESSION_SECTION_size])
                    d = decompress_section_data( _uefi, "", sec_fs_name, sec.Image[sec.HeaderSize+EFI_COMPRESSION_SECTION_size:], ct, True )
                    if (d is None) and (ct == 2) and (len(sec.Image[sec.HeaderSize+EFI_COMPRESSION_SECTION_size:]) > 4):
                        d = decompress_section_data( _uefi, "", sec_fs_name, sec.Image[sec.HeaderSize+EFI_COMPRESSION_SECTION_size + 4:], ct, True )
                    if d:
                        sec.children = build_efi_modules_tree( _uefi, fwtype, d, len(d), 0, polarity )
                elif sec.Type == EFI_SECTION_GUID_DEFINED:
                    if sec.Guid == EFI_CRC32_GUIDED_SECTION_EXTRACTION_PROTOCOL_GUID:
                        sec.children = build_efi_modules_tree( _uefi, fwtype, sec.Image[sec.DataOffset:], Size - sec.DataOffset, 0, polarity )
                    elif sec.Guid == LZMA_CUSTOM_DECOMPRESS_GUID or sec.Guid == TIANO_DECOMPRESSED_GUID:
                        d = decompress_section_data( _uefi, "", sec_fs_name, sec.Image[sec.DataOffset:], 2, True )
                        if d is None:
                            d = decompress_section_data( _uefi, "", sec_fs_name, sec.Image[sec.HeaderSize+EFI_GUID_DEFINED_SECTION_size:], 2, True )
                        if d:
                            sec.children = build_efi_modules_tree( _uefi, fwtype, d, len(d), 0, polarity )
                    else:
                        sec.children = build_efi_model( _uefi, sec.Image[sec.HeaderSize:], fwtype )
                elif sec.Type == EFI_SECTION_FIRMWARE_VOLUME_IMAGE:
                    children = build_efi_file_tree( _uefi, sec.Image[sec.HeaderSize:], fwtype )
                    if not children is None:
                        sec.children = children

            sections.append(sec)
        _off, next_offset, _name, _type, _img, _hdrsz = NextFwFileSection( data, Size, next_offset, polarity )
        secn += 1
    return sections
    
# build_efi_file_tree - extract EFI FV file from EFI image and build an object tree
#
# Input arguements:
# _uefi    - instance of chipsec.hal.uefi.UEFI class
# fv_image - fv_image containing files

def build_efi_file_tree ( _uefi, fv_img, fwtype):
    fv_size, HeaderSize, Attributes = GetFvHeader(fv_img)
    polarity = Attributes & EFI_FVB2_ERASE_POLARITY
    foff, next_offset, fname, ftype, fattr, fstate, fcsum, fsz, fimg, fhdrsz, fUD, fcalcsum = NextFwFile( fv_img, fv_size, HeaderSize, polarity )
    fv = []
    while next_offset is not None:
        if fname:
            fwbin = EFI_FILE( foff, fname, ftype, fattr, fstate, fcsum, fsz, fimg, fhdrsz, fUD, fcalcsum )
            fwbin.calc_hashes()
            if fwbin.Type not in (EFI_FV_FILETYPE_ALL, EFI_FV_FILETYPE_RAW, EFI_FV_FILETYPE_FFS_PAD) or fwbin.State not in (EFI_FILE_HEADER_CONSTRUCTION, EFI_FILE_HEADER_INVALID, EFI_FILE_HEADER_VALID):
                fwbin.children = build_efi_modules_tree( _uefi, fwtype, fwbin.Image, fwbin.Size, fwbin.HeaderSize, polarity )
                fv.append(fwbin)
            elif fwbin.Type == EFI_FV_FILETYPE_RAW:
                if fwbin.Name != NVAR_NVRAM_FS_FILE:
                    fwbin.children = build_efi_tree( _uefi, fwbin.Image[fhdrsz:], fwtype )
                    fv.append(fwbin)
                else:
                    fwbin.isNVRAM   = True
                    fwbin.NVRAMType = FWType.EFI_FW_TYPE_NVAR
                    fv.append(fwbin)
        foff, next_offset, fname, ftype, fattr, fstate, fcsum, fsz, fimg, fhdrsz, fUD, fcalcsum = NextFwFile( fv_img, fv_size, next_offset, polarity )
    return fv
#
# build_efi_tree - extract EFI modules (FV, files, sections) from EFI image and build an object tree
#
# Input arguments:
#   _uefi          - instance of chipsec.hal.uefi.UEFI class  
#   data           - an image containing UEFI firmware volumes
#   fwtype         - platform specific firmware type used to detect NVRAM format (VSS, EVSA, NVAR...)
#
def build_efi_tree( _uefi, data, fwtype ):
    fvolumes = []
    fv_off, fv_guid, fv_size, fv_attr, fv_hdrsz, fv_csum, fv_hdroff, fv_img, fv_calccsum = NextFwVolume( data )
    while fv_off is not None:
        fv = EFI_FV( fv_off, fv_guid, fv_size, fv_attr, fv_hdrsz, fv_csum, fv_hdroff, fv_img, fv_calccsum )
        fv.calc_hashes()

        # Detect File System firmware volumes
        if fv.Guid in (EFI_PLATFORM_FS_GUIDS + EFI_FS_GUIDS):
            fwbin = build_efi_file_tree ( _uefi, fv_img, fwtype)
            for i in fwbin:
			    fv.children.append(i)

        # Detect NVRAM firmware volumes
        elif fv.Guid in EFI_NVRAM_GUIDS: # == VARIABLE_STORE_FV_GUID:
            fv.isNVRAM = True
            try:
                fv.NVRAMType = identify_EFI_NVRAM( fv.Image ) if fwtype is None else fwtype
            except: logger().warn("couldn't identify NVRAM in FV {%s}" % fv.Guid)

        fvolumes.append(fv)
        fv_off, fv_guid, fv_size, fv_attr, fv_hdrsz, fv_csum, fv_hdroff, fv_img, fv_calccsum = NextFwVolume( data, fv.Offset + fv.Size )

    return fvolumes

#
# update_efi_tree propagates EFI file's GUID down to all sections and
# UI_string from the corresponding section, if found, up to the EFI file at the same time
# File GUID and UI string are then used when searching for EFI files and executable sections
#
def update_efi_tree(modules, parent_guid=None):
    ui_string = None
    for m in modules:
        if type(m) == EFI_FILE:
           parent_guid = m.Guid
        elif type(m) == EFI_SECTION:
           # if it's a section update its parent file's GUID
           m.parentGuid = parent_guid
           if m.Type == EFI_SECTION_USER_INTERFACE:
               # if UI section (leaf), update ui_string in sibling sections including in PE/TE,
               # and propagate it up untill and including parent EFI file
               for m1 in modules: m1.ui_string = m.ui_string
               return m.ui_string
        # update parent file's GUID in all children nodes
        if len(m.children) > 0:
            ui_string = update_efi_tree(m.children, parent_guid)
            # if it's a EFI file then update its ui_string with ui_string extracted from UI section
            if ui_string and (type(m) in (EFI_FILE, EFI_SECTION)):
                m.ui_string = ui_string
                if (type(m) == EFI_FILE):
                    ui_string = None
    return ui_string

def build_efi_model( _uefi, data, fwtype ):
    # Try PFS first
    result = ParsePFS(data)
    if result is not None:
        model = []
        for d in result[0]:
            m = build_efi_tree( _uefi, d, fwtype )
            model.extend(m)
        if len(result[1]) > 0:
            m = build_efi_tree( _uefi, result[1], fwtype )
            model.extend(m)
    else:
        model = build_efi_tree( _uefi, data, fwtype )
    update_efi_tree(model)
    return model

def FILENAME(mod, parent, modn):
    fname = "%02d_%s" % (modn,mod.Guid)
    if type(mod) == EFI_FILE:
        type_s = FILE_TYPE_NAMES[mod.Type] if mod.Type in FILE_TYPE_NAMES.keys() else ("UNKNOWN_%02X" % mod.Type)
        fname = "%s.%s" % (fname,type_s)
    elif type(mod) == EFI_SECTION:
        fname = "%02d_%s" % (modn,mod.Name)
        if mod.Type in EFI_SECTIONS_EXE:
            if parent.ui_string:
                if (parent.ui_string.endswith(".efi")):
                    fname = parent.ui_string
                else:
                    fname = "%s.efi" % parent.ui_string
            else:                fname = "%s.%s" % (fname,type2ext[mod.Type])
    return fname

def dump_efi_module(mod, parent, modn, path):
    fname = FILENAME(mod, parent, modn)
    mod_path = os.path.join(path, fname)
    write_file(mod_path, mod.Image[mod.HeaderSize:] if type(mod) == EFI_SECTION else mod.Image)
    if type(mod) == EFI_SECTION or WRITE_ALL_HASHES:
        if mod.MD5   : write_file(("%s.md5"    % mod_path), mod.MD5)
        if mod.SHA1  : write_file(("%s.sha1"   % mod_path), mod.SHA1)
        if mod.SHA256: write_file(("%s.sha256" % mod_path), mod.SHA256)
    return mod_path

class EFIModuleType:
  SECTION_EXE = 0
  SECTION     = 1
  FV          = 2
  FILE        = 4

def search_efi_tree(modules, search_callback, match_module_types=EFIModuleType.SECTION_EXE, findall=True):
    matching_modules = []
    for m in modules:
        if search_callback is not None:
            if ((match_module_types & EFIModuleType.SECTION     == EFIModuleType.SECTION)     and type(m) == EFI_SECTION) or \
               ((match_module_types & EFIModuleType.SECTION_EXE == EFIModuleType.SECTION_EXE) and (type(m) == EFI_SECTION and m.Type in EFI_SECTIONS_EXE)) or \
               ((match_module_types & EFIModuleType.FV          == EFIModuleType.FV)          and type(m) == EFI_FV) or \
               ((match_module_types & EFIModuleType.FILE        == EFIModuleType.FILE)        and type(m) == EFI_FILE):
                if search_callback(m):
                    matching_modules.append(m)
                    if not findall: return True
        
        # recurse search if current module node has children nodes
        if len(m.children) > 0:
            matches = search_efi_tree(m.children, search_callback, match_module_types, findall)
            if len(matches) > 0:
                matching_modules.extend(matches)
                if not findall: return True

    return matching_modules

def match_FV_efi_tree(modules, efi_whitelist, match_module_types=EFIModuleType.FILE|EFIModuleType.FV):
    not_matching_modules = []
    for m in modules:
        print "Obj sha: %s"%m.SHA256
        print "Obj type: %s"%type(m)
        if ((match_module_types & EFIModuleType.FILE        == EFIModuleType.FILE)        and type(m) == EFI_FILE) or \
           ((match_module_types & EFIModuleType.FV          == EFIModuleType.FV)          and type(m) == EFI_FV):
            if (m.SHA256 in efi_whitelist):
                    print "Found in whitelist"
                    continue # FV in whitelist, stop check this FV
            else:
                # recurse search if current module node has children nodes
                if len(m.children) > 0:
                    print "Decode more because EFI_FILE|EFI_FV is not in whitelist and has children"
                    not_matches = match_FV_efi_tree(m.children, efi_whitelist, match_module_types)
                    if not_matches:
                        not_matching_modules.extend(not_matches)
                else:
                    if not m.isNVRAM:
                        print "FV|FILE doesn't have children and not in whitelist"
                        #r = [];r.append(m.SHA256)
                        #not_matching_modules.extend(r)
                    else:
                        print "This is NVRAM"
        else:
            # recurse search if current module node has children nodes
            if len(m.children) > 0:
                print "Decode more because type(m) is not (EFI_FILE|EFI_FV) and has children"
                not_matches = match_FV_efi_tree(m.children, efi_whitelist, match_module_types)
                if not_matches:
                    not_matching_modules.extend(not_matches)
            else:
               print "Obj without childs"
               if  (type(m) == EFI_SECTION and m.Type in EFI_SECTIONS_EXE):
                   if m.SHA256_ACNT:
                       r = [];r.append(m.SHA256_ACNT)
                       not_matching_modules.extend(r)
                   else:
                       r = [];r.append(m.SHA256)
                       not_matching_modules.extend(r)

        
    return not_matching_modules


def save_efi_tree(_uefi, modules, parent=None, save_modules=True, path=None, save_log=True, lvl=0):
    mod_dir_path = None
    modules_arr = []
    modn = 0
    for m in modules:
        md = {}
        m.indent = DEF_INDENT*lvl
        if save_log: logger().log(m)

        # extract all non-function non-None members of EFI_MODULE objects
        attrs = [a for a in dir(m) if not callable(getattr(m,a)) and not a.startswith("__") and (getattr(m,a) is not None)]
        for a in attrs: md[a] = getattr(m,a)
        md["class"] = type(m).__name__
        # remove extra attributes
        for f in ["Image","indent"]: del md[f]

        # save EFI module image, make sub-directory for children
        if save_modules:
            mod_path = dump_efi_module(m, parent, modn, path)
            try:
                md["file_path"] = os.path.relpath(mod_path[4:] if mod_path.startswith("\\\\?\\") else mod_path)
            except:
                md["file_path"] = mod_path.split(os.sep)[-1]
            if m.isNVRAM or len(m.children) > 0:
                mod_dir_path = "%s.dir" % mod_path
                if not os.path.exists(mod_dir_path): os.makedirs(mod_dir_path)
                if m.isNVRAM:
                    try:
                        if m.NVRAMType is not None:
                            # @TODO: technically, NVRAM image should be m.Image but
                            # getNVstore_xxx functions expect FV than a FW file within FV
                            # so for EFI_FILE type of module using parent's Image as NVRAM
                            nvram = parent.Image if (type(m) == EFI_FILE and type(parent) == EFI_FV) else m.Image
                            _uefi.parse_EFI_variables( os.path.join(mod_dir_path, 'NVRAM'), nvram, False, m.NVRAMType )
                        else: raise
                    except: logger().warn( "couldn't extract NVRAM in {%s} using type '%s'" % (m.Guid,m.NVRAMType) )
    
        # save children modules
        if len(m.children) > 0:
            md["children"] = save_efi_tree(_uefi, m.children, m, save_modules, mod_dir_path, save_log, lvl+1)
        else:
            del md["children"]

        modules_arr.append(md)
        modn += 1

    return modules_arr


def parse_uefi_region_from_file( _uefi, filename, fwtype, outpath = None):
    # Create an output folder to dump EFI module tree
    if outpath is None: outpath = "%s.dir" % filename
    if not os.path.exists( outpath ): os.makedirs( outpath )

    # Read UEFI image binary to parse
    rom = read_file(filename)

    # Parse UEFI image binary and build a tree hierarchy of EFI modules
    tree = build_efi_model(_uefi, rom, fwtype)

    # Save entire EFI module hierarchy on a file-system and export into JSON
    tree_json = save_efi_tree(_uefi, tree, path=outpath)
    write_file( "%s.UEFI.json" % filename, json.dumps(tree_json, indent=2, separators=(',', ': ')) )


def decode_uefi_region(_uefi, pth, fname, fwtype):

    bios_pth = os.path.join( pth, fname + '.dir' )
    if not os.path.exists( bios_pth ):
        os.makedirs( bios_pth )
    fv_pth = os.path.join( bios_pth, 'FV' )
    if not os.path.exists( fv_pth ):
        os.makedirs( fv_pth )

    # Decoding UEFI Firmware Volumes
    if logger().HAL: logger().log( "[spi_uefi] decoding UEFI firmware volumes..." )
    parse_uefi_region_from_file( _uefi, fname, fwtype, fv_pth )

    # Decoding EFI Variables NVRAM
    if logger().HAL: logger().log( "[spi_uefi] decoding UEFI NVRAM..." )
    region_data = read_file( fname )
    if fwtype is None:
        fwtype = identify_EFI_NVRAM( region_data )
        if fwtype is None: return
    elif fwtype not in fw_types:
        if logger().HAL: logger().error( "unrecognized NVRAM type %s" % fwtype )
        return
    nvram_fname = os.path.join( bios_pth, ('nvram_%s' % fwtype) )
    logger().set_log_file( (nvram_fname + '.nvram.lst') )
    _uefi.parse_EFI_variables( nvram_fname, region_data, False, fwtype )
