KeygenMe
========

This is an KeygenMe I wrote a while back for a number of reverse engineering community's I frequent. It's designed to be more educative than it is challenging, I wanted to demonstrate some common protection techniques used by executable protectors such as ASProtect and Enigma, alongside showing how a more complex license key system would work. For this reason, strings are not encrypted and the KeygenMe has been made intentionally verbose for ease of debugging and understanding.

So what protection does this thing employ?
1. Uses a Memory CRC check to verify internal routines have not been tampered with or ridden with breakpoints
2. Searches memory for software based breakpoints
3. Checks for existing hardware breakpoints
4. Uses multiple registration routines and calls into a fake one if the key is not formatted correctly
5. If HW BP's are found or memory is deemed corrupted, the registration routine is patched over and never called
6. Calls to the registration routine(s) are obfuscated with junk code

Okay, what about the license system?
1. Uses MD5, AES to hash and encrypt/decrypt
2. Uses RSA to sign and verify keys
3. All keys are tied to hardware ID's
4. Uses a keyfile

There's quite a bit more to the registration system, I suggest taking a look through the code to see how it works.

Here's what happens if you try and set a breakpoint within registration routine, which can normally occur after doing a simple string search for anything matching "Registration successful", which is often the first method of attack for newer reverse engineer's. 


Name: KOrUPt
Key: VT39-37NQ-ZW3J-4WKZ-24UF-X92K-BRNA-DHF6-2RRR-7VWU-G1NH-TBF8-GVP1
Signature: ...


DetectHwBreakpoints()
ScanForSwBreakpoints()
CRC32_Generate_Table()
VerifyMemory()
CRC32_Generate_CRC()
>> Memory CRC = 0x46fe9266
>> Memory corrupt!
CheckKeyFormat()
>> Key format valid!

Running the application as intended with a valid key produces the following output:
Attempting to register application with given key file

P:\Development\KeygenMe>KeygenMe.exe


Name: KOrUPt
Key: VT39-37NQ-ZW3J-4WKZ-24UF-X92K-BRNA-DHF6-2RRR-7VWU-G1NH-TBF8-GVP1
Signature: ...


DetectHwBreakpoints()
ScanForSwBreakpoints()
CRC32_Generate_Table()
VerifyMemory()
CRC32_Generate_CRC()
>> Memory CRC = 0x2479fe52
CheckKeyFormat()
>> Key format valid!
RealRegistrationRoutine()
>> Key decoded successfully!
>> Pseudo Random Numbers within range!
-----
>> Key type: Pro key
>> An eerie myst shrouds your undead aurua o.0
-----
>> Key hardware id: C2480680-94E1FA5E
>> Local hardware id: C2480680-94E1FA5E
>> Hardware fingerprint valid
>> Checking Key signature
VerifyLicenseKey()
>> License key valid!!

P:\Development\KeygenMe>pause
Press any key to continue . . .


The repo contains several files, compiled executable's alongside the source code files and others such as:
1. GenerateKey.bat - A simple batch file which runs the Keygen and generates a key file for the KeygenMe
2. RegisterApplication.bat - Another batch file that runs the KeygenMe and pauses so the output can be read
3. Licence.key, public.key, private.key - This is the key file itself and the public/private RSA key pair used to sign and verify license keys
