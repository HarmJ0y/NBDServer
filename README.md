#Invoke-NBDServer

Invoke-NBDServer is a PowerShell port of Jeff Bryner's (NBDServer project)[https://github.com/jeffbryner/NBDServer], (C) 2012 by Jeff Bryner and based on on nbdsrvr by (Folkert van Heusden)[http://www.vanheusden.com/windows/nbdsrvr/]. The original README for that project is located at https://github.com/jeffbryner/NBDServer/blob/master/README . Invoke-NBDServer utilizes PowerSploit's (Invoke-ReflectivePEInjection script)[https://github.com/mattifestation/PowerSploit/blob/master/CodeExecution/Invoke-ReflectivePEInjection.ps1] written by Joe Bialek (@JosephBialek).


Invoke-NBDServer lets you inject the architeture appropriate NBDServer executable into memory without touching disk. This allows you to perform disk forensics on a host from a remote machine.


* OriginalFiles/ contains the original source to Jeff's (NBDServer)[https://github.com/jeffbryner/NBDServer]
* VisualStudio/ contains the project ported to VisualStudio, with some additional modifications
* NBDServer.32.exe and NBDServer.64.exe are the newly compiled x86/x64 source binaries, respectively
* Invoke-NBDServer.ps1 is the modified Invoke-ReflectivePEInjection.ps1 script with base64 encoded versions of the binaries contained inside.

