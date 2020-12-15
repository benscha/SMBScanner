# SMBScanner
Scan for Patterns in SMB Shares within IP Ranges

This Script will Scan for SMB Shares in defined IP Ranges. If Shares are accessible the Content will be searched for defined Patterns (Username, Passwords, secrets, ...)

  .SYNOPSIS  
    Get the IP addresses in a range and Scan for specific Patterns in SMB Shares
    

  .AUTHOR
  
   Benjamin Zulliger | Get-IP Range Function Barry CWT
   

  .EXAMPLE 
  
   .\ScanSMBSharesParamIP.ps1 -start 192.168.8.2 -end 192.168.8.20 -searchquery "admin,secret,pass,..."
   
   
  .EXAMPLE 
  
   .\ScanSMBSharesParamIP.ps1 -ip 192.168.8.2 -mask 255.255.255.0 -searchquery "admin,secret,pass,..."
   
   
  .EXAMPLE 
  
   .\ScanSMBSharesParamIP.ps1 -ip 192.168.8.3 -cidr 24 -searchquery "admin,secret,pass,..."
   
   
   .EXAMPLE 
   
   .\ScanSMBSharesParamIP.ps1 -ip 192.168.8.3 -cidr 24 -searchquery default
   
   
  .EXAMPLE
  
   .\ScanSMBSharesParamIP.ps1 
   Script will Start with an interactive Menu
   
   

  .OUTPUTS
  
   Search Results $exportFile Path can bedefined in Line 47
   
   "Path"                       ,"LineNumber","Line"
   "\\IP-Address\Share\Filename","19646"     ,"Content of this Line"
   
   LogFile of Scanned IP Addresses will be written to Current Folder SMB_ScanLog.txt

  .THX
  
  Thanks to Barry CWT for the Get-IPRange Function https://gallery.technet.microsoft.com/scriptcenter/List-the-IP-addresses-in-a-60c5bb6b
