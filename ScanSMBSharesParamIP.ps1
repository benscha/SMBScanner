<# 
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
#> 



### Parameter ###
param
(
  [string]$start,
  [string]$end,
  [string]$ip,
  [string]$mask,
  [int]$cidr,
  [string]$searchquery
)


### Definitions ###

# Search Results LogPath
$LogPath = "SMB_ScanLog.txt"



### Functions ###
# IP Menu Function
function Show-Menu-IP
{
    param (
        [string]$Title = 'Define IP Addresses'
    )
    Clear-Host
    Write-Output "========================== $Title =========================="
    Write-Output ""
    Write-Output "1: Scan with Start and End IP Address (10.10.10.10 - 10.10.10.20)"
    Write-Output  "   Press '1' for this option."
    Write-Output ""
    Write-Output "2: Scan with Network Mask 10.0.0.0 255.255.255.0:"
    Write-Output  "   Press '2' for this option."
    Write-Output ""
    Write-Output "3: Scan with CIDR IP Rang 10.0.0.0/24:"
    Write-Output  "   Press '3' for this option."
    Write-Output ""
    Write-Output "Q: Press 'Q' to quit."
    Write-Output ""
}

# Search String Menu Function
function Show-Menu-Search
{
    param (
        [string]$Title = 'Search String'
    )
    Clear-Host
    Write-Output "========================== $Title =========================="
    Write-Output ""
    Write-Output "1: Use Custom Search Patterns SAMPLE: beer,bacon,party,...:"
    Write-Output  "   Press '1' for this option."
    Write-Output ""
    Write-Output "2: Use default Search Patterns:  admin,secret,pass,srv,user,credential"
    Write-Output  "   Press '2' for this option."
    Write-Output ""
    Write-Output "Q: Press 'Q' to quit."
    Write-Output ""
}

# Get-IPRange Function
function Get-IPrange
{

function IP-toINT64 () {
  param ($ip)

  $octets = $ip.split(".")
  return [int64]([int64]$octets[0]*16777216 +[int64]$octets[1]*65536 +[int64]$octets[2]*256 +[int64]$octets[3])
}

function INT64-toIP() {
  param ([int64]$int)

  return (([math]::truncate($int/16777216)).tostring()+"."+([math]::truncate(($int%16777216)/65536)).tostring()+"."+([math]::truncate(($int%65536)/256)).tostring()+"."+([math]::truncate($int%256)).tostring() )
}

if ($ip) {$ipaddr = [Net.IPAddress]::Parse($ip)}
if ($cidr) {$maskaddr = [Net.IPAddress]::Parse((INT64-toIP -int ([convert]::ToInt64(("1"*$cidr+"0"*(32-$cidr)),2)))) }
if ($mask) {$maskaddr = [Net.IPAddress]::Parse($mask)}
if ($ip) {$networkaddr = new-object net.ipaddress ($maskaddr.address -band $ipaddr.address)}
if ($ip) {$broadcastaddr = new-object net.ipaddress (([system.net.ipaddress]::parse("255.255.255.255").address -bxor $maskaddr.address -bor $networkaddr.address))}

if ($ip) {
  $startaddr = IP-toINT64 -ip $networkaddr.ipaddresstostring
  $endaddr = IP-toINT64 -ip $broadcastaddr.ipaddresstostring
} else {
  $startaddr = IP-toINT64 -ip $start
  $endaddr = IP-toINT64 -ip $end
}


for ($i = $startaddr; $i -le $endaddr; $i++)
{
  INT64-toIP -int $i
}

}



# Menu IP
    if ((($start.Length -lt 7) -eq $true ) -and (($end.Length -lt 7 ) -eq $true ) -and (($ip.Length -lt 7 ) -eq $true ) -and (($mask.Length -lt 7 ) -eq $true ) -and (($cidr.Length -lt 2 ) -eq $true )) {


    Show-Menu-IP –Title 'Define IP Addresses'
    $selection = Read-Host "Please make a selection"



    # Ask for Settings Start End IP
    if ($selection -eq 1) {$start = Read-Host -Prompt "Start IP Address"
    $end = Read-Host -Prompt "End IP Address"
    }

    # Ask for Start IP and Subnet Mask
    if ($selection -eq 2) {$ip = Read-Host -Prompt "Define Subnet Mask"
    $mask = Read-Host -Prompt "Subnet Mask"
    }

    # Ask for Start IP and CIDR
    if ($selection -eq 3) {$ip = Read-Host -Prompt "Define CIDR"
    $cidr = Read-Host -Prompt "CIDR"
    }

    if ($selection -eq "q" ) {
    Break Script
    }

     }


# Generate IP Range
if ((($ip -eq $null) -eq $false ) -and (($mask -eq $null) -eq $false ))   { $Servers = Get-IPRange -ip $ip -mask $mask }
if ((($start -eq $null) -eq $false ) -and (($end -eq $null) -eq $false ))   { $Servers = Get-IPRange -start $start -end $end }
if ((($ip -eq $null) -eq $false ) -and (($cidr -eq $null) -eq $false ))   { $Servers = Get-IPRange -ip $ip -cidr $cidr }


# No Search Pattern defined
if ($searchquery -eq "defaut") { $searchquery = "admin,secret,pass,srv,user,credential" }

if (($searchquery.Length -eq 0 ) -eq $true ) { Show-Menu-Search
                                                $selectionsearch = Read-Host "Please make a selection"

    # Ask for search Patterns
    if ($selectionsearch -eq 1) { $searchquery = Read-Host -Prompt "Your search Patterns (Comma separated)"  }

    # Ask for Start IP and Subnet Mask
    if ($selectionsearch -eq 2) { $searchquery = "admin,secret,pass,srv,user,credential" }

    }


if (($searchquery.Length -gt 0 ) -eq $true ) { $search = $searchquery -split ',' }



# Scanning Process
ForEach ( $Server in $Servers) {

            $Delimiter =";"
            $Log = (Get-Date -Format "dd.MM.yyyy") + $Delimiter + (Get-Date -Format "hh:mm") + $Delimiter + $Server

            $Log | Out-File $LogPath -Append
  

            # Test if Host is up
            Write-Output "Test if $Server is up"
            if (Test-Connection $Server -Count 1 -ErrorAction SilentlyContinue) {


            $hostname = [System.Net.Dns]::GetHostByAddress($Server).HostName
            Write-Output "Scanning $hostname"
  
                # List of Shares on Server
                $SharesRAW = net view \\$Server /all 2>$null | Select-Object -Skip 7 | Select-Object -SkipLast 2
                $SharesRAW = $SharesRAW | Where-Object {$_ -like "*Platte*"}
                $SharesRAW = $SharesRAW | Where-Object {$_.tostring() -notlike 'C$*' -and $_.tostring() -notlike 'D$*' -and $_.tostring() -notlike 'E$*' -and $_.tostring() -notlike 'IPC$*' -and $_.tostring() -notlike 'ADMIN$*'}
                $SharesRAW = $SharesRAW -replace "      Platte"

                $SharesRAW = $SharesRAW -replace "(  .*)"
                # $SharesRAW

                    ForEach ( $Share in $SharesRAW ) {

                            Write-Output $Share
                            # Join UNC Path
                            $UNCPath = ""
                            $UNCPath += "\\"
                            $UNCPath += $Server
                            $UNCPath += "\"
                            $UNCPath += $Share

                            # Export File Definition
                            $pattern = '[\\/]'
                            $exportPath = $UNCPath -replace $pattern, "."
                            $exportFile = $exportPath.Trim(".")
                            $exportFile += ".txt"
                            $exportFile = $exportFile -replace (" ","")

                # Search for File Content
                Get-ChildItem -Path $UNCPath -Recurse | Select-String -Pattern $search | Select-Object -Property Path,Linenumber,Line | Export-CSV $exportFile

                # Remove empty Files
                If ( (Get-Item $exportFile).Length -lt 100) { Remove-Item $exportFile }

    }
   }
  }
