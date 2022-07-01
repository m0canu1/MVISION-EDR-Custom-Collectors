# This collector returns the Failed Logins from Windows Event Log
$OutputEncoding = New-Object -typename System.Text.UTF8Encoding
# resize PS buffer size in order to avoid undesired line endings or trims in the output
$pshost = get-host
$pswindow = $pshost.ui.rawui
$newsize = $pswindow.buffersize
$newsize.height = 3000
$newsize.width = 3000
$pswindow.buffersize = $newsize

$failureReasonHash = @{ "%%2304" = "An Error occured during Logon."; "%%2305" = "The specified user account has expired."; "%%2306" = "The NetLogon component is not active."; "%%2307" = "Account locked out."; "%%2308" = "The user has not been granted the requested logon type at this machine."; "%%2309" = "The specified account's password has expired."; "%%2310" = "Account currently disabled."; "%%2311" = "Account logon time restriction violation."; "%%2312" = "User not allowed to logon at this computer."; "%%2313" = "Unknown user name or bad password."; "%%2314" = "Domain sid inconsistent."; "%%2315" = "Smartcard logon is required and was not used."}

$logonTypeHash = @{"2" = "Interactive"; "3" = "Network"; "4" = "Batch"; "5" = "Service"; "7" = "Unlock"; "8" = "NetworkCleartext";
                    "9" = "NewCredentials"; "10" = "RemoteInteractive"; "11" = "CachedInteractive"}

$events = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 300
foreach ($event in $events)
{
    $eventXML = [xml]$event.ToXml()

    $eventArray = New-Object -TypeName PSObject -Property @{
    EventID = $event.id
    EventTime = $event.timecreated
    SubjectUserName = $eventXML.Event.EventData.Data[1].'#text'
    SubjectDomainName = $eventXML.Event.EventData.Data[2].'#text'
    TargetUserName = $eventXML.Event.EventData.Data[5].'#text'
    TargetDomainName = $eventXML.Event.EventData.Data[6].'#text'
    failureReason = $eventXML.Event.EventData.Data[8].'#text'
    LogonType = $eventXML.Event.EventData.Data[10].'#text'
    NetworkInformation = $eventXML.Event.EventData.Data[19].'#text'
    NetworkPort = $eventXML.Event.EventData.Data[20].'#text'
        }

    # $eventid = $eventarray.eventid
    $SubjectUserName = $eventArray.SubjectUserName
    $SubjectDomainName = $eventArray.SubjectDomainName
    $TargetUserName = $eventarray.TargetUserName
    $TargetDomainName = $eventarray.TargetDomainName
    $EventLogonType = $logonTypeHash.($eventarray.logontype)
    $FailureReason = $failureReasonHash.($eventArray.failureReason)
    [datetime]$eventtime = $eventarray.eventtime
    [string]$dateformat = 'yyyy-MM-dd HH:mm:ss'
    $finaltime = $eventtime.ToString($dateformat)
    $SourceIP = $eventArray.Networkinformation
 

    write-output "$SubjectUserName, $SubjectDomainName,$TargetUserName,$TargetDomainName,$EventLogonType,$FailureReason,$Finaltime,$SourceIP"
} 