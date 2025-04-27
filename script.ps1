Write-Output "Script started!"

# Path to the USB drive
$usbDrive = "E:"
$secretFile = "$usbDrive\secret.key.txt"
$expectedSecret = "MY_SUPER_SECRET_12345"  # Your secret text here

# Telegram Bot API Token and Chat ID (ENTER YOUR DETAILS HERE)
$telegramToken = "****"  #  <---  IMPORTANT:  Double-check this!
$telegramChatId = "****"    #  <---  IMPORTANT:  Double-check this!

$telegramMessage = "Autentefication without token"

# Path to the log file
$logDir = "D:\" # Змінено на вказану директорію
$logFile = Join-Path $logDir "script.log" # Створюємо повний шлях до файлу

# Function to send a message to Telegram
function Send-TelegramMessage {
    param(
        [string]$token,
        [string]$chatId,
        [string]$message
    )

    $telegramApiUrl = "https://api.telegram.org/bot$token/sendMessage"
    $body = @{
        chat_id = $chatId
        text    = $message
    }

    try {
        $response = Invoke-RestMethod -Uri $telegramApiUrl -Method Post -Body $body
        if ($response.ok -eq $true) {
            $logMessage = "Telegram message sent successfully. Response: $($response | ConvertTo-Json -Depth 3)"
            Write-Output $logMessage | Out-File -Append -FilePath $logFile
        } else {
            $logMessage = "Failed to send Telegram message. Response: $($response | ConvertTo-Json -Depth 3)"
            Write-Warning $logMessage | Out-File -Append -FilePath $logFile
        }
    } catch {
        $logMessage = "Error sending Telegram message: $($_.Exception.Message)"
        Write-Error $logMessage | Out-File -Append -FilePath $logFile
    }
}

# Function to write to the log file
function Write-Log {
    param(
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $message"
    Write-Output $logEntry | Out-File -Append -FilePath $logFile
}

# Create log directory if it doesn't exist
if (!(Test-Path $logDir)) {
    try {
        New-Item -ItemType Directory -Path $logDir | Out-File -Append -FilePath $logFile
        $logMessage = "Log directory created: $logDir"
        Write-Output $logMessage | Out-File -Append -FilePath $logFile
    } catch {
        $logMessage = "Failed to create log directory: $($_.Exception.Message)"
        Write-Error $logMessage | Out-File -Append -FilePath $logFile
        # Continue execution even if log directory creation fails
    }
}

Write-Log "Script started."
Write-Log "Checking for file: $secretFile"

# Check if the file exists
if (Test-Path $secretFile) {
    Write-Log "File found at: $secretFile"
    Write-Log "File exists: $($true)"
    $actualSecret = Get-Content $secretFile -Raw
    Write-Log "Actual Secret: [$actualSecret]"
    if ($actualSecret.Trim() -eq $expectedSecret) {
        Write-Log "Key is correct. Access granted."
    } else {
        Write-Log "Key is incorrect. Locking computer."
        $computerName = $env:COMPUTERNAME
        $ipAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -ne "Loopback"}).IPAddress[0]
        $macAddress = (Get-NetAdapter | Where-Object {$_.Status -eq "Up"}).MacAddress[0]  # Get the MAC address of the first active adapter
        $fullMessage = "$telegramMessage`nPC Name: $computerName`nIP Address: $ipAddress`nMAC Address: $macAddress"
        Send-TelegramMessage -token $telegramToken -chatId $telegramChatId -message $fullMessage
        rundll32.exe user32.dll,LockWorkStation
    }
} else {
    Write-Log "File not found at: $secretFile"
    Write-Log "File exists: $($false)"
    Write-Log "USB drive or file not found. Locking computer."
    $computerName = $env:COMPUTERNAME
    $ipAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -ne "Loopback"}).IPAddress[0]
    $macAddress = (Get-NetAdapter | Where-Object {$_.Status -eq "Up"}).MacAddress[0] # Get the MAC address of the first active adapter
    $fullMessage = "$telegramMessage`nPC Name: $computerName`nIP Address: $ipAddress`nMAC Address: $macAddress"
    Send-TelegramMessage -token $telegramToken -chatId $telegramChatId -message $fullMessage
    rundll32.exe user32.dll,LockWorkStation
}

# Add a check to see if the script is run interactively before waiting for input
if ($PSBoundParameters.ContainsKey('MyInvocation') -and $MyInvocation.MyCommand.Name -eq $MyInvocation.InvocationName) {
    Write-Host 'Press any key to exit...'
    $x = $host.UI.RawUI.ReadKey([System.ConsoleKey]::NoEcho, [System.ConsoleKey]::IncludeKeyDown)
}
