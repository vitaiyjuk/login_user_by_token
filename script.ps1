Write-Output "Script started!"

# Path to the USB drive
$usbDrive = "E:"
$secretFile = "$usbDrive\secret.key.txt"
$expectedSecret = "MY_SUPER_SECRET_12345"  # Your secret text here

# Telegram Bot API Token and Chat ID (ENTER YOUR DETAILS HERE)
$telegramToken = "TOKEN"  #  <---  IMPORTANT:  Double-check this!
$telegramChatId = "ID"    #  <---  IMPORTANT:  Double-check this!
$telegramMessage = "Sobaka sutula lize do PC"

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
            Write-Output "Telegram message sent successfully."
        } else {
            Write-Warning "Failed to send Telegram message. Response: $($response | ConvertTo-Json -Depth 3)"
        }
    } catch {
        Write-Error "Error sending Telegram message: $($_.Exception.Message)"
    }
}

Write-Output "Checking for file: $secretFile"

# Check if the file exists
if (Test-Path $secretFile) {
    Write-Output "File found at: $secretFile"
    Write-Output "File exists: $($true)"
    $actualSecret = Get-Content $secretFile -Raw
    Write-Output "Actual Secret: [$actualSecret]"
    if ($actualSecret.Trim() -eq $expectedSecret) {
        Write-Output "Key is correct. Access granted."
    } else {
        Write-Output "Key is incorrect. Locking computer."
        $computerName = $env:COMPUTERNAME
        $ipAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -ne "Loopback"}).IPAddress[0]
        $macAddress = (Get-NetAdapter | Where-Object {$_.Status -eq "Up"}).MacAddress[0]  # Get the MAC address of the first active adapter
        $fullMessage = "$telegramMessage`nPC Name: $computerName`nIP Address: $ipAddress`nMAC Address: $macAddress"
        Send-TelegramMessage -token $telegramToken -chatId $telegramChatId -message $fullMessage
        rundll32.exe user32.dll,LockWorkStation
    }
} else {
    Write-Output "File not found at: $secretFile"
    Write-Output "File exists: $($false)"
    Write-Output "USB drive or file not found. Locking computer."
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
