Write-Output "Script started!"

# Path to the USB drive
$usbDrive = "E:"
$secretFile = "$usbDrive\secret.key.txt"
$expectedSecret = "MY_SUPER_SECRET_12345"  # Твій секретний текст тут

# Telegram Bot API Token та Chat ID (ВКАЖІТЬ СВОЇ ДАНІ ТУТ)
$telegramToken = "*****"  #  <---  IMPORTANT:  Double-check this!
$telegramChatId = "*****"    #  <---  IMPORTANT:  Double-check this!
$telegramMessage = "Try login without token"

# Path to the log file
$logDir = "D:\"
$logFile = Join-Path $logDir "script.log"

# Функція для відправки повідомлення в Telegram
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
            $logMessage = "Повідомлення Telegram відправлено успішно. Відповідь: $($response | ConvertTo-Json -Depth 3)"
            Write-Output $logMessage | Out-File -Append -FilePath $logFile
        } else {
            $logMessage = "Не вдалося відправити повідомлення Telegram. Response: $($response | ConvertTo-Json -Depth 3)"
            Write-Warning $logMessage | Out-File -Append -FilePath $logFile
        }
    } catch {
        $logMessage = "Помилка відправки повідомлення Telegram: $($_.Exception.Message)"
        Write-Error $logMessage | Out-File -Append -FilePath $logFile
    }
}

# Функція для запису в лог-файл
function Write-Log {
    param(
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "$timestamp - $message"
    Write-Output $logEntry | Out-File -Append -FilePath $logFile
}

# Функція для перевірки наявності процесу блокування
function Is-LockScreenActive {
    # Get-CimInstance не завжди доступний на старих системах, тому використовуємо try-catch
    try {
        $lockScreen = Get-CimInstance -ClassName Win32_Process -Filter "Name=' LogonUI.exe'"
        return ($lockScreen -ne $null)
    } catch {
        # Якщо не вдалося отримати інформацію, припускаємо, що блокування неактивне
        return $false
    }
}

# Функція для перезапуску скрипта
function Restart-Script {
    $logMessage = "Перезапуск скрипта..."
    Write-Output $logMessage | Out-File -Append -FilePath $logFile
    # Start-Process використовується для запуску нового процесу PowerShell
    Start-Process -FilePath "powershell.exe" -ArgumentList "-File `"$PSCommandPath`"" -Verb RunAs
    exit  # Завершуємо поточний процес скрипта
}

# Функція для додавання завдання до планувальника завдань
function Add-StartupTask {
    param(
        [string]$scriptPath,
        [string]$taskName
    )

    $principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -RunLevel Highest # System account
    $settings = New-ScheduledTaskSettingsSet -RunOnlyIfLoggedOn $false -AllowStartIfOnBatteries $true -DontStopIfGoingOnBatteries $true
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User "S-1-5-18" # Run at system logon

    try {
        Register-ScheduledTask -TaskName $taskName -InputObject $action -Trigger $trigger -Principal $principal -Settings $settings
        Write-Log "Startup task '$taskName' registered successfully."
    } catch {
        $logMessage = "Failed to register startup task '$taskName': $($_.Exception.Message)"
        Write-Error $logMessage | Out-File -Append -FilePath $logFile
    }
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

# Шлях до поточного скрипта
$scriptPath = $MyInvocation.MyCommand.Path
$taskName = "UnlockOnUSB"  # Назва завдання для планувальника

# Add startup task
Add-StartupTask -scriptPath $scriptPath -taskName $taskName

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
        $macAddress = (Get-NetAdapter | Where-Object {$_.Status -eq "Up"}).MacAddress[0]
        $fullMessage = "$telegramMessage`nPC Name: $computerName`nIP Address: $ipAddress`nMAC Address: $macAddress"
        Send-TelegramMessage -token $telegramToken -chatId $telegramChatId -message $fullMessage
        rundll32.exe user32.dll,LockWorkStation
        Restart-Script # Перезапускаємо скрипт після блокування
    }
} else {
    Write-Log "File not found at: $secretFile"
    Write-Log "File exists: $($false)"
    Write-Log "USB drive or file not found. Locking computer."
    $computerName = $env:COMPUTERNAME
    $ipAddress = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -ne "Loopback"}).IPAddress[0]
    $macAddress = (Get-NetAdapter | Where-Object {$_.Status -eq "Up"}).MacAddress[0]
    $fullMessage = "$telegramMessage`nPC Name: $computerName`nIP Address: $ipAddress`nMAC Address: $macAddress"
    Send-TelegramMessage -token $telegramToken -chatId $telegramChatId -message $fullMessage
    rundll32.exe user32.dll,LockWorkStation
    Restart-Script # Перезапускаємо скрипт після блокування
}

# Add a check to see if the script is run interactively before waiting for input
if ($PSBoundParameters.ContainsKey('MyInvocation') -and $MyInvocation.MyCommand.Name -eq $MyInvocation.InvocationName) {
    Write-Host 'Press any key to exit...'
    $x = $host.UI.RawUI.ReadKey([System.ConsoleKey]::NoEcho, [System.ConsoleKey]::IncludeKeyDown)
}
