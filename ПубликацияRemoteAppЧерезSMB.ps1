#запускать на RD Connection Broker
#-----------------------------
#события windows:
#16387 - публикация RDApp завершена
#16408 - обновление свойств публикации завершено
#16388 - отмена публикации завершена
#-----------------------------
#при создании в планировщике задания использовать:
#запуск программы powershell.exe
#аргументы: -Command "& {%systemdrive%\scripts\share_rdapp_smbv2.ps1 -Server $Server -Collection $Collection}" -ExecutionPolicy Unrestricted -NonInteractive -WindowStyle Hidden
#-----------------------------
Param (
[string]$Collection,
[string]$Server
)
$rdp_path = "$Env:systemdrive\rdapp_share\$Collection"
#получаем стандартные параметры безопасности из коллекции
$rd_coll_rules = Get-RDSessionCollectionConfiguration $Collection -UserGroup
#получаем параметры rdapp
#если публикация скрыта на ферме, то эту публикацию не создавать
$rdps = gwmi Win32_RDCentralPublishedRemoteApplication -namespace root\cimv2\TerminalServices `
    | Sort-Object -Property Name `
    | Where-Object -Property PublishingFarm -eq $Collection `
    | Where-Object -Property Showinportal -eq True `
    | Select-Object Name,alias,RDPFileContents
#получаем параметры безопасности для каждой публикации
$rd_app_rules = Get-RDRemoteApp -CollectionName $Collection `
    | Where-Object -Property ShowInWebAccess -eq True `
    | Select-Object Alias,DisplayName,UserGroups
Invoke-Command -ComputerName $Server -ScriptBlock {
    #проверяем наличие папки с rdpapp
    $isexist = Test-Path $Using:rdp_path
    if ($isexist){
        #если существует - очищаем папку от старых публикаций
        Remove-Item "$Using:rdp_path\*" -Force -Recurse -Confirm:$false
    }
    else {
        #если нет - создаем папку, шару и настраиваем права
        New-Item -Path $Using:rdp_path -ItemType "directory"
        New-SmbShare -Name $Using:Collection -Path $Using:rdp_path `
        -FolderEnumerationMode AccessBased `
        -ReadAccess $Using:rd_coll_rules.UserGroup
    } 
    #выгружаем rdapp в файлы на сетевой шаре
    $Using:rdps | ForEach-Object {
        $app_name = $_.Name
        $app_content = $_.RDPFileContents
        New-Item -Path $Using:rdp_path -Name "$app_name.rdp" -ItemType File -Value $app_content
        Set-Content -Path "$Using:rdp_path\$app_name.rdp" -Value $app_content
        #отключить наследование
        $acl = Get-ACL -Path "$Using:rdp_path\$app_name.rdp"
        $acl.SetAccessRuleProtection($True, $True)
        Set-Acl -Path "$Using:rdp_path\$app_name.rdp" -AclObject $acl
        #убираем локальных пользователей из списка доступа
        $acl = Get-ACL -Path "$Using:rdp_path\$app_name.rdp"
        $rules = New-Object System.Security.Principal.Ntaccount('BUILTIN\Пользователи')
        $acl.PurgeAccessRules($rules)
        Set-Acl -Path "$Using:rdp_path\$app_name.rdp" -AclObject $acl
    }
    #назначаем права на rdp файлы в соответсвии с группами
    $Using:rd_app_rules | ForEach-Object {
        $app_name = $_.DisplayName
        try {
            $_.UserGroups | ForEach-Object {
                $app_rule = $_
                $acl = Get-ACL -Path "$Using:rdp_path\$app_name.rdp"
                $perm = New-Object System.Security.AccessControl.FileSystemAccessRule ($app_rule,"Read, ReadAndExecute","Allow")
                $acl.SetAccessRule($perm)
                Set-Acl -Path "$Using:rdp_path\$app_name.rdp" -AclObject $acl
            }
        }
        catch {
            $Using:rd_coll_rules.UserGroup | ForEach-Object {
                $app_default = $_
                $acl = Get-ACL -Path "$Using:rdp_path\$app_name.rdp"
                $perm = New-Object System.Security.AccessControl.FileSystemAccessRule ($app_default,"Read, ReadAndExecute","Allow")
                $acl.SetAccessRule($perm)
                Set-Acl -Path "$Using:rdp_path\$app_name.rdp" -AclObject $acl
            }
        }
    }
}