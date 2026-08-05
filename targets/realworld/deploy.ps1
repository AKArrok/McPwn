# targets/realworld/deploy.ps1 - 管理两个一次性 excel-mcp-server 靶机容器 (Windows 宿主 + Docker Desktop)。
# 状态变更命令默认 dry-run, 只有带 -Yes 才真正执行 docker 命令。
param(
    [switch]$Yes,    # 真正执行 docker (不带则 dry-run 只打印命令)
    [switch]$Check,  # 只打印两个容器的 docker ps -a 状态, 不做任何事
    [switch]$Clean   # 删除两个被管理的容器 (同样受 -Yes 控制, 默认 dry-run)
)

# 旧遗留容器 `excel-mcp` (9203, 0.0.0.0 绑定) 不是本脚本管理的, 建议手动 `docker rm -f excel-mcp` 以免与 excel-mcp-017 端口冲突。

# 本脚本管理的两个一次性靶机容器
$Managed = @(
    @{ Name = 'excel-mcp-017'; HostPort = 9203; Version = '0.1.7' },
    @{ Name = 'excel-mcp-018'; HostPort = 9204; Version = '0.1.8' }
)

function Format-Command {
    param([string[]]$ArgList)
    ($ArgList | ForEach-Object {
        if ($_ -match '[\s"]' -or $_ -eq '') {
            '"' + ($_ -replace '"', '\"') + '"'
        } else {
            $_
        }
    }) -join ' '
}

function Invoke-DockerAction {
    param([string[]]$ArgList, [switch]$Real)
    $display = Format-Command $ArgList
    if ($Real) {
        Write-Host ("[run]  docker {0}" -f $display)
        & docker @ArgList
        if ($LASTEXITCODE -ne 0) {
            Write-Host ("[!!]  docker 返回码 {0}: docker {1}" -f $LASTEXITCODE, $display)
        }
    } else {
        Write-Host ("[dry-run]  docker {0}" -f $display)
    }
}

function Get-ContainerState {
    param([string]$Name)
    $filter = 'name=^/' + $Name + '$'
    $line = (& docker ps -a --filter $filter --format '{{.Names}}|{{.State}}' 2>$null | Select-Object -First 1)
    if ($line) {
        return (($line -split '\|', 2)[1]).Trim()
    }
    return $null
}

function Show-Check {
    param($ManagedContainers)
    Write-Host '== 管理容器 docker ps -a 状态 =='
    Write-Host ('{0,-16} {1,-12} {2}' -f 'NAME', 'STATE', 'STATUS')
    foreach ($c in $ManagedContainers) {
        $filter = 'name=^/' + $c.Name + '$'
        $fmt = '{{.Names}}|{{.State}}|{{.Status}}'
        $line = (& docker ps -a --filter $filter --format $fmt 2>$null | Select-Object -First 1)
        if ($line) {
            $parts = $line -split '\|', 3
            Write-Host ('{0,-16} {1,-12} {2}' -f $parts[0], $parts[1], $parts[2])
        } else {
            Write-Host ('{0,-16} {1,-12} {2}' -f $c.Name, '(未创建)', '-')
        }
    }
}

function Invoke-Clean {
    param($ManagedContainers, [switch]$Real)
    foreach ($c in $ManagedContainers) {
        $state = Get-ContainerState $c.Name
        if ($null -eq $state) {
            Write-Host ("[skip]  {0} 不存在, 无需清理。" -f $c.Name)
            continue
        }
        Invoke-DockerAction -ArgList @('rm', '-f', $c.Name) -Real:$Real
    }
}

function Invoke-Deploy {
    param($ManagedContainers, [switch]$Real)
    foreach ($c in $ManagedContainers) {
        $state = Get-ContainerState $c.Name
        if ($state -eq 'running') {
            Write-Host ("[skip]  {0} 已存在且 Running, 跳过。" -f $c.Name)
            continue
        }
        if ($state) {
            # 存在但 Stopped -> docker start
            Invoke-DockerAction -ArgList @('start', $c.Name) -Real:$Real
            continue
        }
        # 不存在 -> docker run -d (需 -Yes)
        $args = @(
            'run', '-d', '--name', $c.Name,
            '-p', ('127.0.0.1:{0}:8017' -f $c.HostPort),
            '-e', 'EXCEL_FILES_PATH=/tmp/sandbox',
            '-e', 'FASTMCP_HOST=0.0.0.0',
            '-e', 'FASTMCP_PORT=8017',
            '-e', 'HTTP_PROXY=http://host.docker.internal:7897',
            '-e', 'HTTPS_PROXY=http://host.docker.internal:7897',
            'python:3.12-slim', 'sh', '-c',
            ('mkdir -p /tmp/sandbox && pip install --quiet excel-mcp-server=={0} && excel-mcp-server sse' -f $c.Version)
        )
        Invoke-DockerAction -ArgList $args -Real:$Real
    }
}

# --- 主流程 ---
if ($Check) {
    Show-Check $Managed
    return
}
if ($Clean) {
    Invoke-Clean -ManagedContainers $Managed -Real:$Yes
    return
}
Invoke-Deploy -ManagedContainers $Managed -Real:$Yes
