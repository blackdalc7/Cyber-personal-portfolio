# Detection content for the EDR canary. Data, not code: tune without touching the module.
@{
    ProcessTree = @{
        # How far up the tree to look for a suspicious ancestor (catches winword -> rundll32 -> powershell).
        AncestorDepth = 4
        Rules         = @(
            @{
                Id       = 'EDR-PT-001'
                Name     = 'Office application spawned a shell or script host'
                Severity = 'high'
                Parents  = @('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'msaccess.exe',
                             'mspub.exe', 'onenote.exe', 'visio.exe', 'wordpad.exe')
                Children = @('powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe')
                Mitre    = @('T1566.001', 'T1204.002', 'T1059.001', 'T1059.003')
            }
            @{
                Id       = 'EDR-PT-002'
                Name     = 'Office application spawned a living-off-the-land binary'
                Severity = 'high'
                Parents  = @('winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe', 'msaccess.exe',
                             'mspub.exe', 'onenote.exe', 'visio.exe')
                Children = @('rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe', 'wmic.exe',
                             'msbuild.exe', 'installutil.exe', 'schtasks.exe', 'forfiles.exe', 'curl.exe')
                Mitre    = @('T1566.001', 'T1218', 'T1105')
            }
            @{
                Id       = 'EDR-PT-003'
                Name     = 'Script host spawned a shell'
                Severity = 'medium'
                Parents  = @('wscript.exe', 'cscript.exe', 'mshta.exe')
                Children = @('powershell.exe', 'pwsh.exe', 'cmd.exe')
                Mitre    = @('T1059.005', 'T1059.001')
            }
            @{
                Id       = 'EDR-PT-004'
                Name     = 'Server process spawned a shell (possible web shell)'
                Severity = 'critical'
                Parents  = @('w3wp.exe', 'httpd.exe', 'nginx.exe', 'tomcat9.exe', 'php-cgi.exe', 'sqlservr.exe')
                Children = @('cmd.exe', 'powershell.exe', 'pwsh.exe', 'whoami.exe', 'net.exe')
                Mitre    = @('T1505.003', 'T1059')
            }
        )
        # Command-line markers that raise severity one level (obfuscation / download cradles).
        SuspiciousCommandLine = @('-enc', '-encodedcommand', 'frombase64string', 'downloadstring',
                                  'downloadfile', 'invoke-expression', 'iex(', 'iex ', '-w hidden',
                                  '-windowstyle hidden', 'bypass', 'http://', 'https://')
    }

    Canary = @{
        FileNames = @('0_passwords.docx', '00_finance_backup.xlsx')
    }

    Ransomware = @{
        WindowSeconds         = 10
        DistinctFileThreshold = 25     # distinct files written/renamed/deleted by one PID in the window
        SuspiciousExtensions  = @('.locked', '.encrypted', '.enc', '.crypt', '.crypted', '.wncry', '.lockbit',
                                  '.ryk', '.conti', '.akira', '.blackcat', '.pay2key')
        RansomNotePatterns    = @('*readme*decrypt*', '*how_to_decrypt*', '*how_to_recover*', '*restore_files*',
                                  '*ransom*note*', '*decrypt_instructions*')
    }

    Containment = @{
        # Never suspended, whatever the detection says: freezing these hangs or crashes the host.
        ProtectedNames = @('system', 'idle', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe', 'winlogon.exe',
                           'services.exe', 'lsass.exe', 'lsaiso.exe', 'svchost.exe', 'fontdrvhost.exe',
                           'dwm.exe', 'msmpeng.exe', 'memcompression')
        ProtectedPids  = @(0, 4)
    }
}
