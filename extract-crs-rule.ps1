[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string] $TargetPath
)

function Out-CrsSecRuleInfo
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.IO.FileInfo] $RuleFile
    )

    begin {}

    process
    {
        $ruleFileName = [System.IO.Path]::GetFileName($RuleFile.FullName)

        $combinedTextBuilder = New-Object -TypeName 'System.Text.StringBuilder'

        Get-Content -LiteralPath $RuleFile.FullName -ReadCount 1 -Encoding utf8 |

            # Skip empty lines and commented lines.
            ForEach-Object -Process {
                $trimedLineText = $_.Trim()
                if ((-not [string]::IsNullOrWhiteSpace($trimedLineText)) -and (-not $trimedLineText.StartsWith('#')))
                {
                    $trimedLineText
                }
            } |

            # Combine the continuing lines.
            ForEach-Object -Process {
                $lineText = $_
                if ($lineText.EndsWith('\'))
                {
                    [void] $combinedTextBuilder.Append($lineText.TrimEnd('\'))
                }
                else
                {
                    [void] $combinedTextBuilder.Append($lineText)
                    $combinedTextBuilder.ToString()
                    [void] $combinedTextBuilder.Clear()
                }
            } |

            # We need "SecRule" line only.
            Where-Object -FilterScript {
                $_.StartsWith('SecRule')
            } |

            # Extract necessary information from the line.
            ForEach-Object -Process {
                $rulePhase = ''
                if ($_ -match '.+phase:([^,]+),.+')
                {
                    $rulePhase = $Matches[1]
                }

                $ruleId = ''
                if ($_ -match '.+id:([^,]+),.+')
                {
                    $ruleId = $Matches[1]
                }

                if (($rulePhase -ne '') -and ($ruleId -ne ''))
                {
                    [PSCustomObject] @{
                        RuleFileName = $ruleFileName
                        RuleId       = $ruleId
                        RulePhase    = $rulePhase
                    }
                }
            }
    }

    end {}
}


if (Test-Path -PathType Container -LiteralPath $TargetPath)
{
    Get-ChildItem -File -Path $TargetPath -Filter '*.conf' |
        Out-CrsSecRuleInfo |
        ConvertTo-Csv -Delimiter "`t"
}
else
{
    Get-Item -LiteralPath $TargetPath |
        Out-CrsSecRuleInfo |
        ConvertTo-Csv -Delimiter "`t"
}
