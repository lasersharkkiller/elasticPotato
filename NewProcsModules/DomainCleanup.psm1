function ConvertFrom-UrlDomainExtract {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowEmptyString()]
        [string] $InputText
    )

    begin {
        $found = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $hostPattern = '(?i)(?:(?:https?|ftp|ssh)://)?((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,63})'
    }

    process {
        if ([string]::IsNullOrWhiteSpace($InputText)) { return }
        try {
            $regexMatches = [regex]::Matches($InputText, $hostPattern)
            foreach ($m in $regexMatches) {
                $h = $m.Groups[1].Value.Trim().Trim('.', ',', ';', ':', ')', ']', '}', '"', "'").ToLowerInvariant()
                if ($h) { [void] $found.Add($h) }
            }
        } catch {
            return
        }
    }

    end {
        if ($found.Count -eq 0) { return ,([string[]]@()) }
        $sorted = [string[]] ($found | Sort-Object)
        return ,$sorted
    }
}

Export-ModuleMember -Function ConvertFrom-UrlDomainExtract
