[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [String]$f,
    [Parameter(Mandatory=$false)]
    [String]$fexe,
    [Parameter(Mandatory=$false)]
    [String]$o
)
function get_ProviderType
{
    param (
    [string]$x
    )
    switch ($x) {
        "1" {$x = "PROV_RSA_FULL"}
        "2" {$x = "PROV_RSA_SIG"}
        "3" {$x = "PROV_DSS"}
        "4" {$x = "PROV_FORTEZZA"}
        "5" {$x = "PROV_MS_EXCHANGE"}
        "6" {$x = "PROV_SSL"}
        "12" {$x = "PROV_RSA_SCHANNEL"}
        "13" {$x = "PROV_DSS_DH"}
        "14" {$x = "PROV_EC_ECDSA_SIG"}
        "15" {$x = "PROV_EC_ECNRA_SIG"}
        "16" {$x = "PROV_EC_ECDSA_FULL"}
        "17" {$x = "PROV_EC_ECNRA_FULL"}
        "18" {$x = "PROV_DH_SCHANNEL"}
        "20" {$x = "PROV_SPYRUS_LYNKS"}
        "21" {$x = "PROV_RNG"}
        "22" {$x = "PROV_INTEL_SEC"}
        "23" {$x = "PROV_REPLACE_OWF"}
        "24" {$x = "PROV_RSA_AES"}
        Default {}
    } 
    return $x
}

if($f)
{
    $Path=(Resolve-Path -Path $f).path
    $Cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $Cert.Import($Path)
}
elseif ($fexe) 
{
    $Path=(Resolve-Path -Path $fexe).path
    $Cert= Get-AuthenticodeSignature -FilePath  $Path
    $Cert=$Cert.SignerCertificate
}
else{write-host "exit";exit}

$Certheader = [PSCustomObject]@{
    "Filename" = $(if ($fexe){(ls $path).name})
    "FileHash" = $(if ($fexe){(Get-Filehash -Path $path).hash.tolower()})
    "IssuerName" = $Cert.IssuerName.Name
    "CertHash" = ($Cert.GetCertHashString()).ToLower()
    "ValidFrom" = ($Cert.NotBefore).ToString("yyyy-MM-dd HH:mm:ss")
    "ValidTo" = ($Cert.NotAfter).ToString("yyyy-MM-dd HH:mm:ss")
    "Version" = $Cert.Version
    "SerialNumber" = ($Cert.GetSerialNumberString()).ToLower()
}
$CertBody = [PSCustomObject]@{
    "Creation_Date" = $Cert.GetEffectiveDateString()
    "Expiration_Date" = $Cert.GetExpirationDateString()
    "Signature_Algorithm" = $Cert.SignatureAlgorithm.FriendlyName
}
$CertPrivateKey = ""
if($Cert.HasPrivateKey)
{
    $CertPrivateKey = [PSCustomObject]@{
        "ProviderType" = get_ProviderType $Cert.PrivateKey.Key.CspKeyContainerInfo.ProviderType
        "KeyNumber" = $Cert.PrivateKey.Key.CspKeyContainerInfo.KeyNumber
        "CryptoKeySecurity" = $Cert.PrivateKey.Key.CspKeyContainerInfo.CryptoKeySecurity
        "RandomlyGenerated" = $Cert.PrivateKey.Key.CspKeyContainerInfo.RandomlyGenerated
        "KeyExchangeAlgorithm" = $Cert.PrivateKey.Key.KeyExchangeAlgorithm
        "KeySize" = $Cert.PrivateKey.Key.KeySize
        "PersistKeyInCsp" = $Cert.PrivateKey.Key.PersistKeyInCsp
        "Algorithm" = $Cert.PrivateKey.EncodedKeyValue.Oid.FriendlyName
        "Key" =$Cert.PrivateKey.EncodedKeyValue.RawData
    }
}

$CertPublicKey = [PSCustomObject]@{
        "ProviderType" = get_ProviderType $Cert.PublicKey.Key.CspKeyContainerInfo.ProviderType
        "KeyNumber" = $Cert.PublicKey.Key.CspKeyContainerInfo.KeyNumber
        "CryptoKeySecurity" = $Cert.PublicKey.Key.CspKeyContainerInfo.CryptoKeySecurity
        "RandomlyGenerated "= $Cert.PublicKey.Key.CspKeyContainerInfo.RandomlyGenerated
        "KeyExchangeAlgorithm" = $Cert.PublicKey.Key.KeyExchangeAlgorithm
        "KeySize" = $Cert.PublicKey.Key.KeySize
        "PersistKeyInCsp" = $Cert.PublicKey.Key.PersistKeyInCsp
        "Algorithm" = $Cert.PublicKey.EncodedKeyValue.Oid.FriendlyName
        "Key" =$Cert.PublicKey.EncodedKeyValue.RawData
    }

$Json=[PSCustomObject]@{
    "Header" = $Certheader;
    "Meta" = @{
        "Informations" = $CertBody;
        "PrivateKey" = $CertPrivateKey;
        "PublicKey" = $CertPublicKey;
    }
}
$Json = $Json|convertto-json
if($o){set-content -value $Json -Path $o}
else{set-content -value $Json -Path "result.json"}
