# SoulCube
##### Tool for extract the informations from a signed PE, certificate (cer or base 64 ) and parse it to a json. 

##### Useful for hunt samples using the same certificate (campaign) , get serial informations for having to revocation list or combine hash and signature for a goodware software used illegitimate ...

##### The list of arguments are as follows :

```
-f          give the path to certificate file
-fexe       give the path to signed PE file
-o          path to write the json file (by default "result.json" in the same directory of the script)
```
#### Command line examples :

##### Parse a certificate (cer file/base64) :

```pwsh
> .\SoulCube.ps1 -f "ca-bundle.cer" -o MyResult.json
> .\SoulCube.ps1 -f "Cert.txt" -o MyResult.json
```

##### Parse a signed PE file :

```pwsh
> .\SoulCube.ps1 -fexe "C:\Windows\explorer.exe" -o MyResult.json
```
#### Exploitation of the parsed data (Powershell way)

##### Parse a JSON file :
###### For load the JSON use pipe for do a oneliner command
```pwsh
> $Data =(gc MyResult.json)|convertfrom-json
```
##### The structure of the data is splited in two parts:
+ ######  Header which contains globals informations about the certificate
```pwsh
> $Data.header

Filename     : explorer.exe
FileHash     : 4cf1661ef7b8d767656fe0830f54ce4c02a13ba2ec8688fbbcb3eecb96175bb5
IssuerName   : CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
CertHash     : ff82bc38e1da5e596df374c53e3617f7eda36b06
ValidFrom    : 2019-05-02 23:24:36
ValidTo      : 2020-05-02 23:24:36
Version      : 3
SerialNumber : 330000023241fb59996dcc4dff000000000232
```
+ ###### Meta for the metadata of the certificate 

```pwsh
> $Data.Meta 

PrivateKey PublicKey
---------- ---------
           @{ProviderType=PROV_RSA_AES; KeyNumber=1; CryptoKeySecurity=; RandomlyGenerated=True; KeyExchangeAlgorithm=RSA-PKCS1-KeyEx; KeySize=2048; PersistKeyInCsp=False; Algorithm=RSA; Key=48 130 1 10 2 130 1 1 0 146 99 ...
```
###### Give the key and their informations
```pwsh
> $Data.Meta.PublicKey

ProviderType         : PROV_RSA_AES   
KeyNumber            : 1
CryptoKeySecurity    :
RandomlyGenerated    : True
KeyExchangeAlgorithm : RSA-PKCS1-KeyEx
KeySize              : 2048
PersistKeyInCsp      : False
Algorithm            : RSA
Key                  : 48 130 1 10 2 130 1 1 0 146 99 19 91 ...
```
