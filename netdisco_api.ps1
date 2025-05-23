#!/bin/pwsh
#

# Consumiendo netdisco rest-api
# https://github.com/jaredhendrickson13/pfsense-api

#TLS 1.2 para Invoke-RestMethod
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Function irmDesktop($method, $uri, $head, $body, $ct) {
    Invoke-RestMethod -Method $method -Uri $uri -Headers $head -Body $body -ContentType $ct
}

Function irmCore($method, $uri, $head, $body, $ct) {
#    $PSDefaultParameterValues['Invoke-RestMethod:AllowUnencryptedAuthentication'] = $true
    Invoke-RestMethod -Method $method -Uri $uri -Headers $head -Body $body -ContentType $ct -SkipCertificateCheck:$true -AllowUnencryptedAuthentication
}

#Aceptar certificados autofirmados/expirados/inválidos
if ($Global:PSEdition -ne 'Core') {
add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
                return true;
        }
    }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = [TrustAllCertsPolicy]::new()
    New-Alias -name 'irm2' -Value 'irmDesktop' -Scope Local -Force -ErrorAction SilentlyContinue
}
else {
    #TODO Skip certificate check     
    New-Alias -name 'irm2' -Value 'irmCore' -Scope Local -Force -ErrorAction SilentlyContinue
}

# LA CHICHA
#
class netdiscosession : IDisposable {
    [string]$baseURI
    hidden [string]$baseURI2
    [bool]$isReadOnly
    [bool]$PSEditionCore
    [string]$lastToken
    hidden [string]$contentType = 'application/json'
    hidden [HashTable]$headers = @{Accept        = 'application/json';
                                   Authorization = '' }
    hidden [PSCredential]$cred
    hidden [hashTable]$funcionesGet = @{SearchDevices       = 'search/device'
    					SearchNode          = 'search/node'
    					GetDeviceInventory  = 'report/deviceinventory'
					GetNodesDiscovered  = 'report/node/nodesdiscovered'
	   				GetDevices          = 'report/device/deviceaddrnodns' 
					GetDevice           = "object/device/{0}"
					GetDeviceNodes      = "object/device/{0}/nodes"
					GetNeighbors        = 'object/device/{0}/neighbors' 
					}
                                        
    #TODO: manage token expiration

    # constrúúúctor helper
    #
    #TODO: manage skip/force pfSense certificate check on API calls (Invoke-RestMethod)
    #hidden Init([string]$pfSenseBaseURI,[PSCredential]$credentials, [bool]$SkipCertCheck,[bool]$isReadOnly) {
    hidden Init([string]$netdiscoBaseURI,[PSCredential]$credentials, [bool]$isReadOnly) {
        $this.cred = $credentials
        #$this.SkipCertificateCheck = $SkipCertCheck
        $this.isReadOnly = $isReadOnly
        $this.baseURI  = $netdiscoBaseURI
        $this.baseURI2 = $netdiscoBASEURI -replace '\/$','' 
	$this.PSEditionCore = $Global:PSEdition -eq 'Core'
        if ($netdiscoBaseURI -match '\/$') {
            $this.baseURI += 'api/v1/'
        }
        else {
            $this.baseURI  += '/api/v1/'
#	    $this.baseURI2 += '/'
        }
        $this.GetToken()
    }


    # constrúúúctor
    # No changes allowed on pfSense when $isReadOnly is true
    #
    #pfsession([string]$pfSenseBaseURI,[PSCredential]$credentials, [bool]$SkipCertCheck,[bool]$isReadOnly) {
    netdiscosession([string]$netdiscoBaseURI,[PSCredential]$credentials, [bool]$isReadOnly) {
        $this.Init($netdiscoBaseURI,$credentials, $isReadOnly)
    }

    # No changes allowed on pfSense when $isReadOnly is true
    # $isReadOnly = true is the default behavior
    #
    netdiscosession([string]$netdiscoBaseURI,[PSCredential]$credentials) {
        $this.Init($netdiscoBaseURI,$credentials, $true)
    }


    # destrúúúctor
    #
    [void] Dispose() {
        if ($null -ne $this.cred -and $null -ne $this.cred.Password) {
            #Eliminar la password de las credenciales de acceso
            $this.cred.Password.Clear()
            $this.cred.Password.Dispose()
        }

        #Solo para hacer entender que ha sido destruido
        $this.lastToken = ''
        $this.baseURI = ''
    }

    [string] uri([string]$rel) {
    	if ($null -ne $rel -and $rel[0] -eq '/') {
	  return "$($this.baseURI2)$($rel)"
	}
	else {
	  return "$($this.baseURI)$($rel)"
	}
    }

    # Get pfSense token (JWT mode)
    # Saved in lastToken
    #
    [void] GetToken() {
        [string]$relUri = '/login'

		[string]$usr = $this.cred.UserName
		[string]$pas = ( $this.cred.GetNetworkCredential() ).password
		[string]$usrpas = "{0}:{1}" -f $usr, $pas
		[string]$b64e = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($usrpas) )

		[hashtable]$cab = @{
			Accept          = 'application/json'
            Authorization   = ('Basic {0}' -f $b64e ) }

		try {
			$respuesta = irm2 -method Post -uri $this.uri($relUri) -head $cab -ct $this.contentType -Body '' # $null 

			# token ok
			$this.lastToken = $respuesta.api_key
			$this.headers.Authorization = $this.lastToken
		}
		catch {
			# Error (típicamente por token no válido)
			$this.lastToken = ''
			$this.headers.Authorization = ''
		}

    } # end method GetToken


    # Get Functions
    # Returns a PSObject/PSObject array
    #
    hidden [PSObject] GetFunction([string]$function) {
        $f = $this.funcionesGet.$function
        if ($f) {
	    try {
                $respuesta = irm2 -method Get -uri $this.uri($f) -head $this.headers -ct $this.contentType
                return $respuesta
            }
	    catch {
		return $null
	    }
	}
        else {
            return $null
        }
    } # end function GetGunction


    # SearchNode
    #
    #
    [PSObject[]] SearchNode([string]$cadBusqueda) {
		$f = $this.funcionesGet.SearchNode
		if ($f) {
			try {
				Write-Host($this.uri($f) + ("?q={0}" -f $cadBusqueda))
				$respuesta = irm2 -method Get -uri ($this.uri($f) + ("?q={0}" -f $cadBusqueda)) -head $this.headers -ct $this.contentType
				return $respuesta
			}
			catch {
				return $null
			}
		}
		else {
			Write-Host('No Encontrado')
			return $null
		}
    }
    
    # Get netdisco device information
    # Returns a PSObject
    #
    [PSObject] GetDevice([string]$deviceIP) {
    	[string]$f = $this.funcionesGet.GetDevice
		if ($f) {
			try {
				$respuesta = irm2 -method Get -uri $this.uri($f -f $deviceIP) -head $this.headers -Body $null -ct $this.contentType
				return $respuesta 
			}
			catch {
				return $null
			}
		} # end if
		else {
			return $null
		}
    }

    # Get netdisco Interface Bridges
    # Returns a PSObject array
    #
    [PSObject] GetDeviceNodes([string]$deviceIP) {
		[string]$f = $this.funcionesGet.GetDeviceNodes
        if ($f) {
          try {
            $respuesta = irm2 -method Get -uri $this.uri($f -f $deviceIP) -head $this.headers -Body $null -ct $this.contentType
            return $respuesta
          }
          catch {
            return $null
          }
		} # end if
		else {
			return $null
		}
    }

    # Get Firewall Aliases
    # Returns a PSObject array
    #
    [PSObject[]] GetNeighbors($deviceIP) {
    	[string]$f = $this.funcionesGet.GetNeighbors

        if ($f) {
           try {
             $respuesta = irm2 -method Get -uri $this.uri($f -f $deviceIP) -head $this.headers -Body $null -ct $this.contentType
             return $respuesta
           }
           catch {
             return $null
           }
         } # end if
         else {
           return $null
         }
    }

    # Get Nodes Discovered 
    #
    [PSObject[]] GetNodesDiscovered() {
		return $this.GetFunction('GetNodesDiscovered') 
    }

    # Get Firewall Rules
    # Returns a PSObject array
    #
    [PSObject] GetFwRules() {
        return $this.GetFunction('GetFwRules')
    }

    # Get Firewall Virtual IPs
    # Returns a PSObject array
    #
    [PSObject] GetFwVirtualIPs() {
        return $this.GetFunction('GetFwVirtualIPs')
    }

    # Get Firewall NAT Outbound Setting Mode
    # Returns a PSObject array
    #
    [PSObject] GetFwNatOutbound() {
        return $this.GetFunction('GetFwNatOutbound')
    }

    # Get Firewall NAT Outbound Mappings (Rules)
    # Returns a PSObject array
    #
    [PSObject] GetFwNatOutboundMap() {
        return $this.GetFunction('GetFwNatOutboundMap')
    }

    # Get Firewall NAT Port Forwarding
    # Returns a PSObject array
    #
    [PSObject] GetFwNatPFwd() {
        return $this.GetFunction('GetFwNatPFwd')
    }

    # Get Firewall NAT 1 to 1 mappings
    # Returns a PSObject array
    #
    [PSObject] GetFwNat1to1() {
        return $this.GetFunction('GetFwNat1to1')
    }

    # Get Gateways (routing)
    # Returns a PSObject
    #
    [PSObject] GetGateways() {
        return $this.GetFunction('GetGateways')
    }

    # Get CAs
    # Returns a PSObject
    #
    [PSObject] GetCAs() {
        return $this.GetFunction('GetCAs')
    }

    #pem 2 x509 without private key
    hidden [Security.Cryptography.X509Certificates.X509Certificate2] pem2x509([ref]$crt) {
        return [Security.Cryptography.X509Certificates.X509Certificate2]::new([Convert]::FromBase64String($crt.Value))
    }

    #pem 2 x509 with private key (if running under core)
    hidden [Security.Cryptography.X509Certificates.X509Certificate2] pem2x509([ref]$crt, [ref]$prv) {
        if ($this.PSEditionCore) {
            [char[]]$crtS = [Text.Encoding]::ASCII.Getstring([Convert]::FromBase64String($crt.Value)).ToCharArray()
            [char[]]$keyS = [Text.Encoding]::ASCII.Getstring([Convert]::FromBase64String($prv.Value)).ToCharArray()
            return [Security.Cryptography.X509Certificates.X509Certificate2]::CreateFromPem($crtS, $keyS)
        }
        else {
            #return $this.pem2x509($crt.Value)
            return $this.pem2x509($crt)
        }
    }

    #certArray 2 X509 Array
    hidden [Security.Cryptography.X509Certificates.X509Certificate2[]] certArray2X509Array([ref]$array, [bool]$private) {
        [Security.Cryptography.X509Certificates.X509Certificate2[]]$result = @()
        [Security.Cryptography.X509Certificates.X509Certificate2]$ccc = $null
        foreach($c in $array.Value) {
            if ($private -and $this.PSEditionCore) {
                $ccc = $this.pem2x509([ref]($c.crt), [ref]($c.prv))
            }
            else {
                $ccc = $this.pem2x509([ref]($c.crt))
            }
            $ccc.FriendlyName = $c.descr
            $result += $ccc
        }
        return $result
    }

    # Get X509 CA certificates
    # Input params: $private: $true to return private Keys
    # Returns a X509Certificate2 array (with privateKeys if $private is $true and it's called from PWSH 7+ Core)
    #
    # NOTE: Mandatory PWSHCore to return Private Keys.
    #
    [System.Security.Cryptography.X509Certificates.X509Certificate2[]] GetCAsX509([bool]$private) {
        [PSObject]$obj = $this.GetFunction('GetCAs')
        return $this.certArray2X509Array([ref]($obj.ca), $private)
    }

    # Get Certs
    # Returns a PSObject array
    #
    [PSObject] GetCerts() {
        return $this.GetFunction('GetCerts')
    }

    # Get X509 Certificates
    # Input params: $private: $true to return private Keys
    # Returns a X509Certificate2 array (with privateKeys if $private is $true and it's called from PWSH 7+ Core)
    #
    # NOTE: It's mandatory to use PWSHCore to return Private Keys.
    #
    [System.Security.Cryptography.X509Certificates.X509Certificate2[]] GetCertsX509([bool]$private) {
        [PSObject]$obj = $this.GetFunction('GetCerts')
        return $this.certArray2X509Array([ref]($obj.cert), $private)
    }

    # Get Config
    # Returns a PSObject array
    #
    [PSObject] GetConfig() {
        return $this.GetFunction('GetConfig')
    }

    # Get Dns
    # Returns a PSObject array
    #
    [PSObject] GetDns() {
        return $this.GetFunction('GetDns')
    }

    # Get Services
    # Returns a PSObject array
    #
    [PSObject] GetServices() {
        return $this.GetFunction('GetServices')
    }

    # Get HostName
    # Returns a PSObject array
    #
    [PSObject] GetHostName() {
        return $this.GetFunction('GetHostName')
    }

    # Get Users
    # Returns a PSObject array
    #
    [PSObject] GetUsers() {
        return $this.GetFunction('GetUsers')
    }

    # Get Version
    # Returns a PSObject
    #
    [PSObject] GetVersion() {
        return $this.GetFunction('GetVersion')
    }

    hidden [void] throwNoPermission() {
        if ($this.isReadOnly) {
            Throw "Operation rejected: you do not have write permission."
            return # never executed
        }
      
    }

    # Creates new vLan interface
    # Returns string with name of the new vlanIf
    #
    [string] newVLan([string]$parentIf, [uint16]$vlanId, [string]$descr) {
        $this.throwNoPermission()

        $bodyJ = @{if   =$parentIf;
                   tag  =$vlanId;
                   descr=$descr}

        [string]$relUri = 'interface/vlan'
        $respuesta = irm2 -method Post -uri $this.uri($relUri) -head $this.headers -Body $($bodyJ|ConvertTo-Json -Depth 1 -Compress) -ct $this.contentType
        if ($respuesta.code -eq 200) {
            return $respuesta.data.vlanif
        }
        else {
            return $null
        }
    }

    # assignIf
    # Returns a PSObject ¿???
    #
    [PSObject] assignIf([string]$ifName, [string]$descr, [bool]$enable, [string]$ipaddr, [byte]$subnetPref, [bool]$apply) {
        $this.throwNoPermission()

        $bodyJ = @{if     = $ifName
                   descr  = $descr
                   enable = $enable
                   type   = 'staticv4'
                   ipaddr = $ipaddr
                   subnet = $subnetPref
                   apply  = $apply}

        [string]$relUri = 'interface'
        $respuesta = irm2 -method Post -uri $this.uri($relUri) -head $this.headers -Body $($bodyJ|ConvertTo-Json -Depth 1 -Compress) -ct $this.contentType
        if ($respuesta.code -eq 200) {
            return $respuesta.data
        }
        else {
            return $null
        }
    }


    [PSObject[]] GetDevices() {
	return $this.GetFunction('GetDevices')
	 
    }

} #netdiscosession class end




#################
##
##  PoC de uso
##  MAIN
## 
#################


try {
    #$s = [netdiscosession]::New('https://10.0.2.10', (Get-Credential)) # <-- readonly mode
    $s = [netdiscosession]::New('http://10.1.20.10:5000/', (Get-Credential), $true)

    #Obtener array con las IPs de los switches activos
    [string[]]$switchesIP = $s.GetDevices().ip


  # Crear diccionarios de ip-ns e ip-nombre
  # de switches
  #
  [HashTable]$tablaNS      = @{}
  [HashTable]$tablaNombres = @{}
  foreach ($swi in $switchesIP) {
  	$n = $s.GetDevice($swi)
	$tablaNS[$swi]      = $n.serial
	$tablaNombres[$swi] = $n.name
  }

  #### ITEREAMOS AQUI
  $ggg = $nodosEncontrados.mac |select -Unique
  # el valor devuelto bvueno es $a.sightings
  
  [PSCustomObject[]]$nodosEncontrados2 = @()

  [string[]]$arr = @('0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f')
  foreach ($a in $arr) {
    try {
    	$encontrados = $s.SearchNode($a + '*')
	if ($null -ne $encontrados) {
		foreach($b in $encontrados.sightings) {
			# iterar sobre cada mac encontrada
			$nodosEncontrados2 += [PSCustomObject]@{
                                                 serial = $tablaNS[$b.switch]
                                                 ip     = $b.switch
						 nombre = $tablaNombres[$b.switch]
                                                 mac    = $b.mac.ToLower().Trim()
                                                 puerto = $b.port.ToLower().Trim() -replace '#', ''
						 vlan   = $b.vlan
                                                 fecha  = $b.time_recent }
				
		} #end foreach b
	} #end if null
    } # end try
    catch {
    	Write-Host($Error[0].Message)
	return $null
    }
  } # end foreach a

	$nodosEncontrados2 | Export-Csv -Path './salida2.csv' -Delimiter ';' -Force -Encoding utf8

} # end del try MAIN
finally { 
<#
    # Librear variables
    if ($null -ne $s) {
	$s.Dispose()
    }
    Remove-Variable s -ErrorAction SilentlyContinue
#>
}

