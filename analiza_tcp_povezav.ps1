 
<#
.SYNOPSIS
  Ta skripta je namenjena avtomatizaciji analize TCP povezav.

.DESCRIPTION
  Ta skripta je namenjena avtomatični analizi lastnosti TCP povezav, ki se izvedejo pri dostopanju 
  do poljubnih spletnih naslovov, ki so
  podani v tekstovni datoteki. Za zajemanje prometa in 
  analizo povezav se uporablja terminalska verzija 
  programa Wireshark, tshark, ki se zažene preko klicnega ukaza s parametri 
  preko skripta. Uporabnik se odloči ali se prenesena spletna stran shrani v .html 
  datoteko, koliko časa se izvaja zajemanje v programu tshark, ali se pošljejo
  samo čela HTTP ali celotna spletna stran in izbere lahko vmesnik, kjer se posluša promet. 
  Pred samim zajemom skript omogoči, da se ugasnejo vsi procesi, ki imajo 
  vzpostavljene TCP povezave, da se doseže čim čistejši zajem prometa. 
  Na koncu se izvede analiza zajema (funkcija Izpis-Sw). Uporabnik izbere željeno datoteko zajema. V tekstovne datoteke
  se zapiše tabela vseh TCP pogovorov, tabela vseh končnih točk TCP, izpis števila 
  pogovorov TCP med uporabnikom in izbranim ciljnim TCP naslovom.
  Omogoča tudi analizo TCP toka, ki ga izbere uporabnik. 
  V datoteko se za izbran zapiše RTT (začetni, minimalni, povprečni, maksimalni), 
  velikost okna (minimalna, povprečna, maksimalna),izračunana 
  velikost okna (začetna, minimalna, povprečna, maksimalna), za interval dolg 1s se izpiše vrednost zaporedne številke
  ter propustnost v bitih na skeundo, za vsako smer. Uporabnik, lahko tudi shrani zajete podatkve v mapo na namizju

.PARAMETER <Parameter_Name>
  <Brief description of parameter input required. Repeat this attribute if required>

.INPUTS
  Tekostovana datoteka, ki vsebuje  izbrane spletne naslove:
  C:\Users\Uporabnik\Desktop\diploma3\*.txt

.OUTPUTS
  Datoteke z analiznimi podatki
   Mapa s shranjenimi podatki, ki se ustvari z uporabnikovo odločitvijo:
   C:\Users\Uporabnik\Desktop\dd.mm.yyyy~hh_mm_ss  
   
   Vsebina mape:
   - zajete datoteka (njihovo število je odvisno od števila naslovo v tekstovni datoteki, ki vsebuje izbrane spletne strani),
   ime izbere uporabnik:
   C:\Users\Uporabnik\Desktop\dd.mm.yyyy~hh_mm_ss\*.pcap
   - analizne datoteke
   C:\Users\Uporabnik\Desktop\dd.mm.yyyy~hh_mm_ss\ack1.txt
   C:\Users\Uporabnik\Desktop\dd.mm.yyyy~hh_mm_ss\ack2.txt
   C:\Users\Uporabnik\Desktop\dd.mm.yyyy~hh_mm_ss\analiza_rtt_smer1.txt
   C:\Users\Uporabnik\Desktop\dd.mm.yyyy~hh_mm_ss\cas1_max.txt
   C:\Users\Uporabnik\Desktop\dd.mm.yyyy~hh_mm_ss\cas1_min.txt
   C:\Users\Uporabnik\Desktop\dd.mm.yyyy~hh_mm_ss\cas2_max.txt
   C:\Users\Uporabnik\Desktop\dd.mm.yyyy~hh_mm_ss\cas2_min.txt
   C:\Users\Uporabnik\Desktop\dd.mm.yyyy~hh_mm_ss\conv.txt
   C:\Users\Uporabnik\Desktop\dd.mm.yyyy~hh_mm_ss\endpoints.txt
   C:\Users\Uporabnik\Desktop\dd.mm.yyyy~hh_mm_ss\izracunana_velikost_okna_smer1.txt
   C:\Users\Uporabnik\Desktop\dd.mm.yyyy~hh_mm_ss\izracunana_velikost_okna_smer2.txt
   C:\Users\Uporabnik\Desktop\dd.mm.yyyy~hh_mm_ss\max_zap_st_smer1.txt
   C:\Users\Uporabnik\Desktop\dd.mm.yyyy~hh_mm_ss\max_zap_st_smer2.txt
   C:\Users\Uporabnik\Desktop\dd.mm.yyyy~hh_mm_ss\velikost_okna_smer1.txt
   C:\Users\Uporabnik\Desktop\dd.mm.yyyy~hh_mm_ss\velikost_okna_smer2.txt
   C:\Users\Uporabnik\Desktop\dd.mm.yyyy~hh_mm_ss\zacetni_rtt.txt 

  Začasne datoteke, ki služijo izračunom in pridobivanju željen podatkov 
  za zajemalne in prikazovalne filtre programa tshark:
  F:\tshark_temp\ack1.txt
  F:\tshark_temp\ack2.txt
  F:\tshark_temp\cas1_max.txt
  F:\tshark_temp\cas1_min.txt
  F:\tshark_temp\cas2_max.txt
  F:\tshark_temp\cas1_min.txt
  F:\tshark_temp\tcp_len.txt
  F:\tshark_temp\tcp_len1.txt
  F:\tshark_temp\tcp_len2.txt
  F:\tshark_temp\fin_count.txt
  F:\tshark_temp\syn_count.txt

.NOTES
  Version:        1.0
  Author:         Aljaž Gaber
  Creation Date:  16.7.2017
  Purpose/Change: Zaključni projekt

.EXAMPLE
 
  [PS] C:\> .\Analiza_tcp_povezav.ps1
  [PS] C:\> Get-Help .\Desktop\diploma4\analiza_tcp_povezav.ps1 -Full
  [PS] C:\> Get-Help .\Desktop\diploma4\analiza_tcp_povezav.ps1 -Detailed
  [PS] C:\> Get-Help .\Desktop\diploma4\analiza_tcp_povezav.ps1 -Examples
  [PS] C:\> . .\analiza_tcp_povezav3.ps1 ; get-help main -full
  [PS] C:\> $Error[0] | select -Property *
#>

#---------------------------------------------------------[Script Parameters]------------------------------------------------------

Param (
  #Script parameters go here
)

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

#Import Modules & Snap-ins
#to je modul, ki vsebuje funkcije za analizo podatkov
Import-Module AnalizaIzpis
#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Any Global Declarations go here

#-----------------------------------------------------------[Functions]------------------------------------------------------------

function Main{
    <#
            .SYNOPSIS 
            To je glavna funckija.

            .DESCRIPTION
            Na začetku se ponudi izpis trenutnih povezav, vnos tekstovne 
            datoteke ter odločitev ali se stran shranjuje v .html datoteko.
            Ta funkcija je zadolžena, da kliče ostale pomožne funkcije.

            .PARAMETER
            None

            .INPUTS
            Tekstovna datoteka, ki jo izbere uporabnik.

            .OUTPUTS
            None

            .NOTES
            Version:        1.0
            Author:         Aljaž Gaber
            Creation Date:  18.7.2017
            Purpose/Change: Zaključni projekt

            .EXAMPLE
            [PS] C:\> . .\analiza_tcp_povezav3.ps1 ; get-help main -full

            #>
    [CmdletBinding()]

    param()
    begin{
        Write-Verbose 'Začetek skripte !' -Verbose
        #Write-Host 'Začetek skripte' -ForegroundColor Yellow -BackgroundColor DarkCyan
    }

    process{
        Clear-Host

        #v mapi F:\tshark se pobrišejo vse prejšnje datoteke, ki so bile zajete v primeru ponovnega zagona skripta
        $izbrisi_mapo = Get-ChildItem -Path F:\tshark -Include *.* -File -Recurse | ForEach-Object { $_.Delete()}
        $izbrisi_mapo

        #v mapi F:\tshark_temp se pobrišejo vse prejšnje datoteke, ki so bile zajete v primeru ponovnega zagona skripta
        $izbrisi_mapo_temp = Get-ChildItem -Path F:\tshark_temp -Include *.* -File -Recurse | ForEach-Object { $_.Delete()}
        $izbrisi_mapo_temp

        #nalagalno okno za brisanje datotek iz mape F:\tshark, za boljšo povratno informacijo uporbaniku skripte
        for ($i = 1; $i -le 10; $i++) { 
            write-progress -activity "Brisanje prejšnjih datotek" -id 1 "Brišem datoteke" -percentComplete ($i*10) 
            sleep -m 120
            }
        Write-Progress -activity "Brisanje prejšnjih datotek" -id 1 -Status "Ready" -Completed

        $datoteka_z_naslovi=""

        #kličemo funkcijo zanka, ki ugotavlja, če so vzpostavljene le lokalne povezave
        Ugasni

        #kličemo funkcijo Prenesi-Stran (poslušamo planet v vsaki .pcap datoteki posebej)
        
        
        Do{
            $izpis_povezav = Read-Host "Ali želite prenos vsake spletne strani posebej (da/ne)?"
            Switch($izpis_povezav){
                "da"{Prenos-Narazen
                    Izpis-Sw
                    $test_povezav=$true
                    break}
                "ne"{$test_povezav=$true
                    break}
                default{$test_povezav=$false 
                    'Napacen vnos!'}
            }
        }while($test_povezav -eq $false)

        #kličemo funkcijo Prenesi-Skupaj (poslušamo promet v eni .pcap datoteki skupaj)
        
        Do{
            $izpis_povezav = Read-Host "Ali želite prenos vseh spletnih strani skupaj (da/ne)?"
            Switch($izpis_povezav){
                "da"{Prenos-Skupaj
                    Izpis-Sw
                    $test_povezav=$true
                    break}
                "ne"{$test_povezav=$true
                    exit
                    break}
                default{$test_povezav=$false 
                    'Napacen vnos!'}
            }
        }while($test_povezav -eq $false)

        #kličemo analizo
        Izpis-Sw
    }
    
    end{
        Write-Verbose 'Konec skripte !' -Verbose

    }

    

 
}

function Ugasni{

    <#
            .SYNOPSIS 
            To je pomožna funkcija, ki pregleda, če so vzpostavljene kakšne TCP povezave.

            .DESCRIPTION
            Funkcija pregleda vse povezave in ugasne tiste, ki se lahko ugasnjejo. S tem 
            omogočimo čimbolj čist zajem.

            .PARAMETER
            None

            .OUTPUTS
            None

            .INPUTS
            None

            .OUTPUTS
            None

            .NOTES
            Version:        1.0
            Author:         Aljaž Gaber
            Creation Date:  18.7.2017
            Purpose/Change: Zaključni projekt

            .EXAMPLE
            [PS] C:\> . .\analiza_tcp_povezav3.ps1 ; get-help Zanka -full

            #>

    #[OutputType([Boolean])]
    
    [CmdletBinding()]
    param()
    begin{Write-Verbose 'Začtek funkcije Zanka !' -Verbose}
    
    process{
        #ustvari arraylist z imenom $vzpostavljene povezave, kamor se hranijo vsi procesi, ki jih bo skript ugasnil
        $vzpostavljene_povezave = New-Object System.Collections.ArrayList
        
        #pridobimo vse PID vseh procesov, kjer je niso vzpostavljene samo lokalkne povezave
        $pridobi= Get-NetTCPConnection | Where-Object {$_.State -eq "Established" -and $_.RemoteAddress -ne "127.0.0.1"}
        $vsi_procesi = $pridobi.OwningProcess

        #vsi pridobleni PID se shranijo v objekt $vsi_procesi, kjer izločimo na unikatne PID, da se ne ponavljajo
        $vsi_procesi= $vsi_procesi | Select-Object -Unique
        #Write-Output $vsi_procesi
        #v arraylist $vsi procesi, dodamo vsa imena procesov, ki niso enaka sistemskim procesom, ki se imajo največkrat vzpostavljene ne samo lokalno povezave in jih je težko ugasniti
        foreach($proces in $vsi_procesi){
        
            $izpis = Get-Process -id $proces
            #Write-Output "not" $izpis.Name
            if($izpis.Name -ne "svchost" -and $izpis.Name -and "SearchUI" -and $izpis.Name -ne "explorer" -and $izpis.Name -ne "powershell" -and $izpis.Name -ne "powershell_ise" -and $izpis.Name -ne "System"){
                $vzpostavljene_povezave.Add($izpis.Name)
            }

        }

    try{
        
        # spremenljivka $izbrani_procesi vsebuje velikost arraylist $vzpostavljene_povezave
        
        [int]$izbrani_procesi = $vzpostavljene_povezave.Count
        #v primeru, da ta vrednost ni enaka 0, se izvede ugašanje izbranih procesov

        if($izbrani_procesi -ne 0){
        
            #izvedemo zanko s katero ugasnemo vsak proces v arraylistu $vzpostavljene povezeve
            foreach($proces_kill in $vzpostavljene_povezave){
            
            # pridobimo proces in ga shranimo v spremenljivko, ki vsebuje komando Get-Process (z njo pridobimo proces)
            $koncaj = Get-Process -Name $proces_kill -ErrorAction Stop
                if ($koncaj) {
                    # naprej poizkusimo z lažjim poizkusom ugsantive procesa
                    $koncaj.CloseMainWindow()
                    $local_host = $true
                    
                    # ustavimo proces po dveh sekundah
                    sleep 2

                    #izsilimo poskus ugasnitve procesa
                    if (!$koncaj.HasExited) {
                    $koncaj | Stop-Process -Force -ErrorAction Stop
                    
            
                        }

                    #nalagalno okno za ugašanje programov, za boljšo povratno informacijo uporbaniku skripte
                    for ($i = 1; $i -le 10; $i++) { 
                        write-progress -activity "Ugašanje programov $process_kill" -id 1 "Ugašam $proces_kill" -percentComplete ($i*10) 
                    sleep -m 200
                    }
                        Write-Progress -activity "Ugašanje programov $process_kill" -id 1 -Status "Ready" -Completed

                    
                
                    }
                }

                # v primeru, da je velikost arraylist $vzpostavljene_povezave enaka 0, je pogoju že zadoščeno
                }elseif($izbrani_procesi -eq 0){
                    $local_host = $true
                }

            }catch [Microsoft.PowerShell.Commands.ProcessCommandException]{

                #ujemamo napako v primeru, da procesa ni bilo mogoče ugasniti
                Write-Host "Procesa ni bilo mogoče ugasniti $proces_kill"  + $_.Exception.GetType().FullName -fore blue -back white

            
            }catch{

                #ujamemo napako v primeru, da se pojavi druga napaka ob ugašanju procesov
                Write-Host "Druga napaka $process_kill" + $_.Exception.GetType().FullName -fore blue -back white
            
            }
            
            
           
        }

        

    end{Write-Verbose 'Konec funkcija zanka !' -Verbose}
  }

function Prenos-Narazen{

    <#
            .SYNOPSIS 
            V tej funkciji se izvede zajemanje prometa. Za vsako spletno stran se promet zajema v posebno .pcap datoteko.

            .DESCRIPTION
            Izberemo lahko na katerem vmesniku zajemamo,ime datoteke v katero se bo vsebina shranjevala in koliko sekund poslušamo.

            .PARAMETER
            [System.Object] $local_host - če je izpolnjen pogoj za zajemanje 
            [String] $download -ali se v datoteka shranjuje tudi celotna prenešena spletna stran
            [System.Object] $polje_naslovov - tukaj so prebrani spletni naslovi iz vnešene tekstovna datoteke v funkciji Main

            .INPUTS
            None

            .OUTPUTS
            None

            .NOTES
            Version:        1.0
            Author:         Aljaž Gaber
            Creation Date:  18.7.2017
            Purpose/Change: Zaključni projekt

            .EXAMPLE
            [PS] C:\> . .\analiza_tcp_povezav3.ps1 ; get-help Prenesi-Stran -full

            #>
          
        [CmdletBinding()]
        #zahtevani parametri za delovanje funkcije
        #$local_host, če je izpolnjen pogoj za lokalne zanke
        #$polje_naslovov, so vsi naslovi, ki se prenesejo
    param()

    begin{Write-Verbose 'Začetek funkcije Prenos-Narazen !' -Verbose}

    process{

        #zanka zahteva vnos imena tekstovne datoteke v kateri so zapisani vsi naslovi, ki se bodo uporabili za analizo
        #ime datoteke se vpiše v spremenljivko $datoteka_z_naslovi.
        #zanka se izvaja tako dolgo, dokler ni vnešena datoteka, ki obstaja, takrat se vrednost boolean spremenljivke $test_naslovi spremeni v $true
        
        Do{
            
            $datoteka_z_naslovi = Read-Host "Vpisi ime tekstovne datoteke z naslovi?"
            Write-Output $datoteka_z_naslovi
            if($datoteka_z_naslovi -like '*.txt*'){
            Test-Path C:\Users\Uporabnik\Desktop\diploma2\$datoteka_z_naslovi | ForEach-Object {if($_ -eq $true){$test_naslovi=$true}else{$test_naslovi=$false}}
                if($test_naslovi -eq $false){
                    "Datoteka ne obstaja!"
                }else{"Obstaja !"}
            }else{
                Write-Host 'Ni .txt datoteka'
                $test_naslovi = $false
            }
            
        }While($test_naslovi -eq $false)
        
        #pridobimo vsebino teksovne datoteke z naslovi in jo shranimo v spremenljivko [System.Object] $polje_naslovov_main
        $polje_naslovov = Get-Content -Path C:\Users\Uporabnik\Desktop\diploma2\$datoteka_z_naslovi  

    

        $kateri_vmesnik=""

        #zanka do/while se izvaja dokler ni pravega vnosa vmensika
        #zanka se izvaja dokler ni boolean spremenljivka $test_vmesnik enaka $true
        Do{
            # operator & nam omogoči zagon komande, ki nam izpiše vse vmesnike, ki jih lahko uporabimo s programom tshark
            & "F:\wireshark\tshark.exe" "-D" 
            
            try{
                #v spremenljivko $kateri_vmesnik vnesemo številko željenega vmesnika, na katereme želimo zajemati podatke
                #vmesnikov je 7, za to pogoju zadostuejejo vnešene številke od 1 do 7, vse ostalo je nepravilen vnos
                
                [int]$kateri_vmesnik  = Read-Host "Kateri vmesnik želite izbrati za zajemanje (vpiši številko npr. 1)?"
                    if($kateri_vmesnik -lt 1 -or $kateri_vmesnik -gt 7){
                        Write-Output "izbrane opcije ni na seznamu"
                        $test_vmesnik = $False
                }else{
                        Write-Output "Izbrana opcija je na seznamu."
                        $test_vmesnik = $True
                }

            }catch [System.Management.Automation.RuntimeException]{
                #v primeru, da ni vpisan tip integer se ujame napaka o narobešnjem vnosu
                $test_vmesnik = $False
                Write-Host 'Ni vpisano število ! '  + $_.Exception.GetType().FullName -fore blue -back white
            }
        }While($test_vmesnik -eq $False)
  
    
        # zanka se izvede za vsako naslov v objektu, ki vsebuje vse izbrane spletne naslove
        #zanka se izvaja zako dolgo, dokler se ne prenesejo vse spletne strani podane s spletnimi naslovi v tekstovni datoteki
            foreach($naslov in ($polje_naslovov)){

            
            $st++
            Write-Output "podatki za $st. naslov"
            #------------------------------------------------------------------------------------------------------------------------

            # v spremenljivko $datoteka_pcap vpišemo ime datoteke v katero se bo zajem shranjeval
            
            $datoteka_pcap = Read-Host "Vpisi ime datoteke .pcap?"
            Write-Output $datoteka_pcap
        
            #------------------------------------------------------------------------------------------------------------------------

            #zanka do/while se izvaja dokler ni vnosa tipa integer
            #zanka se izvaja dokler ni boolean spremenljivka $test_int enaka $true

            Do{
                try{
                    # vnos casa poslusanja v sekundah v spremelnjivko $cas tipa integer
                    [int]$cas = Read-Host "Vpisi koliko casa se izvaja poslusanje programa tshark (sekunde) ?"
                    Write-Output $cas
                    if($cas -is [int]){
                        $test_int = $True
                    }elseif($cas -isnot [int]){
        
                        $test_int = $False
                    }
                }catch [System.Management.Automation.RuntimeException]{
                    # v primeru, da tip spremenljivke ni enak tipu integer
                    Write-Host 'Niso vpisane številke! '  + $_.Exception.GetType().FullName -fore blue -back white
                    $test_int = $false
        
                }
            }While($test_int -eq $False)
        #------------------------------------------------------------------------------------------------------------------------

        
        #izbira uporabnika, da se pri prenosu prenesejo samo HTTP čela
        #spremenljivka tipa boolean $test_povezav je vrednosti $false dokler, ni vnos niza $test_header vnešen da ali ne

            Do{
                $header = Read-Host "Ali želite, da se pošljejo samo čela HTTP (da/ne) ?"
                Write-Output $header

                Switch($header){
                    "da" {$test_header=$true
                        break}
                    "ne" {$test_header=$true
                        break}
                    default{$test_header=$false 
                        'Napacen vnos!'}
                }
            }While($test_header -eq $False)
        #------------------------------------------------------------------------------------------------------------------------

        #izbira uporabnika, da se pri prenosu stran shrani v .html datoteko
        #spremenljivka tipa boolean $test_povezav je vrednosti $false dokler, ni vnos niza $izbira_download vnešen da ali ne

            Do{
            $download= Read-Host "Ali želite, da se vsebina spletne strani shranjuje v .html datoteko (da/ne) ?" 
            Switch($download){
                "da" {
                  $izbira_download=$true
                    break}
                "ne" {
                  $izbira_download=$true
                    break}
                default{$izbira_download=$false 
                    'Napacen vnos!'}
                }
            }while($izbira_download -eq $false)  
        #------------------------------------------------------------------------------------------------------------------------
            #izvede se tshark komanda, ki vsebuje prej vnešeno številko vmesnika, čas zajema in ime datoteke
            $komanda = "F:\wireshark\tshark.exe" 
            $parametri = "-i $kateri_vmesnik -a duration:$cas -f ""tcp and ip"" -w F:\tshark\$datoteka_pcap.pcap"
            $prms = $parametri.Split(" ")

            #$proces = Start-Process -NoNewWindow  "$komanda" $prms -PassThru
            try{
                $proces = Start-Process "$komanda" $prms  -PassThru
            }catch [System.Management.Automation.RuntimeException]{
                # v primeru, da so vnešeni morebitni napačni podatki se javi obvestilo o napaki
                Write-Host 'Napaka pri zagonu '  + $_.Exception.GetType().FullName -fore blue -back white
            }catch{
                #v primeur, druge napake se pojavi obvestilo o napaki
                Write-Host 'Druga napaka'  + $_.Exception.GetType().FullName -fore blue -back white
            }
            Start-Sleep -Seconds 3

            
        
            $no_write_result = $null

            #glede na prej izbrane parametre se izvede željen prenos posameznega spletnega mesta, ki ga beremo iz tekstovne datoteke

            #v primeru, da je izbrana opcija brez shranjevanje v .html datoteko
            if($download -eq "ne"){
                "download ne"
                #izbrana opcija, če se prenesejo samo HTTP glave
                if($header -eq "da"){
                    $no_write_result = Invoke-WebRequest $naslov -Method Head -Headers @{"Cache-Control"="no-cache"}
                    $no_write_result 
                }elseif($header -eq "ne"){
                    $no_write_result = Invoke-WebRequest $naslov -Headers @{"Cache-Control"="no-cache"}
                    $no_write_result
                }

            #v primeru, da je izbrana opcija s shranjevanjem v .html datoteko
            }elseif($download -eq "da"){
                "download da"
                #izbrana opcija, če se prenesejo samo HTTP glave
                if($header -eq "da"){
                    Write-Host "Čela HTTP ni možno hraniti v .html datoteko"
                    try{
                    $write_result = Invoke-WebRequest $naslov -Method Head -Headers @{"Cache-Control"="no-cache"}
                    $write_result
                    }catch{
                        Write-Host "Naslov ne obstaja!"
                    }
                }elseif($header -eq "ne"){
                    
                    
                    $write_result = Invoke-WebRequest $naslov -Headers @{"Cache-Control"="no-cache"} -OutFile F:\tshark\$st.html
                    $write_result
                    
                }
            
            }

            #naslednji vnos se lahko izvede, ko se poslušanje zaključi
            #$proces.WaitForExit()
    
            }


          
        }

    
    
    end{Write-Verbose 'Konec funkcija Prenos-Narazen' -Verbose}
    }


function Prenos-Skupaj {

    <#
            .SYNOPSIS 
            V tej funkciji se izvede zajemanje prometa.

            .DESCRIPTION
            Izberemo lahko na katerem vmesniku zajemamo,ime datoteke v katero se bo vsebina shranjevala in koliko sekund poslušamo.

            .PARAMETER
            [System.Object] $local_host - če je izpolnjen pogoj za zajemanje 
            [String] $download -ali se v datoteka shranjuje tudi celotna prenešena spletna stran
            [System.Object] $polje_naslovov - tukaj so prebrani spletni naslovi iz vnešene tekstovna datoteke v funkciji Main

            .INPUTS
            None

            .OUTPUTS
            None

            .NOTES
            Version:        1.0
            Author:         Aljaž Gaber
            Creation Date:  18.7.2017
            Purpose/Change: Zaključni projekt

            .EXAMPLE
            [PS] C:\> . .\analiza_tcp_povezav3.ps1 ; get-help Prenesi-Stran -full

            #>
          
        [CmdletBinding()]
        #zahtevani parametri za delovanje funkcije
        #$local_host, če je izpolnjen pogoj za lokalne zanke
        #$polje_naslovov, so vsi naslovi, ki se prenesejo
    param()

    begin{Write-Verbose 'Začetek funkcije Prenos-Skupaj !' -Verbose}

    process{

        #zanka zahteva vnos imena tekstovne datoteke v kateri so zapisani vsi naslovi, ki se bodo uporabili za analizo
        #ime datoteke se vpiše v spremenljivko $datoteka_z_naslovi
        #zanka se izvaja tako dolgo, dokler ni vnešena datoteka, ki obstaja, takrat se vrednost boolean spremenljivke $test_naslovi spremeni v $true

        Do{
            
            $datoteka_z_naslovi = Read-Host "Vpisi ime tekstovne datoteke z naslovi?"
            Write-Output $datoteka_z_naslovi
            if($datoteka_z_naslovi -like '*.txt*'){
            Test-Path C:\Users\Uporabnik\Desktop\diploma2\$datoteka_z_naslovi | ForEach-Object {if($_ -eq $true){$test_naslovi=$true}else{$test_naslovi=$false}}
                if($test_naslovi -eq $false){
                    "Datoteka ne obstaja!"
                }else{"Obstaja !"}
             }else{
             
                Write-Host 'Ni .txt datoteka'
                $test_naslovi = $false
             
             }
        }While($test_naslovi -eq $false)
        

    
   
        #pridobimo vsebino teksovne datoteke z naslovi in jo shranimo v spremenljivko [System.Object] $polje_naslovov_main
        $polje_naslovov = Get-Content -Path C:\Users\Uporabnik\Desktop\diploma2\$datoteka_z_naslovi  

    

        $kateri_vmesnik=""
        #$test_vmesnik = $False

        #zanka do/while se izvaja dokler ni pravega vnosa vmensika
        #zanka se izvaja dokler ni boolean spremenljivka $test_vmesnik enaka $true
        Do{
            # operator & nam omogoči zagon komande, ki nam izpiše vse vmesnike, ki jih lahko uporabimo s programom tshark
            & "F:\wireshark\tshark.exe" "-D" 
            

            #zanka se ponavlja dokler 
            try{
                #v spremenljivko $kater_vmesnik vnesemo številko željenega vmesnika, na katerem želimo zajemati podatke
                #vmesnikov je 7, za to pogoju zadostuejejo vnešene številke od 1 do 7, vse ostalo je nepravilen vnos
                
                [int]$kateri_vmesnik  = Read-Host "Kateri vmesnik želite izbrati za zajemanje (vpiši številko npr. 1)?"
                    if($kateri_vmesnik -lt 1 -or $kateri_vmesnik -gt 7){
                        Write-Output "izbrane opcije ni na seznamu"
                        $test_vmesnik = $False
                }else{
                        Write-Output "Izbrana opcija je na seznamu."
                        $test_vmesnik = $True
                }

            }catch [System.Management.Automation.RuntimeException]{
                #v primeru, da ni vpisan tip integer se ujame napaka o narobešnjem vnosu
                $test_vmesnik = $False
                Write-Host 'Ni vpisano število ! '  + $_.Exception.GetType().FullName -fore blue -back white
            }
        }While($test_vmesnik -eq $False)
  
    
        # zanka se izvede za vsak naslov v v objektu, ki vsebuje spletne naslove
        #zanka se izvaja zako dolgo, dokler se ne prenesjo vse spletne strani podane s spletnimi naslovi v tekstovni datoteki
        

            
            #------------------------------------------------------------------------------------------------------------------------

            # v spremenljivko $datoteka_pcap vpišemo ime datoteke v katero se bo zajem shranjeval
            
            $datoteka_pcap = Read-Host "Vpisi ime datoteke .pcap?"
            Write-Output $datoteka_pcap
        
            #------------------------------------------------------------------------------------------------------------------------

            #zanka do/while se izvaja dokler ni vnosa tipa integer
            #zanka se izvaja dokler ni boolean spremenljivka $test_int enaka $true

            Do{
                try{
                    # vnos casa poslusanja v sekundah  v spremelnjivko $cas tipa integer
                    [int]$cas = Read-Host "Vpisi koliko casa se izvaja poslusanje programa tshark (sekunde) ?"
                    Write-Output $cas
                    if($cas -is [int]){
                        $test_int = $True
                    }elseif($cas -isnot [int]){
        
                        $test_int = $False
                    }
                }catch [System.Management.Automation.RuntimeException]{
                    # v primeru, da tip spremenljivke ni enak tipu integer
                    Write-Host 'Niso vpisane številke! '  + $_.Exception.GetType().FullName -fore blue -back white
                    $test_int = $false
        
                }
            }While($test_int -eq $False)
        #------------------------------------------------------------------------------------------------------------------------

        
        #izbira uporabnika, da se pri prenosu prenesejo samo HTTP čela
        #spremenljivka tipa boolean $test_povezav je vrednosti $false dokler, ni vnos niza $test_header vnešen da ali ne

            Do{
                $header = Read-Host "Ali želite, da se pošljejo samo čela HTTP (da/ne) ?"
                Write-Output $header

                Switch($header){
                    "da" {$test_header=$true
                        break}
                    "ne" {$test_header=$true
                        break}
                    default{$test_header=$false 
                        'Napacen vnos!'}
                }
            }While($test_header -eq $False)
        #------------------------------------------------------------------------------------------------------------------------

        #izbira uporabnika, da se pri prenosu stran shrani v .html datoteko
        #spremenljivka tipa boolean $test_povezav je vrednosti $false dokler, ni vnos niza $izbira_download vnešen da ali ne

            Do{
            $download= Read-Host "Ali želite, da se vsebina spletne strani shranjuje v .html datoteko (da/ne) ?" 
            Switch($download){
                "da" {
                  $izbira_download=$true
                    break}
                "ne" {
                  $izbira_download=$true
                    break}
                default{$izbira_download=$false 
                    'Napacen vnos!'}
                }
            }while($izbira_download -eq $false)  
        #------------------------------------------------------------------------------------------------------------------------
            #izvede se tshark komanda, ki vsebuje prej vnešeno številko vmesnika , čas zajema in ime datoteke
            $komanda = "F:\wireshark\tshark.exe" 
            $parametri = "-i $kateri_vmesnik -a duration:$cas -f ""tcp and ip"" -w F:\tshark\$datoteka_pcap.pcap"
            $prms = $parametri.Split(" ")

            #$proces = Start-Process -NoNewWindow  "$komanda" $prms -PassThru
            try{
                $proces = Start-Process "$komanda" $prms -PassThru
            }catch [System.Management.Automation.RuntimeException]{
                # v primeru, da so vnešeni morebitni napačni podatki se javi obvestilo o napaki
                Write-Host 'Napaka pri zagonu '  + $_.Exception.GetType().FullName -fore blue -back white
            }catch{
                #v primeur, druge napake se pojavi obvestilo o napaki
                Write-Host 'Druga napaka'  + $_.Exception.GetType().FullName -fore blue -back white
            }
            Start-Sleep -Seconds 3
            $st=0
            foreach($naslov in ($polje_naslovov)){
                
                $st++
                Write-Host $st
                Write-Host "gre naprej"
                $write_result1 = $null
                $write_result2 = $null
                $write_result3 = $null
                $write_result4 = $null
                #glede na prej izbrane parametre se izvede željen prenos posameznega spletnega mesta, ki ga beremo iz tekstovne datoteke

                #v primeru, da je izbrana opcija brez shranjevanja v .html datoteko
                if($download -eq "ne"){
                    "download ne"
                    #izbrana opcija, če se prenesejo samo HTTP glave
                    if($header -eq "da"){
                        $write_result1 = Invoke-WebRequest $naslov -Method Head -Headers @{"Cache-Control"="no-cache"}
                        $write_result1 
                    }elseif($header -eq "ne"){
                        $write_result2 = Invoke-WebRequest $naslov -Headers @{"Cache-Control"="no-cache"}
                        $write_result2
                    }

                #v primeru, da je izbrana opcija s shranjevanjem v .html datoteko
                }elseif($download -eq "da"){
                    "download da"
                    #izbrana opcija, če se prenesejo samo HTTP glave
                    if($header -eq "da"){
                        Write-Host "Čela HTTP ni možno hraniti v .html datoteko"
                        
                            $write_result3 = Invoke-WebRequest $naslov -Method Head -Headers @{"Cache-Control"="no-cache"}
                            $write_result3
                        
                        
                    }elseif($header -eq "ne"){
                   
                        $write_result4 = Invoke-WebRequest $naslov -OutFile F:\tshark\$st.html -Headers @{"Cache-Control"="no-cache"}
                        $write_result4
                       


                    }
            
                }

                #naslednji vnos se lahko izvede, ko se poslušanje zaključi
                #$proces.WaitForExit()
    
            }

            $proces.WaitForExit()
          
        }

    
    
    end{Write-Verbose 'Konec funkcija Prenos-Skupaj' -Verbose}
    

    
    
}


#-----------------------------------------------------------[Execution]------------------------------------------------------------

Main

