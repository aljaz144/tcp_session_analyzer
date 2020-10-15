
function Izpis-Sw{

 <#
            .SYNOPSIS 
            Ta funkcija nudi vse možnosti analize.

            .DESCRIPTION
            Izbiramo lahko med izpisom tabel vseh pogovorov, vseh končnih točk, 
            števila TCP pogovorov med izbranim naslovom in analiza izbranega TCP toka. Ta 
            nudi izpis parametrov kot so začetni RTT, RTT za vsako smer prenosa (MAX,MIN,AVG),velikost okna za vsako smer
            prenosa (max,min,avg), izračunano velikostjo okna za vsako smer prenosa (MAX,MIN,AVG), maksimalno vrednost 
            zaporedne številke in propustnost za vsako smer.
            .PARAMETER
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
            [PS] C:\> . .\analiza_tcp_povezav3.ps1 ; get-help izpis_sw -full

            #>

    [CmdletBinding()]

    param()

    begin{
    Write-Verbose 'Začetek funkcija Izpis-Sw' -Verbose
    }

    process{

        #kličemo funkcijo preberi, 
        $datoteka=""
        $datoteka=preberi
    
        #swtich stavek, kjer izbiramo med spodnjimi izpisanimi opcijami
        #swtich stavek je v do/while zanki, ki se izvaja dokler ni vpisano število 7
        Do{
            Write-Host "Izbrana datoteka $datoteka"
            Write-Host '1. Izpis tabele vseh pogovorov TCP'
            Write-Host '2. Izpis tabele vseh končnih točk TCP'
            Write-Host '3. Izpis števila pogovorov TCP med uporabnikom in izbranim naslovom'
            Write-Host '4. Analiza izbranega toka TCP'
            Write-Host '5. Hranitev zajetih in analiznih datotek'
            Write-Host '6. Izbira nove datoteke'
            Write-Host '7. Izhod'

            #vpišemo izbrano opcijo v seznamu, ki se shrani v spremenljivko $izbira
            $izbira = Read-Host 'Vpišite opcijo za želje izpis'
            Write-Host $izbira

            #ustvarimo tekstovno datoteko z vsemi pogovori v izbrani datoteki (conv.txt), v primeru, da se kliče katera izmed drugih opcij, ki potrebuje to datoteko
            & "F:\wireshark\tshark.exe" -r F:\tshark\$datoteka -q -z conv,tcp > F:\tshark\conv.txt
            
            $switch_test = $true
    

            switch ($izbira) {
            
            # v vseh primerih tshakr zaženemo z znakom & (call operator), s katerim lahko izvedemo komando
            # display filters: 
            # -r pomeni branje datoteke 
            # -q pomeni,da se ne izpiše zaporedno štetje zajetih paketov, ki so ponavadi prikazani
            # -z pomeni statistiko
            # MIN (minimalna vrednost v .pcap datoteki), MAX (maksimalna vrednost v .pcap datoteki), AVG (povprečna vrednost v .pcap datoteki), COUNT (štetje segmentov, ki zadostujejo podanemu filtru)
        
                1{
                    #conv,tcp pomeni, izpis vseh tcp pogovorov
                    #tshark izpiše tabelo vseh zajetih pogovorov v izbrani datoteki -> F:\tshark\conv.txt
                    # uporabljena sintaksa za izpis statistike: -z conv,type,[filter]
                    #kot filter je izbran tcp, torej se prikaže le tcp protokol 
                    
                    Write-Host 'Izpis tabele pogovorov'
                    & "F:\wireshark\tshark.exe" -r F:\tshark\$datoteka -q -z conv,tcp
                    
                    #tshark hrani vse pogovore v tekstovno datoteko
                    Write-Verbose 'Pisanje tabele pogovorov v datoteko'
                    & "F:\wireshark\tshark.exe" -r F:\tshark\$datoteka -q -z conv,tcp > F:\tshark\conv.txt
                    
                    break
                } 


                2{
                    #tshark izpiše tabelo vse zajetih pogovorov v izbrani datoteki -> F:\tshark\endpoints.txt
                    #za izpis tabele končnih točk je uporabljen izpis statistike z endpoints,type[,filter]
                    #kot filter je izbran tcp, torej se prikaže le tcp protokol

                    Write-Host 'Izpis tabele končnih točk'
                    & " F:\wireshark\tshark.exe" -r F:\tshark\$datoteka -q -z endpoints,tcp
                    
                    #tshark hrani vse končne točke v tekstovno datoteko
                    Write-Verbose 'Pisanje tabele končnih točk v datoteko'
                    & " F:\wireshark\tshark.exe" -r F:\tshark\$datoteka -q -z endpoints,tcp > F:\tshark\endpoints.txt
                    
                    break
                }


                3{
                    #razčlenejvanje datoteke in izbira pogovora
                    #v arraylist se hranijo deli niza, ki so enaki ip naslovu
                    $polje_ip = New-Object System.Collections.ArrayList($null)
                    #v arraylist se hranijo priključki, pošiljateljevega naslova
                    $polje_port1 = New-Object System.Collections.ArrayList($null)
                    #v to arraylist se hranijo priključki, končnega naslova
                    $polje_port2 = New-Object System.Collections.ArrayList($null)
                    #pot, kjer se nahaja tekstovna datoteka, ki jo želimo razčleniti
                    $input_path = ‘f:\tshark\conv.txt’
                    #iskalni vzorec za IP
                    $regex = ‘\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d{1,5}\b’
                    #poiščemo naslove v tekstovni datoteki in jih hranimo v arraylist ip naslovi
                    $ip_naslovi = select-string -Path $input_path -Pattern $regex -AllMatches | ForEach-Object { $_.Matches }
                    $ip_string = $ip_naslovi -split (":")

                    #v polje se hranijo začetni ip naslovi
                    #v conv.txt se naslovi IP vedno izpišejo na način "začetni ip:vrata -> končni ip:vrata"

                    #začetna vrata so na 2. mestu v polju in se ponavlja na vsake 4 elemente
                    for($i=1;;$i+=4){
                        if($ip_string[$i] -eq $null){break}
                        $vr = $ip_string[$i]
                        $polje_port1.Add("$vr") | Out-Null
                    }

                    #končni IP naslov je na 3. mestu v polju in se ponavlja na vsake 4 elemente
                    for($i=2;;$i+=4){
                        if($ip_string[$i] -eq $null){break}
                        $vr2 = $ip_string[$i]
                        $polje_ip.Add("$vr2") | Out-Null
                    }

                    #končna vrata so na 4. mestu v polju in se ponavlja na vsake 4 elemente
                    for($i=3;;$i+=4){
                        if($ip_string[$i] -eq $null){break}
                        $vr3 = $ip_string[$i]
                        $polje_port2.Add("$vr3") | Out-Null
                    }

                    
            
                    #zanka se izvaja dokler ni izbrana ustrezna številka pogovora
                    #dokler je $test_izbira enaka $false
                    #ko vpišemo pravo številko je vrednost $test_izbire enaka $true

                    Do{
                        #izpis vseh pogovorov s priključki, ki so no voljo
                        #iz arrylistov $ip_izpis, $port_izpis1, $port_izpis2
                        "Vsi pogovori, ki so na voljo."
                        $ip_izpis = $polje_ip.GetEnumerator()
                        $port_izpis1 = $polje_port1.GetEnumerator()
                        $port_izpis2 = $polje_port2.GetEnumerator()

                        $stevec_izpis_pogovorov=0
            
                        While($ip_izpis.MoveNext() -and $port_izpis1.MoveNext() -and $port_izpis2.MoveNext()){
                
                            $stevec_izpis_pogovorov++
                            $naslov = $ip_string[0]
                            Write-Host "$stevec_izpis_pogovorov." $naslov "port:" $port_izpis1.current " <-> "$ip_izpis.current "port:" $port_izpis2.current " "
            
                        }

                        #pretvorimo v celoštevilski tip, da lahko pravilno primerjamo v spodnjem pogoju
                        [int]$vnos1=$stevec_izpis_pogovorov
                        #preverjamo pravi vnos
                        try{
                            #vpišemo številko pogovora
                            [int]$izbira_pogovor  = Read-Host "Izberi željen pogovor s številko"

                            #pretvorba števca v tip integer za postavljanje ustreznega pogoja
                            #preverjamo vnos, glede na vrendost $stevec_izpis_pogovorov, ki prešteje število pogovorov, glede na izpis na zaslon
                            #po vnosu prave številke je vrednost, ki nas vrti v zanki $test_izbira_integer enaka $true

                            if($izbira_pogovor -lt 1 -or $izbira_pogovor -gt $vnos1 -or $izbira_pogovor -notmatch "^\d+$"){
                                $test_izbira_pogovor = $false
                                "Števila ni v seznamu"
                            #po vnosu napačne številke je vrednost, ki nas vrti v zanki $test_izbira_integer enaka $false
                            }else{
                                $test_izbira_pogovor=$true
                                $zacetni_tok_analiza = $ip_string[0]
                                $koncni_tok_analiza = $polje_ip[$izbira_pogovor-1]
                                $port_analiza = $polje_port1[$izbira_pogovor-1]

                                
                                $test_izbira_pogovor = $true
                            }
                        #v primeru druge vrednosti, kot integer nas skript opozori o napaki
                        }catch [System.Management.Automation.RuntimeException]{
                            Write-Host 'Niso vpisane številke! '  + $_.Exception.GetType().FullName -fore blue -back white
                            $test_int = $false
                
                            }

                        }While($test_izbira_pogovor -eq $False)

                        #tshark izpiše tabelo vse zajetih pogovorov za izbran tok v izbrani datoteki -> F:\tshark\izbran_tok.txt
                        #za izpis tabele končnih točk je uporabljena sintaksa: endpoints,type,[filter]
                        #kot filter je izbran tcp, torej se prikaže le tcp protokol
                        #prikažejo se pogovori, ki vsebujejo IP naslov ip.addr==$koncni_tok_analiza
                        Write-Host 'Izpis števila pogovorv TCP med uporabnikom in izbranim naslovom'

                        #izpis izbranega toka
                        & " F:\wireshark\tshark.exe" -r f:\tshark\$datoteka  -q -z conv,tcp,"ip.addr==$koncni_tok_analiza" 

                        & " F:\wireshark\tshark.exe" -r f:\tshark\$datoteka  -q -z conv,tcp,"ip.addr==$koncni_tok_analiza" > F:\tshark\izbran_tok.txt
                        break
        
                    } 
    
                
                4{
                    #pri vseh izbirah je interval 3600 sekund, torej predpostavimo, da zajemanje ne bo trajalo več kot eno uro

                    Write-Host 'Izpis analize izbranega toka'
                    
                    #razčlenjevanje in izbira pogovora
                    #v ta arraylist se hranijo deli niza, ki so enaki ip naslovu
                    $polje_ip = New-Object System.Collections.ArrayList($null)
                    #v to arraylist se hranijo izvorna vrata
                    $polje_port1 = New-Object System.Collections.ArrayList($null)
                    #v to polje se hranijo ciljna vrata
                    $polje_port2 = New-Object System.Collections.ArrayList($null)
                    #pot, kjer se nahaja tekstovna datoteka, ki jo želimo razšleniti
                    $input_path = ‘f:\tshark\conv.txt’
                    #iskalni vzorec za IP
                    $regex = ‘\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\:\d{1,5}\b’
                    #poiščemo naslove v tekstovni datoteki in jih hranimo v arraylist ip naslovi
                    $ip_naslovi = select-string -Path $input_path -Pattern $regex -AllMatches | ForEach-Object { $_.Matches }
                    $ip_string = $ip_naslovi -split (":")

                    #v polje se hranijo začetni ip naslovi
                    #v conv.txt se vedno izpišejo vedno na način "začetni ip:vrata <-> končni ip:vrata"

                    
                    #začetna vrata so na 2. mestu v polju in se ponavljajo na vsake 4 elemente
            
                    for($i=1;;$i+=4){
                        if($ip_string[$i] -eq $null){break}
                        $vr = $ip_string[$i]
                        $polje_port1.Add("$vr") | Out-Null
                    }
                    #končni ip naslov je na 3. mestu v polju in se ponavlja na vsake 4 elemente
                    for($i=2;;$i+=4){
                        if($ip_string[$i] -eq $null){break}
                        $vr2 = $ip_string[$i]
                        $polje_ip.Add("$vr2") | Out-Null
                    }
                    #končna vrata so na 4. mestu v polju in se ponavljajo na vsake 4 elemente
                    for($i=3;;$i+=4){
                        if($ip_string[$i] -eq $null){break}
                        $vr3 = $ip_string[$i]
                        $polje_port2.Add("$vr3") | Out-Null
                    }

                    
            
                    #zanka se izvaja dokler ni izbrana ustrezna številka pogovora
                    #dokler je $test_izbire enaka $false
                    #ko vpišemo pravo številko je vrednost $test_izbira enaka $true

                    Do{
                        #izpis vseh pogovorov s priključki, ki so no valjo
                        #iz arrylistov $ip_izpis, $port_izpis1 , $port_izpis2

                        "Vsi pogovori, ki so na voljo."
                        $ip_izpis = $polje_ip.GetEnumerator()
                        $port_izpis1 = $polje_port1.GetEnumerator()
                        $port_izpis2 = $polje_port2.GetEnumerator()

                        $stevec_izpis_pogovorov=0
            
                        While($ip_izpis.MoveNext() -and $port_izpis1.MoveNext() -and $port_izpis2.MoveNext()){
                
                            $stevec_izpis_pogovorov++
                            $naslov = $ip_string[0]
                            Write-Host "$stevec_izpis_pogovorov." $naslov "port:" $port_izpis1.current " <-> "$ip_izpis.current "port:" $port_izpis2.current " "
            
                        }

                        #prevejramo pravi vnos
                        try{
                            [int]$izbira_pogovor  = Read-Host "Izberi željen pogovor s številko"

                           #pretvorimo v celoštevilski tip, da lahko pravilno primerjamo v spodnjem pogoju
                           [int]$vnos2=$stevec_izpis_pogovorov
                            
                            #preverjamo vnos, glede na vrendost $stevec_izpis_pogovorov, ki prešteje število pogovorov, glede na izpis na zaslon
                            #po vnosu prave številke je vrednost, ki nas vrti v zanki $test_izbira_integer enaka $true
                            if($izbira_pogovor -lt 1 -or $izbira_pogovor -gt $vnos2 -or $izbira_pogovor -notmatch "^\d+$"){
                                $test_izbira_pogovor = $false
                                "Števila ni v seznamu"
                            #po vnosu napačne številke je vrednost, ki nas vrti v zanki $test_izbira_integer enaka $false
                            }else{
                                $test_izbira_pogovor=$true
                                $zacetni_tok_analiza = $ip_string[0]
                                $koncni_tok_analiza = $polje_ip[$izbira_pogovor-1]
                                $port_analiza = $polje_port1[$izbira_pogovor-1]

                                
                                $test_izbira_pogovor = $true
                            }
                        #v primeru druge vrednosti, kot integer nas skript opozori o napaki
                        }catch [System.Management.Automation.RuntimeException]{
                            Write-Host 'Niso vpisane številke! '  + $_.Exception.GetType().FullName -fore blue -back white
                            $test_int = $false
                            $test_izbira_pogovor = $false
                            }

                        }While($test_izbira_pogovor -eq $False) 
                        
                        #-----------------------------------------------------------------------------------------

                        #vzorec za iskanje števil
                        $regex_fin_syn = ‘\b\d{1,10}\b’

                        #preštejemo FIN zastavice
                        #tshark prešteje FIN zastavice in rezultat hrani v datoteko -> F:\tshark_temp\fin_count.txt
                        #uporabljena sintaksa za izpis statistike: z -z io,stat,interval,"[COUNT|SUM|MIN|MAX|AVG|LOAD](field)filter"
                        #uprabljen je izračun za (COUNT - maksimalna vrednost)
                        #kot filter je izbran tcp.flags.fin, ki prešteje FIN zastavice, kjer je naslov IP ip.addr==$koncni_tok_analiza in vtičnica tcp.port == $koncni_tok analiza
                        & "f:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"COUNT(tcp.flags.fin)tcp.flags.fin==set && ip.addr==$koncni_tok_analiza && tcp.port == $port_analiza" > F:\tshark_temp\fin_count.txt
                        $fin_count = select-string -Path F:\tshark_temp\fin_count.txt -Pattern $regex_fin_syn -AllMatches | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value }
                        [string]$fin_count_string = $fin_count[$fin_count.Length-1]
                        [double]$fin_count_double = $fin_count_string
                        Write-Host "fin: " $fin_count_double

                        #preštejemo SYN zastavice
                        #tshark prešteje SYN zastavice in rezultat hrani v datoteko -> F:\tshark_temp\syn_count.txt
                        #uporabljena sintaksa za izpis statistike: -z io,stat,interval,"[COUNT|SUM|MIN|MAX|AVG|LOAD](field)filter"
                        #uprabljen je izračun za (COUNT - maksimalna vrednost)
                        #kot filter je izbran tcp.flags.syn, ki prešteje SYN zastavice, kjer je naslov IP ip.addr==$koncni_tok_analiza in vtičnica tcp.port == $koncni_tok analiza
                        & "f:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"COUNT(tcp.flags.syn)tcp.flags.syn==set && ip.addr==$koncni_tok_analiza && tcp.port == $port_analiza" > F:\tshark_temp\syn_count.txt
                        $syn_count = select-string -Path F:\tshark_temp\syn_count.txt -Pattern $regex_fin_syn -AllMatches | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value }
                        [string]$syn_count_string = $syn_count[$syn_count.Length-1]
                        [double]$syn_count_double = $syn_count_string
                        Write-Host "syn: "$syn_count_double

                    # v primeru, da sta prešteti manj kot dve FIN ali SYN zastavici se analiza za izbran pogovor ne izvede
                    if($syn_count_double -le 1 -or $fin_count_double -le 1){

                        Write-Host "Analiza ni mogoča, pogovor ni zaključen!"
                    
                    # če sta prešteti vsaj dve FIN ali SYN zastavici pomeni, da je pogvor zaključen in se analiza lahko izvede
                    }elseif($syn_count_double -ge 2 -and $fin_count_double -ge 2){
        
            
                    
                    #tshark izpiše začetni RTT v datoteko -> F:\tshark\zacetni_rtt.txt
                    #uporabljena je sintaksa za izpis statistike: -z io,stat,interval,"[COUNT|SUM|MIN|MAX|AVG|LOAD](field)filter"
                    #uprabljen je izračun za (MAX - maksimalna vrednost), ampak pri vseh vrednostih pokaže enake vrednosti,ker je začetni RTT vedno enak
                    #kot filter je izbran tcp.analysis.initial_rtt, torej se prikaže začetni RTT, kjer je izbrani naslov IP ip.addr==$koncni_tok_analiza
                    #rezultat se hrani v F:\tshark\zacetni_rtt.txt

                    Write-Host "Izpis začetnega RTT :"
                    & "F:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"MAX(tcp.analysis.initial_rtt)ip.addr==$koncni_tok_analiza && tcp.analysis.initial_rtt && tcp.port==$port_analiza"
                    
            
                    Write-Verbose "Pisanje začetnega RTT v datoteko"
                    & " F:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"MAX(tcp.analysis.initial_rtt)ip.addr==$koncni_tok_analiza && tcp.analysis.initial_rtt" > F:\tshark\zacetni_rtt.txt
                    
                    Write-Host ""
                    #-----------------------------------------------------------------------------------------
                    
                    #tshark izpiše RTT (MIN - minimalna vrednost, MAX - maksimalna vrednost, AVG - povprečna vrednost) za obe smeri  
                    #za vsako smer je rezultat v datotekah: F:\tshark\analiza_rtt_smer1.txt in F:\tshark\analiza_rtt_smer2.txt
                    #uporabljena sintaksa za izpis statistike: -z io,stat,interval,"[COUNT|SUM|MIN|MAX|AVG|LOAD](field)filter"
                    #kot filter je izbran tcp.analysis.ack_rtt, torej se prikaže RTT, kjer je izbrani ciljni naslov IP ip.dst==$koncni_tok_analiza
                    #smer zamenjamo z: ip.src==$koncni_tok_analiza
                    #upoštevajo se vrata za izbrano smer s filtrom tcp.srcport==$port_analiza
                    #smer zamenjamo z: tcp.dstport==$port_analiza
                    

                    Write-Host "Izpis statistike RTT za smer prenosa $zacetni_tok_analiza -> $koncni_tok_analiza "
                    & " F:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"MIN(tcp.analysis.ack_rtt)ip.dst==$koncni_tok_analiza && tcp.analysis.ack_rtt && tcp.srcport==$port_analiza","MAX(tcp.analysis.ack_rtt)ip.dst==$koncni_tok_analiza && tcp.analysis.ack_rtt && tcp.srcport==$port_analiza","AVG(tcp.analysis.ack_rtt)ip.dst==$koncni_tok_analiza && tcp.analysis.ack_rtt  && tcp.srcport==$port_analiza"
                    
                    Write-Verbose "Pisanje statistike RTT za smer prenosa $zacetni_tok_analiza -> $koncni_tok_analiza v datoteko"
                    & " F:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"MIN(tcp.analysis.ack_rtt)ip.dst==$koncni_tok_analiza && tcp.analysis.ack_rtt && tcp.srcport==$port_analiza","MAX(tcp.analysis.ack_rtt)ip.dst==$koncni_tok_analiza && tcp.analysis.ack_rtt && tcp.srcport==$port_analiza","AVG(tcp.analysis.ack_rtt)ip.dst==$koncni_tok_analiza && tcp.analysis.ack_rtt  && tcp.srcport==$port_analiza" > F:\tshark\analiza_rtt_smer1.txt
                    
                    Write-Host ""
                    Write-Host "Izpis statistike RTT za smer prenosa $koncni_tok_analiza -> $zacetni_tok_analiza "
                    & " F:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"MIN(tcp.analysis.ack_rtt)ip.src==$koncni_tok_analiza && tcp.analysis.ack_rtt  && tcp.dstport==$port_analiza","MAX(tcp.analysis.ack_rtt)ip.src==$koncni_tok_analiza && tcp.analysis.ack_rtt  && tcp.dstport==$port_analiza","AVG(tcp.analysis.ack_rtt)ip.src==$koncni_tok_analiza && tcp.analysis.ack_rtt  && tcp.dstport==$port_analiza"
                    

                    Write-Verbose "Pisanje statistike RTT za smer prenosa $koncni_tok_analiza -> $zacetni_tok_analiza v datoteko"
                    & " F:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"MIN(tcp.analysis.ack_rtt)ip.src==$koncni_tok_analiza && tcp.analysis.ack_rtt  && tcp.dstport==$port_analiza","MAX(tcp.analysis.ack_rtt)ip.src==$koncni_tok_analiza && tcp.analysis.ack_rtt  && tcp.dstport==$port_analiza","AVG(tcp.analysis.ack_rtt)ip.src==$koncni_tok_analiza && tcp.analysis.ack_rtt  && tcp.dstport==$port_analiza" > F:\tshark\analiza_rtt_smer2.txt
                    
                    Write-Host ""
                    #-----------------------------------------------------------------------------------------
                   
                    #tshark izpiše velikost okna (MIN - minimalna vrednost, MAX - maksimalna vrednost, AVG - povprečna vrednost) za obe smeri  
                    #za vsako smer je rezultat v datotekah: F:\tshark\velikost_okna_smer1.txt in F:\tshark\velikost_okna_smer2.txt
                    #uporabljena sintaksa za izpis statistike: -z io,stat,interval,"[COUNT|SUM|MIN|MAX|AVG|LOAD](field)filter"
                    #kot filter je izbran tcp.window_size_value, torej se prikaže velikost okna, za ciljni naslov IP ip.addr==$koncni_tok_analiza
                    #smer zamenjamo z: ip.src==$koncni_tok_analiza
                    #upoštevajo se tudi vrata za izbrano smer s filtrom tcp.srcport==$port_analiza
                    #smer zamenjamo z: tcp.dstport==$port_analiza

                    Write-Host "Izpis velikosti oken za smer prenosa $zacetni_tok_analiza -> $koncni_tok_analiza"
                    & " F:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"AVG(tcp.window_size_value)ip.src==$koncni_tok_analiza && tcp.window_size_value  && tcp.dstport==$port_analiza","MAX(tcp.window_size_value)ip.src==$koncni_tok_analiza && tcp.window_size_value  && tcp.dstport==$port_analiza","MIN(tcp.window_size_value)ip.src==$koncni_tok_analiza && tcp.window_size_value  && tcp.dstport==$port_analiza"
                    

                    Write-Verbose "Pisanje velikosti oken za smer prenosa $zacetni_tok_analiza -> $koncni_tok_analiza v datoteko"
                    & " F:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"AVG(tcp.window_size_value)ip.src==$koncni_tok_analiza && tcp.window_size_value  && tcp.dstport==$port_analiza","MAX(tcp.window_size_value)ip.src==$koncni_tok_analiza && tcp.window_size_value  && tcp.dstport==$port_analiza","MIN(tcp.window_size_value)ip.src==$koncni_tok_analiza && tcp.window_size_value  && tcp.dstport==$port_analiza" > F:\tshark\velikost_okna_smer1.txt
                    
                    Write-Host ""
                    Write-Host "Izpis velikost oken za smer prenosa $koncni_tok_analiza -> $zacetni_tok_analiza"
                    & "F:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"AVG(tcp.window_size_value)ip.dst==$koncni_tok_analiza && tcp.window_size_value  && tcp.srcport==$port_analiza","MAX(tcp.window_size_value)ip.dst==$koncni_tok_analiza && tcp.window_size_value  && tcp.srcport==$port_analiza","MIN(tcp.window_size_value)ip.dst==$koncni_tok_analiza && tcp.window_size_value  && tcp.srcport==$port_analiza"
                    

                    Write-Verbose "Pisanje velikosti oken za smer prenosa $koncni_tok_analiza -> $zacetni_tok_analiza v datoteko"
                    & " F:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"AVG(tcp.window_size_value)ip.dst==$koncni_tok_analiza && tcp.window_size_value  && tcp.srcport==$port_analiza","MAX(tcp.window_size_value)ip.dst==$koncni_tok_analiza && tcp.window_size_value  && tcp.srcport==$port_analiza","MIN(tcp.window_size_value)ip.dst==$koncni_tok_analiza && tcp.window_size_value  && tcp.srcport==$port_analiza" > F:\tshark\velikost_okna_smer2.txt
                    Write-Host ""

                    #-----------------------------------------------------------------------------------------
                    
                    #tshark izpiše izračunano velikost okna (MIN - minimalna vrednost, MAX - maksimalna vrednost, AVG - povprečna vrednost) 
                    #za vsako smer je rezultat v datotekah: F:\tshark\izracunana_velikost_okna_smer1.txt in F:\tshark\izracunana_velikost_okna_smer2.txt
                    #uporabljena sintaksa za izpis statistike: -z io,stat,interval,"[COUNT|SUM|MIN|MAX|AVG|LOAD](field)filter"
                    #kot filter je izbran tcp.window_size, torej se prikaže izračunano velikost okna, kjer začetni naslov IP ip.src==$koncni_tok_analiza
                    #smer zamenjamo z: ip.dst==$koncni_tok_analiza
                    #upoštevajo se vrata za izbrano smer s filtrom tcp.srcport==$port_analiza
                    #smer zamenjamo z: tcp.dstport==$port_analiza

                    Write-Host "Izpis izračunane velikosti oken za smer prenosa $zacetni_tok_analiza -> $koncni_tok_analiza"
                    & " F:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"AVG(tcp.window_size)ip.src==$koncni_tok_analiza && tcp.window_size  && tcp.dstport==$port_analiza","MAX(tcp.window_size)ip.src==$koncni_tok_analiza && tcp.window_size  && tcp.dstport==$port_analiza","MIN(tcp.window_size)ip.src==$koncni_tok_analiza && tcp.window_size  && tcp.dstport==$port_analiza"
                    
    
                    Write-Verbose "Pisanje izračunane velikosti za smer prenosa $zacetni_tok_analiza -> $koncni_tok_analiza v datoteko"
                    & " F:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"AVG(tcp.window_size)ip.src==$koncni_tok_analiza && tcp.window_size  && tcp.dstport==$port_analiza","MAX(tcp.window_size)ip.src==$koncni_tok_analiza && tcp.window_size  && tcp.dstport==$port_analiza","MIN(tcp.window_size)ip.src==$koncni_tok_analiza && tcp.window_size  && tcp.dstport==$port_analiza" > F:\tshark\izracunana_velikost_okna_smer1.txt
                    
                    Write-Host ""
                    Write-Host  "Izpis izračunane velikosti oken za smer prenosa $koncni_tok_analiza -> $zacetni_tok_analiza"
                    & " F:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"AVG(tcp.window_size)ip.dst==$koncni_tok_analiza && tcp.window_size  && tcp.srcport==$port_analiza","MAX(tcp.window_size)ip.dst==$koncni_tok_analiza && tcp.window_size  && tcp.srcport==$port_analiza","MIN(tcp.window_size)ip.dst==$koncni_tok_analiza && tcp.window_size  && tcp.srcport==$port_analiza"
                    
    
                    Write-Verbose  "Pisanje izračunane velikosti oken za smer prenosa $koncni_tok_analiza -> $zacetni_tok_analiza v datoteko"
                    & " F:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"AVG(tcp.window_size)ip.dst==$koncni_tok_analiza && tcp.window_size  && tcp.srcport==$port_analiza","MAX(tcp.window_size)ip.dst==$koncni_tok_analiza && tcp.window_size  && tcp.srcport==$port_analiza","MIN(tcp.window_size)ip.dst==$koncni_tok_analiza && tcp.window_size  && tcp.srcport==$port_analiza" > F:\tshark\izracunana_velikost_okna_smer2.txt
                    Write-Host ""

                    #-----------------------------------------------------------------------------------------
                    
                    #tshark izpiše največjo vrednost zaporedne številke  (MAX - maksimalna vrednost) za obe smeri  
                    #za vsako smer je rezultat v datotekah: F:\tshark\max_zap_st_smer1.txt in F:\tshark\max_zap_st_smer2.txt
                    #uporabljena sintaksa za izpis statistike: -z io,stat,interval,"[COUNT|SUM|MIN|MAX|AVG|LOAD](field)filter"
                    #kot filter je izbran tcp.seq, torej se prikaže maksimalne vrednost zaporedne številke, kjer je koncni naslov IP ip.dst==$koncni_tok_analiza
                    #smer zamenjamo z: ip.src==$koncni_tok_analiza
                    #upoštevajo se vrata za izbrano smer s filtrom tcp.srcport==$port_analiza
                    #smer zamenjamo z: tcp.dstport==$port_analiza

                    Write-Host  "Izpis maksimalne vrednosti zaporedne številke  $zacetni_tok_analiza -> $koncni_tok_analiza "
                    & " F:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,0,1,"MAX(tcp.seq)ip.dst==$koncni_tok_analiza && tcp.seq  && tcp.srcport==$port_analiza"
                    
    
                    Write-Verbose  "Pisanje maksimalne zaporedne številke za smer prenosa $zacetni_tok_analiza -> $koncni_tok_analiza v datoteko"
                    & " F:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,0,1,"MAX(tcp.seq)ip.dst==$koncni_tok_analiza && tcp.seq  && tcp.srcport==$port_analiza" > F:\tshark\max_zap_st_smer1.txt
                    
                    Write-Host ""
                    Write-Host  "Izpis maksimalne vrednosti zaporedne številke  $koncni_tok_analiza -> $zacetni_tok_analiza "
                    & " F:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,0,1,"MAX(tcp.seq)ip.src==$koncni_tok_analiza && tcp.seq  && tcp.dstport==$port_analiza"
                    
    
                    Write-Verbose  "Pisanje maksimalne zaporedne številke za smer prenosa $koncni_tok_analiza -> $zacetni_tok_analiza v datoteko"
                    & "F:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,0,1,"MAX(tcp.seq)ip.src==$koncni_tok_analiza && tcp.seq  && tcp.dstport==$port_analiza" > F:\tshark\max_zap_st_smer2.txt
                    Write-Host ""
                    
                    #------------------------------------------------------------------------------------------

                        Write-Host "Izračun propustnosti za smer $zacetni_tok_analiza -> $koncni_tok_analiza dstport $port_analiza"

                        
                        #uporabljena sintaksa za izpis statistike:  -z io,stat,interval,"[COUNT|SUM|MIN|MAX|AVG|LOAD](field)filter"
                        #kot filter je izbran "tcp.ack", z značko "MAX" pridobimo največjo potrditveno številko, kjer je izbrani izvorni naslov "ip.src==$koncni_tok_analiza"
                        #pravi proces izberemo s ciljnimi vrati "tcp.dstport==$port_analiza"
                        # gre za smer smer od 192.168.1.8 -> ... , za to smer je potreben nasprotna potrditvena številka, ki pove katero zaporedno številko prejemnik pričakuje
    
                        & "f:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"MAX(tcp.ack)tcp.ack && ip.src==$koncni_tok_analiza && tcp.dstport==$port_analiza" > F:\tshark_temp\ack1.txt
                        
                        #filter s katerim razčlenimo datoteko cas1_max.txt, da izluščimo maksimalni #čas trajanje povezave
                        $regex = ‘\b\d{1,10}\b’
                        $potrditvena_st1 = select-string -Path F:\tshark_temp\ack1.txt -Pattern $regex -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value }
                        $dolzina1 = $potrditvena_st1.Length

                        #v objektu $potrditvena_st1 izberemo ustrezno vrednost, ki predstavlja največjo potrditveno številko in jo hranimo v niz $smer1
                        [string]$smer1 = $potrditvena_st1[$dolzina1-1]
                        #$smer1 hranimo v objekt $smer1_double, ki je tipa "double", zaradi računanja
                        [double]$smer1_double = $smer1
            
                        #odštejemo 2 zaradi fantomskih zlogov, ki povečujejo potrditveno število (ob vsaki nastavljeni SYN ali FIN zastavici je poslan fantomski zlog)
                        [double]$podatki1 = $smer1_double-2

                        
                        #uporabljena sintaksa za izpis statistike:  -z io,stat,interval,"[COUNT|SUM|MIN|MAX|AVG|LOAD](field)filter"
                        #kot filter je izbran frame.time_relative, z značko "MIN" pridobimo končni čas pogovora, kjer je izbrani naslov IP za eno smer "ip.addr==$koncni_tok_analiza" in nastavljena zastavica ACK "tcp.flags.ack == Set"
                        #pravi proces se izbere z vrati "tcp.port==$port_analiza"
                        
                        & "f:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"MAX(frame.time_relative)frame.time_relative && tcp.flags.ack == Set && ip.addr == $koncni_tok_analiza  && tcp.port==$port_analiza" > F:\tshark_temp\cas1_max.txt
                        
                        #filter s katerim razčlenimo datoteko cas1_max.txt, da izluščimo maksimalni čas trajanje povezave
                        $regex = ‘\b\d{1,10}\.\d{1,10}\b’
                        #v objektu $cas1_max izberemo ustrezno vrednost, ki predstavlja maksimalni čas in jo hranimo v niz $max_cas1_fin
                        $cas1_max = select-string -Path F:\tshark_temp\cas1_max.txt -Pattern $regex -AllMatches | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value } 
                        [string]$max_cas1_fin = $cas1_max[$cas1_max.Length-1]
                        
                        #uporabljena sintaksa za izpis statistike:  -z io,stat,interval,"[COUNT|SUM|MIN|MAX|AVG|LOAD](field)filter"
                        #kot filter je izbran frame.time_relative in z značko "MAX" prikažemo končni čas pogovora, kjer je izbrani koncni tok za eno smer "ip.addr==$koncni_tok_analiza" in nastavljena zastavica SYN "tcp.flags.syn == Set"
                        #pravi proces se izbere z vrati "tcp.port==$port_analiza"

                        & "f:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"MIN(frame.time_relative)frame.time_relative && tcp.flags.syn == Set && ip.addr == $koncni_tok_analiza  && tcp.port==$port_analiza" > F:\tshark_temp\cas1_min.txt
                        
                        #s filtrom $regex razčlenimo datoteko cas1_min.txt, da izluščimo minimalni čas trajanje povezave in jo hranimo v niz $min_cas1_fin
                        $regex = ‘\b\d{1,10}\.\d{1,10}\b’
                        $cas1_min = select-string -Path F:\tshark_temp\cas1_min.txt -Pattern $regex -AllMatches | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value } 
                        #v objektu $cas1_min izberemo ustrezno vrednost, ki predstavlja minimalni čas
                        [string]$min_cas1_fin = $cas1_min[$cas1_min.Length-1]

                        #spremenimo v tip "double", ker bomo s spremenljivkami $max_cas1_fin_double in $min_cas1_fin_double računali
                        [double]$max_cas1_fin_double = $max_cas1_fin
                        [double]$min_cas1_fin_double = $min_cas1_fin

                        #izračun propustnosti
                        #če je maksimalni čas trajanja povezave enak 0
                        if($max_cas1_fin_double -eq 0){
                            $izracun1 = 0

                        #če je vrednost prenešenih zlogov enaka 0
                        }elseif($podatki1 -eq 0){
                            
                            $izracun1 = 0
                            Write-Host 'Propustnost je 0 bit\s'

                        }else{
                            Write-Host "izracun1 = ($podatki1*8) / ("$max_cas1_fin_double" -" $min_cas1_fin_double" )"
                            $izracun1 = [math]::Round(($podatki1*8) / ($max_cas1_fin_double - $min_cas1_fin_double),2)

                        }

                        Write-Host "Propustnost je " $izracun1 "bit\s"
                    
                        Write-Host ""
                    #----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

                  
                        Write-Host "Izračun propustnosti za smer $koncni_tok_analiza -> $zacetni_tok_analiza srcport: $port_analiza"
                        
                        #uporabljena je stinaksa za izpis statistike:  -z io,stat,interval,"[COUNT|SUM|MIN|MAX|AVG|LOAD](field)filter"
                        #kot filter je izbran "tcp.ack", z značko "MAX" pridobimo največjo potrditveno številko, kjer je izbrani izvorni naslov "ip.src==$koncni_tok_analiza"
                        #pridobimo največjo potrditveno številko, kjer je izbrani izvorni naslov "ip.src==$koncni_tok_analiza"
                        #pravi proces izberemo z vrati tcp.srcport==$port_analiza
                        #pravi proces izberemo s ciljnimi vrati "tcp.dstport==$port_analiza"
                        #gre za smer od 192.168.1.8 -> ... , za to smer je potrebna nasprotna potrditvena številka, ki pove katero zaporedno številko prejemnik pričakuje


                        
                        # smer ... -> 192.168.1.8
                        & "f:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"MAX(tcp.ack)tcp.ack && ip.dst==$koncni_tok_analiza && tcp.srcport==$port_analiza" > F:\tshark_temp\ack2.txt
                        
                        #s filtrom $regex izlušlimo števila iz datoteke F:\tshark_temp\ack1.txt
                        $regex = ‘\b\d{1,10}\b’
                        #pridobimo maksimalno vrednost potrditvene številk
                        $potrditvena_st2 = select-string -Path F:\tshark_temp\ack2.txt -Pattern $regex -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value }
                        $dolzina2 = $potrditvena_st2.Length

                        #v objektu $potrditvena_st1 izberemo ustrezno vrednost, ki predstavlja največjo potrditveno številko in jo hranimo v niz $smer2
                        [string]$smer2 = $potrditvena_st2[$dolzina2-1]
                        #$smer1 hranimo v objekt $smer2_double, ki je tipe "double", zaradi računanja 
                        [double]$smer2_double = $smer2
                        #odštejemo 2 zaradi fantomskih zlogov, ki povečujejo potrdiveno številko (ob vsaki nastavljeni SYN ali FIN zastavici je poslan fantomski zlog)
                        [double]$podatki2 = $smer2_double - 2

                        #uporabljena je stinaksa za izpis statistike:  -z io,stat,interval,"[COUNT|SUM|MIN|MAX|AVG|LOAD](field)filter"
                        #kot filter je izbran "frame.time_relative", z značko "MAX" pridobimo končni čas pogovora, kjer je naslov IP "ip.addr==$koncni_tok_analiza" in nastavljena zastavica ACK "tcp.flags.ack == Set"
                        #pravi proces izberemo z vrati "tcp.port==$port_analiza"
                        
            

                        & "f:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"MAX(frame.time_relative)frame.time_relative && tcp.flags.ack == Set && ip.addr == $koncni_tok_analiza  && tcp.port==$port_analiza" > F:\tshark_temp\cas2_max.txt
                        
                        #s filtrom $regex razčlenimo datoteko cas1_min.txt, da izluščimo minimalni čas trajanje povezave in jo hranimo v niz $max_cas2_fin
                        $regex = ‘\b\d{1,10}\.\d{1,10}\b’
                        #v objektu $cas2_max izberemo ustrezno vredno, ki predstavlja maksimalni čas 
                        $cas2_max = select-string -Path F:\tshark_temp\cas2_max.txt -Pattern $regex -AllMatches | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value } 
                        [string]$max_cas2_fin = $cas2_max[$cas2_max.Length-1]

                        #uporabljena je stinaksa za izpis statistike:  -z io,stat,interval,"[COUNT|SUM|MIN|MAX|AVG|LOAD](field)filter" in nastavljena zastavica SYN "tcp.flags.syn == Set"
                        #kot filter je izbran "frame.time_relative", z značko "MIN" pridobimo začetni čas pogovora, kjer je naslov IP "ip.addr==$koncni_tok_analiza"
                        #pravi proces izberemo z vrati "tcp.port==$port_analiza"

                        & "f:\wireshark\tshark.exe" -r f:\tshark\$datoteka -q -z io,stat,3600,"MIN(frame.time_relative)frame.time_relative && tcp.flags.syn == Set && ip.addr == $koncni_tok_analiza  && tcp.port==$port_analiza" > F:\tshark_temp\cas2_min.txt
                        
                        #s filtrom $regex razčlenimo datoteko cas2_min.txt, da izluščimo minimalni čas trajanje povezave in jo hranimo v niz $max_cas1_fin
                        $regex = ‘\b\d{1,10}\.\d{1,10}\b’
                        $cas2_min = select-string -Path F:\tshark_temp\cas2_min.txt -Pattern $regex -AllMatches | ForEach-Object { $_.Matches} | ForEach-Object { $_.Value } 
                        #v objektu $cas1_min izberemo ustrezno vredno, ki predstavlja minimalni čas 
                        [string]$min_cas2_fin = $cas2_min[$cas2_min.Length-1]
                        #vrednosti, spremenimo v tip double, ker bomo z njimi računali
                        [double]$max_cas2_fin_double = $max_cas2_fin
                        [double]$min_cas2_fin_double = $min_cas2_fin

                        if($max_cas2_fin_double -eq 0){

                            $izracun2 = 0

                        }elseif($podatki2 -eq 0){

                            $izracun2 = 0
                            Write-Host 'Propustnost je 0 bit\s'

                        }else{
                            Write-Host "izracun2 = ($podatki2*8) / ("$max_cas2_fin_double" -" $min_cas2_fin_double" )"
                            $izracun2 = [math]::Round(($podatki2*8) / ($max_cas2_fin_double - $min_cas2_fin_double),2)

                        }
                            Write-Host "Propustnost je $izracun2 bit\s"
                        

                        }
                        ""
                    break
                    } 

                5{ 

                    Hrani
            
                    break
                    }
                

                6{
                    #brišemo vse tekstovne datoteke ustvarjene pri prejšnjih analizah

                    $izbrisi_txt1 = Get-ChildItem -Path F:\tshark -Include *.txt* -File -Recurse | ForEach-Object { $_.Delete()}
                    $izbrisi_txt1

                    $izbrisi_txt2 = Get-ChildItem -Path F:\tshark_temp -Include *.txt* -File -Recurse | ForEach-Object { $_.Delete()}
                    $izbrisi_txt2

                    for ($i = 1; $i -le 10; $i++) { 
                        write-progress -activity "Brisanje .txt datotek" -id 1 "Brišem $process_kill" -percentComplete ($i*10) 
                        sleep -m 100
                    }

                    Write-Progress -activity "Brisanje .txt datotek" -id 1 -Status "Ready" -Completed

                    #ponovno vnesemo ime datoteke

                    $datoteka=Preberi

                    break
                }


                7{
                    $switch_test = $false
                    break
                    }

         
                default{
            
                    if($izbira -lt '1' -or $izbira -gt '7'){
                    Write-Host 'Izbrane opcije ni na seznamu.'

                    }
                }
            }
        }while($switch_test -eq $true)
    }
    
    end{
    Write-Verbose 'Konec funkcija Izpis-Sw' -Verbose
    }
}

function Preberi{

 <#
            .SYNOPSIS 
            Ta funkcija omogoča izbiro datoteke, ki jo želimo analizirati.

            .DESCRIPTION
            Izbiramo lahko datoteko, ki jo želimo alizirati. V primeru, da datoteka ne obstaja nas
            skript o tem opozori.

            .PARAMETER
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
            [PS] C:\> . .\analiza_tcp_povezav3.ps1 ; get-help Preberi -full

            #>
    [CmdletBinding()]
    param()
    begin{Write-Verbose 'Začetek funkcije Preberi' -Verbose}
    process{
        #$test_naslovi=$false

        #zanko izvajamo tako dolgo, dokler ni vpisana datoteka, ki obstaja
        #dokler nima spremenljivka vrednost $test_naslovi $true
        Do{
            #preverjamo, če so v mapi F:\tshark datoteke, ki vsebujejo končnico .pcap oz. preverjamo datoteke, če so v mapi datoteke, ki smo jih zajeli
            #vse zaznane datoteke nato izpišemo s spremenljivko $izpis_imen

            Write-Host 'Zajete datoteke:'
            $izpis_imen = Get-ChildItem 'F:\tshark' -Filter *.pcap | Select-Object -expand Name
            Write-Host $izpis_imen

            #datoteko, ki jo želimo analizirati, shranimo v spremenljivko $datoteka
            $datoteka = Read-Host 'Vpišite ime datoteke, ki jo želite analizirati'
            Write-Host $datoteka

            #v primeru, da je vpisana datoteka, ki ne obstaja nas o tem skript obvesti
            if($datoteka -like '*.pcap*'){
        
                #testira se, če vpisana datoteka obstaja ali ne,,v primeru, da obstaja ima spremenljivka $vrednost_naslovi vrednost $true, kar pomeni izhod iz zanke

                Test-Path F:\tshark\$datoteka | ForEach-Object {if($_ -eq $true){$test_naslovi=$true}else{$test_naslovi=$false}}
                if($test_naslovi -eq $false){
                    Write-Host 'Datoteka ne obstaja!'
            }
            }else{
        
                Write-Host 'ni pcap datoteka'
                $test_naslovi = $false

            }
        }While($test_naslovi -eq $false)

    #funkcija vrne ime datoteke, ko vpišemo datoteko, ki obstaja
    return $datoteka

    }

    end{Write-Verbose 'Konec funkcije Preberi' -Verbose}


}

function Hrani{

 <#
            .SYNOPSIS 
            Funkcija prekopira, datoteke v primeru, da jih uporabnik želi shraniti na namizje.

            .DESCRIPTION
            Funkcija prekopira, datoteke v primeru, da jih uporabnik želi shraniti na namizje.
            Mapa se poimenuje s časom in datumum izvedbe te komande (takos e izognemo duplikatom)

            .PARAMETER
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
            [PS] C:\> . .\analiza_tcp_povezav3.ps1 ; get-help Hrani -full

            #>
    [CmdletBinding()]
    param()
    begin{Write-Verbose 'Začetek funkcije Hrani' -Verbose}
    process{

        #v spremenljivko $ime se shrani trenutna datum in ura

        $ime = (Get-Date).tostring('dd.MM.yyyy~hh_mm_ss')
        Write-Host '$ime'

        #ustvari se mapa, ki ima za ime trenuten datum in uro (spremenljivka $ime)
        New-Item -ItemType Directory -Path 'C:\Users\Uporabnik\Desktop' -Name $ime

        #skopiramo vsebino mape F:\tshark na namizja
        Copy-Item -Path F:\tshark\* -Destination C:\Users\Uporabnik\Desktop\$ime
        Write-Host "Datoteke so bile shranjene v mapo" $ime "na namizju."
        }

    end{Write-Verbose 'Konec funkcije Hrani' -Verbose}

}

