#requires -version 5
# yayuerti.ps1 build    rebuilds both DLLs from src\, audits them, writes YAYUERTI.klc and YAYUERTI.msi
# yayuerti.ps1 verify   asks Windows what the installed layout really produces, key by key
[CmdletBinding()] param([ValidateSet('build','verify')][string]$Do='build')
$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.Encoding]::UTF8
$ROOT=$PSScriptRoot; $N=0xF000
$UPGRADE='{7D4A1E0C-3B9F-4C2E-9A61-5E0F2B8C7D10}'    # never change: it is what lets a new build replace the old one

# ---- THE LAYOUT. One row per key: base, Shift, Ctrl, AltGr, AltGr+Shift. $N = no character. ----
$SPEC=@{
 0xC0=0x0454,0x0404,$N,0x0060,$N;  0x31=0x31,0x21,$N,$N,$N;         0x32=0x32,0x40,$N,$N,$N
 0x33=0x33,0x2116,$N,$N,0x23;      0x34=0x34,0x20B4,$N,$N,0x24;     0x35=0x35,0x25,$N,0x2116,$N
 0x36=0x36,0x5E,$N,$N,$N;          0x37=0x37,0x26,$N,$N,$N;         0x38=0x38,0x2A,$N,$N,$N
 0x39=0x39,0x28,$N,$N,0x5B;        0x30=0x30,0x29,$N,$N,0x5D;       0xBD=0x2D,0x2014,$N,$N,0x7B
 0xBB=0x3D,0x2B,$N,$N,0x7D;        0x51=0x044F,0x042F,$N,$N,$N;     0x57=0x044E,0x042E,$N,$N,$N
 0x45=0x0435,0x0415,$N,0x20AC,$N;  0x52=0x0440,0x0420,$N,$N,0x20BD; 0x54=0x0442,0x0422,$N,$N,$N
 0x59=0x0456,0x0406,$N,$N,$N;      0x55=0x0443,0x0423,$N,$N,$N;     0x49=0x0438,0x0418,$N,$N,$N
 0x4F=0x043E,0x041E,$N,$N,$N;      0x50=0x043F,0x041F,$N,$N,0x5F;   0xDB=0x0448,0x0428,$N,$N,0x3C
 0xDD=0x0449,0x0429,$N,$N,0x3E;    0xDC=0x0457,0x0407,$N,$N,0x5C;   0x41=0x0430,0x0410,$N,$N,0x042B
 0x53=0x0441,0x0421,$N,$N,0x0401;  0x44=0x0434,0x0414,$N,$N,0x042D; 0x46=0x0444,0x0424,$N,$N,0x042A
 0x47=0x0491,0x0490,$N,$N,$N;      0x48=0x0433,0x0413,$N,$N,$N;     0x4A=0x0439,0x0419,$N,$N,$N
 0x4B=0x043A,0x041A,$N,$N,$N;      0x4C=0x043B,0x041B,$N,$N,0x7C;   0xBA=0x0447,0x0427,$N,0x3B,0x201E
 0xDE=0x0436,0x0416,$N,0x3A,0x201C;0x5A=0x0437,0x0417,$N,$N,0x044B; 0x58=0x0445,0x0425,$N,$N,0x0451
 0x43=0x0446,0x0426,$N,$N,0x044D;  0x56=0x0432,0x0412,$N,$N,0x044A; 0x42=0x0431,0x0411,$N,$N,$N
 0x4E=0x043D,0x041D,$N,$N,$N;      0x4D=0x043C,0x041C,$N,$N,0x22;   0xBC=0x2C,0xAB,$N,$N,0x3B
 0xBE=0x2E,0xBB,$N,$N,0x3A;        0xBF=0x27,0x3F,$N,$N,0x2F;       0x20=0x20,0x044C,0x20,$N,0x042C
 0xE2=0x5C,0x7C,$N,$N,$N;          0x6E=0x2C,0x2C,$N,$N,$N
}
$VKNAME=@{0xBA='OEM_1';0xBB='OEM_PLUS';0xBC='OEM_COMMA';0xBD='OEM_MINUS';0xBE='OEM_PERIOD';0xBF='OEM_2';0xC0='OEM_3'
          0xDB='OEM_4';0xDC='OEM_5';0xDD='OEM_6';0xDE='OEM_7';0x20='SPACE';0x6E='DECIMAL';0xE2='OEM_102'}
function KeyName($vk){ if($VKNAME[$vk]){$VKNAME[$vk]}else{[string][char]$vk} }

# ---- PE plumbing shared by everything below. Layout DLLs use 8-byte field slots on both x64 and x86. ----
function Open-Pe([byte[]]$b){
  $e=[BitConverter]::ToInt32($b,0x3C); $opt=$e+24; $is64=[BitConverter]::ToUInt16($b,$opt) -eq 0x20B
  $p=@{b=$b;opt=$opt;is64=$is64;sec=@()}
  if($is64){$p.base=[BitConverter]::ToUInt64($b,$opt+24);$p.dd=$opt+112}else{$p.base=[uint64][BitConverter]::ToUInt32($b,$opt+28);$p.dd=$opt+96}
  $so=$e+24+[BitConverter]::ToUInt16($b,$e+20)
  for($i=0;$i -lt [BitConverter]::ToUInt16($b,$e+6);$i++){ $o=$so+$i*40
    $p.sec+=@{Name=[Text.Encoding]::ASCII.GetString($b,$o,8).TrimEnd([char]0);VSize=[BitConverter]::ToUInt32($b,$o+8);VA=[BitConverter]::ToUInt32($b,$o+12);RawSize=[BitConverter]::ToUInt32($b,$o+16);RawPtr=[BitConverter]::ToUInt32($b,$o+20);Hdr=$o} }
  $p }
function F($p,[int64]$rva){ foreach($s in $p.sec){ if($rva -ge $s.VA -and $rva -lt ($s.VA+[Math]::Max($s.VSize,$s.RawSize))){ return [int]($s.RawPtr+$rva-$s.VA) } } throw ("RVA 0x{0:X} unmapped" -f $rva) }
function Ptr($p,[int64]$rva){ $f=F $p $rva; $v=if($p.is64){[BitConverter]::ToUInt64($p.b,$f)}else{[uint64][BitConverter]::ToUInt32($p.b,$f)}; if($v){[int64]($v-$p.base)}else{-1} }
function SetPtr($p,[int64]$rva,[int64]$to){ $f=F $p $rva; $w=if($p.is64){[BitConverter]::GetBytes([uint64]($p.base+$to))}else{[BitConverter]::GetBytes([uint32]($p.base+$to))}; [Array]::Copy($w,0,$p.b,$f,$w.Length) }
function Tables($p){                                   # -> @{root;pMod;mn;wMax;t=@(entries)}
  $ex=F $p ([BitConverter]::ToUInt32($p.b,$p.dd)); $names=[BitConverter]::ToUInt32($p.b,$ex+32); $ords=[BitConverter]::ToUInt32($p.b,$ex+36); $addrs=[BitConverter]::ToUInt32($p.b,$ex+28)
  $stub=-1; for($i=0;$i -lt [BitConverter]::ToUInt32($p.b,$ex+24);$i++){ $q=F $p ([BitConverter]::ToUInt32($p.b,(F $p ($names+$i*4)))); $s=''; while($p.b[$q]){$s+=[char]$p.b[$q];$q++}
    if($s -eq 'KbdLayerDescriptor'){ $stub=[BitConverter]::ToUInt32($p.b,(F $p ($addrs+4*[BitConverter]::ToUInt16($p.b,(F $p ($ords+$i*2)))))) } }
  $sf=F $p $stub; $root=if($p.b[$sf] -eq 0x48){$stub+7+[BitConverter]::ToInt32($p.b,$sf+3)}else{[BitConverter]::ToUInt32($p.b,$sf+1)-$p.base}
  $pMod=Ptr $p $root; $pVk=Ptr $p ($root+8); $wMax=[BitConverter]::ToUInt16($p.b,(F $p ($pMod+8)))
  $t=@(); for($i=0;;$i++){ $ent=$pVk+$i*16; $rows=Ptr $p $ent; if($rows -lt 0){break}
    $nMod=$p.b[(F $p ($ent+8))]; $cb=$p.b[(F $p ($ent+9))]; $list=@(); $r=0
    while($p.b[(F $p ($rows+$r*$cb))]){ $o=F $p ($rows+$r*$cb); $w=@(); for($c=0;$c -lt $nMod;$c++){$w+=[int][BitConverter]::ToUInt16($p.b,$o+2+$c*2)}
      $list+=@{vk=[int]$p.b[$o];attr=[int]$p.b[$o+1];w=$w}; $r++ }
    $t+=@{ent=$ent;rows=$rows;nMod=[int]$nMod;cb=[int]$cb;cap=($r+1)*$cb;list=$list} }
  @{root=$root;pMod=$pMod;mn=$pMod+10;wMax=$wMax;t=$t} }
function Scancodes($p,$tb){ $vsc=Ptr $p ($tb.root+48); $m=@{}; for($s=0;$s -lt $p.b[(F $p ($tb.root+56))];$s++){ $vk=[BitConverter]::ToUInt16($p.b,(F $p ($vsc+$s*2))) -band 0xFF; if($vk -and $vk -ne 0xFF -and -not $m[$vk]){$m[$vk]=$s} }; $m }

# ---- build one DLL: rewrite the character tables from $SPEC, rename, checksum ----
function Build-Dll($src,$dst,$dllName){
  $p=Open-Pe ([IO.File]::ReadAllBytes($src)); $d=$p.sec|?{$_.Name -eq '.data'}
  if($d.RawSize -lt 0x1000){                                     # x86 file: pad .data out to its page so the tail is file-backed
    $delta=0x1000-$d.RawSize; $at=$d.RawPtr+$d.RawSize; $nb=New-Object byte[] ($p.b.Length+$delta)
    [Array]::Copy($p.b,0,$nb,0,$at); [Array]::Copy($p.b,$at,$nb,$at+$delta,$p.b.Length-$at); $p.b=$nb
    [Array]::Copy([BitConverter]::GetBytes([uint32]0x1000),0,$p.b,$d.Hdr+16,4); $d.RawSize=0x1000
    foreach($s in $p.sec){ if($s.RawPtr -ge $at){ $s.RawPtr+=$delta; [Array]::Copy([BitConverter]::GetBytes([uint32]$s.RawPtr),0,$p.b,$s.Hdr+20,4) } } }
  $tb=Tables $p; $wide=@();$four=@();$two=@();$pass=@()
  foreach($t in $tb.t[1..3]){ foreach($r in $t.list){ if(-not $SPEC.Contains([int]$r.vk)){ $pass+=@{vk=$r.vk;attr=$r.attr;w=@($r.w[0],$(if($r.w.Count -gt 1){$r.w[1]}else{$N}))} } } }  # keys we do not define pass through: tab, numpad
  foreach($vk in $SPEC.Keys){ $w=$SPEC[$vk]; $attr=if($w[0] -ge 0x400 -and $w[0] -le 0x4FF){1}else{0}                                           # Cyrillic base = Caps Lock applies
    if($w[4] -ne $N){$wide+=@{vk=$vk;attr=$attr;w=$w}} elseif($w[2] -ne $N -or $w[3] -ne $N){$four+=@{vk=$vk;attr=$attr;w=$w[0..3]}} else {$two+=@{vk=$vk;attr=$attr;w=$w[0..1]}} }
  $two+=$pass                                                                                                                                       # spec keys first so VkKeyScan prefers the main row over the numpad
  function Emit($rva,$cb,$rows){ $f=F $p $rva; foreach($r in $rows){ $p.b[$f]=[byte]$r.vk; $p.b[$f+1]=[byte]$r.attr; for($c=0;$c -lt ($cb-2)/2;$c++){[Array]::Copy([BitConverter]::GetBytes([uint16]$r.w[$c]),0,$p.b,$f+2+$c*2,2)}; $f+=$cb }; for($i=0;$i -lt $cb;$i++){$p.b[$f+$i]=0} }
  $main=$tb.t[1]; $tail=[int64](($d.VA+$d.VSize+15) -band -16); $limit=$d.VA+$d.RawSize
  $twoAt=$main.rows; $fourAt=[int64](($twoAt+($two.Count+1)*6+15) -band -16); $wideAt=$tail
  if(($fourAt+($four.Count+1)*10) -gt ($main.rows+$main.cap)){throw 'main slot overflow'}; if(($wideAt+($wide.Count+1)*12) -gt $limit){throw 'tail overflow'}
  foreach($t in $tb.t[1..3]){ $f=F $p $t.rows; for($i=0;$i -lt $t.cap;$i++){$p.b[$f+$i]=0} }
  Emit $twoAt 6 $two;  SetPtr $p $tb.t[2].ent $twoAt;  $p.b[(F $p ($tb.t[2].ent+8))]=2; $p.b[(F $p ($tb.t[2].ent+9))]=6
  Emit $fourAt 10 $four; SetPtr $p $tb.t[1].ent $fourAt; $p.b[(F $p ($tb.t[1].ent+8))]=4; $p.b[(F $p ($tb.t[1].ent+9))]=10
  Emit $wideAt 12 $wide; SetPtr $p $tb.t[3].ent $wideAt; $p.b[(F $p ($tb.t[3].ent+8))]=5; $p.b[(F $p ($tb.t[3].ent+9))]=12
  $mods=@(0,1,2,15,15,15,3,4); [Array]::Copy([BitConverter]::GetBytes([uint16]7),0,$p.b,(F $p ($tb.pMod+8)),2); for($i=0;$i -lt 8;$i++){$p.b[(F $p ($tb.mn+$i))]=[byte]$mods[$i]}   # bit combo 7 = AltGr+Shift -> column 4
  $vs=[uint32]($wideAt+($wide.Count+1)*12-$d.VA); [Array]::Copy([BitConverter]::GetBytes($vs),0,$p.b,$d.Hdr+8,4)
  $rs=$p.sec|?{$_.Name -eq '.rsrc'}; foreach($pair in @(@('Russian Phonetic YaWert - WinRus.com','YAYUERTI'),@('Russian (Russia)','Ukrainian'))){   # shrink the length-prefixed UTF-16 name strings in place
    $pat=[Text.Encoding]::Unicode.GetBytes($pair[0]); for($i=$rs.RawPtr;$i -lt $rs.RawPtr+$rs.RawSize-$pat.Length;$i++){ $ok=$true; for($j=0;$j -lt $pat.Length;$j++){if($p.b[$i+$j] -ne $pat[$j]){$ok=$false;break}}
      if($ok -and [BitConverter]::ToUInt16($p.b,$i-2) -eq $pair[0].Length){ $nb=[Text.Encoding]::Unicode.GetBytes($pair[1]); [Array]::Copy([BitConverter]::GetBytes([uint16]$pair[1].Length),0,$p.b,$i-2,2); [Array]::Copy($nb,0,$p.b,$i,$nb.Length); for($j=$nb.Length;$j -lt $pat.Length;$j++){$p.b[$i+$j]=0}; break } } }
  [IO.File]::WriteAllBytes($dst,$p.b)
  $o=0;$n=0; if([IH]::MapFileAndCheckSumW($dst,[ref]$o,[ref]$n)){throw 'checksum'}; [Array]::Copy([BitConverter]::GetBytes([uint32]$n),0,$p.b,$p.opt+64,4); [IO.File]::WriteAllBytes($dst,$p.b)
  $p }
if(-not ('IH' -as [type])){ Add-Type @"
using System.Runtime.InteropServices; public static class IH { [DllImport("imagehlp.dll",CharSet=CharSet.Unicode)] public static extern uint MapFileAndCheckSumW(string f,out uint o,out uint n); }
"@ }

# ---- audit a built DLL against $SPEC, every key, every column ----
function Audit($dll){ $p=Open-Pe ([IO.File]::ReadAllBytes($dll)); $tb=Tables $p; $got=@{}; foreach($t in $tb.t){ foreach($r in $t.list){ $w=@($r.w)+@($N)*(5-$r.w.Count); $got[$r.vk]=$w } }
  $mn=@(); for($i=0;$i -le $tb.wMax;$i++){$mn+=$p.b[(F $p ($tb.mn+$i))]}
  $bad=@(); if($tb.wMax -ne 7 -or $mn[7] -ne 4 -or $mn[3] -ne 15){$bad+='modifier table'}
  foreach($vk in $SPEC.Keys){ if(-not $got[$vk]){$bad+=('missing '+(KeyName $vk));continue}; for($c=0;$c -lt 5;$c++){ if($got[$vk][$c] -ne $SPEC[$vk][$c]){$bad+=('{0} col{1}' -f (KeyName $vk),$c)} } }
  if($bad){ throw ("AUDIT FAILED {0}: {1}" -f (Split-Path $dll -Leaf),($bad -join ', ')) }; "  audit {0}: {1} keys correct" -f (Split-Path $dll -Leaf),$SPEC.Count }

# ---- write the layout as a Microsoft Keyboard Layout Creator source file ----
function Write-Klc($p,$path){ $sc=Scancodes $p (Tables $p); $sc[0x6E]=0x53                      # numpad decimal is NumLock-derived, absent from the raw table
  foreach($vk in $SPEC.Keys){ if(-not $sc.ContainsKey($vk)){ throw ('no scancode for key 0x{0:X2}' -f $vk) } }
  $L=@("KBD`tkbdyay`t`"YAYUERTI`"","","COPYRIGHT`t`"(c) 2026`"","","COMPANY`t`"`"","","LOCALENAME`t`"uk-UA`"","","LOCALEID`t`"00000422`"","","VERSION`t1.0","","SHIFTSTATE","","0`t;base","1`t;Shift","2`t;Ctrl","6`t;AltGr","7`t;AltGr+Shift","","LAYOUT","",";SC`tVK_`t`tCap`t0`t1`t2`t6`t7")
  foreach($vk in ($SPEC.Keys|sort {$sc[$_]})){ $w=$SPEC[$vk]; $cap=if($w[0] -ge 0x400 -and $w[0] -le 0x4FF){1}else{0}
    $L+=("{0:x2}`t{1}`t`t{2}`t{3}" -f $sc[$vk],(KeyName $vk),$cap,(($w|%{ if($_ -eq $N){'-1'}else{'{0:x4}' -f $_} }) -join "`t")) }
  $L+=@("","DESCRIPTIONS","","0409`tYAYUERTI","","LANGUAGENAMES","","0409`tUkrainian (Ukraine)","","ENDKBD")
  [IO.File]::WriteAllText($path,($L -join "`r`n")+"`r`n",[Text.Encoding]::Unicode) }

# ---- package as an MSI using only the Windows Installer engine that ships with Windows ----
function Build-Msi($ver,$klid,$layoutId,$dllName,$dll64,$dll32,$msi){
  $tmp=Join-Path $env:TEMP ("yayuerti-"+[guid]::NewGuid().ToString('N')); New-Item -ItemType Directory $tmp|Out-Null
  Copy-Item $dll64 "$tmp\kbd64.dll"; Copy-Item $dll32 "$tmp\kbd32.dll"
  @(".OPTION EXPLICIT",".Set CabinetNameTemplate=cab.cab",".Set DiskDirectoryTemplate=$tmp",".Set Cabinet=ON",".Set Compress=ON",".Set CompressionType=LZX",".Set MaxDiskSize=0",".Set RptFileName=nul",".Set InfFileName=nul","`"$tmp\kbd64.dll`" kbd64.dll","`"$tmp\kbd32.dll`" kbd32.dll") | Set-Content "$tmp\cab.ddf" -Encoding ASCII
  & "$env:SystemRoot\System32\makecab.exe" /F "$tmp\cab.ddf" | Out-Null; if(-not (Test-Path "$tmp\cab.cab")){throw 'makecab failed'}
  $ps=@{}   # the three helpers the MSI runs, each as an encoded PowerShell command launched from a tiny embedded VBScript
  $ps.sweep=@"
`$r='HKLM:\SYSTEM\CurrentControlSet\Control\Keyboard Layouts'
Get-ChildItem `$r|Where-Object{`$_.PSChildName -ne '$klid' -and (Get-ItemProperty `$_.PSPath -ErrorAction SilentlyContinue).'Layout Text' -like 'YAYUERTI*'}|Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
foreach(`$d in @("`$env:SystemRoot\System32","`$env:SystemRoot\SysWOW64")){ Get-ChildItem "`$d\kbd*.dll" -ErrorAction SilentlyContinue|Where-Object{`$_.Name -ne '$dllName' -and `$_.Name -match '^(kbdya[0-9a-f]{2,3}|kbduk_y)\.dll$'}|Remove-Item -Force -ErrorAction SilentlyContinue }
"@
  $ps.attach=@"
`$k='0422:$($klid.ToUpper())'; `$l=Get-WinUserLanguageList
foreach(`$x in `$l){ foreach(`$t in @(`$x.InputMethodTips)){ if(`$t -match '^0422:[Aa]'){ `$x.InputMethodTips.Remove(`$t)|Out-Null } } }
`$u=`$l|Where-Object{`$_.LanguageTag -like 'uk*'}|Select-Object -First 1
if(-not `$u){ `$l.Add('uk'); `$u=`$l|Where-Object{`$_.LanguageTag -like 'uk*'}|Select-Object -First 1 }
foreach(`$t in @(`$u.InputMethodTips)){ if(`$t -ne `$k){ `$u.InputMethodTips.Remove(`$t)|Out-Null } }
if(`$u.InputMethodTips -notcontains `$k){ `$u.InputMethodTips.Add(`$k) }
Set-WinUserLanguageList `$l -Force
"@
  $ps.detach=@"
`$l=Get-WinUserLanguageList
foreach(`$x in `$l){ foreach(`$t in @(`$x.InputMethodTips)){ if(`$t -match '^0422:[Aa]'){ `$x.InputMethodTips.Remove(`$t)|Out-Null } } }
Set-WinUserLanguageList `$l -Force
"@
  foreach($k in $ps.Keys){ $b64=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ps[$k]))
    "Set s=CreateObject(`"WScript.Shell`"):s.Run `"`"`"`" & s.ExpandEnvironmentStrings(`"%SystemRoot%`") & `"\System32\WindowsPowerShell\v1.0\powershell.exe`"`" -NonInteractive -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -EncodedCommand $b64`",0,True" | Set-Content "$tmp\$k.vbs" -Encoding ASCII }
  Remove-Item $msi -Force -ErrorAction SilentlyContinue; $inst=New-Object -ComObject WindowsInstaller.Installer; $db=$inst.OpenDatabase($msi,3)
  function Q($sql){ $v=$db.OpenView($sql); $v.Execute(); $v.Close() }
  function SetP($o,$name,$i,$val){ [void]$o.GetType().InvokeMember($name,[Reflection.BindingFlags]::SetProperty,$null,$o,@($i,$val)) }   # COM parameterized property
  function Row($table,$cols,$vals){ $cl=($cols|%{'`'+$_+'`'}) -join ','; $qs=(@('?')*$vals.Count) -join ','; $v=$db.OpenView("INSERT INTO ``$table`` ($cl) VALUES ($qs)"); $r=$inst.CreateRecord($vals.Count)
    for($i=0;$i -lt $vals.Count;$i++){ $x=$vals[$i]; if($x -is [int]){SetP $r 'IntegerData' ($i+1) $x}elseif($x -is [IO.FileInfo]){$r.SetStream($i+1,$x.FullName)}elseif($null -ne $x){SetP $r 'StringData' ($i+1) ([string]$x)} }; $v.Execute($r); $v.Close() }
  Q "CREATE TABLE ``Property`` (``Property`` CHAR(72) NOT NULL, ``Value`` CHAR(0) NOT NULL PRIMARY KEY ``Property``)"
  Q "CREATE TABLE ``Directory`` (``Directory`` CHAR(72) NOT NULL, ``Directory_Parent`` CHAR(72), ``DefaultDir`` CHAR(255) NOT NULL PRIMARY KEY ``Directory``)"
  Q "CREATE TABLE ``Component`` (``Component`` CHAR(72) NOT NULL, ``ComponentId`` CHAR(38), ``Directory_`` CHAR(72) NOT NULL, ``Attributes`` SHORT NOT NULL, ``Condition`` CHAR(255), ``KeyPath`` CHAR(72) PRIMARY KEY ``Component``)"
  Q "CREATE TABLE ``Feature`` (``Feature`` CHAR(38) NOT NULL, ``Feature_Parent`` CHAR(38), ``Title`` CHAR(64), ``Description`` CHAR(255), ``Display`` SHORT, ``Level`` SHORT NOT NULL, ``Directory_`` CHAR(72), ``Attributes`` SHORT NOT NULL PRIMARY KEY ``Feature``)"
  Q "CREATE TABLE ``FeatureComponents`` (``Feature_`` CHAR(38) NOT NULL, ``Component_`` CHAR(72) NOT NULL PRIMARY KEY ``Feature_``, ``Component_``)"
  Q "CREATE TABLE ``File`` (``File`` CHAR(72) NOT NULL, ``Component_`` CHAR(72) NOT NULL, ``FileName`` CHAR(255) NOT NULL, ``FileSize`` LONG NOT NULL, ``Version`` CHAR(72), ``Language`` CHAR(20), ``Attributes`` SHORT, ``Sequence`` SHORT NOT NULL PRIMARY KEY ``File``)"
  Q "CREATE TABLE ``Media`` (``DiskId`` SHORT NOT NULL, ``LastSequence`` SHORT NOT NULL, ``DiskPrompt`` CHAR(64), ``Cabinet`` CHAR(255), ``VolumeLabel`` CHAR(32), ``Source`` CHAR(72) PRIMARY KEY ``DiskId``)"
  Q "CREATE TABLE ``Registry`` (``Registry`` CHAR(72) NOT NULL, ``Root`` SHORT NOT NULL, ``Key`` CHAR(255) NOT NULL, ``Name`` CHAR(255), ``Value`` CHAR(0), ``Component_`` CHAR(72) NOT NULL PRIMARY KEY ``Registry``)"
  Q "CREATE TABLE ``Upgrade`` (``UpgradeCode`` CHAR(38) NOT NULL, ``VersionMin`` CHAR(20), ``VersionMax`` CHAR(20), ``Language`` CHAR(255), ``Attributes`` LONG NOT NULL, ``Remove`` CHAR(255), ``ActionProperty`` CHAR(72) NOT NULL PRIMARY KEY ``UpgradeCode``, ``VersionMin``, ``VersionMax``, ``Language``, ``Attributes``)"
  Q "CREATE TABLE ``CustomAction`` (``Action`` CHAR(72) NOT NULL, ``Type`` SHORT NOT NULL, ``Source`` CHAR(72), ``Target`` CHAR(255), ``ExtendedType`` LONG PRIMARY KEY ``Action``)"
  Q "CREATE TABLE ``Binary`` (``Name`` CHAR(72) NOT NULL, ``Data`` OBJECT NOT NULL PRIMARY KEY ``Name``)"
  Q "CREATE TABLE ``InstallExecuteSequence`` (``Action`` CHAR(72) NOT NULL, ``Condition`` CHAR(255), ``Sequence`` SHORT PRIMARY KEY ``Action``)"
  Q "CREATE TABLE ``InstallUISequence`` (``Action`` CHAR(72) NOT NULL, ``Condition`` CHAR(255), ``Sequence`` SHORT PRIMARY KEY ``Action``)"
  $pc=[guid]::NewGuid().ToString('B').ToUpper()
  foreach($kv in @(@('ProductCode',$pc),@('UpgradeCode',$UPGRADE),@('ProductName','YAYUERTI keyboard layout'),@('ProductVersion',"1.0.$ver"),@('ProductLanguage','1033'),@('Manufacturer','YAYUERTI'),@('ALLUSERS','1'),@('ARPNOMODIFY','1'),@('ARPNOREPAIR','1'),@('SecureCustomProperties','PREVIOUSVERSIONSINSTALLED'))){ Row Property @('Property','Value') $kv }
  Row Directory @('Directory','Directory_Parent','DefaultDir') @('TARGETDIR',$null,'SourceDir')
  Row Directory @('Directory','Directory_Parent','DefaultDir') @('System64Folder','TARGETDIR','.')
  Row Directory @('Directory','Directory_Parent','DefaultDir') @('SystemFolder','TARGETDIR','.')
  Row Component @('Component','ComponentId','Directory_','Attributes','Condition','KeyPath') @('C64',[guid]::NewGuid().ToString('B').ToUpper(),'System64Folder',256,$null,'kbd64.dll')
  Row Component @('Component','ComponentId','Directory_','Attributes','Condition','KeyPath') @('C32',[guid]::NewGuid().ToString('B').ToUpper(),'SystemFolder',0,$null,'kbd32.dll')
  Row Component @('Component','ComponentId','Directory_','Attributes','Condition','KeyPath') @('CReg',[guid]::NewGuid().ToString('B').ToUpper(),'System64Folder',260,$null,'R1')
  Row Feature @('Feature','Feature_Parent','Title','Description','Display','Level','Directory_','Attributes') @('Main',$null,'YAYUERTI',$null,1,1,$null,0)
  foreach($c in 'C64','C32','CReg'){ Row FeatureComponents @('Feature_','Component_') @('Main',$c) }
  Row File @('File','Component_','FileName','FileSize','Version','Language','Attributes','Sequence') @('kbd64.dll','C64',$dllName,[int](Get-Item $dll64).Length,$null,$null,512,1)
  Row File @('File','Component_','FileName','FileSize','Version','Language','Attributes','Sequence') @('kbd32.dll','C32',$dllName,[int](Get-Item $dll32).Length,$null,$null,512,2)
  Row Media @('DiskId','LastSequence','DiskPrompt','Cabinet','VolumeLabel','Source') @(1,2,$null,'#cab.cab',$null,$null)
  $key="SYSTEM\CurrentControlSet\Control\Keyboard Layouts\$klid"; $i=0
  foreach($kv in @(@('Layout Text','YAYUERTI'),@('Layout File',$dllName),@('Layout Id',$layoutId),@('Layout Product Code',$UPGRADE),@('Custom Language Name','Ukrainian (Ukraine)'))){ $i++; Row Registry @('Registry','Root','Key','Name','Value','Component_') @("R$i",2,$key,$kv[0],$kv[1],'CReg') }
  Row Upgrade @('UpgradeCode','VersionMin','VersionMax','Language','Attributes','Remove','ActionProperty') @($UPGRADE,'0.0.0',$null,$null,256,$null,'PREVIOUSVERSIONSINSTALLED')
  foreach($k in 'sweep','attach','detach'){ Row Binary @('Name','Data') @($k,(Get-Item "$tmp\$k.vbs")) }
  Row CustomAction @('Action','Type','Source','Target','ExtendedType') @('Sweep', 3142,'sweep',$null,$null)     # VBScript from Binary, deferred, as SYSTEM, ignore failure
  Row CustomAction @('Action','Type','Source','Target','ExtendedType') @('Attach',1094,'attach',$null,$null)    # VBScript from Binary, deferred, as the user, ignore failure
  Row CustomAction @('Action','Type','Source','Target','ExtendedType') @('Detach',1094,'detach',$null,$null)
  foreach($a in @(@('FindRelatedProducts',$null,200),@('ValidateProductID',$null,700),@('CostInitialize',$null,800),@('FileCost',$null,900),@('CostFinalize',$null,1000),@('InstallValidate',$null,1400),@('InstallInitialize',$null,1500),@('RemoveExistingProducts',$null,1520),@('ProcessComponents',$null,1600),@('UnpublishFeatures',$null,1800),@('Detach','REMOVE~="ALL"',2550),@('RemoveRegistryValues',$null,2600),@('RemoveFiles',$null,3500),@('InstallFiles',$null,4000),@('WriteRegistryValues',$null,5000),@('Sweep','NOT REMOVE~="ALL"',5050),@('Attach','NOT REMOVE~="ALL"',5100),@('RegisterUser',$null,6000),@('RegisterProduct',$null,6100),@('PublishFeatures',$null,6300),@('PublishProduct',$null,6400),@('InstallFinalize',$null,6600))){ Row InstallExecuteSequence @('Action','Condition','Sequence') $a }
  foreach($a in @(@('FindRelatedProducts',$null,200),@('CostInitialize',$null,800),@('FileCost',$null,900),@('CostFinalize',$null,1000),@('ExecuteAction',$null,1300))){ Row InstallUISequence @('Action','Condition','Sequence') $a }
  $v=$db.OpenView("INSERT INTO ``_Streams`` (``Name``,``Data``) VALUES (?,?)"); $r=$inst.CreateRecord(2); SetP $r 'StringData' 1 'cab.cab'; $r.SetStream(2,"$tmp\cab.cab"); $v.Execute($r); $v.Close()
  $si=$db.SummaryInformation(20); foreach($kv in @(@(1,1252),@(2,'YAYUERTI'),@(3,'YAYUERTI keyboard layout'),@(4,'YAYUERTI'),@(7,'x64;1033'),@(9,[guid]::NewGuid().ToString('B').ToUpper()),@(14,500),@(15,2))){ SetP $si 'Property' $kv[0] $kv[1] }; $si.Persist()
  $db.Commit(); foreach($o in $db,$inst){ [Runtime.InteropServices.Marshal]::ReleaseComObject($o)|Out-Null }; [GC]::Collect(); [GC]::WaitForPendingFinalizers(); Remove-Item $tmp -Recurse -Force }   # close the compound file so the size reported below is final

# ---- verify: what does Windows actually produce for the installed layout? ----
function Verify(){
  $root='HKLM:\SYSTEM\CurrentControlSet\Control\Keyboard Layouts'
  $reg=@(Get-ChildItem $root|%{ $q=Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue; if($q.'Layout Text' -eq 'YAYUERTI'){ @{klid=$_.PSChildName;file=$q.'Layout File'} } })
  if(-not $reg){ throw 'YAYUERTI is not registered. Install YAYUERTI.msi.' }; $k=$reg[0]
  "registered as $($k.klid) -> $($k.file)"+$(if($reg.Count -gt 1){"  (WARNING: $($reg.Count) entries)"})
  $tips=(Get-WinUserLanguageList|?{$_.LanguageTag -like 'uk*'}).InputMethodTips; "language list: $(if($tips -contains ('0422:'+$k.klid.ToUpper())){'attached'}else{'NOT attached, add it in Settings or reinstall'})"
  if(-not ('KB' -as [type])){ Add-Type @"
using System; using System.Runtime.InteropServices; public static class KB {
 [DllImport("user32",CharSet=CharSet.Unicode)] public static extern IntPtr LoadKeyboardLayoutW(string k,uint f);
 [DllImport("user32")] public static extern int ToUnicodeEx(uint vk,uint sc,byte[] ks,IntPtr buf,int cch,uint fl,IntPtr hkl);
 [DllImport("user32")] public static extern uint MapVirtualKeyExW(uint c,uint t,IntPtr hkl); }
"@ }
  $hkl=[KB]::LoadKeyboardLayoutW($k.klid.ToUpper(),0x80); $buf=[Runtime.InteropServices.Marshal]::AllocHGlobal(64); $bad=0;$ok=0
  $mods=@(@(),@(0x10,0xA0),$null,@(0x11,0xA2,0x12,0xA5),@(0x10,0xA0,0x11,0xA2,0x12,0xA5)); $lbl='','Shift','Ctrl','AltGr','AltGr+Shift'
  foreach($vk in $SPEC.Keys){ for($c=0;$c -lt 5;$c++){ if($c -eq 2 -or $SPEC[$vk][$c] -eq $N){continue}
    $ks=New-Object byte[] 256; foreach($m in $mods[$c]){$ks[$m]=0x80}; for($i=0;$i -lt 64;$i++){[Runtime.InteropServices.Marshal]::WriteByte($buf,$i,0)}
    $r=[KB]::ToUnicodeEx([uint32]$vk,[KB]::MapVirtualKeyExW([uint32]$vk,0,$hkl),$ks,$buf,16,0,$hkl); $got=if($r -gt 0){[Runtime.InteropServices.Marshal]::PtrToStringUni($buf,$r)}else{''}
    if($got -eq [string][char]$SPEC[$vk][$c]){$ok++}else{$bad++; "  WRONG {0,-11} {1,-8} got '{2}' wanted '{3}'" -f (KeyName $vk),$lbl[$c],$got,[char]$SPEC[$vk][$c]} } }
  [Runtime.InteropServices.Marshal]::FreeHGlobal($buf)
  if($bad){ "LIVE LAYOUT WRONG: $bad of $($ok+$bad) checks failed. Reinstall YAYUERTI.msi; if it persists, sign out and back in." } else { "LIVE LAYOUT CORRECT: all $ok defined characters verified against Windows" } }

# ---- entry point ----
if($Do -eq 'verify'){ Verify; exit }
$vf="$ROOT\version.txt"; $ver=if(Test-Path $vf){[int](Get-Content $vf)+1}else{6}; Set-Content $vf $ver
$klid='a0{0:x2}0422' -f $ver; $layoutId='{0:x4}' -f (0xC0+$ver); $dllName='kbdya{0:x2}.dll' -f $ver
"build ${ver}: layout id $klid, file $dllName"
$out="$ROOT\out"; New-Item -ItemType Directory -Force $out|Out-Null
$p64=Build-Dll "$ROOT\src\kbdru_y64.dll" "$out\$dllName" $dllName; $null=Build-Dll "$ROOT\src\kbdru_y32.dll" "$out\wow64_$dllName" $dllName
Audit "$out\$dllName"; Audit "$out\wow64_$dllName"
Write-Klc $p64 "$ROOT\YAYUERTI.klc"
Build-Msi $ver $klid $layoutId $dllName "$out\$dllName" "$out\wow64_$dllName" "$ROOT\YAYUERTI.msi"
"wrote YAYUERTI.msi ({0:N0} bytes) and YAYUERTI.klc" -f (Get-Item "$ROOT\YAYUERTI.msi").Length
