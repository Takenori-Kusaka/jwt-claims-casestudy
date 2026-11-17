param([string]$xlsx, [string]$pdf)
$ErrorActionPreference = 'Stop'
$xl = New-Object -ComObject Excel.Application
$xl.DisplayAlerts = $false
$wb = $xl.Workbooks.Open($xlsx, 0, $true)
"sheets: " + $wb.Worksheets.Count
$ws = $wb.Worksheets.Item('集計')
$ws.Calculate()
"A judgement counts: " + (($ws.Range('B4:B11').Value2 | ForEach-Object { $_ }) -join ',')
$main = $wb.Worksheets.Item('クレーム一覧')
$main.PageSetup.Orientation = 2
$main.Range('A1:AE40').ExportAsFixedFormat(0, $pdf)
$wb.Close($false); $xl.Quit()
