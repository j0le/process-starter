param(
    [string]$vcpkg_path
)

$local:ErrorActionPreference = 'Stop'


if(-not [string]::IsNullOrEmpty($vcpkg_path)){
    if(Test-Path -LiteralPath:$vcpkg_path -PathType:Container){
        $vcpkg_path = $vcpkg_path | Join-Path -ChildPath:'vcpkg.exe'
    }

    $vcpkg_cmd = Get-Command -Name:$vcpkg_path -ErrorAction:SilentlyContinue -CommandType:Application
    if ($null -eq $vcpkg_cmd){
        throw 'vcpkg could not be found under the specified path'
    }
}
else {
    $vcpkg_path = 'vcpkg.exe'

    $vcpkg_cmd = Get-Command -Name:$vcpkg_path -ErrorAction:SilentlyContinue -CommandType:Application
    if ($null -eq $vcpkg_cmd){
        throw 'vcpkg could not be found in path'
    }
}


$vcpkg_path = $vcpkg_cmd.Source
[string]$vcpkg_dir_path = (get-item -LiteralPath:$vcpkg_path | Select-Object -First:1 ).DirectoryName
[string]$vcpkg_msbuild_dir_path = Join-Path -Path:$vcpkg_dir_path `
    'scripts' 'buildsystems' 'msbuild'


[xml]$xml_doc = [xml]::new()

$xml_project = $xml_doc.CreateElement('Project')
$null = $xml_doc.AppendChild($xml_project)

$xml_import = $xml_doc.CreateElement('Import')

$xml_import_path = $xml_doc.CreateAttribute('Project')
$xml_import_path.Value = Join-Path -Path:$vcpkg_msbuild_dir_path 'vcpkg.props'

$null = $xml_import.SetAttributeNode($xml_import_path)
$null = $xml_project.AppendChild($xml_import)

$xml_doc.Save((Join-Path -Path:$PSScriptRoot 'vcpkg.props'))

$xml_import_path.Value = Join-Path -Path:$vcpkg_msbuild_dir_path 'vcpkg.targets'

$xml_doc.Save(($PSScriptRoot | Join-Path -ChildPath:'vcpkg.targets'))
