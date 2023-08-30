# Removes some indicators and builds Rubeus
# Note that no assemblyname/namespace might be almost as suspicious

$old_guid = '658C8B7F-3664-4A95-9572-A3E5871DFC06'
$new_guid = (New-Guid).ToString()

[string[]] $filetypes = "*.cs", "*.sln", "*.csproj"

ForEach ($filetype in $filetypes) {
    $files = Get-ChildItem -Path $filetype -Recurse -File
    ForEach ($file in $files) {
        $content = Get-Content $file
        $content = $content -Replace "$old_guid", "$new_guid"
        $content | Set-Content $file
    }
}

$csproj = Get-ChildItem Rubeus\Rubeus.csproj
$csprojxml = [xml] (Get-Content $csproj.FullName)
$csprojxml.Project.PropertyGroup[0].RootNamespace = ''
$csprojxml.Project.PropertyGroup[0].AssemblyName = ''
$csprojxml.Save($csproj.FullName)

msbuild .\Rubeus.sln -t:Clean
msbuild .\Rubeus.sln /property:Configuration=Release /property:TargetFrameworkVersion=v4.8
