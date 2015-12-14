# powershell
créer un groupe au nom du service dans l'OU du service. Ensuite il rajoute l'utilisateur dans le groupe en fonction de son service.


Import-Module ActiveDirectory
$Groupes = Import-Csv -Path ".\User.csv" -Delimiter ";" | sort Service –Unique
New-ADOrganizationalUnit -Name "Utilisateurs" -Path "DC=tiennot,DC=lan"
foreach ($Groupe in $Groupes)
{
$service=$Groupe.Service
New-ADOrganizationalUnit -Name $service -Path "OU=Utilisateurs,DC=tiennot,DC=lan"
New-ADGroup "G_$service" -GroupScope Global -Path "OU=$service,OU=Utilisateurs,DC=tiennot,DC=LAN"
}
$utilisateurs = Import-Csv -Delimiter ";" -Path ".\User.csv"
foreach ($utilisateur in $utilisateurs)
{
$prenom=$utilisateur.prenom
$nom=$utilisateur.nom
$service=$utilisateur.Service
New-ADUser -name $prenom" "$nom -ChangePasswordAtLogon 1 -Path "OU=$service,OU=Utilisateurs,DC=tiennot,DC=LAN" -Description $service -DisplayName $prenom" "$nom -Enabled $true -GivenName $prenom -SamAccountName $prenom"."$nom -Surname $nom -UserPrincipalName $prenom"."$nom"@tiennot.lan" -AccountPassword (ConvertTo-SecureString "Romain3000" -AsPlainText -force)
Add-ADGroupMember -Identity "G_$service" -Member $prenom"."$nom
}
