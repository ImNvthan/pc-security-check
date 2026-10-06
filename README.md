# pc-security-check

Outils PowerShell pour verifier un PC Windows : services, taches planifiees, demarrage, processus, reseau, comptes, configuration de securite, journaux, extensions de navigateur et pilotes. Chaque constat est explique en francais et accompagne d'un lien VirusTotal.

Lecture seule : rien n'est modifie ni supprime.

## Utilisation

| Fichier | Role |
|---|---|
| `Lancer-Scan.bat` | Audit systeme seul (`Scan-PC.ps1`) |
| `Lancer-Verification-Complete.bat` | Defender + audit + Autoruns + synthese (`Verifier-PC.ps1`) |

Double-cliquez sur un `.bat` et acceptez l'elevation administrateur. Les rapports HTML sont crees dans `Rapports/`.

## VirusTotal (optionnel)

Creez un compte gratuit sur virustotal.com et placez votre cle API dans `vt_key.txt` a cote des scripts. Seules les empreintes SHA256 des fichiers douteux sont envoyees, jamais les fichiers (40 fichiers max par scan, quota gratuit de 4 requetes/min).

## Limites

Aucun outil ne garantit l'absence de malware. Un constat n'est pas une preuve d'infection : beaucoup de logiciels legitimes ne sont pas signes. Combinez avec l'analyse Defender hors ligne et un second avis (Malwarebytes).
