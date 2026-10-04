# Installer et tester Reverse Assistant sur Windows

Ce guide concerne la version alpha, principalement testée sur Windows x64.
Analyser un exécutable Linux ELF depuis Windows est possible : cela ne signifie
pas que l'installation de l'application sur Linux a été validée.

Le dépôt fournit les **sources de l'application**. Télécharger le ZIP ne fournit
ni un `.exe` prêt à lancer, ni les dépendances, ni le corpus BSim généré.
Le premier démarrage nécessite donc une compilation.

## 1. Installer les prérequis

Installer depuis les sites officiels, puis fermer et rouvrir le terminal.

| Logiciel | Utilité et installation |
| --- | --- |
| [Node.js](https://nodejs.org/en/download) | Installer une version LTS avec npm ; Node 22 ou 24 convient au projet. |
| [Visual Studio Build Tools 2022](https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022) | Dans l'installateur, sélectionner **Développement Desktop en C++**, avec MSVC v143 x64/x86 et un Windows SDK. Nécessaire pour Rust/Tauri et les références du corpus. |
| [Rust via rustup](https://rustup.rs/) | Installer la chaîne stable **MSVC**, pas GNU, pour Windows x64. |
| [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) | Moteur d'affichage de Tauri ; souvent déjà présent. Installer le runtime Evergreen s'il manque. |
| [JDK 21, Eclipse Temurin](https://adoptium.net/temurin/releases/?version=21) | Choisir Windows x64, **JDK**, pas seulement JRE. Activer les options `JAVA_HOME` et ajout au `PATH` dans l'installateur. |
| [Ghidra 12.1.2](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.2_build) | Télécharger l'archive de distribution `ghidra_12.1.2_PUBLIC_20260605.zip`, **pas** les archives « Source code ». Extraire, par exemple, dans `C:\Tools\ghidra_12.1.2_PUBLIC`. Cette version correspond à l'intégration actuelle. |
| [Git pour Windows](https://git-scm.com/downloads/win) | Facultatif pour télécharger le ZIP ; utile pour cloner et récupérer les mises à jour. |
| [Ollama](https://ollama.com/download/windows) | Facultatif : seulement pour les fonctionnalités IA locales. L'analyse Ghidra et les correspondances déterministes ne nécessitent pas de modèle IA. |

Les prérequis de compilation Windows sont également détaillés dans la
[documentation officielle Tauri](https://v2.tauri.app/start/prerequisites/#windows).
Il n'est pas nécessaire d'installer globalement Tauri, Gradle, Python ou NASM :
Tauri est une dépendance npm du projet, Ghidra fournit le lanceur Gradle,
et les scripts de corpus téléchargent leurs outils portables nécessaires.

Dans PowerShell, vérifier :

```powershell
node --version
npm.cmd --version
rustc --version
cargo --version
rustup show active-toolchain
java -version
javac -version
Test-Path 'C:\Tools\ghidra_12.1.2_PUBLIC\support\analyzeHeadless.bat'
```

La chaîne Rust doit indiquer `x86_64-pc-windows-msvc`, Java et javac une version
21, et le dernier test doit retourner `True` (adapter le chemin si nécessaire).
Si plusieurs JDK sont installés, `JAVA_HOME` doit désigner le dossier du JDK 21,
et son sous-dossier `bin` doit être prioritaire dans le `PATH`.

## 2. Récupérer le projet

**Avec Git**, depuis un terminal :

```powershell
git clone https://github.com/Dasshopen/reverse-assistant.git C:\Projects\reverse-assistant
Set-Location C:\Projects\reverse-assistant
```

Le dépôt est privé : être connecté à un compte GitHub autorisé. Ne jamais
coller de jeton d'accès dans une URL, un fichier du projet ou une capture.

**Sans Git** : sur GitHub, cliquer sur **Code → Download ZIP**, extraire toute
l'archive, puis ouvrir PowerShell dans le dossier contenant `package.json`.
Le dossier extrait peut s'appeler `reverse-assistant-main` ; adapter les chemins.
Ne pas lancer l'application directement depuis l'archive ZIP.

Privilégier un chemin court comme `C:\Projects\reverse-assistant`, hors OneDrive
ou dossier synchronisé, notamment pour les builds EDK2.

```powershell
npm.cmd ci
```

Cette commande installe les versions verrouillées dans `package-lock.json`.
Ne pas copier `node_modules` depuis une autre machine.

## 3. Générer le corpus BSim local

**Ne pas sauter cette étape pour un premier test complet.** La configuration
de bundle attend `bsim-corpus\build\reverse-assistant-seed.mv.db`, absent du ZIP
et du dépôt Git. Une ancienne installation peut avoir un corpus en cache et
masquer cette absence ; une machine neuve ne l'aura pas.

Fermer Reverse Assistant et Ghidra pendant la génération. Les scripts
téléchargent des sources avec hashes épinglés, compilent les références avec
symboles, puis les analysent pour construire la base. Cette étape est plus
longue qu'une simple installation npm : prévoir du temps, de l'espace disque
et une connexion Internet. Ne pas interrompre un script parce qu'il reste
plusieurs minutes sur une compilation ou une analyse.

Depuis la racine du projet, exécuter les scripts dans cet ordre :

```powershell
$referenceBuildScripts = @(
    'build-sqlite.ps1',
    'build-zlib.ps1',
    'build-lz4.ps1',
    'build-xxhash.ps1',
    'build-zstd.ps1',
    'build-brotli.ps1',
    'build-msvc-runtime.ps1',
    'build-edk2-uefi.ps1',
    'build-pyinstaller.ps1'
)
foreach ($referenceBuildScript in $referenceBuildScripts) {
    & powershell.exe -NoProfile -File (Join-Path '.\bsim-corpus\scripts' $referenceBuildScript)
    if ($LASTEXITCODE -ne 0) { throw "Échec : $referenceBuildScript. Corriger avant de continuer." }
}
```

Puis générer et vérifier la base (adapter le chemin de Ghidra) :

```powershell
& powershell.exe -NoProfile -File .\bsim-corpus\scripts\build-corpus-database.ps1 -GhidraInstallDir 'C:\Tools\ghidra_12.1.2_PUBLIC'
if ($LASTEXITCODE -ne 0) { throw 'La génération du corpus a échoué.' }
& powershell.exe -NoProfile -File .\bsim-corpus\scripts\verify-corpus.ps1 -GhidraInstallDir 'C:\Tools\ghidra_12.1.2_PUBLIC'
if ($LASTEXITCODE -ne 0) { throw 'La vérification du corpus a échoué.' }
Get-Item .\bsim-corpus\build\reverse-assistant-seed.mv.db
```

Les téléchargements et builds restent dans `bsim-corpus/sources` et
`bsim-corpus/build`, exclus de Git. Les licences et détails de reproduction
sont dans [le guide du corpus](../bsim-corpus/README.md).
BSim et Function ID sont distincts : ce pipeline génère la base **BSim**,
pas une base FID couvrant toutes les bibliothèques. Les résultats FID dépendent
des bases de référence disponibles/configurées dans Ghidra.

Si Windows bloque les scripts téléchargés, lire et vérifier leur provenance
avant de les débloquer via les propriétés du fichier. Si une politique locale
le permet, une commande ponctuelle peut utiliser
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File <script> <arguments>`.
Cela concerne uniquement ce processus : ne pas désactiver globalement les
protections ni contourner une politique d'organisation.

## 4. Lancer et configurer l'application

Depuis la racine contenant `package.json` :

```powershell
npm.cmd run tauri dev
```

Le premier build Rust peut prendre plusieurs minutes. Garder le terminal
ouvert pendant le test. La fenêtre native Tauri est l'application complète :
ouvrir seulement `http://localhost:1420` dans un navigateur ne fournit pas
le backend Rust.

Dans l'assistant de configuration de l'application :

1. Vérifier Java et Ghidra ; sélectionner la racine de Ghidra, pas son dossier
   `support` ni le fichier ZIP.
2. Installer/configurer l'extension **Reverse Assistant Exporter** proposée
   par l'assistant ; fermer les autres fenêtres Ghidra pendant cette étape.
3. Vérifier que le corpus BSim local est détecté.
4. Si l'assistant propose des téléchargements Java/Ghidra, ils peuvent préparer
   ces outils, mais **ils ne remplacent pas la génération du corpus à l'étape 3**.

L'extension peut être compilée depuis les sources incluses ; sa première
compilation Gradle peut également télécharger des dépendances.
Pour une installation manuelle, lancer Ghidra une fois puis le fermer afin
de créer son dossier utilisateur, puis utiliser :

```powershell
& powershell.exe -NoProfile -File .\scripts\deploy-ghidra-extension.ps1 -GhidraInstallDir 'C:\Tools\ghidra_12.1.2_PUBLIC'
```

## 5. Activer l'IA locale (facultatif)

Installer et démarrer Ollama, puis télécharger le modèle :

```powershell
ollama pull qwen2.5-coder:7b
ollama list
```

Dans la configuration des fournisseurs IA de Reverse Assistant, ajouter un
fournisseur compatible OpenAI avec :

- Adresse : `http://localhost:11434/v1`.
- Modèle : `qwen2.5-coder:7b` (le nom doit correspondre à `ollama list`).
- Clé : aucune clé secrète Ollama nécessaire pour ce serveur local standard.
- Ajouter le fournisseur et vérifier qu'il apparaît comme **Actif**.

Pour vérifier le serveur local depuis PowerShell :

```powershell
Invoke-RestMethod http://localhost:11434/api/tags
```

Puis lancer une analyse IA dans l'application pour vérifier l'appel complet.

Le téléchargement du modèle et ses besoins mémoire sont importants ; les temps
d'analyse dépendent du CPU/GPU, de la RAM/VRAM et du contexte. Augmenter le
contexte ne garantit pas de meilleurs noms et peut ralentir les réponses.
Ne pas exposer Ollama au réseau pour ce test : le serveur local suffit.
Un fournisseur distant est possible, mais reçoit le contexte transmis
(pseudocode, chaînes, etc.) : voir [SECURITY.md](../SECURITY.md).

## 6. Faire un premier test

Utiliser un petit binaire que l'on est autorisé à analyser ; aucun binaire de
challenge n'est livré dans le dépôt. Ne pas exécuter le binaire pour l'analyser.

1. Ouvrir le fichier et attendre la fin de l'analyse Ghidra.
2. Ouvrir une **fonction locale** dans le Code Browser : vérifier assembleur
   et pseudocode. Une fonction importée n'a pas de corps local ; son relais
   local, s'il existe, est distinct.
3. Vérifier les propositions FID/BSim ; zéro correspondance peut être normal
   si le corpus ne couvre pas les bibliothèques présentes.
4. Si l'IA est activée, attendre ses résultats et examiner provenance, preuves
   et propositions à revoir. Un nom proposé n'est pas un nom original garanti.
5. Renommer une fonction après vérification, contrôler le nom dans les autres
   vues, sauvegarder et rouvrir le projet.

Pour tester réellement une installation neuve, utiliser idéalement une VM ou
un autre compte Windows : retélécharger le dépôt sous le même compte peut
réutiliser Java, Ghidra, fournisseurs, corpus et projets déjà présents dans
les données de l'application. Ne pas supprimer ces données pour faire le test
sans les sauvegarder.

## 7. Créer un installateur (facultatif)

Après un test réussi et avec le corpus généré :

```powershell
npm.cmd run tauri build
```

Les paquets Windows sont produits sous `src-tauri\target\release\bundle`
(sous-dossiers selon les formats générés). Un installateur compilé n'est pas
nécessairement signé. Vérifier les droits de redistribution des composants
et du corpus avant de partager un paquet. Les étapes ci-dessus ne publient
pas automatiquement de Release sur GitHub.

## Dépannage

| Symptôme | À vérifier |
| --- | --- |
| `npm.ps1` bloqué | Utiliser `npm.cmd`, comme dans ce guide. |
| `cargo`, `node` ou `javac` introuvable | Rouvrir le terminal après installation ; vérifier le `PATH` et le JDK, pas seulement un JRE. |
| `link.exe` ou MSVC introuvable | Ajouter la charge C++ et le Windows SDK avec Visual Studio Installer. |
| Ressource `reverse-assistant-seed.mv.db` absente | Finir l'étape 3 ; ne pas créer un fichier vide ni renommer un ZIP en `.mv.db`. |
| Base BSim occupée/verrouillée | Fermer les autres analyses et Ghidra utilisant cette base, puis réessayer. |
| Port `1420` déjà utilisé | Arrêter l'ancien terminal de développement avec Ctrl+C ; ne lancer qu'une instance. Ne pas tuer un processus inconnu. |
| Fichier `.exe` ou extension `.jar` verrouillé | Fermer l'application ou Ghidra avant reconstruction/déploiement. |
| Timeout Ollama / connexion refusée | Vérifier qu'Ollama tourne, le modèle installé, l'URL et la mémoire disponible. |
| Aucun code pour une fonction importée | Normal : l'implémentation est dans une bibliothèque externe, pas dans le binaire analysé. |
| Première compilation/analyse lente | Attendre et regarder les logs ; téléchargements, compilations et démarrage Ghidra coûtent plus que les accès en cache. |

En cas d'échec, conserver la commande, le message complet, la version de Windows
et les versions des outils. Ne jamais joindre de clé API ni de binaire privé.
