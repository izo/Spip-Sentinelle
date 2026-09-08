# Sentinelle

Plugin SPIP de détection, d'isolement et de vérification de cohérence après compromission.

Écrit à partir de l'analyse forensique de six sites SPIP compromis en août 2026.
Les indicateurs qu'il embarque sont ceux réellement trouvés sur ces sites, pas
une liste générique.

- **Compatibilité** : SPIP 4.2 → 4.\*, PHP 7.4 → 8.4+
- **Licence** : GNU/GPL
- **État** : stable

---

## Ce qu'il fait

| | |
|---|---|
| **Détecte** | 9 familles de règles : hash MD5 connu, nom de fichier catalogué, nom générique de dropper, motif de nom, PHP dans un répertoire de données, `.htaccess` détourné, marqueur littéral, expression régulière à forte confiance, heuristiques pondérées |
| **Isole** | Déplace le fichier hors de la racine publique, sous un nom opaque non exécutable — **rien n'est jamais supprimé**, tout est restaurable en un clic |
| **Vérifie** | Empreinte de référence (manifeste MD5) : c'est la **seule** méthode qui voit un webshell inédit, absent de tout catalogue |
| **Prévient** | Tâche périodique, alerte immédiate sur les nouveautés, rapport quotidien même quand tout va bien |

---

## Installation

1. Copier le répertoire dans `plugins/sentinelle/` du site :

   ```
   plugins/sentinelle/paquet.xml
   plugins/sentinelle/lib/…
   …
   ```

2. Espace privé → **Configuration → Gestion des plugins** → activer **Sentinelle**.

3. Le menu **Sentinelle** apparaît sous *Maintenance du site*, ou directement :
   `https://votresite.tld/ecrire/?exec=sentinelle`

L'accès à la page et à toutes les actions est réservé au **webmestre** (`autoriser('webmestre')`),
pas aux administrateurs. Aucune table SQL n'est créée : tout l'état vit dans des fichiers JSON.

---

## Le premier quart d'heure

**L'ordre compte.** L'empreinte de référence fige l'état du site : posée sur un site
compromis, elle fige la compromission et rend la vérification de cohérence aveugle.

1. **Scanner.** Bouton *Lancer un scan complet*. Compter ~1 à 3 s pour 3 500 fichiers.
2. **Lire.** Une ligne par fichier, la règle la plus grave en tête. **N'ouvrir aucun
   de ces chemins dans un navigateur** — plusieurs de ces fichiers réagissent à une
   simple requête `GET`.
3. **Isoler.** Cocher les fichiers vérifiés puis *Isoler la sélection*, ou agir fichier par fichier. Réversible.
4. **Vérifier le site.** Front et espace privé. Un faux positif se rattrape en un clic
   sur *Restaurer*.
5. **Poser l'empreinte.** Seulement maintenant. Tant que des alertes critiques
   restent ouvertes, la pose est bloquée. Une dérogation confirmée existe pour
   les situations déjà vérifiées et reste tracée dans l'empreinte.

Compter **15 à 30 minutes** pour un site propre, une demi-journée pour un site
réellement compromis — le temps ne part pas dans le scan, il part dans la relecture
de ce qui a été isolé.

---

## Le tableau de bord

| Bloc | Contenu |
|---|---|
| **Bilan** | Fichiers uniques par gravité, nombre de règles et groupes d'empreinte |
| **État** | Dernier cycle réussi, fraîcheur, échec éventuel, phase et progression du cron |
| **Posture du site** | Alertes qui ne visent aucun fichier : version de SPIP, `config/connect.php` lisible, `.htaccess` racine absent… |
| **Fichiers signalés** | Une ligne par fichier, avec recherche, filtres, motifs repliables, sélection et pagination |
| **Fichiers isolés** | La quarantaine active, avec son lot et son bouton *Restaurer* |

Chaque bouton est un formulaire `POST` avec confirmation. Aucun lien `GET` ne change
d'état : un lien d'action suivi par un préchargeur de navigateur ou un robot
déclencherait l'action tout seul.

**Garde-fou sur l'isolement** : au-delà de l'autorisation webmestre, un chemin doit
figurer dans les résultats du dernier scan pour pouvoir être déplacé. Sans cette
vérification, l'action serait une primitive « déplacer n'importe quel fichier du site »
offerte à toute session webmestre détournée.

Certains chemins ne sont **jamais** déplacés automatiquement, même signalés :
`.htaccess` racine, `index.php`, `spip.php`, `config/`, `ecrire/`, `prive/`,
`squelettes-dist/`, `plugins-dist/`. Les déplacer casserait le site plus sûrement
que le webshell. La page affiche le motif du refus à la place du bouton.

---

## Le cron

### Ce que fait la tâche

Un cycle complet = lister, analyser, comparer à l'empreinte, comparer au cycle
précédent, puis envoyer **un seul message** : une alerte s'il y a du nouveau, le
rapport de routine sinon.

Quelques milliers de fichiers ne s'analysent pas dans le temps d'une requête web —
et le cron de SPIP s'exécute justement dans une requête web. La tâche travaille donc
par tranches : 12 secondes ou 600 entrées, puis elle rend la main. La découverte,
l'analyse et les deux passes de comparaison possèdent chacune un curseur persistant ;
le tableau de bord affiche la phase et la progression.

Le premier cycle après l'installation enregistre sans alerter — sinon la première
alerte est un mur illisible que personne ne lit jusqu'au bout. Le rapport, lui, part
quand même : il vaut inventaire de départ.

### Le déclencher sans SSH (Infomaniak)

Par défaut, SPIP déclenche son cron sur le trafic du site. Sur un site peu visité,
ça ne suffit pas. Manager Infomaniak → **Hébergement → Tâches cron → Ajouter** :

| Champ | Valeur |
|---|---|
| Type | **URL** |
| URL | `https://votresite.tld/spip.php?action=cron` |
| Fréquence | toutes les 15 minutes, ou toutes les heures |

Cette URL est le point d'entrée public standard de SPIP pour un cron externe : elle
répond `204 No Content` et lance la file de tâches en attente. Elle ne prend aucun
paramètre et n'expose rien.

L'intervalle propre à Sentinelle (6 heures par défaut) est indépendant de la
fréquence du cron externe : celui-ci ne fait que donner à SPIP l'occasion de
regarder si une tâche est due.

### Régler les intervalles

Trois `meta`, à poser depuis un plugin de configuration ou en SQL :

| Meta | Défaut | Effet |
|---|---|---|
| `sentinelle_intervalle` | `21600` (6 h) | Secondes entre deux cycles. **`0` désactive la tâche.** |
| `sentinelle_rapport` | `86400` (24 h) | Secondes entre deux rapports de routine. **`0` coupe le rapport ; les alertes continuent.** |
| `sentinelle_email` | *(vide)* | Destinataire des messages. Vide → `email_webmaster`. |

```sql
INSERT INTO spip_meta (nom, valeur, impt) VALUES ('sentinelle_intervalle', '21600', 'non')
	ON DUPLICATE KEY UPDATE valeur = '21600';
```

### Les deux messages

**L'alerte** part dès qu'un cycle voit apparaître quelque chose qui n'était pas là au
passage précédent — sans attendre l'heure du rapport : entre le dépôt d'un webshell et
sa première requête utile, il s'écoule souvent moins d'une heure. Sujet
`[Sentinelle] Alerte — …`.

**Le rapport** part au plus une fois par jour, *même quand tout va bien*. C'est le
point : son absence est elle-même une information. Un cron arrêté, un hébergeur qui
coupe la tâche, un plugin désactivé par une mise à jour — dans tous ces cas la
surveillance s'est tue sans rien signaler, et seul le silence du rapport le dit. Il
rappelle aussi les signalements critiques et hauts encore ouverts : une alerte n'est
envoyée qu'une fois, un fichier laissé en place doit rester visible. Sujet
`[Sentinelle] Rapport — …`.

Les deux ne se doublent jamais : l'alerte porte déjà le bilan complet du site, elle
tient donc lieu de rapport et repousse le suivant d'autant. Au plus un message par
cycle, un par jour sur un site calme. Un envoi qui échoue reste dans
`notifications.json` et n'est acquitté qu'après succès ; le passage suivant le rejoue
avant de commencer un nouveau cycle.

Le scan lancé à la main depuis l'espace privé n'envoie rien : le webmestre est devant
son écran, le résultat s'affiche sur la page.

### Ce que contient le message

Chemin, règle, hash, taille. **Jamais un extrait du code analysé** : un webshell cité
dans un mail traverse des relais, des antivirus et des sauvegardes, et se retrouve mis
en quarantaine par des systèmes qui n'ont rien demandé. Chaque message se termine par
l'adresse du tableau de bord, et — s'il liste des chemins — par le rappel de ne pas
les ouvrir dans un navigateur.

---

## La ligne de commande

`sentinelle-cli.php` ne charge pas SPIP et n'a besoin d'aucune base. Il s'utilise sur
une copie locale d'un site, sur une sauvegarde, ou sur un site dont l'espace privé
n'est plus fiable.

```bash
php sentinelle-cli.php scan      <racine> [--json] [--quarantaine]
php sentinelle-cli.php baseline  <racine>
php sentinelle-cli.php coherence <racine> [--json]
php sentinelle-cli.php restaurer <racine> <chemin-relatif>
php sentinelle-cli.php liste     <racine>
```

| Commande | Effet |
|---|---|
| `scan` | Analyse complète. `--quarantaine` isole tous les critiques dans un même lot. `--json` sort la structure brute. |
| `baseline` | Pose l'empreinte de référence. Affiche l'avertissement sur l'ordre des opérations. |
| `coherence` | Compare l'état actuel à l'empreinte : ajouts, modifications, disparitions. |
| `restaurer` | Remet un fichier isolé à sa place, avec ses permissions d'origine. |
| `liste` | Quarantaine active. |

**Codes de sortie** — utilisables dans un script :

| Code | Signification |
|---|---|
| `0` | Rien de critique (`scan`) / aucun écart (`coherence`) |
| `1` | Au moins un finding critique (`scan`) / au moins un ajout ou une modification (`coherence`) |
| `2` | Erreur d'usage : commande inconnue, racine introuvable, empreinte absente |

```bash
# Exemple : bloquer un déploiement si le site part avec un webshell
php sentinelle-cli.php scan /var/www/monsite || exit 1
```

La CLI et le plugin partagent le même répertoire d'état. Une empreinte posée en ligne
de commande est lue par le tableau de bord, et inversement — à condition que les deux
tournent sous un utilisateur ayant les mêmes droits sur le stockage privé Sentinelle.

### Cron CLI plutôt que cron HTTP

Si vous préférez faire tourner la CLI depuis le gestionnaire de tâches d'Infomaniak
(type *script PHP*, qui ne passe pas d'arguments), déposer un lanceur à la racine du site :

```php
<?php
// sentinelle-cron.php — à la racine du site
$_SERVER['argv'] = ['cli', 'coherence', __DIR__];
require __DIR__ . '/plugins/sentinelle/sentinelle-cli.php';
```

---

## Où vivent les fichiers

Par défaut, tout est placé **hors de la racine publique**, dans un répertoire voisin
nommé `.spip-sentinelle-<identifiant>`. Si son parent n'est pas inscriptible,
Sentinelle utilise un sous-répertoire privé de `sys_get_temp_dir()`. Une surcharge est
possible avec `_SENTINELLE_ETAT_DIR` ou `SENTINELLE_STATE_DIR` ; une valeur située
dans le site est refusée.

| Fichier | Contenu |
|---|---|
| `findings.json` | Résultats du dernier cycle terminé |
| `baseline.json` | Empreinte de référence (chemin → MD5, taille, mtime) |
| `etat.json` | Position du scan fractionné en cours |
| `quarantaine.json` | Journal des déplacements — c'est lui qui rend la restauration possible |
| `message.json` | Compte rendu de la dernière action, consommé à l'affichage |
| `rapport.json` | Date du dernier message envoyé — c'est lui qui empêche l'alerte et le rapport de se doubler |
| `notifications.json` | File idempotente des messages non encore acquittés |
| `quarantaine/<lot>/*.payload` | Charges isolées sous des noms opaques sans extension exécutable |

Le stockage est créé en `0700`, les états en `0600`. L'isolation est refusée si le
répertoire ne peut pas être protégé ou se trouve sur un autre système de fichiers :
le déplacement doit rester atomique. La sécurité ne dépend donc ni d'Apache ni de
`AllowOverride` et reste valable sous Nginx ou Caddy.

**Sauvegarder `quarantaine.json` avant tout nettoyage du stockage privé.** Sans lui, les
fichiers isolés restent sur le disque mais plus rien ne sait où les remettre.

---

## Ce que Sentinelle ne fait pas

- **Ce n'est pas un antivirus.** Un scan sans alerte n'est pas une preuve d'absence de
  compromission : c'est une absence d'indicateur *catalogué*. Un webshell inédit ne
  sera vu que par la vérification de cohérence.
- **Il ne répare pas SPIP.** Si la posture signale une version vulnérable
  (CVE-2026-77647, CVE-2026-77806 — les deux en 9.8, exploitées dans la nature),
  la mise à jour vers **4.4.21 minimum** reste à faire à la main. Nettoyer sans
  mettre à jour, c'est se faire recompromettre dans la semaine.
- **Il ne change aucun mot de passe.** Si la posture signale un identifiant exposé
  dans `config/connect.php`, il faut le changer partout où il est réutilisé — la
  valeur n'est volontairement recopiée nulle part, ni dans la page, ni dans les logs,
  ni dans les mails.
- **Il ne remonte pas dans le temps.** Il compare le présent à une empreinte. Sans
  empreinte antérieure à l'intrusion, il ne peut pas dater la compromission ; cette
  analyse doit être menée à partir des logs du serveur web.
- **Deux fichiers de son moteur sont exemptés des règles de contenu.** `lib/ioc.php`
  et `lib/scanner.php` portent nécessairement les signatures en clair. Tout le reste
  du plugin suit le pipeline complet ; les règles de hash et de nom restent actives
  même sur ces deux fichiers. La baseline couvre l'ensemble du plugin.

---

## Architecture

```
lib/            moteur pur PHP — zéro dépendance à SPIP
  ioc.php         le catalogue d'indicateurs, seul fichier à mettre à jour
  scanner.php     les 9 règles de détection + les contrôles de posture
  baseline.php    empreinte et comparaison
  state.php       stockage privé, verrous et JSON atomique
  quarantaine.php déplacement réversible et journal

inc/            pont SPIP ↔ moteur, file d'alertes et rapports
genie/          tâche périodique fractionnée
action/         scan · empreinte · quarantaine (POST + securiser_action)
prive/          tableau de bord
sentinelle-cli.php   même moteur, sans SPIP
tests/run.php        tests de sécurité et de récupération
```

Le moteur ne connaît qu'une racine de site et des chemins relatifs. C'est ce qui
permet de l'utiliser sur une copie locale, une sauvegarde ou un miroir FTP — et
c'est ce qui a permis de le valider sur les trois sites compromis avant de l'écrire
sous forme de plugin.

**Pour enrichir la détection**, un seul fichier : `lib/ioc.php`. Hash, nom, marqueur
ou expression régulière — les fonctions y sont documentées une par une, et rien
ailleurs n'a besoin d'être touché.

## Tests

```bash
php tests/run.php
find . -name '*.php' -print0 | xargs -0 -n1 php -l
```

La CI exécute ces contrôles sous PHP 7.4, 8.0, 8.1, 8.2, 8.3 et 8.4, valide la
CLI et `paquet.xml`, et vérifie la parité des catalogues français et anglais.
