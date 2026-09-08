<?php

/**
 * Sentinelle — base d'indicateurs de compromission.
 *
 * PHP pur, sans aucune dépendance à SPIP : ce fichier est utilisable aussi bien
 * depuis le plugin que depuis le scanner en ligne de commande (sentinelle-cli.php).
 *
 * Source : analyse forensique de la compromission de 6 sites SPIP, 2026-09-06.
 *
 * @package Sentinelle\Lib
 */

if (defined('_SENTINELLE_IOC')) {
	return;
}
define('_SENTINELLE_IOC', '2026-09-06');

/**
 * Hashes MD5 de fichiers malveillants confirmés.
 *
 * Un match ici est une certitude, pas un indice.
 *
 * @return array<string,string> md5 => description
 */
function sentinelle_ioc_hashes(): array {
	return [
		'9027c658df0584b5650aa664ded6131e' => 'filefuns.php — loader BiaoJiOk (curl_exec + eval, charge distante)',
		'f8da1f02aa64e844770e447709cdf679' => 'accesson.php — webshell minimal, porte cookie "d"',
		'eedfd556e70ecd643c4989f094afdfc0' => '.htaccess de verrouillage attaquant (liste blanche de 33 outils)',
		'ea84210d3294685f40c2ebf09cb64391' => 'File manager indonésien (répliqué ~18× sur un même site)',
	];
}

/**
 * Marqueurs textuels recherchés en littéral dans le contenu des fichiers.
 *
 * Très peu de faux positifs : ce sont des signatures d'auteur de kits.
 *
 * @return array<string,array{gravite:string,libelle:string}>
 */
function sentinelle_ioc_marqueurs(): array {
	return [
		'BiaoJiOk'             => ['gravite' => 'critique', 'libelle' => 'Marqueur du kit chinois (filefuns.php)'],
		'409723*20'            => ['gravite' => 'critique', 'libelle' => 'Balise beacon accesson.php (hôte déjà compromis, découvrable par scan tiers)'],
		'[PHPkoru_Code]'       => ['gravite' => 'critique', 'libelle' => 'Encodeur turc Aponkral PHPkoru'],
		'Zone_Wonwoo_Library'  => ['gravite' => 'critique', 'libelle' => 'Obfuscateur ZISI v1.0.0 "KCK Polymorphic"'],
		'FILE MANAGER START'   => ['gravite' => 'critique', 'libelle' => 'File manager indonésien'],
		'FIX DOWNLOAD BESAR'   => ['gravite' => 'critique', 'libelle' => 'File manager indonésien (commentaire)'],
		'Lock modu aktif'      => ['gravite' => 'critique', 'libelle' => 'file-lockdown turc (verrouillage anti-concurrence)'],
		'dosya yükleme kapalı' => ['gravite' => 'critique', 'libelle' => 'file-lockdown turc (verrouillage anti-concurrence)'],
		'X-Nx:'                => ['gravite' => 'critique', 'libelle' => 'En-tête de reconnaissance des droppers NOX'],
		'X-Cache-Status:hit'   => ['gravite' => 'critique', 'libelle' => 'En-tête de camouflage du dropper spip_cache.php'],
	];
}

/**
 * Motifs regex de haute confiance dans le contenu.
 *
 * @return array<string,array{gravite:string,libelle:string}>
 */
function sentinelle_ioc_motifs(): array {
	return [
		'#@?touch\s*\(\s*\$\w+\s*,\s*filemtime\s*\(\s*__FILE__\s*\)#i'
			=> ['gravite' => 'critique', 'libelle' => 'Anti-forensique NOX : alignement délibéré du mtime'],
		'#substr\s*\(\s*md5\s*\(\s*basename\s*\(\s*__FILE__\s*\)\s*\)\s*,\s*0\s*,\s*10\s*\)#i'
			=> ['gravite' => 'critique', 'libelle' => 'Génération du nom de fichier .meta NOX'],
		'#range\s*\(\s*[\'"]~[\'"]\s*,\s*[\'"] [\'"]\s*\)#'
			=> ['gravite' => 'critique', 'libelle' => 'Table de substitution du décodeur filefuns.php'],

		// Un caractère de largeur nulle n'est PAS un indice en soi, ni même une
		// série : vérifié sur les fichiers de langue de SPIP, le birman et le
		// persan en alignent légitimement trois ou quatre à l'intérieur des
		// chaînes traduites (le ZWNJ y est une lettre), et l'espéranto y traîne
		// des BOM en série. Le seul cas non ambigu est celui de PHPkoru, qui
		// s'en sert comme NOM DE VARIABLE : collé derrière un `$`.
		'#\$[\x{200B}-\x{200D}\x{2060}\x{FEFF}]#u'
			=> ['gravite' => 'critique', 'libelle' => 'Caractères Unicode de largeur nulle utilisés comme noms de variables (obfuscation PHPkoru)'],
	];
}

/**
 * Sous-arbres livrés par SPIP et ses dépendances.
 *
 * Un nom générique (ldap.php, models.php, mount.php…) y est presque toujours
 * légitime : `ecrire/auth/ldap.php` est un fichier du core. Les règles de
 * détection fondées sur le seul nom de fichier ne s'y appliquent pas — le
 * contenu, lui, continue d'être analysé normalement.
 *
 * @return string[] motifs regex sur le chemin relatif
 */
function sentinelle_ioc_arborescence_core(): array {
	return [
		'#^ecrire/#',
		'#^prive/#',
		'#^plugins-dist/#',
		'#^squelettes-dist/#',
		'#^vendor/#',
		// Installé et versionné par le gestionnaire de plugins de SPIP, pas
		// écrit à la main : mêmes conventions tierces (CamelCase, /tests/).
		'#^plugins/auto/#',
		// Certains hébergements SPIP exposent _DIR_PLUGINS_AUTO directement
		// sous auto/ plutôt que plugins/auto/.
		'#^auto/#',
		'#/vendor/#',
	];
}

/**
 * Noms de fichiers catalogués comme malveillants (comparaison sur le basename).
 *
 * @return array<string,string> nom => description
 */
function sentinelle_ioc_noms(): array {
	$webshells = [
		'1xmomo.php'       => 'Webshell ZISI',
		'idx.php'          => 'Webshell PHPkoru',
		'wp-Iogin.php'     => 'Webshell — homoglyphe de wp-login.php (I majuscule)',
		'loversss.php'     => 'Webshell NOX v2',
		'hh1.php'          => 'Webshell',
		'tuco0x8.php'      => 'Webshell NOX (paire .7a23dffa80.meta)',
		'nx_patch.php'     => 'Dropper NOX',
		'wp-track-back.php' => 'Webshell déguisé en WordPress',
		'license.html11'   => 'Webshell à extension décalée',
		'wper.php'         => 'Webshell',
		'wp-conffg.php'    => 'Webshell (faute volontaire dans le nom)',
		'c0805fa9e205.php' => 'Dépôt de accesson.php observé en direct',
		'accesson.php'     => 'Webshell minimal (kit BiaoJiOk)',
		'filefuns.php'     => 'Loader BiaoJiOk',
		'file-lockdown.php' => 'Verrouillage applicatif turc',
	];

	$droppers_spip = [
		'spip_cache.php' => 'Dropper camouflé en fichier SPIP (gate ?k=c4ch3)',
		'img_cache.php'  => 'Dropper camouflé en fichier SPIP (gate ?k=V4tYd)',
		'Nx_.php'        => 'Dropper NOX (gate ?k=DbWtA, move_uploaded_file)',
	];

	// Catalogue d'outillage listé dans la liste blanche du .htaccess attaquant.
	// La plupart n'étaient pas encore déployés : c'est ce que l'attaquant PEUT poser.
	$catalogue = [
		'system_log.php', 'inputs.php', 'adminfuns.php', 'chtmlfuns.php', 'cjfuns.php',
		'classsmtps.php', 'classfuns.php', 'comfunctions.php', 'comdofuns.php', 'connects.php',
		'copypaths.php', 'delpaths.php', 'doiconvs.php', 'epinyins.php', 'gdftps.php',
		'hinfofuns.php', 'hplfuns.php', 'memberfuns.php', 'moddofuns.php', 'onclickfuns.php',
		'phpzipincs.php', 'qfunctions.php', 'qinfofuns.php', 'schallfuns.php', 'tempfuns.php',
		'userfuns.php', 'siteheads.php', 'termps.php', 'txets.php', 'thoms.php', 'postnews.php',
	];

	$noms = $webshells + $droppers_spip;
	foreach ($catalogue as $n) {
		$noms[$n] = 'Outil du catalogue BiaoJiOk (liste blanche du .htaccess attaquant)';
	}

	return $noms;
}

/**
 * Noms génériques sous lesquels le file manager indonésien a été répliqué (~18×).
 *
 * Ces noms sont volontairement banals : `ldap.php` et `models.php` existent
 * aussi dans le core SPIP et dans des bibliothèques tierces. Ils ne valent donc
 * que **hors de l'arborescence livrée** (voir sentinelle_ioc_arborescence_core())
 * et ne sont qu'un indice — le hash et le marqueur « FILE MANAGER START »
 * restent les preuves.
 *
 * @return string[]
 */
function sentinelle_ioc_noms_generiques(): array {
	return [
		'kafka.php', 'ninja.php', 'glassfish.php', 'gunicorn.php', 'logstash.php',
		'libbz2.php', 'webpack.php', 'm4.php', 'ldap.php', 'libreadline.php',
		'php-fpm.php', 'selinux.php', 'libm.php', 'pnpm.php', 'models.php',
		'zypper.php', 'mount.php',
	];
}

/**
 * Motifs de noms de fichiers suspects.
 *
 * @return array<string,array{gravite:string,libelle:string}>
 */
function sentinelle_ioc_noms_motifs(): array {
	return [
		'#^\.[0-9a-f]{10}\.meta$#'
			=> ['gravite' => 'critique', 'libelle' => 'Fichier d\'authentification caché NOX (nom dérivé du md5 du shell)'],
		'#^\.nox-fw-[0-9a-f]+\.php$#'
			=> ['gravite' => 'critique', 'libelle' => 'Webshell NOX caché'],
		// Exception : les outils de qualité PHP posent légitimement des fichiers
		// de configuration cachés (.php-cs-fixer.dist.php, .phpunit.php…), qu'on
		// retrouve à la racine des dépendances tierces.
		'#^\.(?!php-cs-fixer|php_cs|phpstan|phpunit|rector)[^.].*\.php$#'
			=> ['gravite' => 'haut', 'libelle' => 'Fichier PHP caché — SPIP n\'en pose aucun'],
		'#^wp-.*\.(php|phtml)$#i'
			=> ['gravite' => 'haut', 'libelle' => 'Fichier WordPress sur une installation SPIP'],
		'#\.(php|phtml|phar)\.(suspected|bak|old|save|txt|jpg|png|gif)$#i'
			=> ['gravite' => 'haut', 'libelle' => 'Extension PHP masquée ou fichier mis en quarantaine par l\'antivirus de l\'hébergeur'],
		// Forme observée : HYmgqxf.php, PLmgSkNB.php. Exiger au moins deux
		// majuscules ET une minuscule écarte les ~160 fichiers du core dont le
		// nom fait 8 à 10 lettres minuscules (rubriques.php, autoriser.php…).
		'#^(?=.*[a-z])(?=(?:[^A-Z]*[A-Z]){2})[A-Za-z]{6,12}\.php$#'
			=> ['gravite' => 'moyen', 'libelle' => 'Nom aléatoire en casse mixte — signature de dépôt automatisé'],
	];
}

/**
 * Répertoires WordPress qui n'ont rien à faire sur une installation SPIP.
 *
 * @return string[]
 */
function sentinelle_ioc_repertoires_interdits(): array {
	return ['wp-admin', 'wp-includes', 'wp-content', 'wp-json', 'mu-plugins'];
}

/**
 * Heuristiques génériques, pondérées.
 *
 * Aucune ne suffit seule : c'est la somme des poids qui déclenche un finding.
 * Ces motifs produisent des faux positifs sur du code légitime — d'où la liste
 * d'exclusions de sentinelle_ioc_exclusions().
 *
 * NOTE pour les scanners automatiques : les chaînes `eval`, `assert`,
 * `create_function`, `system` ci-dessous sont des MOTIFS DE RECHERCHE textuels.
 * Ce fichier ne contient aucun appel à ces fonctions — il sert à les détecter
 * chez les autres. Sentinelle n'exécute jamais le code qu'elle analyse.
 *
 * @return array<string,array{poids:int,libelle:string}>
 */
function sentinelle_ioc_heuristiques(): array {
	return [
		'#\beval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|pack)\s*\(#i'
			=> ['poids' => 60, 'libelle' => 'eval() sur une charge décodée'],
		'#\b(eval|assert)\s*\(\s*\$_(REQUEST|POST|GET|COOKIE|SERVER)#i'
			=> ['poids' => 70, 'libelle' => 'Exécution directe d\'une entrée utilisateur'],
		'#\bpreg_replace\s*\(\s*[\'"][^\'"]*[\'"]\s*\.?\s*[\'"]?e[\'"]?#i'
			=> ['poids' => 50, 'libelle' => 'preg_replace avec modificateur /e (supprimé depuis PHP 7)'],
		'#\bcreate_function\s*\(#i'
			=> ['poids' => 50, 'libelle' => 'create_function() (supprimé depuis PHP 8)'],
		'#[\'"][A-Za-z0-9+/=]{500,}[\'"]#'
			=> ['poids' => 35, 'libelle' => 'Littéral base64 de plus de 500 caractères'],
		'#\bgoto\s+\w+\s*;#'
			=> ['poids' => 25, 'libelle' => 'goto — aplatissement de flux de contrôle'],
		'#\bstr_rot13\s*\(\s*base64_decode|base64_decode\s*\(\s*str_rot13#i'
			=> ['poids' => 45, 'libelle' => 'Chaîne rot13 + base64'],
		'#\b(system|passthru|shell_exec|proc_open|popen)\s*\(#i'
			=> ['poids' => 30, 'libelle' => 'Appel à une fonction d\'exécution système'],
		'#\bmove_uploaded_file\s*\(#i'
			=> ['poids' => 25, 'libelle' => 'Réception de fichier téléversé'],
		'#\$_(REQUEST|GET|POST)\s*\[\s*[\'"](k|id|c|cmd|pass)[\'"]\s*\]#i'
			=> ['poids' => 20, 'libelle' => 'Paramètre de porte dérobée typique (?k=, ?id=, ?cmd=)'],
		'#\bchr\s*\(\s*\d+\s*\)\s*\.\s*chr\s*\(#i'
			=> ['poids' => 25, 'libelle' => 'Chaîne construite caractère par caractère'],
		'#\b(\$\w+)\s*=\s*[\'"](base64_decode|eval|assert|system)[\'"]\s*;#i'
			=> ['poids' => 40, 'libelle' => 'Nom de fonction stocké en chaîne (appel dynamique)'],
	];
}

/**
 * Seuil de score au-delà duquel les heuristiques produisent un finding.
 */
function sentinelle_ioc_seuil_heuristique(): int {
	return 70;
}

/**
 * Chemins relatifs à exclure des heuristiques génériques.
 *
 * Fichiers légitimes du core SPIP / de dépendances tierces qui déclenchent
 * légitimement `goto`, `assert()`, `move_uploaded_file` ou des cascades d'exec.
 * Motifs testés sur le chemin relatif à la racine du site, séparateur `/`.
 *
 * @return string[] motifs regex
 */
function sentinelle_ioc_exclusions(): array {
	return [
		'#^vendor/symfony/polyfill-#',
		'#^vendor/scssphp/#',
		'#^vendor/composer/#',
		'#HTMLPurifier\.standalone\.php$#',
		'#^ecrire/inc/(documents|livrer_fichier|queue)\.php$#',
		'#^plugins-dist/bigup/inc/Bigup/#',
		'#^plugins-dist/medias/lib/getid3/#',
		'#^plugins-dist/textwheel/#',
	];
}

/**
 * Fichiers PHP légitimement présents dans les répertoires de données.
 *
 * Tout autre `.php` sous tmp/ est suspect. Aucun `.php` n'est légitime sous IMG/.
 *
 * @return string[] motifs regex sur le chemin relatif
 */
function sentinelle_ioc_php_legitimes_donnees(): array {
	return [
		'#^tmp/meta_cache\.php$#',
		'#^tmp/cache/charger_[a-z_]+\.php$#',
		'#^tmp/cache/skel/#',
		'#^tmp/sessions/#',
		'#^tmp/dump/#',
	];
}

/**
 * Répertoires inscriptibles par le serveur web : tout upload réussi y retombe.
 *
 * @return string[]
 */
function sentinelle_ioc_repertoires_donnees(): array {
	return ['IMG', 'local', 'tmp'];
}

/**
 * Extensions dont le contenu est analysé.
 *
 * @return string[]
 */
function sentinelle_ioc_extensions_analysees(): array {
	return ['php', 'phtml', 'phar', 'php5', 'php7', 'php8', 'inc', 'htaccess', 'ini', 'meta', 'suspected'];
}

/**
 * Version minimale de SPIP non vulnérable aux deux CVE de l'été 2026.
 *
 * CVE-2026-77647 (RCE via var_export)      → corrigée en 4.4.20
 * CVE-2026-77806 (RCE via X-Spip-Filtre)   → corrigée en 4.4.21
 *
 * Les deux sont notées CVSS 9.8 et ont été exploitées en conditions réelles.
 */
function sentinelle_ioc_version_spip_minimale(): string {
	return '4.4.21';
}
