<?php

/**
 * Sentinelle — moteur de scan.
 *
 * PHP pur, sans dépendance à SPIP. N'exécute jamais le code qu'il analyse :
 * tout est lu comme du texte.
 *
 * @package Sentinelle\Lib
 */

if (defined('_SENTINELLE_SCANNER')) {
	return;
}
define('_SENTINELLE_SCANNER', '1.0');

require_once __DIR__ . '/ioc.php';

/** Taille maximale d'un fichier dont on analyse le contenu (8 Mo). */
define('_SENTINELLE_TAILLE_MAX', 8 * 1024 * 1024);

/**
 * Chemin relatif à la racine du site, séparateur `/`.
 */
function sentinelle_chemin_relatif(string $racine, string $absolu): string {
	$racine = rtrim(str_replace('\\', '/', $racine), '/');
	$absolu = str_replace('\\', '/', $absolu);
	if (strpos($absolu, $racine . '/') === 0) {
		return substr($absolu, strlen($racine) + 1);
	}
	return ltrim($absolu, '/');
}

/**
 * Répertoires jamais parcourus (état de Sentinelle, dépôts VCS, quarantaine).
 *
 * @return string[] motifs regex sur le chemin relatif
 */
function sentinelle_scan_ignores(): array {
	return [
		'#^tmp/sentinelle(/|$)#',
		'#^\.git(/|$)#',
		'#^node_modules(/|$)#',
		'#^local/cache-(css|js|gd2|less)(/|$)#',
	];
}

/**
 * Construit la liste des fichiers et répertoires à analyser.
 *
 * Retourne des chemins relatifs. Les répertoires sont suffixés d'un `/`
 * pour être distingués des fichiers.
 *
 * @return string[]
 */
function sentinelle_scan_lister(string $racine): array {
	$etat = sentinelle_scan_decouverte_initialiser();
	while (empty($etat['terminee'])) {
		$etat = sentinelle_scan_decouvrir_tranche($racine, $etat, PHP_FLOAT_MAX, PHP_INT_MAX);
	}
	return $etat['fichiers'];
}

/**
 * État initial sérialisable de la découverte fractionnée.
 */
function sentinelle_scan_decouverte_initialiser(): array {
	return ['repertoires' => [''], 'repertoire_position' => 0, 'entree_position' => 0, 'fichiers' => [], 'terminee' => false];
}

/**
 * Un nom doit-il entrer dans le pipeline complet du scanner ?
 */
function sentinelle_scan_retenir_nom(string $nom): bool {
	$ext = strtolower(pathinfo($nom, PATHINFO_EXTENSION));
	$extensions = sentinelle_ioc_extensions_analysees();
	// La découverte sert aussi au hachage fractionné de la baseline.
	if (function_exists('sentinelle_baseline_extensions')) {
		$extensions = array_merge($extensions, sentinelle_baseline_extensions());
	}
	if (in_array($ext, $extensions, true)
		|| strpos($nom, '.') === 0
		|| isset(sentinelle_ioc_noms()[$nom])) {
		return true;
	}
	foreach (sentinelle_ioc_noms_motifs() as $motif => $regle) {
		if (preg_match($motif, $nom)) {
			return true;
		}
	}
	return false;
}

/**
 * Découvre une tranche d'arborescence avec curseurs persistants.
 */
function sentinelle_scan_decouvrir_tranche(string $racine, array $etat, float $deadline, int $maximum): array {
	$racine = rtrim(str_replace('\\', '/', $racine), '/');
	$traites = 0;
	$ignores = sentinelle_scan_ignores();
	while (($etat['repertoire_position'] ?? 0) < count($etat['repertoires'])) {
		$rel_dir = $etat['repertoires'][$etat['repertoire_position']];
		$absolu = $rel_dir === '' ? $racine : $racine . '/' . $rel_dir;
		try {
			$iterateur = new DirectoryIterator($absolu);
		} catch (UnexpectedValueException $e) {
			$etat['fichiers'][] = '@sentinelle-inaccessible:' . ($rel_dir === '' ? './' : $rel_dir . '/');
			$etat['repertoire_position']++;
			$etat['entree_position'] = 0;
			continue;
		}
		$position = 0;
		foreach ($iterateur as $info) {
			if ($info->isDot()) {
				continue;
			}
			$position++;
			if ($position <= (int) ($etat['entree_position'] ?? 0)) {
				continue;
			}
			$etat['entree_position'] = $position;
			$rel = ltrim(($rel_dir !== '' ? $rel_dir . '/' : '') . $info->getFilename(), '/');
			$ignore = false;
			foreach ($ignores as $motif) {
				if (preg_match($motif, $rel)) {
					$ignore = true;
					break;
				}
			}
			if (!$ignore) {
				if ($info->isLink()) {
					$etat['fichiers'][] = '@sentinelle-lien:' . $rel;
				} elseif ($info->isDir()) {
					if (!is_readable($info->getPathname())) {
						$etat['fichiers'][] = '@sentinelle-inaccessible:' . $rel . '/';
					} else {
						$etat['repertoires'][] = $rel;
						if (in_array($info->getFilename(), sentinelle_ioc_repertoires_interdits(), true)) {
							$etat['fichiers'][] = $rel . '/';
						}
					}
				} elseif ($info->isFile() && sentinelle_scan_retenir_nom($info->getFilename())) {
					$etat['fichiers'][] = $rel;
				}
			}
			$traites++;
			if ($traites >= $maximum || microtime(true) >= $deadline) {
				return $etat;
			}
		}
		$etat['repertoire_position']++;
		$etat['entree_position'] = 0;
	}
	$etat['fichiers'] = array_values(array_unique($etat['fichiers']));
	sort($etat['fichiers']);
	$etat['terminee'] = true;
	return $etat;
}

/**
 * Fabrique un finding normalisé.
 */
function sentinelle_finding(string $chemin, string $gravite, string $regle, string $libelle, string $preuve = '', array $extra = []): array {
	return $extra + [
		'chemin'  => $chemin,
		'gravite' => $gravite,
		'regle'   => $regle,
		'libelle' => $libelle,
		'preuve'  => $preuve,
		'confiance' => $regle === 'hash' ? 'confirme' : 'heuristique',
	];
}

/**
 * Analyse un seul chemin (fichier ou répertoire suffixé `/`).
 *
 * @return array[] liste de findings
 */
function sentinelle_scan_chemin(string $racine, string $rel): array {
	$racine = rtrim(str_replace('\\', '/', $racine), '/');
	$absolu = $racine . '/' . rtrim($rel, '/');

	if (strpos($rel, '@sentinelle-inaccessible:') === 0) {
		$chemin = substr($rel, strlen('@sentinelle-inaccessible:'));
		return [sentinelle_finding($chemin, 'haut', 'couverture', 'Chemin illisible : couverture du scan incomplète', 'Vérifiez les permissions du serveur web')];
	}
	if (strpos($rel, '@sentinelle-lien:') === 0) {
		$chemin = substr($rel, strlen('@sentinelle-lien:'));
		return [sentinelle_finding($chemin, 'moyen', 'couverture', 'Lien symbolique non suivi par sécurité', 'Vérifiez séparément sa cible')];
	}
	if (substr($rel, -1) === '/') {
		return [sentinelle_finding(
			$rel,
			'critique',
			'repertoire_interdit',
			'Arborescence WordPress sur une installation SPIP',
			'Répertoire ' . $rel . ' — SPIP n\'en crée aucun de ce nom'
		)];
	}

	if (!is_file($absolu)) {
		return [sentinelle_finding($rel, 'moyen', 'couverture', 'Chemin disparu pendant le scan', 'Relancez le scan pour confirmer')];
	}
	if (!is_readable($absolu)) {
		return [sentinelle_finding($rel, 'haut', 'couverture', 'Fichier illisible : couverture du scan incomplète', 'Vérifiez les permissions du serveur web')];
	}

	$findings = [];
	$nom = basename($rel);
	$taille = (int) filesize($absolu);
	$mtime = (int) filemtime($absolu);
	$md5 = (string) md5_file($absolu);
	$meta = ['md5' => $md5, 'taille' => $taille, 'mtime' => $mtime];

	// --- Règle 1 : hash de malware confirmé (certitude) -------------------
	$hashes = sentinelle_ioc_hashes();
	if (isset($hashes[$md5])) {
		$findings[] = sentinelle_finding($rel, 'critique', 'hash', $hashes[$md5], 'md5 ' . $md5, $meta);
	}

	// --- Règle 2 : nom de fichier catalogué -------------------------------
	// Ces noms n'existent nulle part dans SPIP : ils valent partout, y compris
	// dans ecrire/ où l'attaquant a effectivement déposé filefuns.php.
	$noms = sentinelle_ioc_noms();
	if (isset($noms[$nom])) {
		$findings[] = sentinelle_finding($rel, 'critique', 'nom', $noms[$nom], 'Nom catalogué : ' . $nom, $meta);
	}

	$dans_core = sentinelle_scan_dans_core($rel);

	// --- Règle 3 : nom générique de dropper, hors arborescence livrée ------
	if (!$dans_core && in_array($nom, sentinelle_ioc_noms_generiques(), true)) {
		$findings[] = sentinelle_finding(
			$rel,
			'moyen',
			'nom_generique',
			'Nom utilisé par les copies du file manager indonésien',
			'Indice seul — à confirmer par le hash ou le contenu',
			$meta
		);
	}

	// --- Règle 4 : motif de nom suspect -----------------------------------
	foreach (sentinelle_ioc_noms_motifs() as $motif => $regle) {
		// Les motifs de gravité « moyen » reposent sur la seule forme du nom :
		// dans vendor/ et plugins-dist/, le CamelCase PSR-4 les ferait sonner
		// sur des centaines de fichiers parfaitement légitimes.
		if ($dans_core && $regle['gravite'] === 'moyen') {
			continue;
		}
		if (preg_match($motif, $nom)) {
			$findings[] = sentinelle_finding($rel, $regle['gravite'], 'nom_motif', $regle['libelle'], 'Nom : ' . $nom, $meta);
		}
	}

	// --- Règle 5 : PHP dans un répertoire de données ----------------------
	$findings = array_merge($findings, sentinelle_scan_php_donnees($rel, $meta));

	// --- Lecture du contenu ------------------------------------------------
	if ($taille > _SENTINELLE_TAILLE_MAX) {
		$findings[] = sentinelle_finding(
			$rel,
			'moyen',
			'taille',
			'Fichier trop volumineux pour être analysé (' . round($taille / 1048576, 1) . ' Mo)',
			'Contenu non lu — à vérifier à la main',
			$meta
		);
		return $findings;
	}

	$contenu = (string) file_get_contents($absolu);

	// --- Règle 6 : .htaccess ------------------------------------------------
	if ($nom === '.htaccess') {
		return array_merge($findings, sentinelle_scan_htaccess($rel, $contenu, $meta));
	}

	// Les règles qui lisent le contenu ne s'appliquent pas aux fichiers de
	// Sentinelle : son catalogue d'IOC les contient tous par construction.
	if (sentinelle_scan_est_sentinelle($racine, $rel)) {
		return $findings;
	}

	// --- Règle 7 : marqueurs textuels ---------------------------------------
	foreach (sentinelle_ioc_marqueurs() as $marqueur => $regle) {
		if (stripos($contenu, $marqueur) !== false) {
			$findings[] = sentinelle_finding(
				$rel,
				$regle['gravite'],
				'marqueur',
				$regle['libelle'],
				'Marqueur trouvé : ' . $marqueur,
				$meta
			);
		}
	}

	// --- Règle 8 : motifs de haute confiance --------------------------------
	foreach (sentinelle_ioc_motifs() as $motif => $regle) {
		if (preg_match($motif, $contenu)) {
			$findings[] = sentinelle_finding($rel, $regle['gravite'], 'motif', $regle['libelle'], $motif, $meta);
		}
	}

	// --- Règle 9 : heuristiques pondérées -----------------------------------
	if (!sentinelle_scan_est_exclu($rel)) {
		$findings = array_merge($findings, sentinelle_scan_heuristiques($rel, $contenu, $meta));
	}

	return $findings;
}

/**
 * Le chemin est-il un fichier de Sentinelle elle-même ?
 *
 * Le catalogue d'IOC porte ses marqueurs en clair — c'est ce qui le rend
 * relisible et auditable — si bien que `lib/ioc.php` déclenche dix règles
 * « marqueur » sur lui-même, et `lib/scanner.php` une onzième (« BiaoJiOk »
 * apparaît dans un libellé). Les trois règles qui lisent le contenu (7, 8, 9)
 * sont donc coupées sur le répertoire du plugin.
 *
 * Les règles de forme restent actives : un webshell *connu* déposé dans
 * `plugins/spip-sentinelle/` est toujours vu par son hash (règle 1), son nom
 * catalogué (2) ou son nom générique de dropper (3). Un webshell inédit n'y est
 * visible que par `coherence` — le répertoire du plugin étant inscriptible et
 * servi par Apache, c'est une raison de plus de poser l'empreinte de référence.
 *
 * Le préfixe est calculé une fois par racine : `realpath()` sur chaque fichier
 * coûterait un appel système par entrée d'arborescence.
 */
function sentinelle_scan_est_sentinelle(string $racine, string $rel): bool {
	static $prefixe = null;
	static $pour = null;

	if ($pour !== $racine) {
		$pour = $racine;
		$prefixe = null;
		$base = realpath($racine);
		$moi = realpath(dirname(__DIR__));
		if ($base !== false && $moi !== false) {
			$base = rtrim(str_replace('\\', '/', $base), '/');
			$moi = rtrim(str_replace('\\', '/', $moi), '/');
			if ($moi === $base) {
				// La racine scannée est le plugin lui-même (cas du CLI).
				$prefixe = '';
			} elseif (strpos($moi, $base . '/') === 0) {
				$prefixe = substr($moi, strlen($base) + 1);
			}
		}
	}

	// Plugin hors de l'arborescence scannée : rien à exclure.
	if ($prefixe === null) {
		return false;
	}

	if ($prefixe === '') {
		return in_array($rel, ['lib/ioc.php', 'lib/scanner.php'], true);
	}
	return in_array($rel, [$prefixe . '/lib/ioc.php', $prefixe . '/lib/scanner.php'], true);
}

/**
 * Le chemin appartient-il à l'arborescence livrée par SPIP ou ses dépendances ?
 */
function sentinelle_scan_dans_core(string $rel): bool {
	foreach (sentinelle_ioc_arborescence_core() as $motif) {
		if (preg_match($motif, $rel)) {
			return true;
		}
	}
	return false;
}

/**
 * Le chemin est-il exclu des heuristiques génériques (core SPIP, vendor) ?
 */
function sentinelle_scan_est_exclu(string $rel): bool {
	foreach (sentinelle_ioc_exclusions() as $motif) {
		if (preg_match($motif, $rel)) {
			return true;
		}
	}
	return false;
}

/**
 * Un fichier PHP dans IMG/, local/ ou tmp/ est-il légitime ?
 *
 * @return array[]
 */
function sentinelle_scan_php_donnees(string $rel, array $meta): array {
	$racine_dir = strtok($rel, '/');
	if (!in_array($racine_dir, sentinelle_ioc_repertoires_donnees(), true)) {
		return [];
	}

	$ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
	if (!in_array($ext, ['php', 'phtml', 'phar', 'php5', 'php7', 'php8'], true)) {
		return [];
	}

	foreach (sentinelle_ioc_php_legitimes_donnees() as $motif) {
		if (preg_match($motif, $rel)) {
			return [];
		}
	}

	return [sentinelle_finding(
		$rel,
		'critique',
		'php_donnees',
		'Fichier PHP dans un répertoire de données inscriptible par le serveur web',
		'Aucun PHP légitime dans ' . $racine_dir . '/ hors cache SPIP connu',
		$meta
	)];
}

/**
 * Analyse d'un `.htaccess`.
 *
 * @return array[]
 */
function sentinelle_scan_htaccess(string $rel, string $contenu, array $meta): array {
	$findings = [];

	// Extension ajoutée par l'antivirus de l'hébergeur, listée par l'attaquant
	// pour survivre au nettoyage automatique.
	if (stripos($contenu, 'suspected') !== false) {
		$findings[] = sentinelle_finding(
			$rel,
			'haut',
			'htaccess',
			'.htaccess mentionnant la quarantaine antivirus (.suspected)',
			'Configuration inhabituelle à vérifier ; elle peut aussi être défensive',
			$meta
		);
	}

	// Liste blanche WordPress sur une installation SPIP.
	if (preg_match('#(wp-login\.php|admin-ajax\.php|xmlrpc\.php|wp-settings\.php)#i', $contenu)) {
		$findings[] = sentinelle_finding(
			$rel,
			'critique',
			'htaccess',
			'Liste blanche de fichiers WordPress dans un .htaccess de site SPIP',
			'Forme WordPress — verrouillage anti-concurrence du kit BiaoJiOk',
			$meta
		);
	}

	// Variantes de casse de l'extension php : signature du blocage attaquant.
	if (preg_match('#FilesMatch[^>]*(pHp|PHp|phP|PhP|pHP)#', $contenu)) {
		$findings[] = sentinelle_finding(
			$rel,
			'haut',
			'htaccess',
			'FilesMatch énumérant les variantes de casse de « php »',
			'Configuration inhabituelle à vérifier ; son origine n’est pas établie',
			$meta
		);
	}

	// RewriteBase non commenté : SPIP le livre commenté (#RewriteBase /).
	if (preg_match('#^\s*RewriteBase\s+/\s*$#mi', $contenu)
		&& preg_match('#RewriteRule\s+\.\s+index\.php#i', $contenu)) {
		$findings[] = sentinelle_finding(
			$rel,
			'haut',
			'htaccess',
			'Réécriture d\'URL de forme WordPress (RewriteBase actif + fallback index.php)',
			'SPIP livre cette ligne commentée',
			$meta
		);
	}

	// .htaccess racine anormalement court : SPIP en livre ~136 lignes.
	if ($rel === '.htaccess' && substr_count($contenu, "\n") < 25) {
		$findings[] = sentinelle_finding(
			$rel,
			'haut',
			'htaccess',
			'.htaccess racine anormalement court (' . (substr_count($contenu, "\n") + 1) . ' lignes)',
			'Le .htaccess livré par SPIP en fait environ 136',
			$meta
		);
	}

	return $findings;
}

/**
 * Heuristiques génériques pondérées.
 *
 * Aucun motif ne déclenche seul : le finding n'existe que si la somme des
 * poids dépasse le seuil. Réduit fortement les faux positifs.
 *
 * @return array[]
 */
function sentinelle_scan_heuristiques(string $rel, string $contenu, array $meta): array {
	$score = 0;
	$touches = [];

	foreach (sentinelle_ioc_heuristiques() as $motif => $regle) {
		if (preg_match($motif, $contenu)) {
			$score += $regle['poids'];
			$touches[] = $regle['libelle'];
		}
	}

	if ($score < sentinelle_ioc_seuil_heuristique()) {
		return [];
	}

	$gravite = $score >= 130 ? 'critique' : 'haut';

	return [sentinelle_finding(
		$rel,
		$gravite,
		'heuristique',
		'Faisceau d\'indices d\'obfuscation (score ' . $score . ')',
		implode(' · ', $touches),
		$meta + ['score' => $score]
	)];
}

/**
 * Contrôles de posture, indépendants de toute compromission détectée.
 *
 * @return array[]
 */
function sentinelle_scan_posture(string $racine): array {
	$racine = rtrim(str_replace('\\', '/', $racine), '/');
	$findings = [];

	// 1. Version de SPIP — les deux CVE de l'été 2026 sont corrigées en 4.4.21.
	$version = sentinelle_scan_version_spip($racine);
	$minimale = sentinelle_ioc_version_spip_minimale();
	if ($version === null) {
		$findings[] = sentinelle_finding('', 'moyen', 'posture', 'Version de SPIP indéterminée', 'CHANGELOG.md illisible ou absent');
	} elseif (version_compare($version, $minimale, '<')) {
		$findings[] = sentinelle_finding(
			'',
			'critique',
			'posture',
			'SPIP ' . $version . ' — vulnérable à CVE-2026-77647 et CVE-2026-77806 (RCE non authentifiée, CVSS 9.8)',
			'Version minimale corrigée : ' . $minimale . '. Les deux failles sont exploitées en conditions réelles.'
		);
	}

	// 2. Écran de sécurité — les 2 sites qui en étaient dépourvus étaient les
	//    2 plus profondément compromis.
	if (!is_file($racine . '/config/ecran_securite.php')) {
		$findings[] = sentinelle_finding(
			'config/ecran_securite.php',
			'haut',
			'posture',
			'Écran de sécurité SPIP absent',
			'Corrélation observée : absence d\'écran ↔ compromission profonde'
		);
	}

	// 3. Répertoires de données sans .htaccess : tout upload réussi y devient
	//    directement exécutable. SPIP protège tmp/ et config/, pas IMG/ ni local/.
	foreach (['IMG', 'local'] as $dir) {
		if (is_dir($racine . '/' . $dir) && !is_file($racine . '/' . $dir . '/.htaccess')) {
			$findings[] = sentinelle_finding(
				$dir . '/',
				'haut',
				'posture',
				'Répertoire inscriptible sans .htaccess : le PHP qui y est déposé est exécutable',
				'Ajouter un .htaccess interdisant l\'exécution PHP dans ' . $dir . '/'
			);
		}
	}

	// 4. Mitigation .htaccess des deux CVE, tant que le core n'est pas à jour.
	$htaccess = @file_get_contents($racine . '/.htaccess');
	if ($htaccess !== false
		&& $version !== null
		&& version_compare($version, $minimale, '<')
		&& !preg_match('#(X-Spip-Filtre|html_entity_decode)#i', $htaccess)) {
		$findings[] = sentinelle_finding(
			'.htaccess',
			'haut',
			'posture',
			'Aucune mitigation .htaccess des CVE sur un SPIP non corrigé',
			'Bloquer les query strings contenant html_entity_decode|var_export|X-Spip-Filtre. Mitigation partielle : une variante /spip.php?a=&b= la contourne.'
		);
	}

	// 5. Identifiants en clair dans config/connect.php.
	//    Sur SQLite3 ces champs sont inertes, mais lisibles par tout webshell.
	$connect = @file_get_contents($racine . '/config/connect.php');
	if ($connect !== false
		&& preg_match('#spip_connect_db\s*\(\s*[\'"][^\'"]*[\'"]\s*,\s*[\'"][^\'"]*[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]\s*,\s*[\'"]([^\'"]+)[\'"]#', $connect, $m)
		&& stripos($connect, 'sqlite') !== false) {
		$findings[] = sentinelle_finding(
			'config/connect.php',
			'critique',
			'posture',
			'Identifiant et mot de passe en clair dans connect.php alors que la base est SQLite',
			'Ces champs sont inertes pour SQLite mais lisibles par tout webshell présent. Considérer ce couple comme divulgué et le changer partout où il est réutilisé. (Valeur volontairement non recopiée ici.)'
		);
	}

	// 6. Fichiers PHP inscriptibles par tous à la racine.
	foreach (['index.php', 'spip.php', '.htaccess', 'config/connect.php'] as $sensible) {
		$chemin = $racine . '/' . $sensible;
		if (is_file($chemin) && (fileperms($chemin) & 0002)) {
			$findings[] = sentinelle_finding(
				$sensible,
				'moyen',
				'posture',
				'Fichier sensible inscriptible par tous (' . substr(sprintf('%o', fileperms($chemin)), -4) . ')',
				'Restreindre à 0644 au plus'
			);
		}
	}

	return $findings;
}

/**
 * Version de SPIP, lue dans CHANGELOG.md.
 *
 * `ecrire/inc_version.php` s'est révélé peu fiable pour cette détection sur
 * les installations analysées (retour vide) — le CHANGELOG est plus sûr.
 */
function sentinelle_scan_version_spip(string $racine): ?string {
	$changelog = @file_get_contents($racine . '/CHANGELOG.md', false, null, 0, 4096);
	if ($changelog !== false && preg_match('~^\#{1,3}\s*v?(\d+\.\d+\.\d+)~m', $changelog, $m)) {
		return $m[1];
	}

	// Repli : lecture TEXTUELLE de inc_version.php (jamais include()).
	$inc = @file_get_contents($racine . '/ecrire/inc_version.php', false, null, 0, 8192);
	if ($inc !== false && preg_match('#\$spip_version_branche\s*=\s*[\'"](\d+\.\d+\.\d+)[\'"]#', $inc, $m)) {
		return $m[1];
	}

	return null;
}

/**
 * Trie une liste de findings par gravité décroissante puis par chemin.
 */
function sentinelle_trier_findings(array $findings): array {
	$ordre = ['critique' => 0, 'haut' => 1, 'moyen' => 2, 'info' => 3];
	usort($findings, function ($a, $b) use ($ordre) {
		$ga = $ordre[$a['gravite']] ?? 9;
		$gb = $ordre[$b['gravite']] ?? 9;
		if ($ga !== $gb) {
			return $ga <=> $gb;
		}
		return strcmp($a['chemin'], $b['chemin']);
	});
	return $findings;
}

/**
 * Compte les findings par gravité.
 *
 * @return array<string,int>
 */
function sentinelle_compter_findings(array $findings): array {
	$compte = ['critique' => 0, 'haut' => 0, 'moyen' => 0, 'info' => 0];
	foreach ($findings as $f) {
		$g = $f['gravite'] ?? 'info';
		$compte[$g] = ($compte[$g] ?? 0) + 1;
	}
	return $compte;
}
