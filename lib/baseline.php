<?php

/**
 * Sentinelle — empreinte de référence et vérification de cohérence.
 *
 * Le scan par IOC ne trouve que ce qui est déjà catalogué. L'empreinte de
 * référence est le seul mécanisme qui repère un webshell inédit : elle compare
 * l'arborescence à un état de référence connu et signale tout ajout,
 * toute modification et toute disparition.
 *
 * À poser sur un site propre — sinon elle fige la compromission.
 *
 * @package Sentinelle\Lib
 */

if (defined('_SENTINELLE_BASELINE')) {
	return;
}
define('_SENTINELLE_BASELINE', '1.0');

require_once __DIR__ . '/ioc.php';
require_once __DIR__ . '/scanner.php';

/**
 * Répertoires dont le contenu change en fonctionnement normal.
 *
 * Les inclure produirait des centaines de différences à chaque cron : le bruit
 * finirait par masquer le signal.
 *
 * @return string[] motifs regex sur le chemin relatif
 */
function sentinelle_baseline_volatils(): array {
	return [
		'#^tmp/#',
		'#^local/#',
		'#^IMG/#',
		'#^\.git(/|$)#',
	];
}

/**
 * Le chemin fait-il partie du périmètre figé par l'empreinte ?
 */
function sentinelle_baseline_dans_perimetre(string $rel): bool {
	foreach (sentinelle_baseline_volatils() as $motif) {
		if (preg_match($motif, $rel)) {
			return false;
		}
	}
	return true;
}

/**
 * Extensions figées dans l'empreinte : le code exécutable et la configuration.
 *
 * Les images et les CSS ne sont pas suivis — leur altération n'est pas le
 * vecteur observé, et les suivre triplerait le temps de calcul.
 *
 * @return string[]
 */
function sentinelle_baseline_extensions(): array {
	return ['php', 'phtml', 'phar', 'php5', 'php7', 'php8', 'inc', 'html', 'htaccess', 'ini', 'yaml', 'xml', 'js'];
}

/**
 * Construit l'empreinte de référence : chemin relatif => md5.
 *
 * @return array{genere_le:int,racine:string,nombre:int,fichiers:array<string,string>}
 */
function sentinelle_baseline_construire(string $racine): array {
	$racine = rtrim(str_replace('\\', '/', $racine), '/');
	$fichiers = [];
	$extensions = array_flip(sentinelle_baseline_extensions());

	if (!is_dir($racine)) {
		return ['genere_le' => time(), 'racine' => $racine, 'nombre' => 0, 'fichiers' => []];
	}

	$parcours = new RecursiveIteratorIterator(
		new RecursiveCallbackFilterIterator(
			new RecursiveDirectoryIterator(
				$racine,
				FilesystemIterator::SKIP_DOTS | FilesystemIterator::UNIX_PATHS
			),
			function ($courant) use ($racine) {
				$rel = sentinelle_chemin_relatif($racine, $courant->getPathname());
				return $rel === '' || sentinelle_baseline_dans_perimetre($rel);
			}
		),
		RecursiveIteratorIterator::LEAVES_ONLY,
		RecursiveIteratorIterator::CATCH_GET_CHILD
	);

	foreach ($parcours as $info) {
		if (!$info->isFile()) {
			continue;
		}
		$rel = sentinelle_chemin_relatif($racine, $info->getPathname());
		$nom = $info->getFilename();
		$ext = strtolower(pathinfo($nom, PATHINFO_EXTENSION));

		if (!isset($extensions[$ext]) && strpos($nom, '.') !== 0) {
			continue;
		}
		$md5 = @md5_file($info->getPathname());
		if ($md5 !== false) {
			$fichiers[$rel] = $md5;
		}
	}

	ksort($fichiers);

	return [
		'genere_le' => time(),
		'racine'    => $racine,
		'nombre'    => count($fichiers),
		'fichiers'  => $fichiers,
	];
}

/**
 * Compare l'état courant à l'empreinte de référence.
 *
 * @return array[] findings (ajouts, modifications, disparitions)
 */
function sentinelle_baseline_comparer(string $racine, array $baseline): array {
	if (empty($baseline['fichiers'])) {
		return [];
	}

	$courant = sentinelle_baseline_construire($racine)['fichiers'];
	$reference = $baseline['fichiers'];
	$findings = [];

	// Ajouts — c'est ici qu'apparaît un webshell inédit.
	foreach (array_diff_key($courant, $reference) as $rel => $md5) {
		$ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
		$executable = in_array($ext, ['php', 'phtml', 'phar', 'php5', 'php7', 'php8', 'inc'], true);
		$findings[] = sentinelle_finding(
			$rel,
			$executable ? 'critique' : 'moyen',
			'baseline_ajout',
			'Fichier absent de l\'empreinte de référence',
			'Apparu depuis le ' . date('Y-m-d H:i', (int) $baseline['genere_le']),
			['md5' => $md5]
		);
	}

	// Modifications — un fichier du core altéré est toujours anormal.
	foreach (array_intersect_key($courant, $reference) as $rel => $md5) {
		if ($md5 !== $reference[$rel]) {
			$findings[] = sentinelle_finding(
				$rel,
				'critique',
				'baseline_modifie',
				'Fichier modifié depuis l\'empreinte de référence',
				'md5 ' . $reference[$rel] . ' → ' . $md5,
				['md5' => $md5]
			);
		}
	}

	// Disparitions — moins grave, mais un nettoyage sauvage se voit ici.
	foreach (array_diff_key($reference, $courant) as $rel => $md5) {
		$findings[] = sentinelle_finding(
			$rel,
			'moyen',
			'baseline_disparu',
			'Fichier présent dans l\'empreinte mais absent du site',
			'Suppression, renommage, ou mise en quarantaine',
			['md5' => $md5]
		);
	}

	return $findings;
}

/**
 * Résumé chiffré d'une comparaison, pour l'affichage.
 *
 * @return array{ajouts:int,modifies:int,disparus:int}
 */
function sentinelle_baseline_resume(array $findings): array {
	$resume = ['ajouts' => 0, 'modifies' => 0, 'disparus' => 0];
	foreach ($findings as $f) {
		switch ($f['regle'] ?? '') {
			case 'baseline_ajout':
				$resume['ajouts']++;
				break;
			case 'baseline_modifie':
				$resume['modifies']++;
				break;
			case 'baseline_disparu':
				$resume['disparus']++;
				break;
		}
	}
	return $resume;
}
