<?php

/**
 * Sentinelle — quarantaine réversible, privée et transactionnelle.
 *
 * Les charges sont déplacées hors de la racine publique, sous un nom opaque
 * sans extension exécutable. Le journal est préparé avant le déplacement et
 * permet de réconcilier une opération interrompue.
 *
 * @package Sentinelle\Lib
 */

if (defined('_SENTINELLE_QUARANTAINE')) {
	return;
}
define('_SENTINELLE_QUARANTAINE', '2.0');

require_once __DIR__ . '/state.php';

function sentinelle_repertoire_quarantaine(string $racine): string {
	$etat = sentinelle_repertoire_etat($racine);
	$dir = $etat . '/quarantaine';
	if (is_link($dir)) {
		throw new RuntimeException('La quarantaine ne peut pas être un lien symbolique.');
	}
	if (!is_dir($dir) && !@mkdir($dir, 0700, true)) {
		throw new RuntimeException('Impossible de créer la quarantaine privée.');
	}
	if (!@chmod($dir, 0700) || ((fileperms($dir) & 0077) !== 0)) {
		throw new RuntimeException('Permissions insuffisantes sur la quarantaine privée.');
	}
	$reel = realpath($dir);
	if ($reel === false || !sentinelle_chemin_dans($reel, $etat)) {
		throw new RuntimeException('Quarantaine privée hors de son stockage attendu.');
	}
	return rtrim(str_replace('\\', '/', $reel), '/');
}

/**
 * Sort les charges de l'ancienne quarantaine web de façon non destructive pour
 * le journal source. Seules les entrées actives, confinées et non symboliques
 * sont reprises.
 */
function sentinelle_quarantaine_migrer_legacy(string $racine, string $etat_dir): void {
	$cible_journal = $etat_dir . '/quarantaine.json';
	$ancien_journal = rtrim($racine, '/\\') . '/tmp/sentinelle/quarantaine.json';
	if (is_file($cible_journal) || !is_file($ancien_journal) || is_link($ancien_journal)) {
		return;
	}
	$ancien = json_decode((string) @file_get_contents($ancien_journal), true);
	if (!is_array($ancien)) {
		return;
	}
	$nouveau = [];
	foreach ($ancien as $entree) {
		$rel = (string) ($entree['chemin'] ?? '');
		$destination_ancienne = (string) ($entree['destination'] ?? '');
		if (!empty($entree['restaure']) || sentinelle_quarantaine_autorisee($rel) !== true
			|| strpos($destination_ancienne, 'tmp/sentinelle/quarantaine/') !== 0
			|| !sentinelle_chemin_existant_sur($racine, $destination_ancienne)) {
			continue;
		}
		$source = rtrim($racine, '/\\') . '/' . $destination_ancienne;
		$stat = @lstat($source);
		if ($stat === false) {
			continue;
		}
		$type = (($stat['mode'] & 0170000) === 0040000) ? 'repertoire' : 'fichier';
		$id = sentinelle_quarantaine_id();
		$lot = 'migration-' . date('Ymd-His');
		$lot_dir = sentinelle_repertoire_quarantaine($racine) . '/' . $lot;
		if (!is_dir($lot_dir) && !@mkdir($lot_dir, 0700, true)) {
			continue;
		}
		$lot_stat = @stat($lot_dir);
		if ($lot_stat === false || (int) $lot_stat['dev'] !== (int) $stat['dev']) {
			continue;
		}
		$destination = $lot_dir . '/' . $id . ($type === 'repertoire' ? '.tree' : '.payload');
		if (!@rename($source, $destination) || !@chmod($destination, $type === 'repertoire' ? 0700 : 0600)) {
			continue;
		}
		$apres = @lstat($destination);
		$nouveau[] = [
			'id' => $id, 'lot' => $lot, 'chemin' => $rel,
			'destination' => 'quarantaine/' . $lot . '/' . basename($destination),
			'type' => $type, 'md5' => $type === 'fichier' ? (string) @md5_file($destination) : '',
			'taille' => $type === 'fichier' ? (int) $stat['size'] : 0,
			'mtime' => (int) ($entree['mtime'] ?? $stat['mtime']),
			'permissions' => (int) ($entree['permissions'] ?? ($stat['mode'] & 0777)),
			'dev' => (int) $stat['dev'], 'ino' => (int) $stat['ino'],
			'quarantaine_dev' => (int) ($apres['dev'] ?? 0), 'quarantaine_ino' => (int) ($apres['ino'] ?? 0),
			'motif' => (string) ($entree['motif'] ?? 'migration'),
			'date' => (int) ($entree['date'] ?? time()), 'etat' => 'actif', 'migre_le' => time(),
		];
	}
	if ($nouveau) {
		sentinelle_etat_ecrire_fichier($etat_dir, 'quarantaine.json', $nouveau);
	}
}

/** @return array[] */
function sentinelle_journal_lire(string $racine): array {
	$dir = sentinelle_repertoire_etat($racine);
	sentinelle_quarantaine_migrer_legacy($racine, $dir);
	$journal = sentinelle_etat_modifier_fichier($dir, 'quarantaine.json', function ($journal) use ($racine, $dir) {
		$journal = is_array($journal) ? $journal : [];
		foreach ($journal as &$entree) {
			if (($entree['etat'] ?? '') !== 'prepare') {
				continue;
			}
			$source = rtrim($racine, '/\\') . '/' . ($entree['chemin'] ?? '');
			$destination = $dir . '/' . ($entree['destination'] ?? '');
		if (!file_exists($source) && file_exists($destination)) {
				$stat = @lstat($destination);
				$mode = ($entree['type'] ?? '') === 'repertoire' ? 0700 : 0600;
				if ($stat !== false && @chmod($destination, $mode)) {
					$entree['quarantaine_dev'] = (int) $stat['dev'];
					$entree['quarantaine_ino'] = (int) $stat['ino'];
					$entree['etat'] = 'actif';
					$entree['reconcilie_le'] = time();
				}
			} elseif (file_exists($source) && !file_exists($destination)) {
				$entree['etat'] = 'annule';
				$entree['reconcilie_le'] = time();
			}
		}
		unset($entree);
		return $journal;
	}, []);
	return is_array($journal) ? $journal : [];
}

function sentinelle_journal_ecrire(string $racine, array $journal): bool {
	return sentinelle_etat_ecrire_fichier(sentinelle_repertoire_etat($racine), 'quarantaine.json', $journal);
}

function sentinelle_journal_modifier(string $racine, string $id, callable $mutation): bool {
	$resultat = sentinelle_etat_modifier_fichier(
		sentinelle_repertoire_etat($racine),
		'quarantaine.json',
		function ($journal) use ($id, $mutation) {
			$journal = is_array($journal) ? $journal : [];
			foreach ($journal as &$entree) {
				if (($entree['id'] ?? '') === $id) {
					$entree = $mutation($entree);
					break;
				}
			}
			unset($entree);
			return $journal;
		},
		[]
	);
	return $resultat !== false;
}

/** @return string[] */
function sentinelle_quarantaine_intouchables(): array {
	return [
		'#^\.htaccess$#', '#^index\.php$#', '#^spip\.php$#', '#^config/#',
		'#^ecrire/#', '#^prive/#', '#^squelettes-dist/#', '#^plugins-dist/#',
		// Le répertoire entier est protégé, mais un fichier PHP précisément
		// signalé sous IMG/ doit pouvoir être isolé sans déplacer les médias.
		'#^IMG/$#', '#^local/$#',
	];
}

function sentinelle_chemin_relatif_valide(string $rel): bool {
	if ($rel === '' || $rel[0] === '/' || strpos($rel, "\0") !== false || strpos($rel, '\\') !== false) {
		return false;
	}
	foreach (explode('/', rtrim($rel, '/')) as $segment) {
		if ($segment === '' || $segment === '.' || $segment === '..') {
			return false;
		}
	}
	return true;
}

function sentinelle_chemin_existant_sur(string $base, string $rel): bool {
	$base_reelle = realpath($base);
	if ($base_reelle === false || !sentinelle_chemin_relatif_valide($rel)) {
		return false;
	}
	$courant = rtrim($base_reelle, '/\\');
	foreach (explode('/', rtrim($rel, '/')) as $segment) {
		$courant .= '/' . $segment;
		$stat = @lstat($courant);
		if ($stat === false || (($stat['mode'] & 0170000) === 0120000)) {
			return false;
		}
	}
	$reel = realpath($courant);
	return $reel !== false && sentinelle_chemin_dans($reel, $base_reelle);
}

function sentinelle_arbre_sans_symlink(string $chemin): bool {
	if (is_link($chemin)) {
		return false;
	}
	if (!is_dir($chemin)) {
		return true;
	}
	$iterateur = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator($chemin, FilesystemIterator::SKIP_DOTS),
		RecursiveIteratorIterator::SELF_FIRST,
		RecursiveIteratorIterator::CATCH_GET_CHILD
	);
	foreach ($iterateur as $info) {
		if ($info->isLink()) {
			return false;
		}
	}
	return true;
}

/** @return string|true */
function sentinelle_quarantaine_autorisee(string $rel) {
	if (!sentinelle_chemin_relatif_valide($rel)) {
		return 'Chemin invalide';
	}
	foreach (sentinelle_quarantaine_intouchables() as $motif) {
		if (preg_match($motif, $rel)) {
			return 'Chemin protégé — décision humaine requise (' . $rel . ')';
		}
	}
	return true;
}

function sentinelle_quarantaine_id(): string {
	try {
		return bin2hex(random_bytes(16));
	} catch (Exception $e) {
		return hash('sha256', uniqid('', true) . mt_rand());
	}
}

/**
 * Valide tous les champs de sécurité d'une entrée avant de lui faire confiance.
 */
function sentinelle_quarantaine_entree_valide(array $entree): bool {
	$id = (string) ($entree['id'] ?? '');
	$lot = (string) ($entree['lot'] ?? '');
	$type = (string) ($entree['type'] ?? '');
	$extension = $type === 'repertoire' ? '.tree' : '.payload';
	return (bool) preg_match('/^[a-f0-9]{32,64}$/D', $id)
		&& (bool) preg_match('/^[A-Za-z0-9_.-]+$/D', $lot)
		&& in_array($type, ['fichier', 'repertoire'], true)
		&& sentinelle_chemin_relatif_valide((string) ($entree['chemin'] ?? ''))
		&& ($entree['destination'] ?? '') === 'quarantaine/' . $lot . '/' . $id . $extension
		&& isset($entree['dev'], $entree['ino'], $entree['permissions'], $entree['taille'])
		&& (int) $entree['permissions'] >= 0
		&& (int) $entree['permissions'] <= 0777
		&& ($type === 'repertoire' || (bool) preg_match('/^[a-f0-9]{32}$/D', (string) ($entree['md5'] ?? '')));
}

/** @return array{ok:bool,message:string,entree?:array} */
function sentinelle_quarantaine_deplacer(string $racine, string $rel, string $lot, string $motif = ''): array {
	$racine_reelle = realpath($racine);
	if ($racine_reelle === false) {
		return ['ok' => false, 'message' => 'Racine du site introuvable.'];
	}
	$racine_reelle = rtrim(str_replace('\\', '/', $racine_reelle), '/');
	$permis = sentinelle_quarantaine_autorisee($rel);
	if ($permis !== true) {
		return ['ok' => false, 'message' => $permis];
	}
	if (!sentinelle_chemin_existant_sur($racine_reelle, $rel)) {
		return ['ok' => false, 'message' => 'Chemin absent, hors racine ou symbolique : ' . $rel];
	}
	$source = $racine_reelle . '/' . rtrim($rel, '/');
	if (!sentinelle_arbre_sans_symlink($source)) {
		return ['ok' => false, 'message' => 'Lien symbolique détecté — isolement refusé : ' . $rel];
	}
	$avant = @lstat($source);
	if ($avant === false) {
		return ['ok' => false, 'message' => 'Fichier introuvable : ' . $rel];
	}
	$est_repertoire = (($avant['mode'] & 0170000) === 0040000);
	try {
		$etat_dir = sentinelle_repertoire_etat($racine_reelle);
		$quarantaine = sentinelle_repertoire_quarantaine($racine_reelle);
	} catch (RuntimeException $e) {
		return ['ok' => false, 'message' => $e->getMessage() . ' Isolement refusé.'];
	}
	$stat_quarantaine = @stat($quarantaine);
	if ($stat_quarantaine === false || (int) $stat_quarantaine['dev'] !== (int) $avant['dev']) {
		return ['ok' => false, 'message' => 'Quarantaine sur un autre système de fichiers ; déplacement atomique impossible.'];
	}

	$lot = preg_replace('/[^A-Za-z0-9_.-]/', '-', $lot);
	$id = sentinelle_quarantaine_id();
	$lot_dir = $quarantaine . '/' . $lot;
	if (!is_dir($lot_dir) && !@mkdir($lot_dir, 0700, true)) {
		return ['ok' => false, 'message' => 'Impossible de créer le lot de quarantaine.'];
	}
	$destination = $lot_dir . '/' . $id . ($est_repertoire ? '.tree' : '.payload');
	$md5 = $est_repertoire ? '' : (string) @md5_file($source);
	$entree = [
		'id' => $id, 'lot' => $lot, 'chemin' => $rel,
		'destination' => 'quarantaine/' . $lot . '/' . basename($destination),
		'type' => $est_repertoire ? 'repertoire' : 'fichier',
		'md5' => $md5, 'taille' => $est_repertoire ? 0 : (int) $avant['size'],
		'mtime' => (int) $avant['mtime'], 'permissions' => (int) ($avant['mode'] & 0777),
		'dev' => (int) $avant['dev'], 'ino' => (int) $avant['ino'],
		'motif' => $motif, 'date' => time(), 'etat' => 'prepare',
	];
	$prepare = sentinelle_etat_modifier_fichier($etat_dir, 'quarantaine.json', function ($journal) use ($entree) {
		$journal = is_array($journal) ? $journal : [];
		$journal[] = $entree;
		return $journal;
	}, []);
	if ($prepare === false) {
		return ['ok' => false, 'message' => 'Journal indisponible — aucun fichier déplacé.'];
	}

	$juste_avant = @lstat($source);
	if ($juste_avant === false || (int) $juste_avant['dev'] !== (int) $avant['dev'] || (int) $juste_avant['ino'] !== (int) $avant['ino']) {
		sentinelle_journal_modifier($racine_reelle, $id, function ($e) { $e['etat'] = 'annule'; return $e; });
		return ['ok' => false, 'message' => 'Le fichier a changé pendant le contrôle — isolement annulé.'];
	}
	if (!@rename($source, $destination)) {
		sentinelle_journal_modifier($racine_reelle, $id, function ($e) { $e['etat'] = 'annule'; return $e; });
		return ['ok' => false, 'message' => 'Déplacement atomique refusé : ' . $rel];
	}
	if (!@chmod($destination, $est_repertoire ? 0700 : 0600)) {
		@rename($destination, $source);
		sentinelle_journal_modifier($racine_reelle, $id, function ($e) { $e['etat'] = 'annule'; return $e; });
		return ['ok' => false, 'message' => 'Verrouillage impossible ; déplacement annulé : ' . $rel];
	}
	$apres = @lstat($destination);
	$entree['quarantaine_dev'] = (int) ($apres['dev'] ?? 0);
	$entree['quarantaine_ino'] = (int) ($apres['ino'] ?? 0);
	$entree['etat'] = 'actif';
	if (!sentinelle_journal_modifier($racine_reelle, $id, function ($e) use ($entree) { return $entree; })) {
		return ['ok' => false, 'message' => 'Fichier isolé ; journal à réconcilier avant restauration.'];
	}
	return ['ok' => true, 'message' => 'Mis en quarantaine : ' . $rel, 'entree' => $entree];
}

/** @return array{ok:bool,message:string} */
function sentinelle_quarantaine_restaurer(string $racine, string $rel, string $lot = ''): array {
	$racine_reelle = realpath($racine);
	if ($racine_reelle === false || !sentinelle_chemin_relatif_valide($rel)) {
		return ['ok' => false, 'message' => 'Chemin de restauration invalide.'];
	}
	$journal = sentinelle_journal_lire($racine_reelle);
	$entree = null;
	foreach ($journal as $candidate) {
		if (($candidate['chemin'] ?? '') === $rel && ($candidate['etat'] ?? '') === 'actif'
			&& ($lot === '' || ($candidate['lot'] ?? '') === $lot)) {
			$entree = $candidate;
		}
	}
	if (!is_array($entree) || !sentinelle_quarantaine_entree_valide($entree)
		|| sentinelle_quarantaine_autorisee($rel) !== true) {
		return ['ok' => false, 'message' => 'Aucune mise en quarantaine active pour ' . $rel];
	}
	$etat_dir = sentinelle_repertoire_etat($racine_reelle);
	$destination_rel = (string) $entree['destination'];
	if (strpos($destination_rel, 'quarantaine/') !== 0 || !sentinelle_chemin_existant_sur($etat_dir, $destination_rel)) {
		return ['ok' => false, 'message' => 'Journal invalide ou charge symbolique — restauration refusée.'];
	}
	$source = $etat_dir . '/' . $destination_rel;
	$stat = @lstat($source);
	if ($stat === false || (int) ($entree['quarantaine_dev'] ?? $stat['dev']) !== (int) $stat['dev']
		|| (int) ($entree['quarantaine_ino'] ?? $stat['ino']) !== (int) $stat['ino']) {
		return ['ok' => false, 'message' => 'La charge de quarantaine a été remplacée — restauration refusée.'];
	}
	$est_repertoire = ($entree['type'] ?? '') === 'repertoire';
	if (!$est_repertoire) {
		$md5 = @md5_file($source);
		if ($md5 === false || !hash_equals((string) ($entree['md5'] ?? ''), $md5)
			|| (int) ($entree['taille'] ?? -1) !== (int) $stat['size']) {
			return ['ok' => false, 'message' => 'Le contenu isolé ne correspond plus au journal — restauration refusée.'];
		}
	}
	$cible = rtrim($racine_reelle, '/\\') . '/' . $rel;
	if (file_exists($cible) || is_link($cible)) {
		return ['ok' => false, 'message' => 'Un fichier occupe déjà ' . $rel . ' — restauration refusée.'];
	}
	$parent_rel = dirname($rel);
	if ($parent_rel !== '.' && !sentinelle_chemin_existant_sur($racine_reelle, $parent_rel)) {
		return ['ok' => false, 'message' => 'Le répertoire parent est absent ou symbolique — restauration refusée.'];
	}
	sentinelle_journal_modifier($racine_reelle, $entree['id'], function ($e) { $e['etat'] = 'restauration'; return $e; });
	if (!@rename($source, $cible)) {
		sentinelle_journal_modifier($racine_reelle, $entree['id'], function ($e) { $e['etat'] = 'actif'; return $e; });
		return ['ok' => false, 'message' => 'Restauration atomique refusée.'];
	}
	@chmod($cible, (int) ($entree['permissions'] ?: ($est_repertoire ? 0755 : 0644)));
	@touch($cible, (int) ($entree['mtime'] ?? time()));
	if (!sentinelle_journal_modifier($racine_reelle, $entree['id'], function ($e) { $e['etat'] = 'restaure'; $e['restaure_le'] = time(); return $e; })) {
		return ['ok' => false, 'message' => 'Restauré mais journal non mis à jour — intervention manuelle requise.'];
	}
	return ['ok' => true, 'message' => 'Restauré : ' . $rel];
}

/** @return array[] */
function sentinelle_quarantaine_actives(string $racine): array {
	return array_values(array_filter(sentinelle_journal_lire($racine), function ($e) {
		return ($e['etat'] ?? '') === 'actif' && sentinelle_quarantaine_entree_valide($e);
	}));
}

function sentinelle_quarantaine_nouveau_lot(): string {
	return date('Y-m-d_His') . '-' . substr(sentinelle_quarantaine_id(), 0, 8);
}
