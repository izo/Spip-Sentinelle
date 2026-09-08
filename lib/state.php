<?php

/**
 * Sentinelle — stockage d'état hors de la racine publique.
 *
 * Les fichiers JSON et les charges isolées ne doivent pas dépendre d'un
 * .htaccess : celui-ci est ignoré par Nginx/Caddy et peut être désactivé sous
 * Apache. Le répertoire est donc placé à côté du site (ou dans le répertoire
 * temporaire système en dernier recours), avec des permissions 0700.
 *
 * @package Sentinelle\Lib
 */

if (defined('_SENTINELLE_STATE')) {
	return;
}
define('_SENTINELLE_STATE', '1.0');

/**
 * Un chemin est-il strictement contenu dans un autre ?
 */
function sentinelle_chemin_dans(string $chemin, string $parent): bool {
	$chemin = rtrim(str_replace('\\', '/', $chemin), '/');
	$parent = rtrim(str_replace('\\', '/', $parent), '/');
	return $chemin === $parent || strpos($chemin, $parent . '/') === 0;
}

/**
 * Racine persistante propre à un site, toujours hors de sa racine publique.
 *
 * Surcharge possible avec la constante _SENTINELLE_ETAT_DIR ou la variable
 * d'environnement SENTINELLE_STATE_DIR. Une surcharge située dans le site est
 * refusée : mieux vaut une opération indisponible qu'une quarantaine servie.
 */
function sentinelle_repertoire_etat(string $racine): string {
	static $memo = [];
	$racine_reelle = realpath($racine);
	if ($racine_reelle === false || !is_dir($racine_reelle)) {
		throw new RuntimeException('Racine du site introuvable pour le stockage Sentinelle.');
	}
	$racine_reelle = rtrim(str_replace('\\', '/', $racine_reelle), '/');
	if (isset($memo[$racine_reelle])) {
		return $memo[$racine_reelle];
	}

	$surcharge = defined('_SENTINELLE_ETAT_DIR') ? (string) _SENTINELLE_ETAT_DIR : '';
	if ($surcharge === '') {
		$surcharge = (string) getenv('SENTINELLE_STATE_DIR');
	}

	$identifiant = substr(hash('sha256', $racine_reelle), 0, 16);
	$candidats = [];
	if ($surcharge !== '') {
		$candidats[] = rtrim($surcharge, '/\\');
	} else {
		$candidats[] = dirname($racine_reelle) . '/.spip-sentinelle-' . $identifiant;
		$candidats[] = rtrim(sys_get_temp_dir(), '/\\') . '/spip-sentinelle/' . $identifiant;
	}

	foreach ($candidats as $dir) {
		$parent = dirname($dir);
		if (!is_dir($parent) && !@mkdir($parent, 0700, true)) {
			continue;
		}
		$parent_reel = realpath($parent);
		if ($parent_reel === false) {
			continue;
		}
		$dir_absolu = rtrim(str_replace('\\', '/', $parent_reel), '/') . '/' . basename($dir);
		if (sentinelle_chemin_dans($dir_absolu, $racine_reelle)) {
			if ($surcharge !== '') {
				throw new RuntimeException('SENTINELLE_STATE_DIR doit être situé hors de la racine publique.');
			}
			continue;
		}
		if (is_link($dir_absolu)) {
			continue;
		}
		if (!is_dir($dir_absolu) && !@mkdir($dir_absolu, 0700, true)) {
			continue;
		}
		$dir_reel = realpath($dir_absolu);
		if ($dir_reel === false || sentinelle_chemin_dans($dir_reel, $racine_reelle)) {
			continue;
		}
		if (!@chmod($dir_absolu, 0700)) {
			continue;
		}
		$mode = @fileperms($dir_absolu);
		if ($mode === false || (($mode & 0077) !== 0)) {
			continue;
		}
		$dir_reel = rtrim(str_replace('\\', '/', $dir_reel), '/');
		$memo[$racine_reelle] = $dir_reel;
		sentinelle_etat_migrer_legacy($racine_reelle, $dir_reel);
		return $dir_reel;
	}

	throw new RuntimeException('Impossible de créer un stockage Sentinelle privé hors de la racine publique.');
}

/**
 * Copie une fois les anciens états JSON depuis tmp/sentinelle sans supprimer
 * la source. La quarantaine est migrée séparément, charge par charge.
 */
function sentinelle_etat_migrer_legacy(string $racine, string $destination): void {
	$ancien = $racine . '/tmp/sentinelle';
	if (!is_dir($ancien) || sentinelle_chemin_dans($destination, $racine)) {
		return;
	}
	foreach (['findings.json', 'baseline.json', 'etat.json', 'message.json', 'rapport.json', 'notifications.json'] as $nom) {
		$cible = $destination . '/' . $nom;
		$source = $ancien . '/' . $nom;
		if (is_file($cible) || !is_file($source) || is_link($source)) {
			continue;
		}
		$contenu = @file_get_contents($source);
		$data = $contenu === false ? null : json_decode($contenu, true);
		if ($contenu !== false && json_last_error() === JSON_ERROR_NONE) {
			sentinelle_etat_ecrire_fichier($destination, $nom, $data);
		}
	}
}

/**
 * Valide un nom de fichier d'état (aucun chemin ni extension arbitraire).
 */
function sentinelle_etat_nom_valide(string $nom): bool {
	return (bool) preg_match('/^[a-z0-9][a-z0-9_.-]*\.json$/D', $nom)
		&& strpos($nom, '..') === false
		&& basename($nom) === $nom;
}

/**
 * Exécute une opération sous un verrou stable propre au fichier d'état.
 *
 * @return mixed
 */
function sentinelle_etat_verrou(string $dir, string $nom, callable $operation) {
	if (!sentinelle_etat_nom_valide($nom)) {
		throw new InvalidArgumentException('Nom de fichier d’état invalide : ' . $nom);
	}
	$verrou = @fopen($dir . '/.' . $nom . '.lock', 'c');
	if ($verrou === false || !@flock($verrou, LOCK_EX)) {
		if (is_resource($verrou)) {
			fclose($verrou);
		}
		throw new RuntimeException('Impossible de verrouiller l’état ' . $nom);
	}
	try {
		return $operation();
	} finally {
		@flock($verrou, LOCK_UN);
		fclose($verrou);
	}
}

/**
 * Lecture JSON stricte. Un fichier corrompu est conservé et signalé.
 *
 * @return mixed
 */
function sentinelle_etat_lire_fichier(string $dir, string $nom, $defaut = []) {
	if (!sentinelle_etat_nom_valide($nom)) {
		return $defaut;
	}
	$chemin = $dir . '/' . $nom;
	if (!is_file($chemin)) {
		return $defaut;
	}
	$contenu = @file_get_contents($chemin);
	if ($contenu === false) {
		error_log('Sentinelle : état illisible — ' . $chemin);
		return $defaut;
	}
	$data = json_decode($contenu, true);
	if (json_last_error() !== JSON_ERROR_NONE) {
		error_log('Sentinelle : JSON corrompu conservé — ' . $chemin . ' (' . json_last_error_msg() . ')');
		return $defaut;
	}
	return $data;
}

/**
 * Écriture JSON atomique sur le même système de fichiers.
 */
function sentinelle_etat_ecrire_fichier(string $dir, string $nom, $data): bool {
	if (!sentinelle_etat_nom_valide($nom)) {
		return false;
	}
	$json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	if ($json === false) {
		return false;
	}

	return (bool) sentinelle_etat_verrou($dir, $nom, function () use ($dir, $nom, $json) {
		$temp = @tempnam($dir, '.' . $nom . '.tmp-');
		if ($temp === false) {
			return false;
		}
		$flux = @fopen($temp, 'wb');
		if ($flux === false) {
			@unlink($temp);
			return false;
		}
		$ok = fwrite($flux, $json) === strlen($json) && fflush($flux);
		if ($ok && function_exists('fsync')) {
			$ok = @fsync($flux);
		}
		fclose($flux);
		$ok = $ok && @chmod($temp, 0600) && @rename($temp, $dir . '/' . $nom);
		if (!$ok) {
			@unlink($temp);
		}
		return $ok;
	});
}

/**
 * Séquence lecture-modification-écriture sous un verrou unique.
 *
 * @return mixed la nouvelle valeur, ou false si l'écriture échoue
 */
function sentinelle_etat_modifier_fichier(string $dir, string $nom, callable $mutation, $defaut = []) {
	return sentinelle_etat_verrou($dir, $nom, function () use ($dir, $nom, $mutation, $defaut) {
		$actuel = sentinelle_etat_lire_fichier($dir, $nom, $defaut);
		$nouveau = $mutation($actuel);
		$json = json_encode($nouveau, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
		if ($json === false) {
			return false;
		}
		$temp = @tempnam($dir, '.' . $nom . '.tmp-');
		if ($temp === false) {
			return false;
		}
		$flux = @fopen($temp, 'wb');
		if ($flux === false) {
			@unlink($temp);
			return false;
		}
		$ok = fwrite($flux, $json) === strlen($json) && fflush($flux);
		if ($ok && function_exists('fsync')) {
			$ok = @fsync($flux);
		}
		fclose($flux);
		$ok = $ok && @chmod($temp, 0600) && @rename($temp, $dir . '/' . $nom);
		if (!$ok) {
			@unlink($temp);
			return false;
		}
		return $nouveau;
	});
}
