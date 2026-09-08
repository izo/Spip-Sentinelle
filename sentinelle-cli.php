<?php

/**
 * Sentinelle — scanner en ligne de commande.
 *
 * Autonome : ne charge pas SPIP, n'a besoin d'aucune base. Utilisable sur une
 * copie locale d'un site, ou depuis le gestionnaire de tâches planifiées
 * d'Infomaniak (qui exécute du PHP en CLI sans donner d'accès SSH).
 *
 * Usage :
 *   php sentinelle-cli.php scan       <racine> [--json] [--quarantaine]
 *   php sentinelle-cli.php baseline   <racine>            (poser l'empreinte)
 *   php sentinelle-cli.php coherence  <racine> [--json]   (comparer à l'empreinte)
 *   php sentinelle-cli.php restaurer  <racine> <chemin>
 *   php sentinelle-cli.php liste      <racine>            (quarantaine active)
 *
 * @package Sentinelle
 */

if (PHP_SAPI !== 'cli') {
	header('HTTP/1.1 403 Forbidden');
	exit("Sentinelle CLI ne s'exécute qu'en ligne de commande.\n");
}

require_once __DIR__ . '/lib/ioc.php';
require_once __DIR__ . '/lib/scanner.php';
require_once __DIR__ . '/lib/baseline.php';
require_once __DIR__ . '/lib/quarantaine.php';

$argv = $_SERVER['argv'];
$commande = $argv[1] ?? '';
$racine = isset($argv[2]) ? rtrim($argv[2], '/') : '';
$options = array_slice($argv, 3);
$json = in_array('--json', $options, true);

if ($commande === '' || $racine === '') {
	sentinelle_cli_usage();
	exit(2);
}
if (!is_dir($racine)) {
	fwrite(STDERR, "Racine introuvable : $racine\n");
	exit(2);
}

switch ($commande) {
	case 'scan':
		exit(sentinelle_cli_scan($racine, $json, in_array('--quarantaine', $options, true)));

	case 'baseline':
		exit(sentinelle_cli_baseline($racine));

	case 'coherence':
		exit(sentinelle_cli_coherence($racine, $json));

	case 'restaurer':
		$cible = $options[0] ?? '';
		if ($cible === '') {
			fwrite(STDERR, "Chemin à restaurer manquant.\n");
			exit(2);
		}
		$r = sentinelle_quarantaine_restaurer($racine, $cible);
		echo $r['message'] . "\n";
		exit($r['ok'] ? 0 : 1);

	case 'liste':
		exit(sentinelle_cli_liste($racine));

	default:
		sentinelle_cli_usage();
		exit(2);
}

// ---------------------------------------------------------------------------

function sentinelle_cli_usage(): void {
	echo <<<TXT
	Sentinelle — scanner SPIP hors ligne.

	  php sentinelle-cli.php scan      <racine> [--json] [--quarantaine]
	  php sentinelle-cli.php baseline  <racine>
	  php sentinelle-cli.php coherence <racine> [--json]
	  php sentinelle-cli.php restaurer <racine> <chemin-relatif>
	  php sentinelle-cli.php liste     <racine>

	Code de sortie de « scan » et « coherence » :
	  0 = rien de critique · 1 = au moins un finding critique · 2 = erreur d'usage

	TXT;
}

function sentinelle_cli_scan(string $racine, bool $json, bool $quarantaine): int {
	$debut = microtime(true);

	$fichiers = sentinelle_scan_lister($racine);
	$findings = sentinelle_scan_posture($racine);
	foreach ($fichiers as $rel) {
		$findings = array_merge($findings, sentinelle_scan_chemin($racine, $rel));
	}
	$findings = sentinelle_trier_findings($findings);

	$quarantines = [];
	if ($quarantaine) {
		$lot = sentinelle_quarantaine_nouveau_lot();
		foreach ($findings as $f) {
			if ($f['gravite'] !== 'critique' || $f['regle'] === 'posture' || $f['chemin'] === '') {
				continue;
			}
			$r = sentinelle_quarantaine_deplacer($racine, $f['chemin'], $lot, $f['regle'] . ' — ' . $f['libelle']);
			$quarantines[] = $r['message'];
		}
	}

	$duree = round(microtime(true) - $debut, 2);
	$compte = sentinelle_compter_findings($findings);

	if ($json) {
		echo json_encode([
			'racine'    => $racine,
			'date'      => date('c'),
			'analyses'  => count($fichiers),
			'duree'     => $duree,
			'compte'    => $compte,
			'findings'  => $findings,
			'quarantaine' => $quarantines,
		], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), "\n";
	} else {
		sentinelle_cli_afficher($racine, $findings, count($fichiers), $duree);
		foreach ($quarantines as $m) {
			echo "  → $m\n";
		}
	}

	return $compte['critique'] > 0 ? 1 : 0;
}

function sentinelle_cli_baseline(string $racine): int {
	$baseline = sentinelle_baseline_construire($racine);
	$chemin = sentinelle_repertoire_etat($racine) . '/baseline.json';
	$ok = sentinelle_etat_ecrire_fichier(sentinelle_repertoire_etat($racine), 'baseline.json', $baseline);

	if (!$ok) {
		fwrite(STDERR, "Écriture impossible : $chemin\n");
		return 1;
	}

	echo "Empreinte de référence posée : {$baseline['nombre']} fichiers\n";
	echo "  $chemin\n\n";
	echo "⚠ Cette empreinte fige l'état ACTUEL du site. Si le site est déjà\n";
	echo "  compromis, elle fige la compromission. Poser l'empreinte après\n";
	echo "  nettoyage, jamais avant.\n";
	return 0;
}

function sentinelle_cli_coherence(string $racine, bool $json): int {
	$chemin = sentinelle_repertoire_etat($racine) . '/baseline.json';
	if (!is_file($chemin)) {
		fwrite(STDERR, "Aucune empreinte de référence. Lancer d'abord : baseline\n");
		return 2;
	}

	$baseline = json_decode((string) file_get_contents($chemin), true);
	if (empty($baseline['fichiers'])) {
		fwrite(STDERR, "Empreinte de référence vide ou invalide : $chemin\nRelancer : baseline\n");
		return 2;
	}

	$findings = sentinelle_trier_findings(sentinelle_baseline_comparer($racine, $baseline));
	$resume = sentinelle_baseline_resume($findings);

	if ($json) {
		echo json_encode([
			'reference' => date('c', (int) $baseline['genere_le']),
			'resume'    => $resume,
			'findings'  => $findings,
		], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), "\n";
		return $resume['ajouts'] + $resume['modifies'] > 0 ? 1 : 0;
	}

	echo "Cohérence — référence du " . date('Y-m-d H:i', (int) $baseline['genere_le']) . "\n";
	echo "  {$resume['ajouts']} ajout(s) · {$resume['modifies']} modification(s) · {$resume['disparus']} disparition(s)\n\n";
	foreach ($findings as $f) {
		printf("  [%-8s] %s\n            %s\n", $f['gravite'], $f['chemin'], $f['libelle']);
	}

	return $resume['ajouts'] + $resume['modifies'] > 0 ? 1 : 0;
}

function sentinelle_cli_liste(string $racine): int {
	$actives = sentinelle_quarantaine_actives($racine);
	if (!$actives) {
		echo "Quarantaine vide.\n";
		return 0;
	}
	echo count($actives) . " fichier(s) en quarantaine :\n\n";
	foreach ($actives as $e) {
		printf(
			"  %s\n    lot %s · %d o · md5 %s\n    motif : %s\n\n",
			$e['chemin'],
			$e['lot'],
			$e['taille'],
			$e['md5'],
			$e['motif']
		);
	}
	echo "Restaurer : php sentinelle-cli.php restaurer $racine <chemin>\n";
	return 0;
}

function sentinelle_cli_afficher(string $racine, array $findings, int $analyses, float $duree): void {
	$compte = sentinelle_compter_findings($findings);

	echo "\nSentinelle — $racine\n";
	echo str_repeat('─', 72) . "\n";
	echo "$analyses fichiers analysés en {$duree}s\n";
	echo "{$compte['critique']} critique · {$compte['haut']} haut · {$compte['moyen']} moyen · {$compte['info']} info\n\n";

	if (!$findings) {
		echo "Aucun IOC connu détecté sur ce périmètre.\n";
		echo "Ce n'est pas une preuve d'absence de compromission : un webshell inédit\n";
		echo "ne sera vu que par la vérification de cohérence (commande « coherence »).\n";
		return;
	}

	$gravite_courante = '';
	foreach ($findings as $f) {
		if ($f['gravite'] !== $gravite_courante) {
			$gravite_courante = $f['gravite'];
			echo "\n" . strtoupper($gravite_courante) . "\n" . str_repeat('─', 72) . "\n";
		}
		echo '  ' . ($f['chemin'] !== '' ? $f['chemin'] : '(posture du site)') . "\n";
		echo '    ' . $f['libelle'] . "\n";
		if ($f['preuve'] !== '') {
			echo '    ' . $f['preuve'] . "\n";
		}
		if (!empty($f['md5'])) {
			echo '    md5 ' . $f['md5'] . ' · ' . $f['taille'] . " o · " . date('Y-m-d H:i', $f['mtime']) . "\n";
		}
		echo "\n";
	}
}
