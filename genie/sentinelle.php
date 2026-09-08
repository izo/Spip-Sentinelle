<?php

/**
 * Sentinelle — tâche périodique entièrement fractionnée.
 *
 * Découverte, analyse et comparaison d'empreinte possèdent chacune un curseur
 * persistant. Chaque passage respecte le même budget et peut reprendre sans
 * recommencer les phases déjà terminées.
 *
 * @plugin Sentinelle
 * @license GNU/GPL
 */

if (!defined('_ECRIRE_INC_VERSION')) {
	return;
}
if (!defined('_SENTINELLE_BUDGET')) {
	define('_SENTINELLE_BUDGET', 12);
}
if (!defined('_SENTINELLE_LOT_MAX')) {
	define('_SENTINELLE_LOT_MAX', 600);
}

/**
 * Un chemin découvert appartient-il à l'empreinte de cohérence ?
 */
function sentinelle_cron_chemin_baseline(string $rel): bool {
	if ($rel === '' || $rel[0] === '@' || substr($rel, -1) === '/' || !sentinelle_baseline_dans_perimetre($rel)) {
		return false;
	}
	$nom = basename($rel);
	$ext = strtolower(pathinfo($nom, PATHINFO_EXTENSION));
	return in_array($ext, sentinelle_baseline_extensions(), true) || strpos($nom, '.') === 0;
}

/**
 * État initial d'un cycle.
 */
function sentinelle_cron_initialiser(string $racine): array {
	return [
		'en_cours' => true,
		'phase' => 'decouverte',
		'demarre_le' => time(),
		'decouverte' => sentinelle_scan_decouverte_initialiser(),
		'file' => [],
		'position' => 0,
		'findings' => sentinelle_scan_posture($racine),
		'baseline_courante' => [],
		'comparaison_position' => 0,
	];
}

/**
 * Ajoute une tranche de différences de baseline.
 */
function sentinelle_cron_comparer_tranche(array $etat, array $baseline, float $deadline): array {
	$reference = (array) ($baseline['fichiers'] ?? []);
	$courante = (array) ($etat['baseline_courante'] ?? []);
	$phase = $etat['phase'];
	$cles = $phase === 'coherence_reference' ? array_keys($reference) : array_keys($courante);
	$traites = 0;
	while ($etat['comparaison_position'] < count($cles) && $traites < _SENTINELLE_LOT_MAX) {
		$rel = $cles[$etat['comparaison_position']++];
		if ($phase === 'coherence_reference') {
			if (!isset($courante[$rel])) {
				$etat['findings'][] = sentinelle_finding(
					$rel, 'moyen', 'baseline_disparu',
					'Fichier présent dans l’empreinte mais absent du site',
					'Suppression, renommage ou mise en quarantaine',
					['md5' => $reference[$rel]]
				);
			} elseif ($courante[$rel] !== $reference[$rel]) {
				$etat['findings'][] = sentinelle_finding(
					$rel, 'critique', 'baseline_modifie',
					'Fichier modifié depuis l’empreinte de référence',
					'md5 ' . $reference[$rel] . ' → ' . $courante[$rel],
					['md5' => $courante[$rel]]
				);
			}
		} elseif (!isset($reference[$rel])) {
			$ext = strtolower(pathinfo($rel, PATHINFO_EXTENSION));
			$executable = in_array($ext, ['php', 'phtml', 'phar', 'php5', 'php7', 'php8', 'inc'], true);
			$etat['findings'][] = sentinelle_finding(
				$rel, $executable ? 'critique' : 'moyen', 'baseline_ajout',
				'Fichier absent de l’empreinte de référence',
				'Apparu depuis le ' . date('Y-m-d H:i', (int) ($baseline['genere_le'] ?? 0)),
				['md5' => $courante[$rel]]
			);
		}
		$traites++;
		if (microtime(true) >= $deadline) {
			break;
		}
	}
	if ($etat['comparaison_position'] >= count($cles)) {
		if ($phase === 'coherence_reference') {
			$etat['phase'] = 'coherence_ajouts';
			$etat['comparaison_position'] = 0;
		} else {
			$etat['phase'] = 'finalisation';
		}
	}
	return $etat;
}

/**
 * Tâche périodique : 1 quand le cycle finit, 0 quand il doit reprendre.
 */
function genie_sentinelle_dist($t) {
	include_spip('inc/sentinelle');
	sentinelle_charger_moteur();
	sentinelle_notifications_rejouer();

	$racine = sentinelle_racine();
	$verrou_dir = sentinelle_repertoire_etat($racine);
	$verrou = @fopen($verrou_dir . '/.cycle.lock', 'c');
	if ($verrou === false || !@flock($verrou, LOCK_EX | LOCK_NB)) {
		if (is_resource($verrou)) {
			fclose($verrou);
		}
		return 0;
	}

	$debut_tranche = microtime(true);
	$deadline = $debut_tranche + _SENTINELLE_BUDGET;
	$etat = sentinelle_etat_lire('etat.json', []);
	if (empty($etat['en_cours']) || empty($etat['phase'])) {
		$etat = sentinelle_cron_initialiser($racine);
	}
	$baseline = sentinelle_etat_lire('baseline.json', []);

	while (microtime(true) < $deadline) {
		if ($etat['phase'] === 'decouverte') {
			$etat['decouverte'] = sentinelle_scan_decouvrir_tranche(
				$racine,
				$etat['decouverte'],
				$deadline,
				_SENTINELLE_LOT_MAX
			);
			$etat['file'] = $etat['decouverte']['fichiers'];
			if (empty($etat['decouverte']['terminee'])) {
				break;
			}
			$etat['phase'] = 'analyse';
			unset($etat['decouverte']);
			continue;
		}

		if ($etat['phase'] === 'analyse') {
			$traites = 0;
			$total = count($etat['file']);
			while ($etat['position'] < $total && $traites < _SENTINELLE_LOT_MAX && microtime(true) < $deadline) {
				$rel = $etat['file'][$etat['position']++];
				$etat['findings'] = array_merge($etat['findings'], sentinelle_scan_chemin($racine, $rel));
				if (!empty($baseline['fichiers']) && sentinelle_cron_chemin_baseline($rel)) {
					$hash = @md5_file($racine . '/' . $rel);
					if ($hash !== false) {
						$etat['baseline_courante'][$rel] = $hash;
					}
				}
				$traites++;
			}
			if ($etat['position'] < $total) {
				break;
			}
			$etat['phase'] = empty($baseline['fichiers']) ? 'finalisation' : 'coherence_reference';
			$etat['comparaison_position'] = 0;
			continue;
		}

		if ($etat['phase'] === 'coherence_reference' || $etat['phase'] === 'coherence_ajouts') {
			$etat = sentinelle_cron_comparer_tranche($etat, $baseline, $deadline);
			if ($etat['phase'] !== 'finalisation') {
				break;
			}
			continue;
		}
		break;
	}

	if ($etat['phase'] !== 'finalisation') {
		$etat['mis_a_jour_le'] = time();
		if (!sentinelle_etat_ecrire('etat.json', $etat)) {
			spip_log('Sentinelle : impossible de persister la tranche ; reprise nécessaire.', 'sentinelle.' . _LOG_ERREUR);
		}
		@flock($verrou, LOCK_UN);
		fclose($verrou);
		return 0;
	}

	$findings = sentinelle_trier_findings($etat['findings']);
	$premier_cycle = sentinelle_dernier_scan() === 0;
	$connus = [];
	foreach (sentinelle_findings_courants() as $ancien) {
		$connus[sentinelle_signature_finding($ancien)] = true;
	}
	$nouveaux = [];
	foreach ($findings as $finding) {
		if (!isset($connus[sentinelle_signature_finding($finding)])) {
			$nouveaux[] = $finding;
		}
	}
	$compte = sentinelle_compter_findings($findings);
	$termine = time();
	$total = count($etat['file']);
	$ok = sentinelle_etat_ecrire('findings.json', [
		'termine_le' => $termine,
		'duree' => max(0, $termine - (int) $etat['demarre_le']),
		'analyses' => $total,
		'compte' => $compte,
		'findings' => $findings,
	]);
	if (!$ok) {
		$etat['erreur'] = 'Impossible d’écrire le résultat final. Vérifiez le stockage privé.';
		$etat['echec_le'] = time();
		sentinelle_etat_ecrire('etat.json', $etat);
		@flock($verrou, LOCK_UN);
		fclose($verrou);
		return 0;
	}

	if ($nouveaux && !$premier_cycle) {
		sentinelle_alerter($nouveaux);
	} else {
		sentinelle_rapporter();
	}
	sentinelle_etat_ecrire('etat.json', [
		'en_cours' => false,
		'phase' => 'termine',
		'fini_le' => $termine,
		'dernier_cycle_reussi' => $termine,
		'analyses' => $total,
	]);
	spip_log(
		'Sentinelle : cycle terminé, ' . $total . ' fichiers, ' . $compte['critique'] . ' critique(s), '
			. count($nouveaux) . ' nouveau(x)',
		'sentinelle.' . ($compte['critique'] ? _LOG_ERREUR : _LOG_INFO)
	);
	@flock($verrou, LOCK_UN);
	fclose($verrou);
	return 1;
}
