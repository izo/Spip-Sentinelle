<?php

/**
 * Sentinelle — scan déclenché à la main.
 *
 * Le cron travaille par tranches parce qu'il s'exécute dans une requête web
 * qu'il ne contrôle pas. Ici l'humain attend devant son écran : on tente le
 * scan complet d'une traite, ce qui donne un résultat immédiat au lieu d'un
 * « revenez dans six heures ».
 *
 * Si l'hébergeur coupe avant la fin, rien n'est corrompu : `findings.json`
 * n'est écrit qu'à la toute fin, et le cycle du cron reprendra normalement.
 *
 * @plugin Sentinelle
 * @license GNU/GPL
 * @package SPIP\Sentinelle\Action
 */

if (!defined('_ECRIRE_INC_VERSION')) {
	return;
}

/**
 * @param string|null $arg inutilisé
 */
function action_sentinelle_scan_dist($arg = null) {
	if ($arg === null) {
		$securiser_action = charger_fonction('securiser_action', 'inc');
		$arg = $securiser_action();
	}

	include_spip('inc/sentinelle');

	if (!autoriser('sentinelle')) {
		spip_log(
			'Sentinelle : scan refusé à ' . ($GLOBALS['visiteur_session']['id_auteur'] ?? '?'),
			'sentinelle.' . _LOG_ERREUR
		);
		sentinelle_message_ecrire(false, _T('sentinelle:action_autorisation_refusee'));
		return;
	}

	sentinelle_charger_moteur();

	if (function_exists('set_time_limit')) {
		@set_time_limit(300);
	}

	$debut = microtime(true);
	$racine = sentinelle_racine();
	$findings = sentinelle_scan_complet();

	$baseline = sentinelle_etat_lire('baseline.json', []);
	if (!empty($baseline['fichiers'])) {
		$findings = sentinelle_trier_findings(
			array_merge($findings, sentinelle_baseline_comparer($racine, $baseline))
		);
	}

	$compte = sentinelle_compter_findings($findings);
	$duree = round(microtime(true) - $debut, 2);

	sentinelle_etat_ecrire('findings.json', [
		'termine_le' => time(),
		'duree'      => $duree,
		'analyses'   => count(sentinelle_scan_lister($racine)),
		'compte'     => $compte,
		'findings'   => $findings,
	]);

	// Le cycle fractionné en cours n'a plus lieu d'être : il écraserait ce
	// résultat avec un état plus ancien.
	sentinelle_etat_ecrire('etat.json', ['en_cours' => false, 'fini_le' => time()]);

	$texte = _T('sentinelle:action_scan_termine', [
		'duree' => $duree,
		'critique' => $compte['critique'],
		'haut' => $compte['haut'],
		'moyen' => $compte['moyen'],
	]);

	if (!$compte['critique'] && !$compte['haut'] && empty($baseline['fichiers'])) {
		$texte .= ' ' . _T('sentinelle:action_scan_sans_baseline');
	}

	spip_log(
		"Sentinelle : scan manuel, {$compte['critique']} critique(s) en {$duree}s",
		'sentinelle.' . ($compte['critique'] ? _LOG_ERREUR : _LOG_INFO)
	);

	sentinelle_message_ecrire($compte['critique'] === 0, $texte);
}
