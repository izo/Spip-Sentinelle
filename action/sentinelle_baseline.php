<?php

/**
 * Sentinelle — pose de l'empreinte de référence.
 *
 * L'empreinte est le seul mécanisme du plugin qui voie un webshell inédit : le
 * scan par IOC ne trouve que ce qui est déjà catalogué, la comparaison
 * d'empreinte signale tout ce qui bouge.
 *
 * Elle se pose sur un site propre. Posée sur un site encore compromis, elle
 * enregistre le webshell comme faisant partie du décor et ne le signalera plus
 * jamais. Le plugin ne refuse pas ce geste — le nettoyage peut être en cours,
 * et c'est une décision d'exploitant — mais il inscrit dans l'empreinte le
 * nombre d'alertes critiques encore ouvertes au moment de la pose. La pose est
 * refusée par défaut ; l'argument explicite `forcer` constitue la dérogation
 * tracée réservée au webmestre.
 *
 * @plugin Sentinelle
 * @license GNU/GPL
 * @package SPIP\Sentinelle\Action
 */

if (!defined('_ECRIRE_INC_VERSION')) {
	return;
}

/**
 * @param string|null $arg `poser` ou `oublier`
 */
function action_sentinelle_baseline_dist($arg = null) {
	if ($arg === null) {
		$securiser_action = charger_fonction('securiser_action', 'inc');
		$arg = $securiser_action();
	}

	include_spip('inc/sentinelle');

	if (!autoriser('baseline', 'sentinelle')) {
		spip_log(
			'Sentinelle : pose d\'empreinte refusée à '
				. ($GLOBALS['visiteur_session']['id_auteur'] ?? '?'),
			'sentinelle.' . _LOG_ERREUR
		);
		sentinelle_message_ecrire(false, _T('sentinelle:action_autorisation_refusee'));
		return;
	}

	sentinelle_charger_moteur();

	if (trim((string) $arg) === 'oublier') {
		sentinelle_etat_ecrire('baseline.json', []);
		spip_log('Sentinelle : empreinte de référence effacée', 'sentinelle.' . _LOG_INFO_IMPORTANTE);
		sentinelle_message_ecrire(true, _T('sentinelle:action_baseline_effacee'));
		return;
	}

	// La construction relit et hache quelques milliers de fichiers : quelques
	// secondes sur un disque tiède, bien davantage sur un hébergement mutualisé
	// au premier passage. On demande du temps sans jamais compter l'obtenir.
	if (function_exists('set_time_limit')) {
		@set_time_limit(180);
	}

	$compte = sentinelle_etat_lire('findings.json', [])['compte'] ?? [];
	$critiques = (int) ($compte['critique'] ?? 0);
	$forcer = trim((string) $arg) === 'forcer';
	if ($critiques > 0 && !$forcer) {
		sentinelle_message_ecrire(
			false,
			_T('sentinelle:action_baseline_bloquee')
		);
		spip_log('Sentinelle : empreinte bloquée avec ' . $critiques . ' critique(s)', 'sentinelle.' . _LOG_ERREUR);
		return;
	}

	$baseline = sentinelle_baseline_construire(sentinelle_racine());
	$baseline['critiques_a_la_pose'] = $critiques;
	$baseline['pose_par'] = (int) ($GLOBALS['visiteur_session']['id_auteur'] ?? 0);

	if (!$baseline['nombre']) {
		sentinelle_message_ecrire(false, _T('sentinelle:action_baseline_vide'));
		return;
	}

	if (!sentinelle_etat_ecrire('baseline.json', $baseline)) {
		sentinelle_message_ecrire(false, _T('sentinelle:action_baseline_ecriture'));
		return;
	}

	$texte = _T('sentinelle:action_baseline_posee', ['nb' => $baseline['nombre']]);
	if ($critiques > 0) {
		$texte .= ' ' . _T('sentinelle:action_baseline_forcee', ['nb' => $critiques]);
	}

	spip_log(
		'Sentinelle : empreinte posée, ' . $baseline['nombre'] . ' fichiers, '
			. $critiques . ' critique(s) ouvert(s)',
		'sentinelle.' . ($critiques ? _LOG_ERREUR : _LOG_INFO_IMPORTANTE)
	);

	sentinelle_message_ecrire($critiques === 0, $texte);
}
