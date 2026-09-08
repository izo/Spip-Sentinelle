<?php

/**
 * Sentinelle — mise en quarantaine et restauration.
 *
 * L'argument est de la forme `<operation>:<chemin>` :
 *
 *   isoler:plugins-dist/medias/lib/ninja.php   isole un fichier
 *   isoler-tout:                               isole tous les critiques du dernier scan
 *   restaurer:tmp/cache/skel/mount.php         remet un fichier isolé à sa place
 *
 * Deux gardes se cumulent, et elles sont indépendantes :
 *
 * 1. L'autorisation webmestre (`sentinelle_autoriser.php`).
 * 2. Le chemin doit figurer dans les alertes du dernier scan. Sans cette
 *    seconde garde, l'action serait un « déplace ce fichier » générique offert
 *    à toute session webmestre volée — exactement la primitive qu'un attaquant
 *    déjà présent cherche à obtenir.
 *
 * @plugin Sentinelle
 * @license GNU/GPL
 * @package SPIP\Sentinelle\Action
 */

if (!defined('_ECRIRE_INC_VERSION')) {
	return;
}

/**
 * @param string|null $arg
 */
function action_sentinelle_quarantaine_dist($arg = null) {
	if ($arg === null) {
		$securiser_action = charger_fonction('securiser_action', 'inc');
		$arg = $securiser_action();
	}

	include_spip('inc/sentinelle');

	if (!autoriser('quarantaine', 'sentinelle')) {
		spip_log(
			'Sentinelle : quarantaine refusée à '
				. ($GLOBALS['visiteur_session']['id_auteur'] ?? '?') . " ($arg)",
			'sentinelle.' . _LOG_ERREUR
		);
		sentinelle_message_ecrire(false, _T('sentinelle:action_autorisation_refusee'));
		return;
	}

	sentinelle_charger_moteur();
	$racine = sentinelle_racine();

	[$operation, $cible] = array_pad(explode(':', (string) $arg, 2), 2, '');

	switch ($operation) {
		case 'isoler':
			sentinelle_action_isoler($racine, $cible);
			break;

		case 'isoler-tout':
			sentinelle_action_isoler_tout($racine);
			break;

		case 'isoler-selection':
			sentinelle_action_isoler_selection($racine, (array) _request('chemins'));
			break;

		case 'restaurer':
			sentinelle_action_restaurer($racine, $cible);
			break;

		default:
			sentinelle_message_ecrire(false, _T('sentinelle:action_operation_inconnue'));
	}
}

/**
 * Isole uniquement les chemins cochés, après recoupement avec le dernier scan.
 *
 * @param string[] $chemins
 */
function sentinelle_action_isoler_selection(string $racine, array $chemins): void {
	$autorises = [];
	foreach (sentinelle_findings_courants() as $finding) {
		$chemin = (string) ($finding['chemin'] ?? '');
		if ($chemin !== '' && ($finding['regle'] ?? '') !== 'posture') {
			$autorises[$chemin] = true;
		}
	}
	$selection = [];
	foreach (array_slice($chemins, 0, 500) as $chemin) {
		$chemin = (string) $chemin;
		if (isset($autorises[$chemin])) {
			$selection[$chemin] = true;
		}
	}
	if (!$selection) {
		sentinelle_message_ecrire(false, _T('sentinelle:action_selection_vide'));
		return;
	}

	$lot = sentinelle_quarantaine_nouveau_lot();
	$faits = 0;
	$refuses = 0;
	$echecs = 0;
	foreach (array_keys($selection) as $rel) {
		if (sentinelle_quarantaine_autorisee($rel) !== true) {
			$refuses++;
			continue;
		}
		$resultat = sentinelle_quarantaine_deplacer($racine, $rel, $lot, implode(', ', sentinelle_gravites_du_chemin($rel)));
		if ($resultat['ok']) {
			sentinelle_oublier_chemin($rel);
			$faits++;
		} else {
			$echecs++;
			spip_log('Sentinelle : ' . $resultat['message'], 'sentinelle.' . _LOG_ERREUR);
		}
	}
	$texte = _T('sentinelle:action_selection_resultat', ['faits' => $faits, 'refuses' => $refuses, 'echecs' => $echecs, 'lot' => $lot]);
	sentinelle_message_ecrire($echecs === 0, $texte);
}

/**
 * Isole un fichier signalé par le dernier scan.
 */
function sentinelle_action_isoler(string $racine, string $rel): void {
	$gravites = sentinelle_gravites_du_chemin($rel);
	if (!$gravites) {
		spip_log("Sentinelle : refus d'isoler un chemin non signalé ($rel)", 'sentinelle.' . _LOG_ERREUR);
		sentinelle_message_ecrire(false, _T('sentinelle:action_chemin_non_signale'));
		return;
	}

	$resultat = sentinelle_quarantaine_deplacer(
		$racine,
		$rel,
		sentinelle_quarantaine_nouveau_lot(),
		implode(', ', $gravites)
	);

	if ($resultat['ok']) {
		sentinelle_oublier_chemin($rel);
		spip_log("Sentinelle : quarantaine de $rel", 'sentinelle.' . _LOG_INFO_IMPORTANTE);
	}

	sentinelle_message_ecrire(
		$resultat['ok'],
		$resultat['ok'] ? _T('sentinelle:action_fichier_isole', ['chemin' => $rel]) : _T('sentinelle:action_isolement_echec', ['chemin' => $rel])
	);
}

/**
 * Isole d'un coup tous les fichiers de gravité critique.
 *
 * Un seul lot pour toute l'opération : la restauration en masse d'une campagne
 * qui se serait trompée reste ainsi une seule décision, pas trente.
 *
 * Les chemins protégés (`.htaccess` racine, `ecrire/`, `config/`…) sont sautés
 * et comptés à part : ils demandent une décision humaine, parce que les
 * déplacer casserait le site plus sûrement que le webshell qu'ils abritent.
 */
function sentinelle_action_isoler_tout(string $racine): void {
	$lot = sentinelle_quarantaine_nouveau_lot();
	$faits = 0;
	$refuses = 0;
	$echecs = 0;

	// Copie figée : chaque succès réécrit findings.json sous nos pieds.
	$critiques = [];
	foreach (sentinelle_findings_courants() as $f) {
		$chemin = $f['chemin'] ?? '';
		if ($chemin !== '' && ($f['gravite'] ?? '') === 'critique') {
			$critiques[$chemin] = true;
		}
	}

	foreach (array_keys($critiques) as $rel) {
		if (sentinelle_quarantaine_autorisee($rel) !== true) {
			$refuses++;
			continue;
		}

		$resultat = sentinelle_quarantaine_deplacer($racine, $rel, $lot, 'critique');
		if ($resultat['ok']) {
			sentinelle_oublier_chemin($rel);
			$faits++;
		} else {
			$echecs++;
			spip_log('Sentinelle : ' . $resultat['message'], 'sentinelle.' . _LOG_ERREUR);
		}
	}

	$texte = "$faits fichier(s) isolé(s) dans le lot $lot.";
	if ($refuses) {
		$texte .= " $refuses chemin(s) protégé(s) laissé(s) en place — à traiter à la main.";
	}
	if ($echecs) {
		$texte .= " $echecs échec(s), voir le journal « sentinelle ».";
	}

	spip_log("Sentinelle : lot $lot — $faits isolé(s), $refuses protégé(s), $echecs échec(s)", 'sentinelle.' . _LOG_INFO_IMPORTANTE);
	sentinelle_message_ecrire($echecs === 0, $texte);
}

/**
 * Remet un fichier isolé à son emplacement d'origine.
 *
 * Aucune vérification de gravité ici : on ne restaure que ce qui figure au
 * journal de quarantaine, et le journal ne contient que ce que Sentinelle a
 * elle-même déplacé.
 */
function sentinelle_action_restaurer(string $racine, string $rel): void {
	$resultat = sentinelle_quarantaine_restaurer($racine, $rel);

	if ($resultat['ok']) {
		spip_log("Sentinelle : restauration de $rel", 'sentinelle.' . _LOG_INFO_IMPORTANTE);
	}

	sentinelle_message_ecrire(
		$resultat['ok'],
		$resultat['ok'] ? _T('sentinelle:action_fichier_restaure', ['chemin' => $rel]) : _T('sentinelle:action_restauration_echec', ['chemin' => $rel])
	);
}
