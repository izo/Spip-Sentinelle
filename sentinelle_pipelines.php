<?php

/**
 * Sentinelle — branchements sur les pipelines de SPIP.
 *
 * @plugin Sentinelle
 * @license GNU/GPL
 * @package SPIP\Sentinelle\Pipelines
 */

if (!defined('_ECRIRE_INC_VERSION')) {
	return;
}

/**
 * Déclare la tâche périodique.
 *
 * Six heures : assez fréquent pour qu'un dépôt de webshell soit vu dans la
 * journée, assez espacé pour que le scan fractionné ait le temps de finir son
 * cycle entre deux départs. Surcharger avec la meta `sentinelle_intervalle`
 * (en secondes) ; la mettre à 0 désactive la tâche.
 *
 * @pipeline taches_generales_cron
 */
function sentinelle_taches_generales_cron($taches_generales) {
	$intervalle = isset($GLOBALS['meta']['sentinelle_intervalle'])
		? (int) $GLOBALS['meta']['sentinelle_intervalle']
		: 6 * 3600;

	if ($intervalle > 0) {
		$taches_generales['sentinelle'] = $intervalle;
	}

	return $taches_generales;
}
