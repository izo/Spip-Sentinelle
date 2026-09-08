<?php

/**
 * Sentinelle — autorisations.
 *
 * Tout est réservé au webmestre, jamais au simple administrateur. Deux raisons,
 * dans cet ordre :
 *
 * 1. La page liste les chemins exacts des fichiers suspects encore en place.
 *    C'est une carte du site pour qui saurait s'en servir.
 * 2. La mise en quarantaine déplace des fichiers. Donner cette primitive à tout
 *    `0minirezo` revient à faire de chaque compte administrateur compromis un
 *    moyen de casser le site — or c'est précisément un compte administrateur
 *    que l'attaquant vise en premier.
 *
 * Le statut webmestre, lui, se règle hors du web quand `_ID_WEBMESTRES` est
 * défini dans `config/mes_options.php` : il survit à la compromission de la
 * base.
 *
 * @plugin Sentinelle
 * @license GNU/GPL
 * @package SPIP\Sentinelle\Autorisations
 */

if (!defined('_ECRIRE_INC_VERSION')) {
	return;
}

/**
 * Fonction du pipeline `autoriser` : n'a rien à faire, sa seule raison d'être
 * est de provoquer l'inclusion de ce fichier.
 *
 * @pipeline autoriser
 */

function sentinelle_autoriser($flux) {
	// Le pipeline sert à charger les fonctions ci-dessous. Il doit néanmoins
	// restituer sa valeur, sinon il corrompt la chaîne des autorisations.
	return $flux;
}

/**
 * Autorisation générique sur le type `sentinelle`.
 *
 * Attrape à la fois `autoriser('sentinelle')` (accès à la page) et tout
 * `autoriser(<action>, 'sentinelle')` qui n'aurait pas de fonction dédiée —
 * un défaut fermé plutôt qu'ouvert.
 *
 * @param string $faire Action demandée
 * @param string $type Type d'objet
 * @param int $id Identifiant de l'objet
 * @param array $qui Description de l'auteur demandant l'autorisation
 * @param array $opt Options
 * @return bool
 */
function autoriser_sentinelle_dist($faire, $type = '', $id = 0, $qui = null, $opt = null) {
	return autoriser('webmestre', '', 0, $qui, $opt);
}

/**
 * Affichage de l'entrée de menu.
 *
 * `ecrire/inc/bandeau.php` appelle `autoriser('menu', "_sentinelle")`, et
 * `autoriser_type()` retire les soulignés : la fonction attendue est bien
 * `autoriser_sentinelle_menu_dist` et non `autoriser__sentinelle_menu_dist`.
 *
 * @return bool
 */
function autoriser_sentinelle_menu_dist($faire, $type = '', $id = 0, $qui = null, $opt = null) {
	return autoriser('sentinelle', '', 0, $qui, $opt);
}

/**
 * Mise en quarantaine et restauration d'un fichier.
 *
 * @return bool
 */
function autoriser_sentinelle_quarantaine_dist($faire, $type = '', $id = 0, $qui = null, $opt = null) {
	return autoriser('sentinelle', '', 0, $qui, $opt);
}

/**
 * Pose ou renouvellement de l'empreinte de référence.
 *
 * @return bool
 */
function autoriser_sentinelle_baseline_dist($faire, $type = '', $id = 0, $qui = null, $opt = null) {
	return autoriser('sentinelle', '', 0, $qui, $opt);
}
