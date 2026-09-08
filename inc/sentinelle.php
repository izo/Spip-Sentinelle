<?php

/**
 * Sentinelle — pont entre SPIP et le moteur `lib/`.
 *
 * Le moteur ignore tout de SPIP : il ne connaît qu'une racine de site et des
 * chemins relatifs. Ce fichier lui fournit ce contexte, gère l'état persistant
 * du scan fractionné, envoie les alertes et le rapport de routine.
 *
 * @plugin Sentinelle
 * @license GNU/GPL
 * @package SPIP\Sentinelle\Inc
 */

if (!defined('_ECRIRE_INC_VERSION')) {
	return;
}

/**
 * Charge le moteur d'analyse.
 */
function sentinelle_charger_moteur(): void {
	$lib = realpath(__DIR__ . '/../lib');
	require_once $lib . '/ioc.php';
	require_once $lib . '/state.php';
	require_once $lib . '/scanner.php';
	require_once $lib . '/baseline.php';
	require_once $lib . '/quarantaine.php';
}

/**
 * Racine du site, telle que la voit le moteur.
 *
 * `_ROOT_RACINE` est absolu et se termine par un `/` ; le moteur travaille sans.
 */
function sentinelle_racine(): string {
	return rtrim(str_replace('\\', '/', _ROOT_RACINE), '/');
}

/**
 * Lit un fichier d'état JSON du plugin.
 */
function sentinelle_etat_lire(string $nom, $defaut = []) {
	sentinelle_charger_moteur();
	try {
		return sentinelle_etat_lire_fichier(sentinelle_repertoire_etat(sentinelle_racine()), $nom, $defaut);
	} catch (RuntimeException $e) {
		spip_log('Sentinelle : ' . $e->getMessage(), 'sentinelle.' . _LOG_ERREUR);
		return $defaut;
	}
}

/**
 * Écrit un fichier d'état JSON du plugin.
 */
function sentinelle_etat_ecrire(string $nom, $data): bool {
	sentinelle_charger_moteur();
	try {
		return sentinelle_etat_ecrire_fichier(sentinelle_repertoire_etat(sentinelle_racine()), $nom, $data);
	} catch (RuntimeException $e) {
		spip_log('Sentinelle : ' . $e->getMessage(), 'sentinelle.' . _LOG_ERREUR);
		return false;
	}
}

/**
 * Met à jour un état sans fenêtre de course entre lecture et écriture.
 *
 * @return mixed
 */
function sentinelle_etat_modifier(string $nom, callable $mutation, $defaut = []) {
	sentinelle_charger_moteur();
	try {
		return sentinelle_etat_modifier_fichier(
			sentinelle_repertoire_etat(sentinelle_racine()),
			$nom,
			$mutation,
			$defaut
		);
	} catch (RuntimeException $e) {
		spip_log('Sentinelle : ' . $e->getMessage(), 'sentinelle.' . _LOG_ERREUR);
		return false;
	}
}

/**
 * Empreinte stable d'un finding, pour ne pas ré-alerter sur le même problème
 * à chaque passage du cron.
 */
function sentinelle_signature_finding(array $f): string {
	return md5(($f['chemin'] ?? '') . '|' . ($f['regle'] ?? '') . '|' . ($f['md5'] ?? ''));
}

/**
 * Destinataire des alertes : la meta `sentinelle_email`, sinon le webmestre.
 */
function sentinelle_destinataire(): string {
	$email = trim((string) ($GLOBALS['meta']['sentinelle_email'] ?? ''));
	if ($email === '') {
		$email = trim((string) ($GLOBALS['meta']['email_webmaster'] ?? ''));
	}
	return $email;
}

/**
 * Période minimale entre deux rapports de routine, en secondes.
 *
 * Le cron passe toutes les six heures : rapporter à chaque cycle ferait quatre
 * messages par jour, identiques les jours où rien ne bouge — et c'est ainsi
 * qu'une alerte finit lue en diagonale, ou classée par un filtre. Un rapport
 * par jour suffit à prouver que la surveillance tourne encore ; les nouveautés,
 * elles, partent sans attendre l'heure du rapport.
 *
 * Surcharger avec la meta `sentinelle_rapport` (en secondes) ; à 0, plus aucun
 * rapport de routine — seules les alertes sont envoyées.
 */
function sentinelle_intervalle_rapport(): int {
	if (isset($GLOBALS['meta']['sentinelle_rapport'])) {
		return max(0, (int) $GLOBALS['meta']['sentinelle_rapport']);
	}
	return 86400;
}

/**
 * Horodatage du dernier message envoyé, alertes et rapports confondus.
 */
function sentinelle_dernier_mail(): int {
	return (int) (sentinelle_etat_lire('rapport.json', [])['envoye_le'] ?? 0);
}

/**
 * Nom du site tel qu'il apparaît dans le sujet des messages.
 */
function sentinelle_nom_site(): string {
	return (string) ($GLOBALS['meta']['nom_site'] ?? $GLOBALS['meta']['adresse_site'] ?? 'ce site');
}

/**
 * Bilan du dernier scan terminé, relu depuis `findings.json`.
 *
 * Les deux messages décrivent le même état : le relire ici plutôt que de le
 * recevoir en argument garantit qu'un mail ne puisse pas annoncer un bilan
 * différent de celui qu'affiche la page privée.
 *
 * @return array{termine_le:int,duree:float,analyses:int,compte:array,findings:array}
 */
function sentinelle_bilan_courant(): array {
	sentinelle_charger_moteur();
	$data = sentinelle_etat_lire('findings.json', []);
	$findings = is_array($data['findings'] ?? null) ? $data['findings'] : [];

	return [
		'termine_le' => (int) ($data['termine_le'] ?? 0),
		'duree'      => (float) ($data['duree'] ?? 0),
		'analyses'   => (int) ($data['analyses'] ?? 0),
		'compte'     => is_array($data['compte'] ?? null)
			? $data['compte']
			: sentinelle_compter_findings($findings),
		'findings'   => $findings,
	];
}

/**
 * Envoie un message au destinataire et note la date.
 *
 * Alertes et rapports passent tous les deux par ici et marquent le même
 * horodatage : une alerte porte déjà le bilan complet, elle tient donc lieu de
 * rapport. Sans ce partage, une alerte à 18 h serait suivie à minuit d'un
 * rapport répétant la même chose.
 *
 * Un envoi qui échoue ne marque rien — le prochain passage du cron réessaiera.
 */
function sentinelle_mail_tenter(string $sujet, string $corps): bool {
	$email = sentinelle_destinataire();
	if ($email === '') {
		spip_log(
			'Sentinelle : aucun destinataire configuré, message non envoyé — ' . $sujet,
			'sentinelle.' . _LOG_ERREUR
		);
		return false;
	}

	$envoyer_mail = charger_fonction('envoyer_mail', 'inc');
	if (!$envoyer_mail($email, $sujet, $corps)) {
		spip_log(
			'Sentinelle : échec de l\'envoi à ' . $email . ' — ' . $sujet,
			'sentinelle.' . _LOG_ERREUR
		);
		return false;
	}

	return true;
}

/**
 * Ajoute un message à la file persistante, de façon idempotente.
 */
function sentinelle_notification_ajouter(string $sujet, string $corps): string {
	// Un rapport de routine remplace le précédent encore en attente ; les
	// alertes, elles, gardent chacune leur identité et leur ordre.
	$id = strpos($sujet, '[Sentinelle] Rapport') === 0
		? hash('sha256', 'sentinelle-rapport')
		: hash('sha256', $sujet . "\n" . $corps);
	sentinelle_etat_modifier('notifications.json', function ($file) use ($id, $sujet, $corps) {
		$file = is_array($file) ? $file : [];
		foreach ($file as &$message) {
			if (($message['id'] ?? '') === $id) {
				$message['sujet'] = $sujet;
				$message['corps'] = $corps;
				$message['mis_a_jour_le'] = time();
				unset($message);
				return $file;
			}
		}
		unset($message);
		$file[] = [
			'id' => $id,
			'sujet' => $sujet,
			'corps' => $corps,
			'cree_le' => time(),
			'essais' => 0,
		];
		return $file;
	}, []);
	return $id;
}

/**
 * Rejoue la file dans l'ordre. Un message n'est acquitté qu'après succès.
 */
function sentinelle_notifications_rejouer(): int {
	$file = sentinelle_etat_lire('notifications.json', []);
	if (!is_array($file)) {
		return 0;
	}
	$envoyes = 0;
	foreach ($file as $message) {
		$id = (string) ($message['id'] ?? '');
		if ($id === '' || !sentinelle_mail_tenter((string) ($message['sujet'] ?? ''), (string) ($message['corps'] ?? ''))) {
			sentinelle_etat_modifier('notifications.json', function ($courante) use ($id) {
				foreach ((array) $courante as &$attente) {
					if (($attente['id'] ?? '') === $id) {
						$attente['essais'] = (int) ($attente['essais'] ?? 0) + 1;
						$attente['dernier_echec_le'] = time();
					}
				}
				unset($attente);
				return $courante;
			}, []);
			break;
		}
		sentinelle_etat_modifier('notifications.json', function ($courante) use ($id) {
			return array_values(array_filter((array) $courante, function ($attente) use ($id) {
				return ($attente['id'] ?? '') !== $id;
			}));
		}, []);
		sentinelle_etat_ecrire('rapport.json', ['envoye_le' => time(), 'sujet' => $message['sujet']]);
		$envoyes++;
	}
	return $envoyes;
}

/**
 * Persiste d'abord le message, puis tente immédiatement de vider la file.
 */
function sentinelle_mail_envoyer(string $sujet, string $corps): bool {
	$id = sentinelle_notification_ajouter($sujet, $corps);
	sentinelle_notifications_rejouer();
	foreach ((array) sentinelle_etat_lire('notifications.json', []) as $message) {
		if (($message['id'] ?? '') === $id) {
			return false;
		}
	}
	return true;
}

/**
 * État du site : date du scan, volume analysé, bilan par gravité, empreinte.
 *
 * L'absence d'empreinte de référence y est rappelée à chaque envoi : c'est le
 * seul dispositif qui voie un webshell inédit, et un site sans empreinte peut
 * annoncer « rien de signalé » en étant compromis depuis des semaines.
 */
function sentinelle_corps_etat(array $bilan): string {
	$compte = $bilan['compte'];

	$corps = "État du site\n";
	$corps .= '  Scan terminé le ' . date('d/m/Y à H:i', $bilan['termine_le'] ?: time())
		. ' — ' . $bilan['analyses'] . ' fichiers analysés en ' . $bilan['duree'] . " s.\n";
	$corps .= '  Signalements ouverts : ' . $compte['critique'] . ' critique · '
		. $compte['haut'] . ' haut · ' . $compte['moyen'] . " moyen\n";

	$baseline = sentinelle_etat_lire('baseline.json', []);
	if (empty($baseline['fichiers'])) {
		$corps .= "  Aucune empreinte de référence : seuls les indicateurs déjà catalogués\n";
		$corps .= "  sont détectés, un webshell inédit passe inaperçu.\n";
	} else {
		$corps .= '  Empreinte de référence : ' . (int) ($baseline['nombre'] ?? count($baseline['fichiers']))
			. ' fichiers, posée le ' . date('d/m/Y', (int) ($baseline['genere_le'] ?? 0)) . ".\n";
	}

	return $corps . "\n";
}

/**
 * Décrit une liste de findings, sans jamais citer le code analysé.
 *
 * Un webshell recopié dans un mail traverse des relais, des antivirus et des
 * sauvegardes : seuls le chemin, la règle, le hash et la taille figurent ici.
 * Au-delà de `$max` entrées le message devient un mur que personne ne lit
 * jusqu'au bout — le reste est compté, la page privée porte le détail.
 *
 * @param array[] $findings
 */
function sentinelle_corps_findings(array $findings, int $max = 15): string {
	$corps = '';
	foreach (array_slice($findings, 0, $max) as $f) {
		$chemin = $f['chemin'] ?? '';
		$corps .= '[' . strtoupper($f['gravite']) . '] ' . ($chemin !== '' ? $chemin : '(posture du site)') . "\n";
		$corps .= '  ' . $f['libelle'] . "\n";
		if (!empty($f['md5'])) {
			$corps .= '  md5 ' . $f['md5'] . ' · ' . (int) ($f['taille'] ?? 0) . " octets\n";
		}
		$corps .= "\n";
	}

	$reste = count($findings) - $max;
	if ($reste > 0) {
		$corps .= "… et $reste autre(s), sur la page de Sentinelle.\n\n";
	}

	return $corps;
}

/**
 * Pied commun aux deux messages.
 *
 * L'avertissement sur la requête GET n'a de sens que si des chemins précèdent :
 * un rapport sans signalement ne dit pas de ne pas ouvrir une liste vide.
 */
function sentinelle_corps_pied(bool $avec_chemins): string {
	$corps = "---\n";
	$corps .= 'Détail et mise en quarantaine : ' . url_absolue(generer_url_ecrire('sentinelle')) . "\n";

	if ($avec_chemins) {
		$corps .= "\nN'ouvrez aucun des chemins ci-dessus dans un navigateur : plusieurs\n";
		$corps .= "de ces fichiers réagissent à une simple requête GET.\n";
	}

	return $corps;
}

/**
 * Envoie l'alerte des findings apparus depuis le dernier passage.
 *
 * Part immédiatement, sans attendre l'heure du rapport : entre le dépôt d'un
 * webshell et sa première requête utile, il s'écoule souvent moins d'une heure.
 *
 * @param array[] $nouveaux
 */
function sentinelle_alerter(array $nouveaux): bool {
	if (!$nouveaux) {
		return false;
	}

	sentinelle_charger_moteur();
	$neuf = sentinelle_compter_findings($nouveaux);
	$site = sentinelle_nom_site();

	$sujet = '[Sentinelle] Alerte — ';
	$sujet .= $neuf['critique']
		? $neuf['critique'] . ' critique(s)'
		: count($nouveaux) . ' nouveau(x)';
	$sujet .= ' sur ' . $site;

	$corps = 'Sentinelle a détecté ' . count($nouveaux) . " élément(s) nouveau(x) sur $site.\n";
	$corps .= $neuf['critique'] . ' critique · ' . $neuf['haut'] . ' haut · '
		. $neuf['moyen'] . " moyen\n\n";
	$corps .= sentinelle_corps_findings($nouveaux);
	$corps .= sentinelle_corps_etat(sentinelle_bilan_courant());
	$corps .= sentinelle_corps_pied(true);

	return sentinelle_mail_envoyer($sujet, $corps);
}

/**
 * Envoie le rapport de routine, au plus une fois par période.
 *
 * Ce message part même quand tout va bien, et c'est le point : son absence est
 * elle-même une information. Un cron arrêté, un hébergeur qui coupe la tâche,
 * un plugin désactivé par une mise à jour — dans tous ces cas la surveillance
 * s'est tue sans rien signaler, et seul le silence du rapport le dit.
 *
 * Il rappelle les signalements critiques et hauts encore ouverts : une alerte
 * n'est envoyée qu'une fois, un fichier laissé en place doit rester visible.
 */
function sentinelle_rapporter(): bool {
	$intervalle = sentinelle_intervalle_rapport();
	if ($intervalle === 0 || (time() - sentinelle_dernier_mail()) < $intervalle) {
		return false;
	}

	$bilan = sentinelle_bilan_courant();
	$compte = $bilan['compte'];
	$site = sentinelle_nom_site();

	$sujet = $compte['critique']
		? '[Sentinelle] Rapport — ' . $compte['critique'] . ' critique(s) non traité(s) sur ' . $site
		: '[Sentinelle] Rapport — rien de nouveau sur ' . $site;

	$ouverts = array_values(array_filter($bilan['findings'], function ($f) {
		return in_array($f['gravite'] ?? '', ['critique', 'haut'], true);
	}));

	$corps = "Rapport de surveillance de $site.\n\n";
	$corps .= sentinelle_corps_etat($bilan);

	if ($ouverts) {
		$corps .= "Signalements encore ouverts\n\n";
		$corps .= sentinelle_corps_findings($ouverts);
	} else {
		$corps .= "Aucun signalement critique ou haut en attente de traitement.\n\n";
	}

	$corps .= sentinelle_corps_pied((bool) $ouverts);

	return sentinelle_mail_envoyer($sujet, $corps);
}

/**
 * Lance un scan complet, en une passe.
 *
 * Réservé au déclenchement manuel depuis l'espace privé : sur un gros site,
 * cette fonction dépasse largement le temps d'exécution d'une requête web.
 * Le cron, lui, passe par le scan fractionné du génie.
 *
 * @return array[] findings triés
 */
function sentinelle_scan_complet(): array {
	sentinelle_charger_moteur();
	$racine = sentinelle_racine();

	$findings = sentinelle_scan_posture($racine);
	foreach (sentinelle_scan_lister($racine) as $rel) {
		$findings = array_merge($findings, sentinelle_scan_chemin($racine, $rel));
	}

	return sentinelle_trier_findings($findings);
}

/**
 * Findings du dernier scan terminé.
 *
 * @return array[]
 */
function sentinelle_findings_courants(): array {
	$data = sentinelle_etat_lire('findings.json', []);
	return is_array($data['findings'] ?? null) ? $data['findings'] : [];
}

/**
 * Horodatage du dernier scan terminé, ou 0.
 */
function sentinelle_dernier_scan(): int {
	return (int) (sentinelle_etat_lire('findings.json', [])['termine_le'] ?? 0);
}

/**
 * Gravités relevées pour un chemin donné dans le dernier scan.
 *
 * Sert de garde aux actions : Sentinelle n'accepte de déplacer que des fichiers
 * qu'elle a elle-même signalés. Sans cette vérification, l'action serait une
 * primitive « déplacer n'importe quel fichier du site » offerte à toute session
 * webmestre détournée.
 *
 * Un finding de règle « posture » (config manquante, version obsolète) ne
 * désigne jamais un fichier malveillant à déplacer — l'exclure ici évite
 * qu'un avertissement de configuration serve de laissez-passer pour isoler
 * IMG/, local/ ou tout autre répertoire de données légitime.
 *
 * @return string[] gravités, dédoublonnées ; tableau vide si le chemin est inconnu
 */
function sentinelle_gravites_du_chemin(string $rel): array {
	$gravites = [];
	foreach (sentinelle_findings_courants() as $f) {
		if (($f['chemin'] ?? '') === $rel && ($f['regle'] ?? '') !== 'posture') {
			$gravites[$f['gravite']] = true;
		}
	}
	return array_keys($gravites);
}

/**
 * Retire de `findings.json` toutes les alertes portant sur un chemin.
 *
 * Appelé après une mise en quarantaine réussie : le fichier n'est plus là où
 * l'alerte le désigne, la laisser afficherait un bouton qui échouerait.
 */
function sentinelle_oublier_chemin(string $rel): void {
	$data = sentinelle_etat_lire('findings.json', []);
	if (empty($data['findings'])) {
		return;
	}

	sentinelle_charger_moteur();
	sentinelle_etat_modifier('findings.json', function ($courant) use ($rel) {
		$courant = is_array($courant) ? $courant : [];
		$courant['findings'] = array_values(array_filter((array) ($courant['findings'] ?? []), function ($f) use ($rel) {
			return ($f['chemin'] ?? '') !== $rel;
		}));
		$courant['compte'] = sentinelle_compter_findings($courant['findings']);
		return $courant;
	}, []);
}

/**
 * Mémorise le compte rendu de la dernière action, pour l'afficher au retour.
 *
 * Une action SPIP redirige : elle ne peut rien rendre à l'écran. Le message est
 * donc déposé ici et relu par la page. Il porte l'auteur et l'heure pour ne pas
 * s'afficher chez quelqu'un d'autre ni ressurgir trois jours plus tard.
 */
function sentinelle_message_ecrire(bool $ok, string $texte): void {
	sentinelle_etat_ecrire('message.json', [
		'ok'        => $ok,
		'texte'     => $texte,
		'id_auteur' => (int) ($GLOBALS['visiteur_session']['id_auteur'] ?? 0),
		'date'      => time(),
	]);
}

/**
 * Relit et consomme le compte rendu de la dernière action.
 *
 * @return array{ok:bool,texte:string}|null
 */
function sentinelle_message_lire(): ?array {
	$message = sentinelle_etat_lire('message.json', []);
	if (empty($message['texte'])) {
		return null;
	}

	$a_moi = (int) $message['id_auteur'] === (int) ($GLOBALS['visiteur_session']['id_auteur'] ?? 0);
	$frais = (time() - (int) $message['date']) < 120;

	sentinelle_etat_ecrire('message.json', []);

	if (!$a_moi || !$frais) {
		return null;
	}
	return ['ok' => (bool) $message['ok'], 'texte' => (string) $message['texte']];
}
