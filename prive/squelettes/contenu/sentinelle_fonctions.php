<?php

/**
 * Sentinelle — données sûres et localisées du tableau de bord.
 */

if (!defined('_ECRIRE_INC_VERSION')) {
	return;
}

function sentinelle_rang_gravite(string $gravite): int {
	$rangs = ['critique' => 0, 'haut' => 1, 'moyen' => 2, 'info' => 3];
	return $rangs[$gravite] ?? 9;
}

function sentinelle_classe_gravite(string $gravite): string {
	$classes = ['critique' => 'error', 'haut' => 'notice', 'moyen' => 'notice', 'info' => 'info'];
	return $classes[$gravite] ?? 'info';
}

function sentinelle_taille_lisible($octets): string {
	$octets = (int) $octets;
	if ($octets <= 0) {
		return '';
	}
	if ($octets < 1024) {
		return $octets . ' ' . _T('sentinelle:unite_octet');
	}
	if ($octets < 1048576) {
		return round($octets / 1024) . ' ' . _T('sentinelle:unite_ko');
	}
	return round($octets / 1048576, 1) . ' ' . _T('sentinelle:unite_mo');
}

function sentinelle_date_lisible($ts): string {
	$ts = (int) $ts;
	return $ts > 0 ? affdate_heure(date('Y-m-d H:i:s', $ts)) : _T('sentinelle:jamais');
}

/**
 * Traduit les textes dynamiques du moteur sans exposer son catalogue interne.
 *
 * Le moteur reste autonome et conserve ses diagnostics français en CLI. Dans
 * l'espace privé anglais, la règle et la preuve sont reformulées à partir des
 * identifiants stables plutôt que d'imprimer ces chaînes françaises.
 *
 * @return array{libelle:string,preuve:string}
 */
function sentinelle_vue_traduire_finding(array $finding): array {
	$libelle = (string) ($finding['libelle'] ?? '');
	$preuve = (string) ($finding['preuve'] ?? '');
	if (($GLOBALS['spip_lang'] ?? 'fr') !== 'en') {
		return ['libelle' => $libelle, 'preuve' => $preuve];
	}
	$regle = (string) ($finding['regle'] ?? '');
	$chemin = (string) ($finding['chemin'] ?? '');
	$nom = basename(rtrim($chemin, '/'));
	$cles = [
		'repertoire_interdit' => ['finding_repertoire_interdit', 'proof_repertoire_interdit'],
		'hash' => ['finding_hash', 'proof_hash'],
		'nom' => ['finding_nom', 'proof_nom'],
		'nom_generique' => ['finding_nom_generique', 'proof_nom_generique'],
		'nom_motif' => ['finding_nom_motif', 'proof_nom_motif'],
		'taille' => ['finding_taille', 'proof_taille'],
		'marqueur' => ['finding_marqueur', 'proof_signature'],
		'motif' => ['finding_motif', 'proof_signature'],
		'php_donnees' => ['finding_php_donnees', 'proof_php_donnees'],
		'htaccess' => ['finding_htaccess', 'proof_htaccess'],
		'heuristique' => ['finding_heuristique', 'proof_heuristique'],
		'baseline_ajout' => ['finding_baseline_ajout', 'proof_baseline'],
		'baseline_modifie' => ['finding_baseline_modifie', 'proof_baseline'],
		'baseline_disparu' => ['finding_baseline_disparu', 'proof_baseline'],
		'couverture' => ['finding_couverture', 'proof_couverture'],
		'posture' => ['finding_posture', 'proof_posture'],
	];
	$paire = $cles[$regle] ?? ['finding_inconnu', 'proof_inconnu'];
	return [
		'libelle' => _T('sentinelle:' . $paire[0], ['nom' => $nom]),
		'preuve' => _T('sentinelle:' . $paire[1], ['nom' => $nom]),
	];
}

/**
 * Compte fichiers consolidés, règles déclenchées et groupes d'empreinte.
 */
function sentinelle_vue_mesures(array $findings): array {
	$chemins = [];
	$groupes = [];
	foreach ($findings as $finding) {
		$chemin = (string) ($finding['chemin'] ?? '');
		if ($chemin === '') {
			continue;
		}
		$rang = sentinelle_rang_gravite((string) ($finding['gravite'] ?? ''));
		if (!isset($chemins[$chemin]) || $rang < $chemins[$chemin]) {
			$chemins[$chemin] = $rang;
		}
		if (!empty($finding['md5'])) {
			$groupes[(string) $finding['md5']] = true;
		}
	}
	$par_gravite = ['critique' => 0, 'haut' => 0, 'moyen' => 0, 'info' => 0];
	$noms = [0 => 'critique', 1 => 'haut', 2 => 'moyen', 3 => 'info'];
	foreach ($chemins as $rang) {
		if (isset($noms[$rang])) {
			$par_gravite[$noms[$rang]]++;
		}
	}
	return [
		'fichiers' => count($chemins),
		'regles' => count($findings),
		'groupes' => count($groupes),
		'par_gravite' => $par_gravite,
	];
}

function sentinelle_vue_resume($rien = ''): array {
	include_spip('inc/sentinelle');
	sentinelle_charger_moteur();
	$scan = sentinelle_etat_lire('findings.json', []);
	$baseline = sentinelle_etat_lire('baseline.json', []);
	$etat = sentinelle_etat_lire('etat.json', []);
	$findings = (array) ($scan['findings'] ?? []);
	$mesures = sentinelle_vue_mesures($findings);
	$intervalle = isset($GLOBALS['meta']['sentinelle_intervalle']) ? (int) $GLOBALS['meta']['sentinelle_intervalle'] : 21600;
	$dernier = (int) ($scan['termine_le'] ?? 0);
	$perime = $dernier > 0 && (time() - $dernier) > max(43200, $intervalle * 2);
	$en_cours = !empty($etat['en_cours']);
	$erreur = (string) ($etat['erreur'] ?? '');
	$phase = (string) ($etat['phase'] ?? '');
	$position = (int) ($etat['position'] ?? 0);
	$total = is_array($etat['file'] ?? null) ? count($etat['file']) : 0;
	$progression = $total > 0 ? min(100, (int) round($position * 100 / $total)) : 0;
	if ($phase === 'decouverte') {
		$decouverte = (array) ($etat['decouverte'] ?? []);
		$position = (int) ($decouverte['repertoire_position'] ?? 0);
		$total = count((array) ($decouverte['repertoires'] ?? []));
		$progression = 0;
	}
	$critique = (int) $mesures['par_gravite']['critique'];
	$haut = (int) $mesures['par_gravite']['haut'];
	$critiques_isolables = [];
	$critiques_proteges = [];
	foreach ($findings as $finding) {
		$chemin = (string) ($finding['chemin'] ?? '');
		if ($chemin === '' || ($finding['gravite'] ?? '') !== 'critique') {
			continue;
		}
		if (sentinelle_quarantaine_autorisee($chemin) === true) {
			$critiques_isolables[$chemin] = true;
		} else {
			$critiques_proteges[$chemin] = true;
		}
	}
	$critiques_ouverts = (int) ($scan['compte']['critique'] ?? $critique);
	$classe = $erreur !== '' || $critique ? 'error' : ($perime || $haut ? 'notice' : 'success');
	$quarantaine_nb = count(sentinelle_quarantaine_actives(sentinelle_racine()));
	$etape = $critiques_ouverts || $haut
		? 'revue'
		: ($quarantaine_nb > 0 ? 'verification' : (empty($baseline['fichiers']) ? 'baseline' : 'surveillance'));

	return [
		'scan_fait' => $dernier > 0,
		'scan_date' => sentinelle_date_lisible($dernier),
		'scan_duree' => (string) ($scan['duree'] ?? ''),
		'scan_analyses' => (int) ($scan['analyses'] ?? 0),
		'critique' => $critique,
		'critiques_isolables' => count($critiques_isolables),
		'critiques_proteges' => count($critiques_proteges),
		'haut' => $haut,
		'moyen' => (int) $mesures['par_gravite']['moyen'],
		'fichiers_signales' => (int) $mesures['fichiers'],
		'regles_declenchees' => (int) $mesures['regles'],
		'groupes_empreinte' => (int) $mesures['groupes'],
		'classe_bilan' => $classe,
		'baseline_posee' => !empty($baseline['fichiers']),
		'baseline_date' => sentinelle_date_lisible($baseline['genere_le'] ?? 0),
		'baseline_nombre' => (int) ($baseline['nombre'] ?? 0),
		'baseline_sale' => (int) ($baseline['critiques_a_la_pose'] ?? 0),
		'baseline_bloquee' => $critiques_ouverts > 0,
		'cycle_en_cours' => $en_cours,
		'cycle_phase' => $phase !== '' ? _T('sentinelle:phase_' . $phase) : '',
		'cycle_position' => $position,
		'cycle_total' => $total,
		'cycle_progression' => $progression,
		'dernier_cycle_reussi' => sentinelle_date_lisible($etat['dernier_cycle_reussi'] ?? $dernier),
		'etat_perime' => $perime,
		'etat_erreur' => spip_htmlspecialchars($erreur),
		'cron_actif' => $intervalle > 0,
		'cron_heures' => $intervalle > 0 ? round($intervalle / 3600, 1) : 0,
		'notifications_attente' => count((array) sentinelle_etat_lire('notifications.json', [])),
		'quarantaine_nb' => $quarantaine_nb,
		'etape' => $etape,
		'mode_attaque' => $critique > 0 || _request('mode') === 'attaque',
	];
}

/** @return array[] */
function sentinelle_vue_posture($rien = ''): array {
	include_spip('inc/sentinelle');
	$lignes = [];
	foreach (sentinelle_findings_courants() as $finding) {
		if (($finding['chemin'] ?? '') !== '') {
			continue;
		}
		$texte = sentinelle_vue_traduire_finding($finding);
		$lignes[] = [
			'gravite' => $finding['gravite'],
			'gravite_libelle' => _T('sentinelle:gravite_' . $finding['gravite']),
			'classe' => sentinelle_classe_gravite($finding['gravite']),
			'libelle' => spip_htmlspecialchars($texte['libelle']),
			'preuve' => spip_htmlspecialchars($texte['preuve']),
		];
	}
	usort($lignes, function ($a, $b) {
		return sentinelle_rang_gravite($a['gravite']) <=> sentinelle_rang_gravite($b['gravite']);
	});
	return $lignes;
}

/** @return array[] */
function sentinelle_vue_fichiers($rien = ''): array {
	include_spip('inc/sentinelle');
	sentinelle_charger_moteur();
	$par_chemin = [];
	foreach (sentinelle_findings_courants() as $finding) {
		$rel = (string) ($finding['chemin'] ?? '');
		if ($rel === '') {
			continue;
		}
		if (!isset($par_chemin[$rel])) {
			$permis = sentinelle_quarantaine_autorisee($rel);
			$par_chemin[$rel] = [
				'chemin' => spip_htmlspecialchars($rel),
				'chemin_brut' => spip_htmlspecialchars($rel),
				'arg' => 'isoler:' . $rel,
				'gravite' => $finding['gravite'],
				'motifs' => [], 'regles' => [], 'md5' => '', 'taille' => '', 'mtime' => '',
				'isolable' => $permis === true,
				'refus' => $permis === true ? '' : spip_htmlspecialchars(
					($GLOBALS['spip_lang'] ?? 'fr') === 'en' ? _T('sentinelle:chemin_protege') : (string) $permis
				),
				'_rang' => sentinelle_rang_gravite($finding['gravite']),
			];
		}
		$ligne = &$par_chemin[$rel];
		$rang = sentinelle_rang_gravite($finding['gravite']);
		if ($rang < $ligne['_rang']) {
			$ligne['gravite'] = $finding['gravite'];
			$ligne['_rang'] = $rang;
		}
		$texte = sentinelle_vue_traduire_finding($finding);
		$motif = '<span>' . spip_htmlspecialchars($texte['libelle']) . '</span>';
		if ($texte['preuve'] !== '') {
			$motif .= '<span class="sentinelle-preuve">' . spip_htmlspecialchars($texte['preuve']) . '</span>';
		}
		$ligne['motifs'][$motif] = true;
		$ligne['regles'][(string) ($finding['regle'] ?? '')] = true;
		$ligne['md5'] = $ligne['md5'] ?: (string) ($finding['md5'] ?? '');
		$ligne['taille'] = $ligne['taille'] ?: sentinelle_taille_lisible($finding['taille'] ?? 0);
		if ($ligne['mtime'] === '' && !empty($finding['mtime'])) {
			$ligne['mtime'] = sentinelle_date_lisible($finding['mtime']);
		}
		unset($ligne);
	}

	$lignes = [];
	foreach ($par_chemin as $rel => $ligne) {
		$motifs = array_keys($ligne['motifs']);
		$contenu = '<ul class="sentinelle-motifs"><li>' . implode('</li><li>', $motifs) . '</li></ul>';
		if (count($motifs) > 1) {
			$contenu = '<details><summary>' . _T('sentinelle:nb_motifs', ['nb' => count($motifs)]) . '</summary>' . $contenu . '</details>';
		}
		$ligne['motifs'] = $contenu;
		$ligne['nb_motifs'] = count($motifs);
		$ligne['gravite_libelle'] = _T('sentinelle:gravite_' . $ligne['gravite']);
		$ligne['repertoire'] = spip_htmlspecialchars(dirname($rel) === '.' ? '/' : dirname($rel));
		$ligne['regles_filtre'] = spip_htmlspecialchars(implode(' ', array_keys($ligne['regles'])));
		$ligne['recherche'] = spip_htmlspecialchars(strtolower($rel . ' ' . implode(' ', array_keys($ligne['regles']))));
		$lignes[] = $ligne;
	}
	usort($lignes, function ($a, $b) {
		return $a['_rang'] !== $b['_rang'] ? $a['_rang'] <=> $b['_rang'] : strcmp($a['chemin'], $b['chemin']);
	});
	return $lignes;
}

/** @return array[] */
function sentinelle_vue_quarantaine($rien = ''): array {
	include_spip('inc/sentinelle');
	sentinelle_charger_moteur();
	$lignes = [];
	foreach (sentinelle_quarantaine_actives(sentinelle_racine()) as $entree) {
		$lignes[] = [
			'chemin' => spip_htmlspecialchars($entree['chemin']),
			'arg' => 'restaurer:' . $entree['chemin'],
			'lot' => spip_htmlspecialchars($entree['lot']),
			'motif' => spip_htmlspecialchars(
				($GLOBALS['spip_lang'] ?? 'fr') === 'en' ? _T('sentinelle:motif_isolation') : ($entree['motif'] ?? '')
			),
			'md5' => spip_htmlspecialchars($entree['md5'] ?? ''),
			'taille' => sentinelle_taille_lisible($entree['taille'] ?? 0),
			'date' => sentinelle_date_lisible($entree['date'] ?? 0),
			'_ts' => (int) ($entree['date'] ?? 0),
		];
	}
	usort($lignes, function ($a, $b) { return $b['_ts'] <=> $a['_ts']; });
	return $lignes;
}

/** @return array[] */
function sentinelle_vue_message($rien = ''): array {
	include_spip('inc/sentinelle');
	$message = sentinelle_message_lire();
	if ($message === null) {
		return [];
	}
	return [[
		'classe' => $message['ok'] ? 'success' : 'error',
		'texte' => spip_htmlspecialchars($message['texte']),
	]];
}
