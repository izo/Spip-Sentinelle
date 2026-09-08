<?php

declare(strict_types=1);

$racineTests = sys_get_temp_dir() . '/sentinelle-tests-' . getmypid() . '-' . bin2hex(random_bytes(4));
$site = $racineTests . '/site';
$etat = $racineTests . '/state';
mkdir($site, 0755, true);
mkdir($etat, 0700, true);
define('_SENTINELLE_ETAT_DIR', $etat);
define('_ECRIRE_INC_VERSION', 'test');
define('_ROOT_RACINE', $site . '/');
define('_LOG_ERREUR', 1);
define('_LOG_INFO', 2);
define('_LOG_INFO_IMPORTANTE', 3);

$GLOBALS['meta'] = ['email_webmaster' => 'webmaster@example.test', 'nom_site' => 'Test'];
$GLOBALS['visiteur_session'] = ['id_auteur' => 1];
$GLOBALS['mail_reussit'] = false;

function spip_log($message, $niveau = null): void {}
function include_spip($fichier): void {}
function charger_fonction($nom, $repertoire) {
	return function ($destinataire, $sujet, $corps) {
		return (bool) $GLOBALS['mail_reussit'];
	};
}
function url_absolue($url): string { return 'https://example.test/' . ltrim($url, '/'); }
function generer_url_ecrire($page): string { return 'ecrire/?exec=' . $page; }

require_once dirname(__DIR__) . '/lib/ioc.php';
require_once dirname(__DIR__) . '/lib/scanner.php';
require_once dirname(__DIR__) . '/lib/baseline.php';
require_once dirname(__DIR__) . '/lib/state.php';
require_once dirname(__DIR__) . '/lib/quarantaine.php';
require_once dirname(__DIR__) . '/inc/sentinelle.php';
require_once dirname(__DIR__) . '/genie/sentinelle.php';
require_once dirname(__DIR__) . '/sentinelle_autoriser.php';

$tests = 0;
$echecs = [];
function verifier(bool $condition, string $message): void {
	global $tests, $echecs;
	$tests++;
	if (!$condition) {
		$echecs[] = $message;
	}
}
function ecrire_fixture(string $racine, string $rel, string $contenu): void {
	$dir = dirname($racine . '/' . $rel);
	if (!is_dir($dir)) mkdir($dir, 0755, true);
	file_put_contents($racine . '/' . $rel, $contenu);
}
function supprimer_fixture(string $chemin): void {
	if (is_link($chemin) || is_file($chemin)) { @unlink($chemin); return; }
	if (!is_dir($chemin)) return;
	foreach (new FilesystemIterator($chemin, FilesystemIterator::SKIP_DOTS) as $item) supprimer_fixture($item->getPathname());
	@rmdir($chemin);
}

// Le pipeline d'autorisation ne doit jamais détruire la valeur qu'il charge.
$fluxAutoriser = ['sentinelle' => true];
verifier(sentinelle_autoriser($fluxAutoriser) === $fluxAutoriser, 'le pipeline autoriser doit restituer son flux');

// Le préfiltre doit livrer les doubles extensions au pipeline complet.
ecrire_fixture($site, 'uploads/shell.php.jpg', '<?php echo 1;');
$liste = sentinelle_scan_lister($site);
verifier(in_array('uploads/shell.php.jpg', $liste, true), 'shell.php.jpg doit être découvert');
$double = sentinelle_scan_chemin($site, 'uploads/shell.php.jpg');
verifier(count($double) > 0, 'shell.php.jpg doit déclencher une règle');

// Les bibliothèques sous auto/ suivent les conventions PSR-4 légitimes.
ecrire_fixture($site, 'auto/scssphp/v3/src/AtRootBlock.php', '<?php class AtRootBlock {}');
$psr = sentinelle_scan_chemin($site, 'auto/scssphp/v3/src/AtRootBlock.php');
verifier(!array_filter($psr, function ($f) { return ($f['regle'] ?? '') === 'nom_motif'; }), 'auto/ ne doit pas produire le faux positif CamelCase');

// La découverte se reprend avec un curseur et ne perd aucun chemin.
$decouverte = sentinelle_scan_decouverte_initialiser();
$decouverte = sentinelle_scan_decouvrir_tranche($site, $decouverte, PHP_FLOAT_MAX, 1);
verifier(empty($decouverte['terminee']), 'une petite tranche de découverte doit demander une reprise');
while (empty($decouverte['terminee'])) {
	$decouverte = sentinelle_scan_decouvrir_tranche($site, $decouverte, PHP_FLOAT_MAX, 2);
}
verifier(in_array('uploads/shell.php.jpg', $decouverte['fichiers'], true), 'la découverte fractionnée doit conserver les fichiers');

// Un fichier illisible devient un diagnostic de couverture, pas un silence.
ecrire_fixture($site, 'uploads/illisible.php', '<?php echo 1;');
chmod($site . '/uploads/illisible.php', 0000);
$illisible = sentinelle_scan_chemin($site, 'uploads/illisible.php');
verifier((bool) array_filter($illisible, function ($f) { return ($f['regle'] ?? '') === 'couverture'; }), 'un fichier illisible doit produire un finding de couverture');
chmod($site . '/uploads/illisible.php', 0644);

// Un lien symbolique est signalé mais jamais suivi par la quarantaine.
ecrire_fixture($racineTests, 'externe.php', '<?php echo "outside";');
symlink($racineTests . '/externe.php', $site . '/lien.php');
$modeAvant = fileperms($racineTests . '/externe.php') & 0777;
$refusLien = sentinelle_quarantaine_deplacer($site, 'lien.php', 'test');
$modeApres = fileperms($racineTests . '/externe.php') & 0777;
verifier(!$refusLien['ok'], 'la quarantaine doit refuser un symlink');
verifier($modeAvant === $modeApres, 'la cible externe ne doit jamais subir chmod');

// Stockage réellement extérieur et charge renommée sans extension exécutable.
ecrire_fixture($site, 'uploads/malveillant.php', '<?php echo "payload";');
$isole = sentinelle_quarantaine_deplacer($site, 'uploads/malveillant.php', 'lot-test', 'test');
verifier($isole['ok'], 'un fichier signalable doit pouvoir être isolé');
verifier(!sentinelle_chemin_dans(sentinelle_repertoire_etat($site), realpath($site)), 'le stockage doit être hors webroot');
verifier(substr($isole['entree']['destination'], -8) === '.payload', 'la charge isolée doit porter un nom non exécutable');
verifier(!file_exists($site . '/uploads/malveillant.php'), 'la source doit quitter le site');
$restaure = sentinelle_quarantaine_restaurer($site, 'uploads/malveillant.php');
verifier($restaure['ok'] && is_file($site . '/uploads/malveillant.php'), 'la restauration valide doit réussir');

// Une charge altérée ne doit pas revenir dans le site.
ecrire_fixture($site, 'uploads/a-verifier.php', '<?php echo "original";');
$alt = sentinelle_quarantaine_deplacer($site, 'uploads/a-verifier.php', 'lot-alt', 'test');
file_put_contents(sentinelle_repertoire_etat($site) . '/' . $alt['entree']['destination'], 'tampered');
$refusHash = sentinelle_quarantaine_restaurer($site, 'uploads/a-verifier.php');
verifier(!$refusHash['ok'], 'une charge modifiée doit être refusée à la restauration');

// Traversées et composants symboliques sont refusés.
verifier(sentinelle_quarantaine_autorisee('../secret.php') !== true, 'la traversée doit être refusée');
verifier(sentinelle_quarantaine_autorisee('/etc/passwd') !== true, 'un chemin absolu doit être refusé');

// JSON corrompu conservé, puis remplacé atomiquement par une valeur valide.
$dirEtat = sentinelle_repertoire_etat($site);
file_put_contents($dirEtat . '/corruption.json', '{invalide');
$lu = sentinelle_etat_lire_fichier($dirEtat, 'corruption.json', ['secours' => true]);
verifier(!empty($lu['secours']), 'un JSON corrompu doit retourner le défaut');
verifier(file_get_contents($dirEtat . '/corruption.json') === '{invalide', 'le JSON corrompu doit être conservé pour diagnostic');
verifier(sentinelle_etat_ecrire_fichier($dirEtat, 'corruption.json', ['ok' => true]), 'l’écriture atomique doit réussir');
verifier(sentinelle_etat_lire_fichier($dirEtat, 'corruption.json', [])['ok'] === true, 'l’état atomique doit être relisible');

// Modifications concurrentes sous verrou (si pcntl est disponible).
sentinelle_etat_ecrire_fichier($dirEtat, 'compteur.json', ['n' => 0]);
if (function_exists('pcntl_fork')) {
	$enfants = [];
	for ($i = 0; $i < 4; $i++) {
		$pid = pcntl_fork();
		if ($pid === 0) {
			for ($j = 0; $j < 20; $j++) {
				sentinelle_etat_modifier_fichier($dirEtat, 'compteur.json', function ($v) { $v['n']++; return $v; }, ['n' => 0]);
			}
			exit(0);
		}
		$enfants[] = $pid;
	}
	foreach ($enfants as $pid) pcntl_waitpid($pid, $status);
	verifier(sentinelle_etat_lire_fichier($dirEtat, 'compteur.json', [])['n'] === 80, 'les mises à jour concurrentes ne doivent pas se perdre');
}

// Une notification échouée reste en file puis est acquittée après succès.
$GLOBALS['mail_reussit'] = false;
verifier(!sentinelle_mail_envoyer('Sujet test', 'Corps test'), 'le premier envoi simulé doit échouer');
verifier(count((array) sentinelle_etat_lire('notifications.json', [])) === 1, 'le mail échoué doit rester en file');
$GLOBALS['mail_reussit'] = true;
verifier(sentinelle_notifications_rejouer() === 1, 'le rejeu doit envoyer le mail en attente');
verifier(count((array) sentinelle_etat_lire('notifications.json', [])) === 0, 'le mail réussi doit être acquitté');

// La baseline et le résumé restent fonctionnels en PHP pur.
$baseline = sentinelle_baseline_construire($site);
verifier($baseline['nombre'] > 0, 'la baseline doit contenir les fixtures exécutables');
ecrire_fixture($site, 'nouveau.php', '<?php echo 2;');
$differences = sentinelle_baseline_comparer($site, $baseline);
verifier((bool) array_filter($differences, function ($f) { return ($f['regle'] ?? '') === 'baseline_ajout'; }), 'la baseline doit détecter un ajout');

// Les deux passes de cohérence sont elles aussi fractionnables.
$etatCompare = ['phase' => 'coherence_reference', 'comparaison_position' => 0, 'baseline_courante' => ['a.php' => 'nouveau'], 'findings' => []];
$refCompare = ['genere_le' => time() - 60, 'fichiers' => ['a.php' => 'ancien', 'b.php' => 'absent']];
$etatCompare = sentinelle_cron_comparer_tranche($etatCompare, $refCompare, PHP_FLOAT_MAX);
verifier($etatCompare['phase'] === 'coherence_ajouts', 'la comparaison doit passer à la phase des ajouts');
$etatCompare = sentinelle_cron_comparer_tranche($etatCompare, $refCompare, PHP_FLOAT_MAX);
verifier($etatCompare['phase'] === 'finalisation' && count($etatCompare['findings']) === 2, 'les différences fractionnées doivent être complètes');

// Les catalogues de langue doivent couvrir exactement les clés du squelette.
function catalogue(string $fichier, string $langue): array {
	$GLOBALS['idx_lang'] = 'test_' . $langue;
	$GLOBALS[$GLOBALS['idx_lang']] = [];
	include $fichier;
	return $GLOBALS[$GLOBALS['idx_lang']];
}
$fr = catalogue(dirname(__DIR__) . '/lang/sentinelle_fr.php', 'fr');
$en = catalogue(dirname(__DIR__) . '/lang/sentinelle_en.php', 'en');
verifier(array_diff_key($fr, $en) === [] && array_diff_key($en, $fr) === [], 'les catalogues français et anglais doivent avoir les mêmes clés');
$squelette = file_get_contents(dirname(__DIR__) . '/prive/squelettes/contenu/sentinelle.html');
preg_match_all('/<:sentinelle:([a-z0-9_]+)/', $squelette, $cles);
verifier(array_diff(array_unique($cles[1]), array_keys($fr)) === [], 'toutes les chaînes du squelette doivent exister');

// Le bilan ne doit pas laisser sa colonne secondaire écraser le résumé.
$css = file_get_contents(dirname(__DIR__) . '/prive/themes/spip/css/sentinelle.css');
verifier(
	(bool) preg_match('/\.sentinelle-etat\s*\{[^}]*grid-template-columns:\s*repeat\(auto-fit,/s', $css),
	'le bilan doit adapter ses colonnes à la largeur de la carte'
);

// Les crochets du nom de champ ne doivent pas fermer prématurément le
// bloc conditionnel SPIP qui entoure la case à cocher.
verifier(
	strpos($squelette, 'name="chemins&#91;&#93;"') !== false && strpos($squelette, 'name="chemins[]"') === false,
	'la sélection multiple doit conserver un balisage SPIP compilable'
);

supprimer_fixture($racineTests);
if ($echecs) {
	fwrite(STDERR, "ÉCHECS (" . count($echecs) . "/$tests)\n- " . implode("\n- ", $echecs) . "\n");
	exit(1);
}
echo "OK — $tests assertions\n";
