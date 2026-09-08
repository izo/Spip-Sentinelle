<?php

/**
 * Compile le tableau de bord avec un SPIP propre.
 * Usage : php tests/compile-skeleton.php /chemin/vers/spip
 */

$spip = realpath($argv[1] ?? '');
if ($spip === false || !is_file($spip . '/ecrire/inc_version.php')) {
	fwrite(STDERR, "Racine SPIP invalide.\n");
	exit(2);
}
chdir($spip);
$_REQUEST['exec'] = 'install';
$_SERVER['PHP_SELF'] = '/ecrire/index.php';
$_SERVER['SCRIPT_NAME'] = '/ecrire/index.php';
$_SERVER['REQUEST_URI'] = '/ecrire/?exec=install';
define('_FILE_CONNECT', 'sentinelle-test-sans-base');
require $spip . '/vendor/autoload.php';
require $spip . '/ecrire/inc_version.php';
include_spip('public/composer');
require_once dirname(__DIR__) . '/prive/squelettes/contenu/sentinelle_fonctions.php';

$squelette = realpath(dirname(__DIR__) . '/prive/squelettes/contenu/sentinelle');
if ($squelette === false) {
	$squelette = dirname(__DIR__) . '/prive/squelettes/contenu/sentinelle';
}
$fonction = public_composer_dist('sentinelle_test_' . substr(md5_file($squelette . '.html'), 0, 8), 'html', 'html', $squelette . '.html');
if (!$fonction) {
	$compiler = charger_fonction('compiler', 'public');
	$diagnostic = $compiler((string) file_get_contents($squelette . '.html'), 'sentinelle_diagnostic', 'html', $squelette . '.html');
	foreach ((array) $diagnostic as $id => $boucle) {
		if (isset($boucle->return)) {
			try {
				eval('return true; ' . $boucle->return);
			} catch (ParseError $e) {
				$lignes = explode("\n", $boucle->return);
				$ligne = max(0, $e->getLine() - 2);
				fwrite(STDERR, "--- $id : " . $e->getMessage() . " ---\n" . implode("\n", array_slice($lignes, $ligne, 8)) . "\n");
			}
		}
	}
	fwrite(STDERR, "Échec de compilation du squelette Sentinelle.\n");
	exit(1);
}
$sourceSquelette = (string) file_get_contents($squelette . '.html');
if (preg_match('/#GET\{resume\//', $sourceSquelette)) {
	fwrite(STDERR, "Le squelette lit une fausse clé resume/... au lieu du tableau resume.\n");
	exit(1);
}
echo "OK — squelette compilé par SPIP\n";
