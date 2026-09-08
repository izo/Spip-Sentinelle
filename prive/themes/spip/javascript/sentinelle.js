(function () {
	'use strict';
	var racine = document.querySelector('[data-sentinelle]');
	if (!racine) return;

	var lignes = Array.prototype.slice.call(racine.querySelectorAll('[data-sentinelle-ligne]'));
	var recherche = racine.querySelector('[data-sentinelle-recherche]');
	var gravite = racine.querySelector('[data-sentinelle-gravite]');
	var regle = racine.querySelector('[data-sentinelle-regle]');
	var repertoire = racine.querySelector('[data-sentinelle-repertoire]');
	var resultat = racine.querySelector('[data-sentinelle-resultats]');
	var precedent = racine.querySelector('[data-sentinelle-precedent]');
	var suivant = racine.querySelector('[data-sentinelle-suivant]');
	var pageTexte = racine.querySelector('[data-sentinelle-page]');
	var page = 1;
	var taillePage = 50;

	function visibles() {
		var texte = (recherche && recherche.value || '').toLowerCase().trim();
		var niveau = gravite && gravite.value || '';
		var type = regle && regle.value || '';
		var dossier = repertoire && repertoire.value || '';
		return lignes.filter(function (ligne) {
			return (!texte || ligne.getAttribute('data-search').indexOf(texte) !== -1)
				&& (!niveau || ligne.getAttribute('data-gravite') === niveau)
				&& (!type || (' ' + ligne.getAttribute('data-regles') + ' ').indexOf(' ' + type + ' ') !== -1)
				&& (!dossier || ligne.getAttribute('data-repertoire').toLowerCase().indexOf(dossier.toLowerCase()) === 0);
		});
	}

	function afficher() {
		var filtrees = visibles();
		var pages = Math.max(1, Math.ceil(filtrees.length / taillePage));
		page = Math.min(page, pages);
		lignes.forEach(function (ligne) { ligne.hidden = true; });
		filtrees.slice((page - 1) * taillePage, page * taillePage).forEach(function (ligne) { ligne.hidden = false; });
		if (resultat) resultat.textContent = filtrees.length + ' / ' + lignes.length;
		if (pageTexte) pageTexte.textContent = page + ' / ' + pages;
		if (precedent) precedent.disabled = page <= 1;
		if (suivant) suivant.disabled = page >= pages;
		synchroniserTout();
	}

	[recherche, gravite, regle, repertoire].forEach(function (controle) {
		if (controle) controle.addEventListener('input', function () { page = 1; afficher(); });
	});
	if (precedent) precedent.addEventListener('click', function () { page--; afficher(); });
	if (suivant) suivant.addEventListener('click', function () { page++; afficher(); });

	var selection = racine.querySelector('[data-sentinelle-selection]');
	var compteur = racine.querySelector('[data-sentinelle-selection-compte]');
	var tout = racine.querySelector('[data-sentinelle-tout]');
	var quickWins = racine.querySelector('[data-sentinelle-quick-wins]');
	function casesDesLignes(lignesCibles) {
		return lignesCibles.map(function (ligne) {
			return ligne.querySelector('input[name="chemins[]"]');
		}).filter(function (caseACocher) { return !!caseACocher; });
	}
	function lignesDeLaPage() {
		return lignes.filter(function (ligne) { return !ligne.hidden; });
	}
	function synchroniserTout() {
		if (!tout) return;
		var cases = casesDesLignes(lignesDeLaPage());
		var cochees = cases.filter(function (caseACocher) { return caseACocher.checked; }).length;
		tout.disabled = cases.length === 0;
		tout.checked = cases.length > 0 && cochees === cases.length;
		tout.indeterminate = cochees > 0 && cochees < cases.length;
	}
	function compterSelection() {
		var n = racine.querySelectorAll('input[name="chemins[]"]:checked').length;
		if (selection) selection.hidden = n === 0;
		if (compteur) compteur.textContent = n;
		synchroniserTout();
	}
	racine.addEventListener('change', function (event) {
		if (event.target && event.target.name === 'chemins[]') compterSelection();
	});
	if (tout) tout.addEventListener('change', function () {
		casesDesLignes(lignesDeLaPage()).forEach(function (caseACocher) { caseACocher.checked = tout.checked; });
		compterSelection();
	});
	if (quickWins) quickWins.addEventListener('click', function () {
		casesDesLignes(lignes).forEach(function (caseACocher) { caseACocher.checked = false; });
		casesDesLignes(lignes.filter(function (ligne) {
			return ligne.getAttribute('data-gravite') === 'critique';
		})).forEach(function (caseACocher) { caseACocher.checked = true; });
		if (gravite) gravite.value = 'critique';
		page = 1;
		afficher();
		compterSelection();
		if (selection) selection.scrollIntoView({ block: 'nearest' });
	});

	racine.addEventListener('click', function (event) {
		var bouton = event.target.closest('[data-copy]');
		if (!bouton) return;
		var valeur = bouton.getAttribute('data-copy');
		if (navigator.clipboard) navigator.clipboard.writeText(valeur);
		bouton.setAttribute('aria-pressed', 'true');
		window.setTimeout(function () { bouton.setAttribute('aria-pressed', 'false'); }, 1200);
	});

	var formulaire = racine.querySelector('[data-sentinelle-form-selection]');
	if (formulaire) formulaire.addEventListener('submit', function (event) {
		var message = formulaire.getAttribute('data-confirm');
		if (message && !window.confirm(message)) event.preventDefault();
	});

	afficher();
	compterSelection();
}());
