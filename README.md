# Vérification des chiffres créateurs · Network Partners

Code source de la page **https://verif.networkpartners.xyz**, qui permet à un créateur de vérifier
lui-même que les chiffres de son dashboard viennent bien du site d'affiliation du casino, sans que
personne (nous compris) ait pu les modifier.

Ce dépôt existe pour une seule raison : que tu n'aies pas à nous croire sur parole. Tout ce que la page
fait dans ton navigateur est ici, et tu peux vérifier que c'est exactement ce code qui tourne.

## Comment ça marche, en bref

La vérification utilise [TLSNotary](https://github.com/tlsnotary/tlsn), un projet open source de
l'équipe de recherche de la Fondation Ethereum (version `v0.1.0-alpha.15`, mode MPC-TLS).

1. Notre serveur ouvre une connexion chiffrée (https) avec le site d'affiliation du casino.
2. **Ton navigateur participe à cette connexion** par un calcul partagé (MPC) : notre serveur ne peut ni
   inventer la réponse du casino, ni la modifier, sans que ton navigateur le voie.
3. Ton navigateur vérifie le **certificat** du site (comme le cadenas de ta barre d'adresse), puis la
   **preuve** que les données révélées sont exactement celles envoyées par le casino.
4. Seules tes lignes sont révélées. Les autres créateurs, notre commission et ce qui porte notre
   accord avec le casino (nom de l'offre, fin du nom de campagne) restent masqués par la preuve elle-même.

Il n'y a pas de « fichier de preuve » à faire vérifier ailleurs : dans ce mode, **le vérificateur, c'est
ton navigateur**. La question qui compte est donc : *le code qui tourne dans mon navigateur est-il bien
celui-ci ?* La section « Vérifier ce qui tourne » y répond.

## Ce que la page contrôle (fichier `main.js`, fonction `check`)

La page **refuse** la preuve, et l'affiche en rouge, si :

- le serveur prouvé n'est pas celui attendu pour ce casino. La liste est écrite en dur dans le code,
  notre serveur ne peut pas la choisir :
  `const HOSTS = { mystake: 'affiliateapi.cellxpert.com', rolletto: 'affiliateapi.cellxpert.com', celsius: 'celsiuspartner.com' }` ;
- la période demandée au casino (la requête est révélée dans la preuve) n'est pas celle affichée ;
- une ligne révélée ne contient pas ton identifiant (ton `afp` chez Rolletto et MyStake, le début de ton
  nom de campagne chez Celsius) ;
- une ligne révélée est illisible.

Le vérificateur TLSNotary lui-même tourne dans `worker.js` (classe `Verifier` du module officiel,
certificats racines par défaut du module).

## Ce que ça ne prouve pas

Soyons honnêtes sur les limites :

- que le casino compte juste : la preuve montre ce que **le casino** a répondu, pas que son système est
  exempt d'erreur ;
- le calcul de ta commission : la preuve porte sur tes joueurs, leurs dépôts et leur NGR, pas sur ton
  contrat ;
- que la liste est **complète** : c'est notre serveur qui choisit quelles lignes de la réponse révéler,
  parce qu'on ne peut pas divulguer les pseudos et les chiffres des joueurs de nos autres créateurs.
  Le site d'affiliation du casino renvoie tous les joueurs de tous nos créateurs en une seule réponse, et
  ne sait pas filtrer par créateur de son côté (testé sur CellXpert, la plateforme de Rolletto et MyStake,
  avec onze noms de paramètre). Prouver qu'aucune ligne masquée n'est à toi obligerait à révéler les autres
  créateurs, et TLSNotary ne sait pas encore prouver « cette ligne n'est pas à toi » sans la montrer.
  La preuve garantit que tout ce qui est montré est authentique, pas que rien n'a été omis. Pour le
  vérifier toi-même : inscris-toi avec ton propre lien, fais un dépôt, puis relance une vérification ; ton
  compte doit apparaître dans la liste ;
- TLSNotary est en version alpha et n'a pas encore été audité par un tiers.

## Comment sont comptés les chiffres affichés

- **Celsius** : la réponse contient les joueurs **inscrits** pendant la période ; leurs dépôts, GGR et NGR
  sont des totaux depuis l'inscription. **FTD** = joueurs de cette liste avec au moins un dépôt
  (`dep_count > 0`).
- **Rolletto, MyStake** : chaque ligne est l'activité d'un joueur **sur la période** ; **déposants** =
  joueurs avec au moins un dépôt sur cette période.

## Vérifier ce qui tourne

Le module de vérification (`pkg/`) n'est pas dans ce dépôt : il se **compile** à partir du code officiel
de TLSNotary, avec la recette `Dockerfile.wasm`.

```bash
# 1. Compiler le module officiel (Docker requis, 15 à 30 minutes)
docker build -f Dockerfile.wasm -t tlsn-wasm .
cid=$(docker create tlsn-wasm) && docker cp "$cid:/tlsn/crates/wasm/pkg" ./pkg && docker rm "$cid"

# 2. Télécharger les fichiers réellement servis par la page
mkdir served && cd served
for f in index.html main.js worker.js pkg/tlsn_wasm.js pkg/tlsn_wasm_bg.wasm pkg/spawn.js; do
  curl -s --create-dirs -o "$f" "https://verif.networkpartners.xyz/$f"
done
cd ..

# 3. Comparer : les empreintes doivent être identiques deux à deux
shasum -a 256 index.html main.js worker.js pkg/tlsn_wasm.js pkg/tlsn_wasm_bg.wasm pkg/spawn.js
shasum -a 256 served/index.html served/main.js served/worker.js served/pkg/tlsn_wasm.js served/pkg/tlsn_wasm_bg.wasm served/pkg/spawn.js
```

Les empreintes attendues sont aussi publiées dans `EMPREINTES.txt`, à chaque version.

## Contact

contact@networkpartners.xyz · Telegram @Network_Contact
