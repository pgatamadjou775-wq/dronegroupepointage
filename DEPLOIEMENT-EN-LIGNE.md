# Héberger Sha'ah en ligne (une instance par entreprise)

Ce dossier est prêt à être déployé sur un hébergeur en ligne (Render,
Railway, etc.) pour que la tablette de pointage et l'espace RH soient
accessibles depuis n'importe où — plus besoin d'être sur le même Wi-Fi.

**Principe retenu : une instance séparée par entreprise cliente.**
Chaque entreprise a son propre serveur, ses propres données, son
propre sous-domaine (ex: `acme.votredomaine.com`). Pour déployer un
nouveau client, on répète simplement les étapes ci-dessous avec un
nouveau dossier/dépôt Git.

---

## ⚠️ Point important : le stockage des données

Ce logiciel enregistre tout dans un fichier `data.json`. Sur la
plupart des hébergeurs gratuits, le disque est **effacé à chaque
redémarrage du serveur** (mise à jour, veille après inactivité...).

**➜ Il faut donc activer un disque persistant** chez l'hébergeur choisi
(voir instructions Render ci-dessous — quelques euros/mois) pour ne
jamais perdre les données de pointage. Sans ça, testez uniquement,
ne mettez pas en production.

---

## Option recommandée : Render.com

### 1. Mettre le code sur GitHub
- Créez un dépôt GitHub (public ou privé) et déposez-y tout le contenu
  de ce dossier (`server.js`, `package.json`, `public/`, etc.)
- Le fichier `.gitignore` fourni exclut déjà `data.json` du dépôt
  (les données ne doivent jamais être dans le code)

### 2. Créer le service sur Render
1. Allez sur https://render.com et créez un compte
2. **New +** → **Web Service**
3. Connectez votre dépôt GitHub
4. Renseignez :
   - **Name** : le nom de votre choix (ex: `acme-presence`)
   - **Runtime** : `Node`
   - **Build Command** : *(laisser vide, aucune dépendance)*
   - **Start Command** : `node server.js`
   - **Instance Type** : le plus petit payant suffit largement (le
     plan gratuit ne permet pas de disque persistant)

### 3. Ajouter le disque persistant (IMPORTANT)
1. Dans les réglages du service → **Disks** → **Add Disk**
2. **Mount Path** : `/data`
3. Taille : 1 Go suffit largement
4. Dans **Environment**, ajoutez la variable :
   - `DATA_FILE` = `/data/data.json`

### 4. Déployer
- Render construit et démarre automatiquement le service
- Ouvrez l'onglet **Logs** : au tout premier démarrage, le serveur
  affiche l'identifiant et le mot de passe RH générés automatiquement,
  ainsi que le code d'activation des tablettes. **Notez-les immédiatement**,
  ils ne seront plus jamais réaffichés en clair.
- Render fournit une adresse du type :
  `https://acme-presence.onrender.com` (HTTPS automatique, cadenas inclus)

### 5. (Optionnel) Nom de domaine personnalisé
1. Dans le service Render → **Settings** → **Custom Domains**
2. Ajoutez `acme.votredomaine.com`
3. Chez votre registrar (OVH, Gandi, Namecheap...), créez un enregistrement
   **CNAME** pointant `acme` vers l'adresse fournie par Render
4. Render active le HTTPS automatiquement (certificat gratuit)

---

## Alternative : Railway.app

Le principe est identique :
1. https://railway.app → **New Project** → **Deploy from GitHub repo**
2. Railway détecte Node.js automatiquement (grâce à `package.json`)
3. Ajoutez un **Volume** (équivalent du disque persistant), monté par
   exemple sur `/data`, puis définissez `DATA_FILE=/data/data.json`
   dans les variables d'environnement
4. Railway fournit une adresse `https://....up.railway.app`, avec
   possibilité d'ajouter un domaine personnalisé dans **Settings → Domains**

---

## Une fois en ligne

- **RH** : ouvrez `https://acme.votredomaine.com/rh.html`, connectez-vous
  avec l'identifiant/mot de passe notés dans les logs au premier démarrage,
  puis changez immédiatement le mot de passe dans
  **Employés → Sécurité → Modifier mon identifiant / mot de passe**.
- **Tablette de pointage** : ouvrez
  `https://acme.votredomaine.com/pointage.html`, saisissez le code
  d'activation (visible et régénérable à tout moment dans
  **Employés → Sécurité** côté RH). Une fois activée, la tablette reste
  activée durablement (pas besoin de ressaisir le code à chaque fois).
- Ajoutez `/pointage.html` à l'écran d'accueil de la tablette (menu du
  navigateur → "Ajouter à l'écran d'accueil") pour un accès en un tap.

## Sécurité — ce que cette version apporte par rapport à la version
## réseau local

- L'espace RH n'est plus protégé par un simple code à 4 chiffres, mais
  par un vrai identifiant + mot de passe, avec limitation du nombre de
  tentatives de connexion.
- Les tablettes de pointage n'ont accès qu'aux actions de pointage —
  jamais à l'ensemble des données RH — grâce à un jeton d'activation
  dédié, révocable à tout moment (régénération = déconnexion immédiate
  de toutes les tablettes).
- L'heure de pointage est toujours celle du **serveur**, jamais celle
  de l'appareil utilisé — impossible de tricher en modifiant l'horloge
  de la tablette.
- Les mots de passe ne sont jamais stockés ni renvoyés en clair
  (hachage scrypt).
- HTTPS (cadenas) fourni automatiquement par l'hébergeur.

## Pour tester en local avant de déployer

Les scripts `demarrer.bat` / `demarrer.sh` fonctionnent toujours pour
tester sur votre PC avant mise en ligne — voir `LISEZ-MOI.txt`.
