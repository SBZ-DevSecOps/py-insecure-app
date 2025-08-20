#!/usr/bin/env python3
import os, sqlite3, yaml, pickle, hashlib, random, tempfile, requests, urllib3, tarfile, zipfile, ssl, subprocess, logging, json, importlib
from xml.etree import ElementTree as ET

urllib3.disable_warnings()
logging.basicConfig(level=logging.DEBUG)

DB = 'app.db'
HARDCODED_SECRET = 'supersecret'          # CWE-798
API_TOKEN = 'AKIA1234567890FAKE'          # Secret scanning (fake AWS-like)
DEFAULT_KEY = 'p@ssw0rd'                  # Secret en clair

def init_db():
    con = sqlite3.connect(DB)
    cur = con.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    cur.execute("DELETE FROM users")
    cur.execute("INSERT INTO users(username,password,role) VALUES('admin','admin','admin')")
    con.commit(); con.close()

def login_unsafe(username, password):
    con = sqlite3.connect(DB)
    cur = con.cursor()
    # CWE-89: injection SQL par concat
    q = f"SELECT id, role FROM users WHERE username='{username}' AND password='{password}'"
    logging.debug("Query=%s", q)          # fuite d’info
    return cur.execute(q).fetchone()

def exec_cmd_unsafe(cmd):
    # CWE-78: injection commande (shell=True)
    subprocess.Popen(cmd, shell=True)

def hash_md5(pw):
    # CWE-327: algo faible
    return hashlib.md5(pw.encode()).hexdigest()

def random_token():
    # CWE-338: PRNG non crypto
    return str(random.random())

def load_yaml_unsafe(path):
    with open(path, 'rb') as f:
        # PyYAML <5.4: yaml.load non safe
        return yaml.load(f.read(), Loader=None)

def unpickle_unsafe(path):
    with open(path, 'rb') as f:
        # CWE-502: désérialisation non sûre
        return pickle.loads(f.read())

def get_url_insecure(url):
    # CWE-295 + SSRF (aucun filtrage, verify=False)
    return requests.get(url, verify=False, allow_redirects=True,
                        headers={'Authorization': f'Bearer {API_TOKEN}'}).text[:200]

def path_traversal(filename):
    # CWE-22
    base = 'data'
    with open(os.path.join(base, filename), 'r') as f:
        return f.read()

def tmpfile_insecure():
    # CWE-377: mktemp est vulnérable (race)
    name = tempfile.mktemp(prefix="insecure_", suffix=".tmp")
    with open(name, 'w') as f:
        f.write('hello')
    os.chmod(name, 0o777)                 # CWE-732: permissions trop larges
    return name

def insecure_tar_extract(p):
    # CWE-22 via tarfile.extractall (Zip/Tar Slip)
    with tarfile.open(p) as t:
        t.extractall("extracted")         # pas de validation du chemin

def insecure_zip_extract(p):
    with zipfile.ZipFile(p) as z:
        z.extractall("extracted")         # idem zip slip

def eval_unsafe(expr):
    # CWE-94: eval de données non fiables
    return eval(expr)

def ssl_noverify(url):
    # désactive la vérif TLS au niveau SSLContext
    ctx = ssl._create_unverified_context()
    import urllib.request as ur
    return ur.urlopen(url, context=ctx).read()[:120]

def assert_auth(user, role_required):
    # CWE-617: utiliser assert pour la sécurité (désactivable avec -O)
    assert user and user.get('role') == role_required, "not authorized"
    return True

def dynamic_import(mod):
    # chargement dynamique non contrôlé (peut exécuter du code d’import)
    return importlib.import_module(mod)

def exec_sql_script(script_text):
    con = sqlite3.connect(DB)
    cur = con.cursor()
    # CWE-89: executescript de contenu non fiable
    cur.executescript(script_text)
    con.commit(); con.close()

def parse_xml_unsafe(p):
    # xml.etree ne gère pas DTD externes, mais on illustre parsing non sécurisé
    tree = ET.parse(p)  # pas de défense (ex: defusedxml)
    return tree.getroot().tag

if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--initdb', action='store_true')
    p.add_argument('--login', nargs=2, metavar=('USER','PASS'))
    p.add_argument('--cmd')
    p.add_argument('--hash')
    p.add_argument('--token', action='store_true')
    p.add_argument('--yaml')
    p.add_argument('--pickle')
    p.add_argument('--url')
    p.add_argument('--read')
    p.add_argument('--tmp', action='store_true')
    p.add_argument('--untar')
    p.add_argument('--unzip')
    p.add_argument('--eval')
    p.add_argument('--ssl')
    p.add_argument('--assert', dest='assert_args', nargs=2, metavar=('USER','ROLE'))
    p.add_argument('--dimport')
    p.add_argument('--sqlscript')
    p.add_argument('--xml')
    args = p.parse_args()

    if args.initdb: init_db()
    if args.login:
        rec = login_unsafe(args.login[0], args.login[1])
        print({'id': rec[0], 'role': rec[1]} if rec else None)
    if args.cmd: exec_cmd_unsafe(args.cmd)
    if args.hash: print(hash_md5(args.hash))
    if args.token: print(random_token())
    if args.yaml: print(load_yaml_unsafe(args.yaml))
    if args.pickle: print(unpickle_unsafe(args.pickle))
    if args.url: print(get_url_insecure(args.url))
    if args.read: print(path_traversal(args.read))
    if args.tmp: print(tmpfile_insecure())
    if args.untar: insecure_tar_extract(args.untar)
    if args.unzip: insecure_zip_extract(args.unzip)
    if args.eval: print(eval_unsafe(args.eval))
    if args.ssl: print(ssl_noverify(args.ssl))
    if args.assert_args:
        user = {'name': args.assert_args[0], 'role':'user'}
        print(assert_auth(user, args.assert_args[1]))
    if args.dimport: print(dynamic_import(args.dimport))
    if args.sqlscript: exec_sql_script(args.sqlscript)
    if args.xml: print(parse_xml_unsafe(args.xml))
