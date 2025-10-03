from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import requests
import time
import json
import sqlite3
import os, re
from werkzeug.security import generate_password_hash, check_password_hash
try:
    import psycopg
except ImportError:
    psycopg = None

app = Flask(__name__)
app.secret_key = "chave_secreta"

API_LOGIN = "https://simplix-integration.partner1.com.br/api/Login"
API_SIMULATE = "https://simplix-integration.partner1.com.br/api/Proposal/Simulate"

TOKEN = ""
TOKEN_EXPIRA = 0

DATABASE_URL = os.environ.get("DATABASE_URL") 
DB_FILE = "users.db"

def get_conn():
    if DATABASE_URL and psycopg:
        return psycopg.connect(DATABASE_URL)
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def init_db():
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            senha TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            background TEXT DEFAULT '#133abb,#00e1ff',
            data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """ if isinstance(conn, sqlite3.Connection) else """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            nome TEXT NOT NULL,
            senha TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            background TEXT DEFAULT '#133abb,#00e1ff',
            data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    if isinstance(conn, sqlite3.Connection):
        c.execute("UPDATE users SET background = ? WHERE background = ?", ("#133abb,#00e1ff", "blue"))
    else:
        c.execute("UPDATE users SET background = %s WHERE background = %s", ("#133abb,#00e1ff", "blue"))

    c.execute("""
        CREATE TABLE IF NOT EXISTS propostas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cpf TEXT,
            nome TEXT,
            valor REAL,
            status TEXT,
            data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """ if isinstance(conn, sqlite3.Connection) else """
        CREATE TABLE IF NOT EXISTS propostas (
            id SERIAL PRIMARY KEY,
            cpf TEXT,
            nome TEXT,
            valor REAL,
            status TEXT,
            data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    if isinstance(conn, sqlite3.Connection):
        c.execute("SELECT * FROM users WHERE role = ?", ("admin",))
    else:
        c.execute("SELECT * FROM users WHERE role = %s", ("admin",))

    if not c.fetchone():
        admin_user = "Leonardo"
        admin_pass = hash_senha("123456")
        if isinstance(conn, sqlite3.Connection):
            c.execute("INSERT INTO users (nome, senha, role, background) VALUES (?, ?, ?, ?)",
                      (admin_user, admin_pass, "admin", "#133abb,#00e1ff"))
        else:
            c.execute("INSERT INTO users (nome, senha, role, background) VALUES (%s, %s, %s, %s)",
                      (admin_user, admin_pass, "admin", "#133abb,#00e1ff"))
        print("✅ Usuário admin criado: login=Leonardo senha=123456")

    conn.commit()
    conn.close()


def hash_senha(senha):
    return generate_password_hash(senha)

def verificar_senha(senha_digitada, senha_hash):
    return check_password_hash(senha_hash, senha_digitada)

def is_admin():
    return session.get("role") == "admin"

def get_user(nome):
    conn = get_conn()
    c = conn.cursor()
    if isinstance(conn, sqlite3.Connection):
        c.execute("SELECT * FROM users WHERE nome = ?", (nome,))
    else:
        c.execute("SELECT * FROM users WHERE nome = %s", (nome,))
    user = c.fetchone()
    conn.close()
    return user

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        nome = request.form["nome"]
        senha = request.form["senha"]
        user = get_user(nome)

        if user and verificar_senha(senha, user[2]):
            session["user"] = nome
            session["role"] = user[3]
            return redirect(url_for("index"))

        return render_template("login.html", erro="Login inválido")

    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("index"))

    if request.method == "POST":
        nome = request.form["nome"]
        senha = hash_senha(request.form["senha"])
        role = request.form.get("role", "user")
        try:
            conn = get_conn()
            c = conn.cursor()
            if isinstance(conn, sqlite3.Connection):
                c.execute("INSERT INTO users (nome, senha, role) VALUES (?, ?, ?)", (nome, senha, role))
            else:
                c.execute("INSERT INTO users (nome, senha, role) VALUES (%s, %s, %s)", (nome, senha, role))
            conn.commit()
            conn.close()
            return redirect(url_for("gerenciar_usuarios"))
        except Exception as e:
            print("Erro ao registrar:", e)
            return render_template("register.html", erro="Nome já existe!")
    return render_template("register.html")

@app.route("/usuarios")
def gerenciar_usuarios():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("index"))

    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id, nome, role FROM users")
    usuarios = c.fetchall()
    conn.close()
    return render_template("usuarios.html", usuarios=usuarios)

@app.route("/excluir/<int:user_id>", methods=["POST"])
def excluir_usuario(user_id):
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("index"))

    conn = get_conn()
    c = conn.cursor()
    if isinstance(conn, sqlite3.Connection):
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    else:
        c.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()
    return redirect(url_for("gerenciar_usuarios"))

@app.route("/editar/<int:user_id>", methods=["GET", "POST"])
def editar_usuario(user_id):
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("index"))

    conn = get_conn()
    c = conn.cursor()

    if request.method == "POST":
        novo_nome = request.form["nome"]
        nova_senha = request.form["senha"]
        novo_background = request.form["background"]

        if nova_senha.strip():
            senha_hash = hash_senha(nova_senha)
            if isinstance(conn, sqlite3.Connection):
                c.execute("UPDATE users SET nome = ?, senha = ?, background = ? WHERE id = ?",
                          (novo_nome, senha_hash, novo_background, user_id))
            else:
                c.execute("UPDATE users SET nome = %s, senha = %s, background = %s WHERE id = %s",
                          (novo_nome, senha_hash, novo_background, user_id))
        else:
            if isinstance(conn, sqlite3.Connection):
                c.execute("UPDATE users SET nome = ?, background = ? WHERE id = ?",
                          (novo_nome, novo_background, user_id))
            else:
                c.execute("UPDATE users SET nome = %s, background = %s WHERE id = %s",
                          (novo_nome, novo_background, user_id))

        conn.commit()
        conn.close()
        return redirect(url_for("gerenciar_usuarios"))

    if isinstance(conn, sqlite3.Connection):
        c.execute("SELECT id, nome, role, background FROM users WHERE id = ?", (user_id,))
    else:
        c.execute("SELECT id, nome, role, background FROM users WHERE id = %s", (user_id,))
    user = c.fetchone()
    conn.close()
    return render_template("editar.html", user=user)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/index")
def index():
    if "user" not in session:
        return redirect(url_for("login"))

    cor1 = session.get("cor1", "#133abb")
    cor2 = session.get("cor2", "#00e1ff")

    return render_template("index.html",
                           usuario=session["user"],
                           cor1=cor1,
                           cor2=cor2)

def gerar_token():
    global TOKEN_EXPIRA
    try:
        dados = {"username": "477f702a-4a6f-4b02-b5eb-afcd38da99f8", "password": "b5iTIZ2n"}
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        resp = requests.post(API_LOGIN, json=dados, headers=headers, timeout=10)
        if resp.status_code == 200 and resp.json().get("success"):
            token = resp.json()["objectReturn"]["access_token"]
            TOKEN_EXPIRA = time.time() + 3600 - 60
            print(f"[TOKEN] Gerado com sucesso")
            return token
    except Exception as e:
        print(f"Erro ao gerar token: {e}")
    return ""

def obter_token():
    global TOKEN
    if not TOKEN or time.time() >= TOKEN_EXPIRA:
        TOKEN = gerar_token()
    return TOKEN

@app.route("/consultar-cpf", methods=["POST"])
def consultar_cpf_unico():
    data = request.get_json()
    cpf = data.get("cpf", "").strip()
    tabela = data.get("tabela", "").strip()

    if not tabela:
        return jsonify({
            "cpf": None,
            "tabela": None,
            "saldoBruto": 0,
            "valorLiberado": 0,
            "situacao": "Erro",
            "informacao": "⚠️ Escolha uma tabela antes de consultar",
            "final": True
        }), 400

    cpf = cpf.zfill(11)
    if not cpf or len(cpf) != 11 or not cpf.isdigit():
        return jsonify({"erro": "CPF inválido."}), 400

    for tentativa in range(5):
        resultado = consultar_cpf(cpf, tabela)
        if "limite" not in resultado["informacao"].lower():
            resultado["tabela"] = tabela
            return jsonify(resultado)
        time.sleep(2)

    return jsonify({
        "cpf": cpf,
        "tabela": tabela,
        "saldoBruto": 0,
        "valorLiberado": 0,
        "situacao": "Erro",
        "informacao": "Limite de tentativas atingido após 5 tentativas",
        "final": True
    })

def consultar_cpf(cpf, tabela=None):
    payload = {
        "cpf": cpf,
        "parcelas": 0,
        "convenio": 1,
        "produto": 1,
        "tabelaComercial": tabela
    }
    headers = {
        "Authorization": f"Bearer {obter_token()}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    try:
        resp = requests.post(API_SIMULATE, json=payload, headers=headers, timeout=60)
        txt = resp.text
        print(f"[{cpf}] 📡 Status Code: {resp.status_code}")

        try:
            data = resp.json()
            print(f"[{cpf}] RAW JSON:\n{json.dumps(data, indent=2, ensure_ascii=False)}")
        except Exception:
            data = {}
            print(f"[{cpf}] RAW TEXT:\n{txt}")

        simulacoes = (data.get("objectReturn", {}) or {}).get("retornoSimulacao", [])

        if tabela:
            for sim in simulacoes:
                if sim.get("tabelaCodigo") == tabela or sim.get("tabelaTitulo") == tabela:
                    detalhes = sim.get("detalhes", {}) or {}
                    msg_ok = sim.get("mensagem", "") or "Autorizado"
                    return {
                        "cpf": cpf,
                        "tabela": sim.get("tabelaCodigo") or sim.get("tabelaTitulo"),
                        "saldoBruto": detalhes.get("saldoTotalBloqueado", 0),
                        "valorLiberado": sim.get("valorLiquido", 0),
                        "parcelas": detalhes.get("parcelas", []),
                        "situacao": "Consulta OK",
                        "informacao": msg_ok,
                        "final": True
                    }

            desc = (data.get("objectReturn", {}) or {}).get("description", "") \
                    or (data.get("objectReturn", {}) or {}).get("observacao", "") \
                    or f"Tabela {tabela} não encontrada nas simulações"

            return {
                "cpf": cpf,
                "tabela": tabela,
                "saldoBruto": 0,
                "valorLiberado": 0,
                "situacao": "Erro",
                "informacao": desc,
                "final": True
            }

        if simulacoes:
            todas = []
            for sim in simulacoes:
                detalhes = sim.get("detalhes", {}) or {}
                todas.append({
                    "tabela": sim.get("tabelaCodigo") or sim.get("tabelaTitulo"),
                    "saldoBruto": detalhes.get("saldoTotalBloqueado", 0),
                    "valorLiberado": sim.get("valorLiquido", 0),
                    "parcelas": detalhes.get("parcelas", []),
                    "situacao": "Consulta OK",
                    "informacao": sim.get("mensagem", "") or "Autorizado"
                })
            return {
                "cpf": cpf,
                "situacao": "Consulta OK",
                "informacao": f"{len(todas)} simulações encontradas",
                "simulacoes": todas,
                "final": True
            }

        desc = (data.get("objectReturn", {}) or {}).get("description", "") \
                or (data.get("objectReturn", {}) or {}).get("observacao", "") \
                or "Cliente não autorizou a instituição financeira a realizar a consulta."

        return {
            "cpf": cpf,
            "tabela": tabela,
            "saldoBruto": 0,
            "valorLiberado": 0,
            "situacao": "Erro",
            "informacao": desc,
            "final": True
        }

    except requests.exceptions.ReadTimeout:
        return {
            "cpf": cpf,
            "tabela": tabela,
            "saldoBruto": 0,
            "valorLiberado": 0,
            "situacao": "Erro",
            "informacao": "Timeout na API",
            "final": True
        }
    except Exception as e:
        return {
            "cpf": cpf,
            "tabela": tabela,
            "saldoBruto": 0,
            "valorLiberado": 0,
            "situacao": "Erro",
            "informacao": f"Erro inesperado: {e}",
            "final": True
        }

@app.before_request
def ensure_db():
    if not hasattr(app, "_db_initialized"):
        try:
            init_db()
            print("✅ Banco inicializado (uma única vez)")
        except Exception as e:
            print(f"⚠️ Erro ao inicializar banco: {e}")
        app._db_initialized = True 

API_CREATE = "https://simplix-integration.partner1.com.br/api/Proposal/Create"

def normalizar_cpf(cpf):
    cpf = re.sub(r'\D', '', cpf)
    return cpf.zfill(11)     

def normalizar_data(data):
    if not data:
        return ""
    data = re.sub(r'\D', '', data)
    if len(data) == 8:
        return f"{data[4:8]}-{data[2:4]}-{data[0:2]}"
    return data

def normalizar_telefone(telefone):
    return re.sub(r'\D', '', telefone) 

def normalizar_valor(valor):
    if not valor:
        return 0.0
    valor = valor.replace(".", "").replace(",", ".")
    try:
        return float(valor)
    except:
        return 0.0

@app.route("/cadastrar-proposta", methods=["GET", "POST"])
def cadastrar_proposta():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        nome = request.form.get("nome", "").strip()
        email = request.form.get("email", "").strip()
        cpf = normalizar_cpf(request.form.get("cpf", ""))
        telefone = normalizar_telefone(request.form.get("telefone", ""))
        data_nasc = normalizar_data(request.form.get("dataNascimento", ""))
        cep = request.form.get("cep", "").strip()
        logradouro = request.form.get("logradouro", "").strip()
        numero = request.form.get("numero", "").strip()
        bairro = request.form.get("bairro", "").strip()
        cidade = request.form.get("cidade", "").strip()
        estado = request.form.get("estado", "").strip()
        valor = normalizar_valor(request.form.get("valor", ""))

        if not nome or not cpf or not data_nasc or valor <= 0:
            return render_template("cadastrar.html",
                                   resposta={"msg": "⚠️ Preencha todos os campos obrigatórios: Nome, CPF, Data de Nascimento e Valor."})

        conn = get_conn()
        c = conn.cursor()
        if isinstance(conn, sqlite3.Connection):
            c.execute("INSERT INTO propostas (cpf, nome, valor, status) VALUES (?, ?, ?, ?)",
                      (cpf, nome, valor, "Enviada"))
        else:
            c.execute("INSERT INTO propostas (cpf, nome, valor, status) VALUES (%s, %s, %s, %s)",
                      (cpf, nome, valor, "Enviada"))
        conn.commit()
        conn.close()

        payload = {
            "cliente": {
                "nome": nome,
                "email": email,
                "cpf": cpf,
                "telefone": telefone,
                "dataDeNascimento": data_nasc,
                "endereco": {
                    "cep": cep,
                    "logradouro": logradouro,
                    "numero": numero,
                    "bairro": bairro,
                    "cidade": cidade,
                    "estado": estado
                }
            },
            "operacao": {
                "simulationId": "123e4567-e89b-12d3-a456-426614174000",
                "periodos": [
                    {
                        "dataRepasse": time.strftime("%Y-%m-%dT%H:%M:%S"),
                        "valor": valor
                    }
                ]
            },
            "callback": {
                "url": "https://simplix-unico.onrender.com/simplix/callback",
                "method": "POST"
            },
            "loginDigitador": session["user"]
        }

        try:
            headers = {
                "Authorization": f"Bearer {obter_token()}",
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            resp = requests.post(API_CREATE, json=payload, headers=headers, timeout=30)

            if resp.status_code == 200:
                print(f"[Simplix] Proposta enviada com sucesso: {resp.json()}")
                msg = "✅ Proposta cadastrada e enviada para Simplix!"
            else:
                print(f"[Simplix] Erro {resp.status_code}: {resp.text}")
                msg = f"⚠️ Proposta salva, mas falhou no envio para Simplix ({resp.status_code})"

        except Exception as e:
            print(f"[Simplix] Erro inesperado: {e}")
            msg = "⚠️ Proposta salva, mas falhou no envio para Simplix"

        return render_template("cadastrar.html", resposta={"msg": msg})

    return render_template("cadastrar.html")

@app.route("/simplix/callback", methods=["POST"])
def simplix_callback():
    dados = request.json
    cpf = dados.get("cliente", {}).get("cpf", "desconhecido")
    status = dados.get("status", "Atualizado")

    conn = get_conn()
    c = conn.cursor()
    c.execute("UPDATE propostas SET status=? WHERE cpf=?", (status, cpf))
    conn.commit()
    conn.close()

    return jsonify({"ok": True})

@app.route("/esteira")
def esteira():
    if "user" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return redirect(url_for("index"))

    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT cpf, nome, valor, status, data_criacao FROM propostas ORDER BY data_criacao DESC")
    propostas = c.fetchall()
    conn.close()

    return render_template("esteira.html", propostas=propostas)

if __name__ == "__main__":
    app.run(debug=True, port=8600)

