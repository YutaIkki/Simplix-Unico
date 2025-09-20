from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import requests
import time
import json
import sqlite3
import os
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
            id SERIAL PRIMARY KEY,
            nome TEXT NOT NULL,
            senha TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            background TEXT DEFAULT 'blue'
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
                      (admin_user, admin_pass, "admin", "blue"))
        else:
            c.execute("INSERT INTO users (nome, senha, role, background) VALUES (%s, %s, %s, %s)",
                      (admin_user, admin_pass, "admin", "blue"))
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
            session["background"] = user[4]
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
    return render_template("index.html", usuario=session["user"],
                           cor1=session.get("cor1", "#133abb"),
                           cor2=session.get("cor2", "#00e1ff"))

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

            return {
                "cpf": cpf,
                "tabela": tabela,
                "saldoBruto": 0,
                "valorLiberado": 0,
                "situacao": "Erro",
                "informacao": f"Tabela {tabela} não encontrada nas simulações",
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

        desc = (data.get("objectReturn", {}) or {}).get("description", "") or txt
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


init_db()

if __name__ == "__main__":
    app.run(debug=True, port=8600)
