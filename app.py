from flask import Flask, render_template, request, jsonify, redirect, url_for, session
import requests
import time
import json
import sqlite3
from datetime import datetime
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
API_CREATE = "https://simplix-integration.partner1.com.br/api/Proposal/Create"

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

    c.execute("""
        CREATE TABLE IF NOT EXISTS propostas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cpf TEXT,
            nome TEXT,
            valor REAL,
            valor_contrato REAL,
            valor_liquido REAL,
            status TEXT,
            data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            data_status TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            data_pagamento TEXT,
            usuario TEXT,
            telefone TEXT,
            email TEXT,
            cep TEXT,
            logradouro TEXT,
            numero TEXT,
            bairro TEXT,
            cidade TEXT,
            estado TEXT,
            banco TEXT,
            agencia TEXT,
            conta TEXT,
            tabela TEXT,
            data_nascimento TEXT
        )
    """ if isinstance(conn, sqlite3.Connection) else """
        CREATE TABLE IF NOT EXISTS propostas (
            id SERIAL PRIMARY KEY,
            cpf TEXT,
            nome TEXT,
            valor REAL,
            valor_contrato REAL,
            valor_liquido REAL,
            status TEXT,
            data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            data_status TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            data_pagamento TEXT,
            usuario TEXT,
            telefone TEXT,
            email TEXT,
            cep TEXT,
            logradouro TEXT,
            numero TEXT,
            bairro TEXT,
            cidade TEXT,
            estado TEXT,
            banco TEXT,
            agencia TEXT,
            conta TEXT,
            tabela TEXT,
            data_nascimento TEXT
        )
    """)

    novos_campos = [
        ("telefone", "TEXT"),
        ("email", "TEXT"),
        ("cep", "TEXT"),
        ("logradouro", "TEXT"),
        ("numero", "TEXT"),
        ("bairro", "TEXT"),
        ("cidade", "TEXT"),
        ("estado", "TEXT"),
        ("banco", "TEXT"),
        ("agencia", "TEXT"),
        ("conta", "TEXT"),
        ("tabela", "TEXT"),
        ("data_nascimento", "TEXT"),
    ]

    for campo, tipo in novos_campos:
        try:
            c.execute(f"ALTER TABLE propostas ADD COLUMN {campo} {tipo}")
        except Exception:
            pass

    if isinstance(conn, sqlite3.Connection):
        c.execute("SELECT * FROM users WHERE role = ?", ("admin",))
    else:
        c.execute("SELECT * FROM users WHERE role = %s", ("admin",))
    if not c.fetchone():
        admin_user = "Leonardo"
        admin_pass = hash_senha("123456")
        if isinstance(conn, sqlite3.Connection):
            c.execute(
                "INSERT INTO users (nome, senha, role, background) VALUES (?, ?, ?, ?)",
                (admin_user, admin_pass, "admin", "#133abb,#00e1ff"),
            )
        else:
            c.execute(
                "INSERT INTO users (nome, senha, role, background) VALUES (%s, %s, %s, %s)",
                (admin_user, admin_pass, "admin", "#133abb,#00e1ff"),
            )
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
    
    if isinstance(conn, sqlite3.Connection):
        c.execute("SELECT id, nome, role FROM users ORDER BY id ASC")
    else:
        c.execute("SELECT id, nome, role FROM users ORDER BY id ASC")
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

            if simulacoes:
                sim = simulacoes[0]
                detalhes = sim.get("detalhes", {}) or {}
                return {
                    "cpf": cpf,
                    "tabela": sim.get("tabelaCodigo") or sim.get("tabelaTitulo"),
                    "saldoBruto": detalhes.get("saldoTotalBloqueado", 0),
                    "valorLiberado": sim.get("valorLiquido", 0),
                    "situacao": "Consulta OK",
                    "informacao": "Tabela diferente encontrada automaticamente.",
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

@app.route("/cadastrar_proposta")
def cadastrar_proposta():
    cpf = request.args.get("cpf")

    if not cpf:
        return "CPF não informado", 400

    cpf = re.sub(r'\D', '', cpf).zfill(11)

    payload = {
        "cpf": cpf,
        "parcelas": 0,
        "convenio": 1,
        "produto": 1
    }

    headers = {
        "Authorization": f"Bearer {obter_token()}",
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    simulacoes = []
    try:
        print(f"[{cpf}] 🔍 Consultando API Simplix para listar todas as tabelas...")
        resp = requests.post(API_SIMULATE, json=payload, headers=headers, timeout=60)
        print(f"[{cpf}] 📡 Status Code: {resp.status_code}")

        try:
            data = resp.json()
            print(f"[{cpf}] RAW JSON:\n{json.dumps(data, indent=2, ensure_ascii=False)}")
        except Exception:
            data = {}
            print(f"[{cpf}] ❌ Erro ao decodificar JSON. Retorno bruto:\n{resp.text}")

        simulacoes = (data.get("objectReturn", {}) or {}).get("retornoSimulacao", [])

        if not simulacoes:
            print(f"[{cpf}] ⚠️ Nenhuma simulação encontrada no retorno da Simplix.")

    except requests.exceptions.Timeout:
        print(f"[{cpf}] ⏱️ Timeout ao consultar API Simplix.")
    except Exception as e:
        print(f"[{cpf}] ❌ Erro inesperado ao consultar Simplix: {e}")

    return render_template(
        "cadastrar_proposta.html",
        cpf=cpf,
        simulacoes=simulacoes
    )

@app.route("/cadastrar_proposta_cliente")
def cadastrar_proposta_cliente():
    cpf = request.args.get("cpf")
    tabela = request.args.get("tabela")
    valor = request.args.get("valor")
    simulation_id = request.args.get("simulation_id")

    return render_template(
        "cadastrar_proposta_cliente.html",
        cpf=cpf,
        tabela=tabela,
        valor=valor,
        simulation_id=simulation_id
    )

@app.route("/enviar-proposta", methods=["POST"])
def enviar_proposta():
    data = request.get_json()
    cliente = data.get("cliente", {})
    cpf = data.get("cpf")
    tabela = data.get("tabela")

    callback_url = request.host_url.rstrip("/") + "/simplix/callback"

    payload = {
        "cliente": {
            "nome": cliente.get("nome"),
            "email": cliente.get("email"),
            "telefone": cliente.get("telefone"),
            "cpf": cpf,
            "dataDeNascimento": cliente.get("dataNascimento"),
            "endereco": {
                "cep": cliente.get("cep"),
                "logradouro": cliente.get("logradouro"),
                "numero": cliente.get("numero"),
                "bairro": cliente.get("bairro"),
                "cidade": cliente.get("cidade"),
                "estado": cliente.get("estado")
            },
            "contaBancaria": {
                "codigoDoBanco": cliente.get("banco"),
                "agencia": cliente.get("agencia"),
                "conta": cliente.get("conta"),
                "tipoDeConta": "ContaCorrente"
            }
        },
        "operacao": {
            "simulationId": data.get("simulationId") or cliente.get("simulationId"),
            "periodos": [
                {"dataRepasse": time.strftime("%Y-%m-%dT%H:%M:%S"), "valor": float(cliente.get("valor", 0))}
            ]
        },
        "callback": {"url": callback_url, "method": "POST"},
        "loginDigitador": session.get("user", "sistema")
    }

    headers = {
        "Authorization": f"Bearer {obter_token()}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    try:
        resp = requests.post(API_CREATE, json=payload, headers=headers, timeout=30)
        data_resp = resp.json()
        print(f"[Simplix Produção] Resposta: {resp.status_code} | {json.dumps(data_resp, indent=2, ensure_ascii=False)}")

        # 🔗 Captura link e ID da proposta
        link_assinatura = (
            data_resp.get("objectReturn", {}).get("signatureUrl") or
            data_resp.get("objectReturn", {}).get("urlAssinatura")
        )
        id_proposta = (
            data_resp.get("objectReturn", {}).get("proposalId") or
            data_resp.get("objectReturn", {}).get("idProposta")
        )

        return jsonify({
            "ok": True,
            "status": resp.status_code,
            "resposta": data_resp,
            "link_assinatura": link_assinatura,
            "id_proposta": id_proposta
        })

    except Exception as e:
        print(f"Erro ao enviar proposta: {e}")
        return jsonify({"ok": False, "erro": str(e)})

@app.route("/editar_proposta/<int:proposta_id>", methods=["GET", "POST"])
def editar_proposta(proposta_id):
    if "user" not in session:
        return redirect(url_for("login"))

    conn = get_conn()
    c = conn.cursor()

    if request.method == "POST":
        campos = [
            "nome", "telefone", "email", "cep", "logradouro", "numero", "bairro",
            "cidade", "estado", "banco", "agencia", "conta", "valor", "tabela", "data_nascimento"
        ]
        dados = [request.form.get(campo) for campo in campos]

        if isinstance(conn, sqlite3.Connection):
            c.execute(f"""
                UPDATE propostas SET
                    nome=?, telefone=?, email=?, cep=?, logradouro=?, numero=?, bairro=?, cidade=?, estado=?,
                    banco=?, agencia=?, conta=?, valor=?, tabela=?, data_nascimento=?
                WHERE id=?
            """, (*dados, proposta_id))
        else:
            c.execute(f"""
                UPDATE propostas SET
                    nome=%s, telefone=%s, email=%s, cep=%s, logradouro=%s, numero=%s, bairro=%s, cidade=%s, estado=%s,
                    banco=%s, agencia=%s, conta=%s, valor=%s, tabela=%s, data_nascimento=%s
                WHERE id=%s
            """, (*dados, proposta_id))

        conn.commit()
        conn.close()
        return redirect(url_for("esteira"))

    if isinstance(conn, sqlite3.Connection):
        c.execute("SELECT * FROM propostas WHERE id = ?", (proposta_id,))
    else:
        c.execute("SELECT * FROM propostas WHERE id = %s", (proposta_id,))
    row = c.fetchone()
    conn.close()

    if not row:
        return "Proposta não encontrada", 404

    colunas = [
        "id", "cpf", "nome", "valor", "valor_contrato", "valor_liquido", "status",
        "data_criacao", "data_status", "data_pagamento", "usuario",
        "telefone", "email", "cep", "logradouro", "numero", "bairro",
        "cidade", "estado", "banco", "agencia", "conta", "tabela", "data_nascimento"
    ]
    proposta = dict(zip(colunas, row))
    return render_template("editar_proposta.html", proposta=proposta)

@app.route("/excluir/<int:proposta_id>")
def excluir_proposta(proposta_id):
    if "user" not in session:
        return redirect(url_for("login"))

    conn = get_conn()
    c = conn.cursor()
    if isinstance(conn, sqlite3.Connection):
        c.execute("DELETE FROM propostas WHERE id = ?", (proposta_id,))
    else:
        c.execute("DELETE FROM propostas WHERE id = %s", (proposta_id,))
    conn.commit()
    conn.close()

    return redirect(url_for("esteira"))

@app.route("/simplix/callback", methods=["POST"])
def simplix_callback():
    dados = request.json or {}

    cliente = dados.get("cliente", {})
    cpf = (cliente.get("cpf") or "").zfill(11)
    status = dados.get("status", "Atualizado")
    valor_contrato = dados.get("valorContrato") or 0
    valor_liquido = dados.get("valorLiquido") or 0
    data_status = time.strftime("%Y-%m-%d %H:%M:%S")

    conn = get_conn()
    c = conn.cursor()

    if isinstance(conn, sqlite3.Connection):
        c.execute("""
            UPDATE propostas
            SET status = ?, valor_contrato = ?, valor_liquido = ?, data_status = ?
            WHERE cpf = ?
        """, (status, valor_contrato, valor_liquido, data_status, cpf))
    else:
        c.execute("""
            UPDATE propostas
            SET status = %s, valor_contrato = %s, valor_liquido = %s, data_status = %s
            WHERE cpf = %s
        """, (status, valor_contrato, valor_liquido, data_status, cpf))

    conn.commit()
    conn.close()

    return jsonify({"ok": True})

@app.route("/esteira")
def esteira():
    if "user" not in session:
        return redirect(url_for("login"))

    if session.get("role") != "admin":
        return redirect(url_for("index"))

    page = int(request.args.get("page", 1))
    per_page = 20
    cpf_filtro = request.args.get("cpf", "").strip()

    conn = get_conn()
    c = conn.cursor()

    if isinstance(conn, sqlite3.Connection):
        if cpf_filtro:
            c.execute("SELECT COUNT(*) FROM propostas WHERE cpf LIKE ?", (f"%{cpf_filtro}%",))
        else:
            c.execute("SELECT COUNT(*) FROM propostas")
    else:
        if cpf_filtro:
            c.execute("SELECT COUNT(*) FROM propostas WHERE cpf LIKE %s", (f"%{cpf_filtro}%",))
        else:
            c.execute("SELECT COUNT(*) FROM propostas")

    total = c.fetchone()[0]
    total_pages = max(1, -(-total // per_page))
    offset = (page - 1) * per_page

    if isinstance(conn, sqlite3.Connection):
        if cpf_filtro:
            c.execute("""
                SELECT id, cpf, nome, valor, status, data_criacao, usuario
                FROM propostas
                WHERE cpf LIKE ?
                ORDER BY data_criacao DESC
                LIMIT ? OFFSET ?
            """, (f"%{cpf_filtro}%", per_page, offset))
        else:
            c.execute("""
                SELECT id, cpf, nome, valor, status, data_criacao, usuario
                FROM propostas
                ORDER BY data_criacao DESC
                LIMIT ? OFFSET ?
            """, (per_page, offset))
    else:
        if cpf_filtro:
            c.execute("""
                SELECT id, cpf, nome, valor, status, data_criacao, usuario
                FROM propostas
                WHERE cpf LIKE %s
                ORDER BY data_criacao DESC
                LIMIT %s OFFSET %s
            """, (f"%{cpf_filtro}%", per_page, offset))
        else:
            c.execute("""
                SELECT id, cpf, nome, valor, status, data_criacao, usuario
                FROM propostas
                ORDER BY data_criacao DESC
                LIMIT %s OFFSET %s
            """, (per_page, offset))

    propostas = c.fetchall()
    conn.close()

    return render_template(
        "esteira.html",
        propostas=propostas,
        page=page,
        total_pages=total_pages,
        total=total
    )

@app.route("/cadastrar_proposta_resumo")
def cadastrar_proposta_resumo():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("cadastrar_proposta_resumo.html")

@app.route("/enviar_proposta", methods=["POST"])
def enviar_proposta_resumo():
    if "user" not in session:
        return redirect(url_for("login"))

    cpf = request.form.get("cpf")
    nome = request.form.get("nome")
    valor = float(request.form.get("valor") or 0)
    tabela = request.form.get("tabela")
    usuario = session.get("user")
    status = "Enviada"
    data_criacao = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_conn()
    c = conn.cursor()

    if isinstance(conn, sqlite3.Connection):
        c.execute("""
            INSERT INTO propostas (cpf, nome, valor, status, data_criacao, usuario)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (cpf, nome, valor, status, data_criacao, usuario))
    else:
        c.execute("""
            INSERT INTO propostas (cpf, nome, valor, status, data_criacao, usuario)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (cpf, nome, valor, status, data_criacao, usuario))

    conn.commit()
    conn.close()

    return redirect(url_for("cadastrar_proposta_conclusao"))

@app.route("/cadastrar_proposta_conclusao")
def cadastrar_proposta_conclusao():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("cadastrar_proposta_conclusao.html")

if __name__ == "__main__":
    app.run(debug=True, port=8600)


