# 🏗️ A04 - Design Inseguro (Insecure Design)

## 📖 Teoria (20%)

Design inseguro refere-se a **falhas estruturais na arquitetura** de uma aplicação — não bugs de implementação, mas decisões de design que criam riscos. Não pode ser corrigido apenas com código; requer redesenho.

**Impacto:** Fluxos lógicos exploráveis, bypass de controles de negócio, ataques em massa.

---

## 💻 Prática (80%)

### 🔴 Exemplo 1 — Sem Rate Limiting (Login)

```python
# Flask — VULNERÁVEL: sem limite de tentativas
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    
    # ❌ Nenhum controle de tentativas
    user = User.query.filter_by(username=username).first()
    if user and verify_password(password, user.password_hash):
        session["user_id"] = user.id
        return redirect("/dashboard")
    return "Login falhou", 401
```

**Exploração:**
```bash
# Brute force com Hydra
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
      http-post-form "//login:username=^USER^&password=^PASS^:Login falhou" \
      -t 64 -V

# Medusa
medusa -h target.com -u admin -P rockyou.txt -M http \
       -m DIR:/login -m FORM:username=^USER^&password=^PASS^

# Wfuzz
wfuzz -c -z file,rockyou.txt \
      -d "username=admin&password=FUZZ" \
      http://target.com/login
```

### 🟢 Seguro — Rate Limiting + Account Lockout
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta

limiter = Limiter(app, key_func=get_remote_address)

# Rastrear tentativas por usuário
login_attempts = {}

def check_lockout(username: str) -> bool:
    attempts = login_attempts.get(username, {"count": 0, "locked_until": None})
    
    if attempts["locked_until"] and datetime.now() < attempts["locked_until"]:
        return True  # Conta bloqueada
    
    return False

def record_failed_attempt(username: str):
    if username not in login_attempts:
        login_attempts[username] = {"count": 0, "locked_until": None}
    
    login_attempts[username]["count"] += 1
    
    # ✅ Bloquear após 5 tentativas por 15 minutos
    if login_attempts[username]["count"] >= 5:
        login_attempts[username]["locked_until"] = datetime.now() + timedelta(minutes=15)
        login_attempts[username]["count"] = 0

@app.route("/login", methods=["POST"])
@limiter.limit("10 per minute")  # ✅ Rate limit por IP
def login_secure():
    username = request.form["username"]
    password = request.form["password"]
    
    # ✅ Verificar lockout ANTES de consultar o banco
    if check_lockout(username):
        return jsonify({"error": "Conta temporariamente bloqueada"}), 429
    
    user = User.query.filter_by(username=username).first()
    if user and verify_password(password, user.password_hash):
        # ✅ Resetar tentativas após sucesso
        login_attempts.pop(username, None)
        session["user_id"] = user.id
        return redirect("/dashboard")
    
    # ✅ Registrar falha
    record_failed_attempt(username)
    
    # ✅ Resposta genérica (não revelar se username existe)
    return jsonify({"error": "Credenciais inválidas"}), 401
```

---

### 🔴 Exemplo 2 — Fluxo de Negócio Explorável

```python
# E-commerce — VULNERÁVEL
@app.route("/checkout", methods=["POST"])
def checkout():
    cart = session.get("cart", [])
    total = sum(item["price"] for item in cart)
    
    # ❌ Preço vem do cliente! Nunca confie no frontend!
    client_total = float(request.form["total"])
    
    process_payment(client_total)  # Cobra o valor enviado pelo cliente
    return "Compra realizada!"
```

**Exploração:**
```bash
# Manipular preço via Burp Suite
# 1. Adicione item de R$1000 ao carrinho
# 2. Intercepte o POST /checkout
# 3. Altere: total=1000.00 → total=0.01
# Resultado: produto de R$1000 por R$0,01!

# Com curl:
curl -X POST http://shop.com/checkout \
     -d "total=0.01&items=item_id_123" \
     -H "Cookie: session=STOLEN_SESSION"
```

### 🟢 Seguro — Preço sempre calculado server-side
```python
@app.route("/checkout", methods=["POST"])
def checkout_secure():
    user_id = session.get("user_id")
    if not user_id:
        return redirect("/login")
    
    # ✅ Buscar carrinho do banco de dados (nunca do cliente)
    cart_items = CartItem.query.filter_by(user_id=user_id).all()
    
    if not cart_items:
        return jsonify({"error": "Carrinho vazio"}), 400
    
    # ✅ Calcular preço server-side com preços do banco
    total = sum(
        Product.query.get(item.product_id).price * item.quantity
        for item in cart_items
    )
    
    # ✅ Aplicar descontos válidos (verificados no banco)
    coupon_code = request.form.get("coupon")
    if coupon_code:
        coupon = Coupon.query.filter_by(code=coupon_code, active=True).first()
        if coupon and not coupon.is_expired():
            total *= (1 - coupon.discount_percentage / 100)
    
    # Processar pagamento com total confiável
    payment_result = process_payment(amount=total, user_id=user_id)
    return jsonify({"success": True, "total_charged": total})
```

---

### 🔴 Exemplo 3 — Recuperação de Senha Insegura

```python
# ❌ Pergunta de segurança fraca
@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    username = request.form["username"]
    answer = request.form["security_answer"]
    
    user = User.query.filter_by(
        username=username,
        security_answer=answer  # "qual o nome do seu pet?"
    ).first()
    
    if user:
        # ❌ Envia senha diretamente (logo, está em texto plano no banco!)
        send_email(user.email, f"Sua senha: {user.password}")
        return "Senha enviada!"
```

### 🟢 Seguro — Token temporário
```python
import secrets
from datetime import datetime, timedelta

@app.route("/forgot-password", methods=["POST"])
@limiter.limit("3 per hour")  # ✅ Rate limit
def forgot_password_secure():
    email = request.form["email"]
    
    # ✅ Sempre retornar a mesma mensagem (evitar user enumeration)
    user = User.query.filter_by(email=email).first()
    
    if user:
        # ✅ Token criptograficamente seguro
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=1)
        
        # Salvar hash do token (não o token em si!)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=expires_at,
            used=False
        ).save()
        
        # Enviar link com token
        reset_link = f"https://app.com/reset-password?token={token}"
        send_email(user.email, f"Link de redefinição (válido 1h): {reset_link}")
    
    # ✅ Mesma resposta independente de o email existir ou não
    return jsonify({"message": "Se o email existir, você receberá um link."})
```

---

### 🛠️ Ferramentas de Análise de Design

```bash
# Threat Modeling — STRIDE com pytm
pip install pytm
# Gerar diagrama de ameaças automaticamente

# OWASP Threat Dragon (visual)
docker run -it --rm \
  -p 3000:3000 \
  -e GITHUB_CLIENT_ID=... \
  owasp/threat-dragon:latest

# Burp Suite — Business Logic Testing
# 1. Mapear todos os fluxos da aplicação
# 2. Testar cada etapa fora de ordem
# 3. Tentar pular etapas (ex: ir direto ao checkout sem adicionar ao carrinho)
# 4. Repetir ações únicas (ex: usar cupom de desconto múltiplas vezes)
```

---

### ✅ Checklist de Prevenção

- [ ] Threat modeling em CADA feature nova
- [ ] Rate limiting em todos os endpoints críticos
- [ ] Preços e valores críticos SEMPRE calculados server-side
- [ ] Fluxos de autenticação com múltiplos fatores
- [ ] Tokens únicos para operações sensíveis (resetar senha, email verification)
- [ ] Testes de lógica de negócio no pipeline CI/CD
- [ ] Revisão de segurança antes do deploy (Secure Code Review)
