const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = 3000;
const JWT_SECRET = 'seu_segredo_do_cafe_123'; // Pode alterar para qualquer frase segura

// Middlewares
app.use(cors());
app.use(express.json());

// Servir arquivos estáticos da pasta 'public' (onde vão ficar seus HTMLs)
app.use(express.static(path.join(__dirname, 'public')));

// Redireciona a raiz (/) automaticamente para a tela de login
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Inicializar e conectar ao banco de dados SQLite (arquivo local)
const db = new sqlite3.Database('./database.sqlite', (err) => {
    if (err) {
        console.error('Erro ao conectar ao banco SQLite:', err.message);
    } else {
        console.log('Conectado com sucesso ao banco de dados SQLite.');
        criarTabelas();
    }
});

// Criar tabelas necessárias se não existirem
function criarTabelas() {
    db.serialize(() => {
        // Tabela de Usuários (Operadores)
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )`);

        // Tabela de Configurações (Limite de mesas)
        db.run(`CREATE TABLE IF NOT EXISTS configs (
            chave TEXT PRIMARY KEY,
            valor TEXT
        )`, () => {
            // Insere valor padrão de 12 mesas caso não exista
            db.run(`INSERT OR IGNORE INTO configs (chave, valor) VALUES ('total_mesas', '12')`);
        });

        // Tabela de Produtos (Cardápio e Estoque)
        db.run(`CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            price REAL NOT NULL,
            stock INTEGER DEFAULT 0
        )`);

        // Tabela de Pedidos / Comandas Ativas e Finalizadas
        db.run(`CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mesa INTEGER NOT NULL,
            cliente TEXT NOT NULL,
            itens TEXT NOT NULL, -- Guardado como String JSON
            total REAL NOT NULL,
            status TEXT DEFAULT 'producao', -- 'producao', 'pagamento', 'finalizado'
            nota TEXT,
            contato TEXT,
            data_venda DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);
    });
}

// Middleware para validar o Token JWT nas rotas protegidas
function verificarToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    if (!authHeader) return res.status(401).json({ error: 'Token não fornecido.' });

    const token = authHeader.split(' ')[1];
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(403).json({ error: 'Token inválido ou expirado.' });
        req.userId = decoded.id;
        req.userRole = decoded.role;
        next();
    });
}

// ==========================================
// ROTAS DE AUTENTICAÇÃO (LOGIN / REGISTRO)
// ==========================================

// Registrar colaborador
app.post('/api/register', (req, res) => {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password) return res.status(400).json({ error: 'Preencha todos os campos obrigatórios.' });

    const salt = bcrypt.genSaltSync(10);
    const hashPassword = bcrypt.hashSync(password, salt);

    const query = `INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)`;
    db.run(query, [name, email, hashPassword, role || 'user'], function (err) {
        if (err) {
            if (err.message.includes('UNIQUE')) {
                return res.status(400).json({ error: 'Este e-mail já está cadastrado.' });
            }
            return res.status(500).json({ error: 'Erro interno ao cadastrar.' });
        }
        res.status(201).json({ message: 'Usuário registrado com sucesso!' });
    });
});

// Login do sistema
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;
    
    db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
        if (err) return res.status(500).json({ error: 'Erro no servidor.' });
        if (!user) return res.status(400).json({ error: 'Usuário ou senha inválidos.' });

        const senhaValida = bcrypt.compareSync(password, user.password);
        if (!senhaValida) return res.status(400).json({ error: 'Usuário ou senha inválidos.' });

        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
        res.json({ token, role: user.role, name: user.name });
    });
});

// ==========================================
// ROTAS DE CONFIGURAÇÃO
// ==========================================

app.get('/api/configs/mesas', verificarToken, (req, res) => {
    db.get(`SELECT valor FROM configs WHERE chave = 'total_mesas'`, [], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ total_mesas: row ? parseInt(row.valor) : 12 });
    });
});

app.post('/api/configs/mesas', verificarToken, (req, res) => {
    const { total_mesas } = req.body;
    db.run(`UPDATE configs SET valor = ? WHERE chave = 'total_mesas'`, [total_mesas], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Configuração atualizada!' });
    });
});

// Retorna quais mesas estão ocupadas no momento para renderizar o grid vermelho/verde
app.get('/api/tables/status', verificarToken, (req, res) => {
    db.all(`SELECT mesa, cliente FROM orders WHERE status IN ('producao', 'pagamento')`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const mapaStatus = {};
        rows.forEach(row => {
            mapaStatus[row.mesa] = { nome: row.cliente };
        });
        res.json(mapaStatus);
    });
});

// ==========================================
// ROTAS DE PRODUTOS (CARDÁPIO)
// ==========================================

app.get('/api/products', verificarToken, (req, res) => {
    db.all(`SELECT * FROM products`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(rows);
    });
});

app.post('/api/products', verificarToken, (req, res) => {
    const { name, price, stock } = req.body;
    db.run(`INSERT INTO products (name, price, stock) VALUES (?, ?, ?)`, [name, price, stock || 0], function(err) {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ id: this.lastID, name, price, stock });
    });
});

app.put('/api/products/:id', verificarToken, (req, res) => {
    const { name, price, stock } = req.body;
    const { id } = req.params;
    db.run(`UPDATE products SET name = ?, price = ?, stock = ? WHERE id = ?`, [name, price, stock, id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Produto atualizado!' });
    });
});

app.delete('/api/products/:id', verificarToken, (req, res) => {
    db.run(`DELETE FROM products WHERE id = ?`, [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Produto removido!' });
    });
});

// ==========================================
// ROTAS DE PEDIDOS E COMANDAS
// ==========================================

// Enviar novos itens para a mesa/comanda
app.post('/api/orders', verificarToken, (req, res) => {
    const { mesa, cliente, itens, total } = req.body;
    const itensString = JSON.stringify(itens);

    // Verifica se já existe comanda aberta para essa mesa
    db.get(`SELECT id, itens, total FROM orders WHERE mesa = ? AND status IN ('producao', 'pagamento')`, [mesa], (err, order) => {
        if (err) return res.status(500).json({ error: err.message });

        if (order) {
            // Se já tem comanda aberta, combina os itens novos com os antigos e atualiza o total acumulado
            const itensAntigos = JSON.parse(order.itens);
            const novosItensCombinados = [...itensAntigos];

            itens.forEach(novoItem => {
                const index = novosItensCombinados.findIndex(i => i.id === novoItem.id);
                if (index > -1) {
                    novosItensCombinados[index].qtd += novoItem.qtd;
                } else {
                    novosItensCombinados.push(novoItem);
                }
            });

            db.run(`UPDATE orders SET itens = ?, total = total + ?, status = 'producao' WHERE id = ?`, 
                [JSON.stringify(novosItensCombinados), total, order.id], (err) => {
                    if (err) return res.status(500).json({ error: err.message });
                    return res.json({ message: 'Itens adicionados à comanda existente!' });
                });
        } else {
            // Se for mesa nova, cria o registro do zero
            db.run(`INSERT INTO orders (mesa, cliente, itens, total, status) VALUES (?, ?, ?, ?, 'producao')`,
                [mesa, cliente, itensString, total], function(err) {
                    if (err) return res.status(500).json({ error: err.message });
                    res.json({ id: this.lastID, message: 'Nova comanda aberta com sucesso!' });
                });
        }
    });
});

// Pegar o consumo atual de uma mesa específica (para o Cardápio mostrar o extrato)
app.get('/api/orders/mesa/:mesa', verificarToken, (req, res) => {
    db.get(`SELECT * FROM orders WHERE mesa = ? AND status IN ('producao', 'pagamento')`, [req.params.mesa], (err, row) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!row) return res.json({ itens: [], total: 0 });
        res.json({ id: row.id, mesa: row.mesa, cliente: row.cliente, itens: JSON.parse(row.itens), total: row.total });
    });
});

// Pegar todos os pedidos ativos (para o painel do Balcão)
app.get('/api/orders/active', verificarToken, (req, res) => {
    db.all(`SELECT * FROM orders WHERE status IN ('producao', 'pagamento') ORDER BY status DESC, id ASC`, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const formatados = rows.map(r => ({
            ...r,
            itens: JSON.parse(r.itens)
        }));
        res.json(formatados);
    });
});

// Atualizar o status da mesa quando o cliente pede a conta no Cardápio (Muda para 'pagamento')
app.put('/api/orders/status-mesa/:mesa', verificarToken, (req, res) => {
    const { status, nota, contato } = req.body;
    db.run(`UPDATE orders SET status = ?, nota = ?, contato = ? WHERE mesa = ? AND status = 'producao'`,
        [status, nota, contato, req.params.mesa], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Pedido de fechamento enviado ao balcão!' });
        });
});

// Finalizar de vez a ordem e receber o pagamento no Balcão
app.put('/api/orders/:id', verificarToken, (req, res) => {
    const { status } = req.body;
    db.run(`UPDATE orders SET status = ? WHERE id = ?`, [status, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Comanda finalizada e arquivada com sucesso!' });
    });
});

// ==========================================
// ROTA DO RELATÓRIO DE GESTÃO (DASHBOARD)
// ==========================================

app.get('/api/reports/sales', verificarToken, (req, res) => {
    const { periodo } = req.query;
    let filtroData = "";

    // Aplica filtros de data baseado no SQLite (diario, semanal, mensal)
    if (periodo === 'diario') {
        filtroData = "AND data_venda >= date('now', 'start of day')";
    } else if (periodo === 'semanal') {
        filtroData = "AND data_venda >= date('now', '-7 days')";
    } else if (periodo === 'quinzenal') {
        filtroData = "AND data_venda >= date('now', '-15 days')";
    } else if (periodo === 'mensal') {
        filtroData = "AND data_venda >= date('now', 'start of month')";
    }

    const query = `SELECT * FROM orders WHERE status = 'finalizado' ${filtroData} ORDER BY id DESC`;
    
    db.all(query, [], (err, rows) => {
        if (err) return res.status(500).json({ error: err.message });
        const dadosFormatados = rows.map(r => ({
            ...r,
            itens: JSON.parse(r.itens)
        }));
        res.json(dadosFormatados);
    });
});

// Iniciar o servidor de escuta
app.listen(PORT, () => {
    console.log(`Servidor rodando perfeitamente em http://localhost:${PORT}`);
});