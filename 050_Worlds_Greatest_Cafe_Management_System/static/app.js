const state = { token: null, user: null, ws: null };

const authStatus = document.getElementById('auth-status');
const feed = document.getElementById('auth-feed');
const menuList = document.getElementById('menu-list');
const orderList = document.getElementById('order-list');

function addFeed(message) {
  const li = document.createElement('li');
  li.textContent = `${new Date().toLocaleTimeString()} · ${message}`;
  feed.prepend(li);
}

function setAuthView() {
  authStatus.textContent = state.user ? `Logged in as ${state.user.name}` : 'Not authenticated';
}

async function request(path, options = {}) {
  const headers = options.headers || {};
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  if (!headers['Content-Type'] && options.body) headers['Content-Type'] = 'application/json';
  const response = await fetch(path, { ...options, headers });
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || 'Request failed');
  return data;
}

function connectRealtime() {
  if (!state.user || !state.token) return;
  if (state.ws) state.ws.close();
  const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
  state.ws = new WebSocket(`${protocol}//${location.host}/ws/auth/${state.user.id}?token=${encodeURIComponent(state.token)}`);

  state.ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    addFeed(`Realtime event: ${data.event}`);
  };

  state.ws.onopen = () => {
    addFeed('Realtime auth stream connected.');
    setInterval(() => {
      if (state.ws?.readyState === WebSocket.OPEN) {
        state.ws.send('ping');
      }
    }, 15000);
  };
}

document.getElementById('register-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  try {
    const data = await request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        name: form.get('name'),
        email: form.get('email'),
        password: form.get('password')
      })
    });
    state.token = data.token;
    state.user = data.user;
    setAuthView();
    connectRealtime();
    addFeed('Registration successful.');
  } catch (err) { addFeed(err.message); }
});

document.getElementById('login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  try {
    const data = await request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: form.get('email'), password: form.get('password') })
    });
    state.token = data.token;
    state.user = data.user;
    setAuthView();
    connectRealtime();
    addFeed('Login successful.');
  } catch (err) { addFeed(err.message); }
});

document.getElementById('logout-btn').addEventListener('click', async () => {
  try {
    await request('/auth/logout', { method: 'POST' });
    addFeed('Logout completed.');
  } catch (err) { addFeed(err.message); }
  state.token = null;
  state.user = null;
  state.ws?.close();
  setAuthView();
});

document.getElementById('menu-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  try {
    await request('/menu', {
      method: 'POST',
      body: JSON.stringify({
        name: form.get('item_name'),
        category: form.get('category'),
        price: Number(form.get('price')),
        in_stock: true
      })
    });
    addFeed('Menu item added.');
    await loadMenu();
  } catch (err) { addFeed(err.message); }
});

async function loadMenu() {
  const data = await request('/menu');
  menuList.innerHTML = '';
  data.items.forEach((item) => {
    const li = document.createElement('li');
    li.innerHTML = `<strong>${item.name}</strong> (${item.category}) - $${item.price.toFixed(2)} [id=${item.id}]`;
    menuList.appendChild(li);
  });
}

document.getElementById('order-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const form = new FormData(e.target);
  try {
    const res = await request('/orders', {
      method: 'POST',
      body: JSON.stringify({
        items: [{
          menu_item_id: Number(form.get('menu_item_id')),
          quantity: Number(form.get('quantity'))
        }]
      })
    });
    addFeed(`Order #${res.order_id} placed, total $${res.total}`);
    await loadOrders();
  } catch (err) { addFeed(err.message); }
});

async function loadOrders() {
  if (!state.token) return;
  const data = await request('/orders');
  orderList.innerHTML = '';
  data.orders.forEach((order) => {
    const li = document.createElement('li');
    li.textContent = `#${order.id} - ${order.status} - $${order.total}`;
    orderList.appendChild(li);
  });
}

(async () => {
  setAuthView();
  await loadMenu();
})();
