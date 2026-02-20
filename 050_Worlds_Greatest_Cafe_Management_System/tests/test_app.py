import os
from pathlib import Path

from fastapi.testclient import TestClient

os.environ['CAFE_SECRET'] = 'test-secret'

from main import app, DB_PATH, init_db  # noqa: E402


def setup_function():
    if Path(DB_PATH).exists():
        Path(DB_PATH).unlink()
    init_db()


def test_auth_and_order_flow():
    client = TestClient(app)

    reg = client.post('/auth/register', json={
        'name': 'Ada',
        'email': 'ada@example.com',
        'password': 'supersecure123'
    })
    assert reg.status_code == 200
    token = reg.json()['token']
    headers = {'Authorization': f'Bearer {token}'}

    menu = client.post('/menu', json={
        'name': 'Flat White', 'category': 'Coffee', 'price': 4.5, 'in_stock': True
    }, headers=headers)
    assert menu.status_code == 200
    item_id = menu.json()['item']['id']

    order = client.post('/orders', json={'items': [{'menu_item_id': item_id, 'quantity': 2}]}, headers=headers)
    assert order.status_code == 200
    assert order.json()['total'] == 9.0

    logout = client.post('/auth/logout', headers=headers)
    assert logout.status_code == 200

    invalid = client.get('/orders', headers=headers)
    assert invalid.status_code == 401
