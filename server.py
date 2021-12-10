import base64
import json


from typing import Optional
import hmac
import hashlib
from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response
 
app = FastAPI()

SECRET_KEY = '6876c12249406c95abeb8d1db2e7fd05df6645d1d81d8c377e84e0042f49faed'
PASSWORD_SALT = '5aa5a69d5475e880f92074fb33ea5fc7930540b952e31593f5bf658dbfbc5f95'

# словарь пользователей
users = {
    'klemazov_kirill@mail.ru':{
        'name':'kirill',
        'password': '96e67086ee7a1aaed6c5d49c957be889429fa2e22dc13310418e528730d0050b',
        'balance': 100000
    },

}

# check hased password
def verify_password(username: str, password: str)->bool:
    password_hash = hashlib.sha256((password+PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]['password']
    return  password_hash == stored_password_hash




# Цифровая подпись кук

def sign_data(data: str)->str:
    """Return signed data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()



def get_username_from_signed_string(username_signed: str)->Optional[str]:
    username_b64, sign = username_signed.split('.')
    username = base64.b64decode(username_b64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username



@app.get('/')
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type='text/html')
    
    valid_username = get_username_from_signed_string(username)
    if not valid_username:
        response =  Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response

    try:
        user = users[valid_username]
    except KeyError:
        response =  Response(login_page, media_type='text/html')
        response.delete_cookie(key='username')
        return response
    return Response(f'Hello {users[valid_username]["name"]}', media_type='text/html')
    # return Response(login_page, media_type='text/html')


# Страница логина
@app.post('/login')
def process_login_page(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(json.dumps({
            'succes': False,
            'message': 'Неверный логин или пароль'
        }), media_type='application/json')
    response =  Response(
        json.dumps(
            {
                'succes': True,
                'message': f'Привет {user["name"]}, баланс: {user["balance"]}'
            }
        )
        , media_type='application/json')
    username_signed = base64.b64encode(username.encode()).decode()+'.'+sign_data(username)
    response.set_cookie(key='username', value=username_signed)
    return response
