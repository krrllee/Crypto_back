from flask import request,jsonify,session,url_for, render_template,redirect
from flask import Flask
from flask_bcrypt import Bcrypt
from flask_cors import CORS,cross_origin
from psycopg2 import pool
from datetime import datetime
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from logic import BOUGHT, SOLD
from authlib.integrations.flask_client import OAuth
import os
import requests
from apscheduler.schedulers.background import BackgroundScheduler


API_URL = "https://pro-api.coinmarketcap.com/v1/cryptocurrency/listings/latest"
API_KEY = "af2bb273-09aa-4b06-955e-a0d7bf570f97"

app = Flask(__name__)
app.secret_key = 'random secret key'
cors = CORS(app,supports_credentials=True)
bcrypt = Bcrypt(app)
app.config['JWT_SECRET_KEY'] = 'my_secret_key'
jwt = JWTManager(app)
scheduler = BackgroundScheduler()

postgreSQL_pool = pool.SimpleConnectionPool(
    1, 1000, database="exampledb", user="docker", password="docker", host="127.0.0.1")
app.config['postgreSQL_pool'] = postgreSQL_pool
app.config['SESSION_COOKIE_NAME'] = 'google-login-session'
app.config['Access-Control-Allow-Origin'] = '*'
app.config["Access-Control-Allow-Headers"]="Content-Type"

oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='483612200058-5tfblq7tf82175hd5l26pmm7tfqdjtfk.apps.googleusercontent.com',
    client_secret='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',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',  # This is only needed if using openId to fetch user info
    client_kwargs={'scope': 'email profile'},
    server_metadata_url= 'https://accounts.google.com/.well-known/openid-configuration'
)

    

def fetch_crypto_data():
    headers = {"X-CMC_PRO_API_KEY": API_KEY}
    params = {"start": 1, "limit": 100, "convert": "USD"}
    response = requests.get(API_URL, headers=headers,params=params)
    data = response.json()
    return data["data"]

def update_database(crypto_data):
    connection = postgreSQL_pool.getconn()
    cursor = connection.cursor()
    for crypto in crypto_data:
        crypto_id = crypto["id"]
        name = crypto["name"]
        symbol = crypto["symbol"]
        price = crypto["quote"]["USD"]["price"]
        query = f"""
            INSERT INTO cryptocurrencies (id, name, symbol, price)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (id) DO UPDATE
            SET price = EXCLUDED.price;
        """
        cursor.execute(query, (crypto_id, name, symbol, price))   
        connection.commit()
    

def fetch_and_update_data():
    crypto_data = fetch_crypto_data()
    update_database(crypto_data=crypto_data)

def schedule_database_update():
    scheduler.add_job(fetch_and_update_data,'interval',minutes=10)
    scheduler.start()

def getCurrId(name):
    connection = postgreSQL_pool.getconn()
    cursor = connection.cursor()
    query = f"SELECT id from cryptocurrencies WHERE name like %s"
    cursor.execute(query,[name])
    result = cursor.fetchone()
    return result

def getPrice(name):
    connection = postgreSQL_pool.getconn()
    cursor = connection.cursor()
    query = f"SELECT price from cryptocurrencies WHERE name like %s"
    cursor.execute(query,[name])
    result = cursor.fetchone()
    return result

def format_db_row_to_transaction(row):
    transaction = {
        'id': row[0],  
        'name': row[3],
        'type': row[4],
        'amount': row[5],
        'time_transacted': row[6],
        'time_created': row[7],
        'price_purchase_at': row[8]
    }
    return transaction

@app.route('/update_database')
def manual_database_update():
    fetch_and_update_data()
    return "Database updated manually!"

@app.route("/")
def health_check():
    email = dict(session).get('email',None)
    return f'Hello,{email}'


@app.route("/registration",methods=["POST"])
def registration():
    username =  request.json["username"]
    first_name = request.json["first_name"]
    last_name = request.json["last_name"]
    adress = request.json["adress"]
    city = request.json["city"]
    state = request.json["state"]
    phone_number = request.json["phone_number"]
    email = request.json["email"]
    password = request.json["password"]

    connection = postgreSQL_pool.getconn()
    cursor = connection.cursor()
    query_username_email = f"SELECT email, username FROM users WHERE email like %s AND username like %s"
    query_email = f"SELECT email, username FROM users WHERE email like %s"
    query_username = f"SELECT email, username FROM users WHERE username like %s"
    cursor.execute(query_username_email, [email, username])
    result_username_email = cursor.fetchall()
    cursor.execute(query_email, [email])
    result_email = cursor.fetchall()
    cursor.execute(query_username, [username])
    resault_username = cursor.fetchall()
    if len(resault_username) == 0 and len(result_email) == 0:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        insert_statement = f"INSERT INTO users (username, first_name, last_name, adress, city, state, phone_number, email, password) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
        cursor.execute(insert_statement, [username, first_name, last_name, adress, city, state, phone_number, email, hashed_password])
        connection.commit()
        print("Korisnik je dodat")
    elif len(result_username_email) == 1:
        print("Korisnik je vec registrovan, prijavite se.")
    elif len(result_email) == 1 and len(resault_username) == 0:
        print("Email je zauzet od strane drugog korisnika.")
    elif len(resault_username) == 1 and len(result_email) == 0:
        print("Username je zauzet od strane drugog korisnika.")

    return jsonify(request.json)


@app.route('/login',methods =['POST'])
def login():
    _email = request.json["email"]
    _password = request.json["password"]

    if _email and _password:
        connection = postgreSQL_pool.getconn()
        cursor = connection.cursor()
        sql = f"SELECT * FROM users WHERE email = %s"
        cursor.execute(sql, [_email])
        row = cursor.fetchone()
        user_id = row[0]
        email = row[8]
        password = row[9]
        if row:
            if bcrypt.check_password_hash(password,_password):
                session['id'] = user_id
                access_token = create_access_token(identity={'id':user_id,'username':row[1],'first_name':row[2],'email':row[8]})
                cursor.close()
                resp = jsonify(message='success', access_token = access_token)
            else:
                resp = jsonify({"error": "Invalid email and password"})
                           
        return resp
    
@app.route('/logout')
@jwt_required()
def logout():
    id = get_jwt_identity()["id"]
    if 'id' in session:
        session.pop('id',None) 
    return jsonify({'message':'You successfully logged out'})


@app.route('/make_token',methods=["POST"])
def make_token():
    googleId = request.json['googleId']
    name = request.json['name']
    email = request.json['email']
    
    access_token = create_access_token(identity={'id':googleId,'name':name,'email':email})
    resp = jsonify(message="token created",access_token=access_token)
    return resp


@app.route('/protected',methods = ["GET"])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as = current_user),200



@app.route('/callback', methods=['POST'])
def google_callback():
    data = request.get_json()
    token = data.get('token')
    
    # Verify the token with Google's servers
    google_response = requests.post('https://www.googleapis.com/oauth2/v3/tokeninfo', data={'id_token': token})
    google_data = google_response.json()

    
    
    if google_data.get('email_verified'):
        # Create a user session or perform other actions
        return jsonify(message='Login successful')
    else:
        return jsonify(message='Login failed')

@app.route('/socialLogin')
@cross_origin()
def socialLogin():
    google = oauth.create_client('google')
    redirect_uri = url_for('authorize', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/authorize')
def authorize():
    google = oauth.create_client('google')
    token = google.authorize_access_token()
    resp = google.get('userinfo')
    user_info = resp.json()
    session['email'] = user_info['email']   
    jwt_token = create_access_token(identity=user_info['email'])
    res = jsonify(message='success', access_token = jwt_token)
    return res

@app.route('/cryptocurrencies')
def get_cryptocurrencies():
    
    fetch_and_update_data()
    api_key = 'af2bb273-09aa-4b06-955e-a0d7bf570f97'
    url = f"https://pro-api.coinmarketcap.com/v1/cryptocurrency/listings/latest?CMC_PRO_API_KEY={api_key}"
    response = requests.get(url)
    data = response.json()

    currencies = []
    for entry in data['data']:
        currency = {
            'name': entry['name'],
            'symbol': entry['symbol'],
            'price': entry['quote']['USD']['price'],
            'price_change_percentage_24h': entry['quote']['USD']['percent_change_24h']
        }
        currencies.append(currency)
    
    return jsonify(currencies)




@app.route("/add_transaction",methods=["POST"])
@jwt_required()
def new_transaction():
    user_id = get_jwt_identity()["id"]
    currName = request.json["name"]
    currId = getCurrId(currName)[0]
    type = request.json["type"]
    amount = int(request.json["amount"])
    time_transacted = datetime.fromtimestamp(request.json["time_transacted"])
    time_created = datetime.fromtimestamp(request.json["time_created"])
    price_purchased_at = float(getPrice(currName)[0])

    connection = postgreSQL_pool.getconn()
    cursor = connection.cursor()

    insert_statement = f"INSERT INTO transactions (user_id,curr_id, coin_name, transaction_type, amount, time_transacted, time_created, price_purchase_at) VALUES ({user_id},'{currId}','{currName}',{type},{amount},'{time_transacted}','{time_created}',{price_purchased_at});"
    cursor.execute(insert_statement)
    connection.commit()

    return jsonify(request.json)



@app.route("/all_transactions",methods=["GET"])
@jwt_required()
def all_transactions():
    user_id = get_jwt_identity()["id"]

    connection = postgreSQL_pool.getconn()
    cursor = connection.cursor()
    query = f"SELECT * FROM transactions WHERE user_id ={user_id};"
    cursor.execute(query)

    transactions = cursor.fetchall()
    
    formatted_transactions = [format_db_row_to_transaction(transaction) for transaction in transactions]

    cursor.close()
    postgreSQL_pool.putconn(connection)

    return jsonify({'transactions': formatted_transactions})

@app.route("/delete_transaction", methods=["DELETE"])
def delete_transaction():

    id = request.json["id"]

    conn = postgreSQL_pool.getconn()
    cur = conn.cursor()
    cur.execute(f"DELETE FROM transactions WHERE id = {id}")
    conn.commit()

    return jsonify({'result': 'transaction deleted'})    

@app.route("/transaction_summary", methods=["GET"])
@jwt_required()
def transaction_summary():
    user_id = get_jwt_identity()["id"]
    connection = postgreSQL_pool.getconn()
    cursor = connection.cursor()
    query = f"SELECT coin_name, transaction_type, amount, price_purchase_at FROM transactions WHERE user_id = {user_id};"
    cursor.execute(query)
    transactions = cursor.fetchall()
    summary = {}
    for transaction in transactions:
        coin_name, transaction_type, amount, price_purchase_at = transaction
        if coin_name not in summary:
            summary[coin_name] = {
                "total_amount": 0,
                "total_value": 0
            }
        if transaction_type == 1:
            summary[coin_name]["total_amount"] += amount
            summary[coin_name]["total_value"] += (amount * price_purchase_at)
        elif transaction_type == 2:
            summary[coin_name]["total_amount"] -= amount
            summary[coin_name]["total_value"] -= (amount * price_purchase_at)
    
    formatted_summary = []
    
    for coin_name, data in summary.items():
        formatted_summary.append({
            "coin_name": coin_name,
            "total_amount": data["total_amount"],
            "total_value": data["total_value"]
        })

    cursor.close()
    postgreSQL_pool.putconn(connection)

    return jsonify({"summary": formatted_summary})



if __name__ == "__main__":
    schedule_database_update()
    app.run(host='0.0.0.0', port=8080, debug=True)