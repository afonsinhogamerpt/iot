from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
from flask_cors import CORS
import bcrypt
import re

app = Flask(__name__)

CORS(app)
app.config['MYSQL_HOST'] = 'mysql'
app.config['MYSQL_USER'] = 'user'
app.config['MYSQL_PASSWORD'] = 'password'
app.config['MYSQL_DB'] = 'iot'


mysql = MySQL(app)

@app.route('/')
def hello_world():
    return 'Hello World'

@app.route('/login', methods=['POST'])
def login():
    # verificar o metodo primeiro
    if request.method == 'POST':
        
        # obter as variaveis do form
        request_data = request.get_json()
        
        email = request_data['email']
        password = request_data['password']
        
        # verificar se nao foram passadas no form
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400
        
        # Verificar se o utilizador existe
        cur = mysql.connection.cursor()
        # Selecionar mais campos do utilizador
        cur.execute("SELECT id, email, password FROM users WHERE email = %s", (email,))
        user_data = cur.fetchone()
        cur.close()
        
        if not user_data:
            return jsonify({'error': 'Invalid username or password'}), 401
            
        # Verify password (o password está no índice 2 assumindo que selecionamos id, email, password, ...)
        if bcrypt.checkpw(password.encode('utf-8'), user_data[2].encode('utf-8')):
            # Construir objeto de utilizador para retornar
            user = {
                'id': user_data[0],
                'email': user_data[1]
            }
            return jsonify({
                'message': 'Login successful',
                'user': user
            }), 200
        else:
            return jsonify({'error': 'Invalid username or password'}), 401
        
    return jsonify({'error': 'Method not allowed'}), 405

@app.route('/register', methods=['POST'])
def register():
    try:
        # Get form data
        
        request_data = request.get_json()
        
        email = request_data['email']
        password = request_data['password']
        confirm_password = request_data['confirm_password']

        # Validate inputs
        if not all([email, password, confirm_password]):
            return jsonify({'error': 'All fields are required'}), 400

        if password != confirm_password:
            return jsonify({'error': 'Passwords do not match'}), 400

        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400

        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return jsonify({'error': 'Invalid email format'}), 400

        # Check if user already exists
        if check_user_exists(email):
            return jsonify({'error': 'Username or email already exists'}), 409

        # Hash password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Create user in database
        user_data = {
            'email': email,
            'password': hashed_password.decode('utf-8')  # store as string
        }
        create_user(user_data)

        return jsonify({'message': 'Registration successful'}), 201

    except Exception as e:
        # Log the error for debugging
        print(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed'}), 500


@app.route('/updateUserAuth', methods=['POST'])
def updateUserAuth():
    try:
        # Get JSON data
        request_data = request.get_json()
        
        # Validate required fields
        if not request_data or 'email' not in request_data or 'isAuthorized' not in request_data:
            return jsonify({'error': 'Email e isAuthorized são necessários'}), 400

        email = request_data['email']
        is_authorized = request_data['isAuthorized']
        
        # Validate isAuthorized is boolean
        if not isinstance(is_authorized, bool):
            return jsonify({'error': 'isAuthorized deve ser true ou false'}), 400
        
        # Verificar se o utilizador existe
        cur = mysql.connection.cursor()
        
        # Primeiro verifica se o usuário existe
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cur.fetchone()
        
        if not user:
            cur.close()
            return jsonify({'error': 'Usuário não encontrado'}), 404
        
        # Atualiza o campo isAuthorized com o valor recebido
        cur.execute("""
            UPDATE users 
            SET isAuthorized = %s 
            WHERE email = %s
        """, (is_authorized, email))
        
        mysql.connection.commit()
        cur.close()
        
        return jsonify({
            'message': 'Autorização do usuário atualizada com sucesso',
            'email': email,
            'isAuthorized': is_authorized
        }), 200

    except Exception as e:
        print(f"Erro ao atualizar autorização: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500


@app.route('/removeCard', methods=['POST'])
def removeCard():
    request_data = request.get_json()
    cur = mysql.connection.cursor()
    try:
        cur.execute("SELECT * FROM Cards WHERE email = %s", (email,))
        user = cur.fetchone()
        return user is not None
    finally:
        cur.close()
    


# Helper functions
def check_user_exists(email):
    cur = mysql.connection.cursor()
    try:
        cur.execute("SELECT * FROM Users WHERE email = %s", (email,))
        user = cur.fetchone()
        return user is not None
    finally:
        cur.close()


@app.route('/getCards', methods=['GET'])
def getCards():
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM Cards")
        cards = cur.fetchall()
        cur.close()
        if not cards:
            return jsonify({'message': 'Nenhum cartão encontrado'}), 404
        # Convert cards to a list of dictionaries
        cards_list = []
        for card in cards:
            cards_list.append({
                'cardID': card[0],
                'userID': card[1],
            })
        return jsonify(cards_list), 200
    except Exception as e:
        print(f"Erro ao obter cartões: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500
    
@app.route('/getHistory', methods=['GET'])
def getHistory():
    try:
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM registo")
        history = cur.fetchall()
        cur.close()
        if not history:
            return jsonify({'message': 'Histórico não encontrado'}), 404
        # Convert history to a list of dictionaries
        history_list = []
        for record in history:
            history_list.append({
                'registoID': record[0],
                'tempo': record[1],
                'status_entrada': record[2],
                'userID': record[3],
                'cardID': record[4],
            })
        return jsonify(history_list), 200
    except Exception as e:
        print(f"Erro ao obter histórico: {str(e)}")
        return jsonify({'error': 'Erro interno do servidor'}), 500

@app.route('/addCard', methods=['POST'])
def addCard():
    request_data = request.get_json()

    cardID = request_data.get('cardID')

    if not cardID:
        return jsonify({'error': 'Card ID are required'}), 400

    cur = mysql.connection.cursor()

    try:
        # Check if the card already exists
        cur.execute("SELECT * FROM Cards WHERE cardID = %s", (cardID,))
        existing_card = cur.fetchone()

        if existing_card:
            return jsonify({'error': 'Card already exists'}), 409
        cur.execute("INSERT INTO Cards (cardID) VALUES (%s)", (cardID,))
        mysql.connection.commit()

        return jsonify({'message': 'Card added successfully'}), 201
    except Exception as e:
        print(f"Error adding card: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500
    finally:
        cur.close()
        
@app.route('/getCardsUser', methods=['GET'])
def getCardsUser():
    request_data = request.get_json()
    email = request_data.get('email')

    if not email:
        return jsonify({'error': 'Email is required'}), 400

    cur = mysql.connection.cursor()

    try:
        # Get user ID from email
        cur.execute("SELECT userID FROM users WHERE email = %s", (email,))
        user = cur.fetchone()

        if not user:
            return jsonify({'error': 'User not found'}), 404

        user_id = user[0]

        cur.execute("SELECT * FROM Cards WHERE userID = %s", (user_id,))
        cards = cur.fetchall()

        if not cards:
            return jsonify({'message': 'No cards found for this user'}), 404

        cards_list = []
        for card in cards:
            cards_list.append({
                'cardID': card[0],
                'userID': card[1],
            })

        return jsonify(cards_list), 200
    except Exception as e:
        print(f"Error getting cards for user: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
    finally:
        cur.close() 


def create_user(user_data):
    cur = mysql.connection.cursor()
    try:
        cur.execute(
            "INSERT INTO users (email, password) VALUES (%s, %s)",
            (user_data['email'], user_data['password'])
        )
        mysql.connection.commit()
    finally:
        cur.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)

    
    
    
    
    
    
    
    
    