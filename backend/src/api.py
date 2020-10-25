from urllib.request import Request
import http.client
import os
from jose.jwt import decode
import requests
from flask import Flask, request, jsonify, abort, render_template
from flask_sqlalchemy import SQLAlchemy
from six import reraise
from sqlalchemy import exc
import json
from flask_cors import CORS
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import NotFound, UnprocessableEntity
from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AUTH0_DOMAIN, AuthError, requires_auth, verify_decode_jwt

app = Flask(__name__)
setup_db(app)
CORS(app)

'''
@DONE uncomment the following line to initialize the database
!! NOTE THIS WILL DROP ALL RECORDS AND START YOUR DB FROM SCRATCH
!! NOTE THIS MUST BE UNCOMMENTED ON FIRST RUN
'''
db_drop_and_create_all()

# ROUTES
'''
@DONE implement endpoint
    GET /drinks
        it should be a public endpoint
        it should contain only the drink.short() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/drinks")
def get_drinks():
    drinks = [drink.short() for drink in Drink.query.all()]
    return jsonify({"success": True, "drinks": drinks}), 200


'''
@DONE implement endpoint
    GET /drinks-detail
        it should require the 'get:drinks-detail' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''


@app.route("/drinks-detail")
@requires_auth(permissions=["get:drinks-detail"])
def get_drinks_detail(token):
    drinks = [drink.long() for drink in Drink.query.all()]
    return jsonify({"success": True, "drinks": drinks}), 200


'''
@DONE implement endpoint
    POST /drinks
        it should create a new row in the drinks table
        it should require the 'post:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the newly created drink
        or appropriate status code indicating reason for failure
'''


@app.route("/drinks", methods=["POST"])
@requires_auth(permissions=["post:drinks"])
def create_drink(token):
    try:
        data = request.get_json()
        if not isinstance(data["recipe"], list):
            raise UnprocessableEntity()

        drink = Drink(title=data["title"], recipe=json.dumps(data["recipe"]))
        drink.insert()
        return jsonify({"success": True, "drinks": [drink.short()]}), 200
    except IntegrityError:
        abort(403, "this title is already taken try another")
    except UnprocessableEntity:
        abort(
            422, 'Recipe must be a list')
    except:
        abort(400, "something went wrong please make sure you are authenticated and entering valid data")


'''
@DONE implement endpoint
    PATCH /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should update the corresponding row for <id>
        it should require the 'patch:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the updated drink
        or appropriate status code indicating reason for failure
'''


@app.route("/drinks/<int:drink_id>", methods=["PATCH"])
@requires_auth(permissions=["patch:drinks"])
def update_drink(token, drink_id):
    try:
        data = request.get_json()
        drink = Drink.query.filter(Drink.id == drink_id).one_or_none()
        if not drink:
            raise NotFound()

        for key in data.keys():
            if hasattr(drink, key):
                if key == "recipe":
                    if not isinstance(data["recipe"], list):
                        raise UnprocessableEntity()
                    setattr(drink, key, json.dumps(data[key]))
                    continue
                setattr(drink, key, data[key])
        drink.update()
        return jsonify({"success": True, "drinks": [drink.short()]}), 200
    except IntegrityError:
        abort(403, "this title is already taken try another")
    except NotFound:
        abort(404, "this drink does not exist")
    except UnprocessableEntity:
        abort(
            422, 'Recipe must be a list')
    except:
        abort(400, "Bad formated data")


'''
@DONE implement endpoint
    DELETE /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should delete the corresponding row for <id>
        it should require the 'delete:drinks' permission
    returns status code 200 and json {"success": True, "delete": id} where id is the id of the deleted record
        or appropriate status code indicating reason for failure
'''


@app.route("/drinks/<int:drink_id>", methods=["DELETE"])
@requires_auth(permissions=["delete:drinks"])
def delete_drink(token, drink_id):
    drink = Drink.query.get_or_404(drink_id)
    drink.delete()
    return jsonify({"success": True, "delete": drink_id}), 200


# Users Management


@app.route("/users", methods=["GET"])
@requires_auth(permissions=["read:users"])
def get_users(decoded_token):
    token = request.headers["Authorization"]

    res = requests.get(f"https://{AUTH0_DOMAIN}/api/v2/users",
                       headers={"Authorization": token})
    return res.text


@app.route("/users", methods=["POST"])
@requires_auth(permissions=["create:users"])
def create_user(decoded_token):
    token = request.headers["Authorization"]
    res = requests.post(
        f"https://{AUTH0_DOMAIN}/api/v2/users",
        json=request.json,
        headers={"Authorization": token}
    )
    return res.text, res.status_code


@app.route("/users/<id>", methods=["GET"])
@requires_auth(permissions=["read:users"])
def get_user(decoded_token, id):
    token = request.headers["Authorization"]
    res = requests.get(
        f"https://{AUTH0_DOMAIN}/api/v2/users/auth0|{id}",
        headers={"Authorization": token})
    return res.text, res.status_code


@app.route("/users/<id>", methods=["PATCH"])
@requires_auth(permissions=["update:users", "read:users"])
def update_user(decoded_token, id):
    token = request.headers["Authorization"]
    res = requests.patch(
        f"https://{AUTH0_DOMAIN}/api/v2/users/auth0|{id}",
        json=request.json,
        headers={"Authorization": token}
    )
    return res.text, res.status_code


@app.route("/users/<id>", methods=["DELETE"])
@requires_auth(permissions=["delete:users"])
def delete_user(decoded_token, id):
    token = request.headers["Authorization"]
    res = requests.delete(
        f"https://{AUTH0_DOMAIN}/api/v2/users/auth0|{id}",
        json=request.json,
        headers={"Authorization": token}
    )
    return res.text, res.status_code


@app.route("/oauth/login")
def oauth_login():
    return jsonify(

        request.values

    )


@app.route("/logout")
def logout():
    res = requests.get(
        "https://urokai-auth.us.auth0.com/v2/logout?client_id=vrr3RaMJu2mOItxKTvB2tpqCbOw74z6W&returnTo=http://127.0.0.1:8100")
    return "logout"


# Error Handling
'''
Example error handling for unprocessable entity
'''


@app.errorhandler(422)
def unprocessable(error):
    if not error:
        error.description = "UNPROCESSABLE"
    return jsonify({
        "success": False,
        "error": 422,
        "message": error.description
    }), 422


'''
@DONE implement error handlers using the @app.errorhandler(error) decorator
    each error handler should return (with approprate messages):
             jsonify({
                    "success": False,
                    "error": 404,
                    "message": "resource not found"
                    }), 404

'''

'''
@DONE implement error handler for 404
    error handler should conform to general task above
'''


@app.errorhandler(404)
def resource_not_found(error):
    if not error:
        error.description = "RESOURCE NOT FOUND"
    return jsonify({
        "success": False,
        "error": 404,
        "message": error.description
    }), 404


'''
@DONE implement error handler for AuthError
    error handler should conform to general task above
'''


@app.errorhandler(405)
def method_not_allowed(error):
    if not error:
        error.description = "METHOD NOT ALLOWED"
    return jsonify({
        "success": False,
        "error": 405,
        "message": error.description
    }), 405


@app.errorhandler(AuthError)
def auth_error(error):
    if not error:
        error.description = "AUTH ERROR"
    return jsonify({
        "success": False,
        "error": error.status_code,
        "message": error.description
    }), error.status_code


@app.errorhandler(400)
def bad_request(error):
    if not error:
        error.description = "BAD REQUEST"
    return jsonify({
        "success": False,
        "error": 400,
        "message": error.description
    }), 400


@app.errorhandler(403)
def forbidden(error):
    if not error:
        error.description = "FORBIDDEN"
    return jsonify({
        "success": False,
        "error": 403,
        "message": error.description
    }), 403


@app.errorhandler(401)
def unauthorized(error):
    if not error:
        error.description = "Unauthorized"
    return jsonify({
        "success": False,
        "error": 401,
        "message": error.description
    }), 401
